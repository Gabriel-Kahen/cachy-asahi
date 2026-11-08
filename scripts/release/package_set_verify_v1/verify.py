#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify selected local release archives without installing or extracting them."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import tempfile

VALIDATOR = Path(__file__).resolve().parents[2] / 'checks/package_checks.py'
MAX_SELECTION = 4 * 1024 * 1024
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_SET = 2 * 1024 * 1024 * 1024
HEX = re.compile(r'[0-9a-f]{64}')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def safe_path(path):
    path = Path(path).absolute()
    need('..' not in path.parts, 'parent traversal in input path')
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'symlink input path')
    return path


def copy_input(path, output, maximum):
    """Read one regular FD, hashing exactly the bounded bytes retained for inspection."""
    path = safe_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        need(stat.S_ISREG(os.fstat(source.fileno()).st_mode), 'regular input required')
        digest, size = hashlib.sha256(), 0
        while block := source.read(1024 * 1024):
            size += len(block)
            need(size <= maximum, 'input byte limit exceeded')
            digest.update(block)
            output.write(block)
    need(size > 0, 'empty input')
    return digest.hexdigest(), size


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        need(key not in value, 'duplicate JSON key: ' + key)
        value[key] = item
    return value


def selection(path, pin):
    import io
    need(isinstance(pin, str) and HEX.fullmatch(pin), 'selection SHA-256 required')
    raw = io.BytesIO()
    digest, _ = copy_input(path, raw, MAX_SELECTION)
    need(digest == pin, 'selection SHA-256 mismatch')
    value = json.loads(raw.getvalue(), object_pairs_hook=unique_object)
    need(type(value) is dict and type(value.get('schema_version')) is int and
         value['schema_version'] == 1, 'release schema_version must be 1')
    need(isinstance(value.get('release_id'), str) and value['release_id'].strip(), 'release_id required')
    rows = value.get('packages')
    need(type(rows) is list and 0 < len(rows) <= 256, 'finite nonempty packages list required')
    names, filenames = set(), set()
    for row in rows:
        need(type(row) is dict, 'package record required')
        for key in ('name', 'version', 'arch', 'filename', 'sha256'):
            need(isinstance(row.get(key), str) and bool(row[key]), 'package field required: ' + key)
        need(re.fullmatch(r'[A-Za-z0-9@._+:-]+', row['name']), 'invalid package name')
        need(not any(c.isspace() for c in row['version']), 'invalid package version')
        need(row['arch'] in ('any', 'aarch64'), 'package architecture must be any or aarch64')
        need(HEX.fullmatch(row['sha256']), 'invalid archive SHA-256')
        need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+:-]*\.pkg\.tar(?:\.(?:gz|xz|zst))?', row['filename']),
             'archive filename must be a package basename')
        need(row['name'] not in names and row['filename'] not in filenames, 'duplicate package name/filename')
        names.add(row['name']); filenames.add(row['filename'])
    return value, sorted(rows, key=lambda row: row['name'])


def verify(selected, pin, archive_root):
    manifest, rows = selection(selected, pin)
    root = safe_path(archive_root)
    need(root.is_dir(), 'archive root must be a directory')
    validator_raw = VALIDATOR.read_bytes()
    # Compile the same bytes whose identity is retained in the report.
    spec = importlib.util.spec_from_file_location('package_set_validator_v1', VALIDATOR)
    checks = importlib.util.module_from_spec(spec)
    exec(compile(validator_raw, str(VALIDATOR), 'exec'), checks.__dict__)
    reports, summaries, total = [], [], 0
    with tempfile.TemporaryDirectory(prefix='package-set-verify-') as directory:
        for row in rows:
            snapshot = Path(directory) / row['filename']
            with snapshot.open('xb') as output:
                digest, size = copy_input(root / row['filename'], output, min(MAX_ARCHIVE, MAX_SET - total))
            total += size
            need(digest == row['sha256'], 'archive SHA-256 mismatch: ' + row['filename'])
            report = checks.package(snapshot)
            need(report['sha256'] == digest, 'snapshot inspection SHA-256 mismatch')
            errors = list(report['errors'])
            metadata = report['metadata'].get('.PKGINFO', {})
            for expected, actual in (('name', 'pkgname'), ('version', 'pkgver'), ('arch', 'arch')):
                if metadata.get(actual) != [row[expected]]:
                    errors.append('selected package ' + expected + ' differs from .PKGINFO')
            reports.append(report)
            summaries.append({key: row[key] for key in ('name', 'version', 'arch', 'filename', 'sha256')} |
                             dict(bytes=size, errors=errors, review=report['review']))
    errors = checks.conflicts(reports)
    failed = bool(errors or any(row['errors'] for row in summaries))
    review = any(row['review'] for row in summaries)
    return dict(schema_version=1, release_id=manifest['release_id'], selection_sha256=pin,
                validator_sha256=hashlib.sha256(validator_raw).hexdigest(), packages=summaries,
                errors=errors, status='FAIL' if failed else 'REVIEW_REQUIRED' if review else 'STATIC_PASS',
                limit='Selected local archive bytes, metadata and paths only; signatures, dependencies, '
                      'source/license closure, installation, native/M2 execution and release acceptance NOT_ESTABLISHED')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', type=Path, required=True, help='Existing release.json')
    parser.add_argument('--selection-sha256', required=True, help='Independently authenticated release.json SHA-256')
    parser.add_argument('--archive-root', type=Path, required=True, help='Directory containing selected package basenames')
    args = parser.parse_args(argv)
    try:
        report = verify(args.selection, args.selection_sha256, args.archive_root)
        print(json.dumps(report, sort_keys=True, indent=2))
        return 0 if report['status'] == 'STATIC_PASS' else 1
    except (OSError, ValueError, TypeError, RecursionError, tarfile.TarError, UnicodeError) as error:
        print(json.dumps(dict(status='REFUSED', errors=[str(error)]), sort_keys=True), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
