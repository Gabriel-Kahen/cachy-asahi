#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify selected local release archives without installing or extracting them."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile

VALIDATOR = Path(__file__).resolve().parents[2] / 'checks/package_checks.py'
MAX_SELECTION = 16 * 1024 * 1024
MAX_PACKAGES = 1024
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_SET = 64 * 1024 * 1024 * 1024
MAX_MEMBERS = 1_000_000
MAX_SPOOL = 128 * 1024 * 1024
MAX_WORKER_OUTPUT = 32 * 1024 * 1024
MAX_REPORT = 64 * 1024 * 1024
WORKER = Path(__file__).with_name('worker.py')
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
        info = os.fstat(source.fileno())
        need(stat.S_ISREG(info.st_mode), 'regular input required')
        need(info.st_size <= maximum, 'input byte limit exceeded')
        digest, size = hashlib.sha256(), 0
        while block := source.read(min(1024 * 1024, maximum - size + 1)):
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
    need(type(rows) is list and 0 < len(rows) <= MAX_PACKAGES, 'finite nonempty packages list required (maximum 1024)')
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


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def run_worker(mode, input_path, validator_pin, *, timeout=90):
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as diagnostic:
        result = subprocess.run([sys.executable, '-I', '-B', str(WORKER), mode,
                                 str(input_path), validator_pin], stdout=output,
                                stderr=diagnostic, timeout=timeout, check=False)
        output.seek(0); raw = output.read(MAX_WORKER_OUTPUT + 1)
        need(len(raw) <= MAX_WORKER_OUTPUT, 'worker report byte budget exceeded')
        diagnostic.seek(0)
        need(result.returncode == 0, 'bounded ' + mode + ' worker refused (exit ' +
             str(result.returncode) + '): ' + diagnostic.read(1000).decode(errors='replace'))
        return json.loads(raw, object_pairs_hook=unique_object)


def inspect_snapshot(snapshot, validator_pin, *, timeout=90):
    return run_worker('inspect', snapshot, validator_pin, timeout=timeout)


def verify(selected, pin, archive_root, *, max_total_bytes=MAX_SET,
           max_members=MAX_MEMBERS, max_spool_bytes=MAX_SPOOL):
    for value, maximum, label in ((max_total_bytes, MAX_SET, 'archive'),
                                  (max_members, MAX_MEMBERS, 'member'),
                                  (max_spool_bytes, MAX_SPOOL, 'spool')):
        need(type(value) is int and 0 < value <= maximum, 'invalid lower-only ' + label + ' budget')
    manifest, rows = selection(selected, pin)
    root = safe_path(archive_root)
    need(root.is_dir(), 'archive root must be a directory')
    validator_pin = hashlib.sha256(VALIDATOR.read_bytes()).hexdigest()
    summaries, total, member_count, spool_bytes, summary_bytes, peak_snapshot = [], 0, 0, 0, 0, 0
    with tempfile.TemporaryDirectory(prefix='package-set-verify-v2-') as directory:
        spool = Path(directory) / 'members.jsonl'
        with spool.open('xb') as stream:
            for row in rows:
                snapshot = Path(directory) / row['filename']
                try:
                    with snapshot.open('xb') as output:
                        digest, size = copy_input(root / row['filename'], output,
                                                  min(MAX_ARCHIVE, max_total_bytes - total))
                    total += size; peak_snapshot = max(peak_snapshot, size)
                    need(digest == row['sha256'], 'archive SHA-256 mismatch: ' + row['filename'])
                    report = inspect_snapshot(snapshot, validator_pin)
                    need(report['sha256'] == digest, 'snapshot inspection SHA-256 mismatch')
                    member_count += len(report['members'])
                    need(member_count <= max_members, 'aggregate member budget exceeded')
                    # Preserve archive member order as well as types for the existing API's findings.
                    projection = json.dumps(dict(artifact=report['artifact'], members=report['members']),
                                            separators=(',', ':')).encode() + b'\n'
                    spool_bytes += len(projection)
                    need(spool_bytes <= max_spool_bytes, 'aggregate spool byte budget exceeded')
                    stream.write(projection)
                    errors = list(report['errors'])
                    metadata = report['metadata'].get('.PKGINFO', {})
                    for expected, actual in (('name', 'pkgname'), ('version', 'pkgver'), ('arch', 'arch')):
                        if metadata.get(actual) != [row[expected]]:
                            errors.append('selected package ' + expected + ' differs from .PKGINFO')
                    summary = {key: row[key] for key in ('name', 'version', 'arch', 'filename', 'sha256')} | \
                              dict(bytes=size, errors=errors, review=report['review'])
                    summary_bytes += len(encoded(summary))
                    need(summary_bytes <= MAX_WORKER_OUTPUT, 'summary byte budget exceeded')
                    summaries.append(summary)
                    del report, projection
                finally:
                    snapshot.unlink(missing_ok=True)
        errors = run_worker('conflicts', spool, validator_pin)
    failed = bool(errors or any(row['errors'] for row in summaries))
    review = any(row['review'] for row in summaries)
    result = dict(schema_version=1, release_id=manifest['release_id'], selection_sha256=pin,
                validator_sha256=validator_pin, packages=summaries,
                errors=errors, status='FAIL' if failed else 'REVIEW_REQUIRED' if review else 'STATIC_PASS',
                budgets=dict(max_packages=MAX_PACKAGES, max_total_bytes=max_total_bytes,
                             max_members=max_members, max_spool_bytes=max_spool_bytes),
                usage=dict(archive_bytes=total, members=member_count, spool_bytes=spool_bytes,
                           peak_snapshot_bytes=peak_snapshot),
                limit='Selected local archive bytes, metadata and paths only; signatures, dependencies, '
                      'source/license closure, installation, native/M2 execution and release acceptance NOT_ESTABLISHED')
    need(len(encoded(result)) <= MAX_REPORT, 'final report byte budget exceeded')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', type=Path, required=True, help='Existing release.json')
    parser.add_argument('--selection-sha256', required=True, help='Independently authenticated release.json SHA-256')
    parser.add_argument('--archive-root', type=Path, required=True, help='Directory containing selected package basenames')
    parser.add_argument('--max-total-bytes', type=int, default=MAX_SET, help='Lower the 64 GiB aggregate archive budget')
    parser.add_argument('--max-members', type=int, default=MAX_MEMBERS, help='Lower the 1,000,000 aggregate member budget')
    parser.add_argument('--max-spool-bytes', type=int, default=MAX_SPOOL, help='Lower the 128 MiB namespace spool budget')
    args = parser.parse_args(argv)
    try:
        report = verify(args.selection, args.selection_sha256, args.archive_root,
                        max_total_bytes=args.max_total_bytes, max_members=args.max_members,
                        max_spool_bytes=args.max_spool_bytes)
        output = json.dumps(report, sort_keys=True, indent=2)
        need(len(output.encode()) <= MAX_REPORT, 'final report byte budget exceeded')
        print(output)
        return 0 if report['status'] == 'STATIC_PASS' else 1
    except (OSError, ValueError, TypeError, RecursionError, tarfile.TarError, UnicodeError,
            subprocess.SubprocessError) as error:
        print(json.dumps(dict(status='REFUSED', errors=[str(error)]), sort_keys=True), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
