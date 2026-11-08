#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Convert explicitly retained Apps inventory DATA for offline advisory review."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


a = module('security_inventory_advisories', 'scripts/maintenance/security_advisories.py')
v = module('security_inventory_observation', 'packages/tools/cachy-asahi-apps16/inventory.py')
need, encoded = a.need, a.encoded
INPUT_CAP = 16 * 1024**2
DECLARED = 'CALLER_DECLARED_METADATA_NOT_HOST_ATTESTED'


def read(path):
    path = Path(path).absolute()
    need(path == path.resolve(), 'ordinary nonsymlink retained input required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= INPUT_CAP,
             'bounded ordinary single-link retained input required')
        raw = stream.read(INPUT_CAP + 1); after = os.fstat(stream.fileno())
    key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(len(raw) == before.st_size and key(before) == key(after) == key(path.lstat()), 'retained input changed')
    return raw


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key'); result[key] = value
        return result
    def invalid(_): raise ValueError('noninteger or nonfinite JSON number')
    need(0 < len(raw) <= INPUT_CAP, 'retained JSON byte bound')
    return json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)


def project(value):
    keys = {'schema_version', 'kind', 'target_arch', 'snapshot_id', 'packages'}
    need(type(value) is dict and set(value) in (keys, keys | {'observation'}), 'closed Apps inventory object required')
    need(type(value['schema_version']) is int and value['schema_version'] == 1
         and value['kind'] == 'complete-installed-inventory' and value['target_arch'] == 'aarch64'
         and type(value['snapshot_id']) is str and 0 < len(value['snapshot_id']) <= 128
         and value['snapshot_id'].isprintable(), 'supported retained ARM inventory required')
    packages = value['packages']
    need(type(packages) is list and 0 < len(packages) <= 4096, 'nonempty retained package count bound')
    rows = []
    for row in packages:
        need(type(row) is dict and {'name', 'version', 'arch', 'provides'} <= set(row), 'complete package identity/provides required')
        selected = {k: row[k] for k in ('name', 'version', 'arch', 'provides', 'pkgbase', 'origin') if k in row}
        a.inventory([selected])
        need(a.FULL_VERSION.fullmatch(selected['version']), 'complete package version including pkgrel required')
        rows.append(selected)
    a.inventory(rows)  # Includes duplicate binary-name refusal; no alias expansion.
    qualifier = DECLARED
    if 'observation' in value:
        # Validate only the retained observation's internal hash consistency.
        # Identity normalization deliberately grants no Apps plan/payload credit.
        qualifier = v.validate(value, lambda row: row)
    raw = encoded(sorted(rows, key=lambda row: row['name']))
    need(len(raw) <= a.CAP, 'projected inventory exceeds advisory input byte bound')
    return raw, qualifier


def write_at(directory, name, raw):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def run(input_path, checksum, output):
    need(type(checksum) is str and re.fullmatch('[0-9a-f]{64}', checksum), 'explicit retained input SHA256 required')
    output = Path(output).absolute()
    need(output == output.resolve() and not os.path.lexists(output) and output.parent.is_dir(), 'fresh ordinary output directory required')
    raw = read(input_path); need(a.pin(raw)['sha256'] == checksum, 'retained input checksum mismatch')
    value = decode(raw); inventory, qualifier = project(value)
    receipt = dict(schema_version=1, status='PROJECTED_RETAINED_INVENTORY_NOT_REOBSERVED',
        source=dict(file='source.json', **a.pin(raw)), inventory=dict(file='inventory.json', **a.pin(inventory)),
        snapshot_id=value['snapshot_id'], package_count=len(value['packages']), source_qualification=qualifier,
        observation=value.get('observation'), observation_check='INTERNAL_HASH_CONSISTENCY_ONLY' if 'observation' in value else 'NOT_OBSERVED',
        freshness='NOT_REOBSERVED_SOURCE_MAY_BE_STALE', payload_verified=False, hardware_verified=False,
        arm_security_status='UNKNOWN', scope='PACKAGE_IDENTITY_PROJECTION_NOT_APPS_PLANNING_OR_SECURITY_ACCEPTANCE')
    output.mkdir(mode=0o700)
    directory = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        original = os.fstat(directory)
        write_at(directory, 'source.json', raw); write_at(directory, 'inventory.json', inventory)
        need(read(input_path) == raw, 'retained input changed before completion')
        current = output.lstat()
        need((current.st_dev, current.st_ino) == (original.st_dev, original.st_ino) and stat.S_ISDIR(current.st_mode), 'output directory changed')
        # Publish completion only after the retained files and directory are durable.
        os.fsync(directory)
        parent = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(parent)
        finally: os.close(parent)
        write_at(directory, '.receipt.pending', encoded(receipt))
        os.link('.receipt.pending', 'receipt.json', src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
        os.unlink('.receipt.pending', dir_fd=directory)
        os.fsync(directory)
    except BaseException:
        # Failed output is retained for inspection, without a completion receipt.
        try: os.unlink('receipt.json', dir_fd=directory)
        except FileNotFoundError: pass
        raise
    finally: os.close(directory)
    return dict(output=str(output), inventory_sha256=a.pin(inventory)['sha256'], package_count=receipt['package_count'],
                source_qualification=qualifier, freshness=receipt['freshness'], arm_security_status='UNKNOWN')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True); parser.add_argument('--input-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True); args = parser.parse_args(argv)
    try: result = run(args.input, args.input_sha256, args.output)
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
        print('security inventory: ' + str(error), file=sys.stderr); return 2
    print(encoded(result).decode(), end=''); return 0


if __name__ == '__main__': raise SystemExit(main())
