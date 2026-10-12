#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Publish one finite status record; never traverse or publish build evidence."""
import argparse
import json
import os
from pathlib import Path
import re
import stat

MAX_BYTES = 16 * 1024
KEYS = {'schema_version', 'stage', 'status', 'phase', 'cancelled', 'source_commit',
        'packet_sha256', 'producer', 'kernel_probe', 'baseline', 'candidate', 'cleanup',
        'native_compilation', 'kernel_runtime', 'hardware', 'installation', 'performance',
        'binary_publication', 'selected_for_release'}
PHASES = {'preflight', 'source', 'producer', 'kernel', 'cleanup', 'complete'}
CHILDREN = ('producer', 'kernel_probe', 'baseline', 'candidate')


def need(value):
    if not value:
        raise ValueError('public-boundary')


def read(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and
         all(stat.S_ISDIR(parent.lstat().st_mode) for parent in path.parents))
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
         before.st_uid == os.getuid() and before.st_size <= MAX_BYTES)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        need((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino))
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(MAX_BYTES + 1)
        after = os.fstat(fd)
        need(len(data) <= MAX_BYTES and
             (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) ==
             (after.st_size, after.st_mtime_ns, after.st_ctime_ns) and
             (path.lstat().st_dev, path.lstat().st_ino) == (opened.st_dev, opened.st_ino))
        return data
    finally:
        os.close(fd)


def decode(data):
    need(len(data) <= MAX_BYTES)
    def unique(rows):
        result = {}
        for key, value in rows:
            need(key not in result)
            result[key] = value
        return result
    result = json.loads(data, object_pairs_hook=unique,
                        parse_constant=lambda _: need(False))
    need(type(result) is dict)
    return result


def project(data, commit, pin, outcome):
    need(type(commit) is str and re.fullmatch('[0-9a-f]{40}', commit) and
         type(pin) is str and re.fullmatch('[0-9a-f]{64}', pin) and
         outcome in {'success', 'failure', 'cancelled', 'skipped', ''})
    value = decode(data)
    need(set(value) == KEYS and type(value['schema_version']) is int and
         value['schema_version'] == 1 and value['stage'] == 'kernel-native-development-job' and
         type(value['cancelled']) is bool and value['selected_for_release'] is False and
         value['source_commit'] == commit and value['packet_sha256'] == pin)
    need(value['status'] in {'PASS', 'FAIL'} and value['phase'] in PHASES and
         value['cleanup'] in {'PASS', 'FAIL'} and
         value['native_compilation'] in {'PASS', 'NOT ACCEPTED', 'NOT RUN'} and
         all(value[name] in {'PASS', 'FAIL', 'NOT RUN'} for name in CHILDREN))
    need(all(value[name] == 'NOT RUN' for name in
             ('kernel_runtime', 'hardware', 'installation', 'binary_publication')) and
         value['performance'] == 'NOT MEASURED')
    accepted = (value['phase'] == 'complete' and not value['cancelled'] and
                value['cleanup'] == 'PASS' and
                all(value[name] == 'PASS' for name in CHILDREN) and
                value['native_compilation'] == 'PASS')
    need(value['status'] != 'PASS' or accepted)
    # A stale PASS left before cancellation or a later step failure is not accepted.
    if outcome != 'success' or value['status'] != 'PASS':
        value['status'] = 'FAIL'
        value['cancelled'] = value['cancelled'] or outcome == 'cancelled'
        value['native_compilation'] = ('NOT ACCEPTED' if any(
            value[name] != 'NOT RUN' for name in ('baseline', 'candidate')) else 'NOT RUN')
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--status', required=True, type=Path)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--packet-sha256', required=True)
    parser.add_argument('--native-outcome', required=True)
    args = parser.parse_args(argv)
    try:
        data = read(args.status)
    except FileNotFoundError:
        print('KERNEL_PUBLIC_RECEIPT_MISSING')
        return 1
    except Exception:
        print('KERNEL_PUBLIC_EVIDENCE_REFUSED')
        return 1
    try:
        value = project(data, args.source_commit, args.packet_sha256, args.native_outcome)
        print(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True))
        return int(args.native_outcome == 'success' and value['status'] != 'PASS')
    except Exception:
        print('KERNEL_PUBLIC_EVIDENCE_REFUSED')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
