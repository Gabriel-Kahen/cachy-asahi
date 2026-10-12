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
        'binary_publication', 'selected_for_release', 'first_failed_phase', 'failure_reason',
        'producer_exit', 'acquisition_exit', 'resources'}
REASONS = {
    'NONE': {'NONE'},
    'preflight': {'PREFLIGHT_REJECTED', 'HOST_CAPABILITIES', 'HOST_MEMORY_RESERVE',
                  'HOST_DISK_RESERVE', 'HOST_TOOL_UNAVAILABLE', 'CANCELLED'},
    'source': {'SOURCE_REJECTED', 'DOCKER_REJECTED', 'DAEMON_OCCUPIED',
               'PRODUCER_TIME_RESERVE', 'CANCELLED'},
    'parallel': {'PRODUCER_EXIT', 'ACQUISITION_EXIT', 'BOTH_CHILDREN_EXIT', 'PARALLEL_TIMEOUT',
                 'PARALLEL_OUTPUT_BOUND', 'PARALLEL_RUN_FAILED', 'CANCELLED'},
    'producer': {'PRODUCER_RECEIPT_REJECTED', 'CANCELLED'},
    'acquisition': {'ACQUISITION_RECEIPT_REJECTED', 'CANCELLED'},
    'kernel': {'KERNEL_TIME_RESERVE', 'KERNEL_DISK_RESERVE', 'KERNEL_OUTPUT_REJECTED',
               'KERNEL_EXIT', 'KERNEL_TIMEOUT', 'KERNEL_OUTPUT_BOUND', 'KERNEL_RUN_FAILED',
               'KERNEL_RECEIPT_REJECTED', 'CANCELLED'},
    'cleanup': {'CLEANUP_FAILED', 'CANCELLED'},
    'finalization': {'CANCELLED', 'PUBLICATION_FAILED'},
    'outcome': {'NATIVE_FAILURE', 'NATIVE_CANCELLED', 'NATIVE_SKIPPED', 'NATIVE_UNAVAILABLE'},
}
FIRST_PHASES = set(REASONS)
PHASES = {'preflight', 'source', 'producer', 'kernel', 'cleanup', 'complete'}
RESOURCE_KEYS = {'mem_total_bytes', 'mem_available_bytes', 'initial_free_disk_bytes',
                 'pre_kernel_free_disk_bytes'}
CHILDREN = ('producer', 'kernel_probe', 'baseline', 'candidate')


def need(value):
    if not value:
        raise ValueError('public-boundary')


def failure_pair(phase, reason):
    need(type(phase) is str and type(reason) is str and
         phase in FIRST_PHASES and reason in REASONS[phase])


def record_failure(value, phase, reason):
    failure_pair(phase, reason)
    failure_pair(value['first_failed_phase'], value['failure_reason'])
    value['status'] = 'FAIL'
    if value['first_failed_phase'] == 'NONE':
        value['first_failed_phase'], value['failure_reason'] = phase, reason


def exit_record(code):
    need(type(code) is int and -64 <= code <= 255)
    return {'kind': 'EXIT_SIGNAL' if code < 0 else 'EXIT_NONZERO' if code else 'EXIT_ZERO',
            'code': code}


def diagnostics(value):
    failure_pair(value['first_failed_phase'], value['failure_reason'])
    for name in ('producer_exit', 'acquisition_exit'):
        row = value[name]
        need(type(row) is dict and set(row) == {'kind', 'code'} and type(row['kind']) is str)
        if row['kind'] in {'NOT_RUN', 'UNOBSERVED'}:
            need(row['code'] is None)
        else:
            need(row == exit_record(row['code']))
    exits = tuple(value[name]['kind'] for name in ('producer_exit', 'acquisition_exit'))
    failed = tuple(kind in {'EXIT_NONZERO', 'EXIT_SIGNAL'} for kind in exits)
    if value['first_failed_phase'] == 'NONE':
        need(not any(failed))
    if value['first_failed_phase'] == 'parallel':
        expected = {'PRODUCER_EXIT': (True, False), 'ACQUISITION_EXIT': (False, True),
                    'BOTH_CHILDREN_EXIT': (True, True)}.get(value['failure_reason'])
        if expected is not None:
            need(failed == expected and all(fail or kind == 'EXIT_ZERO'
                                           for fail, kind in zip(failed, exits)))
    resources = value['resources']
    need(type(resources) is dict and set(resources) == RESOURCE_KEYS and
         all(item is None or type(item) is int and 0 <= item <= 2**60
             for item in resources.values()))
    need(not value['cancelled'] or value['first_failed_phase'] != 'NONE')


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
         value['schema_version'] == 2 and value['stage'] == 'kernel-native-development-job' and
         type(value['cancelled']) is bool and value['selected_for_release'] is False and
         value['source_commit'] == commit and value['packet_sha256'] == pin)
    need(value['status'] in {'PASS', 'FAIL'} and value['phase'] in PHASES and
         value['cleanup'] in {'PASS', 'FAIL'} and
         value['native_compilation'] in {'PASS', 'NOT ACCEPTED', 'NOT RUN'} and
         all(value[name] in {'PASS', 'FAIL', 'NOT RUN'} for name in CHILDREN))
    need(all(value[name] == 'NOT RUN' for name in
             ('kernel_runtime', 'hardware', 'installation', 'binary_publication')) and
         value['performance'] == 'NOT MEASURED')
    diagnostics(value)
    accepted = (value['phase'] == 'complete' and not value['cancelled'] and
                value['first_failed_phase'] == 'NONE' and value['failure_reason'] == 'NONE' and
                all(value[name] == exit_record(0) for name in ('producer_exit', 'acquisition_exit')) and
                value['cleanup'] == 'PASS' and
                all(value[name] == 'PASS' for name in CHILDREN) and
                value['native_compilation'] == 'PASS')
    need(value['status'] != 'PASS' or accepted)
    # A stale PASS left before cancellation or a later step failure is not accepted.
    if outcome != 'success' or value['status'] != 'PASS':
        if outcome != 'success':
            record_failure(value, 'outcome', {'failure': 'NATIVE_FAILURE', 'cancelled': 'NATIVE_CANCELLED',
                           'skipped': 'NATIVE_SKIPPED', '': 'NATIVE_UNAVAILABLE'}[outcome])
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
