#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 cachy-asahi contributors
"""Validate fixture-only KSM proposals; never observe or mutate kernel state."""
import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path


def keys(value, expected, label):
    if type(value) is not dict or set(value) != set(expected):
        raise ValueError(f'{label}: exact fields required: {sorted(expected)}')


def integer(value, maximum, label):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f'{label}: integer outside 0..{maximum}')


def snapshot_digest(snapshot):
    return hashlib.sha256(json.dumps(snapshot, sort_keys=True, separators=(',', ':'),
                                     allow_nan=False).encode()).hexdigest()


def plan(snapshot, request):
    keys(snapshot, ('schema_version', 'target', 'kernel_release', 'page_size',
                    'controls', 'advisor_mode'), 'snapshot')
    keys(request, ('schema_version', 'snapshot_sha256', 'action', 'tuning',
                   'acknowledge_unmerge'), 'request')
    for label, value in (('snapshot', snapshot), ('request', request)):
        if type(value['schema_version']) is not int or value['schema_version'] != 1:
            raise ValueError(f'{label}: unsupported schema')
    if snapshot['target'] not in ('m2-air-13', 'm2-air-15'):
        raise ValueError('unsupported declared target label')
    release = snapshot['kernel_release']
    if type(release) is not str or not re.fullmatch(r'[A-Za-z0-9._+\-]{1,128}', release):
        raise ValueError('kernel_release must be a bounded release label')
    integer(snapshot['page_size'], 1048576, 'page_size')
    if snapshot['page_size'] == 0:
        raise ValueError('page_size must be positive')
    controls = snapshot['controls']
    keys(controls, ('run', 'pages_to_scan', 'sleep_millisecs'), 'controls')
    integer(controls['run'], 1, 'baseline run (unmerge is not restorable)')
    for name in ('pages_to_scan', 'sleep_millisecs'):
        integer(controls[name], 4294967295, name)
    if snapshot['advisor_mode'] not in ('none', 'scan-time', 'unavailable'):
        raise ValueError('advisor_mode must be an explicitly captured supported value or absence')
    checksum = request['snapshot_sha256']
    if type(checksum) is not str or not re.fullmatch(r'[0-9a-f]{64}', checksum):
        raise ValueError('invalid snapshot digest')
    if checksum != snapshot_digest(snapshot):
        raise ValueError('request differs from bound snapshot; this is not a live freshness check')
    states = {'enable': 1, 'pause': 0, 'disable': 2}
    action = request['action']
    if type(action) is not str or action not in states:
        raise ValueError('unsupported action')
    if type(request['acknowledge_unmerge']) is not bool:
        raise ValueError('acknowledge_unmerge must be boolean')
    if request['acknowledge_unmerge'] != (action == 'disable'):
        raise ValueError('only disable requires explicit unmerge acknowledgement')
    tuning = request['tuning']
    if type(tuning) is not dict or not set(tuning) <= {'pages_to_scan', 'sleep_millisecs'}:
        raise ValueError('unsupported tuning control')
    for name, value in tuning.items():
        integer(value, 4294967295, name)
    if 'pages_to_scan' in tuning and snapshot['advisor_mode'] == 'scan-time':
        raise ValueError('pages_to_scan is owned by scan-time advisor; no implicit advisor change')
    desired = {**tuning, 'run': states[action]}
    order = sorted(tuning) + ['run']
    changes = [{'control': name, 'from': controls[name], 'to': desired[name]}
               for name in order if controls[name] != desired[name]]
    restore = [{'control': 'run', 'to': 0}]
    restore += [{'control': name, 'to': controls[name]} for name in sorted(tuning)
                if controls[name] != tuning[name]]
    if controls['run'] == 1:
        restore.append({'control': 'run', 'to': 1})
    gates = ('target-capabilities', 'native-build', 'privilege-boundary',
             'merge-eligibility-security', 'activation', 'concurrent-change-interruption',
             'low-memory-unmerge-recovery', 'control-restoration', 'measured-benefit')
    return {'schema_version': 1, 'status': 'validated-dry-run', 'mutation': False,
            'management_available': False, 'execution': 'NOT IMPLEMENTED',
            'hardware_status': 'NOT RUN', 'snapshot_sha256': checksum,
            'snapshot_assurance': 'declared input only; not hardware or freshness attestation',
            'control_scope': 'global KSM controls affect all registered mergeable memory',
            'target': snapshot['target'], 'page_size': snapshot['page_size'], 'action': action,
            'changes': changes, 'restore': restore, 'restore_scope': 'control-values-only',
            'unmerge_warning': 'Cannot reconstruct sharing or recover killed applications; unmerge can fail under memory pressure.',
            'gates': dict.fromkeys(gates, 'NOT RUN')}


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'duplicate JSON key: {key}')
        result[key] = value
    return result


def load(path):
    # Read only user-supplied JSON, bounded before decoding. No device discovery.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('JSON input must be a regular file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(65537)
    finally:
        os.close(fd)
    if len(data) > 65536:
        raise ValueError('JSON input exceeds 64 KiB')
    def nonfinite(value):
        raise ValueError(f'nonfinite JSON value: {value}')
    return json.loads(data, object_pairs_hook=unique_pairs, parse_constant=nonfinite)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('snapshot', type=Path)
    parser.add_argument('request', type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(plan(load(args.snapshot), load(args.request)), indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, RecursionError) as error:
        print(json.dumps({'status': 'rejected', 'mutation': False, 'error': str(error)}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
