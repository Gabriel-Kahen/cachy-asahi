#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only sampled RSS of a trusted workload's original Linux process group.

RSS sums count shared pages in every process. They are neither unique physical
memory nor a true peak, and cannot see forks/exits between snapshots or detached
processes. No process is signalled and no cgroup/host configuration is changed.
"""
from pathlib import Path
import time

MAX_TASKS = 4096
MAX_MEMBERS = 512
SAMPLE_SECONDS = 0.1
SCOPE = 'original process group only; per-process RSS sum double-counts shared pages; sampled, not true peak'


def stat_identity(raw):
    first, last = raw.find('('), raw.rfind(')')
    if first < 1 or last < first:
        raise ValueError('malformed proc stat')
    pid, fields = int(raw[:first].strip()), raw[last + 1:].split()
    if len(fields) < 22 or pid <= 0:
        raise ValueError('incomplete proc stat')
    row = {'pid': pid, 'state': fields[0], 'group': int(fields[2]),
           'session': int(fields[3]), 'start_ticks': int(fields[19])}
    if row['group'] < 0 or row['session'] < 0 or row['start_ticks'] < 0:
        raise ValueError('invalid process identity')
    return row


def read(path, deadline):
    if time.monotonic() > deadline:
        raise ValueError('sample time budget exceeded')
    with path.open('rb') as stream:
        data = stream.read(16385)
    if len(data) > 16384:
        raise ValueError('proc input byte bound')
    return data.decode('ascii', errors='replace')


def members(procroot, group, deadline):
    result = {}
    count = 0
    for path in procroot.iterdir():
        if not path.name.isascii() or not path.name.isdecimal():
            continue
        count += 1
        if count > MAX_TASKS:
            raise ValueError('proc task scan bound')
        try:
            row = stat_identity(read(path / 'stat', deadline))
        except FileNotFoundError:
            # A process can exit before its group is observable. This is a
            # polling limitation, not a claim of atomic membership coverage.
            continue
        if row['pid'] != int(path.name):
            raise ValueError('proc identity/path mismatch')
        if row['group'] == group:
            if row['session'] != group:
                raise ValueError('workload session differs from original group')
            result[row['pid']] = row
            if len(result) > MAX_MEMBERS:
                raise ValueError('workload process group member bound')
    return result


def same_identity(row):
    return {key: value for key, value in row.items() if key != 'state'}


def sample(leader, procroot=Path('/proc')):
    started = time.monotonic_ns()
    report = {'status': 'unavailable', 'group_id': leader, 'rss_sum_kib': None,
              'members': [], 'scope': SCOPE, 'monotonic_start_ns': started}
    try:
        if type(leader) is not int or leader <= 0:
            raise ValueError('positive original process-group leader required')
        procroot = Path(procroot)
        deadline = time.monotonic() + SAMPLE_SECONDS
        before = members(procroot, leader, deadline)
        if not before:
            try:
                read(procroot / str(leader) / 'stat', deadline)
            except FileNotFoundError:
                report.update(status='exited', reason='no original process-group member or leader observed')
                return report
            raise ValueError('leader still present but original process group not observed')
        if leader not in before or before[leader]['session'] != leader:
            raise ValueError('original session leader identity unavailable')
        live = 0
        for pid, identity in sorted(before.items()):
            path = procroot / str(pid)
            raw = read(path / 'status', deadline)
            fields = [line.split() for line in raw.splitlines()]
            tgid = [row for row in fields if row and row[0] == 'Tgid:']
            if len(tgid) != 1 or len(tgid[0]) != 2 or int(tgid[0][1]) != pid:
                raise ValueError('one RSS observation per thread-group leader required')
            zombie = identity['state'] in ('Z', 'X')
            rss = [row for row in fields if row and row[0] == 'VmRSS:']
            if zombie:
                value = 0
            elif len(rss) == 1 and len(rss[0]) == 3 and rss[0][2] == 'kB' and rss[0][1].isdecimal():
                value = int(rss[0][1]); live += 1
            else:
                raise ValueError('live workload RSS missing/unreadable')
            current = stat_identity(read(path / 'stat', deadline))
            if current != identity:
                # Scheduler state commonly changes; stable identity and zombie
                # classification, rather than R/S state, are what matter.
                if same_identity(current) != same_identity(identity) or (current['state'] in ('Z', 'X')) != zombie:
                    raise ValueError('process exited/reused/changed group during RSS read')
            report['members'].append({**identity, 'rss_kib': value})
        after = members(procroot, leader, deadline)
        if {pid: same_identity(row) for pid, row in before.items()} != {pid: same_identity(row) for pid, row in after.items()}:
            raise ValueError('process group membership changed during sample')
        if any((before[pid]['state'] in ('Z', 'X')) != (after[pid]['state'] in ('Z', 'X')) for pid in before):
            raise ValueError('process exited during membership recheck')
        if live:
            report.update(status='complete', rss_sum_kib=sum(row['rss_kib'] for row in report['members']))
        else:
            report.update(status='exited', reason='only exited/zombie members observed')
    except (OSError, UnicodeError, ValueError, IndexError) as error:
        report.update(status='incomplete', rss_sum_kib=None, reason=type(error).__name__ + ': ' + str(error)[:200])
    finally:
        report['monotonic_end_ns'] = time.monotonic_ns()
    return report


def summarize(samples):
    complete = [row['rss_sum_kib'] for row in samples if row and row.get('status') == 'complete']
    exited = sum(bool(row and row.get('status') == 'exited') for row in samples)
    missing = len(samples) - len(complete) - exited
    identities = {(row['group_id'], next((member['start_ticks'] for member in row['members']
                                         if member['pid'] == row['group_id']), None))
                  for row in samples if row and row.get('status') == 'complete'}
    stable = len(identities) == 1 and all(start is not None for _, start in identities)
    return {'process_group_sampled_rss_kib': max(complete) if complete and not missing and stable else None,
            'process_group_observed_rss_kib': max(complete) if complete else None,
            'process_group_leader_identity_stable': stable if complete else None,
            'process_group_rss_coverage': {'complete_samples': len(complete), 'exited_samples': exited,
                                           'missing_or_incomplete_samples': missing},
            'process_group_rss_scope': SCOPE}
