#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
# Derived from reservation.py, SHA256 bd165fcc806c2951698cc16e1610ffb12a0da95404b5c99aaf3cdc067c1ea0e4.
"""Linux exclusive-child supervision. Call prepare() BEFORE creating the child.

Transfer the child's wait ownership and optional readable pipes to supervise().
Never poll/wait/reap it elsewhere. Group mode requires a fresh session leader;
direct mode targets only the owned child. No numeric operation follows reap/ECHILD.
The caller retains its inherited lease descriptor until this function returns.
"""
import math
import os
import signal
import stat
import subprocess
import threading
import time

TICK = 0.01
PROC_LIMIT = 131072
RSS_MAX_TASKS = 4096
RSS_MAX_MEMBERS = 512
RSS_MAX_SAMPLES = 4096
RSS_MAX_ROWS = 8192
RSS_SAMPLE_SECONDS = 0.1
RSS_SCOPE = 'original process group only; per-process RSS sum double-counts shared pages; sampled, not true peak'


def prepare():
    """Before launch: require the main thread, exclusive waits and SIG_DFL.

    Reinstall DFL to clear an inherited SA_NOCLDWAIT even if getsignal says DFL.
    Other threads must never reap this child or change SIGCHLD during custody.
    """
    if threading.current_thread() is not threading.main_thread():
        raise ValueError('prepare requires the main thread')
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise ValueError('SIGCHLD must be SIG_DFL before launch')
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)


def _stat(pid, *, with_parent=False):
    if type(with_parent) is not bool:
        raise ValueError('boolean parentage DATA selection required')
    fd = os.open('/proc/' + str(pid) + '/stat', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        raw = os.read(fd, 4097)
    finally:
        os.close(fd)
    head, sep, tail = raw.rpartition(b')')
    fields = tail.split()
    if len(raw) > 4096 or not sep or b'(' not in head or len(fields) < 20:
        raise ValueError('invalid bounded proc stat')
    row = (int(head.split(b'(', 1)[0]), fields[0], int(fields[2]),
           int(fields[3]), int(fields[19]))
    return (*row, int(fields[1])) if with_parent else row


def _members(pid, deadline, *, live=False, owned):
    """Bounded reserved-leader census; ownership precedes every numeric read."""
    found = set()
    owned()
    with os.scandir('/proc') as entries:
        for count, entry in enumerate(entries, 1):
            if count > PROC_LIMIT or time.monotonic() >= deadline:
                raise TimeoutError('proc census cap')
            if not entry.name.isascii() or not entry.name.isdecimal():
                continue
            owned()
            if time.monotonic() >= deadline:
                raise TimeoutError('proc census deadline')
            try:
                row = _stat(int(entry.name))
            except (ProcessLookupError, FileNotFoundError):
                continue
            if row[0] != int(entry.name):
                raise ValueError('proc identity mismatch')
            if row[2:4] == (pid, pid) and not (live and row[1] in (b'Z', b'X')):
                found.add((row[0], row[4], row[1]))
    owned()
    return found


def _rss_members(pid, deadline, owned, parentage=None, retired_pid=None):
    """Owned scan; optional PPIDs are DATA from the same bounded stat reads."""
    if parentage is not None and (type(parentage) is not dict or parentage):
        raise ValueError('fresh bounded parentage DATA map required')
    if retired_pid is not None and (type(retired_pid) is not int or not 0 < retired_pid < 2**31 or retired_pid == pid):
        raise ValueError('one exact retired adopted-child PID guard required')
    found = {}
    owned()
    with os.scandir('/proc') as entries:
        tasks = 0
        for count, entry in enumerate(entries, 1):
            if count > PROC_LIMIT or time.monotonic() >= deadline:
                raise TimeoutError('RSS scan deadline/entry bound')
            if not entry.name.isascii() or not entry.name.isdecimal():
                continue
            if retired_pid is not None and int(entry.name) == retired_pid:
                raise ValueError('retired adopted-child PID encountered; no numeric probe')
            tasks += 1
            if tasks > RSS_MAX_TASKS:
                raise ValueError('RSS task bound')
            owned()
            if time.monotonic() >= deadline:
                raise TimeoutError('RSS scan deadline')
            try:
                row = (_stat(int(entry.name)) if parentage is None
                       else _stat(int(entry.name), with_parent=True))
            except (FileNotFoundError, ProcessLookupError):
                continue
            if row[0] != int(entry.name):
                raise ValueError('RSS proc identity/path mismatch')
            if row[2] == pid:
                if row[3] != pid:
                    raise ValueError('RSS original session differs')
                found[row[0]] = dict(pid=row[0], state=row[1].decode('ascii'),
                                     group=row[2], session=row[3], start_ticks=row[4])
                if len(found) > RSS_MAX_MEMBERS:
                    raise ValueError('RSS group member bound')
                if parentage is not None:
                    parentage[row[0]] = row[5]
    return found


def _rss_identity(row):
    return {key: value for key, value in row.items() if key not in ('state', 'rss_kib')}


def _rss_sample(pid, start_ticks, deadline, owned, remaining):
    """Bounded original-group RSS DATA; no public callback or signaling path."""
    report = dict(status='incomplete', group_id=pid, rss_sum_kib=None, members=[],
                  scope=RSS_SCOPE, monotonic_start_ns=time.monotonic_ns())
    try:
        before = _rss_members(pid, deadline, owned)
        if pid not in before or before[pid]['start_ticks'] != start_ticks:
            raise ValueError('RSS reserved leader identity unavailable')
        if len(before) > remaining:
            raise ValueError('RSS retained member-row bound')
        live = 0
        for member, identity in sorted(before.items()):
            owned()
            if time.monotonic() >= deadline:
                raise TimeoutError('RSS status deadline')
            fd = os.open('/proc/' + str(member) + '/status',
                         os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                raw = os.read(fd, 16385)
            finally:
                os.close(fd)
            if len(raw) > 16384:
                raise ValueError('RSS proc input byte bound')
            fields = [line.split() for line in raw.splitlines()]
            tgid = [row for row in fields if row and row[0] == b'Tgid:']
            if len(tgid) != 1 or len(tgid[0]) != 2 or int(tgid[0][1]) != member:
                raise ValueError('RSS requires thread-group leader')
            zombie = identity['state'] in ('Z', 'X')
            rss = [row for row in fields if row and row[0] == b'VmRSS:']
            if zombie:
                value = 0
            elif len(rss) == 1 and len(rss[0]) == 3 and rss[0][2] == b'kB' and rss[0][1].isdigit():
                value = int(rss[0][1])
                live += 1
            else:
                raise ValueError('live workload RSS missing/unreadable')
            owned()
            if time.monotonic() >= deadline:
                raise TimeoutError('RSS identity deadline')
            current = _stat(member)
            if ((current[0], current[2], current[3], current[4]) !=
                    (member, identity['group'], identity['session'], identity['start_ticks'])
                    or (current[1] in (b'Z', b'X')) != zombie):
                raise ValueError('RSS process exited/reused/changed group')
            report['members'].append(dict(identity, rss_kib=value))
        after = _rss_members(pid, deadline, owned)
        if {p: _rss_identity(r) for p, r in before.items()} != {p: _rss_identity(r) for p, r in after.items()}:
            raise ValueError('RSS group membership changed during sample')
        if any((before[p]['state'] in ('Z', 'X')) != (after[p]['state'] in ('Z', 'X')) for p in before):
            raise ValueError('RSS process exited during membership recheck')
        owned()
        if time.monotonic() >= deadline:
            raise TimeoutError('RSS sample deadline')
        report.update(status='complete' if live else 'exited',
                      rss_sum_kib=sum(row['rss_kib'] for row in report['members']) if live else None)
    except (OSError, ValueError, TimeoutError, UnicodeError) as exc:
        report.update(status='incomplete', reason=type(exc).__name__ + ': ' + str(exc)[:200])
    finally:
        report['monotonic_end_ns'] = time.monotonic_ns()
    return report


def _rss_summary(samples, interval, problem):
    complete = [row for row in samples if row['status'] == 'complete']
    exited = sum(row['status'] == 'exited' for row in samples)
    missing = len(samples) - len(complete) - exited
    identities = {(row['group_id'], next((m['start_ticks'] for m in row['members']
                   if m['pid'] == row['group_id']), None)) for row in complete}
    stable = len(identities) == 1 and all(start is not None for _, start in identities)
    usable = bool(complete) and not missing and stable and problem is None
    observed = max((row['rss_sum_kib'] for row in complete), default=None)
    leader = [m['rss_kib'] for row in complete for m in row['members']
              if m['pid'] == row['group_id'] and m['state'] not in ('Z', 'X')]
    return dict(status='complete' if usable else 'partial' if complete else 'error' if problem else 'unavailable',
                error=problem, interval_seconds=interval, sample_budget_seconds=RSS_SAMPLE_SECONDS,
                scope=RSS_SCOPE, samples=samples,
                process_group_sampled_rss_kib=observed if usable else None,
                process_group_observed_rss_kib=observed,
                process_group_leader_identity_stable=stable if complete else None,
                process_group_rss_coverage=dict(complete_samples=len(complete), exited_samples=exited,
                                                missing_or_incomplete_samples=missing),
                process_group_rss_scope=RSS_SCOPE,
                leader_sampled_rss_kib=max(leader) if usable and leader else None,
                leader_observed_rss_kib=max(leader) if leader else None)


def _rss_failure(pid, reason):
    stamp = time.monotonic_ns()
    return dict(status='incomplete', kind='observation_error', group_id=pid,
                rss_sum_kib=None, members=[], scope=RSS_SCOPE, reason=reason,
                monotonic_start_ns=stamp, monotonic_end_ns=stamp)


def supervise(child, *, cap, retirement=1.0, grace=0.2, group=True,
              streams=None, max_output=512 * 1024, log_fd=None, rss_interval=None):
    """Own one Popen or direct-fork PID through the LAST signal, then raw reap.

    cap includes retirement; retirement starts at natural exit, failure or the
    run deadline, whichever comes first. No wait can block. streams are binary
    pipe objects transferred to this function (default: Popen stdout/stderr).
    Combined captured bytes are bounded. An optional borrowed nonblocking log_fd
    receives each chunk; short/failed writes fail the run. Log consumers receive
    bytes only and must never signal children. No logger threads are created.

    Returncode is valid ONLY if reaped=True. UNKNOWN ownership forbids further
    numeric signals/probes. A Popen is unusable for further wait/poll operations
    after transfer, including when its raw exit status remains unknown.

    Every grouped mode requires a complete reserved-terminal-leader-only proof
    before the consuming wait; no numeric child/proc access follows reap/ECHILD.
    rss_interval optionally enables bounded built-in original-group RSS samples
    while WNOWAIT-owned. There is no arbitrary observation callback. Incomplete
    RSS fails the optional run; observed peaks never substitute for data.
    """
    started = time.monotonic()
    for value in (cap, retirement, grace):
        if type(value) not in (int, float) or not math.isfinite(value):
            raise ValueError('finite numeric deadlines required')
    if not 0 < retirement < cap or not 0 <= grace < retirement:
        raise ValueError('require 0 <= grace < retirement < cap')
    if type(group) is not bool or type(max_output) is not int or max_output < 0:
        raise ValueError('boolean group and nonnegative output cap required')
    if rss_interval is not None and (not group or type(rss_interval) not in (int, float)
                                    or not math.isfinite(rss_interval) or not .01 <= rss_interval <= 60):
        raise ValueError('RSS requires group mode and finite interval in [0.01, 60]')
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise ValueError('exclusive SIG_DFL child ownership required')
    popen = child if isinstance(child, subprocess.Popen) else None
    pid = popen.pid if popen is not None else child
    if type(pid) is not int or pid <= 0 or (popen is not None and popen.returncode is not None):
        raise ValueError('fresh positive owned child PID required')
    if log_fd is not None and (type(log_fd) is not int or log_fd < 0
                              or os.get_blocking(log_fd)
                              or not (stat.S_ISFIFO(os.fstat(log_fd).st_mode)
                                      or stat.S_ISSOCK(os.fstat(log_fd).st_mode))
                              or signal.getsignal(signal.SIGPIPE) != signal.SIG_IGN):
        raise ValueError('borrowed nonblocking log pipe/socket and ignored SIGPIPE required')
    if streams is None:
        streams = () if popen is None else tuple(p for p in (popen.stdout, popen.stderr) if p is not None)
    if type(streams) not in (tuple, list) or len(streams) > 2 or len({id(p) for p in streams}) != len(streams):
        raise ValueError('at most two distinct fresh binary pipes required')
    pipes = list(streams)
    deadline = started + cap
    run_end = deadline - retirement
    retire_end = None
    term_end = None
    identity = None
    terminal = None
    ownership = 'OWNED'
    reaped = False
    signaling_over = False
    exitcode = None
    timed_out = False
    sent = []
    output = bytearray()
    error = None
    census = 'NOT_OBSERVED'
    group_retirement = None
    pipes_ready = False
    rss_samples = []
    rss_rows = 0
    rss_due = started
    rss_problem = None

    def fail(exc):
        nonlocal error
        if error is None:
            error = type(exc).__name__ + ': ' + str(exc)[:300]

    def peek():
        nonlocal ownership, terminal
        if ownership != 'OWNED' or reaped:
            raise ValueError('child probe after ownership release refused')
        try:
            row = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG)
        except ChildProcessError:
            ownership = 'UNKNOWN'
            raise ValueError('ECHILD: wait ownership lost; no further numeric operations')
        if row is not None:
            if row.si_pid != pid or row.si_code not in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED):
                ownership = 'UNKNOWN'
                raise ValueError('unexpected child status; ownership unknown')
            code = row.si_status if row.si_code == os.CLD_EXITED else -row.si_status
            if terminal is not None and code != terminal:
                ownership = 'UNKNOWN'
                raise ValueError('reserved terminal status changed')
            terminal = code
        return terminal is not None

    def verify():
        nonlocal identity, ownership
        peek()  # Must precede any numeric proc access or signal.
        row = _stat(pid)
        key = (row[0], row[2], row[3], row[4]) if group else (row[0], row[4])
        if row[0] != pid or (group and row[2:4] != (pid, pid)) or (identity and key != identity):
            ownership = 'UNKNOWN'
            raise ValueError('owned child identity/session differs')
        identity = key

    def send(sig):
        if signaling_over or ownership != 'OWNED':
            raise ValueError('signal after release refused')
        verify()
        try:
            (os.killpg if group else os.kill)(pid, sig)
            sent.append(sig)
        except ProcessLookupError:
            pass

    def live():
        verify()
        # Leave part of the existing retirement budget for final KILL/raw reap
        # if a census exhausts its own bounded scan. Never renew that budget.
        until = min(deadline, retire_end - min(.05, retirement / 4)
                    if retire_end is not None else deadline)
        if group and rss_interval is not None:
            return any(row['state'] not in ('Z', 'X') for row in _rss_members(pid, until, peek).values())
        return bool(_members(pid, until, live=True, owned=peek)) if group else terminal is None

    def drain():
        # One bounded read per pipe per iteration; no blocking logger callback.
        for pipe in pipes[:]:
            try:
                data = os.read(pipe.fileno(), min(65536, max_output - len(output) + 1))
            except BlockingIOError:
                continue
            if not data:
                pipes.remove(pipe)
                pipe.close()
                continue
            remaining = max_output - len(output)
            output.extend(data[:remaining])
            if len(data) > remaining:
                raise ValueError('combined output cap exceeded')
            if log_fd is not None and error is None:
                if os.write(log_fd, data) != len(data):
                    raise OSError('short nonblocking log write')

    def pause(until):
        time.sleep(max(0, min(TICK, until - time.monotonic())))

    try:
        verify()
        descriptors = [pipe.fileno() for pipe in pipes]
        if len(set(descriptors)) != len(descriptors) or any(
                not stat.S_ISFIFO(os.fstat(fd).st_mode) for fd in descriptors):
            raise ValueError('distinct readable pipe descriptors required')
        for fd in descriptors:
            os.set_blocking(fd, False)
        pipes_ready = True
        while time.monotonic() < deadline:
            peek()
            if rss_interval is not None and retire_end is None and error is None and time.monotonic() >= rss_due:
                verify()
                if len(rss_samples) >= RSS_MAX_SAMPLES - 1:
                    rss_problem = 'RSS retained sample bound'
                    rss_samples.append(_rss_failure(pid, rss_problem))
                    fail(ValueError(rss_problem))
                else:
                    sample = _rss_sample(pid, identity[3], min(run_end, time.monotonic() + RSS_SAMPLE_SECONDS),
                                         peek, RSS_MAX_ROWS - rss_rows)
                    rss_samples.append(sample)
                    rss_rows += len(sample['members'])
                    rss_due = sample['monotonic_start_ns'] / 1e9 + rss_interval
                    if sample['status'] == 'incomplete':
                        rss_problem = sample['reason']
                        fail(ValueError(rss_problem))
                    if ownership != 'OWNED':
                        raise ValueError('RSS observation lost child wait ownership')
            try:
                drain()
            except (OSError, ValueError) as exc:
                fail(exc)
            now = time.monotonic()
            if retire_end is None and (terminal is not None or error or now >= run_end):
                timed_out = now >= run_end
                retire_end = min(deadline, now + retirement)
            if retire_end is not None:
                active = live()
                if active and term_end is None:
                    send(signal.SIGTERM)
                    term_end = min(retire_end - min(.05, retirement / 4), now + grace)
                elif active and time.monotonic() >= term_end and signal.SIGKILL not in sent:
                    send(signal.SIGKILL)
                if terminal is not None and not active and not pipes:
                    break
                if time.monotonic() >= retire_end - min(.05, retirement / 4):
                    if active and signal.SIGKILL not in sent:
                        send(signal.SIGKILL)
                    while time.monotonic() < retire_end:
                        peek()
                        try:
                            drain()
                        except (OSError, ValueError) as exc:
                            fail(exc)
                        if terminal is not None and not pipes:
                            break
                        pause(retire_end)
                    if terminal is None or pipes:
                        fail(TimeoutError('retirement cap; status/output may be incomplete'))
                    break
            pause(retire_end if retire_end is not None else run_end)
    except BaseException as exc:
        fail(exc)
        if ownership == 'OWNED' and not signaling_over:
            try:
                send(signal.SIGKILL)
                retire_end = min(deadline, retire_end if retire_end is not None else deadline,
                                 time.monotonic() + retirement)
                while time.monotonic() < retire_end and not peek():
                    pause(retire_end)
            except BaseException as cleanup:
                fail(cleanup)
    finally:
        if group and ownership == 'OWNED' and terminal is not None:
            # All grouped modes prove membership while the leader is reserved.
            # A complete census must contain only this exact reserved zombie.
            try:
                verify()
                until = min(deadline, retire_end if retire_end is not None else deadline)
                parentage = {}
                members = _rss_members(pid, until, peek, parentage=parentage)
                verify()
                # Exclusive waits remain the caller's contract for this group.
                # PPID selects a candidate; only its own WNOWAIT grants custody.
                wait_owner_pid = os.getpid()
                adoption = None
                def snapshot():
                    selected = sorted(members)[:32]
                    value = dict(phase='PRE_REAP',
                        reserved_leader=dict(pid=pid, start_ticks=identity[3]),
                        wait_owner_pid=wait_owner_pid, wait_owner_subreaper='NOT_OBSERVED',
                        member_count=len(members), members=[dict(members[p], ppid=parentage[p],
                            parent_relation=('WAIT_OWNER_PID' if parentage[p] == wait_owner_pid else
                                'RESERVED_LEADER_PID' if parentage[p] == pid else
                                'PID1' if parentage[p] == 1 else 'OTHER')) for p in selected],
                        truncated=len(members) > len(selected))
                    if adoption is not None:value['adopted_child'] = adoption
                    return value
                group_retirement = snapshot()
                initial_leader = members.get(pid)
                sole = (len(members) == 1 and initial_leader is not None
                    and initial_leader['start_ticks'] == identity[3]
                    and initial_leader['state'] in ('Z', 'X'))
                if not sole:
                    extras = [p for p in members if p != pid]
                    candidate = (next(r for r in group_retirement['members'] if r['pid'] == extras[0])
                        if len(members) == 2 and len(extras) == 1 else None)
                    adoption = dict(schema=1, status='REFUSED_ONE_ADOPTED_CHILD',
                        candidate=candidate, initial_member_count=len(members), initial_scan_complete=True,
                        waitid=dict(observed=False, pid=None, code='NOT_OBSERVED', status=None),
                        identity_reverified=False, leader_reserved_before_reap=False,
                        raw_reap=dict(attempted=False, pid=None, exit=None, status_matches=False),
                        ownership='NOT_ACQUIRED', target_queries_closed=True, before_leader_reap=True,
                        final_scan_complete=False, final_census='NOT_REACHED', refusal='INELIGIBLE_MEMBER_SET')
                    group_retirement['adopted_child'] = adoption
                    eligible = (candidate is not None and initial_leader is not None
                        and initial_leader['start_ticks'] == identity[3] and initial_leader['state'] == 'Z'
                        and candidate['state'] == 'Z' and candidate['ppid'] == wait_owner_pid)
                    if candidate is not None and not eligible:adoption['refusal'] = 'EXTRA_NOT_OWN_ZOMBIE'
                    if eligible:
                        extra = candidate['pid']; extra_terminal = None
                        adoption['target_queries_closed'] = False
                        def within():
                            if time.monotonic() >= until:
                                adoption['refusal'] = 'DEADLINE'
                                raise TimeoutError('existing retirement deadline exhausted')
                        def extra_peek():
                            nonlocal extra_terminal
                            if adoption['target_queries_closed']:
                                raise ValueError('adopted-child query after authority closure refused')
                            within()
                            try:
                                row = os.waitid(os.P_PID, extra, os.WEXITED | os.WNOWAIT | os.WNOHANG)
                            except ChildProcessError:
                                adoption['refusal'] = 'EXTRA_ECHILD'
                                raise
                            if row is None:
                                adoption['refusal'] = 'EXTRA_NOT_TERMINAL'
                                raise ValueError('adopted child is not WNOWAIT terminal')
                            names = {os.CLD_EXITED: 'CLD_EXITED', os.CLD_KILLED: 'CLD_KILLED', os.CLD_DUMPED: 'CLD_DUMPED'}
                            if (type(row.si_pid) is not int or row.si_pid != extra or type(row.si_code) is not int or row.si_code not in names
                                    or type(row.si_status) is not int or not 0 <= row.si_status <= 255
                                    or row.si_code != os.CLD_EXITED and row.si_status == 0):
                                adoption['refusal'] = 'EXTRA_STATUS_MISMATCH'
                                raise ValueError('exact adopted-child terminal status required')
                            observed = dict(observed=True, pid=extra, code=names[row.si_code], status=row.si_status)
                            if adoption['waitid']['observed'] and adoption['waitid'] != observed:
                                adoption['refusal'] = 'EXTRA_STATUS_MISMATCH'
                                raise ValueError('reserved adopted-child status changed')
                            adoption['waitid'] = observed; adoption['ownership'] = 'WNOWAIT_RESERVED'
                            extra_terminal = row.si_status if row.si_code == os.CLD_EXITED else -row.si_status
                        try:
                            adoption['refusal'] = 'LEADER_RESERVATION_UNQUALIFIED'
                            within(); verify(); extra_peek()
                            adoption['refusal'] = 'EXTRA_IDENTITY_UNQUALIFIED'
                            verify(); extra_peek(); within()
                            current = _stat(extra, with_parent=True)
                            if current != (extra, b'Z', pid, pid, candidate['start_ticks'], wait_owner_pid):
                                raise ValueError('adopted-child PID/start/group/session/PPID differs')
                            adoption['identity_reverified'] = True
                            adoption['refusal'] = 'LEADER_RESERVATION_UNQUALIFIED'
                            verify(); extra_peek(); within()
                            adoption['leader_reserved_before_reap'] = True
                            adoption['target_queries_closed'] = True
                            adoption['raw_reap']['attempted'] = True
                            adoption['refusal'] = 'EXTRA_RAW_WAIT_UNQUALIFIED'
                            try:got, status = os.waitpid(extra, os.WNOHANG)
                            except ChildProcessError:
                                adoption['refusal'] = 'EXTRA_ECHILD'
                                raise
                            adoption['raw_reap']['pid'] = got if type(got) is int and 0 <= got < 2**31 else None
                            if type(got) is not int or got != extra:
                                raise ValueError('exact adopted-child consuming wait required')
                            adoption['ownership'] = 'REAPED'
                            if type(status) is not int:raise ValueError('observed adopted-child raw status required')
                            observed_exit = os.waitstatus_to_exitcode(status)
                            adoption['raw_reap'].update(exit=observed_exit, status_matches=observed_exit == extra_terminal)
                            if observed_exit != extra_terminal:raise ValueError('adopted-child raw/reserved status differs')
                            if observed_exit != 0:
                                adoption['refusal'] = 'EXTRA_NONZERO'
                                raise ValueError('only zero adopted-child exit qualifies')
                            adoption['refusal'] = 'FINAL_CENSUS_UNAVAILABLE'; adoption['final_census'] = 'UNKNOWN'
                            within(); parentage = {}
                            members = _rss_members(pid, until, peek, parentage=parentage, retired_pid=extra)
                            verify(); within(); adoption['final_scan_complete'] = True
                        except BaseException as exc:
                            adoption['target_queries_closed'] = True
                            if adoption['ownership'] != 'REAPED':adoption['ownership'] = 'UNKNOWN'
                            fail(exc)
                            raise ValueError('one adopted-child retirement refused: ' + adoption['refusal'])
                only = members.get(pid)
                if (len(members) == 1 and only is not None and only['start_ticks'] == identity[3]
                        and only['state'] in ('Z', 'X')):
                    census = 'RESERVED_LEADER_ONLY'
                else:
                    census = 'RESERVED_MEMBERS_REMAIN'
                if adoption is not None:
                    adoption['final_census'] = census
                    if adoption['final_scan_complete']:
                        if census == 'RESERVED_LEADER_ONLY':
                            adoption.update(status='QUALIFIED_ONE_ADOPTED_CHILD_REAPED', refusal='NONE')
                        else:adoption['refusal'] = 'FINAL_NOT_SOLE'
                group_retirement = snapshot()
            except (OSError, ValueError, TimeoutError) as exc:
                census = 'UNKNOWN'
                fail(exc)
        # No path, including a raw-wait exception, can signal after this point.
        signaling_over = True
        if ownership == 'OWNED':
            try:
                if peek():
                    got, status = os.waitpid(pid, os.WNOHANG)
                    if got != pid:
                        raise ValueError('reserved raw wait did not reap child')
                    exitcode = os.waitstatus_to_exitcode(status)
                    reaped = True
                    ownership = 'REAPED'
                    if exitcode != terminal:
                        raise ValueError('raw wait differs from reserved terminal status')
            except ChildProcessError:
                ownership = 'UNKNOWN'
                fail(ValueError('ECHILD during raw reap; exit remains unknown'))
            except BaseException as exc:
                ownership = 'UNKNOWN' if not reaped else 'REAPED'
                fail(exc)
        if popen is not None:
            if reaped:
                popen.returncode = exitcode
            else:
                # CPython's destructor otherwise calls waitpid and may translate
                # ECHILD into zero. Ownership has transferred; suppress that path.
                popen._child_created = False
        for pipe in pipes:
            try:
                pipe.close()
            except OSError as exc:
                fail(exc)
    elapsed = time.monotonic() - started
    result = dict(exit=exitcode, reaped=reaped, ownership=ownership, timeout=timed_out,
                signals=[signal.Signals(sig).name for sig in sent], output=bytes(output),
                output_complete=pipes_ready and not pipes, group_census=census, group_retirement=group_retirement,
                error=error, seconds=elapsed,
                passed=reaped and exitcode == 0 and not timed_out and not sent
                and error is None and elapsed < cap and not pipes
                and (not group or census == 'RESERVED_LEADER_ONLY'))
    if rss_interval is not None:
        if ownership != 'REAPED':
            rss_problem = rss_problem or 'RSS wait ownership/reap unconfirmed'
            if not any(row['status'] == 'incomplete' for row in rss_samples):
                rss_samples.append(_rss_failure(pid, rss_problem))
        result['rss'] = _rss_summary(rss_samples, rss_interval, rss_problem)
        if result['rss']['status'] != 'complete' or result['rss']['leader_sampled_rss_kib'] is None:
            result['passed'] = False
            result['error'] = result['error'] or 'RSS unavailable/incomplete; no usable live-leader/group observations'
    return result


if __name__ == '__main__':
    print(__doc__)
