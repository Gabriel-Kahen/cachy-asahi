# SPDX-License-Identifier: MIT
"""Single-reaper Linux supervision: reserve through last signal, then reap once.

No Popen wait/poll path is used. Loss/unverified ownership permanently forbids
numeric group actions. After reap only a non-signalling /proc census is used.
Original group/session absence is not arbitrary detached-descendant retirement;
the outer namespace and caller's ordinary-process gate remain required.
"""
import errno
import math
import os
from pathlib import Path
import signal
import subprocess
import threading
import time

_DETACHED_POPEN_STATUS = -2147483648  # Finalizer bookkeeping, never an observed exit.


def _need(ok, why):
    if not ok:
        raise ValueError(why)


def _policy():
    _need(threading.current_thread() is threading.main_thread() and threading.active_count() == 1 and
          signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, 'exclusive default-SIGCHLD reaper required')
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)  # Clear inherited SA_NOCLDWAIT before launch.


def _census(pgid, sid):
    rows, errors = [], []
    try:
        nodes = list(Path('/proc').iterdir())
        _need(len(nodes) <= 8192, 'bounded process census required')
    except (OSError, ValueError) as error:
        return dict(complete=False, members=[], error_types=[type(error).__name__])
    for path in nodes:
        if not path.name.isdigit():
            continue
        try:
            raw = (path/'stat').read_bytes()
            _need(len(raw) <= 4096, 'bounded process stat required')
            fields = raw[raw.rfind(b')')+2:].split()
            group, session = int(fields[2]), int(fields[3])
            if group == pgid or session == sid:
                rows.append(dict(pid=int(path.name), state=fields[0].decode(), ppid=int(fields[1]),
                                 pgid=group, sid=session, start_ticks=int(fields[19])))
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (OSError, ValueError, IndexError, UnicodeError) as error:
            errors.append(type(error).__name__)
    return dict(complete=not errors, members=sorted(rows, key=lambda r:r['pid']), error_types=errors[:16])


def refresh(receipt):
    """After the caller's adopted-child drain: /proc only, never a group syscall."""
    if receipt['ownership'] != 'REAPED' or receipt['reap_count'] != 1:
        receipt.update(group_absent=None, retirement='UNKNOWN')
        return receipt
    census = _census(receipt['pid'], receipt['pid'])
    receipt['census'] = census
    receipt['audit'].append(dict(event='CENSUS_AFTER_REAP', complete=census['complete'], members=len(census['members'])))
    if not census['complete']:
        receipt.update(group_absent=None, retirement='UNKNOWN')
    elif census['members']:
        receipt.update(group_absent=False, retirement='PRESENT')
    else:
        receipt.update(group_absent=True, retirement='VERIFIED_ABSENT')
    return receipt


def assert_verified(receipt):
    """Pure offline receipt check. It cannot establish unrecorded execution."""
    _need(type(receipt['pid']) is int and receipt['pid'] > 0 and type(receipt['observations']) is int and
          receipt['observations'] > 0 and type(receipt['exit']) is int and type(receipt['wait_status']) is int and
          receipt['completed'] is True and receipt['timed_out'] is False and receipt['exit'] == 0 and
          receipt['ownership'] == 'REAPED' and type(receipt['reap_count']) is int and receipt['reap_count'] == 1 and
          receipt['group_absent'] is True and receipt['retirement'] == 'VERIFIED_ABSENT',
          'completed command with observed exit and verified retirement required')
    audit = receipt['audit']
    allowed={'LAUNCHED_NEW_SESSION','WNOWAIT_VERIFIED','WNOWAIT_EXIT','OWNERSHIP_BEFORE_SIGNAL',
             'SIGNAL_RESERVED_GROUP','RESERVED_GROUP_NOT_PRESENT','REAP_LEADER_ONCE','CENSUS_AFTER_REAP'}
    _need(audit and audit[0] == dict(event='LAUNCHED_NEW_SESSION',pid=receipt['pid']) and
          all(event['event'] in allowed for event in audit) and not receipt.get('interruption_type'),
          'complete reservation audit without unknown/failed transitions required')
    reaps = [i for i, event in enumerate(audit) if event['event'] == 'REAP_LEADER_ONCE']
    _need(len(reaps) == 1 and os.waitstatus_to_exitcode(audit[reaps[0]]['wait_status']) == receipt['exit'] and
          receipt['wait_status'] == audit[reaps[0]]['wait_status'], 'one actual final leader reap required')
    _need(any(event['event'] == 'WNOWAIT_VERIFIED' for event in audit[:reaps[0]]) and
          not any(event['event'] in ('RESERVATION_LOST', 'SIGNAL_FAILED') for event in audit),
          'unbroken verified leader reservation required')
    exits=[event for event in audit[:reaps[0]] if event['event']=='WNOWAIT_EXIT']
    _need(exits == [dict(event='WNOWAIT_EXIT',code=os.CLD_EXITED,status=0)],
          'observed reserved natural exit0 required')
    signals = []
    for i, event in enumerate(audit):
        if event['event'] == 'SIGNAL_RESERVED_GROUP':
            _need(i < reaps[0] and i > 0 and audit[i-1]['event'] == 'OWNERSHIP_BEFORE_SIGNAL' and
                  event['signal'] in (signal.SIGTERM, signal.SIGKILL), 'signal must follow reserved ownership before reap')
            signals.append(event['signal'])
        if i > reaps[0]:
            _need(event['event'] == 'CENSUS_AFTER_REAP', 'only safe census allowed after leader reap')
    _need(signals == receipt['signals'] and receipt['census']['complete'] is True and not receipt['census']['members'] and
          audit[-1]['event'] == 'CENSUS_AFTER_REAP' and audit[-1]['complete'] is True and audit[-1]['members'] == 0,
          'matching last post-reap /proc census required')


def run(argv, seconds, *, cwd=None, env=None, stdout=None, stderr=None, term_seconds=3, kill_seconds=2):
    """Finite execution/TERM/KILL budgets. Output belongs to supplied files.

    Exit comes only from our successful waitpid. UNKNOWN, timed_out or incomplete
    results must fail. PIPE is refused because this helper does not drain pipes.
    """
    for value, limit in ((seconds, 3600), (term_seconds, 10), (kill_seconds, 10)):
        _need(type(value) in (int, float) and math.isfinite(value) and 0 < value <= limit,
              'finite command and retirement budgets required')
    _need(type(argv) in (list, tuple) and argv and all(type(x) is str for x in argv), 'explicit argv required')
    _need(stdout != subprocess.PIPE and stderr != subprocess.PIPE, 'file-output supervisor requires drained files')
    _policy()
    started = time.monotonic()
    child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL if stdout is None else stdout,
        stderr=subprocess.DEVNULL if stderr is None else stderr, start_new_session=True)
    result = dict(pid=child.pid, exit=None, wait_status=None, reap_count=0, ownership='RESERVED',
        observations=0, completed=False, timed_out=False, group_absent=None, retirement='UNKNOWN',
        signals=[], audit=[dict(event='LAUNCHED_NEW_SESSION', pid=child.pid)],
        scope='ORIGINAL_GROUP_AND_SESSION_CENSUS; OUTER_NAMESPACE_REQUIRED_FOR_DETACHED_DESCENDANTS')
    reservation, exited = True, False

    def lose(reason, error=None):
        nonlocal reservation
        reservation = False
        result['ownership'] = 'LOST' if reason in ('ECHILD', 'CACHED_REAPED_STATUS') else 'UNVERIFIED'
        result['exit'] = None
        result['completed'] = False
        result['reason'] = reason
        result['audit'].append(dict(event='RESERVATION_LOST', reason=reason,
                                    error_type=type(error).__name__ if error else None))

    def observe():
        nonlocal exited
        if not reservation:
            return False
        if child.returncode is not None:
            lose('CACHED_REAPED_STATUS')
            return False
        try:
            info = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            result['observations'] += 1
            if result['observations'] == 1:
                result['audit'].append(dict(event='WNOWAIT_VERIFIED'))
            if info is not None:
                _need(info.si_pid == child.pid, 'unexpected waitid leader')
                if not exited:
                    result['audit'].append(dict(event='WNOWAIT_EXIT', code=info.si_code, status=info.si_status))
                exited = True
            return True
        except (OSError, ValueError) as error:
            lose('ECHILD' if isinstance(error, ChildProcessError) or getattr(error, 'errno', None) == errno.ECHILD
                 else 'WAITID_UNVERIFIED', error)
            return False

    def send(sig):
        if not observe():
            return False
        result['audit'].append(dict(event='OWNERSHIP_BEFORE_SIGNAL', observation=result['observations']))
        try:
            os.killpg(child.pid, sig)
            result['signals'].append(int(sig))
            result['audit'].append(dict(event='SIGNAL_RESERVED_GROUP', signal=int(sig)))
            return True
        except ProcessLookupError:
            result['audit'].append(dict(event='RESERVED_GROUP_NOT_PRESENT', signal=int(sig)))
            return True
        except OSError as error:
            result['reason'] = 'SIGNAL_FAILED'
            result['audit'].append(dict(event='SIGNAL_FAILED', error_type=type(error).__name__))
            return False

    def live_other_members():
        census = _census(child.pid, child.pid)
        result['reserved_census'] = census
        return not census['complete'] or any(r['pid'] != child.pid and r['state'] != 'Z' for r in census['members'])

    try:
        end = started+seconds
        while observe() and not exited:
            if time.monotonic() >= end:
                result['timed_out'] = True
                break
            time.sleep(min(.02, max(0, end-time.monotonic())))
        result['completed'] = reservation and exited and time.monotonic() <= end
        if not result['completed'] and time.monotonic() >= end:
            result['timed_out'] = True
    except BaseException as error:
        result.update(reason='INTERRUPTED', interruption_type=type(error).__name__)
    finally:
        try:
            # Keep a naturally exited leader reserved while descendants retire.
            if observe() and (not exited or live_other_members()):
                send(signal.SIGTERM)
                end = time.monotonic()+term_seconds
                while reservation and time.monotonic() < end:
                    if not observe() or (exited and not live_other_members()):
                        break
                    time.sleep(min(.02, max(0, end-time.monotonic())))
                if reservation and (not exited or live_other_members()):
                    send(signal.SIGKILL)
            end = time.monotonic()+kill_seconds
            while reservation and observe() and time.monotonic() < end and (not exited or live_other_members()):
                time.sleep(min(.02, max(0, end-time.monotonic())))
            # No numeric group action is possible after this final observation.
            if reservation and observe() and exited:
                try:
                    pid, status = os.waitpid(child.pid, os.WNOHANG)
                    _need(pid == child.pid, 'reserved exited leader not ready for final reap')
                    result.update(exit=os.waitstatus_to_exitcode(status), wait_status=status, reap_count=1, ownership='REAPED')
                    child.returncode = result['exit']
                    reservation = False
                    result['audit'].append(dict(event='REAP_LEADER_ONCE', wait_status=status))
                except (OSError, ValueError) as error:
                    lose('ECHILD' if isinstance(error, ChildProcessError) or getattr(error, 'errno', None) == errno.ECHILD
                         else 'REAP_UNVERIFIED', error)
            elif reservation:
                lose('RETIREMENT_DEADLINE')
        except BaseException as error:
            lose('RETIREMENT_UNVERIFIED', error)
        finally:
            if result['ownership'] != 'REAPED':
                # Suppress Popen's destructor wait/poll, never exposing its
                # ECHILD-to-zero fallback or this sentinel as observed status.
                child.returncode = _DETACHED_POPEN_STATUS
                result['popen_finalizer_suppressed_without_exit_observation'] = True
            result['elapsed_seconds'] = time.monotonic()-started
    return refresh(result)
