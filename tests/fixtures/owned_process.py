#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
# Derived from reservation.py, SHA256 bd165fcc806c2951698cc16e1610ffb12a0da95404b5c99aaf3cdc067c1ea0e4.
"""Linux exclusive-child supervision. Call prepare() BEFORE creating the child.

Transfer the child's wait ownership and optional readable pipes to supervise().
Never poll/wait/reap it elsewhere. Group mode requires a fresh session leader;
direct mode targets only the owned child. No numeric operation follows ECHILD.
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


def _stat(pid):
    fd = os.open('/proc/' + str(pid) + '/stat', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        raw = os.read(fd, 4097)
    finally:
        os.close(fd)
    head, sep, tail = raw.rpartition(b')')
    fields = tail.split()
    if len(raw) > 4096 or not sep or b'(' not in head or len(fields) < 20:
        raise ValueError('invalid bounded proc stat')
    return (int(head.split(b'(', 1)[0]), fields[0], int(fields[2]),
            int(fields[3]), int(fields[19]))


def _members(pid, deadline, *, live=False):
    """Read-only bounded group/session census; post-reap matches may be reused."""
    found = set()
    with os.scandir('/proc') as entries:
        for count, entry in enumerate(entries, 1):
            if count > PROC_LIMIT or time.monotonic() >= deadline:
                raise TimeoutError('proc census cap')
            if not entry.name.isascii() or not entry.name.isdecimal():
                continue
            try:
                row = _stat(int(entry.name))
            except (ProcessLookupError, FileNotFoundError):
                continue
            if row[0] != int(entry.name):
                raise ValueError('proc identity mismatch')
            if row[2:4] == (pid, pid) and not (live and row[1] in (b'Z', b'X')):
                found.add((row[0], row[4], row[1]))
    return found


def supervise(child, *, cap, retirement=1.0, grace=0.2, group=True,
              streams=None, max_output=512 * 1024, log_fd=None):
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
    """
    started = time.monotonic()
    for value in (cap, retirement, grace):
        if type(value) not in (int, float) or not math.isfinite(value):
            raise ValueError('finite numeric deadlines required')
    if not 0 < retirement < cap or not 0 <= grace < retirement:
        raise ValueError('require 0 <= grace < retirement < cap')
    if type(group) is not bool or type(max_output) is not int or max_output < 0:
        raise ValueError('boolean group and nonnegative output cap required')
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
    pipes_ready = False

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
        return bool(_members(pid, until, live=True)) if group else terminal is None

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
        if reaped and group:
            # Read-only only. A match may be an old member OR a reused identity.
            # Two empty scans describe this numeric group/session observation,
            # never global zombie/daemon absence or absence of escaped children.
            until = min(deadline, retire_end if retire_end is not None else deadline)
            empty = 0
            try:
                for _ in range(2):
                    if time.monotonic() >= until:
                        break
                    members = _members(pid, until)
                    census = 'PRESENT_OR_REUSED' if members else 'EMPTY_ONCE'
                    if members:
                        break
                    empty = empty + 1 if not members else 0
                    if empty == 2:
                        census = 'EMPTY_TWICE'
                        break
                    pause(until)
            except (OSError, ValueError, TimeoutError) as exc:
                census = 'UNKNOWN'
                fail(exc)
    elapsed = time.monotonic() - started
    return dict(exit=exitcode, reaped=reaped, ownership=ownership, timeout=timed_out,
                signals=[signal.Signals(sig).name for sig in sent], output=bytes(output),
                output_complete=pipes_ready and not pipes, group_census=census,
                error=error, seconds=elapsed,
                passed=reaped and exitcode == 0 and not timed_out and not sent
                and error is None and elapsed < cap and not pipes
                and (not group or census == 'EMPTY_TWICE'))


if __name__ == '__main__':
    print(__doc__)
