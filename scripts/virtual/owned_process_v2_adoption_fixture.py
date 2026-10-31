#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One new-session leader leaves exactly one own zero-exit zombie, then exits0."""
import json
import os
import signal
import time


def main():
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    leader = os.getpid()
    if os.getpgrp() != leader or os.getsid(0) != leader:
        raise ValueError('fixture requires its own original session/group')
    child = os.fork()  # The only descendant created by this fixture.
    if child == 0:
        os._exit(0)
    deadline = time.monotonic() + 2.0
    while True:
        # This is our unconsumed child. ECHILD exits the fixture, with no followup.
        row = os.waitid(os.P_PID, child, os.WEXITED | os.WNOWAIT | os.WNOHANG)
        if row is not None:
            if (row.si_pid, row.si_code, row.si_status) != (child, os.CLD_EXITED, 0):
                raise ValueError('fixture child must be reserved CLD_EXITED0')
            break
        if time.monotonic() >= deadline:
            raise TimeoutError('fixture own-child terminal ceiling')
        time.sleep(.002)
    # Exact child remains waitable: no consuming wait is performed by the leader.
    fd = os.open('/proc/' + str(child) + '/stat', os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        raw = os.read(fd, 4097)
    finally:
        os.close(fd)
    head, separator, tail = raw.rpartition(b')')
    fields = tail.split()
    if not separator or len(raw) > 4096 or len(fields) < 20:
        raise ValueError('complete fixture-owned zombie identity required')
    identity = dict(pid=int(head.split(b'(', 1)[0]), state=fields[0].decode('ascii'),
                    ppid=int(fields[1]), group=int(fields[2]), session=int(fields[3]),
                    start_ticks=int(fields[19]))
    if (identity['pid'], identity['state'], identity['ppid'], identity['group'], identity['session']) != (child, 'Z', leader, leader, leader):
        raise ValueError('exact same-group own zombie required')
    ledger = dict(schema=1, status='ONE_OWN_ZERO_ZOMBIE_LEFT_FOR_ADOPTION',
                  leader=leader, owner=os.getppid(), child=identity,
                  fixture_waitid=dict(pid=child, code='CLD_EXITED', status=0),
                  fixture_consuming_waits=0, fixture_forks=1)
    body = (json.dumps(ledger, sort_keys=True, separators=(',', ':')) + '\n').encode()
    if len(body) > 2048 or os.write(1, body) != len(body):
        raise ValueError('complete bounded fixture ledger required')
    os._exit(0)


if __name__ == '__main__':
    try:
        main()
    except BaseException as error:
        # No cleanup wait, probe or signal follows any ownership/identity failure.
        body = ('fixture refused: ' + type(error).__name__ + '\n').encode()
        os.write(2, body)
        os._exit(91)
