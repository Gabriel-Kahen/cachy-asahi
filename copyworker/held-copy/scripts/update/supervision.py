#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bound one owned worker process group; grant no auxiliary execution policy."""
import os
import selectors
import signal
import subprocess
import time


def run(argv, *, env, cwd, timeout, output_limit=32768, grace=1):
    if not (0 < timeout <= 3600 and 0 < grace <= 5 and 0 < output_limit <= 1024**2):
        raise ValueError('finite worker bounds required')
    output = [bytearray(), bytearray()]
    result = {'returncode': None, 'termination': None, 'direct_child_reaped': False,
              'group_kill_sent': False}
    selector = None
    deadline = time.monotonic() + timeout
    def exited():
        # WNOWAIT keeps the leader's numeric ID reserved until all group signals
        # finish; Popen.poll/wait would reap it and permit PID/PGID reuse.
        return os.waitid(os.P_PID,process.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is not None
    process = subprocess.Popen(argv, env=env, cwd=cwd, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        selector = selectors.DefaultSelector()
        for i, stream in enumerate((process.stdout, process.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, i)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                result['termination'] = 'timeout'
                break
            for key, _ in selector.select(min(remaining, .1)):
                data = os.read(key.fd, 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                if sum(map(len, output)) + len(data) > output_limit:
                    result['termination'] = 'output-limit'
                    break
                output[key.data].extend(data)
            if result['termination']:
                break
        while result['termination'] is None and not exited():
            if time.monotonic() >= deadline:
                result['termination'] = 'timeout'
                break
            time.sleep(.01)
    except BaseException:
        result['termination'] = 'interrupted'
        raise
    finally:
        # Ownership starts immediately after spawn, including selector failures.
        # The leader remains unreaped through both signals, so this group cannot
        # belong to a subsequently reused process ID.
        try:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            end = time.monotonic()+grace
            while not exited() and time.monotonic()<end:
                time.sleep(.01)
            try:
                os.killpg(process.pid, signal.SIGKILL)
                result['group_kill_sent'] = True
            except ProcessLookupError:
                pass
        finally:
            process.wait(timeout=5)
            result.update(returncode=process.returncode, direct_child_reaped=True)
            if selector is not None:selector.close()
            process.stdout.close(); process.stderr.close()
    result.update(stdout=bytes(output[0]), stderr=bytes(output[1]))
    return result
