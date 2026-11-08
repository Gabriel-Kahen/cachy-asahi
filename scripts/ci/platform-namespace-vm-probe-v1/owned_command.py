# SPDX-License-Identifier: MIT
"""VM-lane owned command retirement, with the sole intentional credential FD3."""
# Retirement/drain algorithm: scripts/ci/glibc-owned-runtime/runner.py SHA2564d9aa954d95032ab9ea9085ced784efc81a5db42e2f1f3401e679ee861c16090.
import hashlib
import os
import selectors
import signal
import stat
import subprocess
import time

LIMIT = 65536

def need(value, reason):
    if not value:
        raise ValueError(reason)


def run_command(argv,work,env,seconds=30,cap=LIMIT):
    """Drain finite pipes; keep child unreaped until the final group signals."""
    need(stat.S_ISSOCK(os.fstat(3).st_mode),'fixed owned credential socket FD3 required')
    proc=subprocess.Popen(list(map(str,argv)),cwd=work,env=env,stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,close_fds=True,pass_fds=(3,))
    selector=None;parts=[bytearray(),bytearray()];failure=None
    started=time.monotonic();code=None;group_absent=False
    try:
        selector=selectors.DefaultSelector()
        for n,stream in enumerate((proc.stdout,proc.stderr)):
            os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,n)
        while selector.get_map() or os.waitid(os.P_PID,proc.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None:
            need(time.monotonic()-started<seconds,'command-time-limit')
            for key,_ in selector.select(.05):
                data=os.read(key.fd,8192)
                if not data:selector.unregister(key.fileobj);continue
                need(sum(map(len,parts))+len(data)<=cap,'command-output-limit')
                parts[key.data].extend(data)
    except BaseException as error:failure=error
    finally:
        blocked=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
        try:
            for sig in (signal.SIGTERM,signal.SIGKILL):
                try:os.killpg(proc.pid,sig)
                except ProcessLookupError:pass
            code=proc.wait(timeout=5)
            try:os.killpg(proc.pid,0)
            except ProcessLookupError:group_absent=True
        finally:
            if selector:selector.close()
            proc.stdout.close();proc.stderr.close()
            try:signal.pthread_sigmask(signal.SIG_SETMASK,blocked)
            except BaseException as error:failure=error
    row={'argv':list(map(str,argv)),'exit_code':code,'seconds':round(time.monotonic()-started,6),
         'time_limit':seconds,'output_limit':cap,'group_absence_verified':group_absent,
         'pass_fds':[3],'close_fds':True,
         'stdout_bytes':len(parts[0]),'stdout_sha256':hashlib.sha256(parts[0]).hexdigest(),
         'stderr_bytes':len(parts[1]),'stderr_sha256':hashlib.sha256(parts[1]).hexdigest()}
    return row,bytes(parts[0]),bytes(parts[1]),failure
