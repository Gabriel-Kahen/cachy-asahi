# SPDX-License-Identifier: MIT
"""Exact source-owned tools-generic16k WNOWAIT VM supervisor body."""
import hashlib,os,selectors,signal,subprocess,time
from types import SimpleNamespace

def need(value,why):
 if not value: raise ValueError(why)
s=SimpleNamespace(need=need,sha=lambda data:hashlib.sha256(data).hexdigest())

def supervise(argv,log,seconds,cap=1024**2,diagnostic=None):
    child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
    poll=selectors.DefaultSelector();data=bytearray();started=time.monotonic();natural=False;observed=False
    try:
        os.set_blocking(child.stdout.fileno(),False);poll.register(child.stdout,selectors.EVENT_READ)
        while poll.get_map() or os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is None:
            s.need(time.monotonic()-started<seconds,'owned actor deadline')
            remaining=started+seconds-time.monotonic()
            if diagnostic is not None and not observed and time.monotonic()-started>=min(60,seconds-5) and remaining>3:
                observed=True;state,collect=diagnostic
                try:state.update(collect(child,bytes(data),min(started+seconds-1,time.monotonic()+2)))
                except Exception as error:state.update(status='UNAVAILABLE',error_type=type(error).__name__,reason=str(error)[:160])
            for key,_ in poll.select(.05):
                raw=os.read(key.fd,65536)
                if not raw:poll.unregister(key.fileobj);continue
                s.need(len(data)+len(raw)<=cap,'owned actor output bound');data.extend(raw)
        natural=True
    finally:
        # The unreaped session leader pins its PID through every cleanup signal.
        for sig in (signal.SIGTERM,signal.SIGKILL):
            try:os.killpg(child.pid,sig)
            except ProcessLookupError:pass
        code=child.wait(timeout=5);poll.close();child.stdout.close();log.write_bytes(data)
    try:os.killpg(child.pid,0)
    except ProcessLookupError:absent=True
    else:absent=False
    s.need(natural and absent,'natural actor exit and complete group retirement required')
    return code,bytes(data),dict(argv=list(map(str,argv)),exit=code,natural_exit=natural,group_absent=absent,
        seconds=round(time.monotonic()-started,6),bytes=len(data),sha256=s.sha(data))
