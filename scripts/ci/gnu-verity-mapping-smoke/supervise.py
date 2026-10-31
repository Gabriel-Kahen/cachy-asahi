# SPDX-License-Identifier: MIT
"""Owned unreaped child anchor; force only on failure, never success credit."""
import os,selectors,signal,subprocess,time
from protocol import need,pin

def run(argv,cwd,env,seconds,cap):
 child=subprocess.Popen(argv,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True);selector=selectors.DefaultSelector();parts=[bytearray(),bytearray()];started=time.monotonic();failure=None;natural=False;absent=False;code=None
 try:
  need(os.getpgid(child.pid)==child.pid and os.getsid(child.pid)==child.pid,'unreaped owned session/group anchor')
  for i,stream in enumerate((child.stdout,child.stderr)):os.set_blocking(stream.fileno(),False);selector.register(stream,selectors.EVENT_READ,i)
  while selector.get_map()or os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)is None:
   need(time.monotonic()-started<seconds,'owned child deadline')
   for key,_ in selector.select(.05):
    b=os.read(key.fd,65536)
    if not b:selector.unregister(key.fileobj);continue
    need(sum(map(len,parts))+len(b)<=cap,'combined owned child output cap');parts[key.data]+=b
  natural=True
 except BaseException as e:failure=e
 finally:
  blocked=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGINT,signal.SIGTERM})
  try:
   if failure is not None:
    # Child remains unreaped: its PID/session cannot be recycled before signals.
    for sig in(signal.SIGTERM,signal.SIGKILL):
     try:os.killpg(child.pid,sig)
     except ProcessLookupError:pass
   code=child.wait(timeout=5)
   try:os.killpg(child.pid,0)
   except ProcessLookupError:absent=True
  finally:
   selector.close();child.stdout.close();child.stderr.close();signal.pthread_sigmask(signal.SIG_SETMASK,blocked)
 row=dict(pid=child.pid,pgid=child.pid,session=child.pid,anchor='UNREAPED_CHILD_UNTIL_RETIREMENT',argv=argv,exit_code=code,seconds=round(time.monotonic()-started,6),time_limit=seconds,output_limit=cap,natural_exit=natural and failure is None,termination='NONE'if natural and failure is None else'TERM_KILL_ON_FAILURE',group_absence_verified=absent,stdout=pin(parts[0]),stderr=pin(parts[1]),error_type=None if failure is None else type(failure).__name__)
 need(absent,'group absence UNKNOWN; preserve owned work, no numeric group re-signal after reap')
 return row,bytes(parts[0]),bytes(parts[1]),failure
