#!/usr/bin/env python3
"""Fixed child signal restoration before exec; no authentication code here."""
import ctypes,os,signal,sys
# Parent cancellation is blocked until it owns our handle. Cover parent death
# across this intermediary and exec; bwrap then installs its own parent guard.
expected=int(sys.argv[1]);libc=ctypes.CDLL(None,use_errno=True)
if libc.prctl(1,signal.SIGKILL,0,0,0)!=0:raise OSError(ctypes.get_errno(),'parent-death guard refused')
if os.getppid()!=expected:raise SystemExit(125)
for number in (signal.SIGINT,signal.SIGTERM,signal.SIGPIPE):signal.signal(number,signal.SIG_DFL)
signal.pthread_sigmask(signal.SIG_SETMASK,[])
os.execve(sys.argv[2],sys.argv[2:],{'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8','LANG':'C.UTF-8'})
