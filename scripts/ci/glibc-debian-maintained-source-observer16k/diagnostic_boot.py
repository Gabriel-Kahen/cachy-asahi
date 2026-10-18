#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""PID1 source-only boot; original authority reduction, supervision and teardown."""
import ctypes,json,os,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import guest as G
import source_diagnostic as D
import protocol as P
C=G.C

def emit(nonce,value):
 raw=json.dumps(value,sort_keys=True,separators=(',',':'));C.need(len(raw)<=512*1024,'guest receipt bound');print(P.PREFIX+' '+nonce+' '+raw,flush=True)
def run():
 C.need(os.getpid()==1 and os.getuid()==os.geteuid()==0,'root guest bootstrap only')
 selection=C.decode(C.read(Path(__file__).with_name('selection.json')));nonce=selection['nonce']
 C.need(selection.get('diagnostic_route')==P.ROUTE and D.MARKER in Path('/proc/cmdline').read_text().split(),'dedicated source diagnostic selection/marker')
 nofile=G.observer_file_limit()
 libc=ctypes.CDLL(None,use_errno=True);C.need(libc.prctl(4,0,0,0,0)==0,'protect root bootstrap')
 C.need(os.sysconf('SC_PAGE_SIZE')==16384 and os.uname().release==selection['kernel']['release'],'actual16K boot identity')
 emit(nonce,dict(event='boot',page_size=16384,kernel=os.uname().release,architecture='aarch64',kernel_profile_sha256=selection['kernel_profile_sha256'],observer_nofile=nofile,diagnostic_route=P.ROUTE))
 runtime=C.load('guest_supervisor','/source/scripts/ci/glibc-owned-runtime/runner.py')
 row,stdout,stderr,error=D.supervise(runtime,selection,nonce)
 if not (error is None and row['exit_code']==0 and row['group_absence_verified']):emit(nonce,G.child_failure(row,stdout,stderr,error,'exit-or-retirement'))
 C.need(error is None and row['exit_code']==0 and row['group_absence_verified'] and row['time_limit']==600,'source-only child exit/group retirement failed')
 prefix=('GNU_SOURCE_OBSERVER_ONLY '+nonce+' ').encode();lines=stdout.splitlines()
 C.need(len(lines)==1 and lines[0].startswith(prefix) and not stderr,'one closed source-only child result')
 value=P.subject(C.decode(lines[0][len(prefix):]),selection)
 C.need(C.decode(C.read('/out/result.json',65536))==value,'original child result readback')
 files={}
 for name,cap in P.FILES.items():C.read(Path('/out')/name,cap);files[name]=C.row(Path('/out')/name)
 emit(nonce,dict(event='result',subject=value,isolation=C.decode(C.read('/out/isolation.json',65536)),files=files,bytes=sum(v['bytes'] for v in files.values()),acceptance=P.FORBIDDEN,supervisor=dict(exit_code=row['exit_code'],group_absence_verified=row['group_absence_verified'],time_limit=row['time_limit'])))
 # This is the exact original PID1 mount retirement body.
 import subprocess
 for point in ('/out','/work','/held','/source','/inputs'):
  result=subprocess.run(['/usr/bin/umount',point],stdin=subprocess.DEVNULL,capture_output=True,timeout=15)
  C.need(result.returncode==0 and not os.path.ismount(point),'guest mount retirement failed')
 emit(nonce,dict(event='exit',status=P.DONE,cleanup='PASS_OWNED_CLONES_REMOVED',acceptance=P.FORBIDDEN))
if __name__=='__main__':
 try:run()
 except BaseException as error:print(P.PREFIX+'_ERROR '+type(error).__name__+' '+str(error)[:512],flush=True)
 finally:
  sys.stdout.flush();sys.stderr.flush();os.sync()
  libc=ctypes.CDLL(None,use_errno=True);libc.reboot(0x4321fedc)
  raise RuntimeError('guest poweroff failed')
