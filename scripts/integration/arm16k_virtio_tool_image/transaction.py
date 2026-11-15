#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Own one pacman transaction and its private verification-agent retirement."""
import ctypes,json,os,signal,subprocess,sys,time
from pathlib import Path


def execute(transaction,shutdown,*,whole=110,transaction_seconds=90,shutdown_seconds=10,reap_seconds=8):
 """Always request normal shutdown; never signal an agent or waive residual children."""
 if not(0<transaction_seconds+shutdown_seconds+reap_seconds<whole<=110):raise ValueError('finite transaction/cleanup reserve required')
 if signal.getsignal(signal.SIGCHLD)!=signal.SIG_DFL:raise ValueError('exclusive direct-child ownership required')
 libc=ctypes.CDLL(None,use_errno=True)
 if libc.prctl(36,1,0,0,0)!=0:raise OSError(ctypes.get_errno(),'private transaction subreaper')
 signal.signal(signal.SIGCHLD,signal.SIG_DFL);end=time.monotonic()+whole;report=dict(status='HOLD',subreaper=True,transaction_argv=transaction,shutdown_argv=shutdown,transaction_exit=None,shutdown_exit=None,reaped_children=[],received_signals=[],empty_children_twice=False,signals_sent=[]);children=[];cleaning=[False];previous={}
 def cancel(number,frame):
  report['received_signals'].append(number)
  if not cleaning[0]:raise InterruptedError('transaction cancellation')
 for number in(signal.SIGINT,signal.SIGTERM):previous[number]=signal.signal(number,cancel)
 try:
  try:
   child=subprocess.Popen(transaction,stdin=subprocess.DEVNULL);children.append(child);report['transaction_exit']=child.wait(timeout=min(transaction_seconds,end-time.monotonic()))
  except BaseException as error:report['transaction_failure']=dict(type=type(error).__name__,message=str(error)[:500])
  finally:
   cleaning[0]=True
   try:
    child=subprocess.Popen(shutdown,stdin=subprocess.DEVNULL);children.append(child);report['shutdown_exit']=child.wait(timeout=max(.01,min(shutdown_seconds,end-time.monotonic())))
   except BaseException as error:report['shutdown_failure']=dict(type=type(error).__name__,message=str(error)[:500])
   until=min(end,time.monotonic()+reap_seconds);empty=0
   while time.monotonic()<until and empty<2:
    absent=False
    while True:
     try:pid,status=os.waitpid(-1,os.WNOHANG)
     except ChildProcessError:absent=True;break
     if pid==0:break
     report['reaped_children'].append(dict(pid=pid,exit=os.waitstatus_to_exitcode(status)))
     for child in children:
      if child.pid==pid:child.returncode=os.waitstatus_to_exitcode(status)
    empty=empty+1 if absent else 0
    if empty<2:time.sleep(.02)
   report['empty_children_twice']=empty==2
  if report['transaction_exit']==report['shutdown_exit']==0 and report['empty_children_twice']and all(r['exit']==0 for r in report['reaped_children'])and not report['received_signals']and not any(k.endswith('_failure')for k in report):report['status']='NORMAL_TRANSACTION_AND_PRIVATE_AGENT_REAPED'
  return report
 finally:
  for number,handler in previous.items():signal.signal(number,handler)


def main():
 if not(sys.flags.isolated and __debug__ and os.geteuid()==0 and os.getppid()==1 and os.environ.get('CACHY_VIRTIO_TOOL_IMAGE')=='ROOT_ADMITTED_V1'):raise ValueError('only direct child of the separately admitted container actor')
 package='/packages/qemu-hw-display-virtio-gpu-11.1.3-1-x86_64.pkg.tar.zst';home=Path('/etc/pacman.d/gnupg')
 if home.is_symlink()or not home.is_dir()or home.stat().st_uid!=0:raise ValueError('exact private container GPG homedir')
 report=execute(['/usr/bin/pacman','--config','/tmp/install.conf','--hookdir','/tmp/masked-hooks','--noscriptlet','--noconfirm','-U',package],['/usr/bin/gpgconf','--homedir',str(home),'--kill','gpg-agent'])
 with Path('/receipts/transaction-result.json').open('x')as stream:stream.write(json.dumps(report,sort_keys=True,indent=2)+'\n')
 return 0 if report['status']=='NORMAL_TRANSACTION_AND_PRIVATE_AGENT_REAPED'else 1
if __name__=='__main__':raise SystemExit(main())
