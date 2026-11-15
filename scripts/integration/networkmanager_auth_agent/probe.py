#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One real pkttyagent process-subject registration gate; no credentials yet."""
import fcntl,hashlib,importlib.util,json,os,pty,pwd,resource,select,signal,subprocess,termios,time
from pathlib import Path
I=Path('/opt/nm-private-bus')


def load(name,file):
 s=importlib.util.spec_from_file_location(name,I/file);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m


def main():
 if not(__debug__ and os.geteuid()==os.getegid()==1000 and os.environ.get('CACHY_ASAHI_USER_AUTH_TEST')=='1'and Path('/.dockerenv').is_file()):raise RuntimeError('owned ordinary-UID container only')
 assert pwd.getpwuid(1000).pw_name=='builder'
 caps=dict(l.split(':',1)for l in Path('/proc/self/status').read_text().splitlines()if ':'in l)
 assert all(int(caps[k].strip(),16)==0 for k in ['CapEff','CapPrm','CapBnd','CapInh','CapAmb'])and caps['NoNewPrivs'].strip()=='1'
 O=load('agent_owner','owned_process.py');G=load('agent_environment','previous_guest.py')
 env=G.clean_env(os.environ);env.update(HOME='/home/UID1000',XDG_CONFIG_HOME='/home/UID1000/config',XDG_CACHE_HOME='/home/UID1000/cache',XDG_DATA_HOME='/home/UID1000/data',XDG_RUNTIME_DIR='/home/UID1000/runtime',TERM='dumb')
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 start=Path('/proc/self/stat').read_text().rpartition(')')[2].split()[19];subject=str(os.getpid())+','+start
 master,slave=pty.openpty();readfd,writefd=os.pipe();output=Path('/home/UID1000/pkttyagent.log')
 tty=os.ttyname(slave)
 # Same private terminal-session setup as integration/onboarding.py; custody and
 # cleanup remain with the existing owned_process implementation.
 def terminal_session():
  os.setsid();fcntl.ioctl(slave,termios.TIOCSCTTY,0)
  if os.tcgetpgrp(slave)!=os.getpgrp():raise RuntimeError('private controlling terminal missing')
 argv=['/usr/bin/pkttyagent','--process',subject,'--notify-fd',str(writefd),'--fallback']
 O.prepare()
 with output.open('wb')as log:
  child=subprocess.Popen(argv,env=env,stdin=slave,stdout=log,stderr=subprocess.STDOUT,pass_fds=(writefd,),preexec_fn=terminal_session)
  os.close(slave);os.close(writefd);notify_closed=False;terminal=None;until=time.monotonic()+6
  while time.monotonic()<until:
   terminal=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOWAIT|os.WNOHANG)
   if terminal is not None:break
   ready,_,_=select.select([readfd],[],[],.05)
   if ready:
    notify_closed=os.read(readfd,1)==b''
    time.sleep(.05);terminal=os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOWAIT|os.WNOHANG)
    if notify_closed:break
  registered=notify_closed and terminal is None
  if terminal is None:os.kill(child.pid,signal.SIGTERM)
  retirement=O.supervise(child,cap=8,retirement=2,grace=.2);retirement.pop('output')
 os.close(readfd);os.set_blocking(master,False);ttydata=bytearray()
 try:
  while len(ttydata)<=1024**2:
   try:data=os.read(master,65536)
   except (OSError,BlockingIOError):break
   if not data:break
   ttydata.extend(data)
 finally:os.close(master)
 text=output.read_text(errors='replace')+ttydata.decode(errors='replace')
 report={'uid':os.geteuid(),'gid':os.getegid(),'subject':{'kind':'real unix-process','pid':os.getpid(),'start_time':start},'private_controlling_TTY':tty,'argv':argv,'registration_notify_closed_while_live':registered,'retirement':retirement,'output':text,'agent_program_sha256':hashlib.sha256(Path('/usr/bin/pkttyagent').read_bytes()).hexdigest(),'PAM_and_credentials':'NOT REACHED; registration gate first','added_capabilities':[]}
 assert retirement['reaped']and retirement['ownership']=='REAPED'and not retirement['timeout']and not retirement['signals']and retirement['error']is None
 if not registered and retirement['exit']!=0 and 'register'in text.lower():report['status']='HOLD_REAL_AGENT_REGISTRATION_REFUSED'
 elif registered:report['status']='REGISTERED_REQUIRES_SEPARATE_PAM_ACTOR'
 else:report['status']='HOLD_UNCLASSIFIED_AGENT_RESULT'
 print(json.dumps(report));return 0


if __name__=='__main__':raise SystemExit(main())
