"""One PID1-owned channel, one reserved direct child, no public socket path."""
import ctypes,os,select,socket
import context as C
import protocol as P

def pair():
 C.pid1();a,b=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET|socket.SOCK_CLOEXEC)
 for sock in(a,b):P.channel(sock)
 return a,b

def close_except(allowed):
 # Call ONLY in freshly forked disposable child before any worker code/exec.
 P.need(os.getpid()!=1 and os.getppid()==1,'direct disposable PID1 child only')
 for p in __import__('pathlib').Path('/proc/self/fd').iterdir():
  fd=int(p.name)
  if fd in allowed:continue
  try:os.close(fd)
  except OSError:pass
 for fd in allowed:os.fstat(fd)

class Broker:
 def __init__(self,sock,worker,context):
  C.pid1();P.need(type(worker)is int and worker>1,'one reserved worker PID');P.channel(sock)
  # socketpair SO_PEERCRED is creator PID1; SCM_CREDENTIALS authenticates sender.
  P.need(P.peer(sock)==(1,0,0),'PID1-created inherited channel');self.sock=sock;self.worker=worker;self.context=context;self.pidfd=os.pidfd_open(worker,0);self.seq=0
  status=__import__('pathlib').Path('/proc/%d/status'%worker).read_text();fields=dict(row.split(':',1)for row in status.splitlines()if ':'in row)
  P.need(fields['PPid'].strip()=='1','reserved actual direct child')
 def worker_state(self):
  raw=__import__('pathlib').Path('/proc/%d/status'%self.worker).read_text();P.need(len(raw)<=65536,'bounded reserved worker status');v=dict(row.split(':',1)for row in raw.splitlines()if ':'in row)
  P.need(v['PPid'].strip()=='1'and v['Uid'].split()==['0']*4 and v['NoNewPrivs'].strip()=='1'and v['Seccomp'].strip()=='2','actual reserved direct worker credentials/fences')
  for n in('CapEff','CapPrm','CapBnd'):P.need(int(v[n],16)==P.WORKER_MASK,'actual reserved exact9 worker mask')
  for n in('CapInh','CapAmb'):P.need(int(v[n],16)==0,'no inherited/ambient worker caps')
 def once(self):
  C.pid1();p=select.poll();p.register(self.pidfd,select.POLLIN);P.need(not p.poll(0),'reserved worker must be alive')
  request,fds=P.receive(self.sock,(self.worker,0,0),0);self.seq+=1
  P.need(self.seq<=P.MAX_REQUESTS and request==dict(purpose=P.PURPOSE,nonce=self.context.value['nonce'],op='source',seq=self.seq),'one bounded nonce/sequence/source operation')
  self.worker_state();state=self.context.check();state.update(purpose=P.PURPOSE,nonce=self.context.value['nonce'],seq=self.seq,capacity=self.context.capacity())
  P.send(self.sock,state,(self.context.fd,self.context.index))
 def close(self):
  self.sock.close()
  if self.pidfd>=0:os.close(self.pidfd);self.pidfd=-1
