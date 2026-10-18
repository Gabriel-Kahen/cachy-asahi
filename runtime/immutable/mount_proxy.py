"""Worker uses only authenticated inherited IPC; never mount/umount authority."""
from contextlib import contextmanager
from pathlib import Path
import inputs
P,C,client,_=inputs.broker()
class Proxy:
 def __init__(self,channel):self.channel=channel;self.active=None
 def request(self,op,case):
  c=self.channel;client.restricted();P.need(c.seq<P.MAX_REQUESTS,'bounded lease requests');c.seq+=1
  P.request(c.sock,dict(purpose=P.PURPOSE,nonce=c.nonce,seq=c.seq,op=op,case=case));value,fds=P.receive(c.sock,(1,0,0),0)
  P.need(set(value)=={'purpose','nonce','seq','op','case','receipt'}and value['purpose']==P.PURPOSE and value['nonce']==c.nonce and value['seq']==c.seq and value['op']==op and value['case']==case,'actual PID1 fixed-lease response');return value['receipt']
 def check(self,commands,work):
  P.need(work==Path('/work')and self.active is None,'fixed original preflight route');opened=self.request('lease-open','probe');closed=self.request('lease-close','probe')
  P.need(closed['cleanup']=='EXACT_MOUNTS_ABSENT_PLACEHOLDERS_REMOVED','PID1 probe strictly retired')
  return dict(status='PASS_PID1_READONLY_PROC_PREFLIGHT',cleanup='PASS_PID1_OWNED_PROBE_REMOVED',purpose='GNU_PID1_PRIVATE_RUNTIME_MOUNTS_V1',opened=opened,retired=closed)
 @contextmanager
 def runtime_mounts(self,root,report):
  P.need(root in(Path('/work/pristine/root'),Path('/work/modified/root'))and self.active is None,'one exact owned GNU runtime root');case=root.parent.name;self.active=case;receipt=dict(purpose='GNU_PID1_PRIVATE_RUNTIME_MOUNTS_V1',opened=self.request('lease-open',case));report.setdefault('runtime_mounts',[]).append(receipt)
  try:yield receipt
  finally:
   receipt['retired']=self.request('lease-close',case);P.need(receipt['retired']['cleanup']=='EXACT_MOUNTS_ABSENT_PLACEHOLDERS_REMOVED','PID1 runtime mounts retired');self.active=None
