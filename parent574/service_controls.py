# SPDX-License-Identifier: MIT
"""Private kernel lease/child and fixed-profile controls; no services or GUI actors."""
import copy,ctypes,importlib.util,json,os,signal,sys,tempfile,time,types,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parent

def load(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m
C=load('_service1800_controls_capacity',ROOT/'factory/service_capacity.py')
OLD=ROOT/'original/scripts/ci/welcome-management-native/doctor_lifetime.py'
def module(selected):
 m=types.ModuleType('_private_lifetime_'+str(selected));m.__file__=str(OLD);raw=OLD.read_bytes();exec(compile(C.lifetime(raw)if selected else raw,str(OLD),'exec'),vars(m));return m
# CPython3.12 host lacks os.pidfd_open; this fixture obtains a REAL kernel FD.
# It is used only inside the private control; emitted production is unchanged.
HOST_PIDFD=getattr(os,'pidfd_open',None)
def genuine_pidfd(pid):
 if HOST_PIDFD is not None:return HOST_PIDFD(pid)
 libc=ctypes.CDLL(None,use_errno=True);fd=libc.syscall(434,pid,0)
 if fd<0:raise OSError(ctypes.get_errno(),'private pidfd_open fixture')
 return fd
class Controls(unittest.TestCase):
 def test_canonical_profile_types_unknown_NULL_and_source_drift(self):
  self.assertEqual(C.profile()['service_seconds'],1800)
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);(root/'service-vm-profile.json').write_bytes(C.enc(C.SPEC));other=load('_private_profile',ROOT/'factory/service_capacity.py');other.HERE=root
   for field,value in(('service_seconds',1800.0),('service_seconds',1200),('schema_version',True),('actual',1),('profile',None),('unknown',False)):
    (root/'service-vm-profile.json').write_bytes(C.enc(dict(C.SPEC,**{field:value})))
    with self.assertRaises(ValueError):other.profile()
  with self.assertRaises(ValueError):C.lifetime(OLD.read_bytes()+b'\n')
 def test_entire_default_and_selected_lifetime_inverse(self):
  raw=OLD.read_bytes();new=C.lifetime(raw);back=new.replace(b'SERVICE_SECONDS=1800',b'SERVICE_SECONDS=1200',1).replace(C.PURPOSE.encode(),b'EXISTING_FIXTURE_SERVICE_1200S');self.assertEqual(back,raw)
  a,b=module(False),module(True);self.assertEqual((a.SERVICE_SECONDS,b.SERVICE_SECONDS,a.SECONDS,b.SECONDS),(1200,1800,1080,1080));self.assertEqual(a.CAP,b.CAP)
 def fixture(self,m,root):
  now=time.monotonic_ns();service=dict(schema_version=1,purpose=C.PURPOSE if m.SERVICE_SECONDS==1800 else'EXISTING_FIXTURE_SERVICE_1200S',parent_pid=os.getpid(),parent_nonce='c'*32,started_ns=now-2*10**9,deadline_ns=now+(m.SERVICE_SECONDS-2)*10**9)
  owner=dict(schema_version=1,purpose='EXISTING_MANAGED_PROFILE_1080S',parent_pid=os.getpid(),parent_nonce='b'*32,started_ns=now-10**9,deadline_ns=now+1079*10**9,stage='minimal',profile_nonce='a'*32,service=service);path=root/'lease.json';m.publish(path,owner,0o444);return owner,path
 def test_genuine_FD_mode_link_expiry_and_nonrenewable_leases_both_routes(self):
  for selected in(False,True):
   m=module(selected)
   with tempfile.TemporaryDirectory()as td:
    root=Path(td);owner,path=self.fixture(m,root);self.assertEqual(m.lease('minimal','a'*32,path,os.getuid()),owner)
    with self.assertRaises(FileExistsError):m.publish(path,owner,0o444)
    with patch.object(m.time,'monotonic_ns',return_value=m.deadline(owner)),self.assertRaises(ValueError):m.lease('minimal','a'*32,path,os.getuid())
    alias=root/'alias';alias.symlink_to(path)
    with self.assertRaises(OSError):m.lease('minimal','a'*32,alias,os.getuid())
    alias.unlink();os.link(path,alias)
    with self.assertRaises(ValueError):m.lease('minimal','a'*32,path,os.getuid())
    alias.unlink();path.chmod(0o600)
    with self.assertRaises(ValueError):m.lease('minimal','a'*32,path,os.getuid())
    for field,value in(('purpose','FOREIGN'),('parent_nonce','x'*32),('deadline_ns',owner['service']['deadline_ns']+1)):
     bad=copy.deepcopy(owner);bad['service'][field]=value
     with self.assertRaises(ValueError):m.binding(bad,'minimal','a'*32)
 def test_profile1080_service_1800_minimum_and_no_reset(self):
  m=module(True)
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);owner,path=self.fixture(m,root);late=copy.deepcopy(owner);late.update(started_ns=owner['service']['deadline_ns']-1,deadline_ns=owner['service']['deadline_ns']-1+1080*10**9);m.binding(late,'minimal','a'*32);self.assertEqual(m.deadline(late),owner['service']['deadline_ns'])
   service=root/'service.json'
   with patch.object(m,'root_parent'),patch.object(m.time,'monotonic_ns',return_value=100):
    value=m.service(service);self.assertEqual(value['deadline_ns']-value['started_ns'],1800*10**9);self.assertEqual(value['purpose'],C.PURPOSE)
    with self.assertRaises(FileExistsError):m.service(service)
 def test_actual_owned_direct_child_exit_and_pidfd_refusal_reap(self):
  for selected in(False,True):
   m=module(selected)
   with tempfile.TemporaryDirectory()as td:
    root=Path(td);owner,_=self.fixture(m,root)
    for code in(0,7):
     work=root/str(code);work.mkdir()
     with patch.object(m,'lease',return_value=owner),patch.object(m.os,'pidfd_open',genuine_pidfd,create=True):result=m.supervise(lambda:code,work)
     row=json.loads((work/'worker-exit.json').read_bytes());self.assertEqual(row['child_returncode'],code);self.assertEqual(result,0 if code==0 else 1);self.assertEqual(row['reason'],'NATURAL_CHILD_EXIT')
     with self.assertRaises(ChildProcessError):os.waitpid(row['child_pid'],os.WNOHANG)
    work=root/'refused';work.mkdir()
    with patch.object(m,'lease',return_value=owner),patch.object(m.os,'pidfd_open',side_effect=OSError('private refusal'),create=True):self.assertEqual(m.supervise(lambda:time.sleep(2),work),1)
    row=json.loads((work/'worker-exit.json').read_bytes());self.assertEqual((row['reason'],row['child_returncode']),('PIDFD_REFUSED',-signal.SIGKILL))
    with self.assertRaises(ChildProcessError):os.waitpid(row['child_pid'],os.WNOHANG)
 def test_selected_emitter_executes_actual_rebound_prepare_and_seal(self):
  f=load('_service1800_whole_factory',ROOT/'factory/factory.py');selected=f.service1800();self.assertIs(selected.emit.__globals__['prepare_code'],selected.prepare_code);self.assertIs(selected.emit.__globals__['seal'],selected.seal);self.assertIsNot(selected.emit.__globals__,f.emit.__globals__);self.assertEqual(selected.emit.__code__,f.emit.__code__)
  with self.assertRaises(ValueError):C.factory(vars(f),'arbitrary')
  self.assertEqual(f.prepare_code.__globals__['transform'],f.transform)
if __name__=='__main__':unittest.main(verbosity=2)
