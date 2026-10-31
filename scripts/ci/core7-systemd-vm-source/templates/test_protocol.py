# SPDX-License-Identifier: MIT
"""Typed false-PID1, missing-exit, malformed DATA and preservation refusals."""
import copy,gzip,json,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C

def fixture():
 p=C.decode(C.read(C.HERE/'profile.json',4*1024**2));nonce='a'*32;s=dict(schema=1,scope=p['purpose'],actual=dict(source='b'*40,ref='codex/source-only-fixture',run=1,attempt=1),nonce=nonce,kernel=p['kernel'],source_profiles={n:p['source_profiles'][n]for n in('core800','ksm637','core7_carrier')},budgets=C.BUDGET)
 expected=C.decode(C.read(C.HERE/'pid1-expected.json'));expected.update(kernel=p['kernel']['profile']['release'],nonce=nonce,serial='core7-'+nonce);mask=(1<<41)-1
 process=dict(pid=1,exe_link='/usr/lib/systemd/systemd',exe=expected['exe'],version=expected['version'],package_version=expected['package_version'],manager=dict(Version=expected['manager_version'],Virtualization='qemu',SystemState='running'),root=dict(device=254,inode=2,serial=expected['serial'],machine_id=nonce),boot_id='11111111-1111-1111-1111-111111111111',architecture='aarch64',page_size=16384,kernel=expected['kernel'],capabilities=dict(CapEff=mask,CapPrm=mask,CapBnd=mask,CapInh=0,CapAmb=0,NoNewPrivs=0,Seccomp=0,last=40))
 command=dict(argv=['/source-only-inert-readback'],exit_code=0,group_absence_verified=True,time_limit=90,seconds=.1,output_limit=1024**2,stdout_bytes=0,stdout_sha256=C.pin(b'')['sha256'],stderr_bytes=0,stderr_sha256=C.pin(b'')['sha256'])
 unit=dict(ActiveState='inactive',SubState='dead',Result='success',ExecMainCode='1',ExecMainStatus='0',MainPID='0',ControlGroup='')
 value=dict(schema=1,nonce=nonce,phase=1,status='PASS_ACTUAL_SYSTEMD_PID1_AND_OWNED_STAGE',pid1=process,worker=unit,probe=unit,custody=dict(status='PASS_FULL_GRAPH_SIGNATURE_ACCOUNT_CACHE_AND_USER_PRESERVATION',phase=1,public_home_retired=True),previous=None,observer_commands=[command]*6,hardware='NOT_RUN',release='NOT_ADMITTED')
 value['observer_commands']=[dict(command,argv=['/usr/bin/systemctl','--system','is-system-running','--wait'],stdout_bytes=8,stdout_sha256=C.pin(b'running\n')['sha256'])]+[command]*5
 return s,expected,value

def frames(v):
 retired=dict(schema=1,nonce=v['nonce'],phase=v['phase'],event='observer-retired',status='NATURAL_OBSERVER_EXIT_BEFORE_OWNED_MANAGER_POWEROFF',observer=C.pin(C.encoded(v)),service_result='success',exit_code='exited',exit_status='0')
 return C.PREFIX+json.dumps(v,sort_keys=True,separators=(',',':')).encode()+b'\n'+C.RETIRED+json.dumps(retired,sort_keys=True,separators=(',',':')).encode()+b'\n'

class Protocol(unittest.TestCase):
 def test_complete_projection_then_false_pid1_and_manager_refused(self):
  s,e,v=fixture();self.assertEqual(C.protocol(frames(v),s,1,e),v)
  for field,bad in(('pid',True),('exe_link','/usr/lib/systemd/systemd (deleted)'),('package_version','systemd 262-1\n'),('page_size',4096)):
   changed=copy.deepcopy(v);changed['pid1'][field]=bad
   with self.assertRaises(ValueError):C.protocol(frames(changed),s,1,e)
  changed=copy.deepcopy(v);changed['pid1']['manager']['SystemState']='degraded'
  with self.assertRaises(ValueError):C.protocol(frames(changed),s,1,e)
 def test_missing_retirement_or_forced_unit_cannot_be_positive(self):
  s,e,v=fixture()
  with self.assertRaisesRegex(ValueError,'retirement marker'):C.protocol(frames(v).split(C.RETIRED)[0],s,1,e)
  changed=copy.deepcopy(v);changed['worker']['ExecMainCode']='2'
  with self.assertRaisesRegex(ValueError,'natural oneshot'):C.protocol(frames(changed),s,1,e)
 def test_bounded_whole_graph_and_malformed_data(self):
  self.assertEqual(C.inflate(gzip.compress(b'full original graph',mtime=0),100),b'full original graph')
  for raw in(gzip.compress(b'x'*101,mtime=0),gzip.compress(b'a')+gzip.compress(b'b')):
   with self.assertRaises(ValueError):C.inflate(raw,100)
  for raw in(b'{"pid":1,"pid":2}',b'{"clock":NaN}'):
   with self.assertRaises(ValueError):C.decode(raw)
if __name__=='__main__':unittest.main()
