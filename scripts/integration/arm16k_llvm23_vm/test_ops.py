# SPDX-License-Identifier: MIT
"""Fenced runtime/quota/preflight controls: no daemon, syscall, actor or VM."""
import ast,ctypes,importlib.util,json,os,signal,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('llvm_ops_controls',HERE/'ops.py');C=importlib.util.module_from_spec(s);s.loader.exec_module(C)
K=C.load('contracts');Q=C.load('quota');R=C.load('runtime')
def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.fork','os.posix_spawn','os.exec','fcntl.flock'):raise RuntimeError('operational test fence: '+event)
sys.addaudithook(fence)
class Controls(unittest.TestCase):
 def test_terminal_report_checks_term_delivered_during_private_write(self):
  boot=C.load('boot');cancel=K.helper('reference_controller.py').Cancellation
  original=Path.write_text
  for interrupted in (False,True):
   with self.subTest(interrupted=interrupted),tempfile.TemporaryDirectory() as d:
    out=Path(d);report=dict(status=boot.PASS,owned_container_absence_verified=True)
    state=cancel();state.cleaning=True
    def write(path,body):
     self.assertFalse((out/'report.json').exists())
     if interrupted and json.loads(body)['status']==boot.PASS:signal.raise_signal(signal.SIGTERM)
     return original(path,body)
    previous=signal.getsignal(signal.SIGTERM)
    with patch.object(Path,'write_text',write):
     state.__enter__()
     boot.publish_report(out,report,state)
    self.assertEqual(signal.getsignal(signal.SIGTERM),previous)
    self.assertEqual(report['status'],'HOLD_CLEANUP_OR_CANCELLED' if interrupted else boot.PASS)
    self.assertEqual(report.get('cancelled_signals'),[signal.SIGTERM] if interrupted else None)
    self.assertEqual(json.loads((out/'report.json').read_bytes()),report)
    self.assertEqual(list(out.iterdir()),[out/'report.json'])

 def test_unissued_phase_refuses_before_materials_output_quota_or_daemon(self):
  args=SimpleNamespace(authority=HERE/'authority.TEMPLATE.json',authority_sha256=K.pin(HERE/'authority.TEMPLATE.json')['sha256'])
  with patch.object(C,'guard',side_effect=AssertionError('quota must not run')),patch.object(C.load('adapter'),'preflight',side_effect=AssertionError('materials must not run')),self.assertRaises(ValueError):C.preflight(args,'prepare')
 def test_readonly_quota_headroom_uses_conservative_soft_or_hard_actual_limit(self):
  row=dict(uid=os.getuid(),device=1,valid=3,hard_bytes=10000,soft_bytes=8000,used_bytes=5000)
  self.assertEqual(Q.headroom(row,os.getuid(),1),3000)
  for key,value in [('uid',0),('device',2),('valid',0),('used_bytes',-1)]:
   bad=dict(row,**{key:value})
   with self.subTest(key=key),self.assertRaises(ValueError):Q.headroom(bad,os.getuid(),1)
  with self.assertRaises(ValueError):Q.headroom(dict(row,hard_bytes=0,soft_bytes=0),os.getuid(),1)
 def make_guard(self,out,reader):
  l=dict(clone_allocated_cap_bytes=100,overlay_cap_bytes=100,readback_allocated_cap_bytes=100,logs_cap_bytes=100,reserve_bytes=100,quota_initial_headroom_bytes=1000,quota_live_reserve_bytes=100,output_device=out.parent.stat().st_dev,host_uid=os.getuid(),owner_memory_bytes=1,host_reserve_bytes=1)
  return C.Guard(dict(limits=l,deadline=time.monotonic()+30),out,reader)
 def test_guard_queries_kernel_again_during_live_phase_and_refuses_exhaustion(self):
  with tempfile.TemporaryDirectory()as d:
   out=Path(d)/'fresh';calls=[]
   def reader(p,uid):calls.append((p,uid));return dict(uid=uid,device=out.parent.stat().st_dev,valid=3,hard_bytes=10000,soft_bytes=9000,used_bytes=0 if len(calls)==1 else 8999)
   guard=self.make_guard(out,reader)
   with patch.object(C.shutil,'disk_usage',return_value=SimpleNamespace(free=100000)):
    guard()
    with self.assertRaises(ValueError):guard()
   self.assertEqual(len(calls),2)
 def test_guard_refuses_unknown_quota_physical_space_allocation_and_expired_wall(self):
  with tempfile.TemporaryDirectory()as d:
   out=Path(d)/'fresh';reader=lambda p,u:dict(uid=u,device=out.parent.stat().st_dev,valid=3,hard_bytes=10000,soft_bytes=9000,used_bytes=0)
   with patch.object(C.shutil,'disk_usage',return_value=SimpleNamespace(free=1)),self.assertRaises(ValueError):self.make_guard(out,reader)()
   guard=self.make_guard(out,reader);guard.ctx['deadline']=0
   with self.assertRaises(ValueError):guard()
   with patch.object(C.shutil,'disk_usage',return_value=SimpleNamespace(free=100000)),self.assertRaises(OSError):self.make_guard(out,lambda *a:(_ for _ in()).throw(OSError('no kernel quota')))()
   out.mkdir()
   with patch.object(R,'allocated',return_value=401),patch.object(C.shutil,'disk_usage',return_value=SimpleNamespace(free=100000)),self.assertRaises(ValueError):self.make_guard(out,reader)()
 def test_actor_guard_uses_host_monitor_contract_without_privileged_quota_syscall(self):
  with tempfile.TemporaryDirectory()as d:
   guard=self.make_guard(Path(d)/'fresh',lambda *a:(_ for _ in()).throw(AssertionError('actor quota syscall forbidden')));guard.ctx['actor']=True
   with patch.object(C.shutil,'disk_usage',return_value=SimpleNamespace(free=100000)):guard()
 def test_runtime_receipts_allow_finite_elapsed_but_certificates_stay_strict(self):
  with tempfile.TemporaryDirectory()as d:
   file=Path(d)/'row';file.write_text('{"elapsed_seconds":0.25}\n');self.assertEqual(C.receipt(file)['elapsed_seconds'],.25)
   with self.assertRaises(ValueError):K.load(file)
   for body in ['{"x":1,"x":2}','{"x":NaN}','{"x":Infinity}']:
    file.write_text(body)
    with self.subTest(body=body),self.assertRaises(ValueError):C.receipt(file)
 def test_cooperative_callback_inside_actual_poll_even_without_bulk_watch(self):
  tree=ast.parse((HERE/'runtime.py').read_bytes());command=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='command');node=next(n for n in ast.walk(command)if isinstance(n,ast.FunctionDef)and n.name=='census')
  ticks=[];clock=[0.0];ns=dict(LIVE_GUARD=lambda:ticks.append(clock[0]),watch=None,last_watch=[None],time=SimpleNamespace(monotonic=lambda:clock[0]))
  exec(compile(ast.Module(body=[node],type_ignores=[]),'<actual case runtime census>','exec'),ns);ns['census']();clock[0]=.1;ns['census']();clock[0]=.5;ns['census']();self.assertEqual(ticks,[0.0,.5])
  ns['LIVE_GUARD']=lambda:(_ for _ in()).throw(ValueError('quota lost'))
  with self.assertRaises(ValueError):ns['census'](force=True)
 def test_source111_identity_and_no155_substitution_data(self):
  data=K.load(HERE/'data/baseline111.json');self.assertEqual(len(data['base_packages']),111);self.assertEqual(data['files']['guest.raw']['bytes'],1610612736);self.assertTrue(all(type(v)is str and len(v)==64 for v in data['guest_required_pins'].values()))
 def test_postboot_namespace_refuses_unknown_or_owned_waivers_and_trust(self):
  old=dict(old_namespace={'usr/bin/base':{'kind':'file'},'var/lib/state':{'kind':'file'}},owned={'usr/bin/base':{}},protected={'usr/bin/base':{}},staged_namespace={'var/lib/arm16k-llvm23-vm/root.sh':{'kind':'file'}})
  now=dict(old['old_namespace'],**old['staged_namespace']);self.assertTrue(C.namespace_delta(now,old,dict(mutable_unowned_paths=[],new_unowned_paths=[])))
  for kind in('unknown','owned','changed','trust'):
   bad=dict(now);policy=dict(mutable_unowned_paths=[],new_unowned_paths=[])
   if kind=='unknown':bad['etc/extra']={'kind':'file'}
   elif kind=='owned':policy['mutable_unowned_paths']=['usr/bin/base']
   elif kind=='changed':bad['var/lib/state']={'kind':'changed'}
   else:bad['var/lib/arm16k-llvm23-vm/trust/key']={'kind':'file'}
   with self.subTest(kind=kind),self.assertRaises(ValueError):C.namespace_delta(bad,old,policy)
  now['var/lib/state']={'kind':'changed'};self.assertTrue(C.namespace_delta(now,old,dict(mutable_unowned_paths=['var/lib/state'],new_unowned_paths=[])))
 def test_kernel_quota_mutation_or_eager_call_is_not_in_source(self):
  text=(HERE/'quota.py').read_text();self.assertNotIn('Q_SETQUOTA',text);self.assertNotIn('Q_QUOTAON',text);self.assertEqual(Q.Q_GETQUOTA,0x80000700)
  for event in('ctypes.dlopen','subprocess.Popen','socket.__new__'):
   with self.assertRaises(RuntimeError):sys.audit(event)
if __name__=='__main__':unittest.main(verbosity=2)
