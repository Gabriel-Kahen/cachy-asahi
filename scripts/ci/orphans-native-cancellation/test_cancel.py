# SPDX-License-Identifier: MIT
"""Real temporary process/flock controls; no native/Docker/source-positive claim."""
import copy,fcntl,importlib.util,json,os,signal,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('cancel_component',HERE/'cancel.py');N=importlib.util.module_from_spec(spec);spec.loader.exec_module(N)
ROOT=HERE.parents[2];spec=importlib.util.spec_from_file_location('held_supervisor',ROOT/'scripts/ci/orphans-full574-native/supervise.py');S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)
ID=dict(source_sha='a'*40,trial='normal',proof_sha256='b'*64,consumer_token='c'*32,producer_token='d'*16)
CHILD="""import fcntl,os,time,sys
from pathlib import Path
r=Path(sys.argv[1]);a=os.open(r/'producer',os.O_RDONLY|os.O_DIRECTORY);b=os.open(r/'owner.lock',os.O_RDWR|os.O_CREAT,0o600);fcntl.flock(a,fcntl.LOCK_EX|fcntl.LOCK_NB);fcntl.flock(b,fcntl.LOCK_EX|fcntl.LOCK_NB);(r/'ready').write_text(str(os.getpid()));time.sleep(15)
"""
class Controls(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);(self.root/'producer').mkdir(mode=0o700)
 def launch(self):
  code="import importlib.util,json,sys;from pathlib import Path;s=importlib.util.spec_from_file_location('S',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);v=m.handoff([sys.executable,'-B','-c',sys.argv[2],sys.argv[3]],Path(sys.argv[3])/'handoff.json',json.loads(sys.argv[4]));raise SystemExit(128+v['cancellation_signal'] if v['cancellation_signal'] else v['exit_code'])"
  p=subprocess.Popen([sys.executable,'-B','-c',code,str(ROOT/'scripts/ci/orphans-full574-native/supervise.py'),CHILD,str(self.root),json.dumps(ID)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True);self.addCleanup(self.retire,p)
  end=time.monotonic()+3
  while not (self.root/'ready').exists() and p.poll() is None and time.monotonic()<end:time.sleep(.01)
  self.assertTrue((self.root/'ready').exists());return p,int((self.root/'ready').read_text())
 def retire(self,p):
  if p.poll() is None:
   os.kill(p.pid,signal.SIGTERM)
   try:p.wait(timeout=6)
   except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=1)
  p.stdout.close();p.stderr.close()
 def test_real_PID_owned_two_leases_SIGINT_handoff_then_same_leases_available(self):
  p,pid=self.launch();a=N.held_lease(self.root/'producer',pid,True);b=N.held_lease(self.root/'owner.lock',pid);self.assertTrue(a['contended'] and b['contended']);os.kill(p.pid,signal.SIGINT);p.communicate(timeout=7);self.assertEqual(p.returncode,130);S.check(self.root/'handoff.json',ID);N.released(self.root/'producer',a,True);N.released(self.root/'owner.lock',b)
  value=json.loads((self.root/'handoff.json').read_bytes());self.assertTrue(value['direct_reaped'] and value['group_absent']);self.assertEqual(value['cancellation_signal'],signal.SIGINT)
 def test_foreign_PID_available_alias_and_replaced_lease_refuse(self):
  p,pid=self.launch()
  with self.assertRaises(ValueError):N.held_lease(self.root/'owner.lock',os.getpid())
  alias=self.root/'alias';alias.symlink_to(self.root/'owner.lock')
  with self.assertRaises(ValueError):N.held_lease(alias,pid)
  before=N.held_lease(self.root/'owner.lock',pid);os.kill(p.pid,signal.SIGINT);p.communicate(timeout=7);(self.root/'owner.lock').rename(self.root/'old.lock');(self.root/'owner.lock').write_bytes(b'');(self.root/'owner.lock').chmod(0o600)
  with self.assertRaises(ValueError):N.released(self.root/'owner.lock',before)
  with self.assertRaises(ValueError):N.held_lease(self.root/'owner.lock',os.getpid())
 def test_inspect_is_one_readonly_bounded_command_and_unknown_refuses(self):
  calls=[]
  def invoke(argv,**kw):
   calls.append((argv,kw));kw['stdout'].write(b'[{"Id":"actual-data-only"}]');return SimpleNamespace(returncode=0)
  with patch.object(N.subprocess,'run',side_effect=invoke):self.assertEqual(N.inspect_actor('owned-name',self.root/'inspect'),{'Id':'actual-data-only'})
  self.assertEqual(calls[0][0],['/usr/bin/docker','container','inspect','owned-name']);self.assertEqual(calls[0][1]['timeout'],10)
  def bad(argv,**kw):kw['stdout'].write(b'permission denied');return SimpleNamespace(returncode=1)
  with patch.object(N.subprocess,'run',side_effect=bad),self.assertRaises(ValueError):N.inspect_actor('owned-name',self.root/'inspect')
 def test_run_builds_only_original_supervisor_and_normal_route_without_actor(self):
  a=SimpleNamespace(source=ROOT,packet=self.root/'packet',proof=self.root/'proof',base=self.root/'producer',output=self.root/'output',handoff=self.root/'handoff',component=self.root/'component');calls=[]
  def forbidden(argv,**kw):calls.append((argv,kw));raise RuntimeError('actor-blocked control')
  fake=SimpleNamespace(binding=lambda a,c:ID)
  with patch.object(N.subprocess,'Popen',side_effect=forbidden),self.assertRaisesRegex(RuntimeError,'actor-blocked'):N.run(a,SimpleNamespace(safe=lambda p:p),fake)
  argv,kw=calls[0];self.assertEqual(argv[:6],['/usr/bin/python3','-I','-B',str(ROOT/'scripts/ci/orphans-full574-native/supervise.py'),'run','--trial']);self.assertEqual(argv[6],'normal');self.assertTrue(kw['start_new_session'] and kw['close_fds']);self.assertNotIn('preexec_fn',kw)
 def test_component_scope_duplicate_JSON_and_closed_path_refusals(self):
  with self.assertRaises(ValueError):N.decode(b'{"x":1,"x":2}')
  for n in ('../outside','/absolute','a/./b','a//b','a\\b',''):
   with self.subTest(path=n),self.assertRaises(ValueError):N.relative(n)
  for key,bad in (('status','PASS_NORMAL_MATRIX'),('signal',signal.SIGTERM),('normal_matrix','PASS'),('transaction_outcome',False),('rollback','PASS'),('release','ADMITTED')):
   v=dict(status=N.STATUS,identity=ID,signal=signal.SIGINT,normal_matrix='NOT_CLAIMED',transaction_outcome='UNKNOWN',rollback='NOT_CLAIMED',hardware='NOT_RUN',release='NOT_ADMITTED');v[key]=bad
   with self.subTest(key=key),self.assertRaises(ValueError):N.validate(v,ID)
 def test_source_manifest_and_workflow_envelopes(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden')):N.source(ROOT)
  wf=(ROOT/'.github/workflows/native-arm-orphans-native-cancellation.yml').read_text()
  for text in ('3550s','650s','2300s','timeout-minutes: 120','cancel-in-progress: false','ORIGINAL_CANCELLED_EXPORT_ONLY','COMPONENT_MANIFEST_SHA256','"$COMPONENT/cancel.py" complete'):self.assertIn(text,wf)
  self.assertNotIn('gh api',wf);self.assertIn('options: [normal, interruption]',(ROOT/'.github/workflows/native-arm-orphans-full574-cleanup.yml').read_text())
if __name__=='__main__':unittest.main(verbosity=2)
