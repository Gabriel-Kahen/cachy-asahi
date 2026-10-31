# SPDX-License-Identifier: MIT
"""Real local lease/process cancellation controls; no Docker/network/host mutation."""
import fcntl,hashlib,importlib.util,json,os,signal,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('owned_job_supervisor',HERE/'supervise.py');S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)
IDENTITY=dict(source_sha='a'*40,trial='normal',proof_sha256='b'*64,consumer_token='c'*32,producer_token='d'*16)
CHILD="""import fcntl,os,signal,subprocess,sys,time
from pathlib import Path
root=Path(sys.argv[1]);mode=sys.argv[2];fd=os.open(root/'lease',os.O_RDWR|os.O_CREAT|os.O_CLOEXEC,0o600);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
def leave(number,_):
 (root/'forwarded').write_text(str(number));time.sleep(.15)
 if mode=='group':grandchild.wait(timeout=.7)
 raise SystemExit(0)
for number in (signal.SIGINT,signal.SIGTERM):signal.signal(number,signal.SIG_IGN if mode=='ignore' else leave)
if mode=='group':
 code="import os,signal,time;from pathlib import Path;r=Path("+repr(str(root))+");signal.signal(signal.SIGINT,lambda n,f:((r/'grandchild-signal').write_text(str(n)),exit(0)));(r/'grandchild-ready').write_text(str(os.getpid()));time.sleep(10)"
 grandchild=subprocess.Popen([sys.executable,'-c',code]);end=time.monotonic()+2
 while not (root/'grandchild-ready').exists() and time.monotonic()<end:time.sleep(.01)
(root/'ready').write_text(str(os.getpid()))
if mode=='normal':raise SystemExit(0)
while True:time.sleep(.02)
"""
class Controls(unittest.TestCase):
 def setUp(self):self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
 def launch(self,mode):
  launch="import importlib.util,json,sys;from pathlib import Path;s=importlib.util.spec_from_file_location('S',sys.argv[1]);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);v=m.handoff([sys.executable,'-c',sys.argv[2],sys.argv[3],sys.argv[4]],Path(sys.argv[3])/'handoff.json',json.loads(sys.argv[5]));raise SystemExit(0 if v['cancellation_signal'] is None else 128+v['cancellation_signal'])"
  p=subprocess.Popen([sys.executable,'-B','-c',launch,str(HERE/'supervise.py'),CHILD,str(self.root),mode,json.dumps(IDENTITY)],start_new_session=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  self.addCleanup(self.retire,p);end=time.monotonic()+3
  while not (self.root/'ready').exists() and p.poll() is None and time.monotonic()<end:time.sleep(.01)
  self.assertTrue((self.root/'ready').exists());return p
 def retire(self,p):
  if p.poll() is None:
   try:os.killpg(p.pid,signal.SIGTERM)
   except ProcessLookupError:pass
   try:p.wait(timeout=6)
   except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=1)
  p.stdout.close();p.stderr.close()
 def lease(self,available):
  fd=os.open(self.root/'lease',os.O_RDWR)
  try:
   if available:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   else:
    with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  finally:os.close(fd)
 def finish(self,p):
  out,err=p.communicate(timeout=7);self.assertFalse(err,err);value=json.loads((self.root/'handoff.json').read_bytes());self.assertTrue(value['direct_reaped']);self.assertTrue(value['group_absent']);self.assertEqual(value['identity'],IDENTITY);S.check(self.root/'handoff.json',IDENTITY);return value
 def test_real_nonblocking_lease_race_then_SIGINT_reap_handoff(self):
  p=self.launch('cooperate');self.lease(False);os.kill(p.pid,signal.SIGINT);v=self.finish(p);self.lease(True);self.assertEqual(p.returncode,130);self.assertEqual((self.root/'forwarded').read_text(),str(signal.SIGINT));self.assertEqual(v['cancellation_signal'],signal.SIGINT);self.assertLess(v['cancellation_seconds'],6)
 def test_actual_same_group_descendant_receives_forwarded_INT_and_is_reaped(self):
  p=self.launch('group');self.lease(False);os.kill(p.pid,signal.SIGINT);v=self.finish(p);self.lease(True);self.assertEqual((self.root/'grandchild-signal').read_text(),str(signal.SIGINT));self.assertTrue(v['group_absent'])
 def test_SIGTERM_forwarding_then_original_lock_is_available(self):
  p=self.launch('cooperate');self.lease(False);os.kill(p.pid,signal.SIGTERM);v=self.finish(p);self.lease(True);self.assertEqual(p.returncode,143);self.assertEqual((self.root/'forwarded').read_text(),str(signal.SIGTERM));self.assertIn(signal.SIGKILL,v['signals'])
 def test_ignored_cancellation_is_killed_reaped_within_grace(self):
  p=self.launch('ignore');self.lease(False);os.kill(p.pid,signal.SIGINT);v=self.finish(p);self.lease(True);self.assertEqual(v['exit_code'],-signal.SIGKILL);self.assertEqual(v['signals'],[signal.SIGINT,signal.SIGTERM,signal.SIGKILL]);self.assertLess(v['cancellation_seconds'],6)
 def test_natural_direct_exit_preserves_status_and_has_no_cancel_credit(self):
  p=self.launch('normal');v=self.finish(p);self.assertEqual(p.returncode,0);self.assertEqual(v['exit_code'],0);self.assertIsNone(v['cancellation_signal']);self.lease(True);self.assertEqual(v['inner_actors'],'NOT_OBSERVED_OR_RETIRED_BY_OUTER_SUPERVISOR')
 def test_cleanup_refuses_running_unknown_foreign_and_reused_groups(self):
  path=self.root/'handoff.json';S.check(path,IDENTITY,True)
  p=self.launch('ignore');self.lease(False)
  with self.assertRaises(ValueError):S.check(path,IDENTITY)
  with self.assertRaises(ValueError):S.check(path,IDENTITY,True)
  os.kill(p.pid,signal.SIGTERM);v=self.finish(p)
  with self.assertRaises(ValueError):S.check(path,IDENTITY|dict(trial='interruption'))
  for change in (dict(status='UNKNOWN'),dict(group_absent=False),dict(direct_reaped=False)):
   path.write_text(json.dumps(v|change))
   with self.assertRaises(ValueError):S.check(path,IDENTITY)
  live=subprocess.Popen([sys.executable,'-c','import time;time.sleep(3)'],start_new_session=True)
  try:
   bad=dict(v,job=S.process(live.pid));path.write_text(json.dumps(bad))
   with self.assertRaisesRegex(ValueError,'group is present'):S.check(path,IDENTITY)
  finally:os.killpg(live.pid,signal.SIGKILL);live.wait(timeout=1)
  path.write_text(json.dumps(v));path.chmod(0o640)
  with self.assertRaises(ValueError):S.check(path,IDENTITY)
  path.chmod(0o600);S.check(path,IDENTITY);alias=self.root/'alias';alias.symlink_to(path)
  with self.assertRaises(ValueError):S.check(alias,IDENTITY)
class Generation(unittest.TestCase):
 def test_emitter_retains_supervisor_exact_workflow_and_all121_rows(self):
  root=HERE.parents[2];spec=importlib.util.spec_from_file_location('supervisor_closed_prepare',HERE/'prepare.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
  with tempfile.TemporaryDirectory(prefix='orphan-supervisor-emission-') as temporary,patch.object(subprocess,'Popen',side_effect=AssertionError('source emission cannot launch actors')):
   output=Path(temporary)/'emitted';result=P.emit(root,output);lane=output/P.NEW;manifest=json.loads((lane/'source-manifest.json').read_bytes());self.assertEqual(len(manifest['files']),121)
   for name,row in manifest['files'].items():
    raw=(output/name).read_bytes();self.assertEqual(row,dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
   self.assertEqual((output/P.WF).read_bytes(),(root/P.WF).read_bytes());self.assertEqual(result['workflow'],P.pin((root/P.WF).read_bytes()))
   for name in ('supervise.py','test_supervise.py'):self.assertEqual((lane/name).read_bytes(),(HERE/name).read_bytes());self.assertIn(name,P.OWN)
   self.assertEqual({p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file()},set(manifest['files'])|{P.NEW+'/source-manifest.json',P.WF,'native-adaptation.json'})
   self.assertEqual(len(list(p for p in lane.iterdir() if p.is_file())),27)
   with self.assertRaisesRegex(ValueError,'fixed selected-job workflow seam'):S.workflow((output/P.WF).read_text())

if __name__=='__main__':unittest.main(verbosity=2)
