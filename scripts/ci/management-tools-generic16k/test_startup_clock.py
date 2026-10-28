# SPDX-License-Identifier: MIT
"""Source/clock-call controls only. Every clock setter and subprocess is blocked."""
import copy,importlib.util,json,subprocess,sys,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
HERE=Path(__file__).resolve().parent;ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
sys.path.insert(0,str(HERE));sys.path.insert(1,str(ROOT/'scripts/ci/management-tools-generic16k'))
import guest as G
import run as R
C=R.C
class Clock(unittest.TestCase):
 def setUp(self):
  self.block=patch.object(subprocess,'Popen',side_effect=AssertionError('actors forbidden'));self.block.start();self.addCleanup(self.block.stop)
  self.setter=patch.object(G.time,'clock_settime_ns',side_effect=AssertionError('real clock writes forbidden'));self.setter.start();self.addCleanup(self.setter.stop)
  self.receipt=dict(source_commit='a'*40);self.nonce='b'*32
  with patch.object(R.time,'time_ns',return_value=1792190700000000000),patch.object(R.time,'monotonic_ns',return_value=123456):self.seed=R.startup_seed('a'*40,'c'*16,self.nonce,self.receipt)
 def invoke(self,seed=None,after=None):
  seed=seed or self.seed;target=self.seed['host_realtime_ns']
  with patch.object(G.os,'getuid',return_value=0),patch.object(G.os,'geteuid',return_value=0),patch.object(G.os,'uname',return_value=SimpleNamespace(machine='aarch64')),patch.object(G.os,'sysconf',return_value=16384),patch.object(Path,'read_text',return_value='management16k=1'),patch.object(G.time,'time_ns',side_effect=[30520639712,target+100 if after is None else after]),patch.object(G.time,'monotonic_ns',side_effect=[30520753472,30520753572]),patch.object(G.time,'clock_settime_ns') as setter:
   result=G.startup_clock(C.encoded(seed),self.nonce,self.receipt);setter.assert_called_once_with(G.time.CLOCK_REALTIME,target);return result
 def test_observed_host_seed_is_exact_and_does_not_depend_on_key_time(self):
  self.assertEqual(self.seed['host_realtime_ns'],1792190700000000000);self.assertEqual(self.seed['host_monotonic_ns'],123456)
  self.assertEqual(self.seed['payload_manifest_sha256'],C.sha(C.encoded(self.receipt)));self.assertNotIn('signature',self.seed)
 def test_real_guest_realtime_setter_readback_and_independent_receiver_join(self):
  result=self.invoke();self.assertEqual(result['before']['realtime_ns'],30520639712);self.assertEqual(result['after']['realtime_ns'],self.seed['host_realtime_ns']+100)
  R.clock_report(result,self.nonce,self.receipt)
 def test_host_refuses_before_clock_write(self):
  with self.assertRaisesRegex(ValueError,'marked root'):G.startup_clock(C.encoded(self.seed),self.nonce,self.receipt)
 def test_changed_source_nonce_payload_job_type_or_extra_seed_refuse(self):
  for key,value in (('source_commit','d'*40),('nonce','d'*32),('payload_manifest_sha256','d'*64),('job_token','wrong'),('host_realtime_ns',True),('unexpected',1)):
   seed=self.seed|{key:value}
   with self.subTest(key=key),self.assertRaises(ValueError):self.invoke(seed)
 def test_ignored_set_or_overshot_readback_refuses(self):
  for after in (30520639812,self.seed['host_realtime_ns']+2*10**9):
   with self.subTest(after=after),self.assertRaisesRegex(ValueError,'readback failed'):self.invoke(after=after)
 def test_receiver_rejects_seed_hash_payload_clock_or_uid_forgery(self):
  result=self.invoke()
  for mutate in (lambda x:x.update(seed_sha256='0'*64),lambda x:x.update(uid=23001),lambda x:x['after'].update(realtime_ns=0),lambda x:x['seed'].update(payload_manifest_sha256='0'*64)):
   changed=copy.deepcopy(result);mutate(changed)
   with self.assertRaises(ValueError):R.clock_report(changed,self.nonce,self.receipt)
 def test_privilege_drop_and_original_case_transport_follow_clock_setup(self):
  source=(HERE/'guest.py').read_text();self.assertLess(source.index('clock_setup=startup_clock('),source.index('os.setgroups([])'))
  self.assertIn('original.command(argv,env,expected,30)',source);self.assertIn('os.setuid(23001)',source)
  self.assertIn("guest['clock_setup']['seed']==clock_seed",(HERE/'run.py').read_text())
if __name__=='__main__':unittest.main(verbosity=2)
