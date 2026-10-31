#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Narrow actor-denied controls for producer/observer and exact absence protocol."""
import ast,copy,hashlib,importlib.util,json,os,stat,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;SOURCE=Path(os.environ['DESKTOP_NATIVE_SOURCE']).absolute()
sys.path.insert(0,str(SOURCE/'native'))
def deny(event,args):
 if event.startswith(('subprocess.','socket.')) or event in ('os.system','os.posix_spawn','os.fork','os.exec','os.kill','os.killpg'):
  raise AssertionError('retirement DATA actor denied:'+event)
sys.addaudithook(deny)
import desktop_alpm_v1 as A
import desktop_reader_v1 as R
import desktop_tools_v1 as T
spec=importlib.util.spec_from_file_location('desktop_retirement_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
NEW='8e71ba83e7d5037c6f7772401ec3b872684ccfa8472d855d8d6d3052cb1f41ba'
OLD='a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898'
EXPECTED=b'gpg-connect-agent: no gpg-agent running in this session'+bytes([10])
def command():
 return dict(expected=0,success=True,supervision=dict(exit=0,reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,error=None,timeout=False,signals=[]))
class Retirement(unittest.TestCase):
 def homes(self):
  temp=tempfile.TemporaryDirectory(prefix='desktop-tools-test-');self.addCleanup(temp.cleanup);work=Path(temp.name)
  work.chmod(0o700)
  for name in ('signing','trust'):(work/name).mkdir(mode=0o700)
  return work
 def test_exact_main_producer_and_strict_observer_pin_pair(self):
  value=F.profile();body=(SOURCE/'bootstrap/scripts/ci/native_arm.py').read_bytes()
  self.assertEqual(hashlib.sha256(body).hexdigest(),NEW)
  self.assertEqual(value['basis']['bootstrap/scripts/ci/native_arm.py']['sha256'],OLD)
  observer=(SOURCE/'native/failure_retention.py').read_text()
  self.assertIn("PRODUCER = '"+NEW+"'",observer)
  basis=Path(os.environ['DESKTOP_NATIVE_BASIS'])/'native/failure_retention.py'
  self.assertEqual(observer,basis.read_text().replace("PRODUCER = '"+OLD+"'","PRODUCER = '"+NEW+"'",1))
 def test_full_finite_overlay_preserves191_and_default_guards(self):
  value,before,after=F.render(Path(os.environ['DESKTOP_NATIVE_BASIS']))
  self.assertEqual(len(before),191);self.assertEqual(len(after),199);self.assertEqual(len(value['payload']),15)
  self.assertEqual({n for n in after if after[n]!=before.get(n)},set(value['payload']))
  self.assertEqual(after['native/common.py'],before['native/common.py'])
  self.assertEqual(after['scripts/virtual/owned_process.py'],before['scripts/virtual/owned_process.py'])
  self.assertEqual(F.git_tree(before),'f45820b0ef37b48f50bbc361a22f53b5dd309506')
  self.assertEqual(len(json.loads(after['native/source-map.json'][0])['files']),198)
 def test_exact56_protocol_under_owned_complete_zero(self):
  self.assertEqual(len(EXPECTED),56);self.assertEqual(A.AGENT_ABSENT,EXPECTED);self.assertEqual(R.AGENT_ABSENT,EXPECTED)
  A.exact_agent_absence(EXPECTED);R.exact_agent_absence(command(),EXPECTED)
 def test_bare_zero_truncated_or_normalized_messages_refuse(self):
  for raw in (b'',EXPECTED[:-1],EXPECTED+b'\n',EXPECTED.replace(bytes([10]),bytes([13,10])),EXPECTED*2,EXPECTED.decode(),b'other protocol\n'):
   with self.subTest(raw=raw):
    with self.assertRaises(ValueError):A.exact_agent_absence(raw)
    with self.assertRaises(ValueError):R.exact_agent_absence(command(),raw)
 def test_reader_requires_owned_zero_not_merely_protocol(self):
  for key,value in (('exit',1),('exit',False),('reaped',False),('ownership','UNKNOWN'),('group_census','UNKNOWN'),('output_complete',False),('error','unknown'),('timeout',True),('signals',[15])):
   row=command();row['supervision'][key]=value
   with self.subTest(key=key,value=value),self.assertRaises(ValueError):R.exact_agent_absence(row,EXPECTED)
  for expected in ('nonzero',False,1):
   row=command();row['expected']=expected
   with self.assertRaises(ValueError):R.exact_agent_absence(row,EXPECTED)
 def test_private_cleanup_calls_exit0_and_exact_protocol(self):
  work=self.homes();calls=[]
  def run(step,argv,expected):
   calls.append((step,argv,expected));return EXPECTED if step.startswith('no-autostart-') else b''
  result=A.retire_homes(run,(work/'signing',work/'trust'),work)
  self.assertEqual([row[2] for row in calls],[0,0,0,0]);self.assertTrue(result['homes_retired']);self.assertTrue(result['no_sockets']);self.assertEqual(result['failures'],[])
 def test_private_cleanup_refuses_empty_success_protocol(self):
  work=self.homes();result=A.retire_homes(lambda *args:b'',(work/'signing',work/'trust'),work)
  self.assertFalse(result['homes_retired']);self.assertTrue(result['failures'])
 def test_unprivate_home_cannot_qualify(self):
  work=self.homes();(work/'signing').chmod(0o755)
  result=A.retire_homes(lambda step,*args:EXPECTED if step.startswith('no-autostart-') else b'',(work/'signing',work/'trust'),work)
  self.assertFalse(result['homes_retired'])
 def test_socket_alias_inside_private_home_refuses(self):
  work=self.homes();(work/'signing'/'S.gpg-agent').symlink_to('/nonexistent-test-socket')
  result=A.retire_homes(lambda step,*args:EXPECTED if step.startswith('no-autostart-') else b'',(work/'signing',work/'trust'),work)
  self.assertFalse(result['homes_retired']);self.assertFalse(result['no_sockets'])
 def test_residual_socket_metadata_refuses_without_socket_actor(self):
  work=self.homes();marker=work/'signing'/'S.gpg-agent';marker.write_text('synthetic node metadata')
  prior=Path.lstat
  def fake(path):
   if path==marker:return SimpleNamespace(st_mode=stat.S_IFSOCK|0o600)
   return prior(path)
  with patch.object(Path,'lstat',fake):
   result=A.retire_homes(lambda step,*args:EXPECTED if step.startswith('no-autostart-') else b'',(work/'signing',work/'trust'),work)
  self.assertFalse(result['homes_retired']);self.assertFalse(result['no_sockets'])
 def test_default_snapshot_still_refuses_socket_metadata(self):
  with tempfile.TemporaryDirectory(prefix='desktop-strict-snapshot-') as tmp:
   root=Path(tmp);marker=root/'socket';marker.write_text('synthetic node metadata');prior=Path.lstat
   def fake(path):
    if path==marker:return SimpleNamespace(st_mode=stat.S_IFSOCK|0o600,st_uid=os.getuid(),st_gid=os.getgid())
    return prior(path)
   with patch.object(Path,'lstat',fake),self.assertRaisesRegex(ValueError,'special file refused'):T.snapshot(root)
 def test_expected_signature_failures_remain_nonzero(self):
  module=ast.parse((SOURCE/'native/desktop_alpm_v1.py').read_bytes());found={}
  for node in ast.walk(module):
   if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='run' and node.args and isinstance(node.args[0],ast.Constant) and node.args[0].value in ('untrusted-signature-control','tampered-signature-control'):
    found[node.args[0].value]=ast.literal_eval(node.args[2])
  self.assertEqual(found,dict.fromkeys(('untrusted-signature-control','tampered-signature-control'),'nonzero'))
if __name__=='__main__':unittest.main(verbosity=2)
