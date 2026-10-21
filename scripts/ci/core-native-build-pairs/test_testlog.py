# SPDX-License-Identifier: MIT
"""Pinned Meson serializer fixture and real raw-retention controls; no native actor."""
import copy,importlib.util,json,os,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import prepare as F
HERE=Path(__file__).resolve().parent;P=F.profile()
for name,pin in P['testlog_fixtures'].items():F.need(F.pin(F.read(HERE/name))==pin,'whole testlog fixture')
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
NEW=HERE/'runtime/effective-profile/systemd/cachy-asahi-testlog.py'
F.need(F.pin(F.read(NEW))==P['expected_sources']['selected']['effective-profile/systemd/cachy-asahi-testlog.py'],'exact emitted testlog helper')
A=load('_maintained_testlog',NEW);O=load('_maintained_old_testlog',HERE/'test_support/testlog-before.py')
def fixture():return json.loads(F.read(HERE/'fixtures/meson-1.12.1-intro.json')),[json.loads(x)for x in F.read(HERE/'fixtures/synthetic-testlog.jsonl').splitlines()]
def encode(d,r):return b''.join(json.dumps(x).encode()+b'\n'for x in r),json.dumps(d).encode()
class Controls(unittest.TestCase):
 def test_pinned_serializer_shape_old_refusal_new_exact_join(self):
  d,r=fixture();self.assertEqual(d[1]['cmd'],['/usr/bin/true','']);self.assertEqual(d[1]['env'],{'EMPTY':''})
  with self.assertRaisesRegex(ValueError,'typed introspection invocation'):O.audit(*encode(d,r))
  v=A.audit(*encode(d,r));self.assertEqual(v['tests'],2);self.assertEqual(v['results'],{'OK':2});self.assertEqual(v['process_util'],r[0]);self.assertEqual(v['native_acceptance'],'NOT_GRANTED_BY_AUDITOR')
 def test_executable_and_token_type_refusals(self):
  for index,tokens in((0,('',None,1,False)),(1,(None,1,False,[]))):
   for token in tokens:
    d,r=fixture();d[1]['cmd'][index]=token;r[1]['command'][index]=token
    with self.subTest(index=index,token=token),self.assertRaises(ValueError):A.audit(*encode(d,r))
 def test_exact_argv_env_and_full_record_join(self):
  for drift in('drop_empty','change_empty','env','missing','duplicate'):
   d,r=fixture()
   if drift=='drop_empty':r[1]['command'].pop()
   elif drift=='change_empty':r[1]['command'][1]='changed'
   elif drift=='env':r[1]['env']['EMPTY']='changed'
   elif drift=='missing':r.pop()
   else:r.append(copy.deepcopy(r[1]))
   with self.subTest(drift=drift),self.assertRaises(ValueError):A.audit(*encode(d,r))
 def test_non_skipped_process_util_and_exact_unique_marker(self):
  for drift in('skip','fail','returncode','wrapper','missing_marker','duplicate_marker','foreign_marker'):
   d,r=fixture()
   if drift=='skip':r[0].update(result='SKIP',returncode=77)
   elif drift=='fail':r[0].update(result='FAIL',is_fail=True,returncode=1)
   elif drift=='returncode':r[0]['returncode']=1
   elif drift=='wrapper':d[0]['cmd'][0]=r[0]['command'][0]='/other/wrapper'
   elif drift=='missing_marker':r[0]['stdout']=''
   elif drift=='duplicate_marker':r[0]['stdout']+=A.MARKER+'\n'
   else:r[1]['stdout']=A.MARKER+'\n'
   with self.subTest(drift=drift),self.assertRaises(ValueError):A.audit(*encode(d,r))
 def test_real_raw_files_retained_before_failed_audit(self):
  d,r=fixture();r[0].update(result='SKIP',returncode=77);raw,intro=encode(d,r)
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);log=root/'log';plan=root/'plan';log.write_bytes(raw);plan.write_bytes(intro);out=root/'out';out.mkdir()
   def save(path,body):
    self.assertEqual(Path(path).parent,Path('/out'));A_original_save(str(out/Path(path).name),body)
   env=dict(CACHY_ASAHI_CORE_TESTLOG_EXPORT='1',CACHY_ASAHI_CORE_CONTAINER='1',CORE_RECIPE='systemd');A_original_save=A.save
   with patch.dict(os.environ,env,clear=True),patch.object(sys,'argv',['auditor',str(log),str(plan)]),patch.object(A,'save',side_effect=save),self.assertRaisesRegex(ValueError,'skip/failure'):A.main()
   self.assertEqual({p.name:p.read_bytes()for p in out.iterdir()},{'systemd-testlog.jsonl':raw,'systemd-intro-tests.json':intro})
   with patch.dict(os.environ,dict(env,CORE_RECIPE='pacman'),clear=True),patch.object(sys,'argv',['auditor',str(log),str(plan)]),patch.object(A,'save',side_effect=AssertionError('NO_EXPORT')),self.assertRaisesRegex(ValueError,'export scope'):A.main()
 def test_whole_four_edit_inverse_and_assertion_suffix_held(self):
  text=F.read(NEW).decode();old=F.read(HERE/'test_support/testlog-before.py').decode();delta=F.decode(F.read(HERE/'fixtures/auditor-delta.json'))
  for before,after in reversed(delta['edits']):self.assertEqual(text.count(after),1);text=text.replace(after,before,1)
  self.assertEqual(text,old);self.assertEqual((A.CAP,A.BAD,A.MARKER),(O.CAP,O.BAD,O.MARKER));self.assertEqual(F.read(NEW).decode().split(' hits=[',1)[1].split('def save',1)[0],old.split(' hits=[',1)[1].split('def save',1)[0])
if __name__=='__main__':unittest.main(verbosity=2)
