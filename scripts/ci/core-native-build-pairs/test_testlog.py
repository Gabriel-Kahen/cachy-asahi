# SPDX-License-Identifier: MIT
"""Authentic finite raw projection and original audit/refusal/retention controls."""
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
A=load('_maintained_default_auditor',NEW);O=load('_maintained_old_auditor',HERE/'test_support/testlog-before.py')
def fixture():return json.loads(F.read(HERE/'fixtures/meson-1.12.1-intro.json')),[json.loads(x)for x in F.read(HERE/'fixtures/actual-testlog-subset.jsonl').splitlines()]
def encode(d,r):return b''.join(json.dumps(x).encode()+b'\n'for x in r),json.dumps(d).encode()
class Controls(unittest.TestCase):
 def test_authentic_bare_project_default_wrapper_and_excluded_records_counted(self):
  d,r=fixture();self.assertEqual(d[0]['suite'],['systemd']);self.assertIn('',d[2]['cmd']);self.assertEqual(d[3]['name'],d[4]['name']);self.assertNotEqual(d[3]['cmd'],d[4]['cmd'])
  with self.assertRaisesRegex(ValueError,'typed test suite identity'):O.audit(*encode(d,r))
  v=A.audit(*encode(d,r));self.assertEqual((v['tests'],v['introspection_tests']),(2,5));self.assertEqual(v['default_setup']['excluded_tests'],3);self.assertEqual(v['results'],{'OK':2});self.assertEqual(v['native_acceptance'],'NOT_GRANTED_BY_AUDITOR')
 def test_all_definition_executables_and_token_types_still_validated(self):
  for index in(0,2,3):
   for token in('',None,1,False):
    d,r=fixture();d[index]['cmd'][0]=token
    with self.subTest(index=index,token=token),self.assertRaises(ValueError):A.audit(*encode(d,r))
  d,r=fixture();d[2]['cmd'][1]=None
  with self.assertRaises(ValueError):A.audit(*encode(d,r))
 def test_exact_default_argv_env_and_every_selected_record_required(self):
  for drift in('wrapper','argument','env','missing','duplicate','extra_definition','duplicate_definition','excluded_result'):
   d,r=fixture();p=next(x for x in r if x['name']=='test - systemd:test-process-util')
   if drift=='wrapper':p['command'][0]='/other/wrapper'
   elif drift=='argument':p['command'].append('')
   elif drift=='env':p['env']['PROJECT_BUILD_ROOT']='changed'
   elif drift=='missing':r.pop()
   elif drift=='duplicate':r.append(copy.deepcopy(r[0]))
   elif drift=='extra_definition':d.append(dict(d[0],name='extra-selected'))
   elif drift=='duplicate_definition':d.append(copy.deepcopy(d[2]))
   else:r.append(dict(r[0],name='clang-tidy - systemd:'+d[3]['name']))
   with self.subTest(drift=drift),self.assertRaises(ValueError):A.audit(*encode(d,r))
 def test_original_nonskip_process_util_and_unique_marker(self):
  for drift in('skip','fail','returncode','missing_marker','duplicate_marker','foreign_marker'):
   d,r=fixture();p=next(x for x in r if x['name']=='test - systemd:test-process-util')
   if drift=='skip':p.update(result='SKIP',returncode=77)
   elif drift=='fail':p.update(result='FAIL',is_fail=True,returncode=1)
   elif drift=='returncode':p['returncode']=1
   elif drift=='missing_marker':
    for key in('stdout','stderr'):
     if key in p:p[key]=p[key].replace(A.MARKER,'')
   elif drift=='duplicate_marker':p['stdout']+='\n'+A.MARKER+'\n'
   else:r[0]['stdout']+='\n'+A.MARKER+'\n'
   with self.subTest(drift=drift),self.assertRaises(ValueError):A.audit(*encode(d,r))
 def test_real_raw_files_retained_before_failed_audit(self):
  d,r=fixture();next(x for x in r if x['name']=='test - systemd:test-process-util').update(result='SKIP',returncode=77);raw,intro=encode(d,r)
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);log=root/'log';plan=root/'plan';log.write_bytes(raw);plan.write_bytes(intro);out=root/'out';out.mkdir();original_save=A.save
   def save(path,body):
    self.assertEqual(Path(path).parent,Path('/out'));original_save(str(out/Path(path).name),body)
   env=dict(CACHY_ASAHI_CORE_TESTLOG_EXPORT='1',CACHY_ASAHI_CORE_CONTAINER='1',CORE_RECIPE='systemd')
   with patch.dict(os.environ,env,clear=True),patch.object(sys,'argv',['auditor',str(log),str(plan)]),patch.object(A,'save',side_effect=save),self.assertRaisesRegex(ValueError,'skip/failure'):A.main()
   self.assertEqual({p.name:p.read_bytes()for p in out.iterdir()},{'systemd-testlog.jsonl':raw,'systemd-intro-tests.json':intro})
   with patch.dict(os.environ,dict(env,CORE_RECIPE='pacman'),clear=True),patch.object(sys,'argv',['auditor',str(log),str(plan)]),patch.object(A,'save',side_effect=AssertionError('NO_EXPORT')),self.assertRaisesRegex(ValueError,'export scope'):A.main()
 def test_whole_five_edit_inverse_bounds_and_original_assertion_suffix(self):
  text=F.read(NEW).decode();old=F.read(HERE/'test_support/testlog-before.py').decode();delta=F.decode(F.read(HERE/'fixtures/auditor-delta.json'));self.assertEqual(len(delta['edits']),5)
  for before,after in reversed(delta['edits']):self.assertEqual(text.count(after),1);text=text.replace(after,before,1)
  self.assertEqual(text,old);self.assertEqual((A.CAP,A.BAD,A.MARKER),(O.CAP,O.BAD,O.MARKER));self.assertEqual(F.read(NEW).decode().split(' hits=[',1)[1],old.split(' hits=[',1)[1].replace('tests=len(rows),results=dict(sorted(counts.items()))',delta['receipt_after']))
if __name__=='__main__':unittest.main(verbosity=2)
