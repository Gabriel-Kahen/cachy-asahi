# SPDX-License-Identifier: MIT
"""Verified emitted SOURCE and private fixtures; genuine ALPM/native NOT_RUN."""
import importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent;s=importlib.util.spec_from_file_location('_gnu_extraction_factory_source_controls',HERE/'prepare.py');B=importlib.util.module_from_spec(s);s.loader.exec_module(B)

class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.parent=B.canonical(os.environ['GNU_EXTRACT_PARENT']);cls.expected=B.canonical(os.environ['GNU_EXTRACT_EXPECTED']);cls.before=B.snapshot(cls.parent);cls.target=B.snapshot(cls.expected);cls.tmp=tempfile.TemporaryDirectory(prefix='gnu-extraction-emitted-source-',dir=HERE.parent);cls.work=Path(cls.tmp.name);cls.out=cls.work/'source';B.emit(cls.parent,cls.out,True);assert B.snapshot(cls.out)[0]==cls.target[0];cls.temp=cls.work/'temporary';cls.temp.mkdir(mode=0o700)
 @classmethod
 def tearDownClass(cls):
  assert B.snapshot(cls.parent)==cls.before and B.snapshot(cls.expected)==cls.target
  cls.tmp.cleanup()
 def run_python(self,arguments,cap):
  environment=dict(os.environ,PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TMPDIR=str(self.temp),PYTHONDONTWRITEBYTECODE='1');r=subprocess.run([sys.executable,'-I','-B','-Werror',*map(str,arguments)],stdin=subprocess.DEVNULL,capture_output=True,timeout=cap,env=environment);self.assertEqual((r.returncode,r.stderr),(0,b''),r.stderr.decode(errors='replace'));return r.stdout

 def test_complete_current_SOURCE_and_all_parent_gates_actors_blocked(self):
  entry=self.out/B.LANE/'entry.py'
  code="import runpy,subprocess,sys;from pathlib import Path;from unittest.mock import patch;entry=sys.argv[1];root=sys.argv[2];sys.path.insert(0,str(Path(entry).parent));sys.argv=[entry,'source','--source',root]\nwith patch.object(subprocess,'Popen',side_effect=AssertionError('SOURCE_ONLY_NO_ACTORS_API_GIT')),patch.object(subprocess,'run',side_effect=AssertionError('SOURCE_ONLY_NO_ACTORS_API_GIT')),patch.object(subprocess,'check_output',side_effect=AssertionError('SOURCE_ONLY_NO_ACTORS_API_GIT')):runpy.run_path(entry,run_name='__main__')"
  value=json.loads(self.run_python(['-c',code,entry,self.out],300));self.assertEqual(value['files'],771);self.assertEqual(value['whole_candidate_parent766']['files'],766);self.assertEqual(value['whole_candidate_parent766']['whole_remove_parent749']['files'],749);self.assertTrue(all(value[n]is None for n in('actual_source','actual_ref','actual_run','Root_acceptance')));self.assertEqual(value['candidate_extraction_native'],'NOT_RUN')

 def test_all_normal_REMOVE_derivatives_and_both_extraction_profiles_and_private667(self):
  code="""import json,shutil,subprocess,sys
from pathlib import Path
from unittest.mock import patch
root=Path(sys.argv[1]);work=Path(sys.argv[2]);sys.path.insert(0,str(root/'scripts/ci/gnu-immutable-source-native'));import fixed_case as F,interruption_case as I,extraction_case as X
with patch.object(subprocess,'Popen',side_effect=AssertionError('SOURCE_ONLY_NO_ACTORS')),patch.object(subprocess,'run',side_effect=AssertionError('SOURCE_ONLY_NO_ACTORS')):
 base=F.snapshot(root/'runtime');q=json.loads((root/'scripts/ci/gnu-immutable-source-native/candidate-extraction-profile.json').read_bytes());assert len(base)==667
 for case in F.CASES:assert X.render(base,case,F,'normal')==I.render(base,case,F,'normal')
 for case in I.CASES:
  previous,_=I.render(base,case,F,'remove-interruption');assert X.render(base,case,F,'remove-interruption')==I.render(base,case,F,'remove-interruption');after,ledger=X.render(base,case,F,X.OPERATION);assert{n:I.pin(b)for n,b in after.items()}==q['runtime_profiles'][case];back=I.inverse(after,ledger);back['runtime-source.json']=previous['runtime-source.json'];assert back==previous
  private=work/('private-'+case);private.mkdir(mode=0o700);selected=private/'selected-runtime';shutil.copytree(root/'runtime',selected);receipt=X.prepare(selected,case,X.OPERATION);assert receipt['actual_acceptance']is False and F.snapshot(selected)==after and X.verify_selected(root,selected,case,X.OPERATION)['files']==667
  with(selected/'immutable/worker.py').open('ab')as out:out.write(b'\\n')
  try:X.verify_selected(root,selected,case,X.OPERATION)
  except ValueError:pass
  else:raise AssertionError('changed selected worker accepted')
 for bad in('both','unknown',None,True):
  try:X.selector(bad,X.OPERATION)
  except ValueError:pass
  else:raise AssertionError('nonselected extraction accepted')
print(json.dumps(dict(status='PASS_WHOLE_NORMAL_REMOVE_AND_NEW_PRIVATE667',cases=2,native='NOT_RUN')))
"""
  value=json.loads(self.run_python(['-c',code,self.out,self.work],60));self.assertEqual(value['status'],'PASS_WHOLE_NORMAL_REMOVE_AND_NEW_PRIVATE667')

 def run_unittest(self,name,groups):
  environment=dict(os.environ,PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TMPDIR=str(self.temp),PYTHONDONTWRITEBYTECODE='1');path=self.out/B.LANE/name;r=subprocess.run([sys.executable,'-I','-B','-Werror',str(path),'--source',str(self.out)],stdin=subprocess.DEVNULL,capture_output=True,timeout=60,env=environment);self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'));self.assertIn(('Ran '+str(groups)+' tests').encode(),r.stderr);self.assertTrue(r.stderr.rstrip().endswith(b'OK'));self.assertEqual(r.stdout,b'')
 def test_actual_emitted_candidate_helper_ten_fixture_groups(self):self.run_unittest('test_candidate_extraction.py',10)
 def test_byte_held_REMOVE_helper_five_fixture_groups(self):self.run_unittest('test_interruption.py',5)

if __name__=='__main__':unittest.main(verbosity=2)
