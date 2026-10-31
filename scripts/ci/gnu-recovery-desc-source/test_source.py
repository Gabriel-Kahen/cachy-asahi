# SPDX-License-Identifier: MIT
"""Actual verified emitted SOURCE controls; native recovery remains NOT_RUN."""
import importlib.util,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent;s=importlib.util.spec_from_file_location('_gnu_recovery_factory_source_controls',HERE/'prepare.py');B=importlib.util.module_from_spec(s);s.loader.exec_module(B)

class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.parent=B.canonical(os.environ['GNU_RECOVERY_PARENT']);cls.expected=B.canonical(os.environ['GNU_RECOVERY_EXPECTED']);cls.before=B.snapshot(cls.parent);cls.target=B.snapshot(cls.expected);cls.tmp=tempfile.TemporaryDirectory(prefix='gnu-recovery-emitted-source-',dir=HERE.parent);cls.work=Path(cls.tmp.name);cls.out=cls.work/'source';B.emit(cls.parent,cls.out,True);assert B.snapshot(cls.out)[0]==cls.target[0];cls.temp=cls.work/'temporary';cls.temp.mkdir(mode=0o700)
 @classmethod
 def tearDownClass(cls):
  assert B.snapshot(cls.parent)==cls.before and B.snapshot(cls.expected)==cls.target
  cls.tmp.cleanup()
 def run_python(self,arguments,cap):
  environment=dict(os.environ,PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TMPDIR=str(self.temp),PYTHONDONTWRITEBYTECODE='1');r=subprocess.run([sys.executable,'-I','-B','-Werror',*map(str,arguments)],stdin=subprocess.DEVNULL,capture_output=True,timeout=cap,env=environment);self.assertEqual((r.returncode,r.stderr),(0,b''),r.stderr.decode(errors='replace'));return r.stdout

 def test_complete_current775_SOURCE_and_all_parent_gates_actors_blocked(self):
  entry=self.out/B.LANE/'entry.py'
  code="import runpy,subprocess,sys;from pathlib import Path;from unittest.mock import patch;entry=sys.argv[1];root=sys.argv[2];sys.path.insert(0,str(Path(entry).parent));sys.argv=[entry,'source','--source',root]\nwith patch.object(subprocess,'Popen',side_effect=AssertionError('SOURCE_ONLY_NO_ACTORS_API_GIT')),patch.object(subprocess,'run',side_effect=AssertionError('SOURCE_ONLY_NO_ACTORS_API_GIT')),patch.object(subprocess,'check_output',side_effect=AssertionError('SOURCE_ONLY_NO_ACTORS_API_GIT')):runpy.run_path(entry,run_name='__main__')"
  value=json.loads(self.run_python(['-c',code,entry,self.out],300));self.assertEqual(value['files'],775);self.assertEqual(value['whole_recovery_database_parent771']['files'],771);self.assertEqual(value['whole_recovery_database_parent771']['whole_candidate_parent766']['files'],766);self.assertEqual(value['whole_recovery_database_parent771']['whole_candidate_parent766']['whole_remove_parent749']['files'],749);self.assertTrue(all(value[n]is None for n in('actual_source','actual_ref','actual_run','Root_acceptance')));self.assertEqual(value['recovery_database_native'],'NOT_RUN')

 def test_normal_byte_exact_and_both_selected_raw_profiles_private667(self):
  code="""import ast,json,shutil,subprocess,sys
from pathlib import Path
from unittest.mock import patch
root=Path(sys.argv[1]);work=Path(sys.argv[2]);sys.path.insert(0,str(root/'scripts/ci/gnu-immutable-source-native'));import fixed_case as F,interruption_case as I,extraction_case as X
with patch.object(subprocess,'Popen',side_effect=AssertionError('SOURCE_ONLY_NO_ACTORS')),patch.object(subprocess,'run',side_effect=AssertionError('SOURCE_ONLY_NO_ACTORS')):
 base=F.snapshot(root/'runtime');q=json.loads((root/'scripts/ci/gnu-immutable-source-native/recovery-database-profile.json').read_bytes());helper=(root/'scripts/ci/gnu-immutable-source-native/recovery_database.py').read_bytes();assert len(base)==667
 for case in F.CASES:assert X.render(base,case,F,'normal')==F.render(base,case)
 for case in I.CASES:
  for operation in('remove-interruption',X.OPERATION):
   after,ledger=X.render(base,case,F,operation);assert{n:I.pin(b)for n,b in after.items()}==q['runtime_profiles'][operation][case]
   previous=F.render(base,case)[0]if operation=='remove-interruption'else I.render(base,case,F,'remove-interruption')[0];back=I.inverse(after,ledger);back['runtime-source.json']=previous['runtime-source.json'];assert back==previous
   tree=ast.parse(after['immutable/worker.py']);assignments={node.targets[0].id:node.value for node in tree.body if isinstance(node,ast.Assign)and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)}
   assert ast.literal_eval(assignments['RECOVERY_DATABASE_BODY'])==helper and ast.literal_eval(assignments['RECOVERY_DATABASE_PIN'])==I.pin(helper)
   private=work/('private-'+case+'-'+operation);private.mkdir(mode=0o700);selected=private/'selected-runtime';shutil.copytree(root/'runtime',selected);receipt=X.prepare(selected,case,operation);assert receipt['actual_acceptance']is False and receipt['profile']['recovery_database_evidence']=='REQUIRED_BOUNDED_RAW_DESC_V1'and F.snapshot(selected)==after and X.verify_selected(root,selected,case,operation)['files']==667
   with(selected/'immutable/worker.py').open('ab')as out:out.write(b'\\n')
   try:X.verify_selected(root,selected,case,operation)
   except ValueError:pass
   else:raise AssertionError('changed selected worker accepted')
 for bad in('both','unknown',None,True):
  for operation in('remove-interruption',X.OPERATION):
   try:X.selector(bad,operation)
   except ValueError:pass
   else:raise AssertionError('nonselected interruption accepted')
print(json.dumps(dict(status='PASS_NORMAL_AND_BOTH_RAW_EVIDENCE_PRIVATE667',cases=2,operations=2,native='NOT_RUN')))
"""
  value=json.loads(self.run_python(['-c',code,self.out,self.work],60));self.assertEqual(value['status'],'PASS_NORMAL_AND_BOTH_RAW_EVIDENCE_PRIVATE667')

 def test_real_emitted_parser_normalizes_only_ascii_INSTALLDATE_span(self):
  code="""import base64,copy,importlib.util,json,sys
from pathlib import Path
root=Path(sys.argv[1]);path=root/'scripts/ci/gnu-immutable-source-native/recovery_database.py';s=importlib.util.spec_from_file_location('_actual_emitted_raw_parser',path);M=importlib.util.module_from_spec(s);s.loader.exec_module(M)
raw=b'%NAME%\\nglibc\\n\\n%VERSION%\\nheld\\n\\n%INSTALLDATE%\\n1234567890\\n\\n%REASON%\\n0\\n\\n%VALIDATION%\\nnone\\n\\n';start=raw.index(b'1234567890');end=start+10
def capture(value):
 fields,date,normalized=M.parse(value);return dict(raw_base64=base64.b64encode(value).decode(),logical_node=dict(type='file',mode=420,uid=0,gid=0),parse_error=None)
before=capture(raw)
for n in range(len(raw)):
 if start<=n<end:continue
 altered=raw[:n]+bytes([raw[n]^1])+raw[n+1:]
 try:after=capture(altered)
 except(ValueError,UnicodeError):continue
 assert M.compare(before,after)['normalized_bytes_equal']is False
for date in(b'0',b'1',b'00000000000000000000',b'9223372036854775807'):
 after=capture(raw[:start]+date+raw[end:]);comparison=M.compare(before,after);assert all(comparison[k]is True for k in('metadata_equal','field_order_equal','field_values_equal_except_install_date','normalized_bytes_equal'))
for date in(b'-1',b'+1',b'1.0',b'9223372036854775808',b'0'*21,'１２'.encode(),'١'.encode(),b'1\\n2'):
 try:M.parse(raw[:start]+date+raw[end:])
 except(ValueError,UnicodeError):pass
 else:raise AssertionError('noncanonical numeric date accepted')
for key,value in(('type','symlink'),('mode',384),('uid',1),('gid',1)):
 altered=copy.deepcopy(before);altered['logical_node'][key]=value;assert M.compare(before,altered)['metadata_equal']is False
print(json.dumps(dict(status='PASS_EVERY_NON_DATE_BYTE_AND_METADATA_BINDING',native='NOT_RUN')))
"""
  self.assertEqual(json.loads(self.run_python(['-c',code,self.out],30))['status'],'PASS_EVERY_NON_DATE_BYTE_AND_METADATA_BINDING')

 def run_unittest(self,name,groups):
  environment=dict(os.environ,PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',TMPDIR=str(self.temp),PYTHONDONTWRITEBYTECODE='1');path=self.out/B.LANE/name;r=subprocess.run([sys.executable,'-I','-B','-Werror',str(path),'--source',str(self.out)],stdin=subprocess.DEVNULL,capture_output=True,timeout=60,env=environment);self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'));self.assertIn(('Ran '+str(groups)+' tests').encode(),r.stderr);self.assertTrue(r.stderr.rstrip().endswith(b'OK'));self.assertEqual(r.stdout,b'')
 def test_exact_emitted_raw_descriptor_four_groups(self):self.run_unittest('test_recovery_database.py',4)
 def test_held_candidate_helper_ten_fixture_groups(self):self.run_unittest('test_candidate_extraction.py',10)
 def test_held_REMOVE_helper_five_fixture_groups(self):self.run_unittest('test_interruption.py',5)

if __name__=='__main__':unittest.main(verbosity=2)
