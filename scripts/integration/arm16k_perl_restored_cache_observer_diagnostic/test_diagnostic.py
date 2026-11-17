# SPDX-License-Identifier: MIT
"""Finite failure-observability controls; actual r96 frame/cause remain unknown."""
import ast,copy,hashlib,importlib.util,json,sys,tempfile,time,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
def load(name,path=None):
 s=importlib.util.spec_from_file_location('diagnostic_control_'+name,path or HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
T=load('test_observer');D=load('diagnostic');M=load('inode_metadata');OldM=load('old_inode',HERE/'observer-preimages/inode_metadata.py')
# The exact old module resolves its immutable reader beside the reviewed new
# copy; this relocates only the test import root, not a source body or guard.
OldM.HERE=HERE
class Controls(unittest.TestCase):
 def test_projection_masks_all_xattr_names_values_and_arbitrary_text(self):
  _,rows=T.synthetic();raw=T.frame(rows[T.R.PATHS[0]])+b'Extended attributes:\n  user.PRIVATE (6) = "SECRET"\nUser: 999   Group: 999    Size: 999\nprivate-path=/root/.ssh/NEVER\n'
  result=D.projection(raw);text=json.dumps(result)
  for forbidden in('PRIVATE','SECRET','/root','user.'):self.assertNotIn(forbidden,text)
  self.assertEqual(result['xattr_lines_masked'],3);self.assertEqual(result['candidates']['values']['uid'],0)
  self.assertEqual(result['frame'],D.pin(raw))
 def test_stage_label_inode_and_count_vocabulary_refuse_arbitrary_values(self):
  with tempfile.TemporaryDirectory()as tmp:
   state=D.State(Path(tmp),T.R.labels())
   for kwargs in(dict(name='PRIVATE_STAGE'),dict(name='PARSE_STAT',label='PRIVATE_COMMAND'),dict(name='INODE_READ',inode=3)):
    with self.assertRaises(ValueError):state.stage(**kwargs)
   with self.assertRaises(ValueError):state.counts([{'SECRET':'VALUE'}]*3)
   self.assertFalse((Path(tmp)/'scan').exists())
 def test_actual_typed_mismatch_ten_reachable_fields_keeps_old_refusal_and_exact_bits(self):
  body,rows=T.synthetic()
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);image=root/'inert.img';image.write_bytes(body)
   for field in D.FIELDS:
    # FrozenReader constructs inode from the selected number itself. Changing
    # that selection exercises earlier alias/unused-inode guards, not a false
    # inode equality bit. All11 original comparison expressions stay intact.
    if field=='inode':continue
    changed=copy.deepcopy(rows);value=changed[T.R.PATHS[0]][field];changed[T.R.PATHS[0]][field]='directory'if field=='type'else value+1
    with self.subTest(field=field):
     with self.assertRaisesRegex(ValueError,'independent selected inode typed fields')as old:OldM.observe(image,changed,time.monotonic()+5)
     out=root/field;out.mkdir(mode=0o700);state=D.State(out,T.R.labels());state.stage('INODE_READ','restored-aux-before')
     try:
      with self.assertRaisesRegex(ValueError,'independent selected inode typed fields')as new:M.observe(image,changed,time.monotonic()+5,state)
      self.assertIs(type(new.exception),type(old.exception));state.fail(new.exception)
      v=json.loads((out/'scan/diagnostic.DATA.json').read_bytes());self.assertEqual(v['stage'],D.STAGES.index('INODE_TYPED_COMPARE'));self.assertEqual(v['command'],12);self.assertEqual(v['inode'],0)
      bits=v['typed_comparisons']['0']['equal_bits'];self.assertEqual({k for k,v in bits.items()if not v},{field});self.assertEqual(v['fault']['message_prefix'],D.pin(str(old.exception).encode()));self.assertEqual(v['outcome'],'REFUSED_UNCHANGED_PREDICATE')
     finally:state.close()
 def test_inode_alias_guard_is_unchanged_and_precedes_typed_comparison(self):
  body,rows=T.synthetic();rows[T.R.PATHS[0]]['inode']=2
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);image=root/'inert.img';image.write_bytes(body);state=D.State(root,T.R.labels());state.stage('INODE_READ','restored-aux-before')
   try:
    for observer in(OldM,M):
     with self.assertRaisesRegex(ValueError,'no aliases among selected public inodes'):observer.observe(image,rows,time.monotonic()+5)
    with self.assertRaisesRegex(ValueError,'no aliases among selected public inodes')as error:M.observe(image,rows,time.monotonic()+5,state)
    state.fail(error.exception);self.assertEqual(state.value['typed_comparisons'],{});self.assertEqual(state.value['stage'],D.STAGES.index('INODE_READ'))
   finally:state.close()
 def test_positive_real_synthetic_metadata_is_identical_with_diagnostics(self):
  body,rows=T.synthetic(True)
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);image=root/'inert.img';image.write_bytes(body);state=D.State(root,T.R.labels());state.stage('INODE_READ','restored-aux-before')
   try:
    actual=M.observe(image,rows,time.monotonic()+5,state);expected=OldM.observe(image,rows,time.monotonic()+5);self.assertEqual(actual,expected)
    self.assertTrue(all(all(row['equal_bits'].values())for row in state.value['typed_comparisons'].values()));self.assertNotIn('SECRET',json.dumps(state.value))
   finally:state.close()
 def test_parse_normalize_and_xattr_count_fault_models_remain_refusals(self):
  E=load('observe_initialized');_,rows=T.synthetic();good=T.frame(rows[T.R.PATHS[0]])
  for stage,raw,call in(('NORMALIZE',good+good,lambda raw:E.normalize(raw,T.R.S)),('PARSE_STAT',good+b'UNKNOWN_PRIVATE\n',lambda raw:T.R.S.parse_stat(raw,T.R.PATHS[0])),('XATTR_DISPLAY_COUNT',good+b'Extended attributes:\n'+b'  user.x (0)\n'*65,lambda raw:T.R.S.printed_xattr_count(raw,T.R.PATHS[0]))):
   with tempfile.TemporaryDirectory()as tmp:
    state=D.State(Path(tmp),T.R.labels());state.stage(stage,'restored-aux-before');state.frame(raw)
    try:
     with self.assertRaises(ValueError)as error:call(raw)
     state.fail(error.exception);v=json.loads((Path(tmp)/'scan/diagnostic.DATA.json').read_bytes());self.assertEqual(v['stage'],D.STAGES.index(stage));self.assertEqual(v['frame'],D.pin(raw));self.assertNotIn('UNKNOWN_PRIVATE',json.dumps(v));self.assertNotIn('user.x',json.dumps(v))
    finally:state.close()
 def test_exception_projection_is_finite_and_never_exports_text(self):
  value=D.exception(ValueError('PRIVATE'*1000));self.assertTrue(value['message_truncated']);self.assertEqual(value['message_prefix']['bytes'],4096);self.assertNotIn('PRIVATE',json.dumps(value))
  class PrivateType(Exception):pass
  self.assertEqual(D.exception(PrivateType('SECRET'))['type'],'OTHER_EXCEPTION')
 def test_all_original_guard_calls_and_fail_closed_expressions_preserved(self):
  def guards(raw):
   return [ast.dump(n,include_attributes=False)for n in ast.walk(ast.parse(raw))if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='need']
  for name in('observe_initialized.py','inode_metadata.py'):
   old=guards((HERE/'observer-preimages'/name).read_bytes());new=guards((HERE/name).read_bytes())
   for guard in old:self.assertIn(guard,new,name)
  self.assertEqual((HERE/'observer-preimages/stat_decoder.py').read_bytes(),(HERE/'stat_decoder.py').read_bytes())
 def test_diagnostic_finalization_fits_prevalidated_size_and_never_accepts(self):
  with tempfile.TemporaryDirectory()as tmp:
   state=D.State(Path(tmp),T.R.labels());state.summary_pending();before=(Path(tmp)/'scan/diagnostic.DATA.json').stat().st_size;state.complete();state.close()
   p=Path(tmp)/'scan/diagnostic.DATA.json';value=json.loads(p.read_bytes());self.assertLessEqual(p.stat().st_size,before);self.assertEqual(value['outcome'],'COMPLETED_PREDICATES');self.assertIsNone(value['Root_acceptance']);self.assertIsNone(value['lifecycle_acceptance'])
if __name__=='__main__':unittest.main(verbosity=2)
