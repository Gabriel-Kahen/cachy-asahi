# SPDX-License-Identifier: MIT
"""Portable exact factory/operative emission controls; no historical gate replay."""
import ast,base64,hashlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,types,unittest,zlib
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('_operative_binding_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(s);s.loader.exec_module(F)
SOURCE=Path(os.environ['REPAIR_BINDING_INPUT']).absolute();EXPECTED=Path(os.environ['REPAIR_BINDING_EXPECTED']).absolute()
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def embedded(raw):
 for n in ast.walk(ast.parse(raw)):
  if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='compile'and n.args and isinstance(n.args[0],ast.Constant)and type(n.args[0].value)is str and 'def projected_record'in n.args[0].value:return n.args[0].value
 raise AssertionError('operative helper not emitted')
class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory(dir=os.environ.get('REPAIR_BINDING_WORK'));self.addCleanup(self.temp.cleanup);self.work=Path(self.temp.name)
 def test_actual_known_null_cli_whole245_and_receipt(self):
  expected=F.scan(EXPECTED)[0]
  for context in('known','null'):
   output=self.work/context;receipt=self.work/(context+'.json');child=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--source',str(SOURCE),'--output',str(output),'--receipt',str(receipt),'--context',context],capture_output=True,timeout=30)
   self.assertEqual(child.returncode,0,child.stderr.decode());self.assertFalse(child.stderr);self.assertEqual(F.scan(output)[0],expected);r=json.loads(child.stdout);self.assertEqual(r['source']is None,context=='null');self.assertIsNone(r['actual']);self.assertIsNone(r['Root_acceptance']);self.assertEqual(json.loads(receipt.read_bytes())['file_map'],{n:F.pin(b)for n,b in expected.items()})
 def test_entire_parent_guard_inverse_functions_and_current_guard_only(self):
  values,p=F.compose(SOURCE);before=F.scan(SOURCE)[0];self.assertEqual(values,F.scan(EXPECTED)[0]);self.assertEqual(F.inverse(values,p),before);self.assertEqual(p['counts'],dict(before=245,after=245,held=236,changed=9,added=0));self.assertEqual(values[F.H],before[F.H]);self.assertNotEqual(F.literal(before[F.A])[1],before[F.H].decode());self.assertEqual(F.literal(values[F.A])[1],values[F.H].decode())
  functions=lambda raw:{n.name:ast.dump(n,include_attributes=False)for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
  self.assertEqual(functions(before[F.A]),functions(values[F.A]));guard=load('_exact_public_binding_guard',EXPECTED/F.G)
  def prior_source_only(old,profile):
   self.assertEqual({n:F.pin(b)for n,b in old.items()},profile['before']);return dict(source_files=242,actual=None,scope='PRIVATE_CALLBACK_NOT_SOURCE_QUALIFICATION')
  with patch.object(guard,'old_entry',side_effect=prior_source_only)as old:
   result=guard.prove(EXPECTED);self.assertEqual(result['source_files'],245);self.assertEqual(old.call_count,1)
  self.assertLess(len(values[F.Q]),8*1024**2)
 def test_actual_execution_lifecycle_embedding_and_complete247_buffer(self):
  values,p=F.compose(SOURCE);self.assertEqual(values,F.scan(EXPECTED)[0]);new=load('_actual_bound_adapter',EXPECTED/F.A);old=load('_nonoperative_parent_adapter',SOURCE/F.A);helper=values[F.H].decode();self.assertEqual(new._INSPECT_VALIDATION_SOURCE,helper);self.assertNotEqual(old._INSPECT_VALIDATION_SOURCE,helper)
  with patch.object(subprocess,'Popen',side_effect=AssertionError('NO_NATIVE_OR_API')):
   manifest=json.loads(values['scripts/ci/apps7-full574-repair-native/source-manifest.json']);receipt=new.execution(EXPECTED,self.work/'execution',manifest,inspect_profile=True);raw=(self.work/'execution/scripts/ci/apps7-full574-repair-native/transaction.py').read_bytes();self.assertEqual(embedded(raw),helper);self.assertEqual(receipt['changed'],['scripts/ci/apps7-full574-repair-native/transaction.py']);self.assertTrue(receipt['original_source_preserved'])
   life=new.lifecycle(values['scripts/ci/apps7-full574-repair-native/lifecycle.py'],inspect_profile=True);self.assertEqual(embedded(life),helper);self.assertEqual(old.rendered_backend(SOURCE),new.rendered_backend(EXPECTED));self.assertEqual(old.lifecycle(values['scripts/ci/apps7-full574-repair-native/lifecycle.py']),new.lifecycle(values['scripts/ci/apps7-full574-repair-native/lifecycle.py']))
  T=types.ModuleType('_trusted_emitted_helper');exec(compile(embedded(life),'<PRIVATE_EMITTED_HELPER>','exec'),vars(T));tree=ast.parse(life);node=next(n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='_VM_INSPECT_NOTE_SOURCE'for t in n.targets));note_source=ast.literal_eval(node.value)
  argv=['/usr/bin/python3','-I','-B',T.PATH,'inspect']
  for k in T.KEYS:argv.extend((k,T.FIXED.get(k,'/work/main'if k=='--workspace'else hashlib.sha256(k.encode()).hexdigest())))
  argv.extend((T.FLAG,T.PROFILE));out=hashlib.shake_256(b'PRIVATE_SYNTHETIC_STDOUT').digest(247);err=hashlib.shake_256(b'PRIVATE_SYNTHETIC_STDERR').digest(448);row=dict(argv=argv,exit_code=1,seconds=1201.25,time_limit=1210,output_limit=1024**2,group_absence_verified=True,stdout_bytes=len(out),stdout_sha256=T.pin(out)['sha256'],stderr_bytes=len(err),stderr_sha256=T.pin(err)['sha256']);note=T.note(note_source,row,out,err,None,0);self.assertLessEqual(len(note.encode()),1900);n=json.loads(note[len('APPS574_INSPECT_FAILURE '):]);projection=T.projected_record(n);self.assertEqual(projection['complete_returned_streams']['stdout'],T.pin(out));self.assertEqual(zlib.decompress(base64.b64decode(n['streams']['stdout']['base64'],validate=True)),out);self.assertEqual(n['command_row_source'],'SOURCE_PROJECTED_NOT_EXPORTED_COMMAND_ROW');self.assertFalse(n['acceptance_authority']);self.assertFalse(n['cleanup_authority'])
 def test_source_profile_operand_alias_namespace_and_wrong_parent_refuse_prewrite(self):
  for kind in('drift','missing','extra','empty','symlink','hardlink'):
   source=self.work/kind;shutil.copytree(SOURCE,source);leaf=source/F.H
   if kind=='drift':leaf.write_bytes(leaf.read_bytes()+b'\n')
   elif kind=='missing':leaf.unlink()
   elif kind=='extra':(source/'foreign').write_bytes(b'x')
   elif kind=='empty':(source/'foreign').mkdir()
   elif kind=='symlink':leaf.unlink();leaf.symlink_to(SOURCE/F.H)
   else:leaf.unlink();os.link(source/F.A,leaf)
   with self.subTest(kind=kind),self.assertRaises(ValueError):F.emit(source,self.work/(kind+'-out'),'known')
   self.assertFalse((self.work/(kind+'-out')).exists())
  with self.assertRaises(ValueError):F.emit(EXPECTED,self.work/'wrong-parent','known')
  factory=self.work/'factory';shutil.copytree(HERE,factory);(factory/'guard-edits.json').write_bytes(b'[]\n')
  with patch.object(F,'HERE',factory),self.assertRaises(ValueError):F.emit(SOURCE,self.work/'bad-operands','known')
  self.assertFalse((self.work/'bad-operands').exists())
  (factory/'guard-edits.json').write_bytes((HERE/'guard-edits.json').read_bytes());(factory/'profile.json').write_bytes(b'{}\n')
  with patch.object(F,'HERE',factory),self.assertRaisesRegex(ValueError,'fixed portable'):F.emit(SOURCE,self.work/'bad-profile','known')
  self.assertFalse((self.work/'bad-profile').exists())
 def test_canonical_disjoint_late_same_byte_inode_and_receipt_refusals(self):
  alias=self.work/'alias';alias.symlink_to(SOURCE,target_is_directory=True)
  for source,output in((SOURCE,SOURCE/'nested'),(SOURCE,HERE/'nested'),(alias,self.work/'out'),(SOURCE,'relative'),(SOURCE,str(self.work)+'/a/../out'),(SOURCE,'//tmp/foreign')):
   with self.assertRaises(ValueError):F.emit(source,output,'known')
  with self.assertRaises(ValueError):F.emit(SOURCE,self.work/'out','other')
  with self.assertRaises(ValueError):F.emit(SOURCE,self.work/'out','known',SOURCE/'receipt.json')
  source=self.work/'late-input';shutil.copytree(SOURCE,source);original=F.scan;seen=[]
  def swap(root):
   value=original(root)
   if root==source and not seen:
    seen.append(True);leaf=source/F.H;temporary=leaf.with_suffix('.swap');temporary.write_bytes(leaf.read_bytes());temporary.replace(leaf)
   return value
  with patch.object(F,'scan',side_effect=swap),self.assertRaisesRegex(ValueError,'late'):F.emit(source,self.work/'late-output','known',self.work/'late-receipt.json')
  self.assertFalse((self.work/'late-output').exists());self.assertFalse((self.work/'late-receipt.json').exists())
if __name__=='__main__':unittest.main(verbosity=2)
