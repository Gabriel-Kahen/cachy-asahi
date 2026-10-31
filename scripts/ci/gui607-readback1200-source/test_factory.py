# SPDX-License-Identifier: MIT
"""Literal public output and immutable policy/path controls; no source actors."""
import base64,builtins,importlib.util,json,os,shutil,stat,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('exact_readback_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
SOURCE=F.ordinary(os.environ['GUI_READBACK_INPUT']);EXPECTED=F.ordinary(os.environ['GUI_READBACK_EXPECTED'])
class Controls(unittest.TestCase):
 def test_literal_production_cli_both_receipts_exact_public_under_umask077(self):
  expected=F.tree(EXPECTED)
  with tempfile.TemporaryDirectory()as td:
   for context in('known','null'):
    out=Path(td)/context;p=subprocess.run([sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--source',str(SOURCE),'--output',str(out),'--context',context],capture_output=True,timeout=30,umask=0o077);self.assertEqual(p.returncode,0,p.stderr.decode());receipt=json.loads(p.stdout);self.assertEqual(F.tree(out),expected);self.assertEqual(receipt['files'],{n:F.pin(b)for n,b in expected.items()});self.assertEqual(receipt['source']is None,context=='null');self.assertEqual((receipt['held'],receipt['changed']),(683,9));self.assertTrue(all(receipt[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')));self.assertTrue(all(stat.S_IMODE((out/n).stat().st_mode)==0o644 for n in expected));d=json.loads((out/'implementation/build-inventory-parent.json').read_bytes())['selected_readback'];self.assertEqual(d['source'],'0e7211b326679319b4454bfe2a1c1e8e9b0aac29')
 def test_constructor_never_executes_supplied_source_or_decodes_beforedata(self):
  with patch.object(builtins,'exec',side_effect=AssertionError('NO_PARENT_EXEC')),patch.object(base64,'b64decode',side_effect=AssertionError('NO_BEFORE_DECODE')),patch.object(subprocess,'Popen',side_effect=AssertionError('NO_ACTORS')):values,p,unused,unused2=F.compose(SOURCE)
  self.assertEqual(values,F.tree(EXPECTED));self.assertEqual(p['counts'],dict(parent=692,result=692,held=683,changed=9,added=0))
 def test_whole692_inverse_current_policy_and_held_product_defaults(self):
  values,p,unused,unused2=F.compose(SOURCE);before=F.tree(SOURCE);d=json.loads(values['implementation/build-inventory-parent.json'])['selected_readback'];restored={n:base64.b64decode(d['before'][n],validate=True)if n in d['before']else values[n]for n in d['files']};self.assertEqual(restored,before)
  for n,rows in d['seams'].items():self.assertEqual(F.apply(values[n],rows,True),before[n])
  self.assertEqual(F.pin(values['implementation/runner-context-policy.json']),dict(bytes=33924,sha256='dc73b1aea955d67d96b4b7c6d3ed463852c884ffc46e70341a2c41ded9dcbf26'));self.assertEqual(sum(values[n]==b for n,b in before.items()),683)
  for n in('implementation/factory/installed607.py','implementation/factory/run.py','implementation/factory/factory.py','implementation/expected607.lock','implementation/body-inverses.json','implementation/factory/service-vm-profile.json','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-latest607-welcome8-gui.yml'):self.assertEqual(values[n],before[n],n)
 def test_old_staging_policy_and_profile_or_operand_mutation_refused_before_write(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)
   for name in('runner-context-policy.json.in','profile.json','build_inventory_guard.py.in','test-readback-method.py.in'):
    local=root/name.replace('.','_');shutil.copytree(HERE,local);target=local/name
    if name=='runner-context-policy.json.in':target.write_bytes(F.read(SOURCE/'implementation/runner-context-policy.json'))
    else:target.write_bytes(target.read_bytes()+b' ')
    previous=F.HERE
    try:
     F.HERE=local;out=root/(local.name+'-out')
     with self.subTest(name=name),self.assertRaises(ValueError):F.emit(SOURCE,out,'known')
     self.assertFalse(out.exists())
    finally:F.HERE=previous
 def test_source_drift_missing_foreign_empty_symlink_hardlink_fifo_refused(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)
   for kind in('drift','missing','foreign','empty','symlink','hardlink','fifo'):
    source=root/kind;shutil.copytree(SOURCE,source);leaf=source/'implementation/observer_apply.py'
    if kind=='drift':leaf.write_bytes(leaf.read_bytes()+b'\n')
    elif kind=='missing':leaf.unlink()
    elif kind=='foreign':(source/'foreign').write_bytes(b'foreign')
    elif kind=='empty':(source/'foreign-empty').mkdir()
    elif kind=='symlink':leaf.unlink();leaf.symlink_to(SOURCE/'implementation/observer_apply.py')
    elif kind=='hardlink':leaf.unlink();os.link(source/'implementation/observer_stage.py',leaf)
    else:leaf.unlink();os.mkfifo(leaf)
    out=root/(kind+'-output')
    with self.subTest(kind=kind),self.assertRaises(ValueError):F.emit(source,out,'known')
    self.assertFalse(out.exists())
 def test_early_normalized_alias_existing_actual_and_closed_context_refusals(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);source=root/'source';shutil.copytree(SOURCE,source);alias=root/'alias';alias.symlink_to(source,target_is_directory=True);actual=root/'native-actual-control';actual.mkdir()
   for supplied,out in((source,source),(source,source/'child'),(alias,root/'out'),(source,'relative'),(source,str(root)+'/a/../out'),(source,actual/'out'),(source,HERE/'out')):
    with self.subTest(out=out),self.assertRaises(ValueError):F.emit(supplied,out,'null')
   for supplied,out in((source,'//'+str(source).lstrip('/')+'/double-slash-output'),('//'+str(source).lstrip('/'),root/'alias-output')):
    command=[sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--source',str(supplied),'--output',str(out),'--context','null']
    before=F.scan(source);result=subprocess.run(command,capture_output=True,timeout=10)
    self.assertNotEqual(result.returncode,0);self.assertIn(b'canonical resolved path required',result.stderr);self.assertFalse(Path(out).exists());self.assertEqual(F.scan(source),before)
   with self.assertRaises(ValueError):F.emit(source,root/'absent','foreign')
   self.assertFalse((root/'absent').exists())
 def test_samebyte_replacement_and_late_profile_drift_refused_atime_excluded(self):
  self.assertNotIn('st_atime_ns',F.identity.__code__.co_consts)
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)
   for kind in('source','profile'):
    source=root/(kind+'-source');local=root/(kind+'-factory');shutil.copytree(SOURCE,source);shutil.copytree(HERE,local);original=F.scan;previous=F.HERE;calls=[]
    def scan(path):
     value=original(path)
     if Path(path)==source and not calls:
      calls.append(True)
      if kind=='source':leaf=source/'implementation/observer_apply.py';replacement=source/'replacement';replacement.write_bytes(leaf.read_bytes());os.replace(replacement,leaf)
      else:leaf=local/'profile.json';leaf.write_bytes(leaf.read_bytes()+b' ')
     return value
    try:
     F.HERE=local;out=root/(kind+'-output')
     with patch.object(F,'scan',side_effect=scan),self.assertRaises(ValueError):F.emit(source,out,'known')
     self.assertFalse(out.exists())
    finally:F.HERE=previous
if __name__=='__main__':unittest.main(verbosity=2)
