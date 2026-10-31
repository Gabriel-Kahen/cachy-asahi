# SPDX-License-Identifier: MIT
"""Exercise exact emission and real native-source refusal/retirement boundaries."""
import importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('apps16_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
P,Q,E=[Path(os.environ[n]).absolute()for n in ('APPS15_NATIVE_SOURCE','APPS16_RECIPE_SOURCE','APPS16_NATIVE_SOURCE')]
ORDERED_GATE_PROBE="import json,sys,tempfile\nfrom pathlib import Path\nsys.path.insert(0,sys.argv[1]);import contract as C\nmarkers=C.row(C.ROLES['apps'])['check_markers'];groups=['Ran 54 tests in 1.000s\\nOK','Ran 32 tests in 1.000s\\nOK','Ran 8 tests in 1.000s\\nOK']\ngroup_text='\\n'.join(groups)+'\\n';prefix='\\n'.join(['Starting check()',*[m for m in markers if m not in group_text]])+'\\n';valid=prefix+group_text\nnegative=[valid.replace('Ran 54 tests','Ran 45 tests'),valid.replace('Ran 32 tests','Ran 24 tests'),valid.replace('Ran 32 tests','Ran 18 tests'),valid.replace('Ran 32 tests','Ran 15 tests'),valid.replace('Ran 32 tests','Ran 8 tests'),valid.replace('Ran 8 tests','Ran 32 tests'),prefix+'\\n'.join((groups[0],groups[2],groups[1]))+'\\n',valid.replace(groups[1],''),valid.replace(groups[2],''),valid.replace('Ran 54 tests','Ran 44 tests'),valid+'Ran 1 test in 1.000s\\nOK\\n',valid+'OK\\n',valid+'FAILED (failures=1)\\n',valid+'ERROR: control\\n',valid+'OK (skipped=1)\\n']\nwith tempfile.TemporaryDirectory(prefix='apps16-source-gate-')as td:\n p=Path(td)/'build.log';p.write_text(valid);assert C.check_log(p,C.ROLES['apps'])['status']=='PASS_CHECK_EXIT_NO_SKIPS'\n for raw in negative:\n  p.write_text(raw)\n  try:C.check_log(p,C.ROLES['apps'])\n  except ValueError:pass\n  else:raise AssertionError('incomplete/swapped/old/failed/skipped group admitted')\nprint(json.dumps(dict(status='PASS_ACTUAL_EMITTED_ORDERED54_32_8_94_GATE',negative_cases=len(negative),source='SOURCE_ONLY',actual=None,python=sys.version.split()[0]),sort_keys=True))\n"
class Controls(unittest.TestCase):
 def test_old_apps15_route_retains_whole_factory_and_parent13_guards(self):
  old=Path(os.environ.get('APPS15_SOURCE_FACTORY',HERE.parent/'apps15-native-source')).absolute()
  self.assertEqual(F.pins(F.tree(old)),F.profile()['old_factory'])
  spec=importlib.util.spec_from_file_location('unchanged_apps15_factory',old/'prepare.py');prior=importlib.util.module_from_spec(spec);spec.loader.exec_module(prior)
  parent13=Path(os.environ['APPS14_NATIVE_SOURCE']).absolute();recipe14=Path(os.environ['APPS15_RECIPE_SOURCE']).absolute()
  self.assertEqual(prior.pins(prior.render(parent13,recipe14)),F.profile()['parent'])
  self.assertEqual(prior.profile()['after'],F.profile()['parent'])
 def test_exact_cli_reproduces_whole115_and_both_aliases(self):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';p=subprocess.run([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--parent',str(P),'--recipe',str(Q),'--output',str(out)],capture_output=True,check=True,timeout=30)
   value=json.loads(p.stdout);self.assertIsNone(value['actual_run']);self.assertIsNone(value['actual_source']);self.assertIsNone(value['actual_ref']);self.assertFalse(value['acceptance']);self.assertEqual(value['expected_source'],'135b8fb21941d0ea27da7d34b1fc7b9eb0939ee8');self.assertEqual(value['recipe_source'],'a32501a76b79b65d175c8eefc2b4f741ec0388e5');self.assertEqual(F.pins(F.tree(out)),F.pins(F.tree(E,True)));self.assertEqual((out/'.github/workflows/native-arm-build.yml').read_bytes(),(out/'.github/workflows/native-arm-apps16-client.yml').read_bytes())
 def test_input_extra_drift_symlink_and_hardlink_refuse_before_output(self):
  for role,original,name in (('parent',P,'packages/tools/cachy-asahi-apps15/LICENSE'),('recipe',Q,'packages/tools/cachy-asahi-apps16/LICENSE')):
   for mode in ('extra','drift','symlink','hardlink'):
    with self.subTest(role=role,mode=mode),tempfile.TemporaryDirectory()as td:
     root=Path(td);source=root/'input';shutil.copytree(original,source,ignore=shutil.ignore_patterns('.git'));target=source/name;out=root/'absent'
     if mode=='extra':(source/'extra').write_bytes(b'foreign')
     elif mode=='drift':target.write_bytes(target.read_bytes()+b'\n')
     elif mode=='symlink':target.unlink();target.symlink_to(original/name)
     else:os.link(target,root/'alias')
     parent,recipe=(source,Q)if role=='parent'else(P,source)
     with self.assertRaises((ValueError,AssertionError)):F.emit(parent,recipe,out)
     self.assertFalse(out.exists())
 def test_payload_profile_and_reused_output_refuse(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory);path=factory/'payload/rules.py';path.write_bytes(path.read_bytes()+b'\n');out=root/'absent'
   p=subprocess.run([sys.executable,'-I','-B',str(factory/'prepare.py'),'--parent',str(P),'--recipe',str(Q),'--output',str(out)],capture_output=True,timeout=30);self.assertNotEqual(p.returncode,0);self.assertFalse(out.exists());path.write_bytes((HERE/'payload/rules.py').read_bytes());(factory/'profile.json').write_bytes(b'{}\n')
   p=subprocess.run([sys.executable,'-I','-B',str(factory/'prepare.py'),'--parent',str(P),'--recipe',str(Q),'--output',str(out)],capture_output=True,timeout=30);self.assertNotEqual(p.returncode,0);self.assertFalse(out.exists());out.mkdir()
   with self.assertRaises(ValueError):F.emit(P,Q,out)
 def test_parent_overlap_refuses_without_mutation(self):
  for source in (P,Q,HERE):
   with self.subTest(source=source),self.assertRaises(ValueError):F.emit(P,Q,source/'nested-output')
   self.assertFalse((source/'nested-output').exists())
 def test_noncanonical_source_and_output_refuse_before_input_writes(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);source=root/'parent';shutil.copytree(P,source,ignore=shutil.ignore_patterns('.git'));(root/'q').mkdir();before=F.pins(F.tree(source));out=root/'q'/'..'/'parent'/'generated'
   with self.assertRaisesRegex(ValueError,'normalized'):F.emit(source,Q,out)
   self.assertFalse((source/'generated').exists());self.assertEqual(F.pins(F.tree(source)),before)
   with self.assertRaisesRegex(ValueError,'normalized'):F.emit(root/'q'/'..'/'parent',Q,root/'outside')
   self.assertFalse((root/'outside').exists());self.assertEqual(F.pins(F.tree(source)),before)
 def test_emitted_preflight_and_all18_native_source_controls(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)/'source';F.emit(P,Q,root);lane=root/'scripts/ci/apps16-client-native'
   for n,args in [('preflight.py',['--source',str(root)]),('test_lane.py',[]),('test_retained.py',[])]:
    p=subprocess.run([sys.executable,'-B','-Werror',str(lane/n),*args],capture_output=True,timeout=60)
    self.assertEqual(p.returncode,0,p.stderr[-4096:].decode(errors='replace'))
    if n!='preflight.py':self.assertIn(('Ran '+('14'if n=='test_lane.py'else'4')+' tests').encode(),p.stderr);self.assertTrue(p.stderr.rstrip().endswith(b'OK'))
   gate=subprocess.run([sys.executable,'-I','-B','-c',ORDERED_GATE_PROBE,str(lane)],capture_output=True,timeout=30)
   self.assertEqual(gate.returncode,0,gate.stderr.decode(errors='replace'));self.assertEqual(json.loads(gate.stdout)['negative_cases'],15);print(gate.stdout.decode().strip())
if __name__=='__main__':unittest.main(verbosity=2)
