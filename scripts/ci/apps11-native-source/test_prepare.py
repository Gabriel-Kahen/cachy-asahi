# SPDX-License-Identifier: MIT
"""Exercise exact emission and real native-source refusal/retirement boundaries."""
import importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('apps11_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
P,Q,E=[Path(os.environ[n]).absolute()for n in ('APPS10_NATIVE_SOURCE','APPS11_RECIPE_SOURCE','APPS11_NATIVE_SOURCE')]
class Controls(unittest.TestCase):
 def test_exact_cli_reproduces_whole115_and_both_aliases(self):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';p=subprocess.run([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--parent',str(P),'--recipe',str(Q),'--output',str(out)],capture_output=True,check=True,timeout=30)
   value=json.loads(p.stdout);self.assertIsNone(value['actual_run']);self.assertIsNone(value['actual_source']);self.assertEqual(F.pins(F.tree(out)),F.pins(F.tree(E,True)));self.assertEqual((out/'.github/workflows/native-arm-build.yml').read_bytes(),(out/'.github/workflows/native-arm-apps11-client.yml').read_bytes())
 def test_input_extra_drift_symlink_and_hardlink_refuse_before_output(self):
  for mode in ('extra','drift','symlink','hardlink'):
   with self.subTest(mode=mode),tempfile.TemporaryDirectory()as td:
    root=Path(td);source=root/'parent';shutil.copytree(P,source,ignore=shutil.ignore_patterns('.git'));name='packages/tools/cachy-asahi-apps10/LICENSE';target=source/name;out=root/'absent'
    if mode=='extra':(source/'extra').write_bytes(b'foreign')
    elif mode=='drift':target.write_bytes(target.read_bytes()+b'\n')
    elif mode=='symlink':target.unlink();target.symlink_to(P/name)
    else:os.link(target,root/'alias')
    with self.assertRaises((ValueError,AssertionError)):F.emit(source,Q,out)
    self.assertFalse(out.exists())
 def test_payload_profile_and_reused_output_refuse(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);factory=root/'factory';shutil.copytree(HERE,factory);path=factory/'payload/rules.py';path.write_bytes(path.read_bytes()+b'\n');out=root/'absent'
   p=subprocess.run([sys.executable,'-I','-B',str(factory/'prepare.py'),'--parent',str(P),'--recipe',str(Q),'--output',str(out)],capture_output=True,timeout=30);self.assertNotEqual(p.returncode,0);self.assertFalse(out.exists());path.write_bytes((HERE/'payload/rules.py').read_bytes());(factory/'profile.json').write_bytes(b'{}\n')
   p=subprocess.run([sys.executable,'-I','-B',str(factory/'prepare.py'),'--parent',str(P),'--recipe',str(Q),'--output',str(out)],capture_output=True,timeout=30);self.assertNotEqual(p.returncode,0);self.assertFalse(out.exists());out.mkdir()
   with self.assertRaises(ValueError):F.emit(P,Q,out)
 def test_parent_overlap_refuses_without_mutation(self):
  with self.assertRaises(ValueError):F.emit(P,Q,P/'nested-output')
  self.assertFalse((P/'nested-output').exists())
 def test_dotdot_paths_refuse_before_writes_and_preserve_all_inputs(self):
  # Run the actual previous emitter against an owned clone to reproduce the
  # nested-parent mutation. No original fixture or maintained source is written.
  import ast
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);(root/'hop').mkdir();baseline=root/'baseline';shutil.copytree(P,baseline,ignore=shutil.ignore_patterns('.git'))
   old=ast.get_source_segment((HERE/'prepare.py').read_text(),next(n for n in ast.parse((HERE/'prepare.py').read_text()).body if isinstance(n,ast.FunctionDef)and n.name=='emit'));guard="need(all(p==p.resolve()for p in(parent,recipe,output)),'canonical normalized input/output paths required');";self.assertEqual(old.count(guard),1);old=old.replace(guard,'',1);space=dict(vars(F));exec(compile(old,'original_emit_before_normalization','exec'),space)
   prior=F.pins(F.tree(baseline));bad=root/'hop'/'..'/'baseline'/'nested-output';value=space['emit'](baseline,Q,bad);self.assertEqual(value['files'],115);self.assertEqual(F.pins(F.tree(bad)),F.profile()['after']);self.assertEqual(len(prior),115);self.assertEqual(len(F.tree(baseline)),230)
   parent=root/'parent';recipe=root/'recipe';factory=root/'factory';shutil.copytree(P,parent,ignore=shutil.ignore_patterns('.git'));shutil.copytree(Q,recipe,ignore=shutil.ignore_patterns('.git'));shutil.copytree(HERE,factory);before=[F.pins(F.tree(x))for x in(parent,recipe,factory)]
   cases=[(parent,recipe,root/'hop'/'..'/'parent'/'never-written'),(parent,recipe,root/'hop'/'..'/'recipe'/'never-written'),(parent,recipe,root/'hop'/'..'/'factory'/'never-written'),(root/'hop'/'..'/'parent',recipe,root/'parent-input-out'),(parent,root/'hop'/'..'/'recipe',root/'recipe-input-out')]
   for a,b,out in cases:
    with self.subTest(parent=a,recipe=b,output=out),self.assertRaisesRegex(ValueError,'canonical normalized'):F.emit(a,b,out)
    self.assertFalse(out.exists());self.assertEqual([F.pins(F.tree(x))for x in(parent,recipe,factory)],before)
 def test_emitted_preflight_and_all18_native_source_controls(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)/'source';F.emit(P,Q,root);lane=root/'scripts/ci/apps11-client-native'
   for n,args in [('preflight.py',['--source',str(root)]),('test_lane.py',[]),('test_retained.py',[])]:
    p=subprocess.run([sys.executable,'-B','-Werror',str(lane/n),*args],capture_output=True,timeout=60)
    self.assertEqual(p.returncode,0,p.stderr[-4096:].decode(errors='replace'))
if __name__=='__main__':unittest.main(verbosity=2)
