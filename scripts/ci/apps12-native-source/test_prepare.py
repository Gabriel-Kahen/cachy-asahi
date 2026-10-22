# SPDX-License-Identifier: MIT
"""Exercise exact emission and real native-source refusal/retirement boundaries."""
import importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('apps12_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
P,Q,E=[Path(os.environ[n]).absolute()for n in ('APPS11_NATIVE_SOURCE','APPS12_RECIPE_SOURCE','APPS12_NATIVE_SOURCE')]
class Controls(unittest.TestCase):
 def test_exact_cli_reproduces_whole115_and_both_aliases(self):
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';p=subprocess.run([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--parent',str(P),'--recipe',str(Q),'--output',str(out)],capture_output=True,check=True,timeout=30)
   value=json.loads(p.stdout);self.assertIsNone(value['actual_run']);self.assertIsNone(value['actual_source']);self.assertEqual(F.pins(F.tree(out)),F.pins(F.tree(E,True)));self.assertEqual((out/'.github/workflows/native-arm-build.yml').read_bytes(),(out/'.github/workflows/native-arm-apps12-client.yml').read_bytes())
 def test_input_extra_drift_symlink_and_hardlink_refuse_before_output(self):
  for mode in ('extra','drift','symlink','hardlink'):
   with self.subTest(mode=mode),tempfile.TemporaryDirectory()as td:
    root=Path(td);source=root/'parent';shutil.copytree(P,source,ignore=shutil.ignore_patterns('.git'));name='packages/tools/cachy-asahi-apps11/LICENSE';target=source/name;out=root/'absent'
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
 def test_emitted_preflight_and_all18_native_source_controls(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)/'source';F.emit(P,Q,root);lane=root/'scripts/ci/apps12-client-native'
   for n,args in [('preflight.py',['--source',str(root)]),('test_lane.py',[]),('test_retained.py',[])]:
    p=subprocess.run([sys.executable,'-B','-Werror',str(lane/n),*args],capture_output=True,timeout=60)
    self.assertEqual(p.returncode,0,p.stderr[-4096:].decode(errors='replace'))
if __name__=='__main__':unittest.main(verbosity=2)
