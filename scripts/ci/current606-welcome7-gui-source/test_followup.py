# SPDX-License-Identifier: MIT
"""Exact new option/source controls, whole old functions and before-output refusals."""
import argparse,ast,hashlib,importlib.util,json,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
CFG={'gui': True, 'flag': 'apps-cli-failure-data', 'stem': 'apps-cli-failure', 'source': '51e7797ef639de8fbed96e51b5b12bf5a92c7cb7', 'count': 556, 'held_functions': {'apps8_profile': {'bytes': 156, 'sha256': '01ba3296c569740840f46085b5805990a6b5f1f1bbdc6faaea6cb80123fd908b'}, 'buildkit_profile': {'bytes': 156, 'sha256': '0182334454d3fd01c1041421885d8fb8fa425f4611f4a2b2d7f2caaa501b4a08'}, 'correction_inputs': {'bytes': 1215, 'sha256': '915d297b024a3be6f12947bce51b2975a0bf140759495e34ddfd249db07a20a6'}, 'encoded': {'bytes': 90, 'sha256': 'aa1b17862d0d560152b5f639b753eb459fb17ec1cb2bec71d40dfc9c68030452'}, 'files': {'bytes': 478, 'sha256': '8ae1436227ec346e561b8a513e7a6ba7079c37a0a06c340e7125ae4a6fcb4e98'}, 'loader_profile': {'bytes': 146, 'sha256': 'cc46de295f8f1335f9a392e5090abd1cbdb65a2fa2c9469b0396d3d3d11fcf44'}, 'need': {'bytes': 50, 'sha256': 'a8ebc8f5f3a23b40b0c85a9adaa7e6f5bb29fcb122a2f824dc2f25deed384a8a'}, 'ordinary': {'bytes': 1037, 'sha256': '11603e23294c5416e9f96281094deaa4cb51adbd270ba80c6b178725b14734b5'}, 'pin': {'bytes': 79, 'sha256': 'f71b81de3a25bf17c4f69ffdebe13551b8d55744df3da3469a5b12a9b5ae1076'}, 'prepare': {'bytes': 2805, 'sha256': '692658e23db894163ad617417b1dd288c90f896e792ead457e9b3213e70d2ce6'}, 'prepare_apps8': {'bytes': 4145, 'sha256': 'dd77703ed47bb1227fc3e48aa9349969470da23d2e79f9f4bd57f4a3d9cea014'}, 'prepare_buildkit': {'bytes': 2716, 'sha256': '8a6b0721368847d95250ab4f4fb1f02174a98b85ad42d7c5196aed3843089fbc'}, 'prepare_installer_lock': {'bytes': 1170, 'sha256': '638374e783373051576e3de9384a7c2b6c74c13ac7c964880226c78024fd5db7'}, 'prepare_loader': {'bytes': 2318, 'sha256': 'c82cc8d4dc5e6cb19005fa9316b3f0604b3868635310cd42dd682fb40227cba8'}, 'prepare_transport': {'bytes': 1930, 'sha256': '930d03db1c1ace488387a77ed3d85f8dbb93b73155abbeb7e36b9bc076c60e35'}, 'prepare_welcome8': {'bytes': 2213, 'sha256': 'ad97ab861c65b05c3d53490cd171ffa1e62b75c32de8ece2c32f8c9f385b7174'}, 'profile': {'bytes': 131, 'sha256': '8d795c49bd7a407d973a463f7e8b970e4f021d38bd36cc9ce84dbbedc337ac93'}, 'relative': {'bytes': 223, 'sha256': 'e3de32788dd994b66c973aac81f6dd804da191193c586f43e621c60d11e1be97'}}}
p=argparse.ArgumentParser();p.add_argument('--parent',type=Path,required=True);p.add_argument('--expected',type=Path,required=True);args,rest=p.parse_known_args();PARENT,EXPECTED=args.parent.absolute(),args.expected.absolute();s=importlib.util.spec_from_file_location('_maintained_followup_factory',HERE/'prepare.py');F=importlib.util.module_from_spec(s);s.loader.exec_module(F)
def table(root):
 return {p.relative_to(root).as_posix():dict(bytes=len(b:=p.read_bytes()),sha256=hashlib.sha256(b).hexdigest())for p in root.rglob('*')if p.is_file()and'.git'not in p.relative_to(root).parts}
def emit(parent,out):return (F.prepare_cli_failure_data if CFG['gui']else F.emit_rawdb_key_correction)(parent,out)
def inputs():return (F.cli_failure_inputs if CFG['gui']else F.rawdb_inputs)()
def argv(parent,out):return [sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--'+CFG['flag'],'--predecessor-root'if CFG['gui']else'--parent',str(parent),'--output',str(out)]
class Controls(unittest.TestCase):
 def test_exact_isolated_CLI_whole_output_source_guard_and_actual_controls(self):
  _,_,wanted,_=inputs();self.assertEqual(table(EXPECTED),wanted)
  with tempfile.TemporaryDirectory()as td:
   out=Path(td)/'source';r=subprocess.run(argv(PARENT,out),capture_output=True,cwd='/tmp',timeout=30);self.assertEqual(r.returncode,0,r.stderr);v=json.loads(r.stdout);self.assertEqual(v['source'],CFG['source']);self.assertIsNone(v['actual']);self.assertEqual(table(out),wanted);self.assertEqual(len(wanted),CFG['count'])
   r=subprocess.run([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--help'],capture_output=True,timeout=10);self.assertEqual(r.returncode,0,r.stderr);self.assertIn(('--'+CFG['flag']).encode(),r.stdout)
   if CFG['gui']:
    s=importlib.util.spec_from_file_location('_whole_emitted_GUI_admission',out/'admission.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);self.assertEqual(m.prove(out)['files'],556);entry=out/'apps8_common.py';count=b'Ran 4 tests'
   else:entry=out/'developer/test_source.py';count=b'Ran 13 tests'
   r=subprocess.run([sys.executable,'-I','-B','-Werror',str(entry)],capture_output=True,timeout=60);self.assertEqual(r.returncode,0,r.stderr);self.assertIn(count,r.stderr)
   before=table(out);r=subprocess.run(argv(PARENT,out),capture_output=True,timeout=30);self.assertNotEqual(r.returncode,0);self.assertEqual(table(out),before)
 def test_all_prior_function_bodies_remain_byteexact(self):
  text=(HERE/'prepare.py').read_text();functions={n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  for n,w in CFG['held_functions'].items():
   with self.subTest(function=n):self.assertEqual(F.pin(functions[n].encode()),w)
 def test_new_payload_and_whole_parent_drift_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as td:
   t=Path(td);factory=t/'factory';shutil.copytree(HERE,factory);leaf=next(p for p in(factory/(CFG['stem']+'-payload')).rglob('*')if p.is_file());leaf.write_bytes(leaf.read_bytes()+b'\n')
   with patch.object(F,'HERE',factory),self.assertRaises(ValueError):emit(PARENT,t/'never-support')
   self.assertFalse((t/'never-support').exists());bad=t/'parent';shutil.copytree(PARENT,bad,ignore=shutil.ignore_patterns('.git'));leaf=next(p for p in bad.rglob('*')if p.is_file());leaf.write_bytes(leaf.read_bytes()+b'\n')
   with self.assertRaises(ValueError):emit(bad,t/'never-parent')
   self.assertFalse((t/'never-parent').exists());alias=t/'alias';alias.symlink_to(PARENT,target_is_directory=True)
   with self.assertRaises(ValueError):emit(alias,t/'never-alias')
   self.assertFalse((t/'never-alias').exists())
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
