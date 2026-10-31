# SPDX-License-Identifier: MIT
"""Finite correction CLI, whole source, historical function and drift controls."""
import argparse,ast,hashlib,importlib.util,json,os,shutil,subprocess,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
p=argparse.ArgumentParser();p.add_argument('--parent',type=Path,required=True);p.add_argument('--expected',type=Path,required=True);p.add_argument('--carrier',type=Path);args,rest=p.parse_known_args();P,E=args.parent.absolute(),args.expected.absolute();I=args.carrier.absolute()if args.carrier else None

def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
F=load('_finite_runtime_correction_factory',HERE/'prepare.py')
HELD={'need': 'a8ebc8f5f3a23b40b0c85a9adaa7e6f5bb29fcb122a2f824dc2f25deed384a8a', 'pin': 'f71b81de3a25bf17c4f69ffdebe13551b8d55744df3da3469a5b12a9b5ae1076', 'encoded': 'aa1b17862d0d560152b5f639b753eb459fb17ec1cb2bec71d40dfc9c68030452', 'relative': 'e3de32788dd994b66c973aac81f6dd804da191193c586f43e621c60d11e1be97', 'ordinary': '11603e23294c5416e9f96281094deaa4cb51adbd270ba80c6b178725b14734b5', 'files': '8ae1436227ec346e561b8a513e7a6ba7079c37a0a06c340e7125ae4a6fcb4e98', 'profile': '8d795c49bd7a407d973a463f7e8b970e4f021d38bd36cc9ce84dbbedc337ac93', 'prepare': '692658e23db894163ad617417b1dd288c90f896e792ead457e9b3213e70d2ce6', 'prepare_welcome8': 'ad97ab861c65b05c3d53490cd171ffa1e62b75c32de8ece2c32f8c9f385b7174', 'prepare_transport': '930d03db1c1ace488387a77ed3d85f8dbb93b73155abbeb7e36b9bc076c60e35', 'buildkit_profile': '0182334454d3fd01c1041421885d8fb8fa425f4611f4a2b2d7f2caaa501b4a08', 'prepare_buildkit': '8a6b0721368847d95250ab4f4fb1f02174a98b85ad42d7c5196aed3843089fbc', 'loader_profile': 'cc46de295f8f1335f9a392e5090abd1cbdb65a2fa2c9469b0396d3d3d11fcf44', 'prepare_loader': 'c82cc8d4dc5e6cb19005fa9316b3f0604b3868635310cd42dd682fb40227cba8', 'apps8_profile': '01ba3296c569740840f46085b5805990a6b5f1f1bbdc6faaea6cb80123fd908b', 'prepare_apps8': 'dd77703ed47bb1227fc3e48aa9349969470da23d2e79f9f4bd57f4a3d9cea014'}
FLAG='installer-lock-correction'
def table(root,wanted):return {n:F.pin(raw)for n,raw in F.files(root).items()}
def argv(out):return [sys.executable,'-I','-B','-Werror',str(HERE/'prepare.py'),'--'+FLAG,*['--predecessor-root',str(P)],'--output',str(out)]
class Controls(unittest.TestCase):
 def test_actual_isolated_CLI_exact_full_source_and_complete_emitted_controls(self):
  variant,before,after,payload=F.correction_inputs();self.assertEqual(table(E,after),after)
  with tempfile.TemporaryDirectory()as t:
   out=Path(t)/'source';r=subprocess.run(argv(out),capture_output=True,cwd='/tmp',timeout=30);self.assertEqual(r.returncode,0,r.stderr);v=json.loads(r.stdout);self.assertEqual(v['source'],variant['after_source']);self.assertIsNone(v['actual']);self.assertEqual(table(out,after),table(E,after))
   proof=load('_exact_new_installer_admission',out/'admission.py').prove(out);self.assertEqual(proof['files'],556);self.assertEqual(proof['native_GUI'],'NOT_RUN')
 def test_all_old_function_bodies_and_support_authorities_held(self):
  text=(HERE/'prepare.py').read_text();functions={n.name:ast.get_source_segment(text,n)for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
  for name,w in HELD.items():self.assertEqual(hashlib.sha256(functions[name].encode()).hexdigest(),w,name)
 def test_profile_map_and_every_readable_replacement_drift_refuse_before_output(self):
  p,_,_,_=F.correction_inputs()
  for name in ['correction-profile.json','correction-maps.json',*['correction-payload/'+n for n in p['payload']]]:
   with self.subTest(name=name),tempfile.TemporaryDirectory()as t:
    t=Path(t);factory=t/'factory';shutil.copytree(HERE,factory);q=factory/name;q.write_bytes(q.read_bytes()+b' ');out=t/'never';command=argv(out);command[command.index(str(HERE/'prepare.py'))]=str(factory/'prepare.py');r=subprocess.run(command,capture_output=True,timeout=30);self.assertNotEqual(r.returncode,0);self.assertFalse(out.exists())
 def test_parent_alias_and_drift_refuse_before_output(self):
  with tempfile.TemporaryDirectory()as t:
   t=Path(t);root=t/'parent';shutil.copytree(P,root,ignore=shutil.ignore_patterns('.git'));alias=t/'alias';alias.symlink_to(root,target_is_directory=True)
   command=argv(t/'never');command[command.index(str(P))]=str(alias);r=subprocess.run(command,capture_output=True,timeout=30);self.assertNotEqual(r.returncode,0);self.assertFalse((t/'never').exists())
   leaf=next(q for q in sorted(root.rglob('*'))if q.is_file());leaf.write_bytes(leaf.read_bytes()+b' ');command=argv(t/'never');command[command.index(str(P))]=str(root);r=subprocess.run(command,capture_output=True,timeout=30);self.assertNotEqual(r.returncode,0);self.assertFalse((t/'never').exists())
 def test_actual_installer_full606_hash_gate_and_samecount_wrong_lock(self):
  class Boundary(Exception):pass
  def exercise(installer,lock):
   saved=dict(sys.modules)
   try:
    with tempfile.TemporaryDirectory()as t:
     code=Path(t);(code/'bundle').mkdir();(code/'bundle/manifest.json').write_text('{}');(code/'bundle/expected-installed.lock').write_bytes(lock);shutil.copyfile(E/'factory/support/contract604.py',code/'contract604.py');n=load('_real_emitted_installer_gate',installer);actual=n.load;calls=[]
     def scope(digest,role):self.assertEqual((digest,role),('1'*64,'runtime606'));calls.append('scope')
     def inventory():calls.append('inventory');raise Boundary()
     def dispatch(name,path):
      if name=='_606_owned_build_scope':return types.SimpleNamespace(check=scope)
      if name=='_606_native_install_methods':return types.SimpleNamespace(inventory=inventory)
      if name=='_606_actual_db':return types.SimpleNamespace()
      self.assertEqual(name,'contract');return actual(name,path)
     def path(value):self.assertEqual(value,'/tmp/managed604');return code
     with patch.object(n,'Path',side_effect=path),patch.object(n,'load',side_effect=dispatch):
      try:n.install('1'*64)
      except Boundary:return calls
     raise AssertionError('must stop before any native inventory or transaction')
   finally:
    for name in set(sys.modules)-set(saved):sys.modules.pop(name,None)
    sys.modules.update(saved)
  lock=(E/'factory/expected606.lock').read_bytes();self.assertEqual(len(dict(line.split()for line in lock.decode().splitlines())),606)
  self.assertEqual(exercise(E/'factory/install606.py',lock),['scope','inventory'])
  with self.assertRaisesRegex(ValueError,'exact606 lock required'):exercise(P/'factory/install606.py',lock)
  wrong=lock.replace(b'cachy-asahi-apps 0.1.0-8\n',b'cachy-asahi-apps 0.1.0-7\n',1);self.assertEqual(len(wrong.splitlines()),606)
  with self.assertRaisesRegex(ValueError,'exact606 lock required'):exercise(E/'factory/install606.py',wrong)
if __name__=='__main__':unittest.main(argv=[sys.argv[0],*rest],verbosity=2)
