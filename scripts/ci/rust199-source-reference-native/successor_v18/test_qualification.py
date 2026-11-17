# SPDX-License-Identifier: MIT
"""Maintained qualifier joins real DATA files with explicit existing-kernel MODEL seams."""
import copy,hashlib,importlib.util,json,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
sys.dont_write_bytecode=True

def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
C=module('v18_qualification_dependency_MODEL',HERE/'test_dependencies.py');D=C.D
LIFE=dict(natural_exit=True,forced_cleanup=False,group_absent=True,retirement='REAPED',ownership_lost=False,leader_held_until_group_inspection=True,exit_observed_via_waitpid=True,exit=0)
class Qualification(unittest.TestCase):
 def exercise(self,base,mutation=None,relocated=False):
  p=C.policy();source,image=C.image(base,p);(source/'hosted').mkdir();program=source/'hosted/qualification.py';program.write_bytes((HERE/'payload/hosted/qualification.py').read_bytes());Q=module('v18_join_'+base.name,program)
  observed=D.observe(image,source,p);receipt=dict(observed,native_uid_gid_checked=True,runtime_loads=D.expected_loads(p))
  provider=dict(source=dict(sha='1'*40,ref='refs/heads/codex/MODEL',run='1',job='2',map_sha256='2'*64,approval='3'*64),dispatch_sha256='4'*64)
  boot=dict(image='sha256:'+'5'*64,rootfs_tree_sha256='6'*64,build_dependencies=dict(observation=observed));folder=base/'receipts';folder.mkdir();files={}
  for phase in('data','probe'):
   path=folder/('build-dependencies-'+phase+'.json');path.write_bytes(D.encode(receipt));files['qualification_'+path.name]=dict(local_path=str(path),**D.pin(path.read_bytes()))
  value=dict(schema=4,status='PASS_NATIVE_SOURCE_QUALIFICATION_ONLY',binding=provider['source'],dispatch_sha256=provider['dispatch_sha256'],provider_phase_sha256=hashlib.sha256(Q.encode(provider)).hexdigest(),image_id=boot['image'],rootfs_tree_sha256=boot['rootfs_tree_sha256'],native_acceptance=False,holds_preserved=True,build_dependencies=receipt,files=files,owned_work_bind={},readonly_stage0=dict(paths=['/stage0','/work/build/stage0'],readonly=True,namespace_permissions_verified=True,write_attempts_denied=True,alias_write_attempts_denied=True,attempts=[dict(errno=30),dict(errno=30)]),probe_receipts=[dict(argv=argv,returncode=0,lifecycle=LIFE,kernel_mount_proof_sha256='7'*64)for argv in Q.PROBES],stage0_tree_sha256='8'*64,qualified_llvm_tree_sha256='9'*64,library_cargo_config_sha256='a'*64,source_tree_sha256='b'*64)
  if mutation=='missing-data':(folder/'build-dependencies-data.json').unlink()
  elif mutation=='host-inventory':boot['build_dependencies']['observation']['inventory']=dict(bytes=1,sha256='f'*64)
  elif mutation=='top-provider':value=copy.deepcopy(value);value['build_dependencies']['providers']['usr/lib/libgit2.so.0']['sha256']='f'*64
  elif mutation=='native-flag':
   bad=dict(receipt,native_uid_gid_checked=False);(folder/'build-dependencies-data.json').write_bytes(D.encode(bad))
  elif mutation=='relocated-pin':(folder/'build-dependencies-probe.json').write_bytes(D.encode(receipt)+b' ')
  elif mutation=='old-no-dependency':del value['build_dependencies']
  kernel_calls=[]
  producer=SimpleNamespace(V=SimpleNamespace(binding=lambda *a:dict(token='c'*24)),labels=lambda *a:{},replay_work_bind=lambda *a:None)
  def load(name,path):
   if Path(path).name=='build_dependencies.py':return D
   if Path(path).name=='producer.py':return producer
   raise AssertionError('unexpected qualifier MODEL load '+str(path))
  def kernel(*args):kernel_calls.append(True);return {'qualification-probe':'7'*64}
  with patch.object(Q,'load',side_effect=load),patch.object(Q,'kernel_proofs',side_effect=kernel),patch.object(D,'policy',return_value=p):
   Q.validate_result(value,provider,boot,None if relocated else folder)
  self.assertEqual(kernel_calls,[True]);return value,boot
 def test_both_native_phase_receipts_join_host_image_and_existing_nine_probes(self):
  for relocated in(False,True):
   with self.subTest(relocated=relocated),tempfile.TemporaryDirectory()as td:self.exercise(Path(td),relocated=relocated)
 def test_missing_changed_wrong_scope_or_unbound_dependency_refuses(self):
  for mutation in('missing-data','host-inventory','top-provider','native-flag','old-no-dependency'):
   with self.subTest(mutation=mutation),tempfile.TemporaryDirectory()as td,self.assertRaises((ValueError,KeyError,FileNotFoundError)):self.exercise(Path(td),mutation)
 def test_relocated_observation_must_match_whole_transferred_bytes_pin(self):
  with tempfile.TemporaryDirectory()as td,self.assertRaisesRegex(ValueError,'whole retained'):self.exercise(Path(td),'relocated-pin',True)
if __name__=='__main__':unittest.main(verbosity=2)
