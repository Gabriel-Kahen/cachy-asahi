# SPDX-License-Identifier: MIT
"""Fresh portable DATA controls. No native/package/namespace/process actors."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
parser=argparse.ArgumentParser();parser.add_argument('--checkout',type=Path,required=True);parser.add_argument('--basis',type=Path,required=True)
ARGS=parser.parse_args();ACTORS=[]
def fence(event,args):
 if event.startswith(('subprocess.','socket.'))or event in('os.system','os.exec','os.fork','os.forkpty','os.posix_spawn'):
  ACTORS.append(event);raise AssertionError('DATA-only actor denial: '+event)
sys.addaudithook(fence)
spec=importlib.util.spec_from_file_location('measurement_v2_data_constructor',HERE/'prepare.py');F=importlib.util.module_from_spec(spec);spec.loader.exec_module(F)
class Controls(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.root.chmod(0o700)
 def render(self):return F.render(ARGS.checkout,ARGS.basis)
 def test_current_closed_recipe_module_license_dependencies(self):
  factory,old,source,identity,closure=self.render();self.assertEqual((len(old),len(source)),(199,200));self.assertEqual(len(closure['recipe_files']),18);self.assertEqual(len(closure['payload_files']),14);self.assertEqual(len(closure['buildinfo_installed']),349);self.assertEqual(closure['license'],'MIT');self.assertEqual(len(closure['original_modules_and_license']),6);self.assertEqual(closure['runtime_dependencies'],['python>=3.12']);self.assertEqual(closure['check_dependencies'],['bubblewrap']);self.assertEqual(closure['native_dependencies']['python'],'3.14.8-1')
 def test_full_source_inverse_and_only_finite_runtime_seams(self):
  factory,old,source,identity,closure=self.render();self.assertEqual(set(source)-set(old),F.ADDED)
  self.assertEqual({n for n in old if old[n]!=source[n]},F.REPLACED|{'native/source-map.json'})
  restored={n:r for n,r in source.items()if n not in F.ADDED}
  for n in F.REPLACED|{'native/source-map.json'}:restored[n]=old[n]
  self.assertEqual(factory.rows(restored),factory.rows(old));self.assertEqual(factory.git_tree(restored),'9e30738959eae51df51a0b616b21f49a68aa97a4')
 def test_unissued_draft_has_no_authority(self):
  value=F.draft();self.assertIsNone(value['Root_trust']);self.assertIsNone(value['signing']);self.assertIsNone(value['resources']);self.assertTrue(all(v is None for v in value['actual'].values()));self.assertIsNone(value['approved']);self.assertIsNone(value['accepted'])
 def test_supplied_trust_signing_resources_nonce_or_acceptance_refused(self):
  base=F.draft();path=HERE/'Root-admission.DRAFT.json';original=F.ordinary
  for field in('Root_trust','signing','resources','approved','accepted','actual'):
   changed=copy.deepcopy(base)
   if field=='actual':changed[field]['nonce']='not-an-issued-nonce'
   else:changed[field]=True
   def body(p,cap):return(F.encoded(changed),0o644)if Path(p)==path else original(p,cap)
   with patch.object(F,'ordinary',side_effect=body),self.assertRaises(ValueError):F.draft()
 def test_profile_whole_hash_refuses_before_basis_or_output(self):
  output=self.root/'not-created'
  with patch.object(F,'render',side_effect=AssertionError('must not read basis')):
   with self.assertRaisesRegex(ValueError,'external whole profile'):F.construct(ARGS.checkout,ARGS.basis,output,'0'*64)
  self.assertFalse(output.exists())
 def test_actual_fresh_atomic_emission_and_readback(self):
  output=self.root/'packet';pin=F.pin((HERE/'profile.json').read_bytes())['sha256'];result=F.construct(ARGS.checkout,ARGS.basis,output,pin)
  stage=json.loads((output/'stage.DRAFT.json').read_bytes());self.assertEqual(stage['status'],'SOURCE_DRAFT_ONLY_NO_ACTORS');self.assertEqual(stage['actual'],F.ACTUAL)
  factory=F.load_factory(ARGS.checkout);files=factory.tree(output/'source');self.assertEqual(len(files),200);self.assertEqual(factory.git_tree(files),result['source']['tree'])
  inverse=json.loads((output/'inverse-v1.DATA.json').read_bytes());restored=dict(files)
  for n,row in inverse['changes'].items():
   if row['before']is None:del restored[n]
   else:restored[n]=factory.read(output/'before-v1'/n)
  self.assertEqual(factory.git_tree(restored),inverse['parent_tree']);self.assertEqual(len(restored),199)
  original=(output/'stage.DRAFT.json').read_bytes()
  with self.assertRaises(ValueError):F.construct(ARGS.checkout,ARGS.basis,output,pin)
  self.assertEqual((output/'stage.DRAFT.json').read_bytes(),original)
 def test_changed_or_missing_genuine_basis_refuses(self):
  basis=self.root/'basis';shutil.copytree(ARGS.basis,basis);target=next(p for p in basis.rglob('*')if p.is_file());target.write_bytes(target.read_bytes()+b'drift')
  with self.assertRaises(ValueError):F.render(ARGS.checkout,basis)
  target.unlink()
  with self.assertRaises(ValueError):F.render(ARGS.checkout,basis)
 def test_modified_inputs_manifest_refused_before_factory_import(self):
  original=F.ordinary;manifest=HERE/'inputs.json'
  def body(p,cap):return(b'{}\n',0o644)if Path(p)==manifest else original(p,cap)
  with patch.object(F,'ordinary',side_effect=body),self.assertRaisesRegex(ValueError,'whole maintained input'):F.load_factory(ARGS.checkout)
 def test_payload_drift_and_extra_member_refuse(self):
  factory=F.load_factory(ARGS.checkout);original=factory.tree
  def tree(path,*args,**kwargs):
   result=original(path,*args,**kwargs)
   if Path(path)==HERE/'payload':result['native/foreign.py']=(b'pass\n',0o644)
   return result
  with patch.object(F,'load_factory',return_value=factory),patch.object(factory,'tree',side_effect=tree),self.assertRaises(ValueError):self.render()
 def test_ordinary_alias_hardlink_and_fifo_refusals(self):
  path=self.root/'file';path.write_bytes(b'ordinary');self.assertEqual(F.ordinary(path,8)[0],b'ordinary')
  alias=self.root/'alias';alias.symlink_to(path)
  with self.assertRaises(ValueError):F.ordinary(alias,8)
  alias.unlink();os.link(path,alias)
  with self.assertRaises(ValueError):F.ordinary(path,8)
  alias.unlink();os.mkfifo(alias)
  with self.assertRaises(ValueError):F.ordinary(alias,8)
 def test_no_atime_false_positive_but_metadata_drift_refuses(self):
  path=self.root/'file';path.write_bytes(b'DATA');before=path.stat();self.assertEqual(F.ordinary(path,4)[0],b'DATA')
  original=F.os.fstat
  def drift(fd):
   value=original(fd)
   if not hasattr(drift,'seen'):drift.seen=True;return value
   from types import SimpleNamespace
   return SimpleNamespace(**{k:getattr(value,k)+(1 if k=='st_mtime_ns' else 0)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')})
  with patch.object(F.os,'fstat',side_effect=drift),self.assertRaises(ValueError):F.ordinary(path,4)
 def test_draft_profile_and_closure_drift_refuse(self):
  original=F.ordinary
  for name,raw in(('profile.json',b'{}\n'),('closure.DATA.json',b'{}\n')):
   def body(path,cap):return(raw,0o644)if Path(path)==HERE/name else original(path,cap)
   with patch.object(F,'ordinary',side_effect=body),self.assertRaises(ValueError):self.render()
 def test_current_recipe_namespace_and_provenance_drift_refuse(self):
  factory=F.load_factory(ARGS.checkout);profile,before,source=factory.render(ARGS.basis);original=factory.tree
  def changed(path,*args,**kwargs):
   value=original(path,*args,**kwargs)
   if Path(path)==ARGS.checkout/F.RECIPE:value['benchmark.py']=(b'changed module',0o644)
   return value
  with patch.object(factory,'tree',side_effect=changed),self.assertRaises(ValueError):F.closure(factory,ARGS.checkout,source)
 def test_complete_existing_factory_targets_and_apis_are_preserved(self):
  factory,old,source,identity,closure=self.render();overlay={n:source[n]for n in F.REPLACED|F.ADDED};F.finite_probe_delta(old,overlay)
  for name,before,after in(('native/measurement_tools_v1.py','def compare_archives(', 'def omitted_compare_archives('),('native/measurement_reader_v1.py','def validate(', 'def omitted_validate('),('native/measurement_tools_v1.py','def business(run, cli, root, uid, gid, label):','def business(run, cli, root, uid, gid, label, narrowed=True):')):
   mutant=dict(overlay);body,mode=mutant[name];self.assertIn(before,body.decode());mutant[name]=(body.decode().replace(before,after,1).encode(),mode)
   with self.assertRaises(ValueError):F.finite_probe_delta(old,mutant)
 def test_no_actor_attempts(self):self.assertEqual(ACTORS,[])
if __name__=='__main__':unittest.main(argv=[sys.argv[0]],verbosity=2)
