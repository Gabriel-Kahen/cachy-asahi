# SPDX-License-Identifier: MIT
"""Public source/data controls; no Git/sign/ALPM/native/VM actor runs."""
import copy,importlib.util,json,os,shutil,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('new_public_gui_assets',HERE/'assets.py');A=importlib.util.module_from_spec(s);s.loader.exec_module(A)
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.root=Path(os.environ['PUBLIC_GUI_SOURCE']).absolute();cls.packet=Path(os.environ['PUBLIC_GUI_PACKET']).absolute()
  with patch.object(subprocess,'Popen',side_effect=AssertionError('no actors')):cls.facts=A.inspect(cls.root,cls.packet)
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.work=Path(self.tmp.name);p=patch.object(subprocess,'Popen',side_effect=AssertionError('no actors'));p.start();self.addCleanup(p.stop)
 def test_actual_public_originals_licenses_and_exact_root_pair_authority(self):
  v=self.facts;self.assertEqual(v['public_file_count'],98);self.assertEqual(v['index'],A.INDEX);self.assertEqual(set(v['products']),set(A.VERSIONS));self.assertEqual(sum(r['bytes'] for r in v['archives'].values()),64876)
  self.assertEqual(v['GUI_authority'],'NOT_PROVIDED_BY_PUBLIC_NATIVE_PACKET');self.assertEqual(v['historical_GUI_assets'],'NOT_READ_OR_REUSED')
  for name in A.VERSIONS:self.assertEqual(set(v['licenses'][name]),{'LICENSE','NOTICE'});self.assertEqual(v['licenses'][name]['LICENSE']['sha256'],'51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7')
 def test_default_policy_refuses_before_any_output_or_process(self):
  out=self.work/'output';private=self.work/'signing'
  with self.assertRaisesRegex(ValueError,'UNBOUND'):A.prepare(self.root,self.packet,self.work/'authority',HERE/'policy.json',out,private)
  self.assertFalse(out.exists());self.assertFalse(private.exists())
 def test_public_input_archive_change_symlink_and_hardlink_refused(self):
  root=self.work/'payload';shutil.copytree(self.packet,root);target=root/self.facts['origins']['cachy-asahi-doctor']['path'];original=target.read_bytes();target.write_bytes(original+b'changed')
  with self.assertRaises(ValueError):A.inspect(self.root,root)
  target.write_bytes(original);target.unlink();target.symlink_to(self.packet/self.facts['origins']['cachy-asahi-doctor']['path'])
  with self.assertRaises(ValueError):A.inspect(self.root,root)
  target.unlink();target.write_bytes(original);os.link(target,self.work/'alias')
  with self.assertRaises(ValueError):A.inspect(self.root,root)
 def test_source_recipe_license_drift_and_reference_paths_refused(self):
  root=self.work/'source';root.mkdir()
  for n in A.obj(A.read(HERE/'source-pins.json'))['files']:
   p=root/n;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(self.root/n,p)
  (root/'packages/tools/cachy-asahi-doctor/NOTICE').write_bytes(b'different')
  with self.assertRaises(ValueError):A.inspect(root,self.packet)
  for name in ('../x','/x','a//b','a/./b','a\\b'):
   with self.assertRaises(ValueError):A.relative(name)
 def test_new_asset_purpose_and_closed_shape_only_never_crypto_credit(self):
  root=self.work/'new';directory=root/'assets';directory.mkdir(parents=True)
  for name,p in self.facts['products'].items():
   shutil.copyfile(self.packet/self.facts['origins'][name]['path'],directory/p['archive']);(directory/(p['archive']+'.sig')).write_bytes(b'INERT_NOT_A_SIGNATURE')
  (directory/'TEST-public.asc').write_bytes(b'INERT_NOT_A_KEY');(directory/'control.json').write_bytes(A.encoded(dict(signer='A'*40)));(directory/'products.json').write_bytes(A.encoded(self.facts['products']))
  index=dict(schema_version=1,purpose=A.PURPOSE,files={p.name:A.row(p) for p in directory.iterdir()});(root/'index.json').write_bytes(A.encoded(index))
  def binding():return dict(asset_root='assets',assets_index=dict(path='index.json',**A.row(root/'index.json')))
  self.assertEqual(A.asset_directory(root,binding(),self.root),directory)
  index['purpose']='ACTUAL_CURRENT_WELCOME4_GUI_PUBLIC_INPUTS';(root/'index.json').write_bytes(A.encoded(index))
  with self.assertRaises(ValueError):A.asset_directory(root,binding(),self.root)
  index['purpose']=A.PURPOSE;(root/'index.json').write_bytes(A.encoded(index));(directory/'foreign').write_bytes(b'x')
  with self.assertRaises(ValueError):A.asset_directory(root,binding(),self.root)
 def test_real_disjoint_destinations_refuse_input_and_source_mutation(self):
  root=self.work/'source';packet=self.work/'packet';authority=self.work/'authority'
  for p in (root,packet,authority):p.mkdir()
  out=self.work/'new';signing=self.work/'private';self.assertEqual(A.destinations(root,packet,authority,out,signing),(out,signing))
  for bad,work in ((root/'new',signing),(packet/'new',signing),(out,out/'child'),(out,authority/'private')):
   with self.assertRaises(ValueError):A.destinations(root,packet,authority,bad,work)
  self.assertFalse(out.exists());self.assertFalse(signing.exists())
 def test_real_public_sanitized_authority_counts_lifetime_scope_refusals(self):
  # This explicit public3344B document is a data input; no carrier Git proof is mocked.
  path=Path(os.environ['PUBLIC_GUI_AUTHORITY']);self.assertEqual(A.row(path),dict(bytes=3344,sha256='ab18a8281ee7eb1d2f81c13fc83e762aeb812e28f33552904cb717d6b68e45cb'));doc=A.obj(A.read(path));A.gui_component(doc,self.facts['archives'])
  for key,value in [('frames',12),('management_operations_per_profile',16),('doctor_lifetime','UNKNOWN'),('installed16k','ACCEPTED'),('asset_binding','OLD_PRIVATE_PACKET'),('qualifications',[])]:
   with self.subTest(key=key),self.assertRaises(ValueError):A.gui_component(dict(doc,**{key:value}),self.facts['archives'])
  bad=copy.deepcopy(doc);bad['profile_results']['minimal']['direct_child_wait']=124
  with self.assertRaises(ValueError):A.gui_component(bad,self.facts['archives'])
  bad=copy.deepcopy(doc);bad['profile_runs']['overlay']=bad['profile_runs']['minimal']
  with self.assertRaises(ValueError):A.gui_component(bad,self.facts['archives'])
if __name__=='__main__':unittest.main()
