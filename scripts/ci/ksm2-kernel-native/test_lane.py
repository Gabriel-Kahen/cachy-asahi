"""Real private-file and source controls only; never build/boot an Image."""
import ast,json,os,shutil,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import lane as L
ROOT=L.ROOT;HERE=L.HERE
class Controls(unittest.TestCase):
 def test_source_closed_null_no_process(self):
  with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')),patch.object(subprocess,'run',side_effect=AssertionError('actor')):
   v=L.preflight(ROOT)
  self.assertIsNone(v['actual_source']);self.assertIsNone(v['actual_run'])
 def test_actual_authority_refuses_before_workspace_creation(self):
  with tempfile.TemporaryDirectory()as td,patch.dict(os.environ,{},clear=True),patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
   work=Path(td)/'work';out=Path(td)/'out'
   with self.assertRaisesRegex(ValueError,'genuine source'):L.build(ROOT,work,out)
   self.assertFalse(work.exists());self.assertFalse(out.exists())
 def test_whole_v2_factory_held_and_exact_derivation(self):
  before=L.KP.held(ROOT,'build_kernel.py');after=L.KP.build_helper(before)
  self.assertEqual(after.replace(repr(L.KP.PROFILE).encode(),repr(L.KP.OLD).encode()),before)
  fragment=L.KP.held(ROOT,'kernel.fragment');self.assertEqual(L.KP.fragment(fragment),fragment+b'CONFIG_KSM=y\n')
  def functions(raw):
   text=raw.decode();return{n.name:ast.get_source_segment(text,n)for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
  self.assertEqual(functions(L.KP.contract_bytes(ROOT)),functions(L.KP.held(ROOT,'kernel_contract.py')))
 def test_real_genuine_config_delta_hidden_kconfig_select_and_wrong_change(self):
  a=L.read(HERE/'fixtures/baseline.config');b=L.read(HERE/'fixtures/ksm.config');proof=L.decode(L.read(HERE/'fixtures/configuration-proof.json'))
  self.assertEqual(L.delta(a,b)['changed'],proof['configuration_delta']);L.KP.check_config(HERE/'fixtures/ksm.config')
  for bad in(b.replace(b'CONFIG_KSM=y',b'CONFIG_KSM=n'),b+b'CONFIG_XXHASH=y\n',b.replace(b'CONFIG_ARM64_16K_PAGES=y',b'CONFIG_ARM64_16K_PAGES=n')):
   with self.assertRaises(ValueError):L.delta(a,bad)
 def test_profile_config_rejects_ksm_mmu_and_xxhash_missing(self):
  raw=L.read(HERE/'fixtures/ksm.config')
  with tempfile.TemporaryDirectory()as td:
   p=Path(td)/'config'
   for key in('KSM','MMU','XXHASH','ARM64_16K_PAGES'):
    p.write_bytes(raw.replace(('CONFIG_'+key+'=y').encode(),('CONFIG_'+key+'=n').encode()))
    with self.assertRaises(ValueError):L.KP.check_config(p)
 def test_real_owned_copied_helpers_and_config_cleanup(self):
  with tempfile.TemporaryDirectory()as td:
   p=Path(td)/'owned';owner=L.fresh(p)
   for n in('build_kernel.py','kernel.fragment'):(p/n).write_bytes(L.KP.held(ROOT,n))
   L.KP.prepare_kernel(ROOT,p);self.assertEqual((p/'kernel.fragment').read_bytes(),L.KP.fragment(L.KP.held(ROOT,'kernel.fragment')))
   (p/'sub').mkdir();(p/'sub/file').write_bytes(b'private');target=Path(td)/'outside';target.write_bytes(b'held');(p/'sub/alias').symlink_to(target)
   v=L.remove_owned(p,owner,{'build_kernel.py','kernel.fragment','sub'});self.assertTrue(v['absence_verified']);self.assertEqual(target.read_bytes(),b'held')
 def test_unknown_workspace_top_and_identity_refuse_without_deletion(self):
  with tempfile.TemporaryDirectory()as td:
   p=Path(td)/'owned';owner=L.fresh(p);(p/'UNKNOWN').write_bytes(b'preserve')
   with self.assertRaises(ValueError):L.remove_owned(p,owner,{'known'})
   with self.assertRaises(ValueError):L.remove_owned(p,[owner[0],owner[1]+1,owner[2]],{'UNKNOWN'})
   self.assertEqual((p/'UNKNOWN').read_bytes(),b'preserve')
 def test_source_extra_shadow_git_and_drift_refuse_real_git_metadata_allowed(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td)/'source';shutil.copytree(ROOT,root,ignore=lambda directory,names: {'.git'}if Path(directory)==ROOT else set())
   self.assertFalse((root/'.git').exists())
   (root/'.git').write_text('gitdir: /INERT-not-accessed')
   L.preflight(root);(root/'.git').unlink();(root/'.git').mkdir();(root/'.git/config').write_bytes(b'INERT');L.preflight(root)
   (root/'.git-shadow').write_bytes(b'unknown')
   with self.assertRaisesRegex(ValueError,'exact closed'):L.preflight(root)
   (root/'.git-shadow').unlink();p=root/L.LANE/'runtime.py';p.write_bytes(p.read_bytes()+b'\n# drift\n')
   with self.assertRaisesRegex(ValueError,'source pin'):L.preflight(root)
 def test_fixture_setup_runs_from_both_clone_and_worktree_metadata_shapes(self):
  # Exercise the exact failed method from a real owned clone-shaped directory,
  # then a worktree-shaped file; original checkout metadata remains untouched.
  with tempfile.TemporaryDirectory()as td:
   checkout=Path(td)/'checkout';shutil.copytree(ROOT,checkout,ignore=lambda directory,names: {'.git'}if Path(directory)==ROOT else set())
   (checkout/'.git').mkdir();(checkout/'.git/config').write_bytes(b'OWNED_INERT_METADATA_NOT_GIT_AUTHORITY')
   with patch.dict(globals(),ROOT=checkout):self.test_source_extra_shadow_git_and_drift_refuse_real_git_metadata_allowed()
   self.assertEqual((checkout/'.git/config').read_bytes(),b'OWNED_INERT_METADATA_NOT_GIT_AUTHORITY')
   shutil.rmtree(checkout/'.git');(checkout/'.git').write_text('gitdir: /OWNED_INERT_NOT_ACCESSED')
   with patch.dict(globals(),ROOT=checkout):self.test_source_extra_shadow_git_and_drift_refuse_real_git_metadata_allowed()
   self.assertEqual((checkout/'.git').read_text(),'gitdir: /OWNED_INERT_NOT_ACCESSED')
 def test_data_decoder_rejects_duplicate_nonfinite_and_alias_read(self):
  for raw in(b'{"x":1,"x":2}',b'{"x":NaN}'):
   with self.assertRaises(ValueError):L.decode(raw)
  with tempfile.TemporaryDirectory()as td:
   p=Path(td)/'data';p.write_bytes(b'{}');q=Path(td)/'alias';q.symlink_to(p)
   with self.assertRaises(ValueError):L.read(q)
 def test_pinned_helper_image_header_requires_real_geometry(self):
  H=L.KP.helper(ROOT)
  with tempfile.TemporaryDirectory()as td:
   p=Path(td)/'inert-header-NOT-IMAGE';p.write_bytes(b'\0'*64)
   with self.assertRaises(ValueError):H.image_check(p)
 def test_source_profile_has_no_package_or_prior_kernel_authority(self):
  policy=L.decode(L.read(HERE/'input-policy.json'))
  self.assertTrue(all(policy[k]is None for k in('actual_source','actual_ref','actual_run','native_package_decision')))
  K=L.KP.contract(ROOT)
  with self.assertRaises(ValueError):K.validate(dict(profile=L.KP.OLD,status='PASS'))
 def test_all_source_python_compiles_without_importing_retained_code(self):
  for p in ROOT.rglob('*.py'):
   if '.git'not in p.relative_to(ROOT).parts:compile(p.read_bytes(),str(p),'exec')
if __name__=='__main__':unittest.main(verbosity=2)
