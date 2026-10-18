"""Real private-file and source controls only; never build/boot an Image."""
import ast,json,os,re,shutil,subprocess,tempfile,unittest
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
 def test_whole_historical_factory_and_exact_four_symbol_derivation(self):
  before=L.KP.held(ROOT,'build_kernel.py');after=L.KP.build_helper(before)
  self.assertEqual(after.replace(repr(L.KP.PROFILE).encode(),repr(L.KP.OLD).encode()),before)
  fragment=L.KP.held(ROOT,'kernel.fragment');self.assertEqual(L.KP.fragment(fragment),fragment+L.KP.ADDITIONS)
  def functions(raw):
   text=raw.decode();return{n.name:ast.get_source_segment(text,n)for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)}
  self.assertEqual(functions(L.KP.contract_bytes(ROOT)),functions(L.KP.held(ROOT,'kernel_contract.py')))
 def test_pinned_source_select_closure_and_genuine_baseline_not_candidate(self):
  a=L.read(HERE/'fixtures/baseline.config');proof=L.decode(L.read(HERE/'fixtures/configuration-source-proof.json'));rules=L.decode(L.read(HERE/'fixtures/configuration-rules.json'))
  self.assertEqual(L.pin(a),proof['baseline_config']);self.assertIsNone(proof['actual_candidate_config']);self.assertIsNone(rules['actual_configuration']);self.assertEqual(len(rules['expected_changes']),14)
  values=L.config_values(a)
  for n,row in rules['expected_changes'].items():self.assertEqual(row,dict(before='n',proposed='y'));self.assertEqual(values.get(n,'n'),'n')
  for n in rules['already_enabled_unchanged']:self.assertEqual(values[n],'y')
  for source,selected in proof['edges'].items():
   text=proof['blocks'][source]['text']
   for symbol in selected:self.assertIn(('depends on 'if source=='MD'else'select ')+symbol,text)
  self.assertFalse((HERE/'fixtures/verity.config').exists())
  with self.assertRaises(ValueError):L.delta(a,a)
  with self.assertRaises(ValueError):L.KP.check_config(HERE/'fixtures/baseline.config')
 def test_config_parser_and_delta_refuse_unrelated_or_duplicate_changes(self):
  # Inert parser fragments cannot claim any configured kernel or built Image.
  for a,b in((b'CONFIG_MMU=y\n',b'CONFIG_MMU=m\n'),(b'CONFIG_MD=n\n',b'CONFIG_MD=y\nCONFIG_KSM=y\n'),(b'CONFIG_MMU=y\n',b'CONFIG_MMU=y\nCONFIG_UNRELATED=n\n')):
   with self.assertRaises(ValueError):L.delta(a,b)
  for raw in(b'CONFIG_MD=y\nCONFIG_MD=y\n',b'# CONFIG_MD is not set\nCONFIG_MD=y\n'):
   with self.assertRaises(ValueError):L.config_values(raw)
  with tempfile.TemporaryDirectory()as td:
   p=Path(td)/'inert-not-a-config';p.write_bytes(b'CONFIG_MD=y\nCONFIG_MD=y\n')
   with self.assertRaises(ValueError):L.KP.check_config(p)
 def test_inactive_domain_is_source_derived_prompt_frontier_not_actual_list(self):
  proof=L.decode(L.read(HERE/'fixtures/configuration-source-proof.json'));rules=L.decode(L.read(HERE/'fixtures/configuration-rules.json'));baseline=L.read(HERE/'fixtures/baseline.config')
  result=L.D.validate(rules,proof,baseline,L.pin)
  self.assertEqual(len(result['domain']),189);self.assertEqual(len(result['frontier']),16);self.assertEqual(len(result['routes']),9)
  self.assertNotIn('CONFIG_BLK_WBT',result['domain']);self.assertNotIn('CONFIG_CRYPTO_LIB_SHA256',result['domain']);self.assertNotIn('CONFIG_DM_PCACHE',result['domain']);self.assertNotIn('CONFIG_DM_PERSISTENT_DATA',result['domain']);self.assertNotIn('CONFIG_CRYPTO_KRB5_SELFTESTS',result['domain'])
  for symbol in ('CONFIG_BLK_WBT','CONFIG_CRYPTO_LIB_AES'):
   with self.assertRaisesRegex(ValueError,'inactive configuration domain'):L.delta(b'',(symbol+'=n\n').encode())
 def test_source_emitter_is_finite_passive_and_rejects_drift_before_output(self):
  import prepare as P
  with tempfile.TemporaryDirectory()as td,patch.object(subprocess,'Popen',side_effect=AssertionError('actor')),patch.object(subprocess,'run',side_effect=AssertionError('actor')):
   out=Path(td)/'emitted';v=P.emit(ROOT,ROOT,out)
   self.assertEqual(len(v['files']),20);self.assertIsNone(v['source']);self.assertIsNone(v['ref']);self.assertIsNone(v['run']);L.preflight(out)
   with self.assertRaisesRegex(ValueError,'fresh source-only'):P.emit(ROOT,ROOT,out)
   inputs=Path(td)/'inputs';shutil.copytree(ROOT,inputs,ignore=lambda directory,names:{'.git'}if Path(directory)==ROOT else set())
   target=inputs/'scripts/ci/managed-gui-generic16k/kernel.fragment';target.write_bytes(target.read_bytes()+b'\n')
   refused=Path(td)/'refused'
   with self.assertRaisesRegex(ValueError,'whole borrowed input'):P.emit(ROOT,inputs,refused)
   self.assertFalse(refused.exists())
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
class CandidateRetention(unittest.TestCase):
 def candidate(self,root):
  helper=root/'helper';(helper/'built/build/arch/arm64/boot').mkdir(parents=True)
  (helper/'built/build/.config').write_bytes(b'CONFIG_OUTSIDE_EXPLICIT_DOMAIN=n\n')
  (helper/'built/build/arch/arm64/boot/Image').write_bytes(b'INERT_NOT_A_KERNEL_HEADER'.ljust(64,b'!')+b'NOT_EXPORTED')
  (helper/'built/build-receipt.json').write_bytes(b'{"status":"INERT_NOT_ACCEPTED"}\n');return helper
 def test_real_private_candidate_retained_before_original_delta_refusal(self):
  with tempfile.TemporaryDirectory()as td:
   helper=self.candidate(Path(td));rows={};L.retain_candidate(helper,lambda n,b:rows.__setitem__(n,b))
   with self.assertRaisesRegex(ValueError,'inactive configuration domain'):L.delta(b'',rows['candidate-unvalidated.config'])
   self.assertEqual(len(rows),4);self.assertEqual(rows['candidate-unvalidated-build-receipt.json'],(helper/'built/build-receipt.json').read_bytes())
   self.assertEqual(rows['candidate-unvalidated.Image.header'],(helper/'built/build/arch/arm64/boot/Image').read_bytes()[:64])
   v=L.decode(rows['candidate-unvalidated.json']);self.assertFalse(v['acceptance_authority']);self.assertEqual(v['configuration_delta'],'NOT_YET_VALIDATED');self.assertEqual(v['files'],{n:L.pin(b)for n,b in rows.items()if n!='candidate-unvalidated.json'})
 def test_missing_alias_hardlink_and_oversize_data_never_accept(self):
  for kind in('missing','symlink','hardlink','oversize'):
   with self.subTest(kind=kind),tempfile.TemporaryDirectory()as td:
    root=Path(td);helper=self.candidate(root);p=helper/'built/build/.config';p.unlink()
    if kind in('symlink','hardlink'):
     other=root/'other';other.write_bytes(b'PRIVATE')
     if kind=='symlink':p.symlink_to(other)
     else:os.link(other,p)
    elif kind=='oversize':p.write_bytes(b'x'*262145)
    rows={};L.retain_candidate(helper,lambda n,b:rows.__setitem__(n,b));v=L.decode(rows['candidate-unvalidated.json'])
    self.assertNotIn('candidate-unvalidated.config',rows);self.assertIn('candidate-unvalidated.config',v['unavailable']);self.assertFalse(v['acceptance_authority'])
 def test_header_refuses_alias_hardlink_short_and_large_without_full_read(self):
  with tempfile.TemporaryDirectory()as td:
   root=Path(td);p=root/'Image';p.write_bytes(b'x'*64);q=root/'alias';q.symlink_to(p)
   with self.assertRaises(ValueError):L.image_header(q)
   q.unlink();os.link(p,q)
   with self.assertRaises(ValueError):L.image_header(p)
   q.unlink();p.write_bytes(b'x'*63)
   with self.assertRaises(ValueError):L.image_header(p)
   with p.open('wb')as f:f.truncate(256*1024**2+1)
   with self.assertRaises(ValueError):L.image_header(p)
 def test_actual_build_call_precedes_all_candidate_validation(self):
  text=(HERE/'lane.py').read_text();tree=ast.parse(text);fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='build');body=ast.get_source_segment(text,fn)
  self.assertLess(body.index('receipt=command(helper,False)'),body.index('retain_candidate(helper,emit)'))
  self.assertLess(body.index('retain_candidate(helper,emit)'),body.index('K.from_receipt('))
  self.assertLess(body.index('retain_candidate(helper,emit)'),body.index('delta(baseline_config,'))

if __name__=='__main__':unittest.main(verbosity=2)
