# SPDX-License-Identifier: MIT
"""Constructor DATA controls; no actor, Root issuance, Raw or package execution."""
import copy,importlib.util,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('cache_successor_constructor',HERE/'constructor.py');C=importlib.util.module_from_spec(s);s.loader.exec_module(C)
PARENT=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-perl-observed-hold-successor-readiness-20261117-r1/constructed-source')
PROPOSAL=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-perl-ldcache-semantic-transition-20261117/scripts/integration/arm16k_perl_ldcache_semantic_transition')
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.inputs=C.decode((HERE/'inputs.json').read_bytes());cls.old=C.snapshot(PARENT);cls.proposal=C.snapshot(PROPOSAL)
 def test_frozen_source339_whole_tuple(self):
  C.closed(self.old,self.inputs['predecessor']['source_lock']);self.assertEqual(len(self.old),339);self.assertEqual(sum(len(b)for b,_ in self.old.values()),3512147)
 def test_entire_semantic_proposal_pinned(self):
  C.proposal_closed(self.proposal,self.inputs['proposal']);self.assertEqual(len(self.proposal),35);self.assertEqual(sum(len(b)for b,_ in self.proposal.values()),435271)
 def test_null_selection_refuses_before_material_or_transform(self):
  v=C.decode((HERE/'selection.TEMPLATE.json').read_bytes())
  with patch.object(C,'material',side_effect=AssertionError('no material access')),patch.object(C.importlib.util,'spec_from_file_location',side_effect=AssertionError('no transform execution')):
   with self.assertRaisesRegex(ValueError,'all explicit'):C.selection(v,self.inputs)
 def test_material_or_baseline_pin_drift_refuses(self):
  v=C.decode((HERE/'selection.TEMPLATE.json').read_bytes());v.update(predecessor=str(PARENT),proposal=str(PROPOSAL),output='/MODEL/out',baseline=dict(path='/MODEL/cache',**self.inputs['baseline']),materials=copy.deepcopy(self.inputs['materials']))
  v['materials']['db_archive']['sha256']='0'*64
  with patch.object(C,'material',side_effect=AssertionError('no access')):self.assertRaises(ValueError,C.selection,v,self.inputs)
  v['materials']=self.inputs['materials'];v['baseline']['bytes']+=1
  with patch.object(C,'material',side_effect=AssertionError('no access')):self.assertRaises(ValueError,C.selection,v,self.inputs)
 def test_source_corruption_extra_leaf_and_mode_refuse(self):
  for modify in(lambda f:f.__setitem__('controller.py',(b'corrupt',0o644)),lambda f:f.__setitem__('EXTRA',(b'extra',0o644)),lambda f:f.__setitem__('controller.py',(f['controller.py'][0],0o755))):
   files=dict(self.old);modify(files)
   with self.assertRaises(ValueError):C.closed(files,self.inputs['predecessor']['source_lock'])
 def test_proposal_missing_or_corrupt_leaf_refuses(self):
  files=dict(self.proposal);files.pop('primary/exact-cache.c');self.assertRaises(ValueError,C.proposal_closed,files,self.inputs['proposal']);files=dict(self.proposal);files['transform.py']=(b'corrupt',0o644);self.assertRaises(ValueError,C.proposal_closed,files,self.inputs['proposal'])
 def model_inverse(self):
  # Inverse control uses all actual339 preimages and modes, but MODEL replacements.
  # It is not positive successor projection or a replacement for baseline bytes.
  files=dict(self.old);prefix=C.PREFIX;preimages={}
  for name,leaf in(('guest/root.sh','predecessor-root.sh'),('guest/initialized-state.sh','predecessor-initialized-state.sh')):
   target=prefix+'proposal/'+leaf;files[target]=self.proposal[leaf];preimages[name]=target;files[name]=(b'# MODEL ONLY\n',self.old[name][1])
  files[prefix+'inverse/source.lock.json']=self.old['source.lock.json'];manifest_name=prefix+'construction.DATA.json';added=sorted(set(files)-set(self.old)|{manifest_name});changes={n:dict(before=C.rows({n:self.old[n]})[n],after=C.rows({n:files[n]})[n])for n in preimages};v=dict(added_membership=added,changes=changes,inverse=dict(preimages=preimages,old_lock=prefix+'inverse/source.lock.json'));files[manifest_name]=(C.canonical(v),0o644);return files
 def test_complete_actual339_inverse_using_model_replacements(self):self.assertEqual(C.inverse(self.model_inverse(),self.inputs['predecessor']),self.old)
 def test_inverse_old_lock_preimage_membership_corruption_refuses(self):
  for key in(C.PREFIX+'inverse/source.lock.json',C.PREFIX+'proposal/predecessor-root.sh'):
   files=self.model_inverse();files[key]=(b'corrupt',0o644);self.assertRaises(ValueError,C.inverse,files,self.inputs['predecessor'])
  files=self.model_inverse();files['UNDECLARED']=(b'extra',0o644);self.assertRaises(ValueError,C.inverse,files,self.inputs['predecessor'])
 def test_conservative_budget_is_not_positive_construction(self):
  b=C.budget_bound(self.old,self.proposal,C.snapshot(HERE));self.assertLessEqual(b['upper_bound_bytes'],C.CAP);self.assertTrue(b['fits_conservative_bound']);self.assertIsNone(b['baseline_body']);self.assertIsNone(b['actual_source_lock'])
 def test_source_cap_unchanged_and_enforced(self):
  self.assertEqual(C.CAP,self.inputs['fixture_source_cap_bytes']);self.assertEqual(C.CAP,4194304)
  with tempfile.TemporaryDirectory()as d:
   p=Path(d)/'large';p.write_bytes(b'x'*(C.CAP+1));p.chmod(0o644);self.assertRaises(ValueError,C.snapshot,Path(d))
 def test_symlink_empty_directory_and_hardlink_refuse(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d);(p/'empty').mkdir();self.assertRaises(ValueError,C.snapshot,p);(p/'empty').rmdir();(p/'x').write_bytes(b'x');(p/'x').chmod(0o644);(p/'link').symlink_to(p/'x');self.assertRaises(ValueError,C.snapshot,p);(p/'link').unlink();(p/'hard').hardlink_to(p/'x');self.assertRaises(ValueError,C.snapshot,p)
 def test_own_constructor_whole_closure(self):
  raw=(HERE/'source.lock.json').read_bytes();files,inputs=C.own(C.pin(raw));self.assertEqual(files,C.snapshot(HERE));self.assertEqual(inputs,self.inputs)
 def test_baseline_absence_refuses_project_before_proposal_exec(self):
  ctor=C.snapshot(HERE)
  with patch.object(C.importlib.util,'spec_from_file_location',side_effect=AssertionError('proposal must not execute')):
   with self.assertRaisesRegex(ValueError,'baseline'):C.project(self.old,self.proposal,ctor,PROPOSAL,b'',self.inputs['materials'])
 def test_authority_and_old_qualification_unchanged(self):
  self.assertTrue(all(v is None for v in self.inputs['actual'].values()));self.assertIn(b'no default authority', (HERE/'constructor.py').read_bytes());self.assertIn(b'NO_F51_WAIVER',(HERE/'constructor.py').read_bytes());self.assertNotIn('f51',','.join(self.inputs['materials']))
if __name__=='__main__':unittest.main(verbosity=2)
