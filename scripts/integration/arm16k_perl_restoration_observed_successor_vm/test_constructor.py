# SPDX-License-Identifier: MIT
"""Pure canonical-lock/byte-inverse/tamper/export controls; no actors or Raw."""
import copy,importlib.util,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('compact_successor',HERE/'constructor.py');C=importlib.util.module_from_spec(s);s.loader.exec_module(C)
PARENT=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-perl-ldcache-lifecycle-successor-readiness-20261117-r2/constructed-source')
DIAGNOSTIC=Path('/home/gabe/Documents/ChatGPT/cachy-asahi-perl-cache-restoration-diagnostic-20261117/scripts/integration/arm16k_perl_cache_restoration_diagnostic')
class Controls(unittest.TestCase):
 @classmethod
 def setUpClass(cls):cls.old=C.snapshot(PARENT);cls.diagnostic=C.snapshot(DIAGNOSTIC);cls.own=C.snapshot(HERE);cls.inputs=C.decode(cls.own['inputs.json'][0]);cls.result=C.project(cls.old,cls.diagnostic,cls.own,DIAGNOSTIC)
 def test_old_canonical_lock_exact69318_byte_identity(self):
  raw=self.old['source.lock.json'][0];self.assertEqual(len(raw),69318);self.assertEqual(C.canonical(C.decode(raw)),raw);self.assertEqual(C.pin(raw),self.inputs['predecessor']['source_lock'])
 def test_positive_projection_and_complete387_inverse(self):
  self.assertEqual(C.inverse(self.result,self.inputs['predecessor']),self.old);self.assertEqual(len(self.result),388);self.assertLessEqual(sum(len(b)for b,_ in self.result.values()),C.CAP)
 def test_runtime_only_no_full_old_lock_or_root_duplicate(self):
  added=set(self.result)-set(self.old);self.assertEqual(added,{C.PREFIX+'construction.DATA.json'})
  for n in added:self.assertNotEqual(self.result[n][0],self.old['source.lock.json'][0]);self.assertNotEqual(self.result[n][0],self.old['guest/root.sh'][0]);self.assertNotIn('test_',n);self.assertNotIn('README',n)
  changed={n for n in self.old if n!='source.lock.json'and self.old[n]!=self.result[n]};self.assertEqual(changed,{'guest/root.sh'})
 def test_exact_changed_segment_bytes_and_tiny_preimages(self):
  m=C.decode(self.result[C.PREFIX+'construction.DATA.json'][0]);c=m['changes']['guest/root.sh'];self.assertEqual(C.restore_patch(self.result['guest/root.sh'][0],c['patch']),self.old['guest/root.sh'][0]);self.assertLess(sum(len(C.base64.b64decode(p['before_b64']))for p in c['patch']),1024)
 def reseal_manifest(self,edit):
  files=dict(self.result);m=C.decode(files[C.PREFIX+'construction.DATA.json'][0]);edit(m);files[C.PREFIX+'construction.DATA.json']=(C.canonical(m),0o644);lock=C.decode(files['source.lock.json'][0]);lock['files']=C.rows({n:r for n,r in files.items()if n!='source.lock.json'});files['source.lock.json']=(C.canonical(lock),0o644);return files
 def test_inverse_patch_bytes_offsets_and_membership_tamper_refuse(self):
  for edit in(lambda m:m['changes']['guest/root.sh']['patch'][0].__setitem__('before_b64','Y29ycnVwdA=='),lambda m:m['changes']['guest/root.sh']['patch'][0].__setitem__('start',1),lambda m:m['added_membership'].append('guest/root.sh')):
   with self.assertRaises(ValueError):C.inverse(self.reseal_manifest(edit),self.inputs['predecessor'])
 def test_original_mode_metadata_and_unchanged_body_tamper_refuse(self):
  files=dict(self.result);files['controller.py']=(files['controller.py'][0]+b' ',files['controller.py'][1]);self.assertRaises(ValueError,C.inverse,files,self.inputs['predecessor'])
  files=self.reseal_manifest(lambda m:m['changes']['guest/root.sh']['before'].__setitem__('mode',0o755));self.assertRaises(ValueError,C.inverse,files,self.inputs['predecessor'])
  files=self.reseal_manifest(lambda m:m['original_lock_metadata'].__setitem__('kind','WEAKENED'));self.assertRaises(ValueError,C.inverse,files,self.inputs['predecessor'])
 def test_wrong_parent_family_and_unbound_qmp_refuse_before_import(self):
  for old,diagnostic in((dict(self.old,EXTRA=(b'extra',0o644)),self.diagnostic),(self.old,dict(self.diagnostic,EXTRA=(b'extra',0o644)))):
   with patch.object(C.importlib.util,'spec_from_file_location',side_effect=AssertionError('no unauthenticated import')):self.assertRaises(ValueError,C.project,old,diagnostic,self.own,DIAGNOSTIC)
  self.assertRaises(ValueError,C.project,self.old,self.diagnostic,self.own,DIAGNOSTIC,{'UNISSUED':True})
 def test_template_roles_null_and_no_default_paths(self):
  v=C.decode((HERE/'selection.TEMPLATE.json').read_bytes());self.assertTrue(all(v[n]is None for n in('predecessor','diagnostic','qmp','output')));self.assertTrue(all(v is None for v in self.inputs['actual'].values()))
  with self.assertRaises((ValueError,TypeError)):C.construct(None,None,None,C.pin(self.own['source.lock.json'][0]))
 def test_physical_export_replay_and_no_input_mutation(self):
  with tempfile.TemporaryDirectory()as d:
   report=C.construct(PARENT,DIAGNOSTIC,Path(d)/'source',C.pin(self.own['source.lock.json'][0]));self.assertEqual(report['files'],388);self.assertFalse(report['full_old_lock_copied']);self.assertFalse(report['full_old_root_copied']);self.assertEqual(C.snapshot(PARENT),self.old);self.assertEqual(C.snapshot(DIAGNOSTIC),self.diagnostic);self.assertTrue(all(v is None for v in report['actual'].values()))
 def test_cap_is_unchanged_and_own_closure_authenticated(self):
  self.assertEqual(self.inputs['fixture_source_cap_bytes'],4194304);self.assertEqual(C.CAP,4194304);self.assertEqual(C.own(C.pin(self.own['source.lock.json'][0]))[0],self.own)
if __name__=='__main__':unittest.main(verbosity=2)
