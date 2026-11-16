"""Finite Source-only controls. No network, Docker, build or Root issuance."""
import copy,importlib.util,json,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=module('v14_constructor',HERE/'prepare.py');T=module('v13_model_parent',HERE.parent/'successor_v13/test_data.py')
def parent_model():
 before=T.parent_model()
 with patch.object(T.P,'PARENT',T.P.identity(before)):return T.P.render(before)
class Data(unittest.TestCase):
 def test_complete351_inverse_and_every_untouched_byte_mode(self):
  before=parent_model()
  with patch.object(P,'PARENT',P.identity(before)):
   after=P.render(before);self.assertEqual(P.undo(after),before);self.assertEqual(len(after)-len(before),4)
   for n,row in before.items():
    if n not in P.REPLACED|{'source-map.json'}:self.assertEqual(after[n],row,n)
   self.assertEqual(after['actor/mount_proof.py'],before['actor/mount_proof.py']);marker=json.loads(after[P.MARKER][0]);self.assertTrue(marker['api_owned_private_bind_setup']);self.assertTrue(marker['kernel_preentry_required']);self.assertIsNone(marker['Root_grants'])
 def test_only_finite_setup_and_validation_function_sets_change(self):
  before=parent_model();payload=P.fs.snapshot(HERE/'payload');P.check_delta(before,payload);bad=dict(payload);n='hosted/producer.py';bad[n]=(bad[n][0].replace(b"'--memory=8g'",b"'--memory=9g'"),0o644)
  with self.assertRaises(ValueError):P.check_delta(before,bad)
 def test_tampered_parent_map_payload_archive_modes_and_extra_refuse(self):
  before=parent_model()
  with patch.object(P,'PARENT',P.identity(before)):
   after=P.render(before)
   for n in(P.MARKER,'source-map.json','hosted/producer.py',P.ARCHIVE+'hosted/producer.py'):
    bad=dict(after);bad[n]=(bad[n][0]+b'tamper',0o644)
    with self.subTest(n=n),self.assertRaises(ValueError):P.undo(bad)
   bad=dict(after,extra=(b'extra',0o644))
   with self.assertRaises(ValueError):P.undo(bad)
   bad=dict(after);bad['hosted/qualification.py']=(bad['hosted/qualification.py'][0],0o755)
   with self.assertRaises(ValueError):P.undo(bad)
 def test_current_complete_profile_and_unissued_admission(self):
  v=json.loads((HERE/'constructor-profile.json').read_bytes());self.assertEqual(v['schema'],14);self.assertEqual(v['parent'],P.PARENT);self.assertEqual(v['constructor_files'],P.inputs());self.assertEqual(v['actual'],P.ACTUAL);self.assertIsNone(v['Root_review']);self.assertIsNone(v['accepted']);self.assertEqual((HERE/'Root-admission.TEMPLATE.json').read_bytes(),(HERE.parent/'successor_v13/Root-admission.TEMPLATE.json').read_bytes())
if __name__=='__main__':unittest.main(verbosity=2)
