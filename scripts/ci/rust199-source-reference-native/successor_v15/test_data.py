"""Source-only full inverse and unchanged-policy controls; no native actors."""
import importlib.util,json,os,sys,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
sys.dont_write_bytecode=True

def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=module('v15_constructor',HERE/'prepare.py');T=module('v14_model_parent',HERE.parent/'successor_v14/test_data.py')
def parent_model():
 before=T.parent_model()
 with patch.object(T.P,'PARENT',T.P.identity(before)):return T.P.render(before)
class Data(unittest.TestCase):
 def test_complete355_inverse_and_every_untouched_byte_mode(self):
  before=parent_model()
  with patch.object(P,'PARENT',P.identity(before)):
   after=P.render(before);self.assertEqual(P.undo(after),before);self.assertEqual(len(after)-len(before),6)
   for n,row in before.items():
    if n not in P.REPLACED|{'source-map.json'}:self.assertEqual(after[n],row,n)
   self.assertEqual(after['actor/mount_proof.py'],before['actor/mount_proof.py']);marker=json.loads(after[P.MARKER][0]);self.assertTrue(marker['external_owned_job_directory_setup']);self.assertTrue(marker['kernel_preentry_required']);self.assertIsNone(marker['Root_grants'])
 def test_only_finite_setup_receipt_and_initializer_authority_reduction_change(self):
  before=parent_model();payload=P.fs.snapshot(HERE/'payload');P.check_delta(before,payload)
  for name,old,new in(('hosted/producer.py',b"'--memory=8g'",b"'--memory=9g'"),('hosted/qualification.py',b'--cap-drop=ALL',b'--privileged'),('hosted/volume.py',b'uid==gid==1001',b'uid==gid==0')):
   bad=dict(payload);self.assertIn(old,bad[name][0]);bad[name]=(bad[name][0].replace(old,new),0o644)
   with self.subTest(name=name),self.assertRaises(ValueError):P.check_delta(before,bad)
 def test_tampered_parent_map_payload_archive_modes_and_extra_refuse(self):
  before=parent_model()
  with patch.object(P,'PARENT',P.identity(before)):
   after=P.render(before)
   for n in(P.MARKER,'source-map.json','hosted/owned_dir.py',P.ARCHIVE+'hosted/volume.py'):
    bad=dict(after);bad[n]=(bad[n][0]+b'tamper',0o644)
    with self.subTest(n=n),self.assertRaises(ValueError):P.undo(bad)
   bad=dict(after,extra=(b'extra',0o644))
   with self.assertRaises(ValueError):P.undo(bad)
   bad=dict(after);bad['hosted/qualification.py']=(bad['hosted/qualification.py'][0],0o755)
   with self.assertRaises(ValueError):P.undo(bad)
 def test_current_complete_profile_and_unissued_admission(self):
  v=json.loads((HERE/'constructor-profile.json').read_bytes());self.assertEqual(v['schema'],15);self.assertEqual(v['parent'],P.PARENT);self.assertEqual(v['constructor_files'],P.inputs());self.assertEqual(v['actual'],P.ACTUAL);self.assertIsNone(v['Root_review']);self.assertIsNone(v['accepted']);self.assertEqual((HERE/'Root-admission.TEMPLATE.json').read_bytes(),(HERE.parent/'successor_v14/Root-admission.TEMPLATE.json').read_bytes())
 def test_actual355_identity_and_full355_351_344_340_byte_mode_inverses(self):
  # Optional local supplied actual source is DATA only, never imported/executed.
  actual=os.environ.get('RUST199_V15_PARENT')
  if not actual:self.skipTest('set RUST199_V15_PARENT for exact actual355 DATA closure')
  before=P.capture(Path(actual));after=P.render(before);self.assertEqual(P.undo(after),before)
  stages=[(module('v15_inverse14',HERE.parent/'successor_v14/prepare.py'),351),(module('v15_inverse13',HERE.parent/'successor_v13/prepare.py'),344),(module('v15_inverse12',HERE.parent/'successor_v12/prepare.py'),340)]
  current=before
  for constructor,count in stages:current=constructor.undo(current);self.assertEqual(len(current),count)
if __name__=='__main__':unittest.main(verbosity=2)
