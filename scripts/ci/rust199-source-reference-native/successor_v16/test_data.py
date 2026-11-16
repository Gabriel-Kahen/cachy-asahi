# SPDX-License-Identifier: MIT
"""Exact Source361 post-retirement report-only delta and full inverses."""
import importlib.util,json,os,sys,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
sys.dont_write_bytecode=True

def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=module('v16_constructor',HERE/'prepare.py');T=module('v16_model_held_parent',HERE.parent/'successor_v15/test_data.py')
def parent_model():
 before=T.parent_model()
 with patch.object(T.P,'PARENT',T.P.identity(before)):return T.P.render(before)
class Data(unittest.TestCase):
 def test_full361_inverse_and_every_untouched_body_mode(self):
  before=parent_model()
  with patch.object(P,'PARENT',P.identity(before)):
   after=P.render(before);self.assertEqual(P.undo(after),before);self.assertEqual(len(after)-len(before),3)
   for name,row in before.items():
    if name not in P.REPLACED|{'source-map.json'}:self.assertEqual(after[name],row,name)
   for name in('hosted/producer.py','hosted/volume.py','hosted/owned_dir.py','actor/mount_proof.py'):self.assertEqual(after[name],before[name])
   marker=json.loads(after[P.MARKER][0]);self.assertTrue(marker['post_retirement_report_guard']);self.assertTrue(marker['kernel_preentry_required']);self.assertIsNone(marker['Root_grants'])
 def test_only_exact_final_report_callback_change_is_admitted(self):
  before=parent_model();payload=P.fs.snapshot(HERE/'payload');P.check_delta(before,payload);name='hosted/qualification.py'
  for old,new in((b'workspace.check()',b'None'),(b"'--memory=8g'",b"'--memory=9g'"),(b'sha(path,report_tick)',b'sha(path,tick)'),(b'if command.on_tick is not None:command.on_tick()',b'pass'),(b'not command.cancelled[0]',b'True')):
   bad=dict(payload);self.assertIn(old,bad[name][0]);bad[name]=(bad[name][0].replace(old,new),0o644)
   with self.subTest(old=old),self.assertRaises(ValueError):P.check_delta(before,bad)
 def test_tampered_inverse_marker_map_archive_namespace_and_modes_refuse(self):
  before=parent_model()
  with patch.object(P,'PARENT',P.identity(before)):
   after=P.render(before)
   for name in(P.MARKER,'source-map.json','hosted/qualification.py',P.ARCHIVE+'hosted/qualification.py'):
    bad=dict(after);bad[name]=(bad[name][0]+b'TAMPER',0o644)
    with self.subTest(name=name),self.assertRaises(ValueError):P.undo(bad)
   with self.assertRaises(ValueError):P.undo(dict(after,UNLISTED=(b'MODEL',0o644)))
   bad=dict(after);bad['hosted/qualification.py']=(bad['hosted/qualification.py'][0],0o755)
   with self.assertRaises(ValueError):P.undo(bad)
 def test_complete_profile_and_admission_are_unissued(self):
  value=json.loads((HERE/'constructor-profile.json').read_bytes());self.assertEqual(value['schema'],16);self.assertEqual(value['parent'],P.PARENT);self.assertEqual(value['constructor_files'],P.inputs());self.assertEqual(value['actual'],P.ACTUAL);self.assertIsNone(value['Root_review']);self.assertIsNone(value['accepted']);self.assertEqual((HERE/'Root-admission.TEMPLATE.json').read_bytes(),(HERE.parent/'successor_v15/Root-admission.TEMPLATE.json').read_bytes())
 def test_actual361_parent_and_full361_355_351_344_340_inverse_and_render(self):
  path=os.environ.get('RUST199_V16_PARENT')
  if not path:self.skipTest('set RUST199_V16_PARENT for actual consumed361 DATA closure')
  before=P.capture(Path(path));after=P.render(before);self.assertEqual(P.undo(after),before);current=before
  for version,count in((15,355),(14,351),(13,344),(12,340)):
   constructor=module('v16_exact_inverse_'+str(version),HERE.parent/('successor_v'+str(version))/'prepare.py');prior=current;current=constructor.undo(prior);self.assertEqual(len(current),count);self.assertEqual(constructor.render(current),prior)
if __name__=='__main__':unittest.main(verbosity=2)
