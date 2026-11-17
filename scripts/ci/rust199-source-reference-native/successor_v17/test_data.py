# SPDX-License-Identifier: MIT
"""Exact Source364 manifest-only delta and complete byte/mode inverse controls."""
import importlib.util,json,os,sys,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
sys.dont_write_bytecode=True

def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=module('v17_constructor',HERE/'prepare.py');T=module('v17_held_parent',HERE.parent/'successor_v16/test_data.py')
def parent_model():
 before=T.parent_model()
 with patch.object(T.P,'PARENT',T.P.identity(before)):return T.P.render(before)
class Data(unittest.TestCase):
 def test_full364_inverse_preserves_every_other_leaf_mode_and_authority(self):
  before=parent_model()
  with patch.object(P,'PARENT',P.identity(before)):
   after=P.render(before);self.assertEqual(P.undo(after),before);self.assertEqual(len(after)-len(before),3)
   for name,row in before.items():
    if name not in P.REPLACED|{'source-map.json'}:self.assertEqual(after[name],row,name)
   marker=json.loads(after[P.MARKER][0]);self.assertTrue(marker['manifest_observed_timings']);self.assertTrue(marker['kernel_preentry_required']);self.assertIsNone(marker['Root_grants']);self.assertFalse(marker['metadata_normalization_changed'])
 def test_only_exact_manifest_decoder_import_and_callsite_admitted(self):
  before=parent_model();payload=P.fs.snapshot(HERE/'payload');P.check_delta(before,payload);name='hosted/phase_transfer.py'
  for old,new in ((b'parse_float=invalid',b'parse_float=float'),(b'0<=path[3]<9',b'0<=path[3]<10'),(b'math.isfinite(value)',b'True'),(b'REQUEST_CAP=7',b'REQUEST_CAP=8'),(b"'exact complete transfer file membership'",b"'modified'"),(b'manifest=decode_manifest(raw_manifest)',b'manifest=decode(raw_manifest)')):
   bad=dict(payload);self.assertIn(old,bad[name][0]);bad[name]=(bad[name][0].replace(old,new),0o644)
   with self.subTest(old=old),self.assertRaises(ValueError):P.check_delta(before,bad)
 def test_marker_map_archive_payload_mode_and_extra_namespace_tamper_refuse(self):
  before=parent_model()
  with patch.object(P,'PARENT',P.identity(before)):
   after=P.render(before)
   for name in(P.MARKER,'source-map.json','hosted/phase_transfer.py',P.ARCHIVE+'hosted/phase_transfer.py'):
    bad=dict(after);bad[name]=(bad[name][0]+b'TAMPER',0o644)
    with self.subTest(name=name),self.assertRaises(ValueError):P.undo(bad)
   with self.assertRaises(ValueError):P.undo(dict(after,UNLISTED=(b'MODEL',0o644)))
   bad=dict(after);bad['hosted/phase_transfer.py']=(bad['hosted/phase_transfer.py'][0],0o755)
   with self.assertRaises(ValueError):P.undo(bad)
 def test_profile_is_complete_unissued_and_public_actual_fixture_whole_pinned(self):
  value=json.loads((HERE/'constructor-profile.json').read_bytes());self.assertEqual(value['schema'],17);self.assertEqual(value['parent'],P.PARENT);self.assertEqual(value['constructor_files'],P.inputs());self.assertEqual(value['actual'],P.ACTUAL);self.assertIsNone(value['Root_review']);self.assertIsNone(value['accepted']);self.assertEqual((HERE/'Root-admission.TEMPLATE.json').read_bytes(),(HERE.parent/'successor_v16/Root-admission.TEMPLATE.json').read_bytes())
  raw=(HERE/'fixtures/public-failure.ACTUAL364.json').read_bytes();self.assertEqual(P.fs.pin(raw),dict(bytes=28759,sha256='466401585d11e3e74b5ba41c20131f23d65da42108ec374916cb933364412d8f'))
 def test_actual364_and_full364_361_355_351_344_340_inverse_and_exact_rerenders(self):
  path=os.environ.get('RUST199_V17_PARENT')
  if not path:self.skipTest('set RUST199_V17_PARENT for actual consumed364 DATA closure')
  before=P.capture(Path(path));after=P.render(before);self.assertEqual(P.undo(after),before);current=before
  for version,count in((16,361),(15,355),(14,351),(13,344),(12,340)):
   constructor=module('v17_exact_inverse_'+str(version),HERE.parent/('successor_v'+str(version))/'prepare.py');prior=current;current=constructor.undo(prior);self.assertEqual(len(current),count);self.assertEqual(constructor.render(current),prior)
if __name__=='__main__':unittest.main(verbosity=2)
