#!/usr/bin/env python3
"""Focused source/context controls; no actors."""
import importlib.util,json,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('_outer_lifecycle_test',ROOT/'entry.py');E=importlib.util.module_from_spec(s);s.loader.exec_module(E)
class Source(unittest.TestCase):
 def test_whole_closure_and_null(self):
  p=E.verify();self.assertEqual(p['purpose'],'normal-emulated16k-lifecycle-v1');self.assertEqual(len(p['production_files']),709);self.assertIsNone(p['source']);self.assertFalse(p['normal_updater_acceptance'])
 def test_no_context_no_actor(self):
  old=E.private
  def forbidden():raise AssertionError('ACTOR_FORBIDDEN')
  E.private=forbidden
  try:
   for a in [[],['run'],['run','--lifecycle-mode','wrong'],['--probe-mode','generic16k-fullcopy-capacity']]:
    with self.assertRaises(ValueError):E.main(a)
  finally:E.private=old
 def test_aliases_and_single_artifact(self):
  a=(ROOT/'.github/workflows/native-arm-build.yml').read_bytes();self.assertEqual(a,(ROOT/'.github/workflows/native-arm-updater607-normal-lifecycle.yml').read_bytes());x=json.loads(a);self.assertEqual(x['name'],'native-arm-latest607-updater-generic16k');self.assertEqual(x['jobs']['native']['timeout-minutes'],360);self.assertEqual(len([s for s in x['jobs']['native']['steps']if s.get('uses','').startswith('actions/upload-artifact@')]),1);self.assertEqual(x['on']['workflow_dispatch']['inputs']['case']['options'],['normal','precommit-exit86','postcommit-exit87']);self.assertNotIn('probe_mode',x['on']['workflow_dispatch']['inputs']);self.assertNotIn('native4k-source/capacity/',a.decode());self.assertNotIn('--probe-mode',a.decode())
 def test_transport_global_bounds(self):
  x=json.loads((ROOT/'.github/workflows/native-arm-build.yml').read_bytes());steps=x['jobs']['native']['steps'];t=next(s for s in steps if s.get('name')=='Checkout exact complete574 original public package bytes');self.assertEqual(t['timeout-minutes'],9);self.assertIn('ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad',t['run']);n=next(s for s in steps if s.get('name')=='Run explicit EMULATED16K normal updater lifecycle');self.assertEqual(n['timeout-minutes'],310);self.assertIn('--lifecycle-mode normal-emulated16k-lifecycle-v1',n['run'])
if __name__=='__main__':unittest.main(verbosity=2)
