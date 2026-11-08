"""NEW DATA-only variant emission and corruption controls; no Source imports."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
EVENTS=[]
def fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn','os.fork','os.posix_spawn')) or event in ('os.system','os.kill','os.killpg'):
        EVENTS.append(event);raise RuntimeError('variant DATA controls deny actors')
sys.addaudithook(fence)
spec=importlib.util.spec_from_file_location('pid1_variant_prepare',HERE/'prepare.py');P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)
class Variant(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.work=Path(self.temp.name)
    def test_emitted_all201_bytes_modes_match_reviewed_four_delta(self):
        target=self.work/'source';result=P.construct(ARGS.parent_source,target,ARGS.profile_sha256)
        profile=json.loads((HERE/'profile.json').read_bytes());before=json.loads((HERE/'parent-files.json').read_bytes());expected_names=set(before)
        self.assertEqual({p.relative_to(target).as_posix() for p in target.rglob('*') if p.is_file()},expected_names)
        changed=set()
        for name,row in before.items():
            body=(target/name).read_bytes();self.assertEqual((target/name).stat().st_mode & 0o777,int(row['mode'],8)&0o777)
            if P.pin(body)!={k:row[k] for k in ('bytes','sha256')}:changed.add(name)
        self.assertEqual(changed,P.CHANGED|{P.MAP});self.assertEqual(result['tree'],profile['source_tree']);self.assertEqual(result['held'],197)
        self.assertEqual(json.loads((target/P.MAP).read_bytes())['actual'],dict(source=None,ref=None,run=None))
    def parent_copy(self):
        target=self.work/'parent';shutil.copytree(ARGS.parent_source,target,ignore=shutil.ignore_patterns('.git'));return target
    def test_changed_parent_refused_before_output(self):
        parent=self.parent_copy();path=parent/'native/release_tools_v1.py';path.write_bytes(path.read_bytes()+b'\n')
        target=self.work/'source'
        with self.assertRaises(ValueError):P.construct(parent,target,ARGS.profile_sha256)
        self.assertFalse(target.exists())
    def test_extra_parent_directory_refused_before_output(self):
        parent=self.parent_copy();(parent/'unlisted-empty-directory').mkdir();target=self.work/'source'
        with self.assertRaises(ValueError):P.construct(parent,target,ARGS.profile_sha256)
        self.assertFalse(target.exists())
    def test_variant_fixture_drift_refused_before_output(self):
        variant=self.work/'variant';shutil.copytree(HERE,variant);fixture=variant/'fixtures/release_projection_v1.py.txt';fixture.write_bytes(fixture.read_bytes()+b'\n');target=self.work/'source'
        with patch.object(P,'HERE',variant),self.assertRaises(ValueError):P.construct(ARGS.parent_source,target,ARGS.profile_sha256)
        self.assertFalse(target.exists())
if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--parent-source',type=Path,required=True);parser.add_argument('--profile-sha256',required=True);ARGS=parser.parse_args()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Variant))
    if EVENTS or not result.wasSuccessful() or result.testsRun!=4 or result.skipped:raise SystemExit(1)
