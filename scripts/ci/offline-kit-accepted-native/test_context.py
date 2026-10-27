#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Focused DATA controls; never run candidate payload, GPG, Docker or ALPM."""
import importlib.util,shutil,socket,subprocess,tempfile,unittest,tarfile
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2];LANE='scripts/ci/offline-kit-accepted-native'
def module(path,name):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
O=module(HERE/'owner.py','focused_closed_owner');A=module(HERE/'feature/scripts/release/recipe_source_delivery.py','focused_closed_adapter')
class ContextControls(unittest.TestCase):
 def setUp(self):
  for target in ((subprocess,'Popen'),(socket,'socket')):
   p=patch.object(*target,side_effect=AssertionError('NO_ACTORS_OR_NETWORK'));p.start();self.addCleanup(p.stop)
 def test_exact_fullsource_namespace_and_release_mode(self):
  m=O.source(ROOT,O.sha(O.read(ROOT/O.MAP)))
  self.assertEqual(m['files'][LANE+'/feature/scripts/release/release.py']['mode'],0o755)
  self.assertEqual(m['files'][LANE+'/original-fixture-worker.py']['sha256'],'14381d049506b52770059bf7af415f7a079f69872543e74417aca11ce24ac3c5')
 def test_actual_archives_bind_fullsource_and_licenses_without_execution(self):
  for short,name,count in (('maintenance','cachy-asahi-maintenance',20),('diagnostics','cachy-asahi-session-diagnostics',12)):
   d=HERE/'accepted';p=O.load(d/(short+'.provenance.json'));raw=(d/(short+'.source.tar')).read_bytes();saved,b=A.unpacked(raw,O.sha(raw))
   bound=A.bind_archive(d/p['native_archive'],name,b,A.metadata(b['.SRCINFO']))
   self.assertEqual(bound,saved['archive_binding']);self.assertEqual(bound,p['archive_binding']);self.assertEqual(len(b),count)
   self.assertEqual(O.sha(raw),p['source_bundle_pin']['sha256'])
   for n in ('PKGBUILD','LICENSE','NOTICE'):self.assertEqual(b[n],(d/(short+'.'+n)).read_bytes())
 def test_changed_actual_archive_and_crossed_source_refuse(self):
  d=HERE/'accepted';p=O.load(d/'maintenance.provenance.json');raw=(d/'maintenance.source.tar').read_bytes();_,b=A.unpacked(raw,O.sha(raw))
  with tempfile.TemporaryDirectory() as folder:
   changed=Path(folder)/p['native_archive'];data=bytearray((d/p['native_archive']).read_bytes());data[len(data)//2]^=1;changed.write_bytes(data)
   with self.assertRaises((A.s.Error,ValueError,OSError,EOFError,tarfile.ReadError)):A.bind_archive(changed,p['package'],b,A.metadata(b['.SRCINFO']))
  raw=(d/'diagnostics.source.tar').read_bytes();_,other=A.unpacked(raw,O.sha(raw))
  with self.assertRaises((A.s.Error,ValueError)):A.bind_archive(d/p['native_archive'],p['package'],other,A.metadata(other['.SRCINFO']))
 def test_original_public_material_is_exact_data(self):
  d=HERE/'accepted';m=O.load(d/'FILES.json');self.assertEqual({p.name for p in d.iterdir()},set(m['files'])|{'FILES.json'})
  for n,row in m['files'].items():self.assertEqual(dict(bytes=(d/n).stat().st_size,sha256=O.sha((d/n).read_bytes())),row)
  for short in ('maintenance','diagnostics'):
   key=(d/(short+'.TEST-public.asc')).read_bytes();self.assertTrue(key.startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----'));self.assertNotIn(b'PRIVATE KEY',key)
   self.assertEqual((d/(short+'.TEST-original-status.txt')).read_text().count('[GNUPG:] VALIDSIG '),1)
 def test_extra_leaf_and_wrong_release_mode_refuse(self):
  pin=O.sha(O.read(ROOT/O.MAP))
  with tempfile.TemporaryDirectory() as folder:
   root=Path(folder)/'source';shutil.copytree(ROOT,root,ignore=shutil.ignore_patterns('.git','retained574','retained-public-inputs'))
   release=root/LANE/'feature/scripts/release/release.py';release.chmod(0o644)
   with self.assertRaises(ValueError):O.source(root,pin)
   release.chmod(0o755);(root/'unlisted').write_bytes(b'no')
   with self.assertRaises(ValueError):O.source(root,pin)
 def test_worker_prefix_bound_and_actual_native_payload_parsing(self):
  w=module(HERE/'candidate-source/candidate-worker.py','focused_candidate_worker');generated=(HERE/'candidate-source/candidate-worker.py').read_bytes()
  original=(HERE/'original-fixture-worker.py').read_bytes();marker=b"if __name__ == '__main__': raise SystemExit(main())\n"
  self.assertTrue(generated.startswith(original[:-len(marker)]));self.assertLessEqual(len(generated),128*1024)
  self.assertEqual(w.candidate_profile().PROFILE_SHA,O.sha((HERE/'candidate-source/profile.json').read_bytes()));w._CANDIDATE_ACTIVE=True
  for n in ('cachy-asahi-maintenance-0.1.0-2-any.pkg.tar.xz','cachy-asahi-session-diagnostics-0.1.0-3-any.pkg.tar.xz'):self.assertTrue(w.archive_payload((HERE/'accepted'/n).read_bytes()))
 def test_published_carrier_must_match_all_exact_closed_bytes(self):
  with tempfile.TemporaryDirectory() as folder:
   root=Path(folder)/'data';shutil.copytree(HERE/'accepted',root);(root/'.git').mkdir()
   receipt=O.accepted_carrier(root,Path(folder)/'good');self.assertEqual(receipt['source'],'08638af367190fb437c04c5f460703388dc19c78')
   self.assertEqual(receipt['bytes'],453417)
   path=root/'maintenance.NOTICE';path.write_bytes(path.read_bytes()+b'changed')
   with self.assertRaises(ValueError):O.accepted_carrier(root,Path(folder)/'bad')
 def test_manual_identity_rejects_relabelled_source(self):
  e=dict(SOURCE_SHA='a'*40,GITHUB_SHA='a'*40,GITHUB_WORKFLOW_SHA='a'*40,GITHUB_REPOSITORY='Gabriel-Kahen/cachy-asahi',GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_RUN_ATTEMPT='1',GITHUB_RUN_ID='1',GITHUB_WORKFLOW_REF='Gabriel-Kahen/cachy-asahi/.github/workflows/native-arm-build.yml@refs/heads/review')
  self.assertEqual(O.identity(e)['source_sha'],'a'*40)
  for k,v in (('GITHUB_WORKFLOW_SHA','b'*40),('GITHUB_RUN_ATTEMPT','2'),('GITHUB_EVENT_NAME','push')):
   with self.subTest(key=k),self.assertRaises(ValueError):O.identity(dict(e,**{k:v}))
if __name__=='__main__':unittest.main(verbosity=2)
