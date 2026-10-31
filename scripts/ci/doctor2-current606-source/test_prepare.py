#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-only controls; no producer, package, GPG or native execution."""
import argparse,importlib.util,json,os,shutil,tempfile,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('doctor_source_factory',HERE/'prepare.py');P=importlib.util.module_from_spec(s);s.loader.exec_module(P)
PREDECESSOR=None
REAL27=None
class SourceFactory(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.out=self.root/'out'
 def test_default_exact353_and_unbound(self):
  fact=P.prepare(PREDECESSOR,self.out);self.assertEqual({n:P.pin(b)for n,b in P.files(self.out).items()},P.profile()['views']['default']['files']);self.assertEqual(fact['files'],353)
  for k in('actual_source','actual_ref','actual_run'):self.assertIsNone(fact[k])
  self.assertEqual(fact['acceptance'],'NOT_GRANTED')
 def test_selected_exact353_with_same_predecessor(self):
  fact=P.prepare(PREDECESSOR,self.out,selected=True);self.assertEqual({n:P.pin(b)for n,b in P.files(self.out).items()},P.profile()['views']['selected']['files']);self.assertEqual(fact['view'],'selected')
 def test_changed_predecessor_refused_before_output(self):
  copied=self.root/'before';shutil.copytree(PREDECESSOR,copied);leaf=next(iter(P.profile()['predecessor']['files']));(copied/leaf).write_bytes(b'changed')
  with self.assertRaisesRegex(ValueError,'complete genuine'):P.prepare(copied,self.out)
  self.assertFalse(self.out.exists())
 def test_extra_predecessor_leaf_refused(self):
  copied=self.root/'before';shutil.copytree(PREDECESSOR,copied);(copied/'extra').write_bytes(b'extra')
  with self.assertRaisesRegex(ValueError,'complete genuine'):P.prepare(copied,self.out)
  self.assertFalse(self.out.exists())
 def test_profile_tamper_refused_before_output(self):
  old=P.HERE;altered=self.root/'authority';altered.mkdir();(altered/'source.json').write_bytes((HERE/'source.json').read_bytes()+b' ');P.HERE=altered
  try:
   with self.assertRaisesRegex(ValueError,'whole frozen'):P.prepare(PREDECESSOR,self.out)
   self.assertFalse(self.out.exists())
  finally:P.HERE=old
 def test_symlink_hardlink_fifo_refused_without_block(self):
  real=self.root/'real';real.write_bytes(b'ordinary');link=self.root/'alias';link.symlink_to(real)
  with self.assertRaises(OSError):P.ordinary(link)
  link.unlink();os.link(real,link)
  with self.assertRaisesRegex(ValueError,'single-link'):P.ordinary(real)
  fifo=self.root/'pipe';os.mkfifo(fifo)
  with self.assertRaisesRegex(ValueError,'ordinary'):P.ordinary(fifo)
 def test_existing_output_preserved(self):
  self.out.mkdir();(self.out/'sentinel').write_bytes(b'held')
  with self.assertRaisesRegex(ValueError,'fresh disjoint'):P.prepare(PREDECESSOR,self.out)
  self.assertEqual((self.out/'sentinel').read_bytes(),b'held')
 def test_selected_requires_boolean(self):
  with self.assertRaisesRegex(ValueError,'explicit selected'):P.prepare(PREDECESSOR,self.out,selected=1)
  self.assertFalse(self.out.exists())
class Real27Factory(unittest.TestCase):
 def setUp(self):
  if REAL27 is None:self.skipTest("--real27-predecessor-root required")
  SourceFactory.setUp(self)
 def test_real27_exact361_counter_and_all357_held(self):
  fact=P.prepare_real27(REAL27,self.out);v=P.profile()['real27'];self.assertEqual({n:P.pin(b)for n,b in P.files(self.out).items()},v['files']);self.assertEqual(fact['acceptance'],'NOT_GRANTED');self.assertIsNone(fact['actual_run'])
  name='scripts/ci/current606-doctor2-closed-owner/owner.py';old=(REAL27/name).read_text();new=(self.out/name).read_text();self.assertEqual(new.replace("installed_controls=27 if e['selected_version']=='0.2.0-1'else 0","installed_controls=24 if e['selected_version']=='0.2.0-1'else 0",1),old)
  self.assertEqual(len([n for n in v['files']if v['files'][n]==v['predecessor']['files'][n]]),357)
 def test_real27_drift_and_extra_refused_before_output(self):
  copied=self.root/'before';shutil.copytree(REAL27,copied);name=next(iter(P.profile()['real27']['files']));held=(copied/name).read_bytes();(copied/name).write_bytes(b'drift')
  with self.assertRaisesRegex(ValueError,'complete genuine nullfd361'):P.prepare_real27(copied,self.out)
  self.assertFalse(self.out.exists());(copied/name).write_bytes(held);(copied/'extra').write_bytes(b'extra')
  with self.assertRaisesRegex(ValueError,'complete genuine nullfd361'):P.prepare_real27(copied,self.out)
  self.assertFalse(self.out.exists())
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--predecessor-root',type=Path,required=True);p.add_argument('--real27-predecessor-root',type=Path);a,rest=p.parse_known_args();REAL27=a.real27_predecessor_root.absolute()if a.real27_predecessor_root else None;PREDECESSOR=a.predecessor_root.absolute();unittest.main(argv=[__file__,*rest])
