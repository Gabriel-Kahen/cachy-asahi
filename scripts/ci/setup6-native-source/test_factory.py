#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Complete byte reproduction and original-context/source/refusal controls."""
import argparse,importlib.util,json,os,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;s=importlib.util.spec_from_file_location('_setup6_factory_controls',HERE/'prepare.py');P=importlib.util.module_from_spec(s);s.loader.exec_module(P);CARRIER=EXPECTED=None
class Factory(unittest.TestCase):
 def test_real_isolated_cli_exact73_and_null_authority(self):
  with tempfile.TemporaryDirectory()as t:
   output=Path(t)/'source';r=subprocess.run([sys.executable,'-I','-B',str(HERE/'prepare.py'),'--setup5-carrier',str(CARRIER),'--output',str(output)],capture_output=True,timeout=30);self.assertEqual(r.returncode,0,r.stderr.decode());self.assertEqual(P.files(output),P.files(EXPECTED));v=json.loads(r.stdout);self.assertEqual(v['files'],73);self.assertEqual(v['acceptance'],'NOT_GRANTED');self.assertIsNone(v['actual_run']);self.assertIsNone(v['actual_source']);self.assertEqual((output/'scripts/ci/setup6-native/producer.py').read_bytes(),(EXPECTED/'scripts/ci/setup6-native/producer.py').read_bytes())
 def test_complete44_original_context_and_full_carrier_binding(self):
  p=P.profile();old=P.context(p);self.assertEqual(len(old),44);P.carrier(CARRIER,p,old)
  with tempfile.TemporaryDirectory()as t:
   output=Path(t)/'original';v=P.emit(output,CARRIER,True);self.assertEqual(P.files(output),old);self.assertEqual(v['files'],44)
   self.assertEqual(P.pin(P.read(output/'scripts/ci/setup5-native/test_native.py'))['sha256'],'c38bb9aec7d81d9836dbdcc0e56b5d8aa25946505e9c1619cf8f167b002d4e1f')
 def test_changed_missing_extra_alias_carrier_refuses_without_output(self):
  for change in('changed','missing','extra','alias'):
   with self.subTest(change=change),tempfile.TemporaryDirectory()as t:
    root=Path(t);carrier=root/'carrier';shutil.copytree(CARRIER,carrier,ignore=shutil.ignore_patterns('.git'));p=carrier/'source/cachy-asahi-setup/LICENSE'
    if change=='changed':p.write_bytes(p.read_bytes()+b'drift')
    elif change=='missing':p.unlink()
    elif change=='extra':(carrier/'extra').write_bytes(b'extra')
    else:p.unlink();p.symlink_to('NOTICE')
    output=root/'output'
    with self.assertRaises(ValueError):P.emit(output,carrier)
    self.assertFalse(output.exists())
 def test_support_drift_and_existing_output_refuse(self):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t);support=root/'support';shutil.copytree(HERE,support);p=support/'payload/scripts/ci/setup6-native/producer.py';p.write_bytes(p.read_bytes()+b'\n');output=root/'output'
   with patch.object(P,'HERE',support),self.assertRaises(ValueError):P.emit(output,CARRIER)
   self.assertFalse(output.exists());output.mkdir();(output/'sentinel').write_bytes(b'preserve')
   with self.assertRaises(ValueError):P.emit(output,CARRIER)
   self.assertEqual(P.files(output),{'sentinel':b'preserve'})
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--setup5-carrier',type=Path,required=True);p.add_argument('--expected',type=Path,required=True);a=p.parse_args();CARRIER=a.setup5_carrier.absolute();EXPECTED=a.expected.absolute();unittest.main(argv=[sys.argv[0]],verbosity=2)
