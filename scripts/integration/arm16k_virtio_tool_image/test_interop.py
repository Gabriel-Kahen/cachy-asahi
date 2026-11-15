#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure modeled metadata seam against an explicitly supplied Root consumer."""
import argparse,contextlib,copy,hashlib,importlib.util,json,socket,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--consumer',type=Path,required=True);p.add_argument('--consumer-sha256',required=True);a=p.parse_args();raw=a.consumer.read_bytes()
 if hashlib.sha256(raw).hexdigest()!=a.consumer_sha256:raise ValueError('exact explicit consumer body pin required')
 C=load('virtio_producer',HERE/'contract.py');K=load('Root_held_metadata_consumer',a.consumer);v=C.lock()
 class Interop(unittest.TestCase):
  def setUp(self):
   self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.path=Path(self.tmp.name)/'metadata.json';self.image='sha256:'+'1'*64;self.fixture=dict(kind='ARM16K_VIRTIO_TOOL_IMAGE_V1',status='TOOL_IMAGE_DEVICES_QUALIFIED_NO_GUEST',parent_image_id=v['parent_image_id'],image_id=self.image,required_devices=dict.fromkeys(v['required_devices'],True),owned_containers_absent=True,guest_boot='NOT RUN',image_delta_bytes=1,actual_observed_utc='2000-01-01T00:00:00+00:00',device_help={'bytes':1,'sha256':'0'*64},**{n:v[n]for n in('package','module','qemu','providers')})
  def write(self,data):self.path.write_text(json.dumps(data));return dict(qemu_metadata=K.pin(self.path))
  def test_modeled_exact_producer_to_consumer(self):
   d=C.tool_metadata(self.fixture);a=self.write(d)
   with patch.object(K,'IMAGE',self.image):self.assertEqual(K.tool_metadata(self.path,a),d)
  def test_other_image_refuses(self):
   d=C.tool_metadata(self.fixture);a=self.write(d)
   with patch.object(K,'IMAGE','sha256:'+'2'*64),self.assertRaises(ValueError):K.tool_metadata(self.path,a)
  def test_missing_actual_pin_refuses(self):
   d=C.tool_metadata(self.fixture);d['actual_tool_pin']=None;a=self.write(d)
   with patch.object(K,'IMAGE',self.image),self.assertRaises(ValueError):K.tool_metadata(self.path,a)
 with contextlib.ExitStack()as stack:
  for module,names in((subprocess,('run','Popen','check_output')),(socket,('socket','create_connection'))):
   for n in names:stack.enter_context(patch.object(module,n,side_effect=AssertionError('actor fenced')))
  result=unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(Interop))
 return 0 if result.wasSuccessful()else 1
if __name__=='__main__':raise SystemExit(main())
