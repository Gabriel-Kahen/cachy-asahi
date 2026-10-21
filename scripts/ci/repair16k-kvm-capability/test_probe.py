# SPDX-License-Identifier: MIT
import importlib.util, os, socket, sys, tempfile, time, unittest
from pathlib import Path
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('capability_probe',Path(__file__).with_name('probe.py'))
P=importlib.util.module_from_spec(spec);spec.loader.exec_module(P)

class Probe(unittest.TestCase):
 def test_command_cannot_attach_media_or_start_guest(self):
  args=P.command('/usr/bin/qemu-system-aarch64',Path('/tmp/probe-qmp'))
  self.assertIn('-S',args);self.assertEqual(args[args.index('-accel')+1],'kvm')
  self.assertEqual(args[args.index('-nic')+1],'none')
  self.assertTrue({'-kernel','-drive','-blockdev','-netdev','-cdrom','-bios'}.isdisjoint(args))
  self.assertEqual(args[args.index('-m')+1],'128')
 def test_missing_binary_is_unknown(self):
  with patch.object(P.shutil,'which',return_value=None):value=P.probe()
  self.assertEqual(value['status'],'UNKNOWN_QEMU_BINARY_UNAVAILABLE')
  self.assertFalse(value['process_started']);self.assertEqual(value['generic16K'],'NOT_RUN')
 def test_regular_file_is_not_kvm_device(self):
  with tempfile.TemporaryDirectory()as name:
   path=Path(name)/'kvm';path.write_bytes(b'')
   self.assertFalse(P.device(path)['character_device'])
 def test_failed_process_is_reaped_and_never_passes(self):
  # Python rejects QEMU options; this starts no VM and tests the failure path.
  with patch.object(P.shutil,'which',return_value=sys.executable):value=P.probe()
  self.assertEqual(value['status'],'KVM_UNAVAILABLE_OR_PROBE_FAILED_DATA_ONLY')
  self.assertTrue(value['process']['direct_child_reaped'])
  self.assertTrue(value['process']['group_absence_verified'])
 def test_qmp_finite_response(self):
  left,right=socket.socketpair()
  try:
   right.sendall(b'{"QMP":{}}\n');self.assertEqual(P.QMP(left,time.monotonic()+1).row(),{'QMP':{}})
  finally:left.close();right.close()
if __name__=='__main__':unittest.main()
