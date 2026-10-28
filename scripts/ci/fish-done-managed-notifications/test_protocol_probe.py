# SPDX-License-Identifier: MIT
"""Finite inert controls for the explicitly unaccepted causal probe."""
import ast,base64,hashlib,importlib.util,os,sys,tempfile,unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())
sys.path[:0]=[str(HERE),str(ROOT/'scripts/ci/fish-done-managed-notifications')]
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
S=load('diagnostic_session',HERE/'session.py');C=load('diagnostic_contract',HERE/'contract.py')
class Probe(unittest.TestCase):
 def setUp(self):
  guard=patch('subprocess.Popen',side_effect=AssertionError('actors forbidden'));guard.start();self.addCleanup(guard.stop)
 def test_trace_is_one_client_only_no_global_environment_or_second_actor(self):
  selected={'WAYLAND_DISPLAY':'wayland-1','DBUS_SESSION_BUS_ADDRESS':'owned'};before=dict(selected)
  self.assertEqual(S.protocol_environment(selected,True),dict(selected,WAYLAND_DEBUG='client'));self.assertEqual(selected,before)
  self.assertEqual(S.protocol_environment(selected),selected)
  self.assertIs(type(S.O.diagnostic_policy()['mako_wayland_protocol_probe']),bool)
  with tempfile.TemporaryDirectory() as tmp:
   path=Path(tmp)/'diagnostic-policy.json';policy=S.O.diagnostic_policy()
   with patch.object(S.O,'__file__',str(Path(tmp)/'observation.py')):
    for enabled in (False,True):
     policy['mako_wayland_protocol_probe']=enabled;path.write_text(S.json.dumps(policy))
     self.assertIs(S.O.diagnostic_policy()['mako_wayland_protocol_probe'],enabled)
    for invalid in (None,1,'true'):
     policy['mako_wayland_protocol_probe']=invalid;path.write_text(S.json.dumps(policy))
     with self.assertRaises(ValueError):S.O.diagnostic_policy()
    path.write_text('{"mako_wayland_protocol_probe":false,"mako_wayland_protocol_probe":true}')
    with self.assertRaises(ValueError):S.O.diagnostic_policy()
  for bad in (None,1,'true'):
   with self.assertRaises(ValueError):S.protocol_environment(selected,bad)
  with self.assertRaises(ValueError):S.protocol_environment(dict(selected,WAYLAND_DEBUG='1'))
  text=(HERE/'session.py').read_text();self.assertEqual(text.count("logs,protocol_environment(selected,protocol_probe))"),1)
  self.assertIn("['/usr/bin/mako','--config'",text)
 def test_original_existing_log_bytes_are_joined_only_after_normal_exit(self):
  with tempfile.TemporaryDirectory() as tmp:
   paths=[Path(tmp)/n for n in ('stdout','stderr')];raws=[b'',b'[12.5] -> wl_surface@4.commit()\n[13.0] wl_callback@8.done(42)\n']
   for p,raw in zip(paths,raws):p.write_bytes(raw)
   actor=NS(paths=paths,process=NS(pid=123,returncode=0,poll=lambda:0));value=S.stopped_protocol_trace(actor)
   self.assertEqual(value['pid'],123);self.assertEqual(value['acceptance'],'FORBIDDEN_FOR_THIS_PROBE')
   for stream,raw in zip(value['streams'],raws):
    self.assertEqual(base64.b64decode(stream['raw_base64']),raw);self.assertEqual(stream['sha256'],hashlib.sha256(raw).hexdigest())
   actor.process.poll=lambda:None
   with self.assertRaises(ValueError):S.stopped_protocol_trace(actor)
   actor.process.poll=lambda:0;paths[1].unlink();paths[1].symlink_to(paths[0])
   with self.assertRaises(ValueError):S.stopped_protocol_trace(actor)
   paths[1].unlink();paths[1].write_bytes(b'x'*(256*1024+1))
   with self.assertRaises(ValueError):S.stopped_protocol_trace(actor)
 def test_probe_never_satisfies_normal_acceptance_even_with_pixel_pass(self):
  caller=load('probe_mode_caller',HERE/'ci/caller.py')
  caller.ordinary_mode(dict(mako_wayland_protocol_probe=False))
  for value in (True,None,1,'false'):
   with self.assertRaisesRegex(ValueError,'diagnostic mode'):caller.ordinary_mode(dict(mako_wayland_protocol_probe=value))
  for event in ('mako_wayland_protocol_probe','mako_wayland_protocol_trace'):
   with patch.object(C.managed_contract,'verify_result',side_effect=AssertionError('normal acceptance reached')):
    with self.assertRaisesRegex(ValueError,'diagnostic-only'):C.verify_result([dict(event=event,notification_pixels=dict(status='PASS_PIXEL_PRESENCE_PENDING_READABILITY'))])
 def test_capture_ttl_deadlines_continuation_and_original_cleanup_are_unchanged(self):
  old=(ROOT/'scripts/ci/fish-done-managed-notifications/session.py').read_text();new=(HERE/'session.py').read_text()
  for marker in ('notification_timeout_ms=3000','deadline=time.monotonic()+15',"B.wait_ready(visible,healthy,2",'terminal.continuation(outcome)','until=time.monotonic()+3.5','for logged in (mako,bar,compositor):'):
   self.assertEqual(old.count(marker),new.count(marker));self.assertEqual(new.count(marker),1)
  self.assertGreater(new.index("base.emit('mako_wayland_protocol_trace'"),new.index('lambda p=logged:p.finish()'))
if __name__=='__main__':unittest.main(verbosity=2)
