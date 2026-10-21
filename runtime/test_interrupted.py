# SPDX-License-Identifier: MIT
"""Source/protocol controls only; no host KSM sysfs, VM or passing VM fixture."""
import importlib.util,os,signal,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent));import interrupted as I
S=I.S
class Controls(unittest.TestCase):
 def test_real_owned_SIGTERM_barrier_and_handler_retirement(self):
  incoming,outgoing=os.pipe2(os.O_CLOEXEC);result_in,result_out=os.pipe2(os.O_CLOEXEC);pid=os.fork();reaped=False
  if pid==0:
   try:
    os.close(incoming);os.close(result_in);prior=signal.getsignal(signal.SIGTERM);v=I.checkpoint(outgoing,'a'*32,[],SimpleNamespace(original={'CONTROL_ONLY':0}),time.monotonic()+10);v['prior_handler_restored']=signal.getsignal(signal.SIGTERM)==prior;raw=S.encoded(v);os.write(result_out,raw);os._exit(0)
   except BaseException:os._exit(1)
  os.close(outgoing);os.close(result_out)
  try:
   ready=I.record(incoming,time.monotonic()+5);self.assertEqual(ready['controller']['pid'],pid);self.assertEqual(ready['original'],{'CONTROL_ONLY':0});os.kill(pid,signal.SIGTERM);value=I.record(result_in,time.monotonic()+5);got,status=os.waitpid(pid,0);reaped=True;self.assertEqual((got,os.waitstatus_to_exitcode(status)),(pid,0));self.assertTrue(value.pop('prior_handler_restored'));self.assertEqual(value,dict(signal='SIGTERM',number=15,received=1,point='AFTER_REAL_SHARED_BEFORE_RUN2',handler='EXPLICIT_TEST_BARRIER_ONLY'))
  finally:
   if not reaped:
    try:os.kill(pid,signal.SIGKILL)
    except ProcessLookupError:pass
    os.waitpid(pid,0)
   os.close(incoming);os.close(result_in)
 def test_expired_barrier_refuses_and_restores_handler(self):
  incoming,outgoing=os.pipe();prior=signal.getsignal(signal.SIGTERM)
  try:
   with self.assertRaisesRegex(ValueError,'not received'):I.checkpoint(outgoing,'a'*32,[],SimpleNamespace(original={}),time.monotonic()-1)
   self.assertEqual(signal.getsignal(signal.SIGTERM),prior)
  finally:os.close(incoming);os.close(outgoing)
 def test_guest_guard_precedes_all_sysfs_pipe_or_fork(self):
  with patch.object(S,'Scalars',side_effect=AssertionError('NO_SYSFS')),patch.object(os,'pipe2',side_effect=AssertionError('NO_PIPE')),patch.object(os,'fork',side_effect=AssertionError('NO_ACTOR')):
   with self.assertRaises(ValueError):I.experiment({},-1)
 def test_unknown_duplicate_or_unjoined_capture_refused(self):
  for value in ({},{'profile':I.PROFILE},{'status':'PASS_OWNED_VM_SHARING_UNMERGE_RESTORATION'}):
   with self.assertRaises(ValueError):I.validate(value,'a'*32)
  for rows in ([],[dict(argv=['/usr/bin/python3','-I','-B','/source/interrupted.py','--owned-parent','42'])]*2):
   with self.assertRaises(ValueError):I.command_join(dict(owner_parent=42),rows)
  incoming,outgoing=os.pipe()
  try:
   os.write(outgoing,b'{"x":1,"x":2}\n')
   with self.assertRaisesRegex(ValueError,'duplicate'):I.record(incoming,time.monotonic()+1)
   with patch.object(I.select,'select',side_effect=AssertionError('NO_WAIT')):
    with self.assertRaises(ValueError):I.record(incoming,time.monotonic()-1)
  finally:os.close(incoming);os.close(outgoing)
if __name__=='__main__':unittest.main(verbosity=2)
