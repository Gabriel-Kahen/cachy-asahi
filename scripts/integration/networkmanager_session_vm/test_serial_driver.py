# SPDX-License-Identifier: MIT
"""Real socket transport with the exact recorded standard prompt shape; no VM."""
import importlib.util,json,socket,threading,time,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
D=load('test_session_serial',HERE/'serial_driver.py');B=load('test_frozen_serial',HERE.parent/'systemd_tcg_guest/boot.py')
NONCE='ab'*16;SHA='cd'*32
IDENTITY={'uid':1000,'gid':1000,'tty':'/dev/ttyS0','pid':329,'bus_pid':329,'agent_pid':334,'start_time':2816,'agent_registered':True,'session_active':True,'session_id':'1','agent_sha256':SHA}
def ready(operation='own-create'):
 return ('\nNM_AUTH_READY '+NONCE+' '+json.dumps(IDENTITY)+'\nNM_AUTH_OPERATION '+NONCE+' '+operation+'\n').encode()
def prompt(action=D.OWN,name='NM session TEST user (builder)'):
 # Shape copied from Root's terminal HOLD serial log; actual credentials omitted.
 return ('\x1b[1;31m==== AUTHENTICATING FOR '+action+' ====\r\n\x1b[0mSystem policy prevents modification of personal network settings\r\nAuthenticating as: '+name+'\r\nPassword: ').encode()
class CredentialGate(unittest.TestCase):
 def test_exact_recorded_fragmented_own_prompt_answers_once(self):
  g=D.Gate(NONCE,SHA);data=ready()+prompt()
  answers=[]
  for size in range(1,len(data)+1):answers+=g.observe(data[:size])
  self.assertEqual(answers,['own-create']);self.assertEqual(g.report()['responses'],1);self.assertEqual(g.observe(data),[])
 def test_admin_challenge_never_receives_test_password(self):
  for operation in ['system-delete','foreign-delete']:
   g=D.Gate(NONCE,SHA);self.assertEqual(g.observe(ready(operation)+prompt(D.ADMIN,'root')),[]);self.assertFalse(g.report()['events'][0]['password_sent'])
 def test_unknown_action_or_identity_or_operation_refused(self):
  for operation,action,name in [('own-create',D.OWN,'root'),('own-create',D.ADMIN,'NM session TEST user (builder)'),('own-create','unrecognized.action','NM session TEST user (builder)'),('foreign-delete',D.OWN,'NM session TEST user (builder)')]:
   with self.subTest(operation=operation,action=action,name=name),self.assertRaises(D.RefusedPrompt):D.Gate(NONCE,SHA).observe(ready(operation)+prompt(action,name))
 def test_missing_identity_boundary_and_failed_password_retry(self):
  self.assertEqual(D.Gate(NONCE,SHA).observe(b'login: builder\nPassword: '),[])
  g=D.Gate(NONCE,SHA);data=ready()+prompt();self.assertEqual(g.observe(data),['own-create'])
  with self.assertRaises(D.RefusedPrompt):g.observe(data+b'\n'+prompt())
  bad=dict(IDENTITY,bus_pid=999)
  with self.assertRaises(AssertionError):D.Gate(NONCE,SHA).observe(('NM_AUTH_READY '+NONCE+' '+json.dumps(bad)+'\n').encode()+prompt())
 def test_complete_hold_interrupts_fixed_expected_frame_immediately_over_real_socket(self):
  left,right=socket.socketpair();instances=[];Serial=D.extension(B.Serial,NONCE,b'private-TEST-only',SHA,instances);serial=Serial(left,time.monotonic()+10);sent=[];failures=[]
  frame=('\nNM_SESSION_BEGIN '+NONCE+'\n'+json.dumps({'schema_version':1,'status':'HOLD','failure':{'message':'actual-request-refused'}})+'\nNM_SESSION_END '+NONCE+'\n').encode()
  def guest():
   try:
    for chunk in [ready(),prompt()[:20],prompt()[20:]]:right.sendall(chunk)
    right.settimeout(2);sent.append(right.recv(128));right.sendall(frame)
   except BaseException as e:failures.append(e)
  thread=threading.Thread(target=guest);thread.start();start=time.monotonic()
  try:
   with self.assertRaises(D.JourneyHold):serial.until(b'TCG_LOGIN_END '+NONCE.encode())
   self.assertLess(time.monotonic()-start,2);self.assertEqual(instances[0].gate.journey['status'],'HOLD')
  finally:left.close();right.close();thread.join(3)
  self.assertFalse(failures);self.assertEqual(sent,[b'private-TEST-only\n'])
if __name__=='__main__':unittest.main()
