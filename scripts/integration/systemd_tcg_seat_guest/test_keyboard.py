# SPDX-License-Identifier: MIT
import importlib.util,json,socket,termios,time,unittest
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('keyboard_order_boot',HERE/'boot.py');B=importlib.util.module_from_spec(s);s.loader.exec_module(B);K=B.KEYBOARD
class Keyboard(unittest.TestCase):
 def test_release_counter_fragments_and_ignores_key_values(self):
  counter=K.Releases();stream=b''.join(K.EVENT.pack(1,2,kind,code,value)for kind,code,value in [(1,30,1),(0,0,0),(1,30,0),(1,31,2),(1,31,0)])
  values=[]
  for byte in stream:values+=counter.consume(bytes([byte]))
  self.assertEqual(values,[1,2]);self.assertEqual(counter.report(),{'release_count':2,'raw_events_or_keycodes_exported':False,'event_grab':False});self.assertEqual(counter.pending,b'')
 def test_password_visible_before_echo_off_or_username_ack_is_not_ready(self):
  attrs=[0,0,0,termios.ECHO,0,0,[]];text='login: builder Password: '
  self.assertFalse(K.password_ready(text,attrs,8));attrs[3]=0
  self.assertFalse(K.password_ready(text,attrs,7));self.assertTrue(K.password_ready(text,attrs,8));self.assertFalse(K.password_ready('login: other Password:',attrs,8))
 def test_hung_up_descriptor_is_closed_and_next_observation_reopens(self):
  import errno
  from unittest.mock import patch
  attrs=[0,0,0,0,0,0,[]]
  with patch.object(K.os,'open',side_effect=[10,11])as opened,patch.object(K.os,'close')as closed,patch.object(K.termios,'tcgetattr',side_effect=[termios.error(errno.EIO,'hung up'),attrs]):
   self.assertEqual(K.tty_attributes(),(None,errno.EIO));self.assertEqual(K.tty_attributes(),(attrs,None));self.assertEqual(opened.call_count,2);self.assertEqual([c.args[0]for c in closed.call_args_list],[10,11])
 def test_only_transient_tty_errors_defer_readiness(self):
  import errno
  from unittest.mock import patch
  for number in [errno.EIO,errno.ENXIO]:
   with patch.object(K.os,'open',side_effect=OSError(number,'not ready')):self.assertEqual(K.tty_attributes(),(None,number))
  with patch.object(K.os,'open',side_effect=PermissionError(errno.EACCES,'denied')),self.assertRaises(PermissionError):K.tty_attributes()
  self.assertFalse(K.password_ready('login: builder Password:',None,8))
 def test_qmp_explicit_down_then_up_only(self):
  events=K.key_events('a');self.assertEqual([e['data']['down']for e in events],[True,False]);self.assertTrue(all(e['type']=='key'and e['data']['key']=={'type':'qcode','data':'a'}for e in events))
  with self.assertRaises(ValueError):K.key_events('unknown')
 def test_exact_ack_consumption_preserves_later_ready_marker(self):
  a,b=socket.socketpair();serial=B.Serial(a,time.monotonic()+10,'abc')
  try:
   b.sendall(b'SEAT_KEY_ACK abc 8\r\nSEAT_PASSWORD_READY abc {"echo_disabled":true,"release_count":8}\r\n');serial.release(8)
   marker=serial.until(rb'SEAT_PASSWORD_READY abc (\{[^\r\n]*\})\r?\n');self.assertEqual(json.loads(marker.group(1)),{'echo_disabled':True,'release_count':8})
  finally:a.close();b.close()
 def test_duplicate_skipped_or_foreign_nonce_ack_refused(self):
  for ack in [b'SEAT_KEY_ACK abc 7\n',b'SEAT_KEY_ACK abc 9\n',b'SEAT_KEY_ACK def 8\n']:
   a,b=socket.socketpair();serial=B.Serial(a,time.monotonic()+10,'abc')
   try:
    b.sendall(ack)
    with self.assertRaises(AssertionError):serial.release(8)
   finally:a.close();b.close()
 def test_pam_hold_interrupts_ack_without_authentication_retry(self):
  a,b=socket.socketpair();serial=B.Serial(a,time.monotonic()+10,'abc')
  try:
   b.sendall(b'SEAT_HOLD abc {"failure":{"category":"PermissionError","message":"PAM denied"}}\n')
   with self.assertRaises(B.SeatHold):serial.release(41)
  finally:a.close();b.close()
if __name__=='__main__':unittest.main()
