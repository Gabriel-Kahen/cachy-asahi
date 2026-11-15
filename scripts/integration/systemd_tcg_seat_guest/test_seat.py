# SPDX-License-Identifier: MIT
import copy,importlib.util,json,socket,time,unittest
from pathlib import Path
S=importlib.util.spec_from_file_location('seat_boot_tests',Path(__file__).with_name('boot.py'));B=importlib.util.module_from_spec(S);S.loader.exec_module(B)
def keyboard_record():
 parent='/sys/devices/platform/i8042/serio0/input/input1';leaf=parent+'/event1'
 return {'name':'AT Translated Set 2 keyboard','sysfs_path':leaf,'parent_sysfs_path':parent,'properties':'DEVPATH='+leaf[4:]+'\nDEVNAME=/dev/input/event1\nID_INPUT_KEYBOARD=1\nID_BUS=i8042\nTAGS=:power-switch:\n','parent_properties':'DEVPATH='+parent[4:]+'\nSUBSYSTEM=input\nTAGS=:seat:\nID_PATH_TAG=platform-i8042-serio-0\nID_FOR_SEAT=input-platform-i8042-serio-0\n'}
class Seat(unittest.TestCase):
 def fixture(self):
  props={'Id':'1','Name':'builder','Active':True,'Class':'user','Type':'tty','Remote':False,'Service':'login','TTY':'tty1','Seat':['seat0','/seat0'],'User':[1000,'/user1000']};creds={'UnixUserID':1000,'ProcessID':400}
  return {'status':'PASS_X86_REAL_SEAT_REFERENCE_ONLY','nonce':'abc','user':{'status':'PASS_X86_REAL_SEAT_USER_PROOF_ONLY','uid':1000,'gid':1000,'pid':400,'tty':'/dev/tty1','foreground_VT':'tty1','sd_session_get_seat':{'return':0,'seat':'seat0'},'logind':props,'bus_credentials':creds,'authorization':{'allow_user_interaction':False,'result':[True,False,{}]},'original_policy_sha256':'6002ee5e8fcf3cfdd25fa5425c5dfa879dc293f8b1c69f14b4a8f9259be0b446'},'real_session_corroborated':props,'user_bus_credentials_corroborated':creds,'DRM_cards':['/sys/devices/pci/card0'],'kernel_input_devices':{'event1':keyboard_record()},'stock_udev_seat_rule_sha256':B.INPUT.RULE_SHA256,'VT_screen_pins':[{},{}],'keyboard_delivery':{'release_count':41,'raw_events_or_keycodes_exported':False,'event_grab':False},'observed_stages':{'password_ready_echo_off':True,'profile_entered':True,'PAM_authentication_denied':False}}
 def frame(self,value):return ('SEAT_SESSION_BEGIN abc\r\n'+json.dumps(value)+'\r\nSEAT_SESSION_END abc\r\n').encode()
 def test_seatless_serial_unknown_identity_and_challenge_are_refused(self):
  value=self.fixture();B.parse(self.frame(value),'abc')
  for change in ['seatless','serial','inactive','wrong-pid','wrong-policy','challenge','no-input']:
   v=copy.deepcopy(value)
   if change=='seatless':v['user']['sd_session_get_seat']={'return':-61,'seat':None}
   elif change=='serial':v['user']['tty']='/dev/ttyS0'
   elif change=='inactive':v['real_session_corroborated']['Active']=False
   elif change=='wrong-pid':v['user_bus_credentials_corroborated']['ProcessID']=300
   elif change=='wrong-policy':v['user']['original_policy_sha256']='0'*64
   elif change=='challenge':v['user']['authorization']['result']=[False,True,{}]
   else:v['kernel_input_devices']={}
   with self.subTest(change=change),self.assertRaises(AssertionError):B.parse(self.frame(v),'abc')
 def test_nonce_duplicate_and_large_frame_refused(self):
  frame=self.frame(self.fixture())
  for data,nonce in [(frame,'different'),(frame+frame,'abc'),(b'SEAT_SESSION_BEGIN abc\n'+b'x'*131073+b'\nSEAT_SESSION_END abc','abc')]:
   with self.assertRaises(AssertionError):B.parse(data,nonce)
 def test_only_fixed_ascii_keyboard_sequence(self):
  self.assertEqual(B.key_codes('builder'),list('builder')+['ret']);self.assertEqual(B.key_codes('cafe09'),list('cafe09')+['ret'])
  for text in ['','root\n','A','hello;exit','test_password']:
   with self.assertRaises(ValueError):B.key_codes(text)
 def test_terminal_hold_is_immediate_over_owned_socket(self):
  a,b=socket.socketpair();serial=B.Serial(a,time.monotonic()+10,'abc')
  try:
   b.sendall(b'SEAT_HOLD abc {"failure":{"message":"no VT device"}}\r\n');start=time.monotonic()
   with self.assertRaises(B.SeatHold):serial.until(b'SEAT_SESSION_END abc')
   self.assertLess(time.monotonic()-start,.5)
  finally:a.close();b.close()
 def test_actual_leaf_power_switch_and_tagged_input_parent_are_accepted(self):
  record=keyboard_record();self.assertNotIn(':seat:',record['properties']);self.assertTrue(B.INPUT.is_seat_keyboard(record));B.parse(self.frame(self.fixture()),'abc')
 def test_wrong_or_unrelated_input_parent_is_refused(self):
  for value in ['/sys/devices/platform/i8042/serio0/input/input99','/sys/devices/unrelated/input/input1','/sys/devices/platform/i8042/serio0/input/../input1']:
   record=keyboard_record();record['parent_sysfs_path']=value;self.assertFalse(B.INPUT.is_seat_keyboard(record))
  record=keyboard_record();record['parent_properties']=record['parent_properties'].replace('input1','input99');self.assertFalse(B.INPUT.is_seat_keyboard(record))
 def test_unrelated_tag_wrong_seat_or_wrong_for_seat_are_refused(self):
  for old,new in [('TAGS=:seat:','TAGS=:power-switch:'),('ID_FOR_SEAT=input-platform-i8042-serio-0','ID_FOR_SEAT=unrelated'),('ID_PATH_TAG=platform-i8042-serio-0','ID_PATH_TAG=')]:
   record=keyboard_record();record['parent_properties']=record['parent_properties'].replace(old,new);self.assertFalse(B.INPUT.is_seat_keyboard(record))
  record=keyboard_record();record['parent_properties']+='ID_SEAT=seat1\n';self.assertFalse(B.INPUT.is_seat_keyboard(record))
 def test_frozen_cleanup_handles_ambiguous_create_wait_timeout(self):
  # Exercise the SAME retained implementation, rather than a seat-specific
  # replacement supervisor. Existing detailed tests include signal/report cases.
  import tempfile,subprocess
  from unittest.mock import patch
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);scope=B.B.OwnedContainer('unique',root/'cid','image',{},root,root);scope.submitted=True;scope.cid='a'*64;events=[]
   scope.recover=lambda deadline:{'Id':scope.cid};scope.listing=lambda deadline:None
   def call(argv,deadline):
    events.append(argv)
    if argv[1]=='wait':raise subprocess.TimeoutExpired(argv,1)
    return subprocess.CompletedProcess(argv,0,b'',b'')
   scope.call=call;report={'failure':{'category':'original'}};scope.cleanup(report)
   self.assertTrue(report['owned_container_removed']);self.assertTrue(report['owned_container_absence_verified']);self.assertEqual(report['failure']['category'],'original');self.assertTrue(any('rm'in e for e in events))
if __name__=='__main__':unittest.main()
