#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite Root-owned serial/QMP journey adapter; no socket or actor creation."""
import importlib.util,json,re,socket,time
from pathlib import Path
HERE=Path(__file__).resolve().parent

def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
B=load('arm_seat_frozen_serial',HERE/'frozen/serial.py')
INPUT=load('arm_seat_input',HERE/'input_seat.py')
KEYBOARD=load('arm_seat_keyboard',HERE/'keyboard.py')
class SeatHold(RuntimeError):pass
class Serial(B.Serial):
 def __init__(self,stream,deadline,nonce):
  if not isinstance(nonce,str) or not re.fullmatch('[0-9a-f]{32}',nonce):raise ValueError('exact fresh nonce shape required')
  super().__init__(stream,deadline);self.nonce=nonce
 def release(self,expected):
  old=self.deadline;self.deadline=min(old,time.monotonic()+5)
  try:
   match=self.until(rb'SEAT_KEY_ACK ([0-9a-f]+) ([1-9][0-9]*)\r?\n');assert match.group(1).decode()==self.nonce and int(match.group(2))==expected,'nonce/release order mismatch'
  finally:self.deadline=old
 def until(self,pattern):
  regex=re.compile(pattern)
  while True:
   hold=re.search(rb'(?m)^SEAT_HOLD '+self.nonce.encode()+rb' (\{[^\r\n]*\})\r?\n',bytes(self.data).replace(b'\r',b''))
   if hold:raise SeatHold(str(json.loads(hold.group(1)).get('failure',{}))[:2048])
   match=regex.search(bytes(self.data),self.offset)
   if match:self.offset=match.end();return match
   remaining=self.deadline-time.monotonic()
   if remaining<=0:raise TimeoutError('real-seat serial deadline')
   self.stream.settimeout(min(.5,remaining))
   try:chunk=self.stream.recv(65536)
   except socket.timeout:continue
   if not chunk:raise EOFError('real-seat observer closed')
   self.data.extend(chunk)
   if len(self.data)>1024**2:raise ValueError('real-seat serial byte bound')
def parse(data,nonce):
 if not re.fullmatch('[0-9a-f]{32}',nonce) or len(data)>1024**2:raise ValueError('bounded nonce frame required')
 text=data.decode(errors='replace').replace('\r','');begin='SEAT_SESSION_BEGIN '+nonce+'\n';end='SEAT_SESSION_END '+nonce
 assert text.count(begin)==text.count(end)==1,'missing/duplicate seat frame'
 body=text.split(begin,1)[1].split(end,1)[0].strip();assert len(body)<128*1024
 value=json.loads(body);assert value['status']=='PASS_ARM16K_VIRTIO_SEAT_REFERENCE_ONLY' and value['architecture']=='aarch64' and value['pagesize']==16384 and value['nonce']==nonce
 user=value['user'];assert user['nonce']==nonce;assert user['status']=='PASS_ARM16K_VIRTIO_SEAT_USER_PROOF_ONLY' and user['architecture']=='aarch64' and user['pagesize']==16384 and user['uid']==user['gid']==1000 and user['tty']=='/dev/tty1'and user['foreground_VT']=='tty1'
 assert user['sd_session_get_seat']=={'return':0,'seat':'seat0'}
 for props in [user['logind'],value['real_session_corroborated']]:
  for k,v in {'Name':'builder','Active':True,'Class':'user','Type':'tty','Remote':False,'Service':'login','TTY':'tty1'}.items():assert props[k]==v,(k,props[k])
  assert props['Seat'][0]=='seat0'and props['User'][0]==1000
 assert user['logind']['Id']==value['real_session_corroborated']['Id']
 for credentials in [user['bus_credentials'],value['user_bus_credentials_corroborated']]:assert credentials['UnixUserID']==1000 and credentials['ProcessID']==user['pid']
 assert user['authorization']['allow_user_interaction']is False and user['authorization']['result'][0]is True and user['authorization']['result'][1]is False
 assert user['original_policy_sha256']=='6002ee5e8fcf3cfdd25fa5425c5dfa879dc293f8b1c69f14b4a8f9259be0b446'
 assert value['stock_udev_seat_rule_sha256']==INPUT.RULE_SHA256
 assert len(value['kernel_input_devices'])==1 and any(INPUT.is_seat_keyboard(p)for p in value['kernel_input_devices'].values())
 assert INPUT.is_seat_gpu(value['virtio_GPU']) and value['DRM_cards']==[value['virtio_GPU']['sysfs_path']]
 assert value['keyboard_delivery']=={'release_count':41,'raw_events_or_keycodes_exported':False,'event_grab':False}
 assert value['observed_stages']['password_ready_echo_off']is True and value['observed_stages']['profile_entered']is True and value['observed_stages']['PAM_authentication_denied']is False
 assert len(value['VT_screen_pins'])==2
 return value
def key_codes(text):
 if not re.fullmatch('[a-z0-9]+',text):raise ValueError('only fixed lowercase/hex keyboard text admitted')
 return list(text)+['ret']

def journey(serial,rpc,password):
 """Invoke only fixed QMP methods on Root's already-owned admitted connection."""
 if not re.fullmatch('[0-9a-f]{32}',serial.nonce) or not isinstance(password,str) or not re.fullmatch('[0-9a-f]{32}',password):raise ValueError('fixed nonce/credential shape required')
 released=0
 def keys(codes):
  nonlocal released
  for code in codes:
   rpc('input-send-event',{'events':KEYBOARD.key_events(code)})
   released+=1;serial.release(released)
 chord=[{'type':'key','data':{'down':True,'key':{'type':'qcode','data':k}}}for k in ['ctrl','alt','f1']]
 chord +=[{'type':'key','data':{'down':False,'key':{'type':'qcode','data':k}}}for k in ['f1','alt','ctrl']]
 rpc('input-send-event',{'events':chord})
 ready=serial.until(('SEAT_LOGIN_READY '+serial.nonce+r' (\{[^\r\n]*\})\r?\n').encode());assert json.loads(ready.group(1))=={'release_count':0}
 keys(key_codes('builder'))
 ready=serial.until(('SEAT_PASSWORD_READY '+serial.nonce+r' (\{[^\r\n]*\})\r?\n').encode());assert json.loads(ready.group(1))=={'echo_disabled':True,'release_count':8}
 keys(key_codes(password));serial.until(('SEAT_SESSION_END '+serial.nonce).encode());proof=parse(bytes(serial.data),serial.nonce)
 serial.until(('SEAT_SHELL_RETURNED '+serial.nonce).encode());keys(key_codes('exit'))
 logout=serial.until(('SEAT_LOGOUT_COMPLETE '+serial.nonce+r' (\{[^\r\n]*\})\r?\n').encode());assert json.loads(logout.group(1))=={'login1_session_removed':True,'new_getty_prompt':True,'release_count':46}
 return {'seat':proof,'normal_VT_PAM_logout_observed':True,'keyboard':{'method':'QMP explicit down/up; verified virtio evdev release acknowledgement per character','username_releases':8,'credential_releases':33,'raw_keycodes_exported':False,'credential_values_logged':False}}

def redact_serial(data,password):
 if not isinstance(data,bytes) or len(data)>1024**2 or not isinstance(password,str) or not re.fullmatch('[0-9a-f]{32}',password):raise ValueError('bounded redacted serial required')
 return data.replace(password.encode(),b'[REDACTED TEST PASSWORD]')
