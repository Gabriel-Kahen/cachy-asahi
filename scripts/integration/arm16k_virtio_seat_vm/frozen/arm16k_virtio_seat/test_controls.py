#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-fenced pure identity/protocol fixtures; no runtime acceptance evidence."""
import ast,copy,hashlib,importlib.util,json,os,socket,struct,subprocess,sys,termios,time,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def denied(*a,**kw):raise AssertionError('runtime actor forbidden')
for n in ('Popen','run','call','check_output','check_call'):setattr(subprocess,n,denied)
for n in ('fork','forkpty','system','execv','execve','posix_spawn','posix_spawnp'):
 if hasattr(os,n):setattr(os,n,denied)
socket.socket=denied

def load(name):
 s=importlib.util.spec_from_file_location('armseat_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
I=load('input_seat');P=load('protocol');V=load('verify_source');K=P.KEYBOARD
NONCE='a'*32

def words(value):
 out=[]
 while value:out.append(format(value&((1<<64)-1),'x'));value>>=64
 return ' '.join(reversed(out)) or '0'
def keyboard():
 virt='/sys/devices/platform/a003e00.virtio_mmio/virtio2';parent=virt+'/input/input4';leaf=parent+'/event3'
 return {'name':'QEMU Virtio Keyboard','sysfs_path':leaf,'parent_sysfs_path':parent,'virtio_path':virt,'transport_path':str(Path(virt).parent),'virtio_driver':I.INPUT_DRIVER,'transport_driver':I.MMIO_DRIVER,'virtio_subsystem':'/sys/bus/virtio','transport_subsystem':'/sys/bus/platform','virtio_device':'0x0012','phys':'virtio2/input0','input_ids':{'bustype':'0006','vendor':'0627','product':'0001','version':'0001'},'capabilities':{'ev':'120003','key':words(sum(1<<n for n in range(1,232))),'led':'7'},'dev':'13:67','properties':f'DEVPATH={leaf[4:]}\nDEVNAME=/dev/input/event3\nSUBSYSTEM=input\nMAJOR=13\nMINOR=67\nID_INPUT_KEYBOARD=1\n','parent_properties':f'DEVPATH={parent[4:]}\nSUBSYSTEM=input\nID_INPUT_KEYBOARD=1\nTAGS=:seat:\nID_PATH_TAG=platform-a003e00_virtio_mmio\nID_FOR_SEAT=input-platform-a003e00_virtio_mmio\n'}
def gpu():
 k=keyboard();virt='/sys/devices/platform/a003c00.virtio_mmio/virtio1';card=virt+'/drm/card0'
 return {k:v for k,v in k.items() if k in ('virtio_subsystem','transport_subsystem')}|{'virtio_path':virt,'transport_path':str(Path(virt).parent),'virtio_driver':I.GPU_DRIVER,'transport_driver':I.MMIO_DRIVER,'virtio_device':'0x0010','sysfs_path':card,'dev':'226:0','properties':f'DEVPATH={card[4:]}\nSUBSYSTEM=drm\nDEVNAME=/dev/dri/card0\nMAJOR=226\nMINOR=0\nTAGS=:seat:master-of-seat:\n'}
class Identity(unittest.TestCase):
 def test_full_modeled_keyboard(self):self.assertTrue(I.is_seat_keyboard(keyboard()))
 def test_full_modeled_gpu(self):self.assertTrue(I.is_seat_gpu(gpu()))
 def test_name_only_refused(self):self.assertFalse(I.is_seat_keyboard({'name':'QEMU Virtio Keyboard'}))
 def test_wrong_name(self):self.bad('name','AT Translated Set 2 keyboard')
 def test_i8042_driver(self):self.bad('virtio_driver','/sys/bus/serio/drivers/atkbd')
 def test_pci_transport(self):self.bad('transport_driver','/sys/bus/pci/drivers/virtio-pci')
 def test_wrong_transport_parent(self):self.bad('transport_path','/sys/devices/platform/b0000.virtio_mmio')
 def test_wrong_virtio_id(self):self.bad('virtio_device','0x0010')
 def test_wrong_bus_ids(self):
  k=keyboard();k['input_ids']['bustype']='0011';self.assertFalse(I.is_seat_keyboard(k))
 def test_wrong_phys(self):self.bad('phys','isa0060/serio0/input0')
 def test_traversal(self):self.bad('sysfs_path','/sys/devices/platform/../event3')
 def test_wrong_leaf_parent(self):self.bad('parent_sysfs_path','/sys/devices/platform/other/input/input4')
 def test_missing_key(self):
  k=keyboard();k['capabilities']['key']=words(sum(1<<n for n in I.KEYS if n!=28));self.assertFalse(I.is_seat_keyboard(k))
 def test_pointer_events_refused(self):
  k=keyboard();k['capabilities']['ev']='120007';self.assertFalse(I.is_seat_keyboard(k))
 def test_missing_leds(self):
  k=keyboard();k['capabilities']['led']='0';self.assertFalse(I.is_seat_keyboard(k))
 def test_wrong_device_number(self):self.bad('dev','1:3')
 def test_wrong_udev_major(self):
  k=keyboard();k['properties']=k['properties'].replace('MAJOR=13','MAJOR=14');self.assertFalse(I.is_seat_keyboard(k))
 def test_parent_seat_required(self):
  k=keyboard();k['parent_properties']=k['parent_properties'].replace('TAGS=:seat:','TAGS=:power-switch:');self.assertFalse(I.is_seat_keyboard(k))
 def test_nonseat0_refused(self):
  k=keyboard();k['parent_properties']+='ID_SEAT=seat1\n';self.assertFalse(I.is_seat_keyboard(k))
 def test_parent_seat_join_required(self):
  k=keyboard();k['parent_properties']=k['parent_properties'].replace('ID_FOR_SEAT=input-','ID_FOR_SEAT=forged-');self.assertFalse(I.is_seat_keyboard(k))
 def test_duplicate_properties(self):
  k=keyboard();k['properties']+='ID_INPUT_KEYBOARD=1\n';self.assertFalse(I.is_seat_keyboard(k))
 def test_gpu_driver_required(self):
  k=gpu();k['virtio_driver']=I.INPUT_DRIVER;self.assertFalse(I.is_seat_gpu(k))
 def test_gpu_seat_required(self):
  k=gpu();k['properties']=k['properties'].replace('TAGS=:seat:master-of-seat:','TAGS=:uaccess:');self.assertFalse(I.is_seat_gpu(k))
 def test_bitmap_high_words(self):self.assertEqual(I.bitmap('1 0'),1<<64)
 def test_bitmap_bounds(self):
  for x in ('-1','z','1'*17,' '.join(['1']*17),''):
   with self.assertRaises(ValueError):I.bitmap(x)
 def test_wrong_opened_device_closes(self):
  from types import SimpleNamespace
  k=keyboard()
  with patch.object(I,'keyboard_record',return_value=k),patch.object(I.os,'open',return_value=7),patch.object(I.os,'fstat',return_value=SimpleNamespace(st_mode=0o100600,st_rdev=0)),patch.object(I.os,'close') as close:
   with self.assertRaises(ValueError):I.open_verified_keyboard(Path('/sys/class/input/event3'),k)
   close.assert_called_once_with(7)
 def test_valid_open_readonly_nofollow(self):
  from types import SimpleNamespace
  k=keyboard()
  with patch.object(I,'keyboard_record',return_value=k),patch.object(I.os,'open',return_value=7) as opened,patch.object(I.os,'fstat',return_value=SimpleNamespace(st_mode=0o020600,st_rdev=os.makedev(13,67))):
   self.assertEqual(I.open_verified_keyboard(Path('/sys/class/input/event3'),k),7)
   flags=opened.call_args.args[1];self.assertTrue(flags&os.O_NOFOLLOW);self.assertFalse(flags&os.O_WRONLY or flags&os.O_RDWR)
 def test_open_requires_actual_recollection(self):
  k=keyboard()
  with patch.object(I,'keyboard_record',return_value={'name':'changed'}),patch.object(I.os,'open',side_effect=denied),self.assertRaises(ValueError):I.open_verified_keyboard(Path('/sys/class/input/event3'),k)
 def bad(self,k,v):r=keyboard();r[k]=v;self.assertFalse(I.is_seat_keyboard(r))
def proof():
 props={'Id':'1','Name':'builder','Active':True,'Class':'user','Type':'tty','Remote':False,'Service':'login','TTY':'tty1','Seat':['seat0','/org/freedesktop/login1/seat/seat0'],'User':[1000,'/org/freedesktop/login1/user/_1000'],'Leader':123}
 creds={'UnixUserID':1000,'ProcessID':123}
 user={'nonce':NONCE,'status':'PASS_ARM16K_VIRTIO_SEAT_USER_PROOF_ONLY','architecture':'aarch64','pagesize':16384,'uid':1000,'gid':1000,'tty':'/dev/tty1','foreground_VT':'tty1','sd_session_get_seat':{'return':0,'seat':'seat0'},'logind':copy.deepcopy(props),'bus_credentials':copy.deepcopy(creds),'pid':123,'authorization':{'allow_user_interaction':False,'result':[True,False,{}]},'original_policy_sha256':'6002ee5e8fcf3cfdd25fa5425c5dfa879dc293f8b1c69f14b4a8f9259be0b446'}
 g=gpu()
 return {'nonce':NONCE,'status':'PASS_ARM16K_VIRTIO_SEAT_REFERENCE_ONLY','architecture':'aarch64','pagesize':16384,'user':user,'real_session_corroborated':props,'user_bus_credentials_corroborated':creds,'stock_udev_seat_rule_sha256':I.RULE_SHA256,'DRM_cards':[g['sysfs_path']],'virtio_GPU':g,'kernel_input_devices':{'event3':keyboard()},'keyboard_delivery':{'release_count':41,'raw_events_or_keycodes_exported':False,'event_grab':False},'observed_stages':{'password_ready_echo_off':True,'profile_entered':True,'PAM_authentication_denied':False},'VT_screen_pins':[{'stage':'login','sha256':'b'*64},{'stage':'password','sha256':'c'*64}]}
def frame(p):return ('SEAT_SESSION_BEGIN '+NONCE+'\n'+json.dumps(p)+'\nSEAT_SESSION_END '+NONCE+'\n').encode()
class ProofParser(unittest.TestCase):
 def test_complete_modeled_data_not_actual_acceptance(self):self.assertEqual(P.parse(frame(proof()),NONCE)['pagesize'],16384)
 def test_wrong_user_nonce(self):self.bad(['user','nonce'],'b'*32)
 def test_wrong_uid(self):self.bad(['user','uid'],0)
 def test_inactive(self):self.bad(['real_session_corroborated','Active'],False)
 def test_wrong_tty(self):self.bad(['user','tty'],'/dev/ttyAMA0')
 def test_wrong_foreground(self):self.bad(['user','foreground_VT'],'tty2')
 def test_wrong_arch(self):self.bad(['architecture'],'x86_64')
 def test_wrong_pages(self):self.bad(['pagesize'],4096)
 def test_wrong_policy(self):self.bad(['user','original_policy_sha256'],'0'*64)
 def test_wrong_bus_pid(self):self.bad(['user_bus_credentials_corroborated','ProcessID'],124)
 def test_name_only_input(self):self.bad(['kernel_input_devices'],{'event0':{'name':'QEMU Virtio Keyboard'}})
 def test_fake_gpu(self):self.bad(['virtio_GPU','virtio_driver'],I.INPUT_DRIVER)
 def test_missing_ack_count(self):self.bad(['keyboard_delivery','release_count'],40)
 def test_auth_challenge(self):self.bad(['user','authorization','result'],[False,True,{}])
 def test_no_password_readiness(self):self.bad(['observed_stages','password_ready_echo_off'],False)
 def test_wrong_logind_seat(self):self.bad(['user','logind','Seat'],['seat1','/org/freedesktop/login1/seat/seat1'])
 def test_duplicate_frame(self):
  with self.assertRaises(AssertionError):P.parse(frame(proof())*2,NONCE)
 def bad(self,path,value):
  p=proof();dest=p
  for k in path[:-1]:dest=dest[k]
  dest[path[-1]]=value
  with self.assertRaises((AssertionError,ValueError,KeyError)):P.parse(frame(p),NONCE)
class Stream:
 def __init__(self,data):self.data=data
 def settimeout(self,t):pass
 def recv(self,n):out=self.data[:n];self.data=self.data[n:];return out
class Protocol(unittest.TestCase):
 def test_neutral_keyboard_exact(self):self.assertEqual((HERE/'keyboard.py').read_bytes(),(HERE/'frozen/keyboard.py').read_bytes())
 def test_release_fragments_no_keys_retained(self):
  c=K.Releases();raw=b''.join(K.EVENT.pack(0,0,*r) for r in [(1,30,1),(1,30,0),(0,0,0),(1,31,0)])
  out=[]
  for x in raw:out+=c.consume(bytes([x]))
  self.assertEqual(out,[1,2]);self.assertEqual(c.report(),{'release_count':2,'raw_events_or_keycodes_exported':False,'event_grab':False})
 def test_event_abi_64bit(self):self.assertEqual(K.EVENT.size,24)
 def test_release_over46_refuses(self):
  c=K.Releases()
  with self.assertRaises(ValueError):c.consume(K.EVENT.pack(0,0,1,30,0)*47)
 def test_password_echo_phase_required(self):
  a=[0,0,0,termios.ECHO,0,0,[]];self.assertFalse(K.password_ready('login: builder Password:',a,8));a[3]=0;self.assertTrue(K.password_ready('login: builder Password:',a,8));self.assertFalse(K.password_ready('login: builder Password:',a,7))
 def test_live_tty_reopened_after_hangup(self):
  import errno
  with patch.object(K.os,'open',side_effect=OSError(errno.EIO,'hung up')):self.assertEqual(K.tty_attributes(),(None,errno.EIO))
 def test_qmp_make_break(self):self.assertEqual([x['data']['down'] for x in K.key_events('a')],[True,False])
 def test_unsafe_key_refused(self):
  with self.assertRaises(ValueError):K.key_events('shell command')
 def test_ordered_nonce_ack(self):P.Serial(Stream(f'SEAT_KEY_ACK {NONCE} 8\n'.encode()),time.monotonic()+1,NONCE).release(8)
 def test_wrong_nonce_ack(self):self.badack('b'*32,8)
 def test_duplicate_ack(self):self.badack(NONCE,7)
 def test_skipped_ack(self):self.badack(NONCE,9)
 def badack(self,nonce,n):
  with self.assertRaises(AssertionError):P.Serial(Stream(f'SEAT_KEY_ACK {nonce} {n}\n'.encode()),time.monotonic()+1,NONCE).release(8)
 def test_hold_interrupts_no_retry(self):
  with self.assertRaises(P.SeatHold):P.Serial(Stream(f'SEAT_HOLD {NONCE} {{"failure":{{"category":"PermissionError"}}}}\n'.encode()),time.monotonic()+1,NONCE).release(8)
 def test_redaction(self):self.assertNotIn(b'1'*32,P.redact_serial(b'x'+b'1'*32,'1'*32))
 def test_finite_whole_journey_modeled(self):
  lines=[f'SEAT_LOGIN_READY {NONCE} {{"release_count":0}}\n']
  lines += [f'SEAT_KEY_ACK {NONCE} {i}\n' for i in range(1,9)]
  lines += [f'SEAT_PASSWORD_READY {NONCE} {{"echo_disabled":true,"release_count":8}}\n']
  lines += [f'SEAT_KEY_ACK {NONCE} {i}\n' for i in range(9,42)]
  data=''.join(lines).encode()+frame(proof())+f'SEAT_SHELL_RETURNED {NONCE}\n'.encode()
  data+=''.join(f'SEAT_KEY_ACK {NONCE} {i}\n' for i in range(42,47)).encode()
  data+=f'SEAT_LOGOUT_COMPLETE {NONCE} {{"login1_session_removed":true,"new_getty_prompt":true,"release_count":46}}\n'.encode()
  serial=P.Serial(Stream(data),time.monotonic()+1,NONCE);calls=[]
  def rpc(method,args):self.assertEqual(method,'input-send-event');calls.append(len(args['events']))
  result=P.journey(serial,rpc,'1'*32)
  self.assertEqual(calls,[6]+[2]*46);self.assertTrue(result['normal_VT_PAM_logout_observed']);self.assertNotIn('1'*32,repr(result))
 def test_foreign_nonce_shape_refused(self):
  with self.assertRaises(ValueError):P.Serial(Stream(b''),time.monotonic()+1,'abc')
 def test_frame_bound_refused(self):
  with self.assertRaises(ValueError):P.parse(b'x'*(1024**2+1),NONCE)
 def test_bad_credentials_never_call_rpc(self):
  serial=P.Serial(Stream(b''),time.monotonic()+1,NONCE)
  with self.assertRaises(ValueError):P.journey(serial,denied,'arbitrary input')
class Source(unittest.TestCase):
 def test_pins_and_null_actuals(self):self.assertEqual(V.verify()['status'],'READY_SOURCE_ONLY')
 def test_observer_checks_before_loginready(self):
  s=(HERE/'observer.py').read_text();self.assertLess(s.index('open_verified_keyboard'),s.index("frame('SEAT_LOGIN_READY'"));self.assertIn('final_input==input_record',s);self.assertIn('final_gpu==gpu',s)
 def test_observer_no_i8042_namepredicate(self):
  s=(HERE/'observer.py').read_text();self.assertNotIn('AT Translated Set 2 keyboard',s);self.assertNotIn('/dev/ttyS0',s)
 def test_guest_still_proves_pam_and_policy(self):
  s=(HERE/'user_proof.py').read_text()
  for needle in ['tcgetsid(0)==os.getsid(0)',"props['Seat'][0]=='seat0'","os.ttyname(0)=='/dev/tty1'","'Service':'login'","credentials['ProcessID']==os.getpid()","actual=='seat0'","auth[0]is True and auth[1]is False","os.sysconf('SC_PAGE_SIZE')==16384"]:self.assertIn(needle,s)
 def test_no_event_grab_or_policy_override(self):
  for name in ('input_seat.py','observer.py','user_proof.py'):
   s=(HERE/name).read_text();self.assertNotIn('EVIOCGRAB',s);self.assertNotIn('SetSession',s);self.assertNotIn('setfacl',s)
 def test_all_python_syntax(self):
  for p in HERE.rglob('*.py'):ast.parse(p.read_text())
if __name__=='__main__':
 if not (__debug__ and sys.flags.isolated):raise RuntimeError('isolated assertions required')
 unittest.main()
