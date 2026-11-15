#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only actual ARM virtio-MMIO identity/capabilities and stock seat tagging."""
import os,re,stat,subprocess
from pathlib import Path,PurePosixPath
RULE_SHA256='b57a64ab6c973d0b734dea808e6caf9a49b40739c7c7649784d09bd6d90c36d3'
INPUT_DRIVER='/sys/bus/virtio/drivers/virtio_input'
GPU_DRIVER='/sys/bus/virtio/drivers/virtio_gpu'
MMIO_DRIVER='/sys/bus/platform/drivers/virtio-mmio'
# Linux evdev codes needed by fixed lowercase/hex login, exit and VT selection.
KEYS={*range(2,12),16,17,18,19,20,21,22,23,24,25,28,29,30,31,32,33,34,35,36,37,38,44,45,46,47,48,49,50,56,59}

def properties(text):
 if not isinstance(text,str) or len(text)>65536:raise ValueError('bounded udev properties required')
 result={}
 for line in text.splitlines():
  if not line:continue
  key,value=line.split('=',1)
  if key in result:raise ValueError('duplicate udev property')
  result[key]=value
 return result

def bitmap(text):
 words=text.strip().split()
 if not 1<=len(words)<=16 or any(not re.fullmatch('[0-9a-f]{1,16}',w) for w in words):raise ValueError('bounded ARM64 sysfs capability bitmap required')
 value=0
 for w in words:value=(value<<64)|int(w,16)
 return value

def canonical(path):
 p=PurePosixPath(path)
 if not p.is_absolute() or '..' in p.parts or '.' in path.split('/') or str(p)!=path or not path.startswith('/sys/devices/platform/'):raise ValueError('canonical platform sysfs path required')
 return p

def chain(record,driver,device):
 virt=canonical(record['virtio_path']);transport=canonical(record['transport_path'])
 if virt.parent!=transport or not re.fullmatch('virtio[0-9]+',virt.name):return False
 if not re.fullmatch(r'[0-9a-f]+\.virtio_mmio',transport.name):return False
 if not modern_features(record.get('virtio_features')):return False
 return record['virtio_driver']==driver and record['transport_driver']==MMIO_DRIVER and record['virtio_device']==device and record['virtio_subsystem']=='/sys/bus/virtio' and record['transport_subsystem']=='/sys/bus/platform'

def is_seat_keyboard(record):
 try:
  if record['name']!='QEMU Virtio Keyboard' or not chain(record,INPUT_DRIVER,'0x0012'):return False
  leaf=canonical(record['sysfs_path']);parent=canonical(record['parent_sysfs_path']);virt=canonical(record['virtio_path'])
  if leaf.parent!=parent or parent.parent.name!='input' or parent.parent.parent!=virt or not re.fullmatch('input[0-9]+',parent.name) or not re.fullmatch('event[0-9]+',leaf.name):return False
  if record['input_ids']!={'bustype':'0006','vendor':'0627','product':'0001','version':'0001'}:return False
  if record['phys']!=virt.name+'/input0':return False
  ev=bitmap(record['capabilities']['ev']);keys=bitmap(record['capabilities']['key']);led=bitmap(record['capabilities']['led'])
  if ev!=sum(1<<n for n in (0,1,17,20)) or any(not(keys>>n&1) for n in KEYS) or led!=7:return False
  if not re.fullmatch('13:[0-9]+',record['dev']):return False
  event=properties(record['properties']);device=properties(record['parent_properties'])
  if event.get('DEVPATH')!=str(leaf)[4:] or event.get('DEVNAME')!='/dev/input/'+leaf.name or event.get('SUBSYSTEM')!='input' or event.get('ID_INPUT_KEYBOARD')!='1':return False
  if (event.get('MAJOR')+':'+event.get('MINOR'))!=record['dev']:return False
  if device.get('DEVPATH')!=str(parent)[4:] or device.get('SUBSYSTEM')!='input' or device.get('ID_INPUT_KEYBOARD')!='1':return False
  if 'seat' not in device.get('TAGS','').split(':') or device.get('ID_SEAT','seat0')!='seat0':return False
  tag=device.get('ID_PATH_TAG','')
  return bool(re.fullmatch('[A-Za-z0-9_-]+',tag)) and device.get('ID_FOR_SEAT')=='input-'+tag
 except (KeyError,TypeError,ValueError):return False

def is_seat_gpu(record):
 try:
  card=canonical(record['sysfs_path']);virt=canonical(record['virtio_path'])
  if not chain(record,GPU_DRIVER,'0x0010') or card.parent.name!='drm' or card.parent.parent!=canonical(record['transport_path']) or record['drm_device_path']!=record['transport_path'] or not re.fullmatch('card[0-9]+',card.name):return False
  p=properties(record['properties'])
  if not re.fullmatch('226:[0-9]+',record['dev']) or p.get('MAJOR','')+':'+p.get('MINOR','')!=record['dev']:return False
  return p.get('DEVPATH')==str(card)[4:] and p.get('SUBSYSTEM')=='drm' and p.get('DEVNAME')=='/dev/dri/'+card.name and 'seat' in p.get('TAGS','').split(':') and p.get('ID_SEAT','seat0')=='seat0'
 except (KeyError,TypeError,ValueError):return False

def read(path,cap=65536):
 with path.open('rb') as f:raw=f.read(cap+1)
 if len(raw)>cap:raise ValueError('bounded sysfs operand required')
 return raw.decode('ascii').strip()
def udev(path):
 r=subprocess.run(['/usr/bin/udevadm','info','--query=property','--path',str(path)],capture_output=True,timeout=5)
 if r.returncode or len(r.stdout)>65536 or len(r.stderr)>8192:raise ValueError('bounded ordinary udev observation failed')
 return r.stdout.decode('ascii')
def actual_chain(virt):
 transport=virt.parent
 return {'virtio_path':str(virt),'transport_path':str(transport),'virtio_driver':str((virt/'driver').resolve(strict=True)),'transport_driver':str((transport/'driver').resolve(strict=True)),'virtio_subsystem':str((virt/'subsystem').resolve(strict=True)),'transport_subsystem':str((transport/'subsystem').resolve(strict=True)),'virtio_device':read(virt/'device',32),'virtio_features':read(virt/'features',512)}
def keyboard_record(path):
 event=path.resolve(strict=True);parent=(path/'device').resolve(strict=True);virt=parent.parent.parent
 row={**actual_chain(virt),'name':read(parent/'name',256),'phys':read(parent/'phys',256),'sysfs_path':str(event),'parent_sysfs_path':str(parent),'input_ids':{k:read(parent/'id'/k,32) for k in ('bustype','vendor','product','version')},'capabilities':{k:read(parent/'capabilities'/k,2048) for k in ('ev','key','led')},'dev':read(event/'dev',32),'properties':udev(event),'parent_properties':udev(parent)}
 return row
def gpu_record(path):
 card=path.resolve(strict=True);transport=(path/'device').resolve(strict=True)
 # DRM is allocated on vdev->dev.parent (MMIO), not on the virtio child.
 matches=[]
 for child in transport.glob('virtio[0-9]*'):
  try:row=actual_chain(child.resolve(strict=True))
  except (OSError,ValueError):continue
  if chain(row,GPU_DRIVER,'0x0010'):matches.append(row)
 if len(matches)!=1:raise ValueError('exact single genuine GPU child of DRM MMIO parent required')
 return {**matches[0],'sysfs_path':str(card),'drm_device_path':str(transport),'dev':read(card/'dev',32),'properties':udev(card)}
def choose_keyboard():
 matches=[]
 for path in sorted(Path('/sys/class/input').glob('event[0-9]*')):
  try:row=keyboard_record(path)
  except (OSError,ValueError):continue
  if is_seat_keyboard(row):matches.append((path,row))
 if len(matches)>1:raise ValueError('ambiguous genuine virtio keyboard')
 return matches[0] if matches else None
def choose_gpu():
 matches=[]
 for path in sorted(Path('/sys/class/drm').glob('card[0-9]*')):
  try:row=gpu_record(path)
  except (OSError,ValueError):continue
  if is_seat_gpu(row):matches.append(row)
 if len(matches)>1:raise ValueError('ambiguous genuine virtio GPU')
 return matches[0] if matches else None
def open_verified_keyboard(path,record):
 if path.parent!=Path('/sys/class/input') or not re.fullmatch('event[0-9]+',path.name) or not is_seat_keyboard(record) or keyboard_record(path)!=record:raise ValueError('actual keyboard identity changed before open')
 node=Path('/dev/input')/path.name
 fd=os.open(node,os.O_RDONLY|os.O_NONBLOCK|os.O_CLOEXEC|os.O_NOFOLLOW)
 try:
  st=os.fstat(fd);major,minor=map(int,record['dev'].split(':'))
  if not stat.S_ISCHR(st.st_mode) or os.major(st.st_rdev)!=major or os.minor(st.st_rdev)!=minor or keyboard_record(path)!=record:raise ValueError('opened evdev device/identity differs')
  return fd
 except BaseException:os.close(fd);raise

def modern_features(text):
 # Exact Linux sysfs implementation prints feature0 first; VERSION_1 is bit32.
 return isinstance(text,str) and re.fullmatch('[01]{33,256}',text) is not None and text[32]=='1'

def census():
 """Fixed bounded diagnostic metadata only; no event stream or file contents."""
 rows=[];cards=[]
 devices=sorted(Path('/sys/bus/virtio/devices').glob('virtio[0-9]*'))
 if len(devices)>32:raise ValueError('diagnostic virtio count bound')
 labels={INPUT_DRIVER:'virtio_input',GPU_DRIVER:'virtio_gpu','/sys/bus/virtio/drivers/virtio_blk':'virtio_blk'}
 for path in devices:
  try:
   resolved=path.resolve(strict=True);canonical(str(resolved));device=read(resolved/'device',32);features=read(resolved/'features',512);driver=(resolved/'driver').resolve(strict=False)
   if not re.fullmatch('0x[0-9a-f]{4}',device):raise ValueError('diagnostic device ID format')
   rows.append({'device':path.name,'device_id':device,'version_1_negotiated':modern_features(features),'driver':labels.get(str(driver),'unbound' if not (resolved/'driver').exists() else 'other')})
  except (OSError,ValueError):rows.append({'device':path.name,'category':'UNHANDLED_SYSFS_RECORD'})
 paths=sorted(Path('/sys/class/drm').glob('card[0-9]*'))
 paths=[p for p in paths if re.fullmatch('card[0-9]+',p.name)]
 if len(paths)>8:raise ValueError('diagnostic DRM count bound')
 for path in paths:
  try:
   record=gpu_record(path);props=properties(record['properties'])
   cards.append({'card':path.name,'genuine_mmio_gpu_chain':chain(record,GPU_DRIVER,'0x0010'),'stock_seat_tag':'seat' in props.get('TAGS','').split(':'),'accepted':is_seat_gpu(record)})
  except (OSError,ValueError):cards.append({'card':path.name,'category':'UNHANDLED_OR_UNBOUND_GPU_CHAIN'})
 return {'virtio_count':len(devices),'virtio':rows,'drm_card_count':len(paths),'cards':cards,'typed_keys_exported':False,'credentials_exported':False}
