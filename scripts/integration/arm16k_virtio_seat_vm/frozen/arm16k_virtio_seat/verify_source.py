#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify pinned project and upstream DATA; never observe host input or run tools."""
import hashlib,json,re,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent

def pin(p):
 if not p.is_file() or p.is_symlink():raise ValueError('ordinary source operand required')
 b=p.read_bytes();return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def verify():
 d=json.loads((HERE/'origin.json').read_text())
 for section in ('frozen_sources','declaration_sources'):
  for name,row in d[section].items():
   path=HERE/name if section=='frozen_sources' else HERE/'data'/name
   if pin(path)!={k:row[k] for k in ('bytes','sha256')}:raise ValueError('pinned source bytes differ')
 declarations()
 if (HERE/'keyboard.py').read_bytes()!=(HERE/'frozen/keyboard.py').read_bytes():raise ValueError('neutral keyboard runtime changed')
 for key in ('actual_kernel_bundle','actual_device_enumeration','Source','ref','actor_selectors'):
  if d[key] is not None:raise ValueError('source-only selectors must stay null')
 delivery=json.loads((HERE/'delivery.lock.json').read_text())
 for name,row in delivery['guest_files'].items():
  if pin(HERE/name)!={k:row[k] for k in ('bytes','sha256')}:raise ValueError('guest delivery source differs')
 required=delivery['required_guest_namespace']
 if required['required_official_provider']!='networkmanager' or required['project_policy_action']!='org.freedesktop.NetworkManager.settings.modify.own' or required['policy_path']!='/usr/share/polkit-1/actions/org.freedesktop.NetworkManager.policy' or required['policy_sha256']!=delivery['original_NM_policy_sha256'] or required['source_xml_copy_or_injection_allowed'] is not False or required['authorization_policy_override_allowed'] is not False or required['actual_provider_closure'] is not None:raise ValueError('genuine official NM provider/action prerequisite required')
 for name,value in delivery.items():
  if name.startswith('actual_') and value is not None:raise ValueError('source delivery must not fabricate actual fields')
 return {'status':'READY_SOURCE_ONLY','kernel_bundle':None,'enumeration':None,'Source':None,'ref':None,'actor_selectors':None,'actual_VM':'NOT RUN','native16K':'NOT RUN','M2':'NOT RUN'}
def declarations():
 def text(n):return (HERE/'data'/n).read_text()
 required={'virtio_ids.h':[r'#define VIRTIO_ID_GPU\s+16',r'#define VIRTIO_ID_INPUT\s+18'],'input.h':[r'#define BUS_VIRTUAL\s+0x06'],'input-event-codes.h':[r'#define EV_SYN\s+0x00',r'#define EV_KEY\s+0x01',r'#define EV_LED\s+0x11',r'#define EV_REP\s+0x14',r'#define KEY_REPLY\s+232'],'qemu-virtio-input-hid.c':['QEMU Virtio Keyboard','BUS_VIRTUAL','0x0627','0x0001','i < KEY_REPLY'],'virtio-bus.c':['0x%04x'],'input-core.c':['__set_bit(EV_SYN, dev->evbit)'],'virtio.Makefile':['obj-$(CONFIG_VIRTIO_INPUT) += virtio_input.o'],'virtgpu.Makefile':['obj-$(CONFIG_DRM_VIRTIO_GPU) += virtio-gpu.o']}
 for name,items in required.items():
  for token in items:
   raw=text(name)
   if token.startswith('#define'):
    if not re.search(token,raw):raise ValueError('pinned numeric declaration differs')
   elif token not in raw:raise ValueError('pinned device/capability source differs')
 return True
if __name__=='__main__':
 if not(__debug__ and sys.flags.isolated):raise RuntimeError('isolated assertions required')
 print(json.dumps(verify(),sort_keys=True))
