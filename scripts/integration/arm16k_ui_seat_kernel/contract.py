#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite UI-seat successor; reuse frozen RTC guards without altering consumers."""
import importlib.util,json,re,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

# No process, toolchain or upstream-code execution at import.
R=load('ui_frozen_rtc_contract',HERE/'frozen/rtc/contract.py')
pin,checked,values,delta,header,header_fields=R.pin,R.checked,R.values,R.delta,R.header,R.header_fields
IMAGE_FILE_CAP,IMAGE_MEMORY_CAP=R.IMAGE_FILE_CAP,R.IMAGE_MEMORY_CAP

def spec():return json.loads((HERE/'inputs.lock.json').read_text())
def verify():
 origin=json.loads((HERE/'origin.json').read_text())
 for name,ref in origin['files'].items():checked(HERE/name,ref)
 for name,ref in spec()['data'].items():checked(HERE/'data'/name,ref)
 # The reference receipt is retained exactly, not a rewritten acceptance claim.
 checked(HERE/'data/rtc-built.bundle.json',spec()['rtc_bundle_pin'])
 return R.data()
def lock():
 result=R.lock();result.update(operation=spec()['operation'],kernel_release=spec()['kernel_release']);return result

def data():return verify()
def overlay(raw,changes):
 parsed=values(raw)
 if not set(changes)<=parsed.keys():raise ValueError('existing exact symbols required')
 out=[]
 for line in raw.decode('ascii').splitlines(keepends=True):
  match=re.fullmatch(r'(CONFIG_\w+)=(.*)\n|# (CONFIG_\w+) is not set\n',line)
  key=(match[1] or match[3]) if match else None
  if key in changes:
   value=changes[key];line=key+'='+value+'\n' if value!='n' else '# '+key+' is not set\n'
  out.append(line)
 return ''.join(out).encode('ascii')
def changes():return {'CONFIG_VIRTIO_INPUT':'y','CONFIG_LOCALVERSION':spec()['localversion']}
def construct(raw):
 if raw!=data():raise ValueError('exact original baseline required')
 return overlay(R.construct(raw),changes())
def inverse(raw):
 original=data()
 if raw!=construct(original):raise ValueError('changed requested config refused')
 return original

def reference():
 verify();receipt=json.loads((HERE/'data/rtc-built.bundle.json').read_text());raw=(HERE/'data/rtc-built.config').read_bytes()
 if receipt['status']!='BUILT_ONLY_RTC_BOOT_NOT_RUN' or receipt['kernel_release']!='7.1.13-generic16k-managed-gui-rtc1' or receipt['release_accepted'] is not False:raise ValueError('exact historical built-only RTC receipt required')
 checked(HERE/'data/rtc-built.config',receipt['files']['config'])
 R.final_config(raw,receipt['config_proof']['compiler_facts'])
 return raw,receipt

def dependencies():
 raw,_=reference();v=values(raw);text=(HERE/'data/virtio.Kconfig').read_text()
 match=re.search(r'^config VIRTIO_INPUT\n(.*?)(?=^config )',text,re.M|re.S)
 if not match or 'tristate "Virtio input driver"' not in match[1] or re.findall(r'^\s*depends on (.*)$',match[1],re.M)!=['VIRTIO','INPUT'] or re.search(r'^\s*(select|imply) ',match[1],re.M):raise ValueError('exact input dependency/no-select proof differs')
 if 'obj-$(CONFIG_VIRTIO_INPUT) += virtio_input.o' not in (HERE/'data/virtio.Makefile').read_text():raise ValueError('exact input object binding differs')
 for k in ('TTY','ARM64','ARM64_16K_PAGES','INPUT','INPUT_EVDEV','VT','VT_CONSOLE','FRAMEBUFFER_CONSOLE','VIRTIO','VIRTIO_MMIO','OF','SYSFS','DEVTMPFS','DEVTMPFS_MOUNT','DRM','DRM_VIRTIO_GPU','DRM_VIRTIO_GPU_KMS','DRM_FBDEV_EMULATION','DRM_CLIENT_DEFAULT_FBDEV','EXT4_FS','RTC_DRV_PL031','RTC_HCTOSYS'):
  if v.get('CONFIG_'+k)!='y':raise ValueError('held built-in prerequisite differs: '+k)
 for k in ('VIRTIO_INPUT','MODULES','SERIO_I8042','ARM64_4K_PAGES','ARM64_64K_PAGES'):
  if v.get('CONFIG_'+k,'n')!='n':raise ValueError('held disabled prerequisite differs: '+k)
 if 'select INPUT' not in (HERE/'data/tty.Kconfig').read_text() or 'obj-$(CONFIG_VT)' not in (HERE/'data/vt.Makefile').read_text() or 'keyboard.o' not in (HERE/'data/vt.Makefile').read_text():raise ValueError('VT input/keyboard object source differs')
 source=(HERE/'data/virtio-input.c').read_text()
 if 'input_register_device(vi->idev)' not in source:raise ValueError('kernel input registration source differs')
 q=(HERE/'data/qemu-virtio-input.h').read_text();hid=(HERE/'data/qemu-virtio-input-hid.c').read_text();virt=(HERE/'data/qemu-virt.c').read_text()
 if '"virtio-keyboard-device"' not in q or '"QEMU Virtio Keyboard"' not in hid or 'BUS_VIRTUAL' not in hid or '"virtio-mmio"' not in virt or '"virtio-gpu-device"' not in (HERE/'data/qemu-virtio-gpu.h').read_text():raise ValueError('pinned MMIO/input/GPU declaration differs')
 return {'missing_builtin':'CONFIG_VIRTIO_INPUT=y','all_existing_dependencies_held':True,'transport':'virtio-MMIO','seat_runtime':'NOT RUN','kernel_code_execution':'NOT RUN'}

def final_config(raw,compiler_facts):
 ref,receipt=reference();expected_facts=receipt['config_proof']['compiler_facts']
 if compiler_facts!=expected_facts:raise ValueError('exact fifteen RTC compiler facts required; new probes need separate review')
 v=values(raw)
 if any(v.get(k)!=value for k,value in changes().items()):raise ValueError('exact distinct UI-seat builtins/localversion required')
 restored=overlay(raw,{'CONFIG_VIRTIO_INPUT':'n','CONFIG_LOCALVERSION':'"-generic16k-managed-gui-rtc1"'})
 proof=R.final_config(restored,compiler_facts)
 expected=values(overlay(ref,changes()))
 if {k:v.get(k,'n') for k in v.keys()|expected.keys()}!={k:expected.get(k,'n') for k in v.keys()|expected.keys()}:raise ValueError('unprofiled RTC-to-seat drift')
 dependencies();proof.pop('non_rtc_features_unchanged');proof.update(rtc_inverse_verified=True,requested=pin_bytes(construct(data())),feature_delta=delta(data(),construct(data())),rtc_reference=spec()['rtc_bundle_pin'],ui_seat_delta=delta(ref,raw),non_ui_seat_features_unchanged=True)
 return proof

def pin_bytes(raw):
 import hashlib
 return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def bundle(image,config,profile,profile_sha256,actual_tools,commands,started,finished):
 header(image);proof=final_config(config.read_bytes(),profile['compiler_facts']);s=lock()
 return {'schema_version':1,'kind':'ARM16K_UI_SEAT_REFERENCE_KERNEL_BUNDLE_V1','status':'BUILT_ONLY_UI_SEAT_BOOT_NOT_RUN','kernel_release':s['kernel_release'],'files':{'Image':pin(image),'config':pin(config)},'source':{'revision':s['upstream_revision'],'archive':{k:s['archive'][k] for k in ('bytes','sha256')},'original_source':s['original_native_source'],'original_run':s['original_run']},'config_proof':proof,'toolchain':{'mode':profile['mode'],'profile_sha256':profile_sha256,'actual_tools':actual_tools,'original_receipt':pin(HERE/'frozen/rtc/data/original-build-receipt.json'),'same_toolchain':False},'build':{'commands':commands,'actual_started_utc':started,'actual_finished_utc':finished},'guest_boot':'NOT RUN','native16K':'NOT RUN','M2':'NOT RUN','release_accepted':False}

def device_plan(plan):
 checked(HERE/'device-plan.json',spec()['device_plan'])
 expected=json.loads((HERE/'device-plan.json').read_text())
 if plan!=expected:raise ValueError('exact source-only MMIO keyboard/GPU/tty declaration required')
 if plan['actual_tool_device_availability'] is not None or plan['actual_seat0'] is not None:raise ValueError('source plan cannot assert runtime acceptance')
 dependencies()
 return plan
