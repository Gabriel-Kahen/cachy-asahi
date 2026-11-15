#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actor-fenced DATA tests; synthetic fixtures establish no device availability."""
import ast,base64,contextlib,copy,hashlib,importlib.util,json,os,socket,struct,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;s=importlib.util.spec_from_file_location('virtio_contract',HERE/'contract.py');C=importlib.util.module_from_spec(s);s.loader.exec_module(C)

class Controls(unittest.TestCase):
 def test_metadata_exact_snapshot_signature_and_dependency_closure(self):
  v=C.lock();raw=(HERE/'data/official-desc.data').read_text();r={s.splitlines()[0].strip('%'):s.splitlines()[1:]for s in raw.split('\n\n')if s.startswith('%')};self.assertEqual(C.pin(base64.b64decode(r['PGPSIG'][0])),v['package']['signature']);self.assertEqual(r['SHA256SUM'],[v['package']['archive']['sha256']]);self.assertEqual(r['DEPENDS'],['glibc','pixman','libpixman-1.so=0-64','qemu-common=11.1.3-1']);self.assertEqual(v['module']['needed'],['libc.so.6','libpixman-1.so.0'])
 def test_parent_plus_exact_one_package(self):
  p=json.loads((HERE/'data/parent-packages.json').read_bytes());C.parent(p);v=C.lock();n=copy.deepcopy(p);n[v['package']['name']]={'version':v['package']['version'],'desc':{'bytes':1,'sha256':'0'*64}};C.successor(n);self.assertEqual(len(p),178)
  for name in('pixman','qemu-common','glibc'):
   changed=copy.deepcopy(n);changed[name]['version']='wrong'
   with self.subTest(name=name),self.assertRaises(ValueError):C.successor(changed)
 def test_extra_package_refused(self):
  p=json.loads((HERE/'data/parent-packages.json').read_bytes());p['unreviewed']={}
  with self.assertRaises(ValueError):C.parent(p)
 def test_bad_archive_and_signature_byte_pins_refuse(self):
  with tempfile.TemporaryDirectory()as d:
   p=Path(d)/'archive';p.write_bytes(b'bad')
   with self.assertRaises(ValueError):C.archive(p)
   with self.assertRaises(ValueError):C.checked(p,C.lock()['package']['signature'])
 def test_signature_exact_signer_and_temporal_failures(self):
  audit=json.loads((HERE/'data/static-audit.json').read_bytes());raw=(audit['signature_validsig']+'\n').encode();C.signed(raw)
  for changed in(raw.replace(b'991F6E3F',b'091F6E3F'),raw+b'[GNUPG:] EXPKEYSIG key name\n',raw+b'[GNUPG:] REVKEYSIG key name\n',raw+raw):
   with self.assertRaises(ValueError):C.signed(changed)
 def test_missing_gpu_refuses_observed_help(self):
  with self.assertRaises(ValueError):C.devices(b'name "virtio-blk-device"\nname "virtio-keyboard-device"\n')
 def test_device_names_are_exact_not_prefix(self):
  with self.assertRaises(ValueError):C.devices(b'name "virtio-blk-device"\nname "virtio-keyboard-device"\nname "virtio-gpu-device-gl"\n')
 def test_fixture_full_help_only_data_parser(self):
  raw=b'\n'.join(('name "'+n+'"').encode()for n in C.lock()['required_devices']);self.assertEqual(C.devices(raw),dict.fromkeys(C.lock()['required_devices'],True))
 def row(self):
  mounts={('/recipe','/recipe',False),('/result','/receipts',True)};v={'Name':'/owned','Id':'a'*64,'Image':'sha256:'+'b'*64,'Config':{'Labels':{'owner':'test'},'Entrypoint':['/usr/bin/python3'],'Cmd':['-I','-B','/recipe/actor.py','probe']},'HostConfig':dict(NetworkMode='none',CapDrop=['ALL'],CapAdd=None,Privileged=False,Devices=[],Init=False,ReadonlyRootfs=True,Memory=536870912,MemorySwap=536870912,NanoCpus=1000000000,PidsLimit=64,SecurityOpt=['no-new-privileges']),'Mounts':[dict(Type='bind',Source=a,Destination=b,RW=c)for a,b,c in mounts]};return v,mounts
 def check(self,v,m):C.confinement(v,'owned','sha256:'+'b'*64,{'owner':'test'},'probe',m)
 def test_modeled_ownership_and_resource_contract(self):v,m=self.row();self.check(v,m)
 def test_wrong_owner_image_entry_or_mount_refuses(self):
  for change in('name','image','labels','entry','mount'):
   v,m=self.row()
   if change=='name':v['Name']='/other'
   elif change=='image':v['Image']='sha256:'+'c'*64
   elif change=='labels':v['Config']['Labels']={}
   elif change=='entry':v['Config']['Cmd']=['anything']
   else:v['Mounts'][0]['RW']=not v['Mounts'][0]['RW']
   with self.subTest(change=change),self.assertRaises(ValueError):self.check(v,m)
 def test_unbounded_or_privileged_container_refuses(self):
  for key,value in dict(NetworkMode='host',CapDrop=[],CapAdd=['SYS_ADMIN'],Privileged=True,Devices=[{}],Init=True,ReadonlyRootfs=False,Memory=0,MemorySwap=-1,NanoCpus=0,PidsLimit=0,SecurityOpt=[]).items():
   v,m=self.row();v['HostConfig'][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):self.check(v,m)
 def test_elf_architecture_and_bounds_refuse(self):
  for raw in(b'',b'not ELF',b'\x7fELF\x02\x01'+b'\0'*100):
   with self.assertRaises((ValueError,struct.error)):C.elf(raw)
 def test_no_qualified_image_or_missing_device_is_not_acceptance(self):
  v=C.lock();report=dict(kind='ARM16K_VIRTIO_TOOL_IMAGE_V1',status='TOOL_IMAGE_DEVICES_QUALIFIED_NO_GUEST',parent_image_id=v['parent_image_id'],image_id=v['parent_image_id'],required_devices=dict.fromkeys(v['required_devices'],True),owned_containers_absent=True,guest_boot='NOT RUN',image_delta_bytes=1,**{n:v[n]for n in('package','module','qemu','providers')})
  with self.assertRaises(ValueError):C.qualified(report)
  report['image_id']='sha256:'+'1'*64;report['required_devices']['virtio-gpu-device']=False
  with self.assertRaises(ValueError):C.qualified(report)
 def test_all_python_source_parses_without_actor_import(self):
  for p in HERE.glob('*.py'):ast.parse(p.read_bytes())
if __name__=='__main__':
 with contextlib.ExitStack()as stack:
  for module,names in((subprocess,('run','Popen','check_output')),(socket,('socket','create_connection'))):
   for n in names:stack.enter_context(patch.object(module,n,side_effect=AssertionError('actor fenced: '+n)))
  unittest.main()
