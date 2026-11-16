#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Fenced preboot provenance DATA controls; no image or actor invocation."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE=Path(__file__).resolve().parent

def module(name):
 spec=importlib.util.spec_from_file_location('preboot_control_'+name,HERE/(name+'.py'));value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

K,I,P,A=map(module,('contracts','image','preboot','actor'))

def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.fork','os.posix_spawn'))or event in('os.system','fcntl.flock'):
  raise AssertionError('preboot provenance DATA-only fence: '+event)
sys.addaudithook(fence)

EXPECTED_POLICY=(
 ('etc/.pwd.lock','f','600',0),('etc/.updated','f','644',4096),
 ('etc/audisp','d','755',0),('etc/audit/plugins.d','d','750',0),
 ('etc/audit/rules.d','d','755',0),('etc/ld.so.cache','f','644',1048576),
 ('etc/os-release','l','777',4096),('etc/udev/hwdb.bin','f','444',16777216),
 ('etc/vconsole.conf','f','644',4096))
PARENTS=('etc','etc/audit','etc/udev')

def pin(label):
 raw=('MODEL '+label).encode();return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def fixture():
 nodes={}
 for i,path in enumerate(PARENTS):
  nodes[path]=dict(inode=4096+i,type='directory',mode=0o755,uid=0,gid=0,links=7-i,mtime=1794708503-i,mtime_ns=123456789+i,atime=1794708403,atime_ns=987654321,xattrs={})
 scan=dict(nodes=nodes)
 namespace=K.json_pin({n:I.stable(v)for n,v in nodes.items()})
 cert=dict(baseline_certificate=dict(raw=pin('independent raw'),prepared=pin('independent prepared')),runtime_certificate=dict(baseline_namespace_pin=namespace))
 packet=dict(nonce='a'*32,Source_lock=pin('Source'),case=pin('actual raw case'))
 context=K.canonical(P.context(K,cert,packet['Source_lock'],packet['nonce'],packet['case']))
 return packet,cert,scan,context

class Controls(unittest.TestCase):
 def test_exact_v2_all_parent_stamps_and_ordered_absence_policy(self):
  packet,cert,scan,raw=fixture();value=P.descriptor(K,I,packet,cert,scan,raw).decode()
  context=K.json_pin(P.context(K,cert,packet['Source_lock'],packet['nonce'],packet['case']))
  expected=f'PERL5423_PREBOOT_ETC_V2 {packet["nonce"]} {context["sha256"]}\n'
  for i,path in enumerate(PARENTS):expected+=f'P {path} {4096+i} {7-i} {1794708503-i} {123456789+i}\n'
  for path,kind,mode,cap in EXPECTED_POLICY:expected+=f'A {path} {kind} {mode} {cap}\n'
  self.assertEqual(value,expected)
  self.assertEqual(len(value.splitlines()),13)
  self.assertLessEqual(len(value),4096)
 def test_context_binds_exact_fixed_policy_and_parent_order(self):
  packet,cert,scan,raw=fixture();context=json.loads(raw)
  self.assertEqual(context['kind'],'PERL5423_PREBOOT_CONTEXT_V2')
  self.assertEqual(context['parents'],list(PARENTS))
  self.assertEqual(context['absence_policy'],[dict(path=p,kind=k,mode=m,cap=c)for p,k,m,c in EXPECTED_POLICY])
  for field in ('parents','absence_policy'):
   changed=copy.deepcopy(context);changed[field].reverse()
   with self.subTest(field=field),self.assertRaisesRegex(ValueError,'exact packet Source/case/nonce/baseline preboot context'):
    P.descriptor(K,I,packet,cert,scan,K.canonical(changed))
 def test_source_case_nonce_certificate_raw_prepared_and_namespace_substitutions_refuse(self):
  for field in('Source_lock','case','nonce','raw','prepared','certificate','namespace','context-extra','context-noncanonical'):
   packet,cert,scan,raw=fixture()
   if field in('Source_lock','case'):packet[field]=pin('substitution')
   elif field=='nonce':packet['nonce']='b'*32
   elif field in('raw','prepared'):cert['baseline_certificate'][field]=pin('substitution')
   elif field=='certificate':cert['baseline_certificate']['extra']='unreviewed'
   elif field=='namespace':cert['runtime_certificate']['baseline_namespace_pin']=pin('substitution')
   elif field=='context-extra':raw+=b'X'
   else:raw=raw.replace(b'\n',b'\r\n')
   with self.subTest(field=field),self.assertRaisesRegex(ValueError,'exact packet Source/case/nonce/baseline preboot context'):
    P.descriptor(K,I,packet,cert,scan,raw)
 def test_each_parent_missing_alias_metadata_and_unbounded_stamp_refusals(self):
  cases=[('type','symlink'),('mode',0o700),('uid',1),('gid',1),('uid',False),('mode',True),('inode',0),('inode',2**32),('links',1),('links',65536),('links',True),('mtime',-1),('mtime',2**33),('mtime',True),('mtime_ns',10**9),('mtime_ns',None)]
  for path in PARENTS:
   for field,value in cases:
    packet,cert,scan,raw=fixture();scan['nodes'][path][field]=value
    with self.subTest(path=path,field=field,value=value),self.assertRaises(ValueError):P.descriptor(K,I,packet,cert,scan,raw)
   packet,cert,scan,raw=fixture();scan['nodes']['alias']=scan['nodes'].pop(path)
   with self.subTest(path=path),self.assertRaises(ValueError):P.descriptor(K,I,packet,cert,scan,raw)
 def test_each_named_path_existing_node_alias_or_descendant_refuses(self):
  for path,kind,mode,cap in EXPECTED_POLICY:
   for existing in ('file','directory','symlink','descendant'):
    packet,cert,scan,raw=fixture()
    key=path+'/unexpected-child'if existing=='descendant'else path
    scan['nodes'][key]=dict(type='file'if existing=='descendant'else existing,mode=0o644,uid=0,gid=0,target_b64='dXNyL2xpYg==',sha256='0'*64)
    with self.subTest(path=path,existing=existing),self.assertRaisesRegex(ValueError,'certified preboot policy path and descendants absent'):
     P.descriptor(K,I,packet,cert,scan,raw)
 def test_complete_namespace_tamper_refuses_even_with_same_parent_stamps(self):
  packet,cert,scan,raw=fixture();scan['nodes']['etc/unreviewed-config']=dict(type='file',mode=0o644,uid=0,gid=0,sha256='0'*64)
  with self.assertRaisesRegex(ValueError,'authenticated complete preboot namespace'):P.descriptor(K,I,packet,cert,scan,raw)
 def test_preboot_stamps_are_not_derived_from_stable_namespace_or_late_clock(self):
  packet,cert,scan,raw=fixture();before=P.descriptor(K,I,packet,cert,scan,raw)
  for path in PARENTS:
   prior=copy.deepcopy(scan);scan['nodes'][path].update(mtime=1794827034,mtime_ns=205988225)
   self.assertEqual(I.stable(scan['nodes'][path]),I.stable(prior['nodes'][path]))
   self.assertNotEqual(P.descriptor(K,I,packet,cert,scan,raw),before)
  # Actual raw authentication remains the prepare/controller caller's prerequisite.
  source=(HERE/'actor.py').read_text()
  self.assertLess(source.index("K.need(K.json_pin({n:I.stable(v)for n,v in scan['nodes'].items()})"),source.index("descriptor=module('preboot').descriptor"))
  self.assertIn('preboot_etc_descriptor=descriptor_pin',source)
 def test_all_parent_final_identity_links_xattrs_and_mtime_drift_refuse(self):
  packet,cert,before,raw=fixture();P.preserve_etc(K,before,copy.deepcopy(before))
  for path in PARENTS:
   for field in ('mtime','mtime_ns','inode','links','mode','uid','gid','type','xattrs'):
    after=copy.deepcopy(before);after['nodes'][path][field]=dict(tampered=True)if field=='xattrs'else 'TAMPERED'
    with self.subTest(path=path,field=field),self.assertRaisesRegex(ValueError,'exact original preboot parent identity metadata and mtime'):
     P.preserve_etc(K,before,after)
   after=copy.deepcopy(before);after['nodes'].pop(path)
   with self.subTest(path=path,missing=True),self.assertRaises(ValueError):P.preserve_etc(K,before,after)
 def test_wholeboot_atime_and_ctime_are_not_new_preservation_requirements(self):
  packet,cert,before,raw=fixture();after=copy.deepcopy(before)
  for path in PARENTS:after['nodes'][path].update(atime=999,atime_ns=1,ctime=888)
  P.preserve_etc(K,before,after)
  for path in PARENTS:after['nodes'][path].pop('atime');after['nodes'][path].pop('atime_ns')
  P.preserve_etc(K,before,after)
 def test_kernel_descriptor_hash_is_joined_to_prepared_manifest(self):
  packet,cert,scan,raw=fixture();digest=K.json_pin({'descriptor':'MODEL'})
  args=A.qemu_argv(dict(nonce=packet['nonce'],baseline_nonce='b'*32,preboot_etc_descriptor=digest,root_ssh_descriptor=digest),dict(cpus=2,guest_memory_bytes=2*1024**3),1794708503)
  append=args[args.index('-append')+1]
  self.assertEqual(append.count('arm16k_perl5423_vm_preboot_etc_sha256='),1)
  self.assertIn(' arm16k_perl5423_vm_preboot_etc_sha256='+digest['sha256']+' ',append)
  self.assertIn('arm16k_perl5423_vm_nonce='+packet['nonce'],append)

if __name__=='__main__':unittest.main(verbosity=2)
