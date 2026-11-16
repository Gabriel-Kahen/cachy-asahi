#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Fenced metadata-only root SSH descriptor controls; no SSH or image contents."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
HERE=Path(__file__).resolve().parent


def module(name):
 spec=importlib.util.spec_from_file_location('root_ssh_control_'+name,HERE/(name+'.py'))
 value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


K,I,P,R=map(module,('contracts','image','preboot','root_ssh'))


def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.fork','os.posix_spawn'))or event in ('os.system','fcntl.flock'):
  raise AssertionError('root SSH descriptor metadata-only fence: '+event)
sys.addaudithook(fence)

EXPECTED_POLICY=dict(kind='ROOT_SSH_PREBOOT_V1',parent='root',path='root/.ssh',node_kind='d',mode='700',cap=0,descriptor_max_bytes=1024,late_empty_creation=True,private_contents=False)


def pin(label):
 raw=('MODEL '+label).encode();return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def fixture():
 row=dict(inode=214,type='directory',mode=0o700,uid=0,gid=0,links=2,mtime=1785933495,mtime_ns=123456789,atime=1785933490,atime_ns=987654321,xattrs={})
 scan=dict(nodes={'root':row})
 cert=dict(baseline_certificate=dict(raw=pin('independent raw'),prepared=pin('independent prepared')),runtime_certificate=dict(baseline_namespace_pin=K.json_pin({n:I.stable(v)for n,v in scan['nodes'].items()})))
 packet=dict(nonce='a'*32,Source_lock=pin('Source'),case=pin('actual raw case'))
 raw=K.canonical(P.context(K,cert,packet['Source_lock'],packet['nonce'],packet['case']))
 return packet,cert,scan,raw


class Controls(unittest.TestCase):
 def test_exact_descriptor_and_fixed_context_policy(self):
  packet,cert,scan,raw=fixture();value=R.descriptor(K,I,packet,cert,scan,raw)
  expected=('PERL5423_ROOT_SSH_PREBOOT_V1 '+packet['nonce']+' '+hashlib.sha256(raw).hexdigest()+
   '\nP root 214 2 1785933495 123456789\nA root/.ssh d 700 0\n').encode()
  self.assertEqual(value,expected);self.assertEqual(len(value.splitlines()),3);self.assertLessEqual(len(value),1024)
  self.assertEqual(json.loads(raw)['root_ssh_policy'],EXPECTED_POLICY)
 def test_all_context_provenance_substitutions_refuse(self):
  for field in ('Source_lock','case','nonce','raw','prepared','certificate','namespace','extra','noncanonical'):
   packet,cert,scan,raw=fixture()
   if field in ('Source_lock','case'):packet[field]=pin('substituted')
   elif field=='nonce':packet['nonce']='b'*32
   elif field in ('raw','prepared'):cert['baseline_certificate'][field]=pin('substituted')
   elif field=='certificate':cert['baseline_certificate']['extra']='unreviewed'
   elif field=='namespace':cert['runtime_certificate']['baseline_namespace_pin']=pin('substituted')
   elif field=='extra':raw+=b'X'
   else:raw=raw.replace(b'\n',b'\r\n')
   with self.subTest(field=field),self.assertRaisesRegex(ValueError,'exact packet Source/case/nonce/baseline root SSH context'):
    R.descriptor(K,I,packet,cert,scan,raw)
 def test_literal_nonce_shape_refusals(self):
  for nonce in ('','a'*31,'A'*32,'a'*32+'\nP root 1 2 0 0',True,None):
   packet,cert,scan,raw=fixture();packet['nonce']=nonce
   with self.subTest(nonce=nonce),self.assertRaisesRegex(ValueError,'literal root SSH preboot nonce'):
    R.descriptor(K,I,packet,cert,scan,raw)
 def test_context_policy_substitution_and_unreviewed_fixed_policy_refuse(self):
  packet,cert,scan,raw=fixture()
  for key,value in [('path','root/OTHER'),('mode','755'),('cap',False),('late_empty_creation',False),('private_contents',True)]:
   changed=json.loads(raw);changed['root_ssh_policy'][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):R.descriptor(K,I,packet,cert,scan,K.canonical(changed))
  # A context producer that omits/changes the fixed policy is independently refused.
  original=R._preboot
  self.addCleanup(setattr,R,'_preboot',original)
  for policy in (None,dict(EXPECTED_POLICY,cap=False),dict(EXPECTED_POLICY,extra=True)):
   changed=json.loads(raw)
   if policy is None:changed.pop('root_ssh_policy')
   else:changed['root_ssh_policy']=policy
   R._preboot=lambda changed=changed:types.SimpleNamespace(context=lambda *args:changed)
   with self.subTest(policy=policy),self.assertRaisesRegex(ValueError,'fixed root SSH preboot policy'):
    R.descriptor(K,I,packet,cert,scan,K.canonical(changed))
 def test_root_missing_alias_metadata_type_and_integer_bounds_refuse(self):
  cases=[('type','symlink'),('mode',0o755),('mode',True),('uid',1),('gid',1),('uid',False),('inode',0),('inode',2**32),('inode',True),('links',1),('links',65536),('mtime',-1),('mtime',2**33),('mtime',True),('mtime_ns',None),('mtime_ns',10**9),('xattrs',[])]
  for field,value in cases:
   packet,cert,scan,raw=fixture();scan['nodes']['root'][field]=value
   with self.subTest(field=field,value=value),self.assertRaisesRegex(ValueError,'ordinary bounded certified preboot root directory'):
    R.descriptor(K,I,packet,cert,scan,raw)
  for row in (None,{},False):
   packet,cert,scan,raw=fixture()
   if row is None:scan['nodes'].pop('root')
   else:scan['nodes']['root']=row
   with self.subTest(row=row),self.assertRaises(ValueError):R.descriptor(K,I,packet,cert,scan,raw)
  packet,cert,scan,raw=fixture();scan['nodes']['alias']=scan['nodes'].pop('root')
  with self.assertRaises(ValueError):R.descriptor(K,I,packet,cert,scan,raw)
 def test_existing_selected_path_alias_or_descendants_refuse_without_visiting_rows(self):
  for name in ('root/.ssh','root/.ssh/MODEL','root/.ssh/MODEL/nested'):
   for kind in ('directory','symlink','file'):
    packet,cert,scan,raw=fixture();scan['nodes'][name]=dict(type=kind,mode=0o700,uid=0,gid=0)
    def no_content_access(row):
     if row is scan['nodes'][name]:raise AssertionError('selected subtree row must not be inspected')
     return I.stable(row)
    with self.subTest(name=name,kind=kind),self.assertRaisesRegex(ValueError,'certified preboot root SSH path and descendants absent'):
     R.descriptor(K,types.SimpleNamespace(stable=no_content_access),packet,cert,scan,raw)
 def test_complete_namespace_tamper_refuses(self):
  packet,cert,scan,raw=fixture();scan['nodes']['root/MODEL_UNRELATED']=dict(type='file',mode=0o600,uid=0,gid=0,sha256='0'*64)
  with self.assertRaisesRegex(ValueError,'authenticated complete root SSH preboot namespace'):
   R.descriptor(K,I,packet,cert,scan,raw)
 def test_independent_raw_pin_is_needed_for_directory_times(self):
  packet,cert,scan,raw=fixture();value=R.descriptor(K,I,packet,cert,scan,raw);prior=copy.deepcopy(scan['nodes']['root'])
  scan['nodes']['root'].update(mtime=1794837074,mtime_ns=148000000)
  self.assertEqual(I.stable(scan['nodes']['root']),I.stable(prior))
  self.assertNotEqual(R.descriptor(K,I,packet,cert,scan,raw),value)
 def test_exact_preservation_does_not_mutate_inputs(self):
  packet,cert,before,raw=fixture();after=copy.deepcopy(before);expected=copy.deepcopy((before,after))
  self.assertIsNone(R.preserve(K,before,after));self.assertEqual((before,after),expected)
 def test_final_selected_path_or_descendants_refuse(self):
  for name in ('root/.ssh','root/.ssh/MODEL'):
   for kind in ('directory','symlink','file'):
    packet,cert,before,raw=fixture();after=copy.deepcopy(before);after['nodes'][name]=dict(type=kind)
    with self.subTest(name=name,kind=kind),self.assertRaisesRegex(ValueError,'final certified root SSH path and descendants absent'):
     R.preserve(K,before,after)
  packet,cert,before,raw=fixture();before['nodes']['root/.ssh']=dict(type='directory')
  with self.assertRaisesRegex(ValueError,'certified preboot root SSH path and descendants absent'):R.preserve(K,before,copy.deepcopy(before))
 def test_final_root_identity_links_metadata_xattrs_and_mtime_refuse_drift(self):
  for field,value in [('inode',215),('links',3),('type','symlink'),('mode',0o755),('uid',1),('gid',1),('uid',False),('xattrs',{'MODEL':'changed'}),('mtime',1794837074),('mtime_ns',0)]:
   packet,cert,before,raw=fixture();after=copy.deepcopy(before);after['nodes']['root'][field]=value
   with self.subTest(field=field),self.assertRaisesRegex(ValueError,R.PRESERVATION_ERROR):R.preserve(K,before,after)
  for side in ('before','after'):
   packet,cert,before,raw=fixture();after=copy.deepcopy(before)
   (before if side=='before'else after)['nodes'].pop('root')
   with self.subTest(side=side),self.assertRaises(ValueError):R.preserve(K,before,after)
 def test_wholeboot_atime_and_ctime_are_not_required_or_restored(self):
  packet,cert,before,raw=fixture();after=copy.deepcopy(before);after['nodes']['root'].update(atime=1794837085,atime_ns=440000000,ctime=999)
  expected=copy.deepcopy(after);R.preserve(K,before,after);self.assertEqual(after,expected)
  after['nodes']['root'].pop('atime');after['nodes']['root'].pop('atime_ns');R.preserve(K,before,after)


if __name__=='__main__':unittest.main(verbosity=2)
