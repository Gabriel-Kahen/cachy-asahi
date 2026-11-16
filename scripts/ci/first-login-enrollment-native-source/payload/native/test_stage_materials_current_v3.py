# SPDX-License-Identifier: MIT
"""Fenced staging controls; no real HTTP, process, secret, privilege or native role."""
import copy
import hashlib
import importlib.util
import io
import json
import os
import stat
from pathlib import Path
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('FENCED_material_stager',HERE/'stage_materials_current_v3.py');S=importlib.util.module_from_spec(spec);spec.loader.exec_module(S)
def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock'):
  raise AssertionError('FENCED no operational role: '+event)
sys.addaudithook(fence)

class Controls(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='FENCED-material-staging-');self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
 def model(self):
  now=int(time.time());binding=dict(source='a'*40,ref='refs/heads/codex/MODEL',source_lock=dict(bytes=1,sha256='b'*64))
  d=dict(nonce='c'*64,issued_epoch=now-10,expires_epoch=now-10+7560,capability=dict(allow_material_staging=True),policy=dict(member='policy.json',bytes=1,sha256='d'*64),context_limits=dict(max_context_age_seconds=7560,max_delegation_seconds=7560))
  g=dict(schema=3,kind='ROOT_CURRENT_COMPLETE517_STAGING_V3',issuer='Root',approved=True,**binding,nonce=d['nonce'],policy={k:d['policy'][k]for k in('bytes','sha256')},issued_epoch=now-5,expires_epoch=d['expires_epoch']-1,redirect_urls={},secret_provider='CALLER_ONE_SHOT_EXACT22',scope='COMPLETE517_PUBLIC_DATA_ONLY',storage_parent='/MODEL/cachy-current-material-domain-'+d['nonce'])
  return d,dict(binding=binding),g,dict(material_staging_current_v3=S.PROPOSAL)
 def test_exact_public14_and_held_source_identities(self):
  p=S.public14_profile();self.assertEqual(p['source'],'04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd');self.assertEqual(len(p['files']),18)
  self.assertEqual(p['files']['seed.py']['sha256'],S.PUBLIC_SEED);self.assertEqual(p['files']['index.json']['sha256'],S.PUBLIC_INDEX)
  self.assertEqual(len([n for n in p['files']if n.startswith('inputs/')]),14)
  self.assertEqual(S.PROPOSAL['transport_policy'],dict(fetch_seconds=400,transport_seconds=480,outer_seconds=500,reason='Explicit one-fetch allocation for full retained DATA; no measured latency guarantee'))
  self.assertIsNone(S.PROPOSAL['Root_acceptance'])
 def test_no_ambient_secret_reads_one_shot_and_explicit_cleanup(self):
  values={name:'INERT_MODEL_'+str(n)for n,name in enumerate(S.secret_names())};provider=S.OneShotSecrets(values)
  with patch.dict(os.environ,dict(NEVER_READ_PRIVATE='SENTINEL'),clear=True):
   actual=provider(tuple(S.secret_names()));self.assertIs(actual,values);self.assertNotIn('NEVER_READ_PRIVATE',actual)
  with self.assertRaises(ValueError):provider(tuple(S.secret_names()))
  actual.clear();self.assertEqual(values,{})
  other={name:'INERT'for name in S.secret_names()};provider=S.OneShotSecrets(other);provider.close();self.assertEqual(other,{})
  for bad in ({},dict(other,UNRELATED='NO'),{name:''for name in S.secret_names()}):
   with self.assertRaises(ValueError):S.OneShotSecrets(bad)
 def test_unissued_external_pin_refuses_before_source_or_actor_and_clears_values(self):
  values={name:'INERT'for name in S.secret_names()};provider=S.OneShotSecrets(values)
  with patch.object(S,'selected',side_effect=AssertionError('no program before hash')):
   with self.assertRaises(ValueError):S.stage_materials(source_root=self.root,delegation_raw=b'{}',delegation_sha256='0'*64,context={},grant_raw=b'{}',grant_sha256='0'*64,output=self.root/'out',secret_provider=provider,base_lock={},bootstrap_profile={})
  self.assertEqual(values,{})
 def test_root_grant_whole_pin_schema_and_source_no_extra_authority(self):
  d,c,g,p=self.model();raw=S.encoded(g);self.assertEqual(S.validate_grant(raw,S.pin(raw)['sha256'],d,c,p),g)
  with self.assertRaises(ValueError):S.validate_grant(raw,'0'*64,d,c,p)
  for key,value in [('approved',None),('extra',True),('source','0'*40),('secret_provider','AMBIENT_ENV'),('scope','NATIVE_BUILD')]:
   bad=dict(g);bad[key]=value;raw=S.encoded(bad)
   with self.subTest(key=key),self.assertRaises(ValueError):S.validate_grant(raw,S.pin(raw)['sha256'],d,c,p)
 def test_shared7560_and_context_policy_are_explicit_not_added(self):
  d,c,g,p=self.model()
  for mutate in (lambda:d.update(expires_epoch=d['issued_epoch']+8055),lambda:d['context_limits'].update(max_context_age_seconds=180),lambda:d['capability'].update(allow_material_staging=None)):
   d,c,g,p=self.model();mutate();raw=S.encoded(g)
   with self.assertRaises(ValueError):S.validate_grant(raw,S.pin(raw)['sha256'],d,c,p)
 def test_missing_original_helper_is_named_hold_before_any_run(self):
  p=self.root/S.FAMILY/'profile.json';p.parent.mkdir(parents=True);p.write_bytes(S.encoded(dict(parent_files={})))
  with self.assertRaisesRegex(ValueError,'missing exact Source helper private_seed'):S.verify_helpers(self.root,dict(programs={},materials={}),{})
 def test_descriptor_pins_path_alias_and_empty_source_refuse(self):
  p=self.root/'code.py';p.write_bytes(b'VALUE=1\n');r=dict(member='code.py',**S.pin(p.read_bytes()));self.assertEqual(S.descriptor(self.root,r),p.read_bytes())
  for bad in [dict(r,member='../code.py'),dict(r,sha256='0'*64),dict(r,extra=None)]:
   with self.assertRaises(ValueError):S.descriptor(self.root,bad)
  p.write_bytes(b'')
  with self.assertRaises(ValueError):S.descriptor(self.root,dict(member='code.py',**S.pin(b'')))
 def test_global_allocation_nodes_and_alias_are_bounded(self):
  out=self.root/'owned';out.mkdir();(out/'tiny').write_bytes(b'inert');before={p.name:p.read_bytes()for p in out.iterdir()}
  self.assertEqual(S.census(out,time.monotonic()+10)['nodes'],2);self.assertEqual(before,{p.name:p.read_bytes()for p in out.iterdir()})
  (out/'alias').symlink_to(self.root)
  with self.assertRaises(ValueError):S.census(out,time.monotonic()+10)
 def test_unprovisioned_or_unreported_filesystem_never_waives_bounds(self):
  parent=self.root/('cachy-current-material-domain-'+'a'*64);parent.mkdir(mode=0o700)
  with self.assertRaisesRegex(ValueError,'separate mounted DATA'):S.storage_domain(parent,str(parent),'a'*64,self.root)
  info=SimpleNamespace(st_mode=stat.S_IFDIR|0o700,st_uid=os.getuid(),st_dev=123)
  capacity=SimpleNamespace(f_blocks=8*1024**3//4096,f_frsize=4096,f_files=20000,f_bavail=6*1024**3//4096,f_favail=19000)
  with patch.object(Path,'lstat',return_value=info),patch.object(Path,'is_mount',return_value=True),patch.object(Path,'stat',return_value=SimpleNamespace(st_dev=456)),patch.object(S.os,'statvfs',return_value=capacity):
   self.assertEqual(S.storage_domain(parent,str(parent),'a'*64,self.root)['total_nodes'],20000)
   capacity.f_files=0
   with self.assertRaisesRegex(ValueError,'byte/inode ceilings'):S.storage_domain(parent,str(parent),'a'*64,self.root)
 def test_child_request_wrong_hash_or_duplicate_keys_refuse(self):
  p=self.root/'request';p.write_bytes(b'{}')
  with self.assertRaises(ValueError):S.child_request(p,'0'*64)
  p.write_bytes(b'{"x":1,"x":2}')
  with self.assertRaises(ValueError):S.child_request(p,S.pin(p.read_bytes())['sha256'])
 def test_public_url_credentials_query_http_and_nonstandard_ports_refuse(self):
  for value in ['http://example.invalid/x','https://user:password@example.invalid/x','https://example.invalid:8443/x','https://example.invalid/x?token=NO','https://example.invalid/x#fragment']:
   with self.assertRaises(ValueError):S.public_url(value)
 def response(self,status=200,body=b'public',location=None):
  data=io.BytesIO(body)
  return SimpleNamespace(status=status,read=data.read,getheader=lambda k:location if k=='Location'else str(len(body))if k=='Content-Length'else None)
 def fetch(self,responses,*,body=b'public',aliases=None):
  calls=[];queue=list(responses)
  class Connection:
   def __init__(self,host,port,**kwargs):calls.append((host,port,kwargs));self.row=queue.pop(0)
   def request(self,method,path,headers):
    self.method,self.path,self.headers=method,path,headers
    assert method=='GET'and 'Authorization'not in headers and 'Cookie'not in headers
   def getresponse(self):return self.row
   def close(self):pass
  target=self.root/'download';r=dict(url='https://source.invalid/public',redirect_urls=aliases or [],expected=S.pin(body),output=str(target))
  with patch.object(S.http.client,'HTTPSConnection',Connection):S.download(r)
  return target,calls
 def test_modeled_fetch_exact_body_and_zero_revoked(self):
  target,calls=self.fetch([self.response()]);self.assertEqual(target.read_bytes(),b'public');self.assertEqual(len(calls),1)
  target.unlink();target,calls=self.fetch([self.response(body=b'')],body=b'');self.assertEqual(target.read_bytes(),b'')
 def test_redirect_only_exact_rootlisted_https_urls_and_no_retry(self):
  target,calls=self.fetch([self.response(302,location='https://redirect.invalid/pinned'),self.response()],aliases=['https://redirect.invalid/pinned'])
  self.assertEqual(target.read_bytes(),b'public');self.assertEqual([v[0]for v in calls],['source.invalid','redirect.invalid']);target.unlink()
  with self.assertRaises(ValueError):self.fetch([self.response(302,location='https://UNLISTED.invalid/else')])
 def test_extra_body_wrong_hash_non200_and_existing_target_refuse(self):
  for response in [self.response(body=b'public-extra'),self.response(body=b'WRONG!'),self.response(403)]:
   with self.assertRaises(ValueError):self.fetch([response])
   if (self.root/'download').exists():(self.root/'download').unlink()
  (self.root/'download').write_bytes(b'FOREIGN')
  with self.assertRaises(ValueError):self.fetch([self.response()])
  self.assertEqual((self.root/'download').read_bytes(),b'FOREIGN')
 def test_runner_direct_argv_minimal_secret_environment_natural_retirement(self):
  good=dict(reaped=True,ownership='REAPED',group_census='EMPTY_TWICE',output_complete=True,signals=[],timeout=False,error=None,exit=0)
  order=[];O=SimpleNamespace(prepare=lambda:order.append('prepare'),supervise=lambda *a,**kw:dict(good));R=S.Runner(O,self.root,time.monotonic()+100)
  env={'CACHY_OLD_FOUR_JBIGKIT_01':'INERT_MODEL'};seen=[]
  def spawn(argv,**kw):order.append('spawn');seen.append(dict(kw['env']));return SimpleNamespace(pid=123)
  with patch.object(S.subprocess,'Popen',side_effect=spawn),patch.object(S.os,'waitid',return_value=object()):
   self.assertEqual(R.run(['/usr/bin/python3','MODEL'],15,env=env),b'')
   good['signals']=[15]
   with self.assertRaises(ValueError):R.run(['/usr/bin/python3','MODEL'],15)
  self.assertEqual(order[:2],['prepare','spawn']);self.assertEqual(env,{})
  self.assertEqual(seen[0]['CACHY_OLD_FOUR_JBIGKIT_01'],'INERT_MODEL');self.assertNotIn('CACHY_OLD_FOUR_JBIGKIT_01',seen[1]);self.assertNotIn('INERT_MODEL',json.dumps(R.rows))
  self.assertFalse(list(self.root.glob('command-*')))
  with self.assertRaises(ValueError):R.run(['/bin/sh','-c','NEVER'],15)

if __name__=='__main__':unittest.main()
