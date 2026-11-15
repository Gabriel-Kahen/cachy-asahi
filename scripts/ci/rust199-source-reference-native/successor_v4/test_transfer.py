# SPDX-License-Identifier: MIT
"""FENCED transfer controller DATA models; never executes HTTP, Docker or a role."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import resource
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

HERE=Path(__file__).resolve().parent;ROOT=HERE/'payload'
s=importlib.util.spec_from_file_location('rust_transfer_DATA',ROOT/'hosted/phase_transfer.py');T=importlib.util.module_from_spec(s);s.loader.exec_module(T)


def fence(event,args):
 if event.startswith(('socket.','subprocess.'))or event in('os.system','os.fork','os.exec','os.posix_spawn'):
  raise AssertionError('transfer control attempted an operational role: '+event)
sys.addaudithook(fence)


def natural(exit=0):return dict(natural_exit=True,forced_cleanup=False,retirement='REAPED',group_absent=True,ownership_lost=False,leader_held_until_group_inspection=True,exit_observed_via_waitpid=True,exit=exit)
def pin(path):return dict(local_path=str(path),bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest())


class Commands:
 def __init__(self,image,owner,present=True,mutation=None):
  self.image=image;self.owner=owner;self.present=present;self.tags=[owner['tag']]if present else [];self.mutation=mutation
  self.rows=[];self.events=[];self.deadline=time.monotonic()+20000;self.cancelled=[False];self.cleaning=False;self.on_tick=None
 def __call__(self,argv,timeout=60,check=True):
  assert argv[:len(T.DOCKER)]==T.DOCKER
  args=argv[len(T.DOCKER):];self.events.append(args);out=b'';err=b'';code=0
  if args[:2]==['image','inspect']:
   selected=args[-1]
   if self.present and(selected==self.image or selected in self.tags):
    labels={T.LABEL:self.owner['token'],T.LABEL+'.source':self.owner['source']}
    if self.mutation=='foreign-after-load'and any(e[:2]==['image','load']for e in self.events):labels[T.LABEL]='FOREIGN'
    out=T.encode([dict(Id=self.image,Os='linux',Architecture='arm64',Config=dict(Labels=labels,Volumes=None),RepoTags=self.tags)])
   else:code=1;err=('Error response from daemon: No such image: '+selected+'\n').encode()
  elif args[:2]==['image','save']:
   assert self.present and args[-1]==self.image
   Path(args[args.index('--output')+1]).write_bytes(b'FENCED_IMAGE_NOT_A_DOCKER_ARCHIVE')
  elif args[:2]==['image','load']:
   self.present=True;self.tags=[]
   if self.mutation=='ambiguous-load-failure':
    self.rows.append(dict(lifecycle=natural(1)));raise ValueError('FENCED ambiguous CLI failure after daemon load')
  elif args[:2]==['image','tag']:assert self.present and args[2]==self.image;self.tags.append(args[3])
  elif args[:2]==['image','rm']:assert self.present and args[2]==self.image;self.present=False;self.tags=[]
  else:raise AssertionError('unexpected modeled image command '+str(args))
  self.rows.append(dict(lifecycle=natural(code)));return subprocess.CompletedProcess(argv,code,out,err)


class Response:
 def __init__(self,body,status=200,headers=None):self.body=io.BytesIO(body);self.status=status;self.headers=headers or {}
 def getheader(self,k):return self.headers.get(k)
 def read1(self,size):return self.body.read(size)


class Connection:
 def __init__(self,host,responses,events):self.host=host;self.responses=responses;self.events=events
 def request(self,method,path,headers):self.path=path;self.events.append((self.host,path,headers))
 def getresponse(self):
  value=self.responses[self.path];return value if isinstance(value,Response)else Response(value)
 def close(self):pass


class Controls(unittest.TestCase):
 def fixture(self,base,empty_log=False):
  dispatch=dict(schema='FENCED_NOT_ROOT_ADMISSION',source=dict(sha='f'*40,ref='refs/heads/codex/FENCED',map_sha256='a'*64,approval='b'*64,run=None,job=None),bootstrap=dict(transfer_redirect_hosts=['fenced.blob.core.windows.net']))
  source=dict(dispatch['source'],run='100',job='101');provider=dict(schema=4,status='ACTUAL_PROVIDER_BINDING_ONLY',phase='bootstrap',source=source,run_attempt=1,dispatch_sha256=hashlib.sha256(T.dispatch_bytes(dispatch)).hexdigest(),job_metadata_sha256='d'*64,manual_dispatch=True,readback_required=True,native_acceptance=False)
  owner=T.image_owner(provider);image='sha256:'+'e'*64
  files=[]
  for name in ('material','boot-proof.json','qual-proof.json'):
   path=base/name;path.write_bytes(('FENCED_RAW_PROOF_KEEP_BYTES '+name+' /FENCED/logical-image-root').encode());files.append(pin(path))
  delivered=dict(materials=[dict(files[0],name='FENCED_MATERIAL')],files=dict(llvm_archive=files[0]),receipts=dict(path='/FENCED/not_transferred',sha256='0'*64),bootstrap=dict(cache='/FENCED/cache',carrier='/FENCED/carrier'))
  boot=dict(schema=1,status='PASS_NORMAL_SIGNED_LLVM_IMAGE_DATA',owner=owner,provider_binding=provider,image=image,base_image='sha256:'+'c'*64,rootfs_root='/FENCED/logical-image-root',rootfs_tree_sha256='1'*64,native_acceptance=False,errors=[],files=dict(bootstrap_evidence=files[1]),evidence=files[1]['local_path'])
  qual=dict(schema=4,status='PASS_NATIVE_SOURCE_QUALIFICATION_ONLY',binding=source,dispatch_sha256=provider['dispatch_sha256'],provider_phase_sha256=hashlib.sha256(T.encode(provider)).hexdigest(),image_id=image,rootfs_tree_sha256=boot['rootfs_tree_sha256'],native_acceptance=False,holds_preserved=True,readonly_stage0=dict(paths=['/stage0','/work/build/stage0'],readonly=True,namespace_permissions_verified=True,write_attempts_denied=True,alias_write_attempts_denied=True,attempts=[{'errno':30},{'errno':30}]),probe_receipts=[dict(argv=argv,returncode=0,lifecycle=natural())for argv in T.load('FENCED_probe_vector_DATA',ROOT/'hosted/qualification.py').PROBES],stage0_tree_sha256='2'*64,qualified_llvm_tree_sha256='3'*64,library_cargo_config_sha256='4'*64,source_tree_sha256='5'*64,files=dict(native_qualification=files[2]),proof_path=files[2]['local_path'])
  if empty_log:
   path=base/'probe-0.stderr';path.write_bytes(b'');qual['files']['probe_stderr']=pin(path)
  return dispatch,provider,delivered,boot,qual
 def exported(self,base,empty_log=False):
  source=base/'source';source.mkdir();dispatch,provider,delivered,boot,qual=self.fixture(source,empty_log)
  work=base/'bootstrap-work';work.mkdir();command=Commands(boot['image'],boot['owner'])
  with patch.object(T.resource,'getrlimit',return_value=(-1,-1)),patch.object(T.resource,'setrlimit',lambda *a:None),patch.dict(T.os.environ,{},clear=True):
   out=T.export(ROOT,work,dispatch,provider,delivered,boot,qual,command)
  return dispatch,provider,delivered,boot,qual,out,command
 def import_model(self,base,mutation=None,present=False,empty_log=False):
  d,p,delivered,boot,qual,out,_=self.exported(base,empty_log);bundle=Path(out['directory']);body=io.BytesIO()
  changed=None
  with zipfile.ZipFile(body,'w',compression=zipfile.ZIP_STORED)as z:
   for file in sorted(bundle.rglob('*')):
    if not file.is_file():continue
    raw=file.read_bytes();name=file.relative_to(bundle).as_posix()
    if mutation=='tamper-file'and name.startswith('inputs/')and changed is None:raw=bytes([raw[0]^1])+raw[1:];changed=name
    z.writestr(name,raw)
   if mutation=='extra-file':z.writestr('FENCED_EXTRA',b'UNMAPPED')
   if mutation=='zip-alias':
    info=zipfile.ZipInfo('FENCED_ALIAS');info.create_system=3;info.external_attr=(0o120777)<<16;z.writestr(info,b'/etc/passwd')
  archive=body.getvalue();digest=hashlib.sha256(archive).hexdigest();artifact=dict(id=999,name='rust199-qualified-transfer-v4-100-1',expired=False,size_in_bytes=len(archive),digest='sha256:'+digest,workflow_run=dict(id=100,head_sha='f'*40))
  job=dict(id=101,run_id=100,head_sha='f'*40,status='completed',conclusion='success',name='rust199-bootstrap-v4')
  if mutation=='other-source':artifact['workflow_run']['head_sha']='0'*40
  if mutation=='wrong-job':job['id']=777
  if mutation=='expired':artifact['expired']=True
  responses={'/repos/'+T.REPOSITORY+'/actions/artifacts/999':T.encode(artifact),'/repos/'+T.REPOSITORY+'/actions/jobs/101':T.encode(job),'/repos/'+T.REPOSITORY+'/actions/artifacts/999/zip':archive}
  provider=copy.deepcopy(p);provider['phase']='build';provider['source']['job']='102';work=base/'build-work';work.mkdir()
  args=SimpleNamespace(bootstrap_artifact_id='999',bootstrap_artifact_sha256=digest,bootstrap_job_id='101',bootstrap_manifest_sha256=out['manifest_sha256'])
  if mutation=='wrong-manifest':args.bootstrap_manifest_sha256='0'*64
  if mutation=='wrong-dispatch':d['FENCED']='CHANGED';provider['dispatch_sha256']=hashlib.sha256(T.dispatch_bytes(d)).hexdigest()
  command=Commands(boot['image'],boot['owner'],present=present,mutation=mutation);events=[]
  result=None;error=None
  with patch.object(T,'_connection',side_effect=lambda host,timeout:Connection(host,responses,events)),patch.dict(T.os.environ,{'GH_TOKEN':'FENCED_TOKEN'},clear=True):
   try:result=T.import_phase(ROOT,work,d,provider,args,command)
   except ValueError as exc:error=exc
  return result,error,command,events,work,delivered,boot,qual
 def test_full_export_import_model_preserves_raw_proofs_and_compact_dispatch(self):
  with tempfile.TemporaryDirectory(prefix='FENCED-transfer-DATA-')as temp:
   result,error,command,events,work,delivered,boot,qual=self.import_model(Path(temp));self.assertIsNone(error)
   self.assertEqual(len(events),3);self.assertFalse(result['boot']['base_image']);self.assertTrue(result['boot']['imported_from_bootstrap'])
   self.assertEqual(result['bootstrap_provider']['source']['job'],'101');self.assertEqual(result['boot']['rootfs_root'],'/FENCED/logical-image-root')
   old=Path(qual['files']['native_qualification']['local_path']);new=Path(result['qual']['files']['native_qualification']['local_path']);self.assertNotEqual(old,new);self.assertEqual(old.read_bytes(),new.read_bytes())
   self.assertEqual(result['qual']['proof_path'],str(new));self.assertTrue(any(e[:2]==['image','tag']for e in command.events))
   manifest=T.decode((work/'phase-import/bundle/manifest.json').read_bytes());self.assertEqual(hashlib.sha256(manifest['dispatch_raw'].encode()).hexdigest(),manifest['dispatch_sha256'])
 def test_metadata_source_job_expiry_manifest_or_file_tamper_refuse_before_load(self):
  for mutation in ('other-source','wrong-job','expired','wrong-manifest','tamper-file','wrong-dispatch','extra-file','zip-alias'):
   with self.subTest(mutation=mutation),tempfile.TemporaryDirectory()as temp:
    result,error,command,*_=self.import_model(Path(temp),mutation);self.assertIsNotNone(error);self.assertIsNone(result)
    self.assertFalse(any(e[:2]==['image','load']for e in command.events))
 def test_empty_qualification_log_roundtrip_retains_exact_pin_and_mode(self):
  with tempfile.TemporaryDirectory(prefix='FENCED-empty-log-')as temp:
   result,error,command,*_=self.import_model(Path(temp),empty_log=True);self.assertIsNone(error)
   row=result['qual']['files']['probe_stderr'];path=Path(row['local_path'])
   self.assertEqual(row['bytes'],0);self.assertEqual(row['sha256'],hashlib.sha256(b'').hexdigest());self.assertEqual(path.read_bytes(),b'');self.assertEqual(path.stat().st_mode&0o777,0o444)
   self.assertTrue(any(e[:2]==['image','load']for e in command.events))
   with self.assertRaises(ValueError):T.filepin(path,T.IMAGE_CAP)
 def test_preexisting_image_not_loaded_overwritten_or_removed(self):
  with tempfile.TemporaryDirectory()as temp:
   result,error,command,*_=self.import_model(Path(temp),present=True);self.assertIsNotNone(error)
   self.assertFalse(any(e[:2]in(['image','load'],['image','rm'],['image','tag'])for e in command.events));self.assertTrue(command.present)
 def test_ambiguous_load_failure_recovers_only_exact_owned_image(self):
  with tempfile.TemporaryDirectory()as temp:
   result,error,command,events,work,*_=self.import_model(Path(temp),'ambiguous-load-failure');self.assertIsNotNone(error);self.assertFalse(command.present)
   report=T.decode((work/'phase-import/import.json').read_bytes());self.assertTrue(report['image_retired_after_failure']);self.assertEqual(report['status'],'FAIL')
 def test_foreign_loaded_labels_never_removed_or_tagged(self):
  with tempfile.TemporaryDirectory()as temp:
   result,error,command,events,work,*_=self.import_model(Path(temp),'foreign-after-load');self.assertIsNotNone(error)
   self.assertFalse(any(e[:2]in(['image','tag'],['image','rm'])for e in command.events))
   self.assertIn('cleanup_error',T.decode((work/'phase-import/import.json').read_bytes()))
 def test_file_limit_preserves_soft_and_hard_and_qualification_refuses_promotion(self):
  for previous in ((T.IMAGE_CAP-1,-1),(-1,T.IMAGE_CAP-1),(0,-1)):
   with self.assertRaises(ValueError):T.size_limit(previous,T.IMAGE_CAP)
  self.assertEqual(T.size_limit((-1,-1),T.IMAGE_CAP),T.IMAGE_CAP)
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);d,p,delivered,b,q=self.fixture(root);q['native_acceptance']=True
   with self.assertRaises(ValueError):T.context(ROOT,d,p,b,q)
 def test_http_redirect_never_carries_api_auth_or_exceeds_requests(self):
  with tempfile.TemporaryDirectory()as temp:
   command=SimpleNamespace(deadline=time.monotonic()+100,cancelled=[False],on_tick=None);budget=T.Budget(command,100);events=[]
   responses={'/start':Response(b'',302,{'Location':'https://fenced.blob.core.windows.net/target?secret=FENCED'}),'/target?secret=FENCED':b'DATA'}
   with patch.object(T,'_connection',side_effect=lambda host,timeout:Connection(host,responses,events)):
    T.fetch('https://api.github.com/start',Path(temp)/'data',budget,{'api.github.com','fenced.blob.core.windows.net'},'FENCED_TOKEN',dict(bytes=4,sha256=hashlib.sha256(b'DATA').hexdigest()),cap=4,redirects=3)
   self.assertIn('Authorization',events[0][2]);self.assertNotIn('Authorization',events[1][2])
   budget.requests=[{}]*T.REQUEST_CAP
   with patch.object(T,'_connection',side_effect=AssertionError('connection beyond cap')),self.assertRaises(ValueError):T.fetch('https://api.github.com/start',Path(temp)/'other',budget,{'api.github.com'},'FENCED_TOKEN')
 def test_import_rejects_null_job_ids_and_ungranted_hosts_before_get(self):
  with tempfile.TemporaryDirectory()as temp:
   root=Path(temp);d,p,delivered,b,q=self.fixture(root);p['phase']='build';p['source']['job']='102';d['bootstrap']['transfer_redirect_hosts']=None
   with patch.object(T,'_connection',side_effect=AssertionError('network before Root hosts')),self.assertRaises(ValueError):T.import_phase(ROOT,root,d,p,SimpleNamespace(),Commands(b['image'],b['owner'],False))


if __name__=='__main__':unittest.main()
