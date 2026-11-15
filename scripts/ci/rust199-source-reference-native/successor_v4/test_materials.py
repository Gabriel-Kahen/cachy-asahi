# SPDX-License-Identifier: MIT
"""FENCED delivery DATA controls; connections are mocked, no operational fixture."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import struct
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('rust_v4_material_DATA',HERE/'payload/hosted/materials.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)


def fence(event,args):
 if event.startswith(('socket.','subprocess.'))or event in('os.system','os.exec','os.fork','os.posix_spawn'):
  raise AssertionError('material control attempted an operational role: '+event)
sys.addaudithook(fence)


def budget():return m.Budget(SimpleNamespace(cancelled=[False],on_tick=None))
def row(name,body,role='source_audit',container='ZIP',outer=None):return dict(member=name,role=role,name=Path(name).name,**m.pin(body),container=container,outer_member=outer)
def plan():
 out=dict(schema=1,status='ROOT_ADMITTED_FINITE_RUST_MATERIAL_DELIVERY',holds_preserved=True,sources='PINNED_HTTPS')
 for index,kind in enumerate(m.ARTIFACT_CAPS):
  leaves=[row('FENCED/'+m.PACKAGE,b'DATA','llvm_archive')]if kind=='llvm_original'else [dict(member='FENCED/'+name,role='stage0:'+name,name=name,bytes=size,sha256=sha,container='ZIP',outer_member=None)for name,(size,sha)in m.STAGE0.items()]if kind=='stage0_carrier'else [row('FENCED/'+role,b'DATA',role)for role in sorted(m.PROOFS)]
  out[kind]=dict(repository=m.REPOSITORY,id=str(index+1),run='4',job='5',source='f'*40,bytes=100,sha256='a'*64,metadata_sha256='b'*64,job_metadata_sha256='c'*64,redirect_hosts=['fenced.blob.core.windows.net'],members=leaves,accepted_by_root=True)
 return out


class Response:
 def __init__(self,body=b'',status=200,headers=None):self.body=io.BytesIO(body);self.status=status;self.headers=headers or {}
 def getheader(self,name):return self.headers.get(name)
 def read1(self,size):return self.body.read(size)


class Connection:
 def __init__(self,response,events,host):self.response=response;self.events=events;self.host=host
 def request(self,method,path,headers):self.events.append((self.host,method,path,dict(headers)))
 def getresponse(self):return self.response
 def close(self):pass


class Controls(unittest.TestCase):
 def test_null_selectors_refuse_before_any_connection(self):
  for kind in m.ARTIFACT_CAPS:
   value=plan();value[kind]=None
   with patch.object(m,'_connection',side_effect=AssertionError('network before Root selection')):
    with self.assertRaises(ValueError):m.acquire(Path('/FENCED'),Path('/FENCED'),value,SimpleNamespace(cancelled=[False]),'FENCED')
 def test_exact_pins_roles_bodies_and_hosts(self):
  m.validate(plan())
  mutations=[('repository','FOREIGN/repo'),('accepted_by_root',False),('id',None),('job_metadata_sha256',None),('redirect_hosts',['example.com']),('bytes',9*m.GIB)]
  for key,value in mutations:
   p=plan();p['llvm_original'][key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):m.validate(p)
  for kind in ('stage0_carrier','root_proof_carrier'):
   p=plan();p[kind]['members'].pop()
   with self.assertRaises(ValueError):m.validate(p)
  p=plan();p['stage0_carrier']['members'][0]['sha256']='0'*64
  with self.assertRaises(ValueError):m.validate(p)
 def test_redirect_strips_auth_and_retains_exact_body(self):
  with tempfile.TemporaryDirectory()as d:
   target=Path(d)/'artifact.zip';events=[];responses=[Response(status=302,headers={'Location':'https://fenced.blob.core.windows.net/FENCED?secret=not_logged'}),Response(b'FENCED',headers={'Content-Length':'6'})]
   with patch.object(m,'_connection',side_effect=lambda host,timeout:Connection(responses.pop(0),events,host)):
    m.fetch('https://api.github.com/repos/Gabriel-Kahen/cachy-asahi/actions/artifacts/1/zip',target,m.pin(b'FENCED'),budget(),{'api.github.com','fenced.blob.core.windows.net'},'FENCED_TOKEN',redirects=3)
   self.assertEqual(target.read_bytes(),b'FENCED');self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o444)
   self.assertIn('Authorization',events[0][3]);self.assertNotIn('Authorization',events[1][3]);self.assertEqual(target.stat().st_nlink,1)
 def test_redirect_escape_loop_wrong_hash_size_and_encoded_body_refuse(self):
  variants=[Response(status=302,headers={'Location':'http://example.com/a'}),Response(status=302,headers={'Location':'https://api.github.com/FENCED'}),Response(b'WRONG!'),Response(b'FENCEDX'),Response(b'FENCED',headers={'Content-Encoding':'gzip'})]
  for response in variants:
   with tempfile.TemporaryDirectory()as d:
    events=[]
    with patch.object(m,'_connection',side_effect=lambda host,timeout:Connection(response,events,host)):
     with self.assertRaises(ValueError):m.fetch('https://api.github.com/FENCED',Path(d)/'x',m.pin(b'FENCED'),budget(),{'api.github.com'},'FENCED_TOKEN',redirects=1)
 def test_artifact_and_terminal_job_metadata_must_join(self):
  r=plan()['llvm_original'];artifact=dict(id=1,size_in_bytes=100,expired=False,workflow_run=dict(id=4,head_sha='f'*40));job=dict(id=5,run_id=4,head_sha='f'*40,status='completed',conclusion='success')
  for mutation in (None,'expired','source','job'):
   a=copy.deepcopy(artifact);j=copy.deepcopy(job)
   if mutation=='expired':a['expired']=True
   elif mutation=='source':a['workflow_run']['head_sha']='0'*40
   elif mutation=='job':j['run_id']=9
   bodies=[m.encode(a),m.encode(j)];r['metadata_sha256']=hashlib.sha256(bodies[0]).hexdigest();r['job_metadata_sha256']=hashlib.sha256(bodies[1]).hexdigest()
   with tempfile.TemporaryDirectory()as d,patch.object(m,'_connection',side_effect=lambda host,timeout:Connection(Response(bodies.pop(0)),[],host)):
    if mutation is None:m.artifact_metadata(r,budget(),'FENCED',Path(d))
    else:
     with self.assertRaises(ValueError):m.artifact_metadata(r,budget(),'FENCED',Path(d))
 def test_zip_only_selected_ordinary_whole_pinned_files(self):
  with tempfile.TemporaryDirectory()as d:
   root=Path(d);archive=root/'artifact.zip';out=root/'out';out.mkdir()
   with zipfile.ZipFile(archive,'w')as z:z.writestr('FENCED/leaf',b'DATA');z.writestr('FENCED/unselected',b'UNSELECTED')
   result=m.extract_zip(archive,[row('FENCED/leaf',b'DATA')],out,budget());self.assertEqual(result['source_audit']['sha256'],hashlib.sha256(b'DATA').hexdigest());self.assertEqual({p.name for p in out.iterdir()},{'leaf'})
 def test_zip_alias_traversal_duplicate_and_central_directory_bombs_refuse(self):
  for mode in ('symlink','traversal','duplicate','central'):
   with tempfile.TemporaryDirectory()as d:
    root=Path(d);archive=root/'artifact.zip';out=root/'out';out.mkdir()
    with zipfile.ZipFile(archive,'w')as z:
     if mode=='symlink':
      info=zipfile.ZipInfo('FENCED/leaf');info.create_system=3;info.external_attr=(stat.S_IFLNK|0o777)<<16;z.writestr(info,b'DATA')
     elif mode=='traversal':z.writestr('../leaf',b'DATA')
     elif mode=='duplicate':z.writestr('FENCED/leaf',b'DATA');z.writestr('FENCED/leaf/',b'')
     else:z.writestr('FENCED/leaf',b'DATA')
    if mode=='central':
     raw=bytearray(archive.read_bytes());index=raw.rfind(b'PK\x05\x06');raw[index+12:index+16]=struct.pack('<L',5*m.MIB);archive.write_bytes(raw)
    with self.assertRaises(ValueError):m.extract_zip(archive,[row('FENCED/leaf',b'DATA')],out,budget())
 def test_nested_export_package_only_and_bad_tar_type_refusal(self):
  for malicious in (False,True):
   with tempfile.TemporaryDirectory()as d:
    root=Path(d);body=io.BytesIO()
    with tarfile.open(fileobj=body,mode='w')as t:
     info=tarfile.TarInfo('output/'+m.PACKAGE);info.size=4
     if malicious:info.type=tarfile.SYMTYPE;info.linkname='/etc/passwd';info.size=0
     t.addfile(info,io.BytesIO(b'DATA')if not malicious else None)
    raw=body.getvalue();archive=root/'a.zip';out=root/'out';out.mkdir()
    with zipfile.ZipFile(archive,'w')as z:z.writestr('FENCED/export.tar',raw)
    selection=row('output/'+m.PACKAGE,b'DATA','llvm_archive','EXPORT_TAR',dict(member='FENCED/export.tar',**m.pin(raw)))
    if malicious:
     with self.assertRaises(ValueError):m.extract_zip(archive,[selection],out,budget())
    else:self.assertEqual(m.extract_zip(archive,[selection],out,budget())['llvm_archive']['bytes'],4)
 def test_budget_cancellation_request_cap_and_original_retained_contract(self):
  b=budget();b.command.cancelled[0]=True
  with self.assertRaises(ValueError):b.tick()
  b=budget()
  for _ in range(m.REQUESTS):b.request('https://FENCED',False)
  with self.assertRaises(ValueError):b.request('https://FENCED',False)
  self.assertEqual(m.RETAINED_SECONDS,500);self.assertEqual(sum(v[0]for v in m.STAGE0.values()),108298076)
  self.assertEqual(m.RETAINED_PROFILE,'4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c')
 def test_whole_acquire_controller_fenced_tiny_materials_no_root_fixture(self):
  # This models DATA delivery only. Tiny bytes are not packages, stage0 or Root proofs.
  def archive(leaves):
   stream=io.BytesIO()
   with zipfile.ZipFile(stream,'w')as z:
    for name,body in leaves.items():z.writestr(name,body)
   return stream.getvalue()
  stage={name:('FENCED-STAGE0:'+name).encode()for name in m.STAGE0}
  sources={name:dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest(),url=m.SOURCES[name]['url'])for name,body in ((name,('FENCED-SOURCE:'+name).encode())for name in m.SOURCES)}
  stagepins={name:(len(body),hashlib.sha256(body).hexdigest())for name,body in stage.items()}
  with patch.object(m,'STAGE0',stagepins),patch.object(m,'SOURCES',sources):
   value=plan();responses={};events=[]
   for kind,descriptor in ((kind,value[kind])for kind in m.ARTIFACT_CAPS):
    leaves={item['member']:stage[item['name']]if kind=='stage0_carrier'else b'DATA'for item in descriptor['members']}
    body=archive(leaves);descriptor.update(m.pin(body))
    meta=m.encode(dict(id=int(descriptor['id']),size_in_bytes=len(body),expired=False,workflow_run=dict(id=4,head_sha='f'*40)))
    job=m.encode(dict(id=5,run_id=4,head_sha='f'*40,status='completed',conclusion='success'))
    descriptor.update(metadata_sha256=hashlib.sha256(meta).hexdigest(),job_metadata_sha256=hashlib.sha256(job).hexdigest())
    responses['/repos/'+m.REPOSITORY+'/actions/artifacts/'+descriptor['id']]=meta
    responses['/repos/'+m.REPOSITORY+'/actions/artifacts/'+descriptor['id']+'/zip']=body
    responses['/repos/'+m.REPOSITORY+'/actions/jobs/5']=job
   for name in sources:responses[m.urlsplit(sources[name]['url']).path]=('FENCED-SOURCE:'+name).encode()
   class NetworkStub:
    def __init__(self,host):self.host=host
    def request(self,method,path,headers):self.path=path;events.append((self.host,method,path,headers))
    def getresponse(self):return Response(responses[self.path])
    def close(self):pass
   with tempfile.TemporaryDirectory()as d,patch.object(m,'_connection',side_effect=lambda host,timeout:NetworkStub(host)):
    root=Path(d);result=m.acquire(root,root,value,SimpleNamespace(cancelled=[False],on_tick=None),'FENCED_TOKEN')
    self.assertEqual(result['status'],'ACQUIRED_PINNED_MATERIAL_DATA_ONLY');self.assertEqual(len(result['materials']),5)
    self.assertEqual(len(events),11);self.assertEqual(result['receipts']['requests'],11)
    self.assertEqual(set(result['files']),{'llvm_archive',*m.PROOFS,*('stage0:'+name for name in stage)})
    for item in result['files'].values():self.assertEqual(stat.S_IMODE(Path(item['local_path']).stat().st_mode),0o444)
    self.assertNotIn('native_acceptance',result);self.assertNotIn('Root_acceptance',result)
 def test_token_never_accepted_as_URL_or_redirect_authority(self):
  for url in ('https://token@api.github.com/FENCED','https://api.github.com:8443/FENCED','http://api.github.com/FENCED','https://FOREIGN.example/FENCED'):
   with self.assertRaises(ValueError):m.url_parts(url,{'api.github.com'})
  with self.assertRaises(ValueError):m.decode(b'{"id":1,"id":2}')


if __name__=='__main__':unittest.main()
