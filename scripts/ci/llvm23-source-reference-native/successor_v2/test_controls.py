#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""DATA controls: no Docker, process, namespace, lease or Source payload execution."""
import copy,hashlib,importlib.util,json,os,socket,subprocess,tempfile,time,unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
PARENT=None
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
P=load('v2_prepare',HERE/'prepare.py');V=load('v2_volume',HERE/'payload/hosted/volume.py');W=load('v2_work_check',HERE/'payload/actor/work_check.py');D=load('v2_producer',HERE/'payload/hosted/producer.py');R=load('v2_reader',HERE/'payload/hosted/reader.py')
B=dict(operation=V.OP,source='a'*40,run='123',job='456',ref='refs/heads/v2',approval='b'*64,source_map_sha256='c'*64)
OWNER=V.owner(B);IMAGE='sha256:'+'d'*64

def init_row(b=OWNER):
 return dict(Name='/'+b['init'],Id='e'*64,Image=IMAGE,Config=dict(User='0:0',Entrypoint=['/usr/bin/python3'],Cmd=['-I','-B','-c',V.INIT_CODE,V.encode(b).decode()],Labels=V.labels(b,'initializer')),HostConfig=dict(ReadonlyRootfs=True,NetworkMode='none',CapDrop=['ALL'],CapAdd=['CHOWN'],SecurityOpt=['no-new-privileges'],Privileged=False,Devices=[],Init=False,Memory=536870912,MemorySwap=536870912,NanoCpus=10**9,PidsLimit=64,Mounts=[dict(Type='volume',Source=b['volume'],Target='/work',VolumeOptions=dict(NoCopy=True))]),Mounts=[dict(Type='volume',Name=b['volume'],Destination='/work',RW=True)],State=dict(Status='exited',ExitCode=0,Running=False,Pid=0,OOMKilled=False))
def volume_row(b=OWNER):return dict(Name=b['volume'],Driver='local',Scope='local',Options=None,Labels=V.labels(b,'work'))
def receipt(b=OWNER):
 return dict(schema=1,status='INITIALIZED_EMPTY_WORK_VOLUME',binding=b,before=dict(device=3,inode=4,uid=0,gid=0,mode=493),after=dict(device=3,inode=4,uid=1001,gid=1001,mode=448),limits={'cpu.max':'100000 100000','memory.max':'536870912','memory.swap.max':'0','pids.max':'64'},capabilities='CHOWN_ONLY_CHMOD_BEFORE_CHOWN',recursive=False)
def actor_row(inputs,source,volume_sha):
 return dict(Name='/'+OWNER['actor'],Id='f'*64,Image=IMAGE,Config=dict(User='1001:1001',Hostname='llvm23-native',WorkingDir='/work',Labels=V.labels(OWNER,'builder'),Env=['WORK_VOLUME_ADMISSION_SHA256='+volume_sha],Entrypoint=['/usr/bin/bash'],Cmd=['--noprofile','--norc','/inputs/actor/entry.sh']),HostConfig=dict(ReadonlyRootfs=True,NetworkMode='none',CapDrop=['ALL'],CapAdd=[],SecurityOpt=['no-new-privileges'],Privileged=False,Memory=8*1024**3,MemorySwap=8*1024**3,NanoCpus=2*10**9,PidsLimit=512,Init=True,Mounts=[dict(Type='volume',Source=OWNER['volume'],Target='/work',VolumeOptions=dict(NoCopy=True))]),Mounts=[dict(Type='volume',Name=OWNER['volume'],Destination='/work',RW=True),dict(Type='bind',Source=str(inputs),Destination='/inputs',RW=False),dict(Type='bind',Source=str(source),Destination='/source',RW=False)],State=dict(Status='exited',ExitCode=0,Running=False,Pid=0,OOMKilled=False))

class Controls(unittest.TestCase):
 def test_init_exact_domain(self):
  a=V.init_options(OWNER,IMAGE);self.assertEqual(a.count('--mount'),1);self.assertIn('--cap-add=CHOWN',a);self.assertIn('volume-nocopy',a[a.index('--mount')+1]);V.inspect_init(init_row(),OWNER,IMAGE)
 def test_foreign_volume_refused(self):
  for field,value in [('Name','other'),('Driver','nfs'),('Scope','global'),('Options',{'x':'y'}),('Labels',{})]:
   row=volume_row();row[field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):V.volume_identity(row,OWNER)
 def test_initializer_extra_caps_refused(self):
  row=init_row();row['HostConfig']['CapAdd'].append('FOWNER')
  with self.assertRaises(ValueError):V.inspect_init(row,OWNER,IMAGE)
 def test_initializer_copyup_refused(self):
  row=init_row();row['HostConfig']['Mounts'][0]['VolumeOptions']['NoCopy']=False
  with self.assertRaises(ValueError):V.inspect_init(row,OWNER,IMAGE)
 def test_initializer_extra_mount_refused(self):
  row=init_row();row['Mounts'].append(dict(Destination='/host'))
  with self.assertRaises(ValueError):V.inspect_init(row,OWNER,IMAGE)
 def test_receipt_identity_and_owner(self):
  V.receipt(receipt(),OWNER)
  for field,value in [('uid',0),('gid',0),('mode',493),('inode',999)]:
   r=receipt();r['after'][field]=value
   with self.subTest(field=field),self.assertRaises(ValueError):V.receipt(r,OWNER)
 def test_receipt_binding_refused(self):
  r=receipt();r['binding']=dict(OWNER,source='x'*40)
  with self.assertRaises(ValueError):V.receipt(r,OWNER)
 def test_preentry_exact_readonly_observation(self):W.verify(V.admission(OWNER),receipt(),receipt()['after'],1001,1001,True,True)
 def test_preentry_refusals(self):
  for uid,gid,rw,empty in [(0,1001,True,True),(1001,0,True,True),(1001,1001,False,True),(1001,1001,True,False)]:
   with self.subTest(uid=uid,gid=gid,rw=rw,empty=empty),self.assertRaises(ValueError):W.verify(V.admission(OWNER),receipt(),receipt()['after'],uid,gid,rw,empty)
 def test_preentry_inode_refusal(self):
  with self.assertRaises(ValueError):W.verify(V.admission(OWNER),receipt(),dict(receipt()['after'],inode=22),1001,1001,True,True)
 def test_actor_nocopy_and_frozen_domain(self):
  r=actor_row(Path('/inputs'),Path('/src'),'1'*64);D.inspect_actor(r,OWNER['actor'],OWNER['volume'],IMAGE,Path('/inputs'),Path('/src'),OWNER,'1'*64)
  r['HostConfig']['Mounts'][0]['VolumeOptions']['NoCopy']=False
  with self.assertRaises(ValueError):D.inspect_actor(r,OWNER['actor'],OWNER['volume'],IMAGE,Path('/inputs'),Path('/src'),OWNER,'1'*64)
 def test_reader_full_volume_join(self):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t);base=root/'llvm-build';(base/'inputs').mkdir(parents=True);ad=V.admission(OWNER);raw=V.encode(ad);vs=hashlib.sha256(raw).hexdigest()
   values={'volume-initialization.json':receipt(),'inputs/volume-initialization.json':receipt(),'inputs/volume-admission.json':ad,'volume-before.json':volume_row(),'initializer-before.json':init_row(),'initializer-after.json':init_row()}
   for n,v in values.items():(base/n).write_bytes(V.encode(v))
   p=dict(volume_owner=OWNER,inner_operation=V.INNER,actor=OWNER['actor'],init=OWNER['init'],volume=OWNER['volume'],volume_initialization=receipt(),volume_admission_sha256=vs,inputs_path='/inputs',source_intake={'root':'/src'})
   with patch.object(R,'ROOT',HERE/'payload'):
    R.check_volume(root,p,dict(B,image=IMAGE),D,actor_row(Path('/inputs'),Path('/src'),vs))
    bad=init_row();bad['State']['ExitCode']=1;(base/'initializer-after.json').write_bytes(V.encode(bad))
    with self.assertRaises(ValueError):R.check_volume(root,p,dict(B,image=IMAGE),D,actor_row(Path('/inputs'),Path('/src'),vs))
 def modeled_run(self,failed=False):
  with tempfile.TemporaryDirectory()as t:
   root=Path(t)/'source';work=Path(t)/'work';work.mkdir();(work/'bootstrap').mkdir();(work/'bootstrap/signatures.json').write_bytes(b'{}');root.mkdir()
   for name in ['actor','helpers','packages/port/llvm23-source-reference','hosted']:(root/name).mkdir(parents=True)
   (root/'contract.json').write_bytes(b'{}');(root/'policy.json').write_bytes(b'{"export_bytes": 1024}')
   (root/'packages/port/llvm23-source-reference/reference.py').write_text("def tree_digest(path):return '0'*64\n")
   (root/'hosted/volume.py').write_bytes((HERE/'payload/hosted/volume.py').read_bytes())
   (root/'hosted/common.py').write_text("import json,hashlib,importlib.util\ndef encode(v):return(json.dumps(v,sort_keys=True,indent=2)+'\\n').encode()\ndef decode(v):return json.loads(v)\ndef read(p,*a):return p.read_bytes()\ndef pin(v):return dict(bytes=len(v),sha256=hashlib.sha256(v).hexdigest())\ndef need(v,s):\n if not v:raise ValueError(s)\ndef load(n,p):\n s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m\n")
   archive=Path(t)/'archive';archive.write_bytes(b'fixture');source=Path(t)/'unpacked';source.mkdir()
   class Command:
    on_tick=None;deadline=time.monotonic()+10000;cancelled=[False];cleaning=False
    def __init__(self):self.events=[];self.rows={};self.owned=self
    def __call__(self,argv,timeout=60,check=True):
     a=argv[len(D.DOCKER):];self.events.append(a);out=b'';code=0
     if a[:2]==['volume','inspect']:out=V.encode([volume_row()])
     elif a[0]=='create':
      name=a[a.index('--name')+1]
      if name==OWNER['init']:self.rows[name]=init_row()
      else:
       vs=next(x.split('=',1)[1]for x in a if x.startswith('WORK_VOLUME_ADMISSION_SHA256='));self.rows[name]=actor_row(work/'llvm-build/inputs',source,vs)
     elif a[0]=='inspect'or a[:2]==['container','inspect']:out=V.encode([self.rows[a[-1]]])
     elif a[:2]==['start','--attach']:
      if a[-1]==OWNER['init']:out=V.encode(receipt())
      elif failed:raise RuntimeError('first actor fixture failure')
     return SimpleNamespace(stdout=out,returncode=code)
    def run(self,argv,**kw):
     kw['stdout'].write(b'fixture export');kw['lifecycle'].update(natural_exit=True,retirement='REAPED',group_absent=True,forced_cleanup=False)
     return SimpleNamespace(returncode=1 if failed else 0)
   command=Command()
   with patch.object(D.resource,'setrlimit',lambda *a:None):report=D.run(root,work,B,IMAGE,dict(archive=str(archive),root=str(source)),command)
   return report,command.events
 def test_producer_complete_order_and_cleanup(self):
  report,events=self.modeled_run();self.assertEqual(report['status'],'COMPLETED_EXPORTED_RETIRED');self.assertTrue(report['owned_resources_absent'])
  creates=[i for i,a in enumerate(events)if a[0]=='create'];starts=[i for i,a in enumerate(events)if a[:2]==['start','--attach']]
  self.assertEqual(len(creates),2);self.assertEqual(len(starts),2);self.assertLess(max(creates),min(starts));self.assertEqual(events[starts[0]][-1],OWNER['init']);self.assertEqual(events[starts[1]][-1],OWNER['actor'])
  self.assertEqual(report['cleanup'],[OWNER['actor'],OWNER['init'],OWNER['volume']])
 def test_producer_first_failure_survives_export_refusal(self):
  report,events=self.modeled_run(True);self.assertIn('first actor fixture failure',report['error']);self.assertIn('natural bounded export',report['export_error']);self.assertEqual(report['status'],'FAIL');self.assertTrue(report['owned_resources_absent'])
 def test_constructor_exact_parent_and_inverse(self):
  before=P.parent(PARENT);after=P.render(before);meta=json.loads(after['successor-v2.json'][0]);self.assertEqual(P.undo(after,before,meta),before)
  for n in meta['frozen_python']:self.assertEqual(after[n],before[n])
  self.assertEqual({n:v for n,v in after.items()if n.startswith('packages/')},{n:v for n,v in before.items()if n.startswith('packages/')})
  self.assertTrue(all(v is None for v in meta['actual'].values()));self.assertNotIn('.github/workflows/native-arm-llvm23-source-reference-v1.yml',after)
  self.assertEqual(after['.github/workflows/native-arm-build.yml'],after['.github/workflows/native-arm-llvm23-source-reference-v2.yml'])
  self.assertEqual(json.loads(after['policy.json'][0])['native_seconds'],19920)
  self.assertEqual(json.loads(after['contract.json'][0])['operation'],V.INNER)
 def test_inverse_tamper_refused(self):
  before=P.parent(PARENT);after=P.render(before);meta=json.loads(after['successor-v2.json'][0]);after['actor/entry.sh']=(b'bad',0o755)
  with self.assertRaises(ValueError):P.undo(after,before,meta)
 def test_parent_tamper_refused(self):
  before=P.parent(PARENT);before['actor/entry.py']=(b'bad',0o644)
  with self.assertRaises(ValueError):P.render(before)

if __name__=='__main__':
 import argparse
 parser=argparse.ArgumentParser();parser.add_argument('--parent-source',required=True,type=Path);args=parser.parse_args();PARENT=args.parent_source
 def denied(*a,**k):raise AssertionError('actor/network/process operation forbidden in DATA controls')
 with patch.object(subprocess,'Popen',denied),patch.object(os,'system',denied),patch.object(socket,'socket',denied),patch.object(os,'fork',denied):unittest.main(argv=[__file__],verbosity=2)
