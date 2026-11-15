#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded serial parsing only. Never starts Docker/QEMU or a guest."""
import importlib.util
from pathlib import Path
import socket,time,unittest
s=importlib.util.spec_from_file_location('tcg_reference_boot',Path(__file__).with_name('boot.py'));b=importlib.util.module_from_spec(s);s.loader.exec_module(b)
NONCE='1'*32
FRAME=('TCG_LOGIN_BEGIN '+NONCE+'\nUID=1000\nUSERNAME=builder\nPID1=systemd\nXDG_SESSION_ID=1\nId=1\nName=builder\nUser=1000\nClass=user\nType=tty\nService=login\nRemote=no\nLeader=55\nActive=yes\nState=active\nLOGIND=active\nDBUS=active\nTCG_LOGIN_END '+NONCE+'\n').encode()
class Controller(unittest.TestCase):
 def test_exact_real_session_fields_required(self):
  self.assertEqual(b.parse_frame(FRAME,NONCE)['Id'],'1')
  for data,nonce in [(FRAME, '2'*32),(FRAME.replace(b'UID=1000',b'UID=0'),NONCE),(FRAME.replace(b'Type=tty',b'Type=unspecified'),NONCE),(FRAME+FRAME,NONCE)]:
   with self.subTest(),self.assertRaises(AssertionError):b.parse_frame(data,nonce)
 def test_fragmented_serial_and_bound(self):
  a,c=socket.socketpair();self.addCleanup(a.close);self.addCleanup(c.close);serial=b.Serial(a,time.monotonic()+1)
  c.sendall(b'boot\r\nlog');c.sendall(b'in: ');serial.until(rb'login:');self.assertLessEqual(len(serial.data),b.MAX_SERIAL)
  serial.data=bytearray(b.MAX_SERIAL+1);c.sendall(b'x')
  with self.assertRaises(ValueError):serial.until(rb'never')

# Fixed Docker cleanup controls. No actual Docker/QEMU calls occur here.
import contextlib,io,json,os,signal,subprocess,sys,tempfile
from unittest.mock import patch
CID='a'*64
IMAGE='sha256:'+'b'*64

class FakeDocker:
 def __init__(self,scope,foreign=False):self.scope=scope;self.present=True;self.removed=False;self.foreign=foreign;self.calls=[]
 def __call__(self,argv,**kw):
  self.calls.append(argv)
  if argv[1:3]==['container','ls']:
   value=(CID+' '+self.scope.name+'\n').encode()if self.present else b''
   return subprocess.CompletedProcess(argv,0,value,b'')
  if argv[1:3]==['container','inspect']:
   row={'Id':CID,'Name':'/'+self.scope.name,'Image':IMAGE,'Config':{'Labels':dict(self.scope.labels),'Entrypoint':['/usr/bin/python3'],'Cmd':['-I','-B','/opt/vm_actor.py']},'Mounts':[{'Type':'bind','Source':self.scope.source,'Destination':'/inputs','RW':False},{'Type':'bind','Source':self.scope.out,'Destination':'/work','RW':True}],'HostConfig':{'ReadonlyRootfs':True,'NetworkMode':'none','CapDrop':['ALL'],'CapAdd':[],'Privileged':False,'Devices':[],'Init':False,'Memory':3*1024**3,'NanoCpus':2_000_000_000,'PidsLimit':256}}
   if self.foreign:row['Config']['Labels']['owner']='foreign'
   return subprocess.CompletedProcess(argv,0,json.dumps([row]).encode(),b'')
  if argv[1]=='wait':raise subprocess.TimeoutExpired(argv,kw.get('timeout',0))
  if argv[1:4]==['container','rm','--force']:
   self.present=False;self.removed=True;return subprocess.CompletedProcess(argv,0,b'',b'')
  raise AssertionError(argv)

class Cleanup(unittest.TestCase):
 def make_scope(self,root):
  source=root/'input';source.mkdir();out=root/'output';out.mkdir()
  return b.OwnedContainer('cachy-tcg-reference-test',out/'container.cid',IMAGE,{'owner':'test'},source,out)
 def test_ambiguous_create_without_cid_recovers_exact_contract_wait_timeout_still_removes(self):
  with tempfile.TemporaryDirectory()as tmp:
   scope=self.make_scope(Path(tmp));scope.submitted=True;fake=FakeDocker(scope);original={'category':'TimeoutExpired','message':'original create failure'};report={'failure':dict(original)}
   with patch.object(b.subprocess,'run',fake):scope.cleanup(report)
   self.assertTrue(fake.removed);self.assertEqual(report['failure'],original)
   self.assertTrue(report['owned_container_absence_verified']);self.assertEqual(report['container_id'],CID)
   self.assertEqual(report['cleanup_errors'][0]['category'],'TimeoutExpired')
 def test_ambiguous_name_with_foreign_contract_is_never_removed(self):
  with tempfile.TemporaryDirectory()as tmp:
   scope=self.make_scope(Path(tmp));scope.submitted=True;fake=FakeDocker(scope,foreign=True);report={}
   with patch.object(b.subprocess,'run',fake):scope.cleanup(report)
   self.assertFalse(fake.removed);self.assertEqual(report['cleanup_errors'][0]['step'],'ownership-recovery')
 def test_private_cid_name_mismatch_is_never_removed(self):
  with tempfile.TemporaryDirectory()as tmp:
   scope=self.make_scope(Path(tmp));scope.submitted=True;scope.cidfile.write_text('c'*64+'\n');fake=FakeDocker(scope);report={}
   with patch.object(b.subprocess,'run',fake):scope.cleanup(report)
   self.assertFalse(fake.removed);self.assertIn('differ',report['cleanup_errors'][0]['message'])
 def test_sigterm_raises_cancellation_and_cleanup_defers_sigint(self):
  old={n:signal.getsignal(n)for n in [signal.SIGINT,signal.SIGTERM]}
  with b.Cancellation()as state:
   with self.assertRaises(b.Cancelled):os.kill(os.getpid(),signal.SIGTERM)
   state.cleaning=True;os.kill(os.getpid(),signal.SIGINT)
   self.assertEqual(state.pending,[signal.SIGTERM,signal.SIGINT])
  self.assertEqual({n:signal.getsignal(n)for n in old},old)
 def test_main_sigterm_during_create_still_recovers_removes_and_writes_original_report(self):
  with tempfile.TemporaryDirectory()as tmp:
   root=Path(tmp);source=root/'input';source.mkdir();out=root/'output'
   refs={}
   for name in ['guest.raw','vmlinuz','initramfs.img']:
    f=source/name;f.write_bytes(b'SYNTHETIC never booted');refs[name]={'bytes':f.stat().st_size,'sha256':b.sha(f)}
   manifest=source/'prepared.json';manifest.write_text(json.dumps({'status':'PREPARED_NOT_BOOTED','nonce':'1'*32,'files':refs}))
   (source/'credentials.json').write_text(json.dumps({'username':'builder','password':'X'*32}));(source/'credentials.json').chmod(0o600)
   holder={};created=False
   def output(argv,**kw):
    if argv[1:3]==['image','inspect']:return json.dumps([{'Id':IMAGE,'Config':{'Labels':{}}}]).encode()
    return b'["name=rootless"]'
   def run(argv,**kw):
    nonlocal created
    if argv[1]=='create':
     created=True;name=argv[argv.index('--name')+1];labels={argv[i+1].split('=',1)[0]:argv[i+1].split('=',1)[1]for i,v in enumerate(argv)if v=='--label'}
     scope=b.OwnedContainer(name,Path(argv[argv.index('--cidfile')+1]),IMAGE,labels,source,out);holder['fake']=FakeDocker(scope)
     os.kill(os.getpid(),signal.SIGTERM)
     raise AssertionError('signal must interrupt create')
    if not created:return subprocess.CompletedProcess(argv,0,b'',b'')
    return holder['fake'](argv,**kw)
   argv=['boot.py','--allow-first-x86-reference-boot','--prepared',str(source),'--prepared-sha256',b.sha(manifest),'--tool-image','fixture','--tool-image-id',IMAGE,'--output',str(out)]
   with patch.object(sys,'argv',argv),patch.object(b.subprocess,'check_output',output),patch.object(b.subprocess,'run',run),contextlib.redirect_stdout(io.StringIO()):
    self.assertEqual(b.main(),1)
   report=json.loads((out/'report.json').read_text());self.assertEqual(report['failure']['category'],'Cancelled')
   self.assertTrue(report['owned_container_removed']);self.assertTrue(holder['fake'].removed)
   self.assertEqual(report['cleanup_errors'][0]['category'],'TimeoutExpired')

if __name__=='__main__':unittest.main(verbosity=2)
