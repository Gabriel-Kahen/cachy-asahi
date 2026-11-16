# SPDX-License-Identifier: MIT
"""FENCED post-fsck failure DATA; no raw image, credential, Docker, lease or VM."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent

def module(name):
 s=importlib.util.spec_from_file_location('retirement_DATA_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
A,C,K,R=map(module,('actor','controller','contracts','runtime'))
NONCE='a'*32
SOURCE=dict(bytes=9000,sha256='b'*64)
PACKET=dict(nonce=NONCE,Source_lock=SOURCE)
RUNTIME=dict(files={'/usr/lib/approved.so':{}},baseline_files={})
NATURAL=dict(passed=True,reaped=True,ownership='REAPED',exit=0,group_census='EMPTY_TWICE',output_complete=True,signals=[],timeout=False,error=None,
 command_cancelled=[],command_timed_out=False,original_budget_overrun=False,emergency_retirement=False)

def fence(event,args):
 if event.startswith(('subprocess.','socket.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock','resource.setrlimit'):
  raise AssertionError('no operational actor in retirement DATA controls')
sys.addaudithook(fence)

class Controls(unittest.TestCase):
 def fixture(self,out,error=None):
  return A.write_failure(K,out,'boot',PACKET,dict(stage='baseline_scan'),error or ValueError('inode link-count mismatch'),RUNTIME)
 def test_actual_boot_sequence_after_readonly_fsck_rethrows_and_reports_stage(self):
  with tempfile.TemporaryDirectory(prefix='FENCED-perl-post-fsck-')as name:
   out=Path(name);calls=[];original=ValueError('inode link-count mismatch')
   metadata=dict(operation=K.OP,packet=SOURCE,raw=SOURCE,nonce=NONCE,baseline_nonce='c'*32,preboot_etc_descriptor=SOURCE)
   resources=dict(cpus=2,guest_memory_bytes=2*1024**3,overlay_cap_bytes=512*1024**2,readback_allocated_cap_bytes=1024**3,logs_cap_bytes=16*1024**2,reserve_bytes=1,cleanup_seconds=90)
   cert=dict(resource_certificate=resources,runtime_certificate=RUNTIME)
   def command(argv,work,label,*args,**kwargs):calls.append(label);return SimpleNamespace(returncode=0)if label=='journal-copy-only'else b''
   fakeR=SimpleNamespace(command=command,receipt=lambda p:copy.deepcopy(NATURAL),natural=R.natural)
   fakeI=SimpleNamespace(scan=lambda *args:(_ for _ in()).throw(original))
   def load(path):return metadata if str(path)=='/prepared/prepared.json'else dict(nonce=NONCE,utc_ns=10**9)
   with patch.object(K,'load',side_effect=load),patch.object(K,'pin',return_value=SOURCE),patch.object(A.time,'time_ns',return_value=10**9):
    with self.assertRaises(ValueError)as caught:A.run_phase('boot',K,fakeR,fakeI,out,PACKET,cert,lambda:None,10000)
   self.assertIs(caught.exception,original)
   self.assertEqual(calls,['overlay-create','qemu','readback-convert','journal-copy-only','readback-readonly-fsck'])
   value,pin=A.read_failure(K,out,'boot',NONCE,SOURCE,RUNTIME)
   self.assertEqual(value['stage'],'baseline_scan');self.assertEqual(value['failure']['code'],'EXT4_LINK_COUNT')
   self.assertLessEqual(pin['bytes'],4096);self.assertIsNone(value['VM_acceptance']);self.assertIsNone(value['Root_acceptance'])
   captured=C.capture_actor_failure(K,out,'boot',NONCE,SOURCE,RUNTIME)
   self.assertEqual(captured['status'],'CAPTURED_PUBLIC_FAILURE_DATA_ONLY');self.assertEqual(captured['file'],pin)
 def test_wait_cli_success_does_not_waive_container_nonzero_or_qemu_retirement(self):
  # Selected retained Case9 semantics: Docker CLI exit0, stdout1, QEMU exit0;
  # actor container ExitCode1 remains a failure independent of three guest PASS frames.
  self.assertTrue(R.natural(NATURAL));self.assertEqual(int(b'1\n'),1)
  source=(HERE/'controller.py').read_text()
  gate="K.need(finished['State']['ExitCode']==0 and not finished['State']['Running'] and not finished['State']['OOMKilled'],'natural actor completion')"
  self.assertEqual(source.count(gate),1)
  for code,running,oom in((1,False,False),(0,True,False),(0,False,True)):
   with self.assertRaises(ValueError):K.need(code==0 and not running and not oom,'natural actor completion')
  for key,value in(('exit',1),('signals',['SIGTERM']),('timeout',True),('emergency_retirement',True),('original_budget_overrun',True),('reaped',False)):
   row=copy.deepcopy(NATURAL);row[key]=value;self.assertFalse(R.natural(row))
 def test_nonpublic_exception_text_never_exported_and_public_path_is_certified(self):
  private='CREDENTIAL_TEXT=/private/home/key\x1b[31m\nSTATUS=PASS'
  for error in(ValueError(private),OSError(13,private),RuntimeError(private)):
   fields=A.failure_fields(error,RUNTIME);raw=K.canonical(fields)
   self.assertNotIn(b'CREDENTIAL_TEXT',raw);self.assertNotIn(b'private/home',raw);self.assertNotIn(b'\x1b',raw)
  for path,expected in(('usr/lib/approved.so','usr/lib/approved.so'),('home/builder/secret',None),('root/.gnupg/key',None),('usr/lib/unreviewed.so',None),('usr/lib/../private',None)):
   fields=A.failure_fields(ValueError('baseline owned file bytes/mode/owner/version/time: '+path),RUNTIME)
   self.assertEqual(fields['code'],'BASELINE_OWNED_CHANGED');self.assertEqual(fields['public_path'],expected)
 def test_fixed_stage_allowlist_and_existing_receipt_are_not_overwritten(self):
  with tempfile.TemporaryDirectory(prefix='FENCED-perl-failure-stage-')as name:
   out=Path(name)
   for stage in('arbitrary/path','STATUS=PASS','baseline_scan\n'):
    with self.assertRaises(ValueError):A.write_failure(K,out,'boot',PACKET,dict(stage=stage),ValueError('x'),RUNTIME)
   self.fixture(out);before=(out/A.FAILURE_FILE).read_bytes()
   with self.assertRaises(FileExistsError):self.fixture(out)
   self.assertEqual((out/A.FAILURE_FILE).read_bytes(),before)
 def test_truncated_malformed_wrong_nonce_source_acceptance_and_private_message_refuse(self):
  with tempfile.TemporaryDirectory(prefix='FENCED-perl-invalid-receipt-')as name:
   out=Path(name);value=self.fixture(out);path=out/A.FAILURE_FILE
   bad=[]
   for key,wrong in(('nonce','d'*32),('source_lock',dict(bytes=1,sha256='e'*64)),('stage','unknown'),('VM_acceptance',True),('schema',True)):
    item=copy.deepcopy(value);item[key]=wrong;bad.append(K.canonical(item))
   item=copy.deepcopy(value);item['failure']['message']='private credential text';bad.append(K.canonical(item))
   bad.extend([b'{',b'{}',K.canonical(value)[:-2],b'x'*4097])
   for raw in bad:
    path.write_bytes(raw)
    with self.subTest(raw=raw[:40]),self.assertRaises((ValueError,KeyError)):A.read_failure(K,out,'boot',NONCE,SOURCE,RUNTIME)
    self.assertEqual(C.capture_actor_failure(K,out,'boot',NONCE,SOURCE,RUNTIME),dict(status='REFUSED_UNSAFE_OR_INVALID',data=None))
 def test_mode_links_alias_owner_and_changed_metadata_refuse(self):
  with tempfile.TemporaryDirectory(prefix='FENCED-perl-receipt-identity-')as name:
   out=Path(name);self.fixture(out);path=out/A.FAILURE_FILE;raw=path.read_bytes()
   path.chmod(0o644)
   with self.assertRaises(ValueError):A.read_failure(K,out,'boot',NONCE,SOURCE,RUNTIME)
   path.chmod(0o600);os.link(path,out/'alias')
   with self.assertRaises(ValueError):A.read_failure(K,out,'boot',NONCE,SOURCE,RUNTIME)
   (out/'alias').unlink();path.unlink();(out/'other').write_bytes(raw);path.symlink_to(out/'other')
   with self.assertRaises(ValueError):A.read_failure(K,out,'boot',NONCE,SOURCE,RUNTIME)
   path.unlink();path.write_bytes(raw);path.chmod(0o600)
   real=A.os.fstat;calls=[]
   def changed(fd):
    info=real(fd);calls.append(fd)
    values={k:getattr(info,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')}
    if len(calls)>1:values['st_mtime_ns']+=1
    return SimpleNamespace(**values)
   with patch.object(A.os,'fstat',side_effect=changed),self.assertRaises(ValueError):A.read_failure(K,out,'boot',NONCE,SOURCE,RUNTIME)
   def foreign(fd):
    info=real(fd);values={k:getattr(info,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')};values['st_uid']+=1
    return SimpleNamespace(**values)
   with patch.object(A.os,'fstat',side_effect=foreign),self.assertRaises(ValueError):A.read_failure(K,out,'boot',NONCE,SOURCE,RUNTIME)
 def test_diagnostic_failure_preserves_original_exception_and_absence_is_data_only(self):
  original=MemoryError('private text')
  with tempfile.TemporaryDirectory(prefix='FENCED-perl-receipt-write-failure-')as name:
   out=Path(name)
   with patch.object(A,'boot',side_effect=original),patch.object(A,'write_failure',side_effect=OSError('unwritable')):
    with self.assertRaises(MemoryError)as caught:A.run_phase('boot',K,None,None,out,PACKET,dict(runtime_certificate=RUNTIME),None,0)
   self.assertIs(caught.exception,original)
   self.assertEqual(C.capture_actor_failure(K,out,'boot',NONCE,SOURCE,RUNTIME),dict(status='ABSENT',data=None))

if __name__=='__main__':unittest.main()
