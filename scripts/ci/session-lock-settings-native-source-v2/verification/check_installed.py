#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Exact installed/moved bytes and inert child controls; no desktop operation."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import sys
import tempfile
import types
import unittest

NAME='cachy-asahi-session-lock'
VERSION='0.1.0-1'
TEST_PIN=(16518,'7f235c42e12336f3bf61e3ecead4477afe67bf3af6270d6913e0f4b123ca60d2')
PAYLOAD={
 'usr/bin/'+NAME:(8597,'9084a6796479d68a1c0955ecdbd8395252e8289d4dbc98f6aeff3a84fe6252f6',0o755),
 'usr/share/doc/'+NAME+'/README.md':(5563,'c230dcdd091481257c01dbcda2206ade24e05cd315045fc2f10e13e5a64402c8',0o644),
 'usr/share/licenses/'+NAME+'/NOTICE':(389,'7fd19f4b37f18c0331329c50651414d0c8f44c371565e3ce3fee9e510090653c',0o644),
 'usr/share/licenses/'+NAME+'/LICENSE':(1081,'51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7',0o644)}

def need(value,why):
 if not value:raise ValueError(why)

def ordinary(path):
 path=Path(path)
 need(path.is_absolute()and str(path)==os.path.normpath(str(path))and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary canonical absolute operand')
 return path

def identity(info):
 return tuple(getattr(info,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))

def checked(path,wanted,mode=None):
 path=ordinary(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  before=os.fstat(fd)
  need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_size==wanted[0]and not before.st_mode&0o022,'exact ordinary single-link payload or tests')
  if mode is not None:need(stat.S_IMODE(before.st_mode)==mode,'exact installed payload mode')
  raw=b''
  while block:=os.read(fd,65536):
   raw+=block;need(len(raw)<=wanted[0],'bounded operand body')
  need((len(raw),hashlib.sha256(raw).hexdigest())==wanted,'exact pinned operand body')
  need(identity(before)==identity(os.fstat(fd))==identity(path.lstat()),'stable operand identity')
 finally:os.close(fd)
 return raw,identity(before)

def controls(program,tests,raw_tests):
 # The pinned test module imports only the exact program beside its SOURCE.
 raw_program,_=checked(program,PAYLOAD['usr/bin/'+NAME][:2],0o755)
 implementation=types.ModuleType('installed_session_lock');implementation.__file__=str(program)
 exec(compile(raw_program,str(program),'exec'),implementation.__dict__)
 namespace={'__name__':'session_lock_installed_controls','__file__':str(tests)}
 # Import of the module's original SOURCE is avoided: it is replaced through a
 # temporary sibling with identical pinned bytes, not by changing the test text.
 with tempfile.TemporaryDirectory(prefix='session-lock-controls-')as tmp:
  copy=Path(tmp);(copy/NAME).write_bytes(raw_program);(copy/NAME).chmod(0o755)
  namespace['__file__']=str(copy/'test_session_lock.py')
  exec(compile(raw_tests,str(tests),'exec'),namespace)
  namespace['SOURCE']=program;namespace['S']=implementation
  suite=unittest.defaultTestLoader.loadTestsFromTestCase(namespace['SessionLock'])
  need(suite.countTestCases()==24,'exact actual package24 controls')
  diagnostics=io.StringIO();result=unittest.TextTestRunner(stream=diagnostics,verbosity=1).run(suite)
  raw=diagnostics.getvalue().encode();need(len(raw)<=65536,'bounded control diagnostics')
 return dict(tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),successful=result.wasSuccessful(),
  diagnostics_pin=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))

def verify(root,tests):
 need(sys.flags.isolated,'isolated Python required')
 need(os.getuid()!=0 and os.geteuid()==os.getuid(),'ordinary unprivileged controls user required')
 root=ordinary(root);tests=ordinary(tests);need(root.is_dir(),'existing filesystem prefix')
 raw_tests,_=checked(tests,TEST_PIN);observed={};payload=[]
 for member,(size,sha,mode)in PAYLOAD.items():
  _,observed[str(root/member)]=checked(root/member,(size,sha),mode)
  payload.append(dict(member=member,bytes=size,sha256=sha,mode=mode))
 program=root/'usr/bin'/NAME
 # Audit hooks cannot be removed. Keep their state disabled after this call so
 # importing this verifier does not constrain unrelated later process work.
 state={'active':True,'programs':{str(program)}}
 def permitted(executable):
  if executable in state['programs']or executable==sys.executable:return True
  # Two original controls intentionally execute a missing private fixture path.
  path=Path(executable)
  if not path.is_absolute()or path.name!='absent'or path.exists()or path.is_symlink():return False
  parent=path.parent;info=parent.lstat()
  return parent.name.startswith('session-lock-test-')and stat.S_ISDIR(info.st_mode)and info.st_uid==os.getuid()and stat.S_IMODE(info.st_mode)==0o700
 def fence(event,args):
  if not state['active']:return
  if event in('subprocess.Popen','os.posix_spawn'):
   need(permitted(str(args[0])),'only pinned CLI or owned inert Python children may execute')
  elif event=='socket.__new__':need(args[1]==socket.AF_UNIX,'only owned inert AF_UNIX socket fixtures')
  elif event in('socket.connect','os.system','os.exec'):raise ValueError('no network, shell or external actor')
 sys.addaudithook(fence)
 try:
  locations=[dict(kind='installed',**controls(program,tests,raw_tests))]
  with tempfile.TemporaryDirectory(prefix='session-lock-moved-')as tmp:
   moved=Path(tmp)/'moved'/NAME;moved.parent.mkdir();shutil.copyfile(program,moved);moved.chmod(0o755)
   checked(moved,PAYLOAD['usr/bin/'+NAME][:2],0o755);state['programs'].add(str(moved))
   locations.append(dict(kind='moved',**controls(moved,tests,raw_tests)))
  for path,before in observed.items():need(identity(Path(path).lstat())==before,'installed payload unchanged through controls')
 finally:state['active']=False
 return dict(schema=1,kind='SESSION_LOCK_INSTALLED_MODEL_CONTROLS_DATA_V1',status='PASS'if all(r['successful']for r in locations)else'FAIL',
  package=dict(name=NAME,version=VERSION),payload=payload,locations=locations,controls=sum(r['tests']for r in locations),
  Root_final_acceptance=None,hardware_acceptance=False,compositor=False,PAM=False,suspend=False)

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,required=True);parser.add_argument('--tests',type=Path,required=True);parser.add_argument('--output',type=Path)
 args=parser.parse_args()
 try:report=verify(args.root,args.tests)
 except (OSError,ValueError)as e:report=dict(schema=1,kind='SESSION_LOCK_INSTALLED_MODEL_CONTROLS_DATA_V1',status='REFUSED',error=str(e),Root_final_acceptance=None,hardware_acceptance=False)
 raw=(json.dumps(report,sort_keys=True,indent=2)+'\n').encode()
 if args.output:
  with open(args.output,'xb')as output:output.write(raw)
 print(raw.decode(),end='');return 0 if report['status']=='PASS'else 1

if __name__=='__main__':sys.exit(main())
