#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded root UI frame; original ARM observer independently proves real seat."""
import importlib.util,json,os,time
from pathlib import Path
H=Path('/home/builder');R=Path('/run/ui-session')
def validators():
 modules=[]
 for label,path in [('UI_error_schema','/usr/local/libexec/ui-receipts.py'),('ARM_ui_result','/usr/local/libexec/ui-result.py')]:
  spec=importlib.util.spec_from_file_location(label,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);modules.append(module)
 return modules

def error_receipt(nonce,error,schema):
 # This existing fixture-owned directory survives ordinary Python removal.
 directory=Path('/var/lib/arm16k-virtio-seat/receipts');info=directory.lstat()
 assert directory.is_dir()and not directory.is_symlink()and info.st_uid==0 and info.st_mode&0o077==0
 value={'schema_version':1,'nonce':nonce,'stage':'failed','operation':'observer-stage',**schema.exception_data(error)}
 schema.validate('runtime-error-observer-stage.json',value,nonce)
 raw=(json.dumps(value,sort_keys=True)+'\n').encode();assert len(raw)<=4096
 fd=os.open(directory/'ui-observer-error.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  os.fchmod(fd,0o600)
  with os.fdopen(fd,'wb',closefd=False)as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
 finally:os.close(fd)
 fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def read(path,uid):
 s=path.lstat();assert path.is_file()and not path.is_symlink()and s.st_uid==uid and s.st_nlink==1 and s.st_size<128*1024;return json.loads(path.read_text())
def main():
 assert __debug__ and os.geteuid()==0 and os.uname().machine=='aarch64'and os.sysconf('SC_PAGE_SIZE')==16384
 nonce=Path('/etc/arm16k-virtio-seat-nonce').read_text().strip();until=time.monotonic()+360
 with open('/dev/ttyAMA0','w',buffering=1)as serial:
  try:
   # Both modules and their finite dependencies must load while Python is
   # installed, before normal ALPM removal can delete their runtime files.
   schema,result=validators()
   while time.monotonic()<until:
    failure=R/'failure.json'
    if failure.exists():
     value=read(failure,0);schema.validate('failure.json',value,nonce);serial.write('\nUI_HOLD '+nonce+' '+json.dumps({'stage':value['stage'],'error_label':value['error_label'],'category':'root-fixture-HOLD'})+'\n');return 1
    client=H/'UI_CLIENT_REPORT.json';removed=R/'removed.json'
    if client.exists():
     user=read(client,1000)
     if user['status']=='HOLD':raise RuntimeError('ordinary-client-HOLD')
     if removed.exists():break
    time.sleep(.1)
   else:raise TimeoutError('UI client/restoration bound')
   value={'client':user,'root':read(removed,0)};result.accept_ui(value)
   serial.write('\nUI_SESSION_BEGIN '+nonce+'\n'+json.dumps(value,sort_keys=True)+'\nUI_SESSION_END '+nonce+'\n');(R/'UI_VERIFIED').touch();return 0
  except BaseException as error:
   if 'schema'in locals():
    try:error_receipt(nonce,error,schema)
    except (OSError,AssertionError,ValueError):pass # Original failure still emits HOLD, never PASS.
   serial.write('\nUI_HOLD '+nonce+' '+json.dumps({'stage':'UI-result','category':type(error).__name__})+'\n');return 1
if __name__=='__main__':raise SystemExit(main())
