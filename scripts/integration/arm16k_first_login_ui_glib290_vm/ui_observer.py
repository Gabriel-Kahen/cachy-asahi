#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded root UI frame; original ARM observer independently proves real seat."""
import importlib.util,json,os,time
from pathlib import Path
H=Path('/home/builder');R=Path('/run/ui-session')
def read(path,uid):
 s=path.lstat();assert path.is_file()and not path.is_symlink()and s.st_uid==uid and s.st_nlink==1 and s.st_size<128*1024;return json.loads(path.read_text())
def main():
 assert __debug__ and os.geteuid()==0 and os.uname().machine=='aarch64'and os.sysconf('SC_PAGE_SIZE')==16384
 nonce=Path('/etc/arm16k-virtio-seat-nonce').read_text().strip();until=time.monotonic()+360
 with open('/dev/ttyAMA0','w',buffering=1)as serial:
  try:
   while time.monotonic()<until:
    failure=R/'failure.json'
    if failure.exists():
     value=read(failure,0);spec=importlib.util.spec_from_file_location('UI_error_schema','/usr/local/libexec/ui-receipts.py');schema=importlib.util.module_from_spec(spec);spec.loader.exec_module(schema);schema.validate('failure.json',value,nonce);serial.write('\nUI_HOLD '+nonce+' '+json.dumps({'stage':value['stage'],'error_label':value['error_label'],'category':'root-fixture-HOLD'})+'\n');return 1
    client=H/'UI_CLIENT_REPORT.json';removed=R/'removed.json'
    if client.exists():
     user=read(client,1000)
     if user['status']=='HOLD':raise RuntimeError('ordinary-client-HOLD')
     if removed.exists():break
    time.sleep(.1)
   else:raise TimeoutError('UI client/restoration bound')
   value={'client':user,'root':read(removed,0)};s=importlib.util.spec_from_file_location('ARM_ui_result','/usr/local/libexec/ui-result.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m);m.accept_ui(value)
   serial.write('\nUI_SESSION_BEGIN '+nonce+'\n'+json.dumps(value,sort_keys=True)+'\nUI_SESSION_END '+nonce+'\n');(R/'UI_VERIFIED').touch();return 0
  except BaseException as error:serial.write('\nUI_HOLD '+nonce+' '+json.dumps({'stage':'UI-result','category':type(error).__name__})+'\n');return 1
if __name__=='__main__':raise SystemExit(main())
