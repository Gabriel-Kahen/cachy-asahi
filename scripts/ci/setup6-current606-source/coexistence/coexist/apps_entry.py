#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real installed Apps7 CLI and original15 controls, both ordinary private homes."""
import ctypes,hashlib,importlib.util,json,os,pwd,stat,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from native_api import C

def main():
 if sys.argv[1:]==['--help']:print('Native-only Apps7 two-home readonly installed controls');return
 C.need(len(sys.argv)==4,'verification home, fresh private output, exact inventory');keys,work,expected=map(Path,sys.argv[1:]);C.native_scope('/',keys,'/out/setup6-native.log');C.need(work.parent==Path('/tmp')and work.name.startswith('coexist-apps-')and work.is_dir()and not any(work.iterdir())and expected.parent==Path('/out')and expected.name.startswith('coexist-expected-'),'fixed private native fixture operands');wanted=C.decode(C.ordinary(expected));C.need(len(wanted)in(605,606)and wanted['cachy-asahi-apps']=='0.1.0-7'and wanted['cachy-asahi-repository-runtime']=='0.1.0-1','exact Apps7-present phase inventory')
 account=pwd.getpwnam('alarm');C.need(account.pw_uid>0 and work.stat().st_uid==account.pw_uid and stat.S_IMODE(work.stat().st_mode)==0o700,'ordinary owned private parent');os.setgroups([]);os.setgid(account.pw_gid);os.setuid(account.pw_uid)
 class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
 class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
 libc=ctypes.CDLL(None,use_errno=True);header=Header(0x20080522,0);data=(Data*2)();C.need(libc.capset(ctypes.byref(header),ctypes.byref(data))==0 and libc.prctl(47,4,0,0,0)==0 and libc.prctl(38,1,0,0,0)==0,'ordinary zero capabilities/ambient and NNP');state=dict(line.split(':',1)for line in Path('/proc/self/status').read_text().splitlines()if':'in line);C.need(all(int(state[k],16)==0 for k in('CapEff','CapPrm','CapInh','CapAmb'))and int(state['CapBnd'],16)==0xdb and int(state['NoNewPrivs'])==1,'actual original bounded ordinary process security')
 import subprocess
 context=Path('/runner/copyworker/held-apps');spec=importlib.util.spec_from_file_location('_whole_original_apps7_installed_controls',context/'fixture_checks.py');fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture);receipts={}
 for name in('fresh','existing'):
  home=work/name;home.mkdir(mode=0o700);sentinel=home/'user-owned.conf'
  if name=='existing':sentinel.write_bytes(b'coexistence-user-config\n')
  before=sentinel.read_bytes()if sentinel.exists()else None;os.environ.clear();os.environ.update(PATH='/usr/bin:/bin',HOME=str(home),LANG='C.UTF-8',LC_ALL='C.UTF-8',PYTHONDONTWRITEBYTECODE='1');os.chdir(home)
  def call(argv,seconds):
   r=subprocess.run(argv,stdin=subprocess.DEVNULL,capture_output=True,timeout=seconds);C.need(r.returncode==0 and len(r.stdout)+len(r.stderr)<=128*1024,'actual installed Apps7 CLI command');return r
  result=call(['/usr/bin/cachy-asahi-apps','--help'],15);C.need(b'inventory'in result.stdout,'actual installed readonly inventory help');snapshot=home/'actual-inventory.json';result=call(['/usr/bin/cachy-asahi-apps','inventory','--dbpath','/var/lib/pacman/local','--output',str(snapshot)],40);reply=json.loads(result.stdout);raw=snapshot.read_bytes();metadata=snapshot.lstat();C.need(0<len(raw)<=16*1024**2 and stat.S_ISREG(metadata.st_mode)and metadata.st_nlink==1 and metadata.st_uid==os.getuid()and reply['applied']=='NOT_APPLIED'and reply['sha256']==hashlib.sha256(raw).hexdigest(),'actual readonly own snapshot');rows=json.loads(raw)['packages'];inventory={r['name']:r['version']for r in rows};C.need(len(rows)==len(inventory)and inventory==wanted,'whole actual Apps7 frontend inventory equals exact phase graph');snapshot.unlink();controls=fixture.run_suite('apps',fixtures=context);C.need(controls['tests']==15 and controls['status']=='PASS_INSTALLED_CONTROLS'and controls['installed_source']is True,'all15 actual installed Apps7 controls');C.need((sentinel.read_bytes()if sentinel.exists()else None)==before,'existing/fresh user configuration held');receipts[name]=dict(CLI=2,inventory_count=len(inventory),inventory_versions_sha256=hashlib.sha256(''.join(n+' '+v+'\n'for n,v in sorted(inventory.items())).encode()).hexdigest(),installed_controls=controls,user_config_preserved=True)
 print(json.dumps(dict(status='PASS_ACTUAL_NATIVE_APPS7_BOTH_HOMES',homes=receipts,zero_capabilities=True,NNP=1,CapBnd='00000000000000db',applied='NOT_APPLIED'),sort_keys=True))
if __name__=='__main__':main()
