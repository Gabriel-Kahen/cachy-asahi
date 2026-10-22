#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Drop this owned foreground process to alarm, then exec exact original real240."""
import ctypes,os,pwd,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from native_api import C

def main():
 if sys.argv[1:]==['--help']:print('Native-only ordinary Setup240: exact verification home and one fresh owned real-module workspace');return
 C.need(len(sys.argv)==3,'fixed verification home and fresh owned phase output');keys,work=map(Path,sys.argv[1:]);C.native_scope('/',keys,'/out/setup6-native.log');account=pwd.getpwnam('alarm');C.need(account.pw_uid>0 and account.pw_gid>0 and work.parent==Path('/tmp')and work.name in('coexist-setup-install-setup6','coexist-setup-same-setup6','coexist-setup-forward-setup6','coexist-setup-reinstall-setup6')and work.is_dir()and not(work/'work').exists(),'one of four private real-module workspaces')
 C.need(not any(p.is_symlink()for p in(work,*work.parents))and work.stat().st_uid==account.pw_uid and work.stat().st_mode&0o777==0o700,'ordinary-owned actual workspace')
 os.setgroups([]);os.setgid(account.pw_gid);os.setuid(account.pw_uid)
 class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
 class Data(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
 libc=ctypes.CDLL(None,use_errno=True);header=Header(0x20080522,0);data=(Data*2)();C.need(libc.capset(ctypes.byref(header),ctypes.byref(data))==0 and libc.prctl(47,4,0,0,0)==0 and libc.prctl(38,1,0,0,0)==0,'ordinary capability/ambient drop and NNP')
 source=Path('/runner/setup240');entry=source/'scripts/ci/setup6-real-modules/installed.py';environment=dict(PATH='/usr/bin:/bin',HOME=str(work),LANG='C.UTF-8',LC_ALL='C.UTF-8',PYTHONDONTWRITEBYTECODE='1',CACHY_SETUP6_REAL_USER='1');os.chdir(work);os.execve('/usr/bin/python3',['/usr/bin/python3','-I','-B',str(entry),'--source',str(source),'--output',str(work/'work')],environment)
if __name__=='__main__':main()
