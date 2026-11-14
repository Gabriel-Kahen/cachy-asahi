#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Two fixed non-root makepkg operations for this candidate, never install."""
import hashlib
import json
import os
import resource
from pathlib import Path
import shutil
import subprocess
import time


def main():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    assert os.geteuid()!=0,'ordinary user required'
    root=Path('/work');assert not (root/'recipe').exists(),'fresh container workspace required'
    shutil.copytree('/opt/input',root/'recipe')
    (root/'recipe').chmod(0o700)
    for path in (root/'recipe').rglob('*'):
        path.chmod(0o700 if path.is_dir() else 0o600)
    for name in ['home','tmp','runtime','xdg-config','xdg-cache','xdg-data','results']:(root/name).mkdir(mode=0o700)
    env={'PATH':'/usr/bin:/bin','HOME':'/work/home','TMPDIR':'/work/tmp','XDG_RUNTIME_DIR':'/work/runtime',
         'XDG_CONFIG_HOME':'/work/xdg-config','XDG_CACHE_HOME':'/work/xdg-cache','XDG_DATA_HOME':'/work/xdg-data',
         'LC_ALL':'C.UTF-8','MAKEFLAGS':'-j2','SOURCE_DATE_EPOCH':'1794614400'}
    report={'schema_version':1,'scope':'x86_64 source/profile/software test only','uid':os.geteuid(),
            'source_input':'root-owned readonly /opt/input; private writable /work','network':'container-none required by caller',
            'commands':[],'host_install':False,'native_ARM':'NOT RUN','hardware':'NOT RUN','status':'HOLD'}
    deadline=time.monotonic()+1500
    commands=[['makepkg','--ignorearch','--verifysource','--noconfirm'],
              ['makepkg','--ignorearch','--cleanbuild','--nosign','--noconfirm']]
    for i,argv in enumerate(commands):
        path=root/'results'/('command-'+str(i)+'.log');started=time.monotonic()
        try:
            with path.open('wb')as log:
                result=subprocess.run(argv,cwd=root/'recipe',env=env,stdout=log,stderr=subprocess.STDOUT,timeout=max(1,deadline-time.monotonic()))
            code=result.returncode
        except subprocess.TimeoutExpired:code=124
        report['commands'].append({'argv':argv,'exit':code,'seconds':round(time.monotonic()-started,3),'log':path.name})
        (root/'results/result.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report['commands'][-1]),flush=True)
        if code:break
    success=len(report['commands'])==2 and all(row['exit']==0 for row in report['commands'])
    report['status']='PASS_HOST_SOFTWARE_ONLY'if success else'HOLD_BUILD_OR_TEST_REFUSAL'
    for path in (root/'recipe/src/build/meson-logs').glob('*'):
        if path.is_file():shutil.copyfile(path,root/'results'/path.name)
    for path in (root/'recipe').glob('*.pkg.tar.*'):
        if path.is_file():
            with path.open('rb')as stream:sha=hashlib.file_digest(stream,'sha256').hexdigest()
            report.setdefault('host_archives',[]).append({'name':path.name,'bytes':path.stat().st_size,'sha256':sha,'native_ARM':False})
    (root/'results/result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True)
    return 0 if success else report['commands'][-1]['exit']


if __name__=='__main__':
    raise SystemExit(main())
