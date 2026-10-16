#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root guest entry; launch one ordinary, no-capability installer trial."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

SHARED=Path('/usr/local/share/full-installer')
PASS='PASS_FULL_COMPOSITION_INSTALLER'


def need(value,reason):
    if not value: raise ValueError(reason)


def emit(nonce,value):
    raw=json.dumps(value,sort_keys=True,separators=(',',':'))
    need(len(raw.encode())<=1024**2,'guest result byte limit')
    print('FULL_INSTALLER '+nonce+' '+raw,flush=True)


def pinned_sources(c):
    for name in ('guest.py','installer.py','profile.py','installer-profile.json','payload.json'):
        path=SHARED/name; ref=c['runner_files'][name]
        need(not any(p.is_symlink() for p in (path,*path.parents)),'ordinary guest source required')
        info=path.stat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and info.st_nlink==1 and
             not info.st_mode & 0o022 and info.st_size==ref['bytes'],'guest source protection differs')
        with path.open('rb') as stream: digest=hashlib.file_digest(stream,'sha256').hexdigest()
        need(digest==ref['sha256'],'guest source bytes differ')


def main():
    need(sys.argv[1:]==['boot'] and os.getuid()==os.geteuid()==0 and os.getgid()==0 and
         os.uname().machine=='aarch64' and os.uname().release=='7.2.10-1-aarch64-ARCH' and
         os.sysconf('SC_PAGE_SIZE')==4096,'fixed generic4K root guest entry required')
    need(os.environ.get('CACHY_ASAHI_FULL_INSTALLER_GUEST')=='1' and
         'cachy_asahi_virtual_proof=1' in Path('/proc/cmdline').read_text().split(),'systemd/VM marker required')
    c=json.loads((SHARED/'contract.json').read_bytes()); nonce=c['nonce']
    pinned_sources(c)
    emit(nonce,dict(event='boot',scope='generic-arm-full-installer-software',page_size=4096,kernel=os.uname().release,uid=0))
    status='FAIL'; cleanup='FAIL'; result=dict(event='result',status='FAIL',phase='guest-bootstrap')
    try:
        spec=importlib.util.spec_from_file_location('_installer_guest_profile',SHARED/'profile.py')
        p=importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
        for name,row in c['code_files'].items(): p.checked(SHARED/'code',name,row,maximum=2*1024**2,protected=True)
        held=p.constants(SHARED/'code/scripts/virtual/common.py',{'TRANSACTION_LAUNCHER'})['TRANSACTION_LAUNCHER']
        for alias,target in held['aliases'].items(): need(str(Path(alias).resolve(strict=True))==target,'launcher alias differs')
        for name,row in held['files'].items(): p.checked(Path('/'),name.lstrip('/'),row,maximum=64*1024**2,protected=True)
        need(not Path('/etc/ld.so.preload').exists() and not Path('/etc/ld.so.preload').is_symlink(),'launcher preload refused')
        trial=Path('/var/lib/full-installer/trial')
        need(not trial.exists() and not trial.is_symlink(),'fresh guest trial required')
        trial.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        need(not any(x.is_symlink() for x in (trial.parent,*trial.parent.parents)),'ordinary disk trial parent required')
        trial.mkdir(mode=0o700); os.chown(trial,23001,23001)
        # Explicit held ELF loader + library closure avoids host loader settings.
        argv=['/usr/lib/ld-linux-aarch64.so.1','--inhibit-cache','--glibc-hwcaps-mask','',
            '--library-path','/usr/lib','/usr/bin/setpriv','--reuid=23001','--regid=23001','--clear-groups',
            '--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all','--no-new-privs','--',
            '/usr/bin/python3','-I','-B',str(SHARED/'installer.py'),'run']
        # The same selected source owns process-group retirement at both levels.
        spec=importlib.util.spec_from_file_location('_installer_guest_worker',SHARED/'installer.py')
        worker=importlib.util.module_from_spec(spec); spec.loader.exec_module(worker)
        receipt=worker.supervise(argv,env=dict(PATH='/usr/bin:/bin',LC_ALL='C',HOME=str(trial),TMPDIR=str(trial)),timeout=4650)
        rows=receipt.pop('output').decode('utf-8').splitlines()
        need(len(rows)==1,'exact one ordinary installer result required')
        result=json.loads(rows[0]); need(type(result) is dict,'installer result must be object')
        result['event']='result'
        need(receipt['returncode']==0 and receipt['termination'] is None and receipt['direct_child_reaped'] and
             receipt['group_retired'] and result.get('status')==PASS,'ordinary installer failed')
        status=PASS; cleanup='PASS'
    except BaseException as error:
        status='FAIL'; result.update(status='FAIL',guest_error_type=type(error).__name__,guest_error=str(error)[:512])
        # Group retirement is explicit in supervise; all exceptions fail closed.
        cleanup='FAIL'
    emit(nonce,result)
    emit(nonce,dict(event='exit',status=status,cleanup=cleanup))
    # Natural QEMU shutdown remains separate from receipt completion.
    row=subprocess.run(['/usr/bin/systemctl','poweroff','--no-block'],env=dict(PATH='/usr/bin:/bin',LC_ALL='C'),
                       stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
    need(row.returncode==0,'guest poweroff request failed')
    return int(status!=PASS)


if __name__=='__main__': sys.exit(main())
