#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Execute held native trial and export its closed private-profile bytes as DATA."""
import argparse
import ast
import hashlib
import stat
import json
import os
import pwd
from pathlib import Path
import sys
import tarfile
import time
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import closed as C


def execute(source,output,context_sha):
    C.need(os.getpid()==1 and os.getuid()==0 and os.uname().machine=='aarch64' and Path('/.dockerenv').is_file(),'native private root PID1 required')
    account=pwd.getpwnam('alarm');C.need(account.pw_uid==account.pw_gid==1000,'retained rootfs alarm UID/GID1000 required')
    m=C.verify(source);data=source/C.DATA
    C.need(context_sha==m['held_context_sha256'],'held context digest differs')
    native=C.load(source/C.HELD/'native.py','held_native_real_shells')
    # Reuse only the exact two bounded preservation functions from accepted Setup8.
    raw=C.read(source/'scripts/ci/setup8-native/lifecycle.py')
    parsed=ast.parse(raw);functions=[n for n in parsed.body if isinstance(n,ast.FunctionDef) and n.name in ('sha','snapshot')]
    C.need(len(functions)==2,'held preservation function set differs')
    namespace=dict(os=os,stat=stat,hashlib=hashlib,C=C)
    exec(compile(ast.Module(body=functions,type_ignores=[]),'<held-setup8-preservation>','exec'),namespace)
    snapshot=namespace['snapshot'];original=native.C.command
    lock=json.loads(C.read(source/'scripts/ci/maintained-desktop574-inputs.json'))
    base={r['name']:r['version'] for r in lock['packages']}
    context=json.loads(C.read(data/'context.json'))
    products={'cachy-asahi-setup':'0.3.0-1',**{r['package']:r['version'] for r in context['packages'].values()}}
    paths=('/etc/pacman.conf','/etc/pacman.d','/etc/fish','/etc/zsh','/etc/skel')
    protected={name:snapshot(Path(name)) for name in paths};observations=[]
    def user_snapshot(parent):
        if not parent.exists():return None
        C.need({p.name for p in parent.iterdir()}=={'work'},'closed ordinary workspace registry differs')
        work=parent/'work';directories={'old-1.0-1','new-2.0-1','fresh','existing','conflict','interrupted','namespace-guard'}
        allowed=directories|{'migration.json','expected-homes.json','fixture-receipt.json','report.json','reinstall-report.json'}
        C.need({p.name for p in work.iterdir()}<=allowed and {p.name for p in work.iterdir() if p.is_dir()}==directories,'finite seven-partition private user tree differs')
        def metadata(path):
            s=path.lstat();return {key:getattr(s,key) for key in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_mtime_ns','st_ctime_ns')}
        return dict(roots={'.':metadata(parent),'work':metadata(work)},partitions={p.name:snapshot(p) for p in sorted(work.iterdir())})
    phases=('install','repeat-install','remove','reinstall','final-remove')
    reaping=[]
    def drain_adopted():
        # The synchronous subprocess.run child has already been waited by held C.command.
        # No SIGCHLD handler or concurrent Popen wait is used.
        deadline=time.monotonic()+2;rows=[]
        while True:
            try:pid,status=os.waitpid(-1,os.WNOHANG)
            except ChildProcessError:return rows
            if pid:rows.append(dict(pid=pid,wait_status=status));continue
            if time.monotonic()>=deadline:return rows
            time.sleep(.02)
    def observed(argv,**kwargs):
        is_transaction=str(argv[0])=='/usr/bin/pacman' and '--config' in argv and ('-U' in argv or '-R' in argv)
        user_before=user_snapshot(output/'ordinary') if is_transaction else None
        result=original(argv,**kwargs)
        if str(argv[0])=='/usr/bin/runuser':reaping.append(dict(command_index=len(reaping),reaped=drain_adopted()))
        if is_transaction:
            index=len(observations);C.need(index<len(phases),'finite five-transaction observation set')
            installed='-U' in argv
            inventory=dict(line.split() for line in original(['/usr/bin/pacman','-Q']).stdout.decode().splitlines())
            C.need(inventory==(base|products if installed else base),'exact574/583 package inventory differs')
            files={n:r for n,r in context['stage_tree'].items() if r['kind']=='file'}
            if installed:
                union=set()
                for name,version in products.items():
                    C.need(original(['/usr/bin/pacman','-Q',name]).stdout.decode().strip()==name+' '+version,'nine installed versions differ')
                    owned=original(['/usr/bin/pacman','-Qql',name]).stdout.decode().splitlines()
                    union.update(p.lstrip('/') for p in owned if not p.endswith('/'))
                C.need(union==set(files),'complete installed nine-package ownership differs')
                for n,row in files.items():
                    path=Path('/')/n;item=path.lstat()
                    C.need(stat.S_ISREG(item.st_mode) and item.st_uid==item.st_gid==0 and stat.S_IMODE(item.st_mode)==row['mode'] and native.C.digest(path)==row['sha256'],'actual installed package bytes/mode/owner differ')
            else:C.need(all(not os.path.lexists('/'+n) for n in files),'removed payload leaf remains')
            user_after=user_snapshot(output/'ordinary')
            C.need(user_after==user_before and {n:snapshot(Path(n)) for n in paths}==protected,'ALPM changed user/protected inode metadata or bytes')
            observations.append(dict(phase=phases[index],inventory=inventory,products=products if installed else {},payload_files=len(files) if installed else 0,user_before=user_before,user_after=user_after,protected=protected,preserved=True))
        return result
    native.C.command=observed
    try:result=native.native(data,output,context_sha)
    finally:native.C.command=original
    C.need(len(observations)==5,'all five original transactions observed')
    C.save(output/'adopted-reaping.json',reaping)
    C.save(output/'alpm-observations.json',observations)
    result['adopted_reaping_sha256']=C.digest(output/'adopted-reaping.json')
    result['alpm_observations_sha256']=C.digest(output/'alpm-observations.json')
    parent=output/'ordinary';before=native.C.tree(parent)
    archive=output/'user-profiles.tar.xz'
    with tarfile.open(archive,'w:xz') as tar:
        for path in (parent,*sorted(parent.rglob('*'))):
            row=tar.gettarinfo(str(path),'ordinary/'+str(path.relative_to(parent)))
            if path.is_file():
                with path.open('rb') as stream:tar.addfile(row,stream)
            else:tar.addfile(row)
    C.need(native.C.tree(parent)==before,'profile DATA export changed live tree')
    xattrs={str(p.relative_to(parent)):{key:os.getxattr(p,key).hex() for key in os.listxattr(p)} for p in (parent,*sorted(parent.rglob('*')))}
    C.save(output/'user-profile-xattrs.json',xattrs)
    result.update(user_archive=dict(bytes=archive.stat().st_size,sha256=C.digest(archive)),user_xattrs_sha256=C.digest(output/'user-profile-xattrs.json'),actual_source=None,actual_ref=None,actual_run=None)
    C.save(output/'native-report.json',result)
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser()
    for n in ('source','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--context-sha256',required=True);a=p.parse_args()
    print(json.dumps(execute(C.safe(a.source.absolute()),C.safe(a.output.absolute()),a.context_sha256),indent=2))
