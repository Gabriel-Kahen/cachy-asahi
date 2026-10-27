#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline native container entry; Root supplies the existing disposable builder image."""
import argparse
import json
import os
from pathlib import Path
import pwd
import shutil
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as C


def native(context,output,expected):
    C.need(os.getuid()==os.geteuid()==0 and os.getpid()==1 and os.uname().machine=='aarch64'
        and Path('/.dockerenv').is_file() and os.environ.get('CACHY_SETUP8_REAL_SHELL_CONTAINER')=='1',
        'marked disposable native ARM container root PID1 required')
    C.need(C.digest(context/'context.json')==expected,'externally reviewed context digest differs')
    meta=C.verify_context(context)
    C.need(not output.exists(),'fresh native output required');output.mkdir(mode=0o755)
    account=pwd.getpwnam('alarm');C.need(account.pw_uid>0,'ordinary alarm builder required')
    C.command(['/usr/bin/pacman','-T','python>=3.11','gnupg','fish>=4.9.3','zsh>=5.9','libnotify','coreutils','base-devel'])
    base=C.command(['/usr/bin/pacman','-Q']).stdout
    protected={str(p):C.tree(p) if p.is_dir() else C.digest(p) if p.is_file() else None
        for p in map(Path,('/etc/pacman.conf','/etc/fish','/etc/zsh','/etc/skel'))}
    def unchanged():
        for name,before in protected.items():
            p=Path(name);C.need((C.tree(p) if p.is_dir() else C.digest(p) if p.is_file() else None)==before,'protected config changed: '+name)
    names=['cachy-asahi-setup']+[v['package'] for v in meta['packages'].values()]
    installed={line.split()[0] for line in base.decode().splitlines()}
    C.need(not set(names)&installed,'trial packages must be absent from base')
    build=output/'build';build.mkdir(mode=0o755)
    archives=[context/'setup8.pkg.tar.xz'];builds=[]
    for component,row in meta['packages'].items():
        work=build/component;shutil.copytree(context/row['source'],work)
        for p in (work,*work.rglob('*')):os.chown(p,account.pw_uid,account.pw_gid)
        result=C.command(['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i','PATH=/usr/bin:/bin','HOME='+str(work),
            'LANG=C.UTF-8','PYTHONDONTWRITEBYTECODE=1','PKGEXT=.pkg.tar.xz',
            '/usr/bin/makepkg','--nodeps','--holdver','--noconfirm'],cwd=work,timeout=180)
        (output/(component+'-build.stdout')).write_bytes(result.stdout)
        (output/(component+'-build.stderr')).write_bytes(result.stderr)
        matches=list(work.glob(row['package']+'-'+row['version']+'-*.pkg.tar.*'))
        matches=[p for p in matches if not p.name.endswith('.sig')]
        C.need(len(matches)==1,'one native archive required');archives.extend(matches)
        builds.append(dict(component=component,archive=str(matches[0].relative_to(output)),sha256=C.digest(matches[0])))
    # Suppress host-style package hooks and scriptlets in this finite offline container.
    hooks=output/'hooks';hooks.mkdir();seen=set()
    for directory in ('/etc/pacman.d/hooks','/usr/share/libalpm/hooks','/builder-disabled-hooks'):
        for path in Path(directory).glob('*.hook'):
            if path.name not in seen:(hooks/path.name).symlink_to('/dev/null');seen.add(path.name)
    conf=output/'pacman.conf';conf.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Optional\nHookDir = '+str(hooks)+'\n')
    pacman=['/usr/bin/pacman','--config',str(conf),'--noconfirm','--noscriptlet']
    events=[]
    def transaction(phase,args):
        r=C.command(pacman+args,timeout=120);unchanged()
        events.append(dict(phase=phase,stdout_sha256=C.sha(r.stdout),stderr_sha256=C.sha(r.stderr)))
        (output/(phase+'.stdout')).write_bytes(r.stdout);(output/(phase+'.stderr')).write_bytes(r.stderr)
        C.command(['/usr/bin/pacman','-Dk'])
    transaction('install',['-U',*archives])
    parent=output/'ordinary';parent.mkdir(mode=0o700);os.chown(parent,account.pw_uid,account.pw_gid)
    work=parent/'work'
    def ordinary_absent():
        entries=list(Path('/proc').iterdir());C.need(len(entries)<1024,'finite private process namespace required')
        for entry in entries:
            if not entry.name.isdigit():continue
            try:raw=(entry/'status').read_text()
            except FileNotFoundError:continue
            uids=[line.split()[1:] for line in raw.splitlines() if line.startswith('Uid:')]
            C.need(len(uids)==1 and str(account.pw_uid) not in uids[0],'ordinary trial process remains')
    def trial(reinstall=False):
        argv=['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i','PATH=/usr/bin:/bin','HOME='+str(parent),
            '/usr/bin/python3','-I','-B',str(context/'trial.py'),'--context',str(context),'--work',str(work),'--installed']
        if reinstall:argv.append('--verify-reinstall')
        r=C.command(argv,timeout=240);(output/('reinstall.json' if reinstall else 'trial.json')).write_bytes(r.stdout)
        return json.loads(r.stdout)
    report=trial();ordinary_absent();before=C.tree(parent)
    transaction('repeat-install',['-U',*archives]);C.need(C.tree(parent)==before,'repeat ALPM changed user homes')
    transaction('remove',['-R',*names]);C.need(C.tree(parent)==before,'ALPM removal changed user homes')
    C.need(C.command(['/usr/bin/pacman','-Q']).stdout==base,'base not restored after removal')
    transaction('reinstall',['-U',*archives]);C.need(C.tree(parent)==before,'ALPM reinstall changed user homes')
    reinstalled=trial(True);ordinary_absent();before=C.tree(parent)
    transaction('final-remove',['-R',*names]);C.need(C.tree(parent)==before,'final ALPM removal changed user homes')
    C.need(C.command(['/usr/bin/pacman','-Q']).stdout==base,'exact base inventory not restored')
    result=dict(status='PASS_FINITE_NATIVE_SETUP8_REAL_SHELL_COMPOSITION',trial=report,reinstall=reinstalled,
        builds=builds,events=events,actual_page_size=os.sysconf('SC_PAGE_SIZE'),machine=os.uname().machine,
        preserved_user_tree=C.tree(parent),base_inventory_sha256=C.sha(base),protected_configuration_preserved=True,
        trust='UNSIGNED_LOCAL_TEST_PACKAGES',physical_M2='NOT_RUN',release='NOT_ADMITTED',
        cleanup='CONTAINER_RETIREMENT_BY_ROOT_REQUIRED; OUTPUT_RETAINS_DISPOSABLE_USER_PROFILES')
    C.save(output/'native-report.json',result)
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('context','output'):p.add_argument('--'+n,type=Path,required=True)
    p.add_argument('--context-sha256',required=True)
    a=p.parse_args();print(json.dumps(native(a.context.absolute(),a.output.absolute(),a.context_sha256),indent=2))
