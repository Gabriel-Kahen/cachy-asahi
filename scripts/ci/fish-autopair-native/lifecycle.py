#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Single-package ALPM lifecycle and the actual installed14-case Fish PTYs."""
import importlib.util
import json
import os
from pathlib import Path
import pwd
import stat


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module


def absent_environment(helper,home,session):
    # Fish --no-config skips reading configuration but can still initialize its
    # XDG config tree. Keep probe-generated state outside the protected HOME.
    environment=helper.user_environment(home,session)
    environment['XDG_CONFIG_HOME']=str(session/'fish-config')
    return environment


def main():
    C=load('fish_lifecycle_contract','/runner/contract.py');L=load('accepted_fish_preservation','/accepted/lifecycle.py')
    L.need(os.getuid()==0 and os.getpid()==1 and Path('/.dockerenv').is_file() and os.uname().machine=='aarch64' and
           os.environ.get('CACHY_ASAHI_FISH_AUTOPAIR_LIFECYCLE')=='1','dedicated native ARM container PID1 required')
    original=json.loads(Path('/inputs/base.json').read_text());products=json.loads(Path('/inputs/products.json').read_text())
    L.need(set(products)=={C.PACKAGE} and len(original)==574 and L.inventory()==original,'exact574 and one Fish package required')
    product=products[C.PACKAGE];archive=Path('/inputs')/product['archive']
    L.need(archive.parent==Path('/inputs') and archive.is_file() and not archive.is_symlink() and
           L.sha(archive)==product['sha256'] and set(product['payload'])==set(C.files()),'exact Fish archive/payload required')
    wrapper='usr/share/cachy-asahi/fish-autopair/opt-in.fish';wrapper_sha=product['payload'][wrapper]['sha256']
    hooks=Path('/tmp/fish-hooks');hooks.mkdir();masked=set()
    for parent in ('/usr/share/libalpm/hooks','/etc/pacman.d/hooks','/builder-disabled-hooks'):
        for path in Path(parent).glob('*.hook'):
            if path.name not in masked:(hooks/path.name).symlink_to('/dev/null');masked.add(path.name)
    config=Path('/tmp/fish-pacman.conf');config.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Optional\nHookDir = '+str(hooks)+'\n')
    pacman=['/usr/bin/pacman','--config',str(config),'--noconfirm','--noscriptlet']
    system=Path('/etc/fish');protected=dict(root=L.entry(system),tree=L.snapshot(system)) if system.exists() else None
    account=pwd.getpwnam('alarm');homes=[];sessions={};receipts={};events=[]
    for kind in ('fresh','existing'):
        home=Path('/tmp')/('fish-home-'+kind);home.mkdir(mode=0o700)
        if kind=='existing':
            for name,text in (('.config/fish/config.fish','# preserve custom Fish config\nbind -M default ctrl-x true\n'),
                              ('.config/fish/conf.d/user.fish','# preserve explicit opt-in choices\n'),
                              ('.config/fish/fish_variables','# preserve existing universal variables\n'),
                              ('.local/share/fish/fish_history','preserve original history bytes\n')):
                path=home/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text);path.chmod(0o600)
            (home/'.config/fish/config-alias').symlink_to('config.fish')
        output=Path('/tmp')/('fish-output-'+kind);output.mkdir(mode=0o700);(output/'outside').write_text('preserve user-owned outside file\n')
        sessions[home]=L.session_paths(home,output)
        (sessions[home]/'fish-config').mkdir(mode=0o700)
        for path in (home,*home.rglob('*'),output,*output.rglob('*')):os.chown(path,account.pw_uid,account.pw_gid,follow_symlinks=False)
        homes.append((home,L.snapshot(home),output,L.entry(output/'outside')))

    def user(home,argv,*,absent_probe=False):
        environment=absent_environment(L,home,sessions[home]) if absent_probe else L.user_environment(home,sessions[home])
        return L.command(['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i',
            *(key+'='+value for key,value in environment.items()),*argv],timeout=150)

    def preserve():
        for home,before,output,outside in homes:L.preservation_check(home,before,output,outside)
        now=dict(root=L.entry(system),tree=L.snapshot(system)) if system.exists() else None
        L.need(now==protected,'system Fish configuration changed')
        L.need(all(L.entry(path)==pin for path,pin in receipts.items()),'user Fish receipt changed')

    def installed(label):
        L.need(L.inventory()==original|{C.PACKAGE:product['version']},'exact575 installed inventory differs')
        L.command(['/usr/bin/pacman','-Qkk',C.PACKAGE]);owned=L.command(['/usr/bin/pacman','-Qql',C.PACKAGE]).splitlines()
        L.need({p for p in owned if not p.endswith('/')}=={'/'+p for p in product['payload']},'Fish ALPM ownership list differs')
        for relative,row in product['payload'].items():
            path=Path('/')/relative;info=path.lstat()
            L.need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==row['mode'] and info.st_uid==info.st_gid==0 and
                   L.sha(path)==row['sha256'],'installed Fish/source/license identity differs')
        observations=[]
        for home,_,output,_ in homes:
            work=output/label;work.mkdir(mode=0o700);os.chown(work,account.pw_uid,account.pw_gid)
            summary=json.loads(user(home,['/usr/bin/python3','-I','-B','/inputs/sources/'+C.PACKAGE+'/check-module.py',
                '--source','/usr/share/cachy-asahi/fish-autopair','--output',str(work/'results')]))
            receipt=work/'results/receipt.json';proof=json.loads(receipt.read_text());C.validate_pty(proof,wrapper_sha)
            L.need(summary['status']=='PASS' and summary['cases']==14 and summary['receipt']==str(receipt),'Fish child/parent receipt identity differs')
            receipts[receipt]=L.entry(receipt)
            observations.append(dict(home=home.name,proof=proof,receipt_sha256=L.sha(receipt),fish_sha256=L.sha(Path('/usr/bin/fish'))))
        preserve();events.append(dict(phase=label,status='PASS',inventory_count=575,observations=observations,config_preserved=True))

    def absent(label):
        L.need(L.inventory()==original,'exact574 inventory not restored')
        for relative in product['payload']:L.need(not os.path.lexists(Path('/')/relative),'Fish addon payload remained')
        for home,_,_,_ in homes:
            user(home,['/usr/bin/fish','--no-config','--command',
                'if test -r /usr/share/cachy-asahi/fish-autopair/opt-in.fish; source /usr/share/cachy-asahi/fish-autopair/opt-in.fish; end; '+
                'functions --query _autopair_backspace; and exit 31; exit 0'],absent_probe=True)
        preserve();events.append(dict(phase=label,status='PASS',inventory_count=574,config_preserved=True,guarded_opt_in_absent=True))

    archives=[str(archive)]
    for label in ('install','same-version-reinstall'):L.command(pacman+['-U',*archives]);installed(label)
    L.command(pacman+['-R',C.PACKAGE]);absent('remove')
    L.command(pacman+['-U',*archives]);installed('reinstall-after-removal')
    L.command(pacman+['-R',C.PACKAGE]);absent('final-remove')
    result=dict(status='PASS_FISH_AUTOPAIR_INSTALLED_LIFECYCLE',events=events,base_count=574,installed_count=575,
        user_config_preserved=True,system_config_preserved=True,user_outputs_preserved=True,masked_hooks=len(masked),
        actual_page_size=os.sysconf('SC_PAGE_SIZE'),hardware='NOT_RUN',native_architecture='aarch64',wrapper_sha256=wrapper_sha,
        trust='UNSIGNED_LOCAL_CANDIDATE_ONLY')
    C.validate_lifecycle(result);Path('/out/lifecycle.json').write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()
