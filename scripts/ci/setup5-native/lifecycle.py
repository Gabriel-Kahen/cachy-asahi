#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actual dep-aware ALPM setup4→5→4→5 and ordinary installed user CLI route."""
import importlib.util
import json
import os
from pathlib import Path
import pwd
import stat


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def main():
    C=load('setup5_lifecycle_contract',Path('/runner/contract.py'));L=load('accepted_setup5_preservation',Path('/accepted/lifecycle.py'))
    L.need(os.getuid()==0 and os.getpid()==1 and Path('/.dockerenv').is_file() and os.uname().machine=='aarch64' and os.environ.get('CACHY_ASAHI_SETUP5_LIFECYCLE')=='1','dedicated native ARM container PID1 required')
    original=json.loads(Path('/inputs/base.json').read_text());products=json.loads(Path('/inputs/products.json').read_text());old=json.loads(Path('/inputs/setup4/product.json').read_text())
    L.need(len(original)==574 and C.PACKAGE not in original and L.inventory()==original and set(products)=={C.PACKAGE},'exact574 and one setup candidate required')
    new=products[C.PACKAGE];rows={'0.1.0-4':old,'0.1.0-5':new};archives={v:Path('/inputs/setup4' if v.endswith('-4') else '/inputs')/p['archive'] for v,p in rows.items()}
    for version,product in rows.items():
        L.need(product['version']==version and set(product['payload'])==set(C.files()) and archives[version].is_file() and not archives[version].is_symlink() and L.sha(archives[version])==product['sha256'],'exact versioned setup archive/payload required')
    hooks=Path('/tmp/setup5-hooks');hooks.mkdir();masked=set()
    for parent in ('/usr/share/libalpm/hooks','/etc/pacman.d/hooks','/builder-disabled-hooks'):
        for path in Path(parent).glob('*.hook'):
            if path.name not in masked:(hooks/path.name).symlink_to('/dev/null');masked.add(path.name)
    config=Path('/tmp/setup5-pacman.conf');config.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Optional\nHookDir = '+str(hooks)+'\n')
    pacman=['/usr/bin/pacman','--config',str(config),'--noconfirm']
    protected_paths=[Path('/etc/pacman.conf'),Path('/etc/fish'),Path('/etc/zsh')]
    def system():return {str(p):dict(root=L.entry(p),tree=L.snapshot(p) if p.is_dir() else None) if p.exists() else None for p in protected_paths}
    protected=system();account=pwd.getpwnam('alarm');profiles=(*C.LEGACY,'new-grouped-journal');homes={};progress={p:{} for p in profiles};events=[];raw_proofs=[]
    templates=Path('/tmp/setup5-inert');templates.mkdir(mode=0o755)
    names={'fish':'fish/config.fish','zsh':'zsh/config.zsh','hyprland':'hyprland/hyprland.lua'}
    for name in ('fish-bang-bang','fish-autopair','fish-done','zsh-autosuggestions','zsh-syntax-highlighting','zsh-history-substring-search'):names[name]=name+('/opt-in.fish' if name.startswith('fish-') else '/opt-in.zsh')
    for name,relative in names.items():
        path=templates/relative;path.parent.mkdir(mode=0o755);path.write_text(('--' if name=='hyprland' else '#')+' inert namespaced module fixture; never executed\n');path.chmod(0o644)
    missing=Path('/tmp/setup5-inert-missing');import shutil;shutil.copytree(templates,missing);(missing/'zsh-history-substring-search/opt-in.zsh').unlink()
    for profile in profiles:
        home=Path('/tmp')/('setup5-user-'+profile);home.mkdir(mode=0o700)
        for relative,text in (('.config/fish/config.fish','# original custom Fish\n'),('.zshrc','# original custom Zsh\n'),('outside-sentinel','preserve unrelated user bytes\n')):
            path=home/relative;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700);path.write_text(text);path.chmod(0o640)
        (home/'custom-link').symlink_to('outside-sentinel')
        for path in (home,*home.rglob('*')):os.chown(path,account.pw_uid,account.pw_gid,follow_symlinks=False)
        homes[profile]=home

    def snapshots():return {name:L.snapshot(home) for name,home in homes.items()}
    def check_system():L.need(system()==protected,'system shell/repository configuration changed')
    def installed(version):
        L.need(L.inventory()==original|{C.PACKAGE:version},'exact575 versioned inventory differs');L.command(pacman+['-Dk']);L.command(pacman+['-T','python>=3.11','gnupg','pacman'])
        product=rows[version];L.command(pacman+['-Qkk',C.PACKAGE]);owned=L.command(pacman+['-Qql',C.PACKAGE]).splitlines()
        L.need({p for p in owned if not p.endswith('/')}=={'/'+n for n in C.files()},'exact six-file ALPM ownership differs')
        for relative,row in product['payload'].items():
            path=Path('/')/relative;info=path.lstat();L.need(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==row['mode'] and L.sha(path)==row['sha256'],'installed source/license bytes or mode differ')
    def transition(label,version=None):
        before=snapshots();check_system()
        L.command(pacman+['--noscriptlet']+(['-U',str(archives[version])] if version else ['-R',C.PACKAGE]))
        if version:installed(version)
        else:
            L.need(L.inventory()==original,'full574 inventory not restored');L.command(pacman+['-Dk'])
            L.need(all(not os.path.lexists('/'+n) for n in C.files()),'removed setup payload remains')
        check_system();L.need(snapshots()==before,'ALPM transition changed user state/config/journals')
        events.append(dict(phase=label,status='PASS',inventory_count=575 if version else 574,homes_preserved=True,database_check=True))
    def exercise(phase,version):
        helper_sha=rows[version]['payload']['usr/bin/cachy-asahi-setup']['sha256']
        for profile,home in homes.items():
            env=dict(PATH='/usr/bin:/bin',HOME=str(home),LANG='C.UTF-8',LC_ALL='C.UTF-8',PYTHONDONTWRITEBYTECODE='1',CACHY_ASAHI_SETUP5_USER='1')
            raw=L.command(['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i',*(k+'='+v for k,v in env.items()),'/usr/bin/python3','-I','-B','/runner/exercise.py','--phase',phase,'--profile',profile,'--home',str(home),'--templates',str(templates),'--missing',str(missing),'--helper-sha256',helper_sha],timeout=60)
            value=json.loads(raw);L.need(value['status']=='PASS' and value['phase']==phase and value['profile']==profile and value['uid']==account.pw_uid and value['installed_helper_sha256']==helper_sha,'actual ordinary installed CLI proof identity differs')
            for key,status in value['cases'].items():L.need(key in C.CASES and status=='PASS','unknown or failed installed CLI case')
            progress[profile].update(value['cases']);raw_proofs.append(dict(phase=phase,profile=profile,sha256=L.sha(Path('/usr/bin/cachy-asahi-setup')),proof=value))
            # Closed proof contains statuses/identity only, never user config/state bytes.
            directory=Path('/out/observations');directory.mkdir(exist_ok=True);(directory/(profile+'-'+phase+'.json')).write_text(json.dumps(value,indent=2)+'\n')
        check_system()

    transition('install-setup4','0.1.0-4');exercise('legacy','0.1.0-4')
    transition('upgrade-setup5','0.1.0-5');exercise('upgrade','0.1.0-5')
    transition('same-version-reinstall-setup5','0.1.0-5')
    transition('rollback-setup4','0.1.0-4');exercise('rollback','0.1.0-4')
    transition('forward-setup5','0.1.0-5');exercise('forward','0.1.0-5')
    transition('remove-setup5');transition('reinstall-setup5','0.1.0-5');transition('final-remove-setup5')
    proofs=[dict(profile=p,cases=progress[p],uid=account.pw_uid,installed_helper_sha256=new['payload']['usr/bin/cachy-asahi-setup']['sha256']) for p in profiles]
    result=dict(status='PASS_SETUP5_INSTALLED_LEGACY_LIFECYCLE',base_count=574,events=events,proofs=proofs,actual_observations=raw_proofs,
        system_config_preserved=True,user_state_preserved_on_alpm=True,full574_restored=True,actual_page_size=os.sysconf('SC_PAGE_SIZE'),native_architecture='aarch64',masked_hooks=len(masked),hardware='NOT_RUN',trust='UNSIGNED_LOCAL_CANDIDATES_ONLY',fixture_scope='INERT_NAMESPACED_MODULE_FIXTURES_ONLY',real_module_acceptance='NOT_RUN')
    C.validate_lifecycle(result);Path('/out/lifecycle.json').write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()
