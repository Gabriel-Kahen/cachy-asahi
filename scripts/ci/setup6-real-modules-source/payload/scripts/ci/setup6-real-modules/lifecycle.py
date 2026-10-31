#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Keep exact legacy8/24 first; separate installed seven-product581→574 route."""
import json
import os
from pathlib import Path
import pwd
import stat
import types
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C


def legacy_source(path):
    raw=path.read_text()
    for before,after in (("Path('/runner/contract.py')","Path('/legacy/contract.py')"),("'/runner/exercise.py'","'/legacy/exercise.py'")):
        C.need(raw.count(before)==1,'exact legacy mount path anchor differs');raw=raw.replace(before,after)
    return raw


def retain_real(raw,target):
    C.need(type(raw) is str and len(raw.encode())<=128*1024,'bounded actual real-flow stdout required')
    target.write_text(raw)
    value=json.loads(raw);C.validate_real(value);return value


def workspace_snapshot(parent,real,L,H):
    # Seven independently bounded homes; registry equality covers every outer node.
    C.safe(parent);work=parent/'work';C.safe(work)
    C.need(parent.is_dir() and work.is_dir() and {p.name for p in parent.iterdir()}=={'work'},'exact real-user workspace root required')
    names=set(real['lifecycle'])|{'edited-conflict-user'}|set(real['extension']['homes'])
    C.need(len(names)==15 and all(Path(n).name==n and n not in ('.','..') for n in names),'fifteen distinct bounded real-user home names required')
    C.need({p.name for p in work.iterdir()}==names|{'receipt.json'},'complete real-user workspace registry differs')
    receipt=work/'receipt.json';C.safe(receipt);C.need(receipt.is_file() and receipt.stat().st_size<=128*1024,'bounded generated real-user receipt required')
    result={'.':L.entry(parent),'work':L.entry(work),'work/receipt.json':L.entry(receipt)}
    for name in sorted(names):
        home=work/name;C.safe(home);C.need(home.is_dir(),'ordinary real-user home required')
        result['work/'+name]=L.entry(home)
        # Reuse all256-node/1MiB-file/4MiB-home bounds, then retain the legacy
        # exact entry metadata (including directory/symlink mtimes) for every node.
        for relative in H.snapshot(home):result['work/'+name+'/'+relative]=L.entry(home/relative)
    return result


def main():
    C.SOURCE=Path('/code')
    C.need(os.getuid()==os.geteuid()==0 and os.getpid()==1 and os.uname().machine=='aarch64' and Path('/.dockerenv').is_file() and os.environ.get('CACHY_ASAHI_SETUP6_REAL_LIFECYCLE')=='1','dedicated marked native ARM root PID1 required')
    C.verify_source(C.SOURCE);legacy_path=Path('/legacy/lifecycle.py');old=types.ModuleType('unchanged_setup5_legacy_lifecycle');old.__file__=str(legacy_path);exec(compile(legacy_source(legacy_path),str(legacy_path),'exec'),old.__dict__)
    # Exact original eight ALPM operations and24 per-phase observations finish at574.
    os.environ['CACHY_ASAHI_SETUP5_LIFECYCLE']='1';old.main();legacy=json.loads(Path('/out/lifecycle.json').read_text());old_contract=C.load('accepted_legacy_contract',Path('/legacy/contract.py'));old_contract.validate_lifecycle(legacy)
    Path('/out/lifecycle.json').rename('/out/legacy-lifecycle.json')
    L=C.load('accepted_lifecycle_io',Path('/accepted/lifecycle.py'));base=json.loads(Path('/inputs/base.json').read_text());products=json.loads(Path('/inputs/modules.json').read_text())
    C.need(len(base)==574 and not (set(C.NAMES)&set(base)) and len(base|C.VERSIONS)==581 and base|C.VERSIONS==C.expected() and L.inventory()==base and set(products)==set(C.NAMES) and all(products[n]['version']==v for n,v in C.VERSIONS.items()),'complete574 and exact seven candidate versions required')
    hooks=Path('/tmp/setup5-hooks');config=Path('/tmp/setup5-pacman.conf');C.need(hooks.is_dir() and config.is_file(),'accepted legacy private pacman policy required')
    pacman=['/usr/bin/pacman','--config',str(config),'--noconfirm']
    profiles=(*old_contract.LEGACY,'new-grouped-journal');homes={p:Path('/tmp')/('setup5-user-'+p) for p in profiles}
    def protected():
        return dict(homes={n:L.snapshot(p) for n,p in homes.items()},system={str(p):dict(root=L.entry(p),tree=L.snapshot(p) if p.is_dir() else None) if p.exists() else None for p in (Path('/etc/pacman.conf'),Path('/etc/fish'),Path('/etc/zsh'))})
    before=protected();events=[]
    def payloads():
        for name,product in products.items():
            L.command(pacman+['-Qkk',name]);owned=L.command(pacman+['-Qql',name]).splitlines()
            C.need({p for p in owned if not p.endswith('/')}=={'/'+p for p in product['payload']},'exact ALPM candidate ownership differs')
            for relative,row in product['payload'].items():
                path=Path('/')/relative;info=path.lstat();C.need(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==row['mode'] and L.sha(path)==row['sha256'],'actual installed source/license bytes differ')
    archives=[]
    for name,product in products.items():
        archive=Path('/inputs')/product['archive'];C.need(archive.is_file() and not archive.is_symlink() and L.sha(archive)==product['sha256'],'seven accepted archives required');archives.append(str(archive))
    L.command(pacman+['--noscriptlet','-U',*archives]);C.need(L.inventory()==C.expected(),'exact581 installed inventory differs');L.command(pacman+['-Dk']);L.command(pacman+['-T','python>=3.11','gnupg','pacman','fish>=4.0','zsh']);payloads();C.need(protected()==before,'seven-package install changed legacy homes/system')
    events.append(dict(phase='install-real-seven',inventory_count=581,status='PASS',legacy_homes_preserved=True,system_preserved=True,database_check=True))
    account=pwd.getpwnam('alarm');parent=Path('/tmp/setup5-real-user');parent.mkdir(mode=0o700);os.chown(parent,account.pw_uid,account.pw_gid)
    def ordinary_absent():
        entries=list(Path('/proc').iterdir());C.need(len(entries)<512,'bounded private process namespace required')
        for entry in entries:
            if not entry.name.isdigit():continue
            try:status=(entry/'status').read_text()
            except FileNotFoundError:continue
            uids=[line.split()[1:] for line in status.splitlines() if line.startswith('Uid:')]
            C.need(len(uids)==1 and len(uids[0])==4 and str(account.pw_uid) not in uids[0],'ordinary fixture process remains')
    ordinary_absent()
    env=dict(PATH='/usr/bin:/bin',HOME=str(parent),LANG='C.UTF-8',LC_ALL='C.UTF-8',PYTHONDONTWRITEBYTECODE='1',CACHY_SETUP6_REAL_USER='1')
    raw=L.command(['/usr/bin/runuser','-u','alarm','--','/usr/bin/env','-i',*(k+'='+v for k,v in env.items()),'/usr/bin/python3','-I','-B','/runner/installed.py','--source','/code','--output',str(parent/'work')],timeout=240)
    real=retain_real(raw,Path('/out/real-modules.json'));ordinary_absent();payloads();C.need(protected()==before,'real behavior changed legacy homes/system')
    # Preserve the newly-created user tree, including edited blocks, through ALPM removal.
    H=C.load('accepted_per_home_snapshot',C.SOURCE/'scripts/ci/setup5-real-modules/run.py')
    user_before=workspace_snapshot(parent,real,L,H)
    old_setup=json.loads(Path('/inputs/products.json').read_text())['cachy-asahi-setup']
    for phase,product in (('rollback-real-setup5',old_setup),('forward-real-setup6',products['cachy-asahi-setup'])):
        archive=Path('/inputs')/product['archive'];C.need(L.sha(archive)==product['sha256'],'exact rollback/forward archive required')
        L.command(pacman+['--noscriptlet','-U',str(archive)]);expected=C.expected();expected['cachy-asahi-setup']=product['version'];C.need(L.inventory()==expected,'exact581 rollback/forward version map required');L.command(pacman+['-Dk']);L.command(pacman+['-Qkk','cachy-asahi-setup'])
        for relative,row in product['payload'].items():
            path=Path('/')/relative;info=path.lstat();C.need(stat.S_ISREG(info.st_mode) and info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==row['mode'] and L.sha(path)==row['sha256'],'rollback/forward installed source bytes differ')
        ordinary_absent();C.need(protected()==before and workspace_snapshot(parent,real,L,H)==user_before,'rollback/forward changed complete private user/system state')
        events.append(dict(phase=phase,inventory_count=581,status='PASS',legacy_homes_preserved=True,system_preserved=True,database_check=True))
    payloads()
    L.command(pacman+['--noscriptlet','-R',*C.NAMES]);C.need(L.inventory()==base,'exact574 inventory not restored');L.command(pacman+['-Dk'])
    C.need(all(not os.path.lexists('/'+p) for product in products.values() for p in product['payload']),'removed candidate payload remains')
    C.need(protected()==before and workspace_snapshot(parent,real,L,H)==user_before,'ALPM removal changed user configurations/journals/edits/system')
    events.append(dict(phase='remove-real-seven',inventory_count=574,status='PASS',legacy_homes_preserved=True,system_preserved=True,database_check=True))
    result=dict(status='PASS_NATIVE_SETUP6_LEGACY_AND_REAL_MODULES',base_count=574,restored_count=574,products=C.VERSIONS,legacy=legacy,events=events,real_modules=real,installed_payloads_preserved=True,new_user_state_preserved_on_remove=True,ordinary_user_processes_absent=True,actual_page_size=os.sysconf('SC_PAGE_SIZE'),hardware='NOT_RUN',trust='UNSIGNED_LOCAL_CANDIDATES_ONLY',release='NOT_ADMITTED')
    C.validate_lifecycle(result);Path('/out/lifecycle.json').write_text(json.dumps(result,indent=2)+'\n')


if __name__=='__main__':main()
