# SPDX-License-Identifier: MIT
"""Lane-local use of Welcome and full-root preservation/TEST verification APIs."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


def apis():return load('orphans_welcome','/runner/accepted/lifecycle.py'),load('orphans_database','/runner/accepted/root_upgrade.py')


def entry(L,path):
    row=L.entry(path);info=path.lstat()
    return dict(row,device=info.st_dev,inode=info.st_ino,links=info.st_nlink,ctime_ns=info.st_ctime_ns)


def base_state(L,driver):
    packages=driver.database(Path('/'),max_packages=574)
    L.need(len(packages)==574 and {p['name']:p['version'] for p in packages}==L.inventory(),'complete original574 ownership records required')
    nodes={};spent=0
    for package in packages:
        db=Path('/var/lib/pacman/local')/(package['name']+'-'+package['version'])
        paths={Path('/')/p for p in package['files']}|set(db.iterdir())|{db,Path('/var/lib/pacman/local/ALPM_DB_VERSION')}
        for path in sorted(paths):
            name=str(path)
            if name in nodes:continue
            info=path.lstat();L.need(stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or path==db and stat.S_ISDIR(info.st_mode),'ordinary base payload/database entry required')
            if stat.S_ISREG(info.st_mode):spent+=info.st_size;L.need(info.st_size<=1024**3 and spent<=6*1024**3,'inherited full-root byte bounds')
            L.need(len(nodes)<4000000,'inherited full-root node bound');nodes[name]=entry(L,path)
            L.need(nodes[name]==entry(L,path),'base observation changed')
    return dict(packages=packages,nodes=nodes)


def preserve_base(L,held):
    # Package insertion/removal changes only the local DB parent directory; all574 existing records/payloads stay exact.
    for name,row in held['nodes'].items():L.need(entry(L,Path(name))==row,'original574 payload/database changed: '+name)
    return hashlib.sha256(json.dumps(held,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def pacman(L,signer,*,public='/inputs/TEST-public.asc',extra=None):
    hooks=Path('/tmp/orphans-hooks');hooks.mkdir();masked=set()
    for parent in ('/usr/share/libalpm/hooks','/etc/pacman.d/hooks','/builder-disabled-hooks'):
        for path in Path(parent).glob('*.hook'):
            if path.name not in masked:(hooks/path.name).symlink_to('/dev/null');masked.add(path.name)
    trust=Path('/tmp/orphans-trust');trust.mkdir(mode=0o700)
    gpg=['/usr/bin/gpg','--batch','--no-options','--homedir',str(trust),'--no-auto-key-retrieve']
    roles=[(public,signer)]+([extra] if extra is not None else [])
    for key,fingerprint in roles:
        shown=L.command(gpg+['--with-colons','--import-options','show-only','--import',key])
        L.need(fingerprint in [line.split(':')[9] for line in shown.splitlines() if line.startswith('fpr:')],
            'exact bound verification signer required')
        L.command(gpg+['--import',key])
    # Only this disposable verification keyring gets TEST ownertrust.
    import subprocess
    result=subprocess.run(gpg+['--import-ownertrust'],input=''.join(fingerprint+':6:\n' for _,fingerprint in roles).encode(),capture_output=True,timeout=20)
    L.need(result.returncode==0 and len(result.stdout)+len(result.stderr)<=65536,'TEST ownertrust import failed')
    config=Path('/tmp/orphans-pacman.conf');config.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nHookDir = '+str(hooks)+'\nGPGDir = '+str(trust)+'\n')
    return ['/usr/bin/pacman','--config',str(config),'--noconfirm','--noscriptlet']


def database_check(L,pacman):
    L.need(len(pacman)==5 and pacman[:2]==['/usr/bin/pacman','--config'] and pacman[3:]==['--noconfirm','--noscriptlet'],'fixed transaction vector required')
    return L.command(pacman[:3]+['-Dk'])


def payloads(L,products):
    for name,row in products.items():
        L.command(['/usr/bin/pacman','-Qkk',name])
        paths=L.command(['/usr/bin/pacman','-Qql',name]).splitlines()
        L.need({p for p in paths if not p.endswith('/')}=={'/'+p for p in row['payload']},'installed ownership list differs')
        for relative,node in row['payload'].items():
            path=Path('/')/relative;info=path.lstat()
            L.need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode)==node['mode'] and
                info.st_uid==info.st_gid==0 and L.sha(path)==node['sha256'],'installed exact source/license payload differs')


def guard(L,operation):
    L.need(os.getuid()==0 and os.getpid()==1 and Path('/.dockerenv').is_file() and os.uname().machine=='aarch64' and
        os.environ.get('CACHY_ASAHI_ORPHANS_OPERATION')==operation,'dedicated native root container PID1 required')
