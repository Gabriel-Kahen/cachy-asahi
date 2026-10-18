#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Context only: reuse original signed verification/DB/payload primitives; never runs on host."""
import hashlib
import importlib.util
import json
import os
import re
import stat
from pathlib import Path
import shutil
import subprocess
import sys

def need(ok,why):
    if not ok:raise ValueError(why)
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

BUILD_MOUNT=Path('/run/cachy-asahi-managed604-build.json')

def build_admission(digest):
    """Exact context receipt on a real readonly BuildKit file mount, never a marker."""
    need(re.fullmatch('[0-9a-f]{64}',digest or ''),'explicit context digest required')
    path=BUILD_MOUNT;info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_uid==0 and 0<info.st_size<=4096 and not path.is_symlink(),'ordinary root-owned bounded build admission')
    need(os.statvfs(path).f_flag&os.ST_RDONLY,'build admission must be kernel readonly')
    mounts=Path('/proc/self/mountinfo').read_text();need(len(mounts)<=1024**2,'finite mount metadata')
    rows=[line.split() for line in mounts.splitlines() if len(line.split())>=10 and line.split()[4]==str(path)]
    need(len(rows)==1 and 'ro' in rows[0][5].split(','),'exact readonly file mount required')
    raw=path.read_bytes();need(len(raw)==info.st_size and hashlib.sha256(raw).hexdigest()==digest,'context-bound admission bytes')
    v=json.loads(raw);need(type(v)is dict and set(v)=={'schema_version','purpose','nonce','installer_sha256','context_sha256','manifest_sha256','expected604_sha256'} and type(v['schema_version'])is int and v['schema_version']==1 and v['purpose']=='OWNED_OFFLINE_SIGNED604_BUILD' and re.fullmatch('[0-9a-f]{32}',v['nonce'] or '') and v['expected604_sha256']=='7bc6caa51301bf076aeda4d137277a128c53a16e5bfd25f02e7309c4b3a408c3','exact finite build admission scope')
    root=Path('/tmp/managed604');need(Path(__file__).resolve()==root/'install604.py','fixed install-context entry required')
    for key,name in (('installer_sha256','install604.py'),('context_sha256','context604.py'),('manifest_sha256','bundle/manifest.json')):
        p=root/name;need(p.is_file() and not p.is_symlink() and p.stat().st_nlink==1 and p.stat().st_size<=1024**2 and hashlib.sha256(p.read_bytes()).hexdigest()==v[key],'source/context/manifest admission pin differs')
    network=Path('/proc/net/dev').read_text();need(len(network)<=65536 and {line.split(':',1)[0].strip() for line in network.splitlines() if ':' in line}=={'lo'},'actual offline build namespace required')
    return True

def build_guard():
    facts=dict(euid=os.geteuid(),machine=os.uname().machine,docker_marker=Path('/.dockerenv').is_file(),systemd_runtime=Path('/run/systemd/system').exists(),buildkit_context=False)
    try:
        if sys.argv[1:]:
            need(len(sys.argv)==3 and sys.argv[1]=='--owned-buildkit-context','explicit build-context invocation required');facts['buildkit_context']=build_admission(sys.argv[2])
        need(facts['euid']==0 and facts['machine']=='aarch64' and not facts['systemd_runtime'] and (facts['buildkit_context'] if sys.argv[1:] else facts['docker_marker']),'owned native offline build only')
    finally:print('CURRENT604_BUILD_ENV '+json.dumps(facts,sort_keys=True,separators=(',',':')),flush=True)

def install():
    build_guard()
    code=Path('/tmp/managed604/code');sys.path.insert(0,str(code/'scripts/ci/expanded604-apps6-public-pairs'))
    C=load('contract',code/'scripts/ci/expanded604-apps6-public-pairs/contract.py')
    L=load('_604_native_install_methods',code/'scripts/ci/expanded604-apps6-public-pairs/lifecycle.py');L.CODE=code
    db=C.load('_604_actual_db',code/'scripts/ci/full-root-upgrade/root_upgrade.py')
    bundle=Path('/tmp/managed604/bundle');manifest=C.read(bundle/'manifest.json',1024**2)
    expected=C.lock((bundle/'expected-installed.lock').read_bytes(),604)
    C.need(hashlib.sha256((bundle/'expected-installed.lock').read_bytes()).hexdigest()==C.TARGET_SHA,'exact604 lock required')
    select=load('_604_exact_provider_transition',Path(__file__).with_name('context604.py')).selection
    before=L.inventory();selected=select(before,expected)
    baseline=db.database(Path('/'),max_packages=574)
    preserved=[r for r in baseline if r['name']!='libfdk-aac'];C.need(len(preserved)==573,'exact573 preserved DB records required')
    baseline_db={r['name']:L.tree(Path('/var/lib/pacman/local')/(r['name']+'-'+r['version'])) for r in preserved}
    baseline_nodes={p:L.node(Path('/')/p) for r in preserved for p in r['files']}
    user={str(p):L.tree(p) for p in (Path('/home'),Path('/root'))}
    # Existing held methods verify every detached signature against the exact primary signer,
    # mask each finite hook explicitly, and require signed local ALPM transactions.
    rows=manifest['packages'];incoming=[r for r in rows if r['name'] in selected]
    C.need(len(incoming)==31 and len(rows)==604,'exact31 incoming packages from actual574 required')
    home=Path('/tmp/managed604/trust');home.mkdir(mode=0o700)
    gpg=['gpg','--batch','--no-options','--homedir',str(home),'--no-auto-key-retrieve']
    roles=manifest['preparation']['signer_roles'];C.need(set(roles)=={'upstream_ALARM','ephemeral_TEST'} and len(set(roles.values()))==2,'two distinct signer roles required')
    L.run(gpg+['--import',*[bundle/r['path'] for r in manifest['keyrings']]])
    L.run(gpg+['--import-ownertrust'],''.join(s+':6:\n' for s in sorted(roles.values())))
    hooks=Path('/tmp/managed604/hooks');hooks.mkdir();names=set()
    for directory in ('/usr/share/libalpm/hooks','/etc/pacman.d/hooks'):names.update(p.name for p in Path(directory).glob('*.hook'))
    for row in incoming:
        archive=C.checked(bundle,dict(path=row['archive'],bytes=row['size'],sha256=row['sha256']),256*1024**2)
        signature=C.checked(bundle,dict(path=row['signature'],bytes=row['signature_size'],sha256=row['signature_sha256']),1024**2)
        C.need(row['signature']==row['archive']+'.sig' and row['signer'] in roles.values(),'closed signed incoming tuple required')
        L.verify_signature(gpg,archive,signature,row['signer'])
        meta=L.metadata(archive)
        conflicts={re.split('[<>=]',name)[0] for name in meta.get('conflict',[])} & (set(before)|selected)
        C.need(conflicts==({'libfdk-aac'} if row['name']=='cachy-asahi-fdk-aac' else set()) and not meta.get('replaces') and not meta.get('backup'),'sole selected/installed conflict must be FDK replacement')
        names.update(Path(p).name for p in L.run(['pacman','-Qqlp',archive]).splitlines() if p.startswith(('/usr/share/libalpm/hooks/','/etc/pacman.d/hooks/')) and p.endswith('.hook'))
    for name in names:
        C.need(__import__('re').fullmatch(r'[A-Za-z0-9_.@+-]+\.hook',name),'safe finite hook required');(hooks/name).symlink_to('/dev/null')
    conf=Path('/tmp/managed604/pacman.conf');conf.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nGPGDir = '+str(home)+'\nHookDir = '+str(hooks)+'\n')
    try:
        L.run(['pacman','--config',conf,'-U','--noconfirm','--noscriptlet','--ask','4',*[bundle/r['archive'] for r in incoming]])
        C.need(L.inventory()==expected,'real installed604 inventory differs')
        actual=db.database(Path('/'),max_packages=604);C.need({r['name']:r['version'] for r in actual}==expected,'complete604 ALPM DB differs')
        for r in preserved:C.need(L.tree(Path('/var/lib/pacman/local')/(r['name']+'-'+r['version']))==baseline_db[r['name']],'preserved573 DB changed')
        C.need(all(L.node(Path('/')/p)==v for p,v in baseline_nodes.items()),'preserved573 actual payload changed')
        C.need({str(p):L.tree(p) for p in (Path('/home'),Path('/root'))}==user,'original user state changed')
        payload=C.read(Path('/tmp/managed604/incoming.json'),32*1024**2)
        L.check_incoming(payload,expected,{r['name']:r for r in actual})
        L.run(['ldconfig'])
        Path('/runtime-packages.lock').write_bytes(C.inventory_bytes(expected))
        Path('/installed604-install.json').write_bytes(C.encoded(dict(status='PASS_ACTUAL_SIGNED574_TO604',packages=604,original573_database='PRESERVED',original573_payload='PRESERVED',provider_replacement={'before':'libfdk-aac 3.0.0-1','after':'cachy-asahi-fdk-aac 3.0.0-1'},incoming_packages=31,user='PRESERVED',signature='EACH_EXACT_PRIMARY_SIGNER_REQUIRED',hooks='MASKED',scriptlets='DISABLED',hardware='NOT_RUN')))
    finally:
        L.run(['gpgconf','--homedir',home,'--kill','all']);shutil.rmtree(home)
if __name__=='__main__':install()
