#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Context only: reuse original signed verification/DB/payload primitives; never runs on host."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

def need(ok,why):
    if not ok:raise ValueError(why)
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m

def install(proof_sha256):
    code=Path('/tmp/managed604');load('_606_owned_build_scope',code/'build_scope.py').check(proof_sha256,'runtime606')
    code=Path('/tmp/managed604')
    C=load('contract',code/'contract604.py');sys.modules['contract']=C
    L=load('_606_native_install_methods',code/'lifecycle604.py');L.CODE=code
    db=load('_606_actual_db',code/'alpm_reader.py')
    bundle=code/'bundle';manifest=C.read(bundle/'manifest.json',1024**2)
    expected=C.lock((bundle/'expected-installed.lock').read_bytes(),606)
    C.need(hashlib.sha256((bundle/'expected-installed.lock').read_bytes()).hexdigest()=='a82c146aeb78259d965b5db8523f047ac7640b8d9e0003073d910fb33f3010e0','exact606 lock required')
    before=L.inventory();C.need(len(before)==574 and set(before)-set(expected)=={'libfdk-aac'} and all(expected.get(n)==v for n,v in before.items()if n!='libfdk-aac') and expected['cachy-asahi-fdk-aac']=='3.0.0-1','exact original574 with sole native FDK replacement required')
    baseline=db.database(Path('/'),max_packages=574)
    removed=next(r for r in baseline if r['name']=='libfdk-aac');held=[r for r in baseline if r['name']!='libfdk-aac'];C.need(len(held)==573,'exact573 held baseline rows')
    baseline_db={r['name']:L.tree(Path('/var/lib/pacman/local')/(r['name']+'-'+r['version'])) for r in held}
    baseline_nodes={p:L.node(Path('/')/p) for r in held for p in r['files']}
    user={str(p):L.tree(p) for p in (Path('/home'),Path('/root'))}
    # Existing held methods verify every detached signature against the exact primary signer,
    # mask each finite hook explicitly, and require signed local ALPM transactions.
    rows=manifest['packages'];incoming=[r for r in rows if r['name'] not in before]
    C.need(len(incoming)==33 and len(rows)==606 and len({r['name']for r in incoming})==33,'exact33 incoming with one original FDK removal')
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
        names.update(Path(p).name for p in L.run(['pacman','-Qqlp',archive]).splitlines() if p.startswith(('/usr/share/libalpm/hooks/','/etc/pacman.d/hooks/')) and p.endswith('.hook'))
    for name in names:
        C.need(__import__('re').fullmatch(r'[A-Za-z0-9_.@+-]+\.hook',name),'safe finite hook required');(hooks/name).symlink_to('/dev/null')
    fdk=next(r for r in C.read(code/'incoming.json',32*1024**2)if r['name']=='cachy-asahi-fdk-aac');C.need(fdk['metadata']['pkgname']==['cachy-asahi-fdk-aac'] and fdk['metadata']['pkgver']==['3.0.0-1'] and fdk['metadata'].get('conflict')==['libfdk-aac'] and not fdk['metadata'].get('replaces') and fdk['metadata'].get('depend')==['glibc'] and set(fdk['metadata'].get('provides',[]))=={'libfdk-aac=3.0.0','libfdk-aac.so=2-64','libfdk-xhe-aac.so=0-64'},'exact original accepted FDK replacement metadata')
    conf=Path('/tmp/managed604/pacman.conf');conf.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nGPGDir = '+str(home)+'\nHookDir = '+str(hooks)+'\n')
    try:
        L.run(['pacman','--config',conf,'-U','--noconfirm','--noscriptlet','--ask','4',*[bundle/r['archive'] for r in incoming]])
        C.need(L.inventory()==expected,'real installed604 inventory differs')
        actual=db.database(Path('/'),max_packages=606);C.need({r['name']:r['version'] for r in actual}==expected,'complete604 ALPM DB differs')
        C.need(not (Path('/var/lib/pacman/local')/('libfdk-aac-'+before['libfdk-aac'])).exists() and 'libfdk-aac'not in expected,'exact original FDK ALPM removal identity')
        new_fdk=set(fdk['payload']);C.need(all(not (Path('/')/p).exists() and not (Path('/')/p).is_symlink()for p in removed['files']if p not in new_fdk),'all removed FDK-only leaves absent')
        for r in held:C.need(L.tree(Path('/var/lib/pacman/local')/(r['name']+'-'+r['version']))==baseline_db[r['name']],'original574 DB changed')
        C.need(all(L.node(Path('/')/p)==v for p,v in baseline_nodes.items()),'original574 actual payload changed')
        C.need({str(p):L.tree(p) for p in (Path('/home'),Path('/root'))}==user,'original user state changed')
        payload=C.read(Path('/tmp/managed604/incoming.json'),32*1024**2)
        L.check_incoming(payload,expected,{r['name']:r for r in actual})
        L.run(['ldconfig'])
        Path('/runtime-packages.lock').write_bytes(C.inventory_bytes(expected))
        Path('/installed604-install.json').write_bytes(C.encoded(dict(status='PASS_ACTUAL_SIGNED574_TO606',packages=606,original573_database='PRESERVED',original573_payload='PRESERVED',sole_removed='libfdk-aac',sole_replacement='cachy-asahi-fdk-aac',user='PRESERVED',signature='EACH_EXACT_PRIMARY_SIGNER_REQUIRED',hooks='MASKED',scriptlets='DISABLED',hardware='NOT_RUN')))
    finally:
        L.run(['gpgconf','--homedir',home,'--kill','all']);shutil.rmtree(home)
if __name__=='__main__':
    need(len(sys.argv)==2,'one exact caller build-proof digest');install(sys.argv[1])
