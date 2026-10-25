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

def install():
    need(os.geteuid()==0 and Path('/.dockerenv').is_file() and os.uname().machine=='aarch64' and not Path('/run/systemd/system').exists(),'owned native offline build only')
    code=Path('/tmp/managed604/code');sys.path.insert(0,str(code/'scripts/ci/expanded604-current-management'))
    C=load('contract',code/'scripts/ci/expanded604-current-management/contract.py')
    L=load('_604_native_install_methods',code/'scripts/ci/expanded604-current-management/lifecycle.py');L.CODE=code
    db=C.load('_604_actual_db',code/'scripts/ci/full-root-upgrade/root_upgrade.py')
    bundle=Path('/tmp/managed604/bundle');manifest=C.read(bundle/'manifest.json',1024**2)
    expected=C.lock((bundle/'expected-installed.lock').read_bytes(),604)
    C.need(hashlib.sha256((bundle/'expected-installed.lock').read_bytes()).hexdigest()==C.TARGET_SHA,'exact604 lock required')
    before=L.inventory();C.need(len(before)==574 and all(expected.get(n)==v for n,v in before.items()),'fresh actual574 preserved base required')
    baseline=db.database(Path('/'),max_packages=574)
    baseline_db={r['name']:L.tree(Path('/var/lib/pacman/local')/(r['name']+'-'+r['version'])) for r in baseline}
    baseline_nodes={p:L.node(Path('/')/p) for r in baseline for p in r['files']}
    user={str(p):L.tree(p) for p in (Path('/home'),Path('/root'))}
    # Existing held methods verify every detached signature against the exact primary signer,
    # mask each finite hook explicitly, and require signed local ALPM transactions.
    rows=manifest['packages'];incoming=[r for r in rows if r['name'] not in before]
    C.need(len(incoming)==30 and len(rows)==604,'exact30 additions from actual574 required')
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
    conf=Path('/tmp/managed604/pacman.conf');conf.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nGPGDir = '+str(home)+'\nHookDir = '+str(hooks)+'\n')
    try:
        L.run(['pacman','--config',conf,'-U','--noconfirm','--noscriptlet',*[bundle/r['archive'] for r in incoming]])
        C.need(L.inventory()==expected,'real installed604 inventory differs')
        actual=db.database(Path('/'),max_packages=604);C.need({r['name']:r['version'] for r in actual}==expected,'complete604 ALPM DB differs')
        for r in baseline:C.need(L.tree(Path('/var/lib/pacman/local')/(r['name']+'-'+r['version']))==baseline_db[r['name']],'original574 DB changed')
        C.need(all(L.node(Path('/')/p)==v for p,v in baseline_nodes.items()),'original574 actual payload changed')
        C.need({str(p):L.tree(p) for p in (Path('/home'),Path('/root'))}==user,'original user state changed')
        payload=C.read(Path('/tmp/managed604/incoming.json'),32*1024**2)
        L.check_incoming(payload,expected,{r['name']:r for r in actual})
        L.run(['ldconfig'])
        Path('/runtime-packages.lock').write_bytes(C.inventory_bytes(expected))
        Path('/installed604-install.json').write_bytes(C.encoded(dict(status='PASS_ACTUAL_SIGNED574_TO604',packages=604,original574_database='PRESERVED',original574_payload='PRESERVED',user='PRESERVED',signature='EACH_EXACT_PRIMARY_SIGNER_REQUIRED',hooks='MASKED',scriptlets='DISABLED',hardware='NOT_RUN')))
    finally:
        L.run(['gpgconf','--homedir',home,'--kill','all']);shutil.rmtree(home)
if __name__=='__main__':install()
