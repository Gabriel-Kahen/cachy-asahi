# SPDX-License-Identifier: MIT
"""Only inside an owned offline original574 Docker derivative; never guest606."""
import importlib.util,json,os,re,shutil
from pathlib import Path
HERE=Path('/tmp/tooling606')
def load(name,path):s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def main(proof_sha256):
    load('_590_owned_build_scope',HERE/'build_scope.py').check(proof_sha256,'controller590')
    C=load('contract',HERE/'contract604.py');import sys;sys.modules['contract']=C;L=load('_original_tooling_signed_primitives',HERE/'lifecycle604.py');db=load('_tooling_full_db',HERE/'alpm_reader.py');value=C.read(HERE/'tooling.json');rows=value['rows'];expected=dict(line.split()for line in(HERE/'expected590.lock').read_text().splitlines());before=L.inventory();C.need(len(before)==574 and len(rows)==16 and len(expected)==590 and all(expected.get(n)==v for n,v in before.items()),'exact574 to590 controller-only composition')
    home=HERE/'trust';home.mkdir(mode=0o700);gpg=['gpg','--batch','--no-options','--homedir',str(home),'--no-auto-key-retrieve'];L.run(gpg+['--import',HERE/'archlinuxarm.gpg']);L.run(gpg+['--import-ownertrust'],value['signer']+':6:\n');hooks=HERE/'hooks';hooks.mkdir();names={p.name for d in('/usr/share/libalpm/hooks','/etc/pacman.d/hooks')for p in Path(d).glob('*.hook')}
    for r in rows:
        archive=C.checked(HERE,dict(path='packages/'+r['filename'],bytes=r['size'],sha256=r['sha256']),256*1024**2);sig=C.checked(HERE,dict(path='packages/'+r['filename']+'.sig',bytes=r['signature_size'],sha256=r['signature_sha256']),1024**2);L.verify_signature(gpg,archive,sig,value['signer']);names.update(Path(p).name for p in L.run(['pacman','-Qqlp',archive]).splitlines()if p.endswith('.hook'))
    for name in names:C.need(re.fullmatch(r'[A-Za-z0-9_.@+-]+\.hook',name),'safe fixed hook');(hooks/name).symlink_to('/dev/null')
    conf=HERE/'pacman.conf';conf.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nGPGDir = '+str(home)+'\nHookDir = '+str(hooks)+'\n')
    try:
        L.run(['pacman','--config',conf,'-U','--noconfirm','--noscriptlet',*[HERE/'packages'/r['filename']for r in rows]]);C.need(L.inventory()==expected,'exact controller590 actual lock');actual=db.database(Path('/'),max_packages=590);L.check_incoming(value['payload'],expected,{r['name']:r for r in actual});L.run(['qemu-system-aarch64','--version']);Path('/controller590.lock').write_bytes(C.inventory_bytes(expected))
    finally:L.run(['gpgconf','--homedir',home,'--kill','all']);shutil.rmtree(home)
if __name__=='__main__':
    import sys
    if len(sys.argv)!=2:raise ValueError('one exact caller build-proof digest')
    main(sys.argv[1])
