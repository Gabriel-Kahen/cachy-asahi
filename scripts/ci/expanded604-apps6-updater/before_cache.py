# SPDX-License-Identifier: MIT
"""One owned-cache substitution: genuine Setup3, with all other603 rows unchanged."""
from pathlib import Path
import shutil
import contract as C

STATUS='READY_SIGNED_EXPANDED604'


def verify(target,api):
    value=C.read(target/'manifest.json');before,_=C.locks()
    C.need(value.get('status')==STATUS and value.get('expected_lock')==dict(path='expected-installed.lock',sha256=C.BEFORE) and
         C.sha(target/'expected-installed.lock')==C.BEFORE and len(value.get('packages',[]))==604 and
         len({r['name'] for r in value['packages']})==604 and {r['name']:r['version'] for r in value['packages']}==before,
         'complete signed before604/Setup3 manifest required')
    roles=value['preparation']['signer_roles'];C.need(set(roles)=={'ephemeral_TEST','upstream_ALARM'} and
         len(set(roles.values()))==2,'same two public signer roles required')
    total=0
    for row in value['packages']:
        total+=row['size'];C.need(total<=4*1024**3,'original compressed cache aggregate bound')
        api.checked(target,dict(path=row['archive'],bytes=row['size'],sha256=row['sha256']),256*1024**2)
        C.need(row['signature']==row['archive']+'.sig' and row['signer'] in roles.values(),'exact detached signature authority required')
        api.checked(target,dict(path=row['signature'],bytes=row['signature_size'],sha256=row['signature_sha256']),1024**2)
    C.need(len(value['projects'])==21 and len({r['name'] for r in value['projects']})==21 and
         all(before[r['name']]==r['version'] for r in value['projects']),'complete21 genuine before604 project payload maps required')
    builder=value['builder_lock'];C.need(builder['path']=='builder-packages.lock' and builder['sha256']==api.BUILDER,
         'original574 source-native builder provenance required')
    api.checked(target,dict(path=builder['path'],bytes=builder['size'],sha256=builder['sha256']),1024**2)
    C.need(len(value['keyrings'])==2,'two original public keyrings required')
    for key in value['keyrings']:api.checked(target,dict(path=key['path'],bytes=key['size'],sha256=key['sha256']),1024**2)
    return value


def bind(target,api,owner):
    C.need(owner['purpose']=='expanded604-apps6-updater' and target==Path(owner['output'])/'ready604' and C.read(target.parent/'owner.json')==owner,'exact owned baseline cache')
    value,ref,inventory=api.target_manifest(target)
    C.need(inventory==C.locks()[0] and inventory['cachy-asahi-setup']=='0.1.0-5','held authentic Apps5/Setup5 current604 baseline')
    verify(target,api)
    (target.parent/'before-cache.json').write_bytes(C.encoded(dict(status='UNCHANGED_SIGNED_APPS5_CURRENT604_BASELINE',before_sha256=C.BEFORE,after_sha256=C.AFTER,manifest=ref,other603='UNCHANGED',actors='NOT_RUN')))
    return target


def flat_inputs(ready,raw,target,original_plan,api):
    C.need(not target.exists(),'fresh flat inputs required');value=verify(ready,api)
    projects={r['name'] for r in value['projects']}
    audio={'asahi-audio','alsa-ucm-conf-asahi','speakersafetyd','bankstown','triforce-lv2','lsp-plugins-lv2'}
    names=projects|audio|{'htmlq','pacman-contrib','archlinux-contrib','pyalpm'}
    rows=[r for r in value['packages'] if r['name'] in names]
    C.need(len(projects)==21 and len(rows)==31 and {r['name'] for r in rows}==names,'exact21 projects and31 additions required')
    target.mkdir(mode=0o700);packages=[]
    for row in rows:
        name=Path(row['archive']).name;sig=Path(row['signature']).name
        C.need(name not in {r['filename'] for r in packages} and sig==name+'.sig','distinct archive basename/signature required')
        for relative,size,digest,destination,cap in ((row['archive'],row['size'],row['sha256'],name,256*1024**2),
             (row['signature'],row['signature_size'],row['signature_sha256'],sig,1024**2)):
            path=api.checked(ready,dict(path=relative,bytes=size,sha256=digest),cap);shutil.copyfile(path,target/destination)
        packages.append(dict(name=row['name'],version=row['version'],filename=name,size=row['size'],sha256=row['sha256'],
             signature_size=row['signature_size'],signature_sha256=row['signature_sha256']))
    for name in ('expectedbase.lock','core-lifecycle.py','provider-helpers.py','TEST-public.asc','archlinuxarm.gpg'):
        source=C.safe(raw/'inputs'/name);C.need(source.is_file(),'original helper/key input missing');shutil.copyfile(source,target/name)
    shutil.copyfile(ready/'expected-installed.lock',target/'expected-installed.lock')
    # No reconstructed fallback: these are the held producer plan values captured by prepare_with_plan.
    plan={key:original_plan[key] for key in ('hooks','signer_fingerprint','test_signer_fingerprint')}
    plan.update(packages=packages,projects=value['projects'],setup4={'helpers':original_plan['setup4']['helpers']},full_root_upgrade=True)
    (target/'plan.json').write_bytes(C.encoded(plan));return target
