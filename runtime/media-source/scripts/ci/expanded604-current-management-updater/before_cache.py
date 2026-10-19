# SPDX-License-Identifier: MIT
"""One owned-cache substitution: genuine Setup3, with all other603 rows unchanged."""
from pathlib import Path
import shutil
import contract as C

STATUS='READY_SIGNED_EXPANDED604_SETUP3'


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


def replace_setup3(ready,target,producer_root,source,api,owner):
    """Consume only the original587 and complete authenticated604 materializer outputs."""
    C.need(owner['purpose']=='expanded604-current-management-updater' and target==Path(owner['output'])/'ready604' and
         producer_root==Path(owner['producer']) and C.read(target.parent/'owner.json')==owner,'exact owned604 cache lease required')
    target=C.safe(target);source=C.safe(source)
    after,after_ref,inventory=api.target_manifest(target)
    C.need(inventory==C.locks()[1],'final604 materializer cache required before substitution')
    profile=api.load('_root604_original_profile',source/'scripts/ci/full-composition-installer-vm/profile.py')
    original,_,_=profile.manifest(ready)
    old=next(r for r in original['packages'] if r['name']=='cachy-asahi-setup')
    selected=next(r for r in after['packages'] if r['name']=='cachy-asahi-setup')
    predecessor=next(r for r in original['projects'] if r['name']=='cachy-asahi-setup')
    C.need(old['version']==predecessor['version']=='0.1.0-3' and selected['version']=='0.1.0-5' and
         selected['sha256']==C.PACKAGE and old['signer']==after['preparation']['signer_roles']['ephemeral_TEST'] and
         original['preparation']['signer_roles']==after['preparation']['signer_roles'] and
         predecessor['sha256']==old['sha256'],'genuine same-authority Setup3 predecessor/Setup5 pair required')
    prior=api.load('_root604_copy_contract',source/'scripts/ci/expanded600-installer-vm/contract.py')
    helper=api.scoped_load('_root604_copy_original',source/'scripts/ci/expanded600-installer-vm/materializer.py',{'contract':prior})
    packages=target/'packages';packages.chmod(0o700)
    for key,size,digest in (('archive','size','sha256'),('signature','signature_size','signature_sha256')):
        C.need(Path(old[key]).parent==Path('packages') and Path(selected[key]).parent==Path('packages') and old[key]!=selected[key],
             'distinct fixed predecessor cache paths required')
        helper.copy_archive(ready/old[key],target/old[key],dict(size=old[size],sha256=old[digest]))
    producer=api.load('_root604_public_verifier',source/'scripts/ci/full-composition-installer-vm/producer.py')
    verifier=producer.PublicVerifier(producer_root/'private/expanded604-before-verifier',[target/k['path'] for k in after['keyrings']])
    try:verifier(target/old['archive'],target/old['signature'],old['signer'])
    finally:verifier.close()
    rows=[dict(old) if r['name']=='cachy-asahi-setup' else dict(r) for r in after['packages']]
    projects=[dict(predecessor) if r['name']=='cachy-asahi-setup' else dict(r) for r in after['projects']]
    protected=lambda values:{r['name']:r for r in values if r['name']!='cachy-asahi-setup'}
    C.need(len(protected(rows))==603 and protected(rows)==protected(after['packages']) and
         protected(projects)==protected(after['projects']) and {r['name']:r['version'] for r in rows}==C.locks()[0],
         'all603 unselected archive/signature/project records must remain exact')
    snapshot=target.parent/'after604-materialized-manifest.json'
    C.need(not snapshot.exists(),'fresh owned materializer manifest snapshot required')
    original_manifest=api.checked(target,after_ref,1024**2)
    with snapshot.open('xb') as stream:stream.write(original_manifest.read_bytes())
    snapshot.chmod(0o400);after_ref=dict(after_ref,path=snapshot.name)
    for key,size,digest in (('archive','size','sha256'),('signature','signature_size','signature_sha256')):
        path=api.checked(target,dict(path=selected[key],bytes=selected[size],sha256=selected[digest]),256*1024**2 if key=='archive' else 1024**2)
        path.unlink()  # Only these exact two obsolete files in this owned private cache.
    value=dict(after,status=STATUS,expected_lock=dict(path='expected-installed.lock',sha256=C.BEFORE),packages=rows,projects=projects,
         preparation=dict(after['preparation'],compressed_archive_bytes=sum(r['size'] for r in rows)),
         copied_root604=dict(after604_manifest=after_ref,before_sha256=C.BEFORE,after_sha256=C.AFTER,
             replaced_only='cachy-asahi-setup',preserved_packages=603,source='GENUINE_ORIGINAL587_SETUP3',
             selected_setup5_sha256=C.PACKAGE,hardware='NOT_RUN',release='NOT_ADMITTED'))
    for name,raw in (('expected-installed.lock',(C.HERE/'before604.lock').read_bytes()),('manifest.json',C.encoded(value))):
        path=target/name;path.chmod(0o600);path.write_bytes(raw);path.chmod(0o444)
    verify(target,api);packages.chmod(0o555)
    (target.parent/'before-cache.json').write_bytes(C.encoded(dict(status='SIGNED_BEFORE604_CACHE_ONLY',before_sha256=C.BEFORE,
         after_sha256=C.AFTER,original_after_manifest=after_ref,unselected_archive_records=603,setup3=old,
         setup5=selected,full_transaction='NOT_RUN',hardware='NOT_RUN')))
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
