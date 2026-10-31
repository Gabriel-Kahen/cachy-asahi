# SPDX-License-Identifier: MIT
"""Reused accepted archives only; complete604 signatures before an owned consumer."""
from pathlib import Path
import shutil
import sys
import contract as C

META={'.PKGINFO','.BUILDINFO','.MTREE'}


def legacy_reader(legacy):
    old=C.load('_604_legacy_native_contract',legacy/'scripts/ci/expanded-development-composition/contract.py')
    return C.scoped_load('_604_legacy_native_inputs',legacy/'scripts/ci/expanded-development-composition/inputs.py',{'contract':old})


def accepted(source,legacy,eight,seven,audio,management,setup,welcome,policy):
    C.need(policy==C.policy(),'complete current Root604 input binding required')
    C.bound_inputs(source,legacy,eight,seven,management,setup,welcome,policy)
    api=C.scoped_load('_604_retained_inputs',C.HERE/'inputs.py',{'contract':C})
    value=api.validate_inputs(source,legacy,eight,seven,management,setup,welcome,policy)
    for name,ref in policy['combined']['files'].items():
        C.need(ref['path']==name,'unchanged combined fixture path differs');C.checked(legacy,ref)
    paths=list(sys.path)
    try:audios=legacy_reader(legacy).audio(audio,legacy)
    finally:sys.path[:]=paths
    pairs=dict(value['pairs']);pairs['cachy-asahi-welcome']=value['welcome'];pairs[C.SETUP]=value['setup'];pairs.update(value['management'])
    C.need(set(pairs)==C.SCRIPTS|C.MANAGEMENT.keys()|C.UPGRADES.keys() and set(audios)==C.AUDIO,
           'complete accepted13 pairs and6 audio archives required')
    rows={**audios,**pairs};C.need(len(rows)==19 and all(row['version']==C.locks()[1][name] for name,row in rows.items()),
        'retained sources do not select exact19 incoming versions')
    return value,rows


def prepare(ready,producer_root,eight,seven,audio,legacy,target,policy,management,setup,welcome,source):
    # All actual immutable inputs, including missing archive and source checks, precede target creation/signing.
    evidence,incoming=accepted(source,legacy,eight,seven,audio,management,setup,welcome,policy)
    C.prerequisites(eight,policy)
    profile=C.load('_604_original587_profile',source/'scripts/ci/full-composition-installer-vm/profile.py')
    original,_,before=profile.manifest(ready);after=C.selected(before,{n:r['version'] for n,r in incoming.items()})
    old=C.load('_604_original600_materializer_contract',source/'scripts/ci/expanded600-installer-vm/contract.py')
    helper=C.scoped_load('_604_original600_copy_and_sign',source/'scripts/ci/expanded600-installer-vm/materializer.py',{'contract':old})
    C.need(not target.exists(),'fresh separate604 ready directory required');C.safe(target.absolute());target.mkdir(mode=0o700)
    (target/'packages').mkdir();(target/'keys').mkdir();rows=[];to_sign=[]
    for row in original['packages']:
        if row['name'] in C.UPGRADES:continue
        helper.copy_archive(ready/row['archive'],target/row['archive'],row)
        helper.copy_archive(ready/row['signature'],target/row['signature'],dict(size=row['signature_size'],sha256=row['signature_sha256']))
        rows.append(dict(row))
    roles=original['preparation']['signer_roles'];C.need(set(roles)=={'ephemeral_TEST','upstream_ALARM'},'two original producer signer roles required')
    for name,row in sorted(incoming.items()):
        archive=Path(row['archive']);relative='packages/'+archive.name;dest=target/relative
        selected=dict(name=name,version=row['version'],size=archive.stat().st_size,sha256=C.sha(archive),archive=relative,
            signature=relative+'.sig',signer=roles['upstream_ALARM' if name=='lsp-plugins-lv2' else 'ephemeral_TEST'])
        helper.copy_archive(archive,dest,selected)
        if name=='lsp-plugins-lv2':
            helper.copy_archive(archive.with_name(archive.name+'.sig'),dest.with_name(dest.name+'.sig'),
                dict(size=row['signature_size'],sha256=row['signature_sha256']))
        else:to_sign.append(dest)
        rows.append(selected)
    C.need(len(rows)==604 and len(to_sign)==18 and {r['name']:r['version'] for r in rows}==after,
           'exact604 cache with18 new TEST signatures and1 official LSP input required')
    helper.sign(producer_root/'private/test-signing',to_sign,roles['ephemeral_TEST'])
    for row in rows:
        sig=target/row['signature'];row.update(signature_size=sig.stat().st_size,signature_sha256=C.sha(sig));sig.chmod(0o444)
    for key in original['keyrings']:
        helper.copy_archive(ready/key['path'],target/key['path'],dict(size=key['size'],sha256=key['sha256']))
    (target/'expected-installed.lock').write_bytes((C.HERE/'expected604.lock').read_bytes())
    shutil.copyfile(ready/'builder-packages.lock',target/'builder-packages.lock')
    producer=C.load('_604_original_public_verifier',source/'scripts/ci/full-composition-installer-vm/producer.py')
    verifier=producer.PublicVerifier(producer_root/'private/expanded604-verifier',[target/k['path'] for k in original['keyrings']])
    try:
        for row in rows:verifier(target/row['archive'],target/row['signature'],row['signer'])
    finally:verifier.close()
    total=sum(r['size'] for r in rows);C.need(total<=4*1024**3,'original compressed cache byte bound exceeded')
    payload_api=C.load('_604_original_project_payload',source/'scripts/ci/full-development-composition/run.py')
    projects=[dict(r) for r in original['projects'] if r['name'] not in C.UPGRADES]
    for name,row in incoming.items():
        if name in C.AUDIO:continue
        inspected=row['inspected'];pkg=inspected['metadata']['.PKGINFO']
        projects.append(dict(name=name,version=row['version'],archive=Path(row['archive']).name,sha256=inspected['sha256'],
            depends=pkg.get('depend',[]),provides=pkg.get('provides',[]),conflicts=pkg.get('conflict',[]),payload=payload_api.payload(inspected)))
    C.need(len(projects)==21 and len({r['name'] for r in projects})==21,'exact21 project recipes in604 required')
    result=dict(original,status='READY_SIGNED_EXPANDED604',expected_lock=dict(path='expected-installed.lock',sha256=C.TARGET_SHA),
        packages=sorted(rows,key=lambda r:r['name']),projects=projects,
        preparation=dict(original['preparation'],archive_count=604,compressed_archive_bytes=total),
        expanded604=dict(original587_sha256=C.BASE_SHA,original587_manifest_sha256=C.sha(ready/'manifest.json'),
            expected600_sha256=C.OLD600,target604_sha256=C.TARGET_SHA,inputs=evidence['summary'],new_builds='NOT_RUN_REUSED_ACCEPTED_PAIRS',
            source_native_environment='ORIGINAL574_BUILD_PROVENANCE_DISTINCT_FROM_NEW604_DEPLOYMENT',same_two_signer_roles=True,
            copied_original_archive_signatures=585,new_TEST_signatures=18,hardware='NOT_RUN',release='NOT_ADMITTED'))
    (target/'manifest.json').write_bytes(C.encoded(result))
    for name in ('manifest.json','builder-packages.lock','expected-installed.lock'):(target/name).chmod(0o444)
    C.target_manifest(target)
    for name in ('packages','keys'):(target/name).chmod(0o555)
    return target
