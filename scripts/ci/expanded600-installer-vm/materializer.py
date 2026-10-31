# SPDX-License-Identifier: MIT
"""Reuse accepted pairs, preserve original archive bytes, sign only in private producer state."""
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import contract as C

META={'.PKGINFO','.BUILDINFO','.MTREE'}


def legacy_inputs(legacy):
    base=legacy/'scripts/ci/expanded-development-composition'
    contract=C.load('_installer600_input_contract',base/'contract.py')
    module=C.load('_installer600_input_reader',base/'inputs.py');module.C=contract
    return contract,module


def bang_pair(root,row,legacy,old,reader):
    fields={'version','native_source','native_run','qualification','evidence','files','metadata',
            'recipe_inputs','sources','payload','raw_lifecycle','acceptance'}
    C.need(set(row)==fields and row['version']=='0.1.0-2' and re.fullmatch('[0-9a-f]{40}',row['native_source']) and
           type(row['native_run']) is int and row['native_run']>0 and row['qualification'].startswith('PASS'),
           'accepted bang2 source/run/version fields incomplete')
    C.need(set(row['files'])=={'a','b'} and row['files']['a']['sha256']==row['files']['b']['sha256'] and
           row['files']['a']['bytes']==row['files']['b']['bytes'] and row['files']['a']['path']!=row['files']['b']['path'],
           'two distinct complete byte-identical bang2 archives required')
    C.need(set(row['sources'])==set(row['recipe_inputs']) and 'PKGBUILD' in row['recipe_inputs'],
           'bang2 complete source/license closure required')
    for name,ref in row['sources'].items():
        C.need(Path(name).name==name and ref['sha256']==row['recipe_inputs'][name],'bang source map differs')
        path=C.checked(root,ref)
        C.need(C.sha(legacy/'packages/shells'/C.BANG/name)==C.sha(path),'accepted bang2 differs from held product source')
    checks,bind=reader.tools(legacy);reports=[]
    for side in ('a','b'):
        path=C.checked(root,row['files'][side],8*1024**2)
        C.need(path.name in (C.BANG+'-0.1.0-2-any.pkg.tar.xz',C.BANG+'-0.1.0-2-any.pkg.tar.zst'),'exact bang2 archive basename required')
        report=checks.package(path)
        C.need(not report['errors'] and not report['elf'] and
               not bind.bind_artifact(row['metadata'],report,row['recipe_inputs']['PKGBUILD']),
               'bang2 archive/BUILDINFO metadata differs')
        actual={p:n for p,n in report['members'].items() if n['type']!='5' and p not in META}
        C.need(actual==row['payload'] and len(actual)==7 and
               all(n['type']=='0' and n['uid']==n['gid']==0 and n['mode']==0o644 and
                   any(ref['sha256']==n['sha256'] and ref['bytes']==n['size'] for ref in row['sources'].values())
                   for n in actual.values()),'bang2 seven installed source/license members differ')
        C.need(not any(report['metadata']['.PKGINFO'].get(k) for k in ('conflict','replaces','backup')),
               'bang2 replacement/config mutation refused');reports.append(report)
    C.need(reports[0]['metadata']['.BUILDINFO']==reports[1]['metadata']['.BUILDINFO'],'bang2 pair BUILDINFO differs')
    accepted=C.read(C.checked(root,row['acceptance']));C.checked(root,row['evidence'])
    C.need(accepted.get('status')=='ROOT_ACCEPTED_NATIVE_CANDIDATE' and accepted.get('name')==C.BANG and
           accepted.get('version')=='0.1.0-2' and accepted.get('source_sha')==row['native_source'] and
           accepted.get('native_run')==row['native_run'] and accepted.get('native_pair')=='PASS_BYTES_IDENTICAL' and
           accepted.get('native_lifecycle')=='PASS' and accepted.get('qualification')==row['qualification'] and
           accepted.get('archive_sha256')==row['files']['a']['sha256'] and
           accepted.get('raw_lifecycle_sha256')==row['raw_lifecycle']['sha256'],'Root bang2 acceptance differs')
    life=C.read(C.checked(root,row['raw_lifecycle']));old.validate_result(life)
    return dict(row,archive=str(C.checked(root,row['files']['a'],8*1024**2)),inspected=reports[0])


def accepted_pairs(eight,seven,legacy,policy):
    old,reader=legacy_inputs(legacy)
    original=C.read(C.checked(seven,policy['retained_seven_index']))
    value=C.read(C.checked(eight,policy['eight_pair_index']))
    C.need(value.get('schema_version')==1 and value.get('status')=='READY_EIGHT_RETAINED_FOR_SIGNED_EXPANDED600_INSTALLER' and
           value.get('hardware')=='NOT_RUN' and value.get('release')=='NOT_ADMITTED' and
           type(value.get('packages')) is dict and set(value['packages'])==C.SCRIPTS|{C.BANG},
           'final immutable accepted eight-pair index required')
    C.need({n:value['packages'][n] for n in C.SCRIPTS}==original['packages'],
           'the original seven retained input rows must remain unchanged')
    rows=reader.retained(eight,original,legacy)
    rows[C.BANG]=bang_pair(eight,value['packages'][C.BANG],legacy,old,reader)
    return rows


def copy_archive(source,target,row):
    C.need(source.is_file() and not source.is_symlink() and source.stat().st_size==row['size'] and C.sha(source)==row['sha256'] and
           not target.exists(),'fresh exact archive copy required')
    shutil.copyfile(source,target);C.need(C.sha(target)==row['sha256'],'copied archive differs');target.chmod(0o444)


def sign(home,paths,signer):
    C.safe(home);info=home.stat()
    C.need(info.st_uid==__import__('os').getuid() and __import__('stat').S_IMODE(info.st_mode)==0o700,
           'owned original producer signing home required')
    argv=['gpg','--batch','--no-options','--homedir',str(home),'--no-auto-key-retrieve',
          '--pinentry-mode','loopback','--passphrase','']
    listing=subprocess.check_output(argv+['--with-colons','--list-secret-keys'],text=True,timeout=20)
    fingerprints=[line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')]
    C.need(fingerprints==[signer],'original producer TEST secret-key role differs')
    try:
        for path in paths:
            subprocess.run(argv+['--local-user',signer,'--output',str(path)+'.sig','--detach-sign',str(path)],
                           check=True,capture_output=True,timeout=30)
    finally:subprocess.run(['gpgconf','--homedir',str(home),'--kill','all'],check=True,capture_output=True,timeout=15)


def prepare(ready,producer_root,eight,seven,audio,legacy,target,policy):
    """Called only after final policy/prerequisite acceptance and original producer success."""
    C.prerequisites(eight,policy);pairs=accepted_pairs(eight,seven,legacy,policy)
    old,reader=legacy_inputs(legacy);audios=reader.audio(audio,legacy)
    profile=C.load('_installer600_original_profile',legacy/'scripts/ci/full-composition-installer-vm/profile.py')
    original,_,before=profile.manifest(ready);oldmap,newmap=C.locks()
    C.need(before==oldmap,'held original587 export differs')
    C.need(set(pairs)==C.SCRIPTS|{C.BANG} and set(audios)==C.AUDIO,'six audio and eight script pairs required')
    additions=list(audios.values())+[dict(row,name=name) for name,row in pairs.items()]
    C.need(before|{r['name']:r['version'] for r in additions}==newmap,'accepted archives do not define exact600')
    C.need(not target.exists(),'fresh expanded600 ready output required');target.mkdir(mode=0o700)
    (target/'packages').mkdir();(target/'keys').mkdir()
    rows=[];to_sign=[]
    for row in original['packages']:
        if row['name']==C.BANG:continue
        dest=target/row['archive'];copy_archive(ready/row['archive'],dest,row)
        sig=dict(size=row['signature_size'],sha256=row['signature_sha256'])
        copy_archive(ready/row['signature'],target/row['signature'],sig);rows.append(row)
    test=original['preparation']['signer_roles']['ephemeral_TEST'];alarm=original['preparation']['signer_roles']['upstream_ALARM']
    for row in additions:
        source=Path(row['archive']);archive='packages/'+source.name;dest=target/archive
        selected=dict(name=row['name'],version=row['version'],size=source.stat().st_size,sha256=C.sha(source),
                      archive=archive,signature=archive+'.sig',signer=alarm if row['name']=='lsp-plugins-lv2' else test)
        copy_archive(source,dest,selected)
        if row['name']=='lsp-plugins-lv2':
            copy_archive(source.with_name(source.name+'.sig'),dest.with_name(dest.name+'.sig'),
                         dict(size=row['signature_size'],sha256=row['signature_sha256']))
        else:to_sign.append(dest)
        rows.append(selected)
    C.need(len(rows)==600 and len(to_sign)==13,'exact600 archive/thirteen new-signature counts required')
    sign(producer_root/'private/test-signing',to_sign,test)
    for row in rows:
        sig=target/row['signature'];row.update(signature_size=sig.stat().st_size,signature_sha256=C.sha(sig));sig.chmod(0o444)
    for key in original['keyrings']:
        copy_archive(ready/key['path'],target/key['path'],dict(size=key['size'],sha256=key['sha256']))
    (target/'expected-installed.lock').write_bytes((C.HERE/'expected600.lock').read_bytes())
    shutil.copyfile(ready/'builder-packages.lock',target/'builder-packages.lock')
    producer=C.load('_installer600_verifier',legacy/'scripts/ci/full-composition-installer-vm/producer.py')
    verifier=producer.PublicVerifier(producer_root/'private/expanded600-verifier',[target/k['path'] for k in original['keyrings']])
    try:
        for row in rows:verifier(target/row['archive'],target/row['signature'],row['signer'])
    finally:verifier.close()
    C.need(sum(r['size'] for r in rows)<=4*1024**3,'original compressed cache bound exceeded')
    result=dict(original,status='READY_SIGNED_EXPANDED600',expected_lock=dict(path='expected-installed.lock',sha256=C.AFTER),
        packages=sorted(rows,key=lambda r:r['name']),expanded600=dict(original587_sha256=C.BEFORE,eight_pair_source=policy['eight_pair_source'],
            index=policy['eight_pair_index'],new_builds='NOT_RUN_RETAINED_EIGHT_PAIRS',same_two_signer_roles=True))
    # Old project metadata is evidence only; replace the selected bang row with its
    # exact inspected successor and append the seven accepted additions.
    payload_api=C.load('_installer600_project_payload',legacy/'scripts/ci/full-development-composition/run.py')
    result['preparation']=dict(original['preparation'],archive_count=600,compressed_archive_bytes=sum(r['size'] for r in rows))
    result['expanded600']['original587_manifest_sha256']=C.sha(ready/'manifest.json')
    project_rows=[]
    for row in original['projects']:
        if row['name']!=C.BANG:project_rows.append(row)
    for name,row in pairs.items():
        pkg=row['inspected']['metadata']['.PKGINFO']
        project_rows.append(dict(name=name,version=row['version'],archive=Path(row['archive']).name,sha256=row['inspected']['sha256'],
            depends=pkg.get('depend',[]),provides=pkg.get('provides',[]),conflicts=pkg.get('conflict',[]),payload=payload_api.payload(row['inspected'])))
    result['projects']=project_rows
    (target/'manifest.json').write_bytes(C.encoded(result))
    for name in ('expected-installed.lock','builder-packages.lock','manifest.json'):(target/name).chmod(0o444)
    for name in ('packages','keys'):(target/name).chmod(0o555)
    return target
