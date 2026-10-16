# SPDX-License-Identifier: MIT
"""Bounded, passive input checks. No fetch, build, signing or installation."""
from pathlib import Path
import shutil
import sys
import contract as C

META={'.PKGINFO','.BUILDINFO','.MTREE'}


def tools(code):
    sys.path.insert(0,str(code/'scripts/checks'))
    checks=C.load('expanded_package_checks',code/'scripts/checks/package_checks.py')
    bind=C.load('expanded_build_binding',code/'scripts/build/build.py')
    return checks,bind


def retained(root,index,code):
    rows=C.accepted_index(root,index)
    checks,bind=tools(code)
    result={}
    for name,row in rows.items():
        if '.SRCINFO' in row['sources']:
            sourceinfo=C.checked(root,row['sources']['.SRCINFO'])
            bind.bind_generated(row['metadata'],checks.metadata(sourceinfo.read_text()))
        pair=[]
        for ref in (row['files']['a'],row['files']['b']):
            report=checks.package(C.checked(root,ref,8*1024**2))
            C.need(not report['errors'] and not bind.bind_artifact(row['metadata'],report,row['recipe_inputs']['PKGBUILD']),
                   'retained package metadata/BUILDINFO rejected: '+name)
            actual={p:n for p,n in report['members'].items() if n['type']!='5' and p not in META}
            C.need(actual==row['payload'],'retained installed payload differs: '+name)
            C.need(all(n['type'] in ('0','5') and n['uid']==n['gid']==0 for n in report['members'].values()),
                   'ordinary root-owned retained archive required')
            C.need(not any(report['metadata']['.PKGINFO'].get(k) for k in ('conflict','replaces','backup')),
                   'retained replacement/config mutation refused')
            pair.append(report)
        C.need(pair[0]['metadata']['.BUILDINFO']==pair[1]['metadata']['.BUILDINFO'],
               'retained pair BUILDINFO differs')
        result[name]=dict(row,name=name,archive=str(C.checked(root,row['files']['a'],8*1024**2)),
                          inspected=pair[0])
    return result


def audio(root,code):
    policy=code/'scripts/ci/full-development-composition/audio-inputs.json'
    C.need(C.sha(policy)==C.AUDIO_SHA,'audio source policy changed')
    rows=C.read(policy);C.need(len(rows)==6 and {r['name'] for r in rows}==C.AUDIO,'six exact audio rows required')
    checks,_=tools(code)
    helper=C.load('expanded_audio_inputs',code/'scripts/ci/full-development-composition/audio_inputs.py')
    api=C.load('expanded_audio_api',code/'scripts/ci/full-development-composition/run.py')
    expected={r['filename'] for r in rows}|{r['filename']+'.sig' for r in rows if r['origin']=='ALARM'}
    C.need({p.name for p in root.iterdir()}==expected,'closed audio input directory required')
    result={}
    for row in rows:
        path=C.checked(root,dict(path=row['filename'],bytes=row['size'],sha256=row['sha256']))
        report=checks.package(path);inspected=helper.inspect(row,report,api)
        if row['origin']=='ALARM':
            C.checked(root,dict(path=row['filename']+'.sig',bytes=row['signature_size'],sha256=row['signature_sha256']),1024**2)
        result[row['name']]=dict(inspected,archive=str(path),inspected=report)
    return result


def combined(root,policy):
    """The driver is data until launched inside the owned600 container."""
    bound=policy['combined']
    C.need(set(bound)=={'source','files','entry','arguments','receipt','status'} and
           bound['status']=='ROOT_BOUND_SIX_MODULE_DRIVER' and
           type(bound['files']) is dict and bound['files'] and bound['entry'] in bound['files'] and
           bound['receipt']=='receipt.json' and
           bound['arguments']==['--source','/combined','--output','{work}'],
           'fixed installed-driver interface required')
    C.need(__import__('re').fullmatch('[0-9a-f]{40}',bound['source'] or ''),'immutable combined source required')
    for name,ref in bound['files'].items():
        C.need(ref['path']==name,'combined closure paths differ');C.checked(root,ref)
    return bound


def plan(ready,bundle,audio_root,code,bang,combined_root,policy,target):
    """Validate before copying the fourteen incoming files; signing follows later."""
    profile=C.load('expanded_original_profile',code/'scripts/ci/full-composition-installer-vm/profile.py')
    original,manifest_ref,before=profile.manifest(ready)
    index=C.read(C.checked(bundle,policy['script_index']))
    scripts=retained(bundle,index,code);audios=audio(audio_root,code)
    driver=combined(combined_root,policy)
    C.need(bang['name']==C.UPGRADE and bang['version']==C.NEW and bang['pair_status']=='PASS_BYTES_AND_BUILDINFO_IDENTICAL',
           'new in-lane bang2 pair has not passed')
    checked=C.checked(Path(bang['root']),bang['archive_ref'],8*1024**2)
    rows=list(audios.values())+list(scripts.values())+[dict(bang,archive=str(checked))]
    after=C.selected(before,{n:r['version'] for n,r in audios.items()},
                     {n:r['version'] for n,r in scripts.items()}|{C.UPGRADE:C.NEW})
    C.need(not target.exists(),'fresh addon directory required');target.mkdir(mode=0o700)
    selection=[];sign=[]
    for row in rows:
        source=Path(row['archive']);dest=target/source.name
        C.need(not dest.exists(),'incoming archive basename collision')
        shutil.copyfile(source,dest)
        signature=source.with_name(source.name+'.sig')
        alarm=row['name']=='lsp-plugins-lv2'
        if alarm:shutil.copyfile(signature,dest.with_name(dest.name+'.sig'))
        else:sign.append(dest)
        inspected=row['inspected']
        selection.append(dict(name=row['name'],version=row['version'],archive=dest.name,size=dest.stat().st_size,
                              sha256=C.sha(dest),metadata=inspected['metadata']['.PKGINFO'],
                              payload={p:n for p,n in inspected['members'].items() if n['type']!='5' and p not in META},
                              signer_role='ALARM' if alarm else 'expanded_TEST'))
    C.need(len(selection)==14 and len(sign)==13,'exact fourteen inputs/thirteen new signatures required')
    return dict(schema_version=1,baseline_sha256=C.BASE_SHA,original_manifest=manifest_ref,
                before=before,after=after,incoming=selection,combined=driver),sign
