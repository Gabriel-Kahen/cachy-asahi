#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reuse the existing consumer leases and owned574 image cleanup in strict dependency order."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C


def save(path,value):path.write_bytes(C.encoded(value))


def inherited(source):
    module=C.load('apps_cache_original_job',source/'scripts/ci/tools-native/job.py');module.C=C;return module


def prove(source,environment):
    C.policy();C.verify_source(source);manifest=C.read(C.HERE/'source-manifest.json')
    C.need(manifest.get('status')=='FROZEN_ROOT_FINAL_SOURCES','Root final source manifest required')
    C.need(subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True,timeout=15).strip()==environment['SOURCE_SHA'],
        'checked-out source differs from exact workflow source')
    subprocess.run(['git','-C',str(source),'diff','--exit-code','HEAD','--',str((C.HERE/'source-manifest.json').relative_to(source)),*manifest['files']],
        check=True,capture_output=True,timeout=15)
    return inherited(source).prove(source,manifest,environment)


def cleanup(source,proof,base,runtime,output,command=None):
    old=inherited(source);command=command or old.invoke
    old.manifest_files(source,C.read(C.HERE/'source-manifest.json'))
    result=dict(status='FAIL',consumer_groups={},dependency_images={},producer='NOT_RETIRED',authority='RETAINED')
    producer=C.load('apps_cache_dependency_retirement',source/'scripts/ci/maintained_desktop574.py')
    try:
        # Each group retains the original eight-container bound and exact image/label/token checks.
        for group,role in (('apps-consumers','runtime-dependency-image'),('base-consumers',None)):
            image_base=base if role is None else runtime/(role+'-image')
            if (runtime/group/'owner.json').exists():C.need((image_base/'report.json').is_file(),'consumer image owner missing')
            result['consumer_groups'][group]=old.retire_consumers(runtime/group,image_base,proof,command)
        for role in ('runtime-dependency-image',):
            directory=runtime/(role+'-image')
            if not (directory/'report.json').exists():result['dependency_images'][role]='NOT_STARTED';continue
            record=C.read(directory/'report.json');owner=record['ownership']
            if not owner['build_started']:
                tag,_=producer.owner_names(owner['token'])
                C.need(not producer.docker('image','ls','-a','--filter','reference='+tag,'-q') and
                    not producer.docker('image','ls','-a','--filter','label='+producer.OWNER_LABEL+'='+owner['token'],'-q') and record['image'] is None,
                    'dependency image creation outcome uncertain')
                retired=dict(status='PASS_NO_DEPENDENCY_IMAGE_ACTORS',absence_verified=True)
            else:
                retired=producer.retire_owned(directory,owner['token'],record);C.need(retired['status']=='PASS','owned dependency image retirement uncertain')
            result['dependency_images'][role]=retired
        # This unchanged API rechecks the base consumer lease before retiring its original owned producer.
        ordered=old.cleanup(source,C.read(C.HERE/'source-manifest.json'),proof,base,runtime/'base-consumers',runtime/'base-cleanup.json',command)
        C.need(ordered['status']=='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP','original574 cleanup failed');result['producer']=ordered
        if (base/'report.json').is_file():
            before=C.read(base/'report.json')['ownership']['before_images'];after=producer.docker('image','ls','-a','--no-trunc','-q').splitlines()
            C.need(set(before)<=set(after),'borrowed/preexisting image lost');result['borrowed_images_preserved']=True
        authority=runtime/'test-signing'
        if authority.exists():
            C.safe(authority);row=command(['gpgconf','--homedir',str(authority),'--kill','all']);C.need(row.returncode==0,'TEST agent retirement unknown')
            shutil.rmtree(authority)
        result.update(status='PASS_ORDERED_CONSUMERS_DEPENDENCY_IMAGES_PRODUCER_AND_AUTHORITY',authority='PASS_REMOVED_AFTER_ACTOR_RETIREMENT')
    except BaseException as error:result.update(error_type=type(error).__name__,error=str(error)[:512])
    save(output,result);return result


def retain(source,base,runtime,proof,cleanup_path,output):
    C.safe(output);C.need(not output.exists(),'fresh bounded public export required');output.mkdir(mode=0o700)
    old=inherited(source);result=dict(status='FAIL_OR_INCOMPLETE',files={},errors=[],bytes=0,hardware='NOT_RUN',release='NOT_ADMITTED',cache_cleanup='NOT_RUN')
    def copy(path,name,cap,required=True):
        if not required and not path.exists():return
        try:
            info=old.regular(path,cap);C.need(result['bytes']+info.st_size<=old.MAX_TOTAL,'inherited192MiB export cap')
            target=output/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
            result['files'][name]=dict(bytes=info.st_size,sha256=C.digest(target));result['bytes']+=info.st_size
        except Exception as error:result['errors'].append(name+': '+str(error)[:256])
    copy(proof,'source-proof.json',65536);copy(cleanup_path,'ordered-cleanup.json',65536)
    for name in ('report.json','installed-packages.lock'):copy(base/name,'base/'+name,1024**2)
    for name in ('report.json','lifecycle.json','groups.json','runtime-image.json','runtime575.lock'):
        copy(runtime/name,'runtime/'+name,4*1024**2,name in ('report.json','lifecycle.json','groups.json','runtime-image.json','runtime575.lock'))
    for group in ('base-consumers','apps-consumers'):
        copy(runtime/group/'owner.json','runtime/'+group+'/owner.json',65536)
    for role in ('runtime-dependency-image',):
        copy(runtime/(role+'-image/report.json'),'runtime/'+role+'-image/report.json',65536,role.startswith('runtime'))
    for name in ('base-inventory.log','lifecycle.log','catalog-fixture.log','runtime-dependency-image-install.log','runtime-dependency-image-commit.log'):
        copy(runtime/name,'runtime/'+name,16*1024**2)
    for path in sorted(C.HERE.iterdir()):
        if path.is_file():copy(path,'harness/'+path.name,4*1024**2)
    for name in C.NAMES:
        copy(runtime/(name+'-comparison.json'),'runtime/'+name+'-comparison.json',2*1024**2)
        for path in sorted((source/'packages/tools'/name).iterdir()):copy(path,'source/'+name+'/'+path.name,2*1024**2)
        for side in ('a','b'):
            directory=runtime/(name+'-'+side);prefix='runtime/'+name+'-'+side+'/'
            for file,cap in (('provenance.json',2*1024**2),('validation.json',2*1024**2),('expected-packages.lock',256*1024),('build.log',16*1024**2)):
                copy(directory/file,prefix+file,cap)
            for file,cap in (('environment.txt',512*1024),('packages.lock',256*1024),('config.sha256',8192),('makepkg.conf',65536),('pacman.conf',65536),('generated.SRCINFO',65536)):
                copy(directory/'artifacts'/file,prefix+'artifacts/'+file,cap)
            for suffix in ('xz','zst'):
                file=name+'-'+C.version(source,name)+'-any.pkg.tar.'+suffix
                copy(directory/'artifacts'/file,'packages/'+name+'-'+side+'/'+file,8*1024**2,False)
    # Public verification material only; never export authority homes or private keys.
    copy(runtime/'lifecycle-inputs/TEST-public.asc','trust/TEST-public.asc',65536)
    for name in C.NAMES:
        version=C.version(source,name)
        for suffix in ('xz','zst'):
            archive=name+'-'+version+'-any.pkg.tar.'+suffix
            copy(runtime/'lifecycle-inputs'/(archive+'.sig'),'trust/'+archive+'.sig',65536,False)
    fixture=runtime/'catalog-fixture'
    if fixture.exists():
        entries=list(fixture.rglob('*'));C.need(len(entries)<=128,'closed synthetic fixture node bound')
        links={}
        for path in sorted(entries):
            if path.is_symlink():links[path.relative_to(fixture).as_posix()]=os.readlink(path)
            elif path.is_file():copy(path,'signed-synthetic-fixture/'+path.relative_to(fixture).as_posix(),8*1024**2)
            else:C.need(path.is_dir(),'synthetic fixture special node refused')
        path=output/'signed-synthetic-fixture-links.json';raw=C.encoded(links)
        C.need(len(raw)<=65536 and result['bytes']+len(raw)<=old.MAX_TOTAL,'synthetic link metadata bound')
        path.write_bytes(raw);result['files'][path.name]=dict(bytes=len(raw),sha256=C.digest(path));result['bytes']+=len(raw)
    try:
        C.verify_source(source);report=C.read(runtime/'report.json');C.validate_lifecycle(report['lifecycle'])
        C.need(report['status']=='PASS_NATIVE_APPS_RUNTIME_CACHE_PAIRS_AND_INSTALLED_LIFECYCLE' and set(report['products'])==set(C.NAMES) and
            C.read(runtime/'lifecycle.json')==report['lifecycle'],'native parent/installed result mismatch')
        ordered=C.read(cleanup_path);source_proof=C.read(proof);original=C.read(base/'report.json')
        C.need(source_proof['status']=='SOURCE_PROOF_PASS' and original['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION' and
            original['ownership']['token']==source_proof['job_token'] and original['owned_cleanup']['status']=='PASS' and
            original['owned_cleanup']['image']==dict(id=original['image'],absence_verified=True) and
            report['base_image']==original['image'] and report['ownership_token']==source_proof['consumer_token'],
            'source/producer/consumer native identity mismatch')
        C.need(ordered['status']=='PASS_ORDERED_CONSUMERS_DEPENDENCY_IMAGES_PRODUCER_AND_AUTHORITY' and
            ordered.get('borrowed_images_preserved') is True and ordered['authority']=='PASS_REMOVED_AFTER_ACTOR_RETIREMENT',
            'ordered actor/image/authority cleanup missing')
        for group,count in [('base-consumers',8),('apps-consumers',2)]:
            owner=C.read(runtime/group/'owner.json');retired=ordered['consumer_groups'][group]
            C.need(owner['token']==source_proof['consumer_token'] and owner['label']==C.LABEL and len(owner['containers'])==count and
                retired['status']=='PASS_CONSUMERS_RETIRED' and {r['container'] for r in retired['containers']}==set(owner['containers']) and
                all(r['status']=='PASS' and r['absence_verified'] is True for r in retired['containers']),
                'exact bounded owned consumer set/retirement missing')
        pair=C.load('apps_cache_export_pairs',source/'scripts/ci/tools-native/run.py')
        environments=set()
        for name,row in report['products'].items():
            pair.pair_gate(row['comparison']);C.need(len(row['builds'])==2,'two clean native builds required')
            for side,build in zip(('a','b'),row['builds']):
                provenance=C.read(runtime/(name+'-'+side)/'provenance.json')
                C.need(provenance['status']=='built-package-static-pass' and provenance['mode']=='native' and
                    provenance['image_id']==row['build_image'] and provenance['expected_packages_sha256']==row['build_inventory_sha256'] and
                    provenance['clean_environment_id'] not in environments,'six clean native build bindings required')
                environments.add(provenance['clean_environment_id'])
                C.need('--network=none' in provenance['command'] and '--read-only' in provenance['command'] and
                    not any('/authority' in part or 'test-signing' in part for part in provenance['command']),
                    'build actor authority/network/read-only boundary differs')
                key='packages/'+name+'-'+side+'/'+build['archive']
                C.need(key in result['files'] and result['files'][key]['sha256']==build['sha256'],'complete reproduced archive pair missing')
        C.need(not result['errors'],'closed evidence export incomplete');result.update(status='PASS_NATIVE_UNSELECTED_APPS_RUNTIME_CACHE_CANDIDATES',cache_cleanup='APPLIED_DISPOSABLE_FIXTURES_ONLY',cache_apply='PASS_REAL_ALPM16_EMPTY_TRANSACTION')
    except Exception as error:result['errors'].append(str(error)[:512])
    save(output/'retention.json',result);return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=('proof','cleanup','retain'))
    for name in ('source','proof','base','runtime','cleanup','output'):p.add_argument('--'+name,type=Path)
    a=p.parse_args()
    if a.phase=='proof':
        value=prove(a.source,os.environ);save(a.proof,value)
        with open(os.environ['GITHUB_OUTPUT'],'a') as stream:
            stream.write('job_token='+value['job_token']+'\nconsumer_token='+value['consumer_token']+'\n')
    elif a.phase=='cleanup':value=cleanup(a.source,C.read(a.proof),a.base,a.runtime,a.output)
    else:value=retain(a.source,a.base,a.runtime,a.proof,a.cleanup,a.output)
    print(json.dumps(value,sort_keys=True));raise SystemExit(int(value['status'] not in (
        'SOURCE_PROOF_PASS','PASS_ORDERED_CONSUMERS_DEPENDENCY_IMAGES_PRODUCER_AND_AUTHORITY','PASS_NATIVE_UNSELECTED_APPS_RUNTIME_CACHE_CANDIDATES')))
