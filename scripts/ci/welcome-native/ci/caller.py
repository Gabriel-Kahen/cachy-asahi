#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source proof and closed capped export of the two product candidates."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat

NAMES=('cachy-asahi-welcome',)
MAX_TOTAL=128*1024**2


def need(ok,message):
    if not ok:raise ValueError(message)


def digest(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def regular(path,cap):
    need(not any(p.is_symlink() for p in (path,*path.parents)),'symlink refused')
    info=path.lstat();need(stat.S_ISREG(info.st_mode) and info.st_size<=cap,'unsafe/oversized file: '+path.name)
    return info


def read(path,cap=16*1024**2):regular(path,cap);return json.loads(path.read_text())


def prove(workspace,manifest,environment):
    source=environment['SOURCE_SHA']
    need(re.fullmatch('[0-9a-f]{40}',source) and source==environment['GITHUB_SHA']==environment['GITHUB_WORKFLOW_SHA'],
         'exact source/workflow revision required')
    need(environment['RUNNER_ARCH']=='ARM64' and environment['RUNNER_OS']=='Linux','native ARM runner required')
    run,attempt=environment['GITHUB_RUN_ID'],environment['GITHUB_RUN_ATTEMPT']
    need(re.fullmatch('[1-9][0-9]{0,19}',run) and re.fullmatch('[1-9][0-9]{0,9}',attempt),'run identity differs')
    for name,row in manifest['files'].items():
        path=Path(name);need(not path.is_absolute() and '..' not in path.parts,'unsafe source path')
        target=workspace/path;info=regular(target,16*1024**2)
        need(info.st_size==row['bytes'] and digest(target)==row['sha256'],'source pin differs: '+name)
    return dict(status='SOURCE_PROOF_PASS',source_sha=source,workflow_sha=source,run_id=run,run_attempt=attempt,
        source_files=len(manifest['files']),job_token=hashlib.sha256(('product-build-pair:'+run+':'+attempt+':'+source).encode()).hexdigest()[:16])


def retain(base,runtime,proof,output):
    need(not output.exists() and not output.is_symlink(),'fresh public output required');output.mkdir(mode=0o700)
    result=dict(status='NOT_ACCEPTED',files={},errors=[],total_bytes=0,GUI='NOT_RUN',hardware='NOT_RUN',
                selection='UNSELECTED_CANDIDATES',release_trust='NOT_RUN',original_ten_composition='UNCHANGED')
    def copy(source,name,cap,required=True):
        if not required and not source.exists() and not source.is_symlink():return
        try:
            info=regular(source,cap);need(result['total_bytes']+info.st_size<=MAX_TOTAL,'public total cap')
            target=output/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
            result['total_bytes']+=info.st_size;result['files'][name]=dict(bytes=info.st_size,sha256=digest(target))
        except Exception as error:result['errors'].append(str(error)[:512])
    copy(proof,'source-proof.json',128*1024)
    for name in ('report.json','installed-packages.lock'):copy(base/name,'base/'+name,512*1024)
    for name in ('report.json',):copy(runtime/name,'runtime/'+name,16*1024**2)
    for name in ('base-inventory.log',):copy(runtime/name,'runtime/'+name,16*1024**2,False)
    try:
        cleanup=read(runtime/'report.json')['cleanup'];need(len(cleanup)<=6,'cleanup record cap')
        for entry in cleanup:
            name=entry['container']
            need(re.fullmatch(r'cachy-asahi-product-(?:(?:probe|lifecycle)-)?[0-9a-f]{32}',name),'unsafe cleanup name')
            copy(runtime/('cleanup-'+name+'.log'),'runtime/cleanup-'+name+'.log',65536)
    except Exception as error:result['errors'].append(str(error)[:512])
    for product in NAMES:
        copy(runtime/(product+'-comparison.json'),'runtime/'+product+'-comparison.json',2*1024**2,True)
        for side in ('a','b'):
            prefix=product+'-'+side;directory=runtime/prefix
            for name,cap in (('provenance.json',2*1024**2),('validation.json',8*1024**2),('build.log',16*1024**2),
                             ('expected-packages.lock',256*1024)):
                copy(directory/name,'runtime/'+prefix+'/'+name,cap,True)
            for name,cap in (('environment.txt',512*1024),('packages.lock',256*1024),('config.sha256',8192),
                             ('makepkg.conf',65536),('pacman.conf',65536),('generated.SRCINFO',65536)):
                copy(directory/'artifacts'/name,'runtime/'+prefix+'/artifacts/'+name,cap,True)
            # Only the exact expected candidate basename; arbitrary artifacts stay private.
            arch='aarch64'
            for suffix in ('xz','zst'):
                version='0.1.0-7'
                name=product+'-'+version+'-'+arch+'.pkg.tar.'+suffix
                copy(directory/'artifacts'/name,'packages/'+prefix+'/'+name,8*1024**2,False)
    try:
        source=read(proof,128*1024);original=read(base/'report.json',512*1024);report=read(runtime/'report.json')
        need(source['status']=='SOURCE_PROOF_PASS' and original['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION', 'source/base result absent')
        need(original['ownership']['token']==source['job_token'] and original['owned_cleanup']['status']=='PASS' and
             original['owned_cleanup']['image']==dict(id=original['image'],absence_verified=True) and
             original['owned_cleanup']['probe']['absence_verified'] is True,'original owned builder cleanup incomplete')
        need(report['status']=='PASS_NATIVE_WELCOME7_BUILD_PAIR_CONTENTS_ONLY' and
             report['base_image']==original['image'] and report['base_count']==574 and
             set(report['products'])==set(NAMES),'native product pair absent')
        need(len(report['cleanup'])==3 and len({r['container'] for r in report['cleanup']})==3 and all(r.get('status')=='PASS' and r.get('absence_verified') is True
             for r in report['cleanup']),'three owned build containers not retired')
        for product in NAMES:
            row=report['products'][product]
            need(row['comparison']['status']=='contents-reproduced' and not row['comparison']['errors'] and len(row['builds'])==2,
                 'fresh pair comparison absent')
            for side,build in zip(('a','b'),row['builds']):
                relative='packages/'+product+'-'+side+'/'+build['archive']
                need(relative in result['files'] and result['files'][relative]['sha256']==build['sha256'], 'candidate archive/hash absent')
        need(not result['errors'],'public evidence incomplete')
        result.update(status='PASS_NATIVE_WELCOME7_BUILD_PAIR_RETAINED_ONLY',reproducibility={
            name:report['products'][name]['comparison']['packages'] for name in NAMES})
    except Exception as error:result['errors'].append(str(error)[:512])
    (output/'retention.json').write_text(json.dumps(result,indent=2)+'\n');return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('phase',choices=('proof','retain'))
    for name in ('workspace','manifest','proof','base','runtime','output'):parser.add_argument('--'+name,type=Path)
    args=parser.parse_args()
    if args.phase=='proof':
        spec=importlib.util.spec_from_file_location('doctor2_source_activation',Path(__file__).resolve().parents[1]/'contract.py')
        contract=importlib.util.module_from_spec(spec);spec.loader.exec_module(contract);contract.activation(args.workspace.resolve())
        result=prove(args.workspace.resolve(),read(args.manifest,512*1024),os.environ)
        result['manifest_sha256']=digest(args.manifest)
        with args.proof.open('x') as stream:json.dump(result,stream,indent=2);stream.write('\n')
        with open(os.environ['GITHUB_OUTPUT'],'a') as stream:stream.write('job_token='+result['job_token']+'\n')
    else:result=retain(args.base,args.runtime,args.proof,args.output)
    print(json.dumps(result,indent=2));return int(result['status'] not in ('SOURCE_PROOF_PASS','PASS_NATIVE_WELCOME7_BUILD_PAIR_RETAINED_ONLY'))


if __name__=='__main__':raise SystemExit(main())
