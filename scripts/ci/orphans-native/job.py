#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Accepted source proof, labeled consumer cleanup, then owned574 producer cleanup."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C

MAX_TOTAL=192*1024**2


def regular(path,cap):
    C.safe(path.absolute());info=path.lstat()
    C.need(stat.S_ISREG(info.st_mode) and info.st_size<=cap,'bounded regular file required: '+path.name);return info


def read(path,cap=2*1024**2):regular(path,cap);return json.loads(path.read_bytes())


def save(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def manifest_files(source,manifest):
    C.need(manifest.get('schema_version')==1 and 1<=len(manifest['files'])<=128,'closed orphans source manifest required')
    for name,row in manifest['files'].items():
        C.need(not Path(name).is_absolute() and '..' not in Path(name).parts,'safe source path required')
        path=source/name;info=regular(path,16*1024**2)
        C.need(info.st_size==row['bytes'] and C.digest(path)==row['sha256'],'source pin differs: '+name)


def prove(source,manifest,environment):
    manifest_files(source,manifest);C.verify_source(source)
    shared=C.load('accepted_orphans_source_proof',source/'scripts/ci/welcome-native/ci/caller.py')
    result=shared.prove(source,manifest,environment)
    result['consumer_token']=hashlib.sha256(('orphans-consumer:'+result['run_id']+':'+result['run_attempt']+':'+result['source_sha']).encode()).hexdigest()[:32]
    return result


def invoke(argv):
    row=subprocess.run(list(map(str,argv)),stdin=subprocess.DEVNULL,capture_output=True,
        env=dict(PATH='/usr/bin:/bin',LC_ALL='C',TZ='UTC',HOME='/tmp'),timeout=240 if str(argv[0])=='python3' else 30)
    C.need(len(row.stdout)+len(row.stderr)<=1024**2,'bounded cleanup observer required');return row


def retire_consumers(runtime,base,proof,command=invoke):
    token=proof['consumer_token'];C.need(re.fullmatch('[0-9a-f]{32}',token),'consumer token required')
    if not (runtime/'consumer.lock').exists():
        C.need(not (runtime/'owner.json').exists(),'owner without lease refused')
        return dict(status='PASS_NO_CONSUMER_ACTORS',containers=[])
    regular(runtime/'consumer.lock',0);fd=os.open(runtime/'consumer.lock',os.O_RDWR|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if not (runtime/'owner.json').exists():return dict(status='PASS_NO_CONSUMER_ACTORS',containers=[])
        owner=read(runtime/'owner.json');original=read(base/'report.json');image=original['image'];names=owner.get('containers')
        C.need(re.fullmatch('sha256:[0-9a-f]{64}',image) and owner==dict(schema_version=1,token=token,image=image,label=C.LABEL,containers=names) and
               type(names) is list and len(names)<=4 and len(set(names))==len(names) and all(
               type(n) is str and re.fullmatch(r'cachy-asahi-product-(?:(?:probe|lifecycle)-)?[0-9a-f]{32}',n) for n in names),
               'exact persisted consumer ownership required')
        def inspect(name):
            row=command(['/usr/bin/docker','container','inspect',name])
            if row.returncode:
                text=(row.stdout+row.stderr).decode(errors='replace').lower()
                C.need(row.returncode==1 and name in text and ('no such container' in text or 'no such object' in text),
                       'unknown consumer daemon state');return None
            rows=json.loads(row.stdout);C.need(len(rows)==1,'ambiguous consumer identity');value=rows[0]
            C.need(value['Image']==image and value['Config'].get('Labels',{}).get(C.LABEL)==token and
                   re.fullmatch('[0-9a-f]{64}',value['Id']) and value['Name']=='/'+name,'foreign consumer preserved')
            return value
        result=[]
        for name in reversed(names):
            value=inspect(name)
            if value is not None:C.need(command(['/usr/bin/docker','rm','-f',value['Id']]).returncode==0,'owned consumer removal failed')
            C.need(inspect(name) is None,'owned consumer remains');result.append(dict(container=name,status='PASS',absence_verified=True))
        return dict(status='PASS_CONSUMERS_RETIRED',containers=result)
    finally:os.close(fd)


def cleanup(source,manifest,proof,base,runtime,output,command=invoke):
    manifest_files(source,manifest);result=dict(status='FAIL',consumer='NOT_OBSERVED',producer='NOT_RETIRED')
    try:
        result['consumer']=retire_consumers(runtime,base,proof,command)
        if (base/'report.json').exists():
            row=command(['python3','-I','-B',str(source/'scripts/ci/maintained_desktop574.py'),'cleanup','--inputs',
                str(source/'scripts/ci/maintained-desktop574-inputs.json'),'--output',str(base),'--job-token',proof['job_token']])
            C.need(row.returncode==0,'owned574 producer cleanup failed')
            result['producer']=read(base/'report.json')['owned_cleanup'];C.need(result['producer']['status']=='PASS','producer absence unverified')
        else:result['producer']='NOT_STARTED'
        result['status']='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP'
    except BaseException as error:result.update(error=str(error)[:512],error_type=type(error).__name__)
    save(output,result);return result


def retain(source,base,runtime,proof,cleanup_path,output):
    C.safe(output.absolute());C.need(not output.exists(),'fresh public evidence directory required');output.mkdir(mode=0o700)
    result=dict(status='FAIL_OR_INCOMPLETE',files={},errors=[],total_bytes=0,selection='UNSELECTED',hardware='NOT_RUN',
                performance='NOT_MEASURED',removal='NOT_IMPLEMENTED',release_signatures='EPHEMERAL_TEST_ONLY',original_selected_inventory='UNCHANGED')
    def copy(path,name,cap,required=True):
        if not required and not path.exists() and not path.is_symlink():return
        try:
            info=regular(path,cap);C.need(result['total_bytes']+info.st_size<=MAX_TOTAL,'closed evidence total cap')
            target=output/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
            result['files'][name]=dict(bytes=info.st_size,sha256=C.digest(target));result['total_bytes']+=info.st_size
        except Exception as error:result['errors'].append(name+': '+str(error)[:256])
    copy(proof,'source-proof.json',65536);copy(cleanup_path,'ordered-cleanup.json',65536)
    for name in ('report.json','installed-packages.lock'):copy(base/name,'base/'+name,1024**2)
    for name,cap in (('report.json',4*1024**2),('lifecycle.json',4*1024**2),('owner.json',65536),
                     ('base-inventory.log',256*1024),('lifecycle.log',16*1024**2)):
        copy(runtime/name,'runtime/'+name,cap)
    for kind in ('fresh','existing'):
        for phase,count in C.PHASES:
            if count!=575:continue
            for name in ('default-assessment.json','fixture-assessment.json','fixture-plan.json','fixture-observation.json'):
                relative='public-reports/'+kind+'/'+phase+'/'+name
                copy(runtime/relative,'runtime/'+relative,32*1024**2)
    try:
        products=read(runtime/'lifecycle-inputs/products.json');archive=products[C.PRODUCT]['archive']
        C.need(re.fullmatch(r'cachy-asahi-orphans-0\.1\.0-1-any\.pkg\.tar\.(xz|zst)',archive),'exact signed candidate basename required')
        copy(runtime/'lifecycle-inputs'/archive,'signed/'+archive,8*1024**2)
        copy(runtime/'lifecycle-inputs'/(archive+'.sig'),'signed/'+archive+'.sig',16384)
    except Exception as error:result['errors'].append('signed archive: '+str(error)[:256])
    for name in ('TEST-public.asc','control.json'):copy(runtime/'lifecycle-inputs'/name,'signed/'+name,65536)
    copy(source/'scripts/ci/orphans-native/source-manifest.json','source/source-manifest.json',1024**2)
    for path in sorted((source/'scripts/ci/orphans-native').iterdir()):
        if path.is_file():copy(path,'harness/'+path.name,2*1024**2)
    for product in C.NAMES:
        for path in sorted((source/'packages/tools'/product).iterdir()):copy(path,'source/'+product+'/'+path.name,1024**2)
        copy(runtime/(product+'-comparison.json'),'runtime/'+product+'-comparison.json',2*1024**2)
        for side in ('a','b'):
            prefix=product+'-'+side;directory=runtime/prefix
            for name,cap in (('provenance.json',2*1024**2),('validation.json',2*1024**2),('build.log',16*1024**2),('expected-packages.lock',256*1024)):
                copy(directory/name,'runtime/'+prefix+'/'+name,cap)
            for name,cap in (('environment.txt',512*1024),('packages.lock',256*1024),('config.sha256',8192),
                             ('makepkg.conf',65536),('pacman.conf',65536),('generated.SRCINFO',65536)):
                copy(directory/'artifacts'/name,'runtime/'+prefix+'/artifacts/'+name,cap)
            # Retain optional makepkg function logs only when the pinned build provenance declares them.
            try:
                provenance=read(directory/'provenance.json')
                log_names=[n for n in provenance['files'] if n.startswith('artifacts/') and n.endswith('.log')]
                C.need(len(log_names)<=4,'bounded makepkg function log set required')
                for relative in log_names:
                    basename=Path(relative).name
                    C.need(relative=='artifacts/'+basename and basename.startswith(product+'-') and
                           re.fullmatch(r'[A-Za-z0-9._:+-]{1,240}\.log',basename),'unexpected makepkg log basename')
                    C.need(C.digest(directory/relative)==provenance['files'][relative],'makepkg log identity differs')
                    copy(directory/relative,'runtime/'+prefix+'/'+relative,8*1024**2)
            except Exception as error:result['errors'].append(prefix+': '+str(error)[:256])
            version=C.version(source,product)
            for suffix in ('xz','zst'):
                name=product+'-'+version+'-any.pkg.tar.'+suffix
                copy(directory/'artifacts'/name,'packages/'+prefix+'/'+name,8*1024**2,False)
    try:
        C.verify_source(source)
        source_proof=read(proof);original=read(base/'report.json');report=read(runtime/'report.json',4*1024**2)
        ordered=read(cleanup_path);owner=read(runtime/'owner.json');C.validate_lifecycle(report['lifecycle'])
        C.need(source_proof['status']=='SOURCE_PROOF_PASS' and original['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION' and
               original['ownership']['token']==source_proof['job_token'] and original['owned_cleanup']['status']=='PASS' and
               original['owned_cleanup']['image']==dict(id=original['image'],absence_verified=True) and
               original['owned_cleanup']['probe']['absence_verified'] is True,'owned base/source acceptance absent')
        C.need(report['status']=='PASS_NATIVE_ORPHANS_PAIR_AND_READONLY_LIFECYCLE' and report['base_image']==original['image'] and
               report['base_count']==574 and set(report['products'])==set(C.NAMES) and
               ordered['status']=='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP' and
               ordered['consumer']['status']=='PASS_CONSUMERS_RETIRED' and len(owner['containers'])==4 and
               len(ordered['consumer']['containers'])==4 and ordered['producer']==original['owned_cleanup'] and
               owner['token']==source_proof['consumer_token']==report['ownership_token'] and
               owner['image']==original['image'] and owner['label']==C.LABEL and
               report['base_lock_sha256']==C.digest(base/'installed-packages.lock') and
               {r['container'] for r in ordered['consumer']['containers']}==set(owner['containers']) and all(
               r['status']=='PASS' and r['absence_verified'] is True for r in ordered['consumer']['containers']),
               'all four owned consumers then producer must be retired')
        C.need(read(runtime/'lifecycle.json',4*1024**2)==report['lifecycle'],'parent/standalone lifecycle mismatch')
        run=C.load('orphans_pair_export_gate',Path(__file__).with_name('run.py'))
        for product,row in report['products'].items():
            run.pair_gate(row['comparison']);C.need(len(row['builds'])==2,'two native builds required')
            for side,build in zip(('a','b'),row['builds']):
                expected=product+'-'+C.version(source,product)+'-any.pkg.tar.'
                C.need(build['archive'] in (expected+'xz',expected+'zst'),'exact candidate basename required')
                key='packages/'+product+'-'+side+'/'+build['archive']
                C.need(key in result['files'] and result['files'][key]['sha256']==build['sha256'],'archive identity absent')
        for event in report['lifecycle']['events']:
            if event['count']!=575:continue
            for observation in event['observations']:
                kind=observation['home'].removeprefix('orphans-home-')
                for name,pin in observation['reports'].items():
                    key='runtime/public-reports/'+kind+'/'+event['phase']+'/'+name
                    C.need(key in result['files'] and result['files'][key]['sha256']==pin,'retained actual report identity absent')
                relative='public-reports/'+kind+'/'+event['phase']+'/'
                actual=read(runtime/relative/'default-assessment.json',32*1024**2)
                wanted=dict(line.split() for line in (base/'installed-packages.lock').read_text().splitlines())
                C.need(actual['scope']==C.SCOPE and actual['root']=='/' and actual['dbpath']=='/var/lib/pacman' and actual['apply_supported'] is False and
                    {n:r['version'] for n,r in actual['packages'].items()}==wanted|{C.PRODUCT:C.version(source,C.PRODUCT)} and
                    all(actual['packages'][n]['protected'] for n in wanted),'retained real575 metadata facts differ')
        signer=report.get('signer',{});C.need(signer.get('authority')=='EPHEMERAL_TEST_ONLY_OUTSIDE_UNTRUSTED_ACTORS' and
            read(runtime/'lifecycle-inputs/control.json')['signer']==signer.get('fingerprint') and re.fullmatch('[0-9A-F]{40}',signer['fingerprint']),
            'bound TEST signature authority absent')
        C.need(not result['errors'],'complete closed candidate evidence required')
        result['status']='PASS_NATIVE_ORPHANS_CANDIDATE_READONLY_LIFECYCLE'
    except Exception as error:result['errors'].append(str(error)[:512])
    save(output/'retention.json',result);return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('phase',choices=('proof','cleanup','retain'))
    for name in ('source','manifest','proof','base','runtime','cleanup','output'):parser.add_argument('--'+name,type=Path)
    args=parser.parse_args()
    if args.phase=='proof':
        value=prove(args.source,read(args.manifest),os.environ);save(args.proof,value)
        with open(os.environ['GITHUB_OUTPUT'],'a') as stream:stream.write('job_token='+value['job_token']+'\nconsumer_token='+value['consumer_token']+'\n')
    elif args.phase=='cleanup':value=cleanup(args.source,read(args.manifest),read(args.proof),args.base,args.runtime,args.output)
    else:value=retain(args.source,args.base,args.runtime,args.proof,args.cleanup,args.output)
    print(json.dumps(value,sort_keys=True,indent=2))
    raise SystemExit(int(value['status'] not in ('SOURCE_PROOF_PASS','PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP','PASS_NATIVE_ORPHANS_CANDIDATE_READONLY_LIFECYCLE')))
