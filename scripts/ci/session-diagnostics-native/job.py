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
    C.safe(source.absolute())
    C.need(manifest.get('schema_version')==1 and 32<=len(manifest['files'])<=128 and
           manifest.get('self_excluded')==C.LANE+'/source-manifest.json' and
           C.ACTOR in manifest['files'] and C.ALIAS in manifest['files'],'complete closed source manifest required')
    for name,row in manifest['files'].items():
        C.need(not Path(name).is_absolute() and '..' not in Path(name).parts and
               type(row) is dict and set(row)=={'bytes','sha256'},'safe source path/hash row required')
        path=source/name;info=regular(path,16*1024**2)
        C.need(info.st_size==row['bytes'] and C.digest(path)==row['sha256'],'source pin differs: '+name)
    actual=set()
    for path in source.rglob('*'):
        name=path.relative_to(source).as_posix()
        if path.relative_to(source).parts[0] in ('.git','retained-public-inputs','retained574'):continue
        C.need(not path.is_symlink(),'source tree symlinks refused')
        if path.is_file() and name!=manifest['self_excluded']:actual.add(name)
    C.need(actual==set(manifest['files']),'unmanifested or missing source file')
    pins=read(source/C.LANE/'source-pins.json')
    C.need(pins=={name:row['sha256'] for name,row in manifest['files'].items()
                 if name!=C.LANE+'/source-pins.json'},'complete secondary source pins required')
    C.need((source/C.ACTOR).read_bytes()==(source/C.ALIAS).read_bytes(),'registered workflow alias differs')


def prove(source,manifest,environment):
    manifest_files(source,manifest);C.verify_source(source)
    policy=read(C.HERE/'input-policy.json')
    C.need(policy['candidate_files']==C.frozen_files() and policy['dispatcher_workflow_id']==381664314,
           'frozen package policy and registered dispatcher required')
    C.need(re.fullmatch('[0-9a-f]{40}',policy.get('candidate_source') or ''),'Root-bound published candidate source required before secrets')
    shared=C.load('accepted_tools_source_proof',source/'scripts/ci/welcome-native/ci/caller.py')
    result=shared.prove(source,manifest,environment)
    result['dispatcher_workflow_id']=381664314
    result['source_manifest_sha256']=C.digest(source/C.LANE/'source-manifest.json')
    result['consumer_token']=hashlib.sha256(('session-diagnostics-consumer:'+result['run_id']+':'+result['run_attempt']+':'+result['source_sha']).encode()).hexdigest()[:32]
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


def fixture_evidence(source,runtime,life,rows):
    """Join every raw ordinary-user report to the finite lifecycle and source."""
    expected=set();fixture=C.load('diagnostics_raw_schema',source/C.LANE/'cli_fixture.py')
    for label,users in [('staged-before-install',life['staged_observations'])]+[
            (event['phase'],event['observations']) for event in life['events'] if event['inventory_count']==575]:
        for user in users:
            proof=user['session_diagnostics'];prefix='fixture-evidence/'+label+'/'+user['home']+'/'
            for name,pin in proof['public_evidence'].items():
                relative=prefix+name;expected.add(relative)
                C.need(rows.get(relative)==pin,'raw fixture/lifecycle hash join differs: '+relative)
            expected.add(prefix+'report.json')
            C.need(read(runtime/(prefix+'report.json'))==proof,'raw fixture report/lifecycle differs')
            actual=read(runtime/(prefix+'headless.stdout'))
            C.need(fixture.assert_headless(actual,architecture=life['native_architecture'],page_size=life['actual_page_size'])==proof['headless_checks'] and
                   actual['tool_sha256']==C.frozen_files()['session_probe.py']['sha256'] and
                   actual['identity']['architecture']==life['native_architecture'] and
                   actual['identity']['page_size_bytes']==life['actual_page_size'],
                   'raw installed headless report/source identity differs')
            for name,field in (('missing-tool-control.json','missing_tool_control'),
                               ('owned-process-control.json','owned_process_cleanup')):
                C.need(read(runtime/(prefix+name))==proof[field],'raw control/lifecycle differs: '+name)
            commands=read(runtime/(prefix+'commands.json'))
            labels=['help','headless','tamper-changed','tamper-missing','tamper-oversized','tamper-symlink','tamper-restored']
            C.need([r.get('case') for r in commands]==labels and
                   [r.get('returncode') for r in commands]==[0,0,2,2,2,2,0] and all(
                   r.get('hostile_python_environment_ignored') is True and
                   r.get('stdout_bytes')==proof['public_evidence'][r['case']+'.stdout']['bytes'] and
                   r.get('stderr_bytes')==proof['public_evidence'][r['case']+'.stderr']['bytes'] for r in commands),
                   'complete raw command/control receipts required')
            for case in labels[2:6]:
                C.need((runtime/(prefix+case+'.stdout')).read_bytes()==b'' and
                       b'runtime missing or changed' in (runtime/(prefix+case+'.stderr')).read_bytes(),
                       'raw private integrity refusal differs')
    signing=life['package_test_signing'];archive=Path(signing['archive']).name
    for name in (archive,archive+'.sig','TEST-public.asc','verification.txt'):
        expected.add('fixture-evidence/package-signing/'+name)
    C.need(set(rows)==expected,'complete exact raw fixture evidence map required')
    for name,field in ((archive,'archive_sha256'),(archive+'.sig','signature_sha256')):
        C.need(rows['fixture-evidence/package-signing/'+name]['sha256']==signing[field],
               'raw TEST signing/installed archive differs')
    installed=C.load('diagnostics_signature_status',source/C.LANE/'installed.py')
    installed.verify_signature_status(C,(runtime/'fixture-evidence/package-signing/verification.txt').read_text(),signing['fingerprint'])


def retain(source,base,runtime,proof,cleanup_path,output):
    C.safe(output.absolute());C.need(not output.exists(),'fresh public evidence directory required');output.mkdir(mode=0o700)
    result=dict(status='FAIL_OR_INCOMPLETE',files={},errors=[],total_bytes=0,selection='UNSELECTED',hardware='NOT_RUN',
                performance='NOT_MEASURED',security_acceptance='UNKNOWN',production_release_signatures='NOT_RUN',original_selected_inventory='UNCHANGED')
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
    copy(base/'session-diagnostics-retained-inputs.json','base/session-diagnostics-retained-inputs.json',512*1024)
    copy(source/'scripts/ci/session-diagnostics-native/source-manifest.json','source/source-manifest.json',1024**2)
    for path in sorted((source/'scripts/ci/session-diagnostics-native').iterdir()):
        if path.is_file():copy(path,'harness/'+path.name,2*1024**2)
    source_manifest=read(source/C.LANE/'source-manifest.json')
    for name in source_manifest['files']:
        copy(source/name,'closed-source/'+name,2*1024**2)
    copy(runtime/'fixture-evidence-manifest.json','runtime/fixture-evidence-manifest.json',2*1024**2)
    try:
        fixture_map=read(runtime/'fixture-evidence-manifest.json')
        C.need(type(fixture_map) is dict and len(fixture_map)<=4096,'finite public TEST evidence set required')
        for relative,pin in fixture_map.items():
            C.need(relative.startswith('fixture-evidence/') and '..' not in Path(relative).parts and
                   not Path(relative).is_absolute() and set(pin)=={'bytes','sha256'},'safe public TEST evidence row required')
            path=runtime/relative
            C.need(regular(path,2*1024**2).st_size==pin['bytes'] and C.digest(path)==pin['sha256'],'TEST evidence bytes differ')
            copy(path,'runtime/'+relative,2*1024**2)
    except Exception as error:result['errors'].append('TEST evidence: '+str(error)[:256])
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
        retained=C.load('diagnostics_retained_input_validation',source/C.LANE/'retained_inputs.py')
        retained.validate_retained_inputs(read(base/'session-diagnostics-retained-inputs.json',512*1024))
        source_proof=read(proof);original=read(base/'report.json');report=read(runtime/'report.json',4*1024**2)
        ordered=read(cleanup_path);owner=read(runtime/'owner.json');C.validate_lifecycle(report['lifecycle'])
        C.need(report['lifecycle']['fixture_evidence_manifest_sha256']==C.digest(runtime/'fixture-evidence-manifest.json'),
               'public TEST fixture evidence manifest differs')
        fixture_evidence(source,runtime,report['lifecycle'],fixture_map)
        C.need(source_proof['status']=='SOURCE_PROOF_PASS' and original['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION' and
               original['ownership']['token']==source_proof['job_token'] and original['owned_cleanup']['status']=='PASS' and
               original['owned_cleanup']['image']==dict(id=original['image'],absence_verified=True) and
               original['owned_cleanup']['probe']['absence_verified'] is True,'owned base/source acceptance absent')
        C.need(report['status']=='PASS_NATIVE_SESSION_DIAGNOSTICS_PAIR_AND_LIFECYCLE' and report['base_image']==original['image'] and
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
        run=C.load('tools_pair_export_gate',Path(__file__).with_name('run.py'))
        for product,row in report['products'].items():
            run.pair_gate(row['comparison']);C.need(len(row['builds'])==2,'two native builds required')
            C.need(report['lifecycle']['package_test_signing']['archive_sha256']==row['builds'][0]['sha256'],
                   'actual TEST package signature must bind the compared archive')
            for side,build in zip(('a','b'),row['builds']):
                expected=product+'-'+C.version(source,product)+'-any.pkg.tar.'
                C.need(build['archive'] in (expected+'xz',expected+'zst'),'exact candidate basename required')
                key='packages/'+product+'-'+side+'/'+build['archive']
                C.need(key in result['files'] and result['files'][key]['sha256']==build['sha256'],'archive identity absent')
        C.need(not result['errors'],'complete closed candidate evidence required')
        result['status']='PASS_NATIVE_SESSION_DIAGNOSTICS_CANDIDATE_LIFECYCLE'
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
    raise SystemExit(int(value['status'] not in ('SOURCE_PROOF_PASS','PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP','PASS_NATIVE_SESSION_DIAGNOSTICS_CANDIDATE_LIFECYCLE')))
