#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Accepted source proof, labeled consumer cleanup, then owned574 producer cleanup."""
import argparse
import fcntl
import hashlib
import json
from itertools import islice
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C

MAX_TOTAL=192*1024**2
DIAGNOSTIC_INDEX_CAP=512*1024
DIAGNOSTIC_STREAM_CAP=128*1024
DIAGNOSTIC_TOTAL=4*1024**2
DIAGNOSTIC_COMMANDS=20


def regular(path,cap):
    C.safe(path.absolute());info=path.lstat()
    C.need(stat.S_ISREG(info.st_mode) and info.st_size<=cap,'bounded regular file required: '+path.name);return info


def read(path,cap=2*1024**2):regular(path,cap);return json.loads(path.read_bytes())


def save(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')


def diagnostic_index(directory):
    """Validate the closed public prefix set, including incomplete failure captures."""
    C.safe(directory.absolute());C.need(directory.is_dir(),'ordinary public diagnostics directory required')
    def body(name,cap):
        path=directory/name;info=regular(path,cap)
        C.need(info.st_nlink==1,'singlelink public diagnostic required');return path.read_bytes()
    def unique(pairs):
        C.need(len({k for k,v in pairs})==len(pairs),'duplicate diagnostic JSON member')
        return dict(pairs)
    raw=body('index.json',DIAGNOSTIC_INDEX_CAP);index=json.loads(raw,object_pairs_hook=unique)
    fields={'schema_version','status','scope','files','total_bytes','cap','stream_cap','commands'}
    C.need(type(index) is dict and set(index) in (fields,fields|{'gate'}) and type(index['schema_version']) is int and index['schema_version']==1 and
           type(index['status']) is str and re.fullmatch(r'[A-Z][A-Z0-9_-]{0,100}',index['status']) and
           index['scope']=='PUBLIC_TEST_SIGNATURE_AND_ALPM_GATE_ONLY' and type(index['cap']) is int and index['cap']==DIAGNOSTIC_TOTAL and
           type(index['stream_cap']) is int and index['stream_cap']==DIAGNOSTIC_STREAM_CAP and type(index['files']) is dict and len(index['files'])<=2*DIAGNOSTIC_COMMANDS and
           type(index['total_bytes']) is int and 0<=index['total_bytes']<=DIAGNOSTIC_TOTAL and type(index['commands']) is list and
           len(index['commands'])<=DIAGNOSTIC_COMMANDS,'closed bounded diagnostic index required')
    expected={};total=0
    def whole(value):
        return type(value) is dict and set(value)=={'bytes','sha256'} and type(value['bytes']) is int and 0<=value['bytes']<=DIAGNOSTIC_STREAM_CAP and type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}',value['sha256'])
    for number,row in enumerate(index['commands']):
        C.need(type(row) is dict and set(row)=={'operation','argv','exit','started_epoch','finished_epoch','stdout','stderr','complete','error'} and
               type(row['operation']) is str and re.fullmatch(r'[A-Za-z0-9._-]{1,100}',row['operation']) and type(row['argv']) is list and
               1<=len(row['argv'])<=64 and all(type(v) is str and len(v)<=2048 for v in row['argv']) and sum(map(len,row['argv']))<=8192 and
               (row['exit'] is None or type(row['exit']) is int) and type(row['started_epoch']) is int and type(row['finished_epoch']) is int and
               0<=row['started_epoch']<=row['finished_epoch'] and type(row['complete']) is bool and
               (row['error'] is None or type(row['error']) is str and len(row['error'])<=512),'typed diagnostic command required')
        for role in ('stdout','stderr'):
            ref=row[role];name='%03d.%s'%(number,role)
            C.need(type(ref) is dict and set(ref)=={'file','bytes','sha256','observed_bytes','complete'} and ref['file']==name and
                   whole({k:ref[k] for k in ('bytes','sha256')}) and type(ref['observed_bytes']) is int and ref['observed_bytes']>=ref['bytes'] and
                   type(ref['complete']) is bool and ref['complete']==(ref['observed_bytes']==ref['bytes']),'fixed bounded diagnostic stream required')
            content=body(name,DIAGNOSTIC_STREAM_CAP);pin=dict(bytes=len(content),sha256=hashlib.sha256(content).hexdigest())
            C.need(pin=={k:ref[k] for k in ('bytes','sha256')},'diagnostic raw stream pin differs')
            expected[name]=pin;total+=len(content)
        C.need(row['complete']==all(row[r]['complete'] for r in ('stdout','stderr')),'diagnostic completeness differs')
    C.need(all(whole(p) for p in index['files'].values()) and index['files']==expected and total==index['total_bytes']<=DIAGNOSTIC_TOTAL and
           {p.name for p in islice(directory.iterdir(),2*DIAGNOSTIC_COMMANDS+2)}=={'index.json'}|set(expected),'exact closed public diagnostic files required')
    return index,dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def join_diagnostics(index,index_pin,gate):
    C.need(gate.get('diagnostics')==dict(index=index_pin,directory='signature-verification') and index['status']==gate['status'] and
           index.get('gate')=={k:v for k,v in gate.items() if k!='diagnostics'},'retained diagnostics must bind exact lifecycle gate projection')
    C.need(len(index['commands'])==len(gate['commands'])==13,'all thirteen signature commands must have retained raw output')
    for captured,command in zip(index['commands'],gate['commands']):
        projection={k:captured[k] for k in ('operation','exit','started_epoch','finished_epoch')}
        projection.update({r:{k:captured[r][k] for k in ('bytes','sha256')} for r in ('stdout','stderr')})
        C.need(captured['complete'] is True and captured['error'] is None and projection==command and
               captured['stdout']['bytes']+captured['stderr']['bytes']<=DIAGNOSTIC_STREAM_CAP,
               'retained complete raw command receipts must equal lifecycle commands')


def retain_diagnostics(directory,copy,errors):
    # Preserve bounded public diagnostics before any positive lifecycle acceptance.
    try:
        C.need(regular(directory/'index.json',DIAGNOSTIC_INDEX_CAP).st_nlink==1,'singlelink public diagnostic index required')
        copy(directory/'index.json','signature-verification/index.json',DIAGNOSTIC_INDEX_CAP)
        index,index_pin=diagnostic_index(directory)
        for name in sorted(index['files']):copy(directory/name,'signature-verification/'+name,DIAGNOSTIC_STREAM_CAP)
        return index,index_pin
    except Exception as error:errors.append('signature-verification: '+str(error)[:256])
    return None


def manifest_files(source,manifest):
    C.need(manifest.get('schema_version')==1 and 1<=len(manifest['files'])<=128,'closed tools source manifest required')
    for name,row in manifest['files'].items():
        C.need(not Path(name).is_absolute() and '..' not in Path(name).parts,'safe source path required')
        path=source/name;info=regular(path,16*1024**2)
        C.need(info.st_size==row['bytes'] and C.digest(path)==row['sha256'],'source pin differs: '+name)


def workflow_binding(source,manifest):
    paths=['.github/workflows/native-arm-mirrors-candidate.yml','.github/workflows/native-arm-build.yml']
    C.need(manifest.get('workflow_binding')==dict(paths=paths,method='EXACT_RENDERED_PINNED_TEMPLATE_EQUALITY_BEFORE_SECRETS'),
           'registered workflow binding required')
    lane=source/'scripts/ci/mirrors-native'
    C.need(manifest==read(lane/'source-manifest.json'),'proof must use the exact closed manifest')
    text=(lane/'workflow.yml.in').read_text()
    for marker,path in (('@JOB_SHA256@',lane/'job.py'),('@MANIFEST_SHA256@',lane/'source-manifest.json')):
        C.need(text.count(marker)==1,'single workflow proof marker required')
        text=text.replace(marker,C.digest(path))
    expected=text.encode()
    for name in paths:
        path=source/name;regular(path,65536)
        C.need(path.read_bytes()==expected,'registered/dedicated workflow bytes differ from closed source: '+name)
    return dict(paths=paths,bytes=len(expected),sha256=hashlib.sha256(expected).hexdigest())


def prove(source,manifest,environment):
    manifest_files(source,manifest);C.verify_source(source)
    workflows=workflow_binding(source,manifest)
    policy=read(C.HERE/'input-policy.json')
    C.need(re.fullmatch('[0-9a-f]{40}',policy.get('candidate_source') or ''),'Root-bound published candidate source required before secrets')
    shared=C.load('accepted_tools_source_proof',source/'scripts/ci/welcome-native/ci/caller.py')
    result=shared.prove(source,manifest,environment)
    result['issued_epoch']=int(time.time())
    result['workflow_binding']=workflows
    result['consumer_token']=hashlib.sha256(('mirrors-consumer:'+result['run_id']+':'+result['run_attempt']+':'+result['source_sha']).encode()).hexdigest()[:32]
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
               type(names) is list and len(names)<=5 and len(set(names))==len(names) and all(
               type(n) is str and re.fullmatch(r'cachy-asahi-product-(?:(?:probe|signer|lifecycle)-)?[0-9a-f]{32}',n) for n in names),
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
                performance='NOT_MEASURED',external_mirror_rank='NOT_RUN',release_signatures='NOT_RUN',candidate_signatures='EPHEMERAL_JOB_BOUND_TEST_REQUIRED',original_selected_inventory='UNCHANGED')
    def copy(path,name,cap,required=True):
        if not required and not path.exists() and not path.is_symlink():return
        try:
            info=regular(path,cap);C.need(result['total_bytes']+info.st_size<=MAX_TOTAL,'closed evidence total cap')
            target=output/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(path,target)
            result['files'][name]=dict(bytes=info.st_size,sha256=C.digest(target));result['total_bytes']+=info.st_size
        except Exception as error:result['errors'].append(name+': '+str(error)[:256])
    copy(proof,'source-proof.json',65536);copy(cleanup_path,'ordered-cleanup.json',65536)
    diagnostics=retain_diagnostics(runtime/'signature-verification',copy,result['errors'])
    for name in ('TEST-public.asc','WRONG-TEST-public.asc','build-a.sig','build-b.sig','wrong-key.sig','signing.json'):
        copy(runtime/'signing'/name,'signing/'+name,512*1024)
    for name in ('signing-job.json','signing-input.json'):
        copy(runtime/'lifecycle-inputs'/name,'signing/'+name,65536)
    for name in ('report.json','installed-packages.lock'):copy(base/name,'base/'+name,1024**2)
    for name,cap in (('report.json',4*1024**2),('lifecycle.json',4*1024**2),('owner.json',65536),
                     ('base-inventory.log',256*1024),('signer.log',16*1024**2),('lifecycle.log',16*1024**2)):
        copy(runtime/name,'runtime/'+name,cap)
    copy(base/'mirrors-retained-inputs.json','base/mirrors-retained-inputs.json',512*1024)
    for path in sorted((source/'scripts/ci/setup6-retained-helpers').iterdir()):
        if path.is_file():copy(path,'harness/retained574/'+path.name,2*1024**2)
    copy(source/'scripts/ci/mirrors-native/source-manifest.json','source/source-manifest.json',1024**2)
    for path in sorted((source/'scripts/ci/mirrors-native').iterdir()):
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
        retained_inputs=C.load('mirror_retained_input_validation',source/'scripts/ci/mirrors-native/retained_inputs.py')
        retained_inputs.validate_retained_inputs(read(base/'mirrors-retained-inputs.json',512*1024))
        source_proof=read(proof);original=read(base/'report.json');report=read(runtime/'report.json',4*1024**2)
        ordered=read(cleanup_path);owner=read(runtime/'owner.json');C.validate_lifecycle(report['lifecycle'])
        auth=C.load('mirror_signed_retainer_auth',source/'scripts/ci/mirrors-native/test_auth.py')
        signing_input=read(runtime/'lifecycle-inputs/signing-input.json');signing=read(runtime/'signing/signing.json',512*1024)
        auth.validate_signing(signing,signing_input['job'],signing_input['products'])
        C.need(signing_input['job']==dict(source_sha=source_proof['source_sha'],run_id=source_proof['run_id'],run_attempt=source_proof['run_attempt'],proof_issued_epoch=source_proof['issued_epoch'],consumer_token=source_proof['consumer_token']),'signer job/source proof differs')
        C.need(report['signing']==signing,'parent signer receipt differs')
        C.need(read(runtime/'lifecycle-inputs/signing-job.json')==signing_input['job'],'lifecycle signing job differs')
        for side in ('a','b'):
            build=report['products'][C.NAMES[0]]['builds'][0 if side=='a' else 1];archive=runtime/(C.NAMES[0]+'-'+side)/'artifacts'/build['archive']
            C.need(signing_input['products'][side]==dict(archive='/inputs/'+side+'/'+build['archive'],bytes=archive.stat().st_size,sha256=C.digest(archive)),'signing input differs from native archive pair')
        public_refs={'TEST-public.asc':signing['public_key'],'WRONG-TEST-public.asc':signing['wrong_public_key'],'build-a.sig':signing['archives']['a']['signature'],'build-b.sig':signing['archives']['b']['signature'],'wrong-key.sig':signing['wrong_signature']}
        for name,row in public_refs.items():
            path=runtime/'signing'/name;C.need(dict(bytes=path.stat().st_size,sha256=C.digest(path))==row,'actual public key/signature output differs')
        gate=report['lifecycle']['signature_verification'];raw=runtime/'signing/signing.json'
        C.need(diagnostics is not None,'retained public signature diagnostics required')
        join_diagnostics(*diagnostics,gate)
        C.need(result['files'].get('signature-verification/index.json')==diagnostics[1],'retained index differs from lifecycle diagnostic pin')
        C.need(all(result['files'].get('signature-verification/'+name)==row for name,row in diagnostics[0]['files'].items()),
               'retained raw output differs from indexed command pins')
        C.need(gate['signing_receipt_data']==signing and gate['signing_receipt']==dict(bytes=raw.stat().st_size,sha256=C.digest(raw)),'installed verification does not bind the same signer receipt')
        C.need(source_proof['status']=='SOURCE_PROOF_PASS' and original['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION' and
               original['ownership']['token']==source_proof['job_token'] and original['owned_cleanup']['status']=='PASS' and
               original['owned_cleanup']['image']==dict(id=original['image'],absence_verified=True) and
               original['owned_cleanup']['probe']['absence_verified'] is True,'owned base/source acceptance absent')
        C.need(report['status']=='PASS_NATIVE_MIRRORS_PAIR_AND_LIFECYCLE' and report['base_image']==original['image'] and
               report['base_count']==574 and set(report['products'])==set(C.NAMES) and
               ordered['status']=='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP' and
               ordered['consumer']['status']=='PASS_CONSUMERS_RETIRED' and len(owner['containers'])==5 and
               len(ordered['consumer']['containers'])==5 and ordered['producer']==original['owned_cleanup'] and
               owner['token']==source_proof['consumer_token']==report['ownership_token'] and
               owner['image']==original['image'] and owner['label']==C.LABEL and
               report['base_lock_sha256']==C.digest(base/'installed-packages.lock') and
               {r['container'] for r in ordered['consumer']['containers']}==set(owner['containers']) and all(
               r['status']=='PASS' and r['absence_verified'] is True for r in ordered['consumer']['containers']),
               'all five owned consumers then producer must be retired')
        C.need(read(runtime/'lifecycle.json',4*1024**2)==report['lifecycle'],'parent/standalone lifecycle mismatch')
        run=C.load('tools_pair_export_gate',Path(__file__).with_name('run.py'))
        for product,row in report['products'].items():
            run.pair_gate(row['comparison']);C.need(len(row['builds'])==2,'two native builds required')
            for side,build in zip(('a','b'),row['builds']):
                expected=product+'-'+C.version(source,product)+'-any.pkg.tar.'
                C.need(build['archive'] in (expected+'xz',expected+'zst'),'exact candidate basename required')
                key='packages/'+product+'-'+side+'/'+build['archive']
                C.need(key in result['files'] and result['files'][key]['sha256']==build['sha256'],'archive identity absent')
        C.need(not result['errors'],'complete closed candidate evidence required')
        result['status']='PASS_NATIVE_MIRRORS_CANDIDATE_LIFECYCLE'
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
    raise SystemExit(int(value['status'] not in ('SOURCE_PROOF_PASS','PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP','PASS_NATIVE_MIRRORS_CANDIDATE_LIFECYCLE')))
