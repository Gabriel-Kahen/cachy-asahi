#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Manual CI source proof, ordered owned cleanup, and closed evidence export."""
import argparse,fcntl,hashlib,importlib.util,json,os,platform,re,stat,subprocess
from pathlib import Path

LABEL='org.cachy-asahi.glibc-gnu-provider.job'
PACKAGE='cachy-asahi-glibc-gnu-provider-2.43.caa1-1-aarch64.pkg.tar.xz'
MAX_TOTAL=768*1024**2


def need(ok,message):
    if not ok:raise ValueError(message)

def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()

def regular(path,cap):
    need(not any(p.is_symlink() for p in (path,*path.parents)),'ordinary evidence path required')
    info=path.stat();need(stat.S_ISREG(info.st_mode) and info.st_size<=cap,'bounded regular evidence required: '+path.name);return info

def read(path,cap=2*1024**2):regular(path,cap);return json.loads(path.read_bytes())

def save(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')


def manifest_files(workspace,manifest):
    need(manifest['schema_version']==1 and 1<=len(manifest['files'])<=96,'bounded integration manifest required')
    for name,row in manifest['files'].items():
        need(not Path(name).is_absolute() and all(p not in ('','.','..') for p in name.split('/')),'safe source reference required')
        path=workspace/name;info=regular(path,16*1024**2)
        need(info.st_size==row['bytes'] and sha(path)==row['sha256'],'held integration source changed: '+name)


def admission(workspace,binding):
    need(binding.get('schema_version')==1 and binding.get('status')=='ROOT_BOUND_ACCEPTED_PRIVATE16K_AND_GNU_INPUT_PACKET',
         'pending Root accepted private16K result and exact GNU input packet')
    row=binding.get('private16k');packet=binding.get('gnu_inputs')
    need(type(row) is dict and type(packet) is dict and
         re.fullmatch('[0-9a-f]{40}',row.get('source','')) and
         re.fullmatch('[1-9][0-9]{0,19}',str(row.get('run',''))) and
         re.fullmatch('[1-9][0-9]{0,9}',str(row.get('attempt',''))) and
         re.fullmatch('[0-9a-f]{40}',packet.get('ref','')) and
         re.fullmatch('[0-9a-f]{64}',packet.get('index_sha256','')) and
         type(packet.get('index_bytes')) is int and 0<packet['index_bytes']<=65536,
         'complete exact Root run/source/packet bindings required')
    name=row.get('path','');need(name and not Path(name).is_absolute() and
         all(p not in ('','.','..') for p in name.split('/')),'safe private16K evidence reference required')
    path=workspace/name;info=regular(path,2*1024**2)
    need(info.st_size==row['bytes'] and sha(path)==row['sha256'],'Root accepted private16K evidence bytes differ')
    rootref=row['root_verification'];name=rootref['path']
    need(name and not Path(name).is_absolute() and all(p not in ('','.','..') for p in name.split('/')),
         'safe Root verification reference required')
    rootpath=workspace/name;regular(rootpath,65536)
    need(rootpath.stat().st_size==rootref['bytes'] and sha(rootpath)==rootref['sha256'],
         'Root private16K acceptance bytes differ')
    accepted=read(rootpath,65536)
    need(accepted['status']=='ROOT_ACCEPTED_PRIVATE_GNU16K_RUNTIME' and accepted['run_id']==row['run'] and
         accepted['source_sha']==row['source'] and accepted['page_size']==16384 and
         accepted['cases']==8 and accepted['runtime_records']==12 and accepted['commands']==14 and accepted['compile_commands']==13 and
         accepted['candidate_package_sha256']=='04e481dc5b3ac711760ca42749044b0be85283b3aa9c9c631cb6738ac7d699fb' and
         accepted['actual_parent_child_providers']==accepted['source_archive_payload_join']==accepted['ordered_cleanup']=='PASS' and
         accepted['hardware']==accepted['installation']=='NOT_RUN' and accepted['security']=='NO_CREDIT' and
         accepted['performance']=='NOT_MEASURED' and accepted['release']=='NOT_ADMITTED',
         'explicit Root accepted qualified private16K prerequisite required')
    value=read(path)
    need(value['status']=='PASS_PRIVATE_GLIBC_GENERIC16K_AND_ORDERED_CLEANUP' and
         value['source_commit']==row['source'] and
         value['job_token']==hashlib.sha256(('glibc16k:'+str(row['run'])+':'+str(row['attempt'])+':'+row['source']).encode()).hexdigest()[:16] and
         value['pair_source']=='18569401aa28e2be86f4ada20489913f28739b92' and
         value['pair_sha256']=='04e481dc5b3ac711760ca42749044b0be85283b3aa9c9c631cb6738ac7d699fb' and
         value['natural_VM_exit'] is True and value['QEMU_exit']==0 and
         value['kernel_work_removed'] is True and value['kernel']['kernel_build']=='PASS' and
         value['consumer_cleanup']['capture_absent'] is True and value['consumer_cleanup']['private_removed'] is True and
         value['producer_cleanup']['status']=='PASS' and
         value['producer_cleanup']['probe']['absence_verified'] is True and
         value['producer_cleanup']['image']['absence_verified'] is True and
         value['producer_cleanup']['image']['id']==value['image_id'] and
         len(value['actors'])==2 and all(a['natural_exit'] is True and a['exit']==0 and a['group_absent'] is True for a in value['actors']),
         'complete accepted private16K VM and ordered cleanup required')
    spec=importlib.util.spec_from_file_location('provider_private16k_receipts',workspace/'scripts/ci/glibc-generic16k/common.py')
    checks=importlib.util.module_from_spec(spec);spec.loader.exec_module(checks)
    checks.compile_receipt(value['capture']['compile']);checks.guest_receipt(value['guest'])
    return dict(status='PASS_BOUND_ROOT_ACCEPTED_PRIVATE16K',**row,qualification=accepted['limitation'],gnu_source_ref=packet['ref'])


def packet(inputs,binding):
    need(binding.get('status')=='ROOT_BOUND_ACCEPTED_PRIVATE16K_AND_GNU_INPUT_PACKET','pending Root source packet binding')
    row=binding['gnu_inputs'];index=inputs/'index.json';regular(index,65536)
    need(index.stat().st_size==row['index_bytes'] and sha(index)==row['index_sha256'],'exact Root GNU packet index required')
    value=read(index)
    expected={
        'glibc-2.43.tar.gz':dict(bytes=40287809,sha256='e1e622cbd635019090fa23260e5d9ec219b12f97ae7ae02f033d4ae42cf2c004'),
        'glibc-2.43.tar.gz.sig':dict(bytes=1018,sha256='bfd0c5a9924e4f084281cd2f3ba96e5c6e87a6d363113e7a0f98c5151463c9e3'),
        'gnu-keyring.gpg':dict(bytes=3698125,sha256='0fe55175b96a8ea1c4b670cc3fe11d56b341e4eff81b161ea49958ae550be6ca')}
    need(value.get('schema_version')==1 and value.get('status')=='ROOT_BOUND_COMPLETE_GNU243_INPUT_PACKET' and
         value.get('accepted_native_run')==38915137670 and value.get('files')==expected,'complete exact retained GNU source packet required')
    for name,row in expected.items():
        p=inputs/name;info=regular(p,96*1024**2)
        need(info.st_size==row['bytes'] and sha(p)==row['sha256'],'GNU packet file differs: '+name)
    return dict(status='PASS_EXACT_RETAINED_GNU_SOURCE_PACKET',ref=binding['gnu_inputs']['ref'],index_sha256=sha(index))


def normal_binding():
    spec=importlib.util.spec_from_file_location('provider_normal_policy',Path(__file__).resolve().parent/'normal_clients.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    module.policy()
    return module.identity(Path(__file__).resolve().parent/'normal-client-policy.json')


def prove(workspace,manifest,environment):
    source=environment['SOURCE_SHA']
    need(re.fullmatch('[0-9a-f]{40}',source) and source==environment['WORKFLOW_SHA']==environment['GITHUB_SHA'],'source must equal exact workflow revision before secrets')
    need(environment['RUNNER_ARCH']=='ARM64' and environment['RUNNER_OS']=='Linux','native ARM runner required')
    run,attempt=environment['GITHUB_RUN_ID'],environment['GITHUB_RUN_ATTEMPT']
    need(re.fullmatch('[1-9][0-9]{0,19}',run) and re.fullmatch('[1-9][0-9]{0,9}',attempt),'bounded run identity required')
    manifest_files(workspace,manifest)
    binding=read(workspace/'scripts/ci/glibc-gnu-provider/bindings.json')
    accepted=admission(workspace,binding)
    normal=normal_binding()
    identity=run+':'+attempt+':'+source
    return dict(status='SOURCE_PROOF_PASS',source_sha=source,workflow_sha=source,
                run_id=run,run_attempt=attempt,job_token=hashlib.sha256(('glibc-provider-producer:'+identity).encode()).hexdigest()[:16],
                consumer_token=hashlib.sha256(('glibc-provider-consumer:'+identity).encode()).hexdigest()[:32],
                hardware='NOT RUN',selection='UNSELECTED',private16k=accepted,normal_client_policy=normal,gnu_source_sha=binding['gnu_inputs']['ref'])


def invoke(argv):
    row=subprocess.run(list(map(str,argv)),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                       env=dict(PATH='/usr/bin:/bin',LC_ALL='C',TZ='UTC',HOME='/tmp'),timeout=30)
    need(len(row.stdout)+len(row.stderr)<=1024**2,'cleanup observer output bound');return row


def retire_consumers(runtime,base,proof,command=invoke):
    token=proof['consumer_token'];need(re.fullmatch('[0-9a-f]{32}',token),'consumer ownership token required')
    if not(runtime/'consumer.lock').exists():
        need(not(runtime/'owner.json').exists(),'owner without actor lease refused')
        return dict(status='PASS_NO_CONSUMER_ACTORS',containers=[])
    regular(runtime/'consumer.lock',0)
    fd=os.open(runtime/'consumer.lock',os.O_RDWR|os.O_CLOEXEC|os.O_NOFOLLOW)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if not(runtime/'owner.json').exists():return dict(status='PASS_NO_CONSUMER_ACTORS',containers=[])
        owner=read(runtime/'owner.json');original=read(base/'report.json')
        image=original['image'];need(re.fullmatch('sha256:[0-9a-f]{64}',image) and owner==dict(schema_version=1,token=token,image=image,label=LABEL),'exact consumer/base ownership required')
        def inspect(name):
            row=command(['/usr/bin/docker','container','inspect',name])
            if row.returncode:
                text=(row.stdout+row.stderr).decode('utf-8','replace').lower()
                need(row.returncode==1 and name.lower() in text and ('no such container' in text or 'no such object' in text),'unknown consumer daemon state')
                return None
            rows=json.loads(row.stdout);need(len(rows)==1,'ambiguous consumer identity')
            value=rows[0];need(value['Image']==image and value['Config']['Labels'].get(LABEL)==token and re.fullmatch('[0-9a-f]{64}',value['Id']),'foreign consumer preserved');return value
        result=[]
        for suffix in ('b-smoke','b','a-smoke','a','probe'):
            name='caa-glibc-provider-'+token+'-'+suffix
            try:
                value=inspect(name)
                if value is not None:need(command(['/usr/bin/docker','rm','-f',value['Id']]).returncode==0,'owned consumer removal failed')
                need(inspect(name) is None,'consumer remains');result.append(dict(container=name,status='PASS-absence-verified'))
            except Exception as error:result.append(dict(container=name,status='FAIL_OR_UNKNOWN',error=str(error)[:256]))
        need(all(r['status']=='PASS-absence-verified' for r in result),'consumer cleanup unknown; producer must remain')
        return dict(status='PASS_CONSUMERS_RETIRED',containers=result)
    finally:os.close(fd)


def cleanup(workspace,manifest,proof,base,runtime,output):
    manifest_files(workspace,manifest)
    result=dict(status='FAIL',consumer='NOT_OBSERVED',producer='NOT_RETIRED')
    try:
        result['consumer']=retire_consumers(runtime,base,proof)
        if (base/'report.json').exists():
            argv=['python3','-I','-B',str(workspace/'scripts/ci/maintained_desktop574.py'),'cleanup','--inputs',
                  str(workspace/'scripts/ci/maintained-desktop574-inputs.json'),'--output',str(base),'--job-token',proof['job_token']]
            row=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                               env=dict(PATH='/usr/bin:/bin',LC_ALL='C',HOME=str(base/'home')),timeout=240)
            need(row.returncode==0 and len(row.stdout)+len(row.stderr)<=1024**2,'producer owned cleanup did not pass')
            result['producer']=read(base/'report.json')['owned_cleanup'];need(result['producer']['status']=='PASS','producer absence unverified')
        else:result['producer']='NOT_STARTED'
        result['status']='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP'
    except BaseException as error:result.update(error_type=type(error).__name__,error=str(error)[:512])
    save(output,result);return result


def retain(workspace,base,runtime,bundle,proof,cleanup_path,output):
    need(not output.exists() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary public output required')
    output.mkdir(mode=0o700);result=dict(status='FAIL_OR_INCOMPLETE',files={},errors=[],total_bytes=0,selection='UNSELECTED',hardware='NOT RUN',performance='NOT MEASURED')
    def copy(source,name,cap,required=True,tail=False):
        if not required and not source.exists() and not source.is_symlink():return
        try:
            info=regular(source,16*1024**3 if tail else cap);size=min(info.st_size,cap)
            need(result['total_bytes']+size<=MAX_TOTAL,'closed evidence aggregate cap exceeded')
            target=output/name;target.parent.mkdir(parents=True,exist_ok=True)
            with source.open('rb') as src,target.open('xb') as dst:
                if tail:src.seek(max(0,info.st_size-cap))
                remaining=size
                while remaining:
                    data=src.read(min(1024**2,remaining));need(data,'source truncated during evidence copy');dst.write(data);remaining-=len(data)
            need(source.stat().st_size==info.st_size and target.stat().st_size==size,'evidence source changed')
            result['total_bytes']+=size;result['files'][name]=dict(bytes=size,sha256=sha(target),source_bytes=info.st_size,truncated=info.st_size>size)
        except Exception as error:result['errors'].append(name+': '+str(error)[:256])
    copy(proof,'source-proof.json',65536);copy(cleanup_path,'ordered-cleanup.json',65536)
    for name in ('report.json','seed-report.json','installed-packages.lock'):copy(base/name,'base/'+name,1024**2,name!='seed-report.json')
    copy(runtime/'result.json','runtime/result.json',2*1024**2)
    try:
        source=read(bundle/'bundle.json');copy(bundle/'bundle.json','source/bundle.json',1024**2)
        need(len(source['files'])<=32,'closed source bundle bound')
        for name in source['files']:
            need(Path(name).name==name and name not in ('.','..'),'flat source bundle required')
            copy(bundle/name,'source/'+name,96*1024**2 if name=='glibc-2.43.tar.gz' else 8*1024**2)
    except Exception as error:result['errors'].append('source bundle: '+str(error)[:256])
    harness=workspace/'scripts/ci/glibc-gnu-provider'
    for name in read(harness/'source-manifest.json')['files']:copy(harness/name,'build-harness/'+name,256*1024)
    copy(harness/'source-manifest.json','build-harness/source-manifest.json',65536)
    for side in ('a','b'):
        directory=runtime/side;prefix='runtime/'+side+'/'
        copy(directory/'artifacts'/PACKAGE,'packages/'+side+'/'+PACKAGE,256*1024**2,False)
        for name in ('generated.SRCINFO','packages-before.lock','packages-after.lock','packages-runtime.lock','toolchain.txt','check-exit','abi-exit','makepkg-exit'):
            copy(directory/'evidence'/name,prefix+'evidence/'+name,512*1024,False)
        copy(directory/'evidence/upstream-tests.json',prefix+'evidence/upstream-tests.json',32*1024**2,False)
        for name in ('static-abi.json','provider-stage.json','provider-ownership.json'):
            copy(directory/'evidence'/name,prefix+'evidence/'+name,2*1024**2,False)
        for name in ('upstream-check.log','upstream-abi.log'):
            copy(directory/'evidence'/name,prefix+'evidence/'+name,8*1024**2,False,True)
        copy(runtime/(side+'-build.log'),prefix+'build.log',8*1024**2,False,True)
        copy(runtime/(side+'-smoke.log'),prefix+'smoke.log',8*1024**2,False,True)
        for name in ('runtime-inputs.json','makepkg.conf'):copy(directory/name,prefix+name,65536,False)
        for name in ('.PKGINFO','.BUILDINFO','.MTREE'):copy(directory/'stage'/name,prefix+'package-metadata/'+name,2*1024**2,False)
        for relative in ('header-check/receipt.json','header-check/headers.d','runtime-smoke/receipt.json'):
            copy(directory/relative,prefix+relative,2*1024**2,False)
        copy(directory/'normal-clients/receipt.json',prefix+'normal-clients/receipt.json',2*1024**2,False)
        for name in ('smoke-normal','exec-child','plugin.so'):
            key=prefix+'normal-clients/bin/'+name
            copy(directory/'normal-clients/bin'/name,key,4*1024**2,False)
            if key in result['files']:
                (output/key).chmod(0o755);result['files'][key]['mode']=0o755
        for name in ('patch.stdout','patch.stderr'):
            copy(directory/'normal-clients'/name,prefix+'normal-clients/'+name,262144,False)
        for i in range(13):
            for suffix in ('stdout','stderr'):
                name=f'command-{i:02d}.'+suffix
                copy(directory/'normal-clients/build'/name,prefix+'normal-clients/build/'+name,262144,False)
        for i in range(32):
            for suffix in ('stdout','stderr'):
                name=f'command-{i:02d}.'+suffix;copy(directory/'runtime-smoke'/name,prefix+'runtime-smoke/'+name,262144,False)
    try:
        native=read(runtime/'result.json');base_result=read(base/'report.json');ordered=read(cleanup_path)
        need(native['status']=='PASS_UNSELECTED_NATIVE_PAIR' and native['archive_bytes_reproduced'] is True and
             native['normal_client_bytes_reproduced'] is True and
             base_result['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION' and ordered['status']=='PASS_ORDERED_CONSUMER_THEN_PRODUCER_CLEANUP','native/ordered cleanup result incomplete')
        need(len(native['builds'])==2 and {r['side'] for r in native['builds']}=={'a','b'},'real pair absent')
        for row in native['builds']:
            key='packages/'+row['side']+'/'+PACKAGE
            need(row['status']=='PASS_NATIVE_BUILD_TEST_ABI_RUNTIME' and key in result['files'] and result['files'][key]['sha256']==row['sha256'],'native archive identity absent')
            for relative in ('evidence/upstream-tests.json','evidence/static-abi.json','evidence/provider-stage.json','evidence/provider-ownership.json','header-check/receipt.json','runtime-smoke/receipt.json','package-metadata/.BUILDINFO','evidence/generated.SRCINFO'):
                need('runtime/'+row['side']+'/'+relative in result['files'],'required native proof absent')
            key='runtime/'+row['side']+'/normal-clients/receipt.json'
            need(key in result['files'] and result['files'][key]['sha256']==row['normal_compile_receipt_sha256'],'normal compiler receipt absent or changed')
            for name,digest in row['normal_clients'].items():
                key='runtime/'+row['side']+'/normal-clients/bin/'+name
                need(key in result['files'] and result['files'][key]['sha256']==digest,'normal interpreter artifact absent or changed')
        need(not result['errors'],'bounded public evidence incomplete')
        result['status']='PASS_UNSELECTED_GNU_PROVIDER_NATIVE_PAIR_EVIDENCE'
    except Exception as error:result['errors'].append(str(error)[:512])
    save(output/'retention.json',result);return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('phase',choices=('proof','packet','cleanup','retain'))
    for name in ('workspace','manifest','proof','base','runtime','bundle','cleanup','output','inputs'):parser.add_argument('--'+name,type=Path)
    args=parser.parse_args();workspace=args.workspace.resolve(strict=True)
    if args.phase=='proof':
        value=prove(workspace,read(args.manifest),os.environ);value['manifest_sha256']=sha(args.manifest)
        with args.proof.open('x') as stream:json.dump(value,stream,sort_keys=True,indent=2);stream.write('\n')
        with open(os.environ['GITHUB_OUTPUT'],'a') as stream:
            for name in ('job_token','consumer_token','gnu_source_sha'):stream.write(name+'='+value[name]+'\n')
    elif args.phase=='packet':value=packet(args.inputs,read(workspace/'scripts/ci/glibc-gnu-provider/bindings.json'))
    elif args.phase=='cleanup':
        need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0 and
             not any(k.startswith('DOCKER_') for k in os.environ),'ordinary local native cleanup required')
        context=invoke(['/usr/bin/docker','context','inspect','default'])
        need(context.returncode==0 and json.loads(context.stdout)[0]['Endpoints']['docker']['Host']=='unix:///var/run/docker.sock',
             'local default cleanup daemon required')
        current=invoke(['/usr/bin/docker','context','show']);need(current.returncode==0 and current.stdout.strip()==b'default','default cleanup context required')
        value=cleanup(workspace,read(args.manifest),read(args.proof),args.base,args.runtime,args.output)
    else:value=retain(workspace,args.base,args.runtime,args.bundle,args.proof,args.cleanup,args.output)
    print(json.dumps(value,sort_keys=True));return int(not value['status'].startswith(('SOURCE_PROOF_PASS','PASS_')))

if __name__=='__main__':raise SystemExit(main())
