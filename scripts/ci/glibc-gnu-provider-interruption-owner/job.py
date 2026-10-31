#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source/packet gates, stopped-image snapshot, private binding and ordered cleanup."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys

HERE=Path(__file__).resolve().parent
LANE='scripts/ci/glibc-gnu-provider-interruption'
LABEL='org.cachy-asahi.glibc-provider-interruption-owner'
INNER_LABEL='org.cachy-asahi.glibc-gnu-provider-interruption'
LOCK='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
MAX_PUBLIC=768*1024**2


def need(ok,why):
    if not ok:raise ValueError(why)


def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()


def relative(name):
    need(type(name) is str and name and not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/')),'safe relative reference');return name


def ordinary(path,cap=2*1024**2):
    need(not any(p.is_symlink() for p in (path,*path.parents)),'ordinary no-alias path')
    info=path.stat();need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=cap,'bounded ordinary file');return info


def read(path,cap=2*1024**2):ordinary(path,cap);return json.loads(path.read_bytes())

def save(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')

def reference(root,row,cap=256*1024**2):
    need(set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int and 0<row['bytes']<=cap and re.fullmatch('[0-9a-f]{64}',row['sha256']),'explicit actual file ref')
    p=root/relative(row['path']);need(ordinary(p,cap).st_size==row['bytes'] and sha(p)==row['sha256'],'immutable input byte join');return p


def ref(root,path):return dict(path=path.relative_to(root).as_posix(),bytes=path.stat().st_size,sha256=sha(path))


def load(name,path):
    spec=importlib.util.spec_from_file_location('provider_owner_'+name,path);module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module);return module


def selection(workspace):
    policy=read(HERE/'policy.json',65536)
    need(policy['schema_version']==1 and policy['status']=='ROOT_BOUND_IMMUTABLE_PROVIDER_PACKET' and type(policy['packet']) is dict,'UNBOUND provider interruption owner; no secrets or actors permitted')
    packet=policy['packet'];need(set(packet)=={'ref','directory','index_sha256'} and re.fullmatch('[0-9a-f]{40}',packet['ref']) and re.fullmatch('[0-9a-f]{64}',packet['index_sha256']),'one exact future immutable input packet')
    relative(packet['directory'])
    manifest=read(HERE/'integration-manifest.json')
    needed={'scripts/apps/file_capabilities.py','scripts/ci/apps-full574-native/export_extract.py','scripts/ci/glibc-gnu-provider-lifecycle-owner/snapshot.py','scripts/ci/glibc-gnu-provider-lifecycle/capabilities.py'}|{HERE.relative_to(workspace).as_posix()+'/capability_snapshot.py'}
    needed|={'scripts/ci/glibc-gnu-trial-apparmor/profile.py','scripts/ci/glibc-gnu-trial-apparmor/vendor/apparmor/template.go','scripts/ci/glibc-gnu-trial-apparmor/vendor/apparmor/apparmor.go','scripts/ci/glibc-gnu-trial-apparmor/vendor/LICENSE','scripts/ci/glibc-gnu-trial-apparmor/vendor/source.json'}
    need(needed<=manifest['files'].keys(),'capability-aware frozen owner closure required')
    for name,row in manifest['files'].items():reference(workspace,dict(path=name,**row),16*1024**2)
    return policy


def proof(args):
    policy=selection(args.workspace)  # Deliberately before subprocess/GITHUB_OUTPUT/mkdir/secrets.
    env=os.environ;source=env['SOURCE_SHA'];need(re.fullmatch('[0-9a-f]{40}',source) and source==env['WORKFLOW_SHA']==env['GITHUB_SHA'],'exact source equals workflow')
    need(env['RUNNER_ARCH']=='ARM64' and env['RUNNER_OS']=='Linux','native ARM runner only')
    row=subprocess.run(['/usr/bin/git','-C',str(args.workspace),'rev-parse','HEAD'],capture_output=True,text=True,timeout=10)
    need(row.returncode==0 and row.stdout.strip()==source,'exact checkout source')
    run,attempt=env['GITHUB_RUN_ID'],env['GITHUB_RUN_ATTEMPT'];need(run.isdecimal() and attempt.isdecimal(),'run identity')
    identity=run+':'+attempt+':'+source
    value=dict(status='SOURCE_PROOF_BOUND_PACKET',source_sha=source,run_id=run,attempt=attempt,packet=policy['packet'],
        producer_token=hashlib.sha256(('gnu-provider574:'+identity).encode()).hexdigest()[:16],consumer_token=hashlib.sha256(('gnu-provider-interruption:'+identity).encode()).hexdigest()[:32],hardware='NOT_RUN')
    save(args.proof,value)
    with open(env['GITHUB_OUTPUT'],'a') as stream:
        for key,val in [('job_token',value['producer_token']),('consumer_token',value['consumer_token']),('packet_ref',policy['packet']['ref'])]:stream.write(key+'='+val+'\n')
    return value


def packet(workspace,root):
    policy=selection(workspace);directory=root/relative(policy['packet']['directory']);index=directory/'packet.json'
    need(sha(index)==policy['packet']['index_sha256'],'Root frozen packet manifest hash')
    value=read(index);need(value['schema_version']==1 and value['status']=='ROOT_ACCEPTED_PROVIDER_LIFECYCLE_INPUTS','actual accepted provider inputs only')
    files=value['files'];need(type(files) is dict and 8<=len(files)<=256,'closed bounded packet files')
    need(not {'interruption-input.json','base.lock','producer.json'}&set(files),'generated binding names reserved')
    total=0
    for name,row in files.items():
        p=reference(directory,dict(path=name,**row));total+=p.stat().st_size
    need(total<=512*1024**2,'512MiB immutable packet bound')
    for field in ('private16k','provider_pair','probe_receipt','held'):
        row=value[field];need(row['path'] in files and files[row['path']]=={k:row[k] for k in ('bytes','sha256')},'packet reference joins file closure');reference(directory,row)
    for group in ('archives','probes'):
        for row in value[group].values():need(row['path'] in files and files[row['path']]=={k:row[k] for k in ('bytes','sha256')},'archive/probe reference closure')
    need(set(value['archives'])=={'a','b'} and set(value['probes'])=={'smoke-normal','exec-child','plugin.so'},'exact new pair and normal probes')
    need(value['archives']['a']['sha256']==value['archives']['b']['sha256'],'actual pair hash equality')
    private=read(reference(directory,value['private16k']));native=read(reference(directory,value['provider_pair']));probes=read(reference(directory,value['probe_receipt']))
    need(private['status']=='ROOT_ACCEPTED_PRIVATE_GNU16K_RUNTIME' and private['page_size']==16384 and private['cases']==8 and private['ordered_cleanup']=='PASS','Rootaccepted private actual16K before any base actor')
    need(native['status']=='ROOT_ACCEPTED_PROVIDER_NATIVE_PAIR' and native['archive_sha256']==value['archives']['a']['sha256'] and native['hardware']=='NOT_RUN','Root accepted actual new provider pair')
    need(probes['status']=='ROOT_ACCEPTED_NORMAL_INTERPRETER_PROBES' and probes['files']==value['probes'],'Root accepted actual normal-client compilation')
    common=load('canonical_interruption_common',workspace/LANE/'common.py')
    need(sha(reference(directory,value['held']))==common.HELD_SHA and value['held']['path'].split('/')[-1]==common.HELD,'exact authenticated held rollback archive')
    for name in ('smoke-normal','exec-child'):common.interpreter(reference(directory,value['probes'][name]).read_bytes())
    need(probes['normal_source_sha256']==read(workspace/LANE/'normal-exec-change.json')['after_sha256'],'normal-exec source before/after binding')
    # These receipts are coordinator acceptances, never source-generated passes.
    return directory,value


def runtime(workspace):return load('held_process_runtime',workspace/'scripts/ci/glibc-owned-runtime/runner.py')


def inspect(name,command):
    row=command(['/usr/bin/docker','container','inspect',name],False)
    if row['code']:
        text=(row['out']+row['err']).decode(errors='replace').lower()
        need(row['code']==1 and name.lower() in text and ('no such container' in text or 'no such object' in text),'unknown daemon state');return None
    rows=json.loads(row['out']);need(len(rows)==1,'unique actor identity');return rows[0]


def verify_actor(value,name,image,label,token,cid=None):
    need(value['Name']=='/'+name and value['Image']==image and value['Config']['Labels'].get(label)==token and re.fullmatch('[0-9a-f]{64}',value['Id']) and cid in (None,value['Id']),'foreign actor preserved')
    if value['AppArmorProfile']=='' and label==LABEL and name=='caa-gnu-provider-interruption-owner-'+token+'-export':
        # Docker applies its runtime profile on start. This data export never starts.
        never_started(value);state=value['State'];config=value['HostConfig']
        need(re.fullmatch('[0-9a-f]{32}',token) and state['Status']=='created' and state['FinishedAt'].startswith('0001-') and state['ExitCode']==0 and state['Error']=='' and
             all(state[k] is False for k in ('Paused','Restarting','OOMKilled','Dead')) and value['RestartCount']==0 and
             config['Privileged'] is False and config['CapDrop']==['ALL'] and not config['CapAdd'] and config['NetworkMode']=='none' and
             config['SecurityOpt']==['no-new-privileges'] and value['Config']['Entrypoint']==['/usr/bin/false'],
             'empty profile only for exact never-started owned data export with original confinement config')
    else:need(value['AppArmorProfile']=='docker-default','outer observers preserve enforcing Docker default profile')
    return value['Id']


@contextmanager
def lease(path,new=False):
    fd=os.open(path,os.O_RDWR|os.O_CLOEXEC|os.O_NOFOLLOW|(os.O_CREAT|os.O_EXCL if new else 0),0o600)
    try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
    finally:os.close(fd)


@contextmanager
def producer_lease(base):
    fd=os.open(base,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
    finally:os.close(fd)


def command_api(workspace,output,report):
    api=runtime(workspace)
    def command(argv,required=True,seconds=30,private_stdout=False):
        if private_stdout:need(argv==['/usr/bin/sudo','-n','--','/usr/bin/cat','--','/sys/kernel/security/apparmor/profiles'] and seconds==10,'only bounded exact CI registry observer may redact stdout')
        row,out,err,error=api.run_command(argv,output,dict(api.ENV,HOME=str(output),TMPDIR=str(output)),seconds,1024**2)
        stored=out
        if private_stdout:
            row['stdout_retention']='HASH_AND_LENGTH_ONLY_PRIVATE_KERNEL_PROFILE_REGISTRY'
            stored=(json.dumps(dict(bytes=len(out),sha256=hashlib.sha256(out).hexdigest(),scope='PRIVATE_REGISTRY_NOT_EXPORTED'),sort_keys=True)+'\n').encode()
        n=len(report['commands']);need(n<256,'bounded owner commands');report['commands'].append(row);save(output/'owner.json',report)
        (output/('command-%03d.stdout'%n)).write_bytes(stored);(output/('command-%03d.stderr'%n)).write_bytes(err)
        if error:raise error
        need(row['group_absence_verified'] and (not required or row['exit_code']==0),'actor command exit/group retirement')
        return dict(code=row['exit_code'],out=out,err=err)
    return command


def reserve(report,output,role):
    need(role in ('export','extract','source-cleanup','inner-scrub'),'finite outer actor role')
    name='caa-gnu-provider-interruption-owner-'+report['token']+'-'+role
    need(role not in {r['role'] for r in report['actors']},'one actor per role')
    row=dict(role=role,name=name,id=None,status='RESERVED');report['actors'].append(row);save(output/'owner.json',report);return row


def retire(rows,image,label,token,command,output,report):
    for row in reversed(rows):
        if row['status']=='PASS_ABSENCE_VERIFIED':continue
        value=inspect(row['name'],command)
        if value is not None:
            cid=verify_actor(value,row['name'],image,label,token,row['id']);row['id']=cid;save(output/'owner.json',report)
            command(['/usr/bin/docker','rm','--force',cid])
        need(inspect(row['name'],command) is None,'owned actor remains');row['status']='PASS_ABSENCE_VERIFIED';save(output/'owner.json',report)


def observer(workspace,output,report,command,role,script,extra=()):
    row=reserve(report,output,role);need(inspect(row['name'],command) is None,'fresh outer actor name')
    argv=['/usr/bin/docker','run','--name',row['name'],'--label',LABEL+'='+report['token'],'--pull=never','--platform=linux/arm64','--network=none','--read-only','--user=0:0','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=128','--memory=4g','--cpus=2','--ulimit=nofile=8192:8192']
    argv+=['--cap-add='+n for n in ('CHOWN','DAC_OVERRIDE','FOWNER','FSETID')]
    if role=='extract':argv+=['--cap-add=SETFCAP']
    argv+=['--env=CACHY_GNU_PROVIDER_SNAPSHOT=1','--env=CACHY_GNU_PROVIDER_INTERRUPTION=1','--env=OWNER_TOKEN='+report['token'],'--env=OUTPUT_UID='+str(os.getuid()),'--env=OUTPUT_GID='+str(os.getgid()),'--env=PYTHONDONTWRITEBYTECODE=1']
    if role=='extract':argv+=['--env=SOURCE_TAR_SHA256='+report['snapshot_point']['archive_sha256']]
    data=output/'data';public=output/'snapshot-public';public.mkdir(mode=0o700,exist_ok=True)
    mounts=[(workspace,'/source',True),(HERE,'/runner',True),(data,'/data',False),(public,'/out',False)]
    if role=='inner-scrub':mounts.append((output/'inner/private','/work',False))
    for source,target,readonly in mounts:argv+=['--mount','type=bind,src='+str(source)+',dst='+target+(',readonly' if readonly else '')]
    argv+=['--entrypoint=/usr/bin/python3',report['image'],'-I','-B',script,*extra]
    result=command(argv,False,900 if role=='extract' else 180)
    value=inspect(row['name'],command);need(value is not None,'observer CID retained');row.update(id=verify_actor(value,row['name'],report['image'],LABEL,report['token']),status='EXITED',exit=result['code'],AppArmorProfile=value['AppArmorProfile']);save(output/'owner.json',report)
    need(result['code']==0,'owned snapshot observer failed')


def never_started(value):
    need(value['State']['Running'] is False and value['State']['Pid']==0 and value['State']['StartedAt'].startswith('0001-') and value['HostConfig']['ReadonlyRootfs'] is True,'NEVER_STARTED immutable source container')


def snapshot_source(workspace,output,report,command):
    row=reserve(report,output,'export');need(inspect(row['name'],command) is None,'fresh stopped export container')
    result=command(['/usr/bin/docker','create','--name',row['name'],'--label',LABEL+'='+report['token'],'--pull=never','--platform=linux/arm64','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--entrypoint=/usr/bin/false',report['image']])
    cid=result['out'].decode().strip();need(re.fullmatch('[0-9a-f]{64}',cid),'actual create CID');row['id']=cid;save(output/'owner.json',report)
    value=inspect(row['name'],command);verify_actor(value,row['name'],report['image'],LABEL,report['token'],cid)
    never_started(value)
    source=output/'data/source.tar';command(['/usr/bin/docker','export','--output',str(source),cid],seconds=300)
    need(ordinary(source,12*1024**3).st_size>0,'bounded original574 rootfs export')
    after=inspect(row['name'],command);verify_actor(after,row['name'],report['image'],LABEL,report['token'],cid)
    need(after['State']==value['State'],'export never ran a source-root actor')
    report['snapshot_point']=dict(container=cid,image=report['image'],state=value['State'],archive_bytes=source.stat().st_size,archive_sha256=sha(source),kind='NEVER_STARTED_ORIGINAL574_IMAGE_ROOTFS',AppArmorProfile=value['AppArmorProfile'])
    save(output/'owner.json',report);retire([row],report['image'],LABEL,report['token'],command,output,report)
    observer(workspace,output,report,command,'extract','/runner/capability_snapshot.py')
    snapshot=read(output/'snapshot-public/snapshot.json');need(snapshot['status']=='PASS_ORIGINAL574_DATA_SNAPSHOT' and snapshot['observation']['database_sha256']==LOCK and snapshot['extraction']['archive_sha256']==report['snapshot_point']['archive_sha256'],'actual complete original574 snapshot and archive join')
    need(snapshot['extraction']['capability_restoration']==snapshot['observation']['capabilities']=='PRESERVED_AND_COMPLETE_NODE_MAP_VERIFIED' and snapshot['extraction']['security_capabilities']==snapshot['observation']['security_capabilities'] and snapshot['extraction']['security_capabilities_sha256']==snapshot['observation']['source_capabilities_sha256'],'exact restored original574 capability snapshot')
    report['source_snapshot']=snapshot;save(output/'owner.json',report)


def capability_records(workspace,output,report):
    observation=report['source_snapshot']['observation'];mapping=observation['security_capabilities']
    index=read(output/'inputs/interruption-input.json')
    need(index['source_capabilities']==mapping and index['source_capabilities_sha256']==observation['source_capabilities_sha256'],'extraction/private input capability join')
    bridge=load('capability_records',workspace/'scripts/ci/glibc-gnu-provider-lifecycle/capabilities.py')
    child=read(output/'inner/public/result.json',8*1024**2)
    stages=('source-before','clone','before574','precommit-refused','provider574','reinstalled574','held574','source-after')
    stages+=('interrupted-before-unlock','recovered-held574')
    return bridge.records(index,child['cases'],stages)


def materialize(workspace,base,packet_root,packet_value,output,report):
    inputs=output/'inputs';inputs.mkdir(mode=0o700)
    for name,row in packet_value['files'].items():
        source=reference(packet_root,dict(path=name,**row));target=inputs/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,target)
    for name,source in [('base.lock',base/'installed-packages.lock'),('producer.json',base/'report.json')]:shutil.copyfile(source,inputs/name)
    value=dict(schema_version=1,status='ROOT_BOUND_UNSELECTED_PROVIDER_INTERRUPTION',package='cachy-asahi-glibc-gnu-provider',version='2.43.caa1-1',base_lock_sha256=LOCK,
        image_id=report['image'],token=report['token'],producer_token=report['producer_token'],source_nodes_sha256=report['source_snapshot']['observation']['node_sha256'],source_capabilities=report['source_snapshot']['observation']['security_capabilities'],source_capabilities_sha256=report['source_snapshot']['observation']['source_capabilities_sha256'],
        private16k=packet_value['private16k'],provider_pair=packet_value['provider_pair'],probe_receipt=packet_value['probe_receipt'],held=packet_value['held'],archives=packet_value['archives'],probes=packet_value['probes'],
        private16k_archive_sha256=read(reference(inputs,packet_value['private16k']))['candidate_package_sha256'],provider_pair_archive_sha256=packet_value['archives']['a']['sha256'],provider_pkgbuild_sha256=packet_value['provider_pkgbuild_sha256'],
        base_lock=ref(inputs,inputs/'base.lock'),producer_report=ref(inputs,inputs/'producer.json'))
    save(inputs/'interruption-input.json',value)
    runner=output/'interruption-runner';runner.mkdir(mode=0o700)
    source_manifest=read(workspace/LANE/'source-manifest.json')
    for name,row in source_manifest['files'].items():shutil.copyfile(reference(workspace/LANE,dict(path=name,**row)),runner/name)
    shutil.copyfile(workspace/LANE/'source-manifest.json',runner/'source-manifest.json')
    original=read(runner/'input-policy.json');need(original['status']=='UNBOUND_DO_NOT_EXECUTE' and original['binding'] is None,'canonical inner lane remains UNBOUND')
    changed=dict(original,status='BOUND_BY_ROOT',binding=dict(index_sha256=sha(inputs/'interruption-input.json'),token=report['token'],image_id=report['image']))
    save(runner/'input-policy.json',changed)
    manifest=read(runner/'source-manifest.json');before=sha(runner/'source-manifest.json');manifest['files']['input-policy.json']={k:v for k,v in ref(runner,runner/'input-policy.json').items() if k!='path'}
    save(runner/'source-manifest.json',manifest)
    for name,row in manifest['files'].items():reference(runner,dict(path=name,**row))
    report['private_binding']=dict(input_index_sha256=sha(inputs/'interruption-input.json'),canonical_policy_sha256=sha(workspace/LANE/'input-policy.json'),private_policy_sha256=sha(runner/'input-policy.json'),before_manifest_sha256=before,after_manifest_sha256=sha(runner/'source-manifest.json'),changed_files=['input-policy.json','source-manifest.json'])
    save(output/'owner.json',report)
    return inputs,runner


def consumer_records(output,source_hash):
    """Require complete real interruption/runtime records before owner acceptance/export."""
    public=output/'inner/public';result=read(public/'result.json',8*1024**2)
    need(result['status']=='PASS_GENERIC_ARM_PROVIDER_INTERRUPTION_RECOVERY' and
         result['hardware']=='NOT_RUN' and result['interrupted_in_progress_replacement']==
         'REMOVE_PHASE_ONLY_CANDIDATE_EXTRACTION_NOT_TESTED' and
         set(result['cases'])=={'pristine','modified'},'actual narrow interruption consumer result')
    required=['result.json']
    stages=('source-before','source-after','clone','before574','precommit-refused',
            'interrupted-before-unlock','recovered-held574','provider574','reinstalled574','held574')
    for case,row in result['cases'].items():
        need(row['status']=='PASS_INTERRUPTED_RECOVERED_NORMAL_PROVIDER_SEQUENCE' and
             row['source_before']==row['source_after']==source_hash and
             row['copy_lifetime']['cleanup']=='PASS-owned-workspace-removed',
             'complete original574 source preservation and copy lifetime')
        interrupted=row['interruption'];writer=interrupted['writer'];checkpoint=interrupted['checkpoint']
        need(interrupted['status']=='PASS_ACTUAL_REMOVE_PHASE_KILL_AND_EXTERNAL_RECOVERY' and
             writer['group_absence_verified'] is True and writer['exit_code']==-signal.SIGKILL and
             interrupted['observed_stop']=='KERNEL_CLD_STOPPED_SIGSTOP_WITH_UNREAPED_OWNED_LEADER' and
             checkpoint['phase']=='ALPM_COMMIT_REMOVE_PAYLOAD_BEFORE_OLD_DATABASE_REMOVAL' and
             checkpoint['event']==4 and checkpoint['package']=='glibc' and
             interrupted['partial_state']=='HELD574_DATABASE_WITH_PARTIALLY_REMOVED_HELD_PAYLOAD_CANDIDATE_NOT_ADDED' and
             interrupted['lock_recovery']['status']=='PASS_EXACT_OWNED_STALE_LOCK_REMOVED_AFTER_GROUP_ABSENCE' and
             interrupted['outer_runtime_before']==interrupted['outer_runtime_after'],
             'real stopped/killed writer external recovery and intact observer records')
        for name in ('before_runtime','recovered_runtime','provider_runtime','reinstalled_runtime','held_runtime'):
            runtime=row[name]
            need(runtime['normal_parent_and_child'] is True and runtime['result']['status']=='PASS' and
                 runtime['result']['cases']==8 and runtime['result']['page_size']==4096,
                 'unchanged genuine normal parent/child runtime at every stage')
        required += [case+'-'+stage+'-root.json.gz' for stage in stages]
    for name in required:need(ordinary(public/name,64*1024**2).st_size>0,'complete interruption root/runtime evidence')
    return dict(status='PASS_COMPLETE_INTERRUPTION_AND_NORMAL_RUNTIME_RECORDS',files=required)


def execute(args):
    selection(args.workspace)
    with producer_lease(args.base):return execute_leased(args)


def execute_leased(args):
    need(not any(k.startswith(('DOCKER_','LD_')) for k in os.environ),'daemon and loader overrides refused')
    for path in (args.workspace,args.base,args.packet_root,args.output.parent):
        need(path.is_absolute() and path.is_dir() and not any(p.is_symlink() for p in (path,*path.parents)) and ',' not in str(path),'ordinary explicit owner path')
    need(not any(args.output.is_relative_to(p) or p.is_relative_to(args.output) for p in (args.workspace,args.base,args.packet_root)),'disjoint owner/base/source/packet roots')
    packet_root,packet_value=packet(args.workspace,args.packet_root);proof_value=read(args.proof);base=read(args.base/'report.json')
    need(base['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION' and base['packages']==574 and base['ownership']['token']==proof_value['producer_token'] and sha(args.base/'installed-packages.lock')==LOCK,'fresh owned574 producer handshake')
    helper=load('original574_owner',args.workspace/'scripts/ci/maintained_desktop574.py');image=helper.inspect_image(base['image'],proof_value['producer_token'])
    need(image['Id']==base['image'] and image['Id'] not in base['ownership']['before_images'] and image['Size']<=8*1024**3,'fresh bounded image; borrowed images preserved')
    need(not args.output.exists() and args.output.is_absolute() and shutil.disk_usage(args.output.parent).free>=40*1024**3,'fresh40GiB owner workspace')
    args.output.mkdir(mode=0o700);(args.output/'data').mkdir(mode=0o700)
    report=dict(status='FAIL',token=proof_value['consumer_token'],producer_token=proof_value['producer_token'],image=base['image'],source_sha=proof_value['source_sha'],producer_lease='EXCLUSIVE_ORIGINAL574_BASE_DIRECTORY_FLOCK',actors=[],commands=[],producer_cleanup='NOT_ATTEMPTED',hardware='NOT_RUN',release_admission=False)
    with lease(args.output/'owner.lock',True):
        command=command_api(args.workspace,args.output,report);save(args.output/'owner.json',report)
        try:
            apparmor=load('trial_apparmor',args.workspace/'scripts/ci/glibc-gnu-trial-apparmor/profile.py')
            report['apparmor']=apparmor.load(args.output/'apparmor',proof_value,base,'interruption',command,(args.base/'probe-cid').read_text().strip());save(args.output/'owner.json',report)
            snapshot_source(args.workspace,args.output,report,command)
            inputs,runner=materialize(args.workspace,args.base,packet_root,packet_value,args.output,report)
            result=command([sys.executable,'-I','-B',str(runner/'run.py'),'--inputs',str(inputs),'--input-sha256',sha(inputs/'interruption-input.json'),'--source-root',str(args.workspace),'--held-root',str(args.output/'data/original574'),'--output',str(args.output/'inner'),'--apparmor-state',str(args.output/'apparmor')],False,3800)
            inner=read(args.output/'inner/owner.json');need(result['code']==0 and inner['status']=='PASS_GENERIC_ARM_INTERRUPTION_RECOVERY_AND_TEARDOWN','actual installed lifecycle and inner teardown')
            report['consumer_records']=consumer_records(args.output,report['source_snapshot']['observation']['node_sha256'])
            report['capabilities']=capability_records(args.workspace,args.output,report)
            report['status']='PASS_INTERRUPTION_PENDING_ORDERED_PRODUCER_CLEANUP'
        except BaseException as error:report.update(error_type=type(error).__name__,error=str(error)[:512])
        finally:
            try:retire(report['actors'],report['image'],LABEL,report['token'],command,args.output,report)
            except BaseException as error:report.update(outer_cleanup_error=str(error)[:512])
            if (args.output/'apparmor/state.json').exists():report['apparmor']=read(args.output/'apparmor/state.json',128*1024)
            save(args.output/'owner.json',report)
    return int(report['status']!='PASS_INTERRUPTION_PENDING_ORDERED_PRODUCER_CLEANUP')


def cleanup(args):
    selection(args.workspace);proof_value=read(args.proof);result=dict(status='FAIL',consumer='UNKNOWN',producer='PRESERVED');base_fd=None
    try:
        if args.base.is_dir():
            base_fd=os.open(args.base,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);fcntl.flock(base_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        if (args.output/'owner.json').exists():
            with lease(args.output/'owner.lock'):
                report=read(args.output/'owner.json');need(report['token']==proof_value['consumer_token'] and report['producer_token']==proof_value['producer_token'],'owned wrapper token/source')
                command=command_api(args.workspace,args.output,report)
                inner_path=args.output/'inner/owner.json'
                if inner_path.exists():
                    inner=read(inner_path);need(inner['token']==report['token'] and inner['image_id']==report['image'],'inner owner identity')
                    with lease(args.output/'inner/lease'):
                        need({r['role'] for r in inner['actors']}<={'trial','scrub'},'finite inner actor roles')
                        for row in inner['actors']:need(row['name']=='caa-glibc-interruption-'+report['token']+'-'+row['role'],'exact inner name')
                        retire(inner['actors'],report['image'],INNER_LABEL,report['token'],command,args.output,report)
                        save(inner_path,inner)
                else:need(not (args.output/'inner').exists(),'anonymous inner state preserved')
                retire(report['actors'],report['image'],LABEL,report['token'],command,args.output,report)
                if (args.output/'inner/private').exists():
                    observer(args.workspace,args.output,report,command,'inner-scrub','/source/'+LANE+'/scrub.py')
                    retire(report['actors'],report['image'],LABEL,report['token'],command,args.output,report)
                    need(not any((args.output/'inner/private').iterdir()),'inner clone data remains');(args.output/'inner/private').rmdir()
                if (args.output/'data/original574').exists():
                    observer(args.workspace,args.output,report,command,'source-cleanup','/runner/capability_snapshot.py',('--cleanup',))
                    retire(report['actors'],report['image'],LABEL,report['token'],command,args.output,report)
                need(not (args.output/'data/original574').exists(),'original data snapshot remains')
                archive=args.output/'data/source.tar'
                if archive.exists():ordinary(archive,12*1024**3);archive.unlink()
                apparmor=load('trial_apparmor',args.workspace/'scripts/ci/glibc-gnu-trial-apparmor/profile.py')
                try:
                    report['apparmor']=apparmor.unload(args.output/'apparmor',proof_value,read(args.base/'report.json'),'interruption',command) if (args.output/'apparmor/state.json').exists() else apparmor.unregistered_absent(proof_value['consumer_token'],'interruption',command)
                    result['apparmor']=report['apparmor']
                finally:
                    if (args.output/'apparmor/state.json').exists():report['apparmor']=read(args.output/'apparmor/state.json',128*1024)
                    save(args.output/'owner.json',report)
                report['consumer_cleanup']='PASS_ALL_ACTORS_CLONES_AND_SOURCE_DATA_RETIRED';save(args.output/'owner.json',report);result['consumer']=report['consumer_cleanup']
        else:
            need(not args.output.exists(),'unidentified wrapper output preserved');result['consumer']='NOT_STARTED'
        # Nothing above may be skipped to reach producer removal.
        if base_fd is not None:os.close(base_fd);base_fd=None
        if (args.base/'report.json').exists():
            process=runtime(args.workspace)
            argv=[sys.executable,'-I','-B',str(args.workspace/'scripts/ci/maintained_desktop574.py'),'cleanup','--inputs',str(args.workspace/'scripts/ci/maintained-desktop574-inputs.json'),'--output',str(args.base),'--job-token',proof_value['producer_token']]
            row,out,err,error=process.run_command(argv,args.base,dict(process.ENV,HOME=str(args.base/'home')),240,1024**2)
            need(error is None and row['exit_code']==0 and row['group_absence_verified'],'existing guarded producer cleanup')
            producer=read(args.base/'report.json')['owned_cleanup'];need(producer['status']=='PASS','producer absence verified');result['producer']=producer
        else:result['producer']='NOT_STARTED'
        result['status']='PASS_ORDERED_ALL_CONSUMERS_THEN_PRODUCER'
    except BaseException as error:result.update(error_type=type(error).__name__,error=str(error)[:512])
    finally:
        if base_fd is not None:os.close(base_fd)
    save(args.receipt,result);return int(result['status']!='PASS_ORDERED_ALL_CONSUMERS_THEN_PRODUCER')


def retain(args):
    selection(args.workspace);need(not args.public.exists(),'fresh public export');args.public.mkdir(mode=0o700)
    result=dict(status='FAIL_OR_INCOMPLETE',files={},total_bytes=0,errors=[],hardware='NOT_RUN',release_admission=False)
    def copy(source,name,cap):
        try:
            info=ordinary(source,cap);need(result['total_bytes']+info.st_size<=MAX_PUBLIC,'closed public aggregate bound')
            destination=args.public/relative(name);destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,destination)
            result['files'][name]=dict(bytes=info.st_size,sha256=sha(destination));result['total_bytes']+=info.st_size
        except BaseException as error:result['errors'].append(dict(file=name,error=str(error)[:256]))
    copy(args.proof,'source-proof.json',65536);copy(args.receipt,'ordered-cleanup.json',2*1024**2)
    copy(HERE/'integration-manifest.json','source/integration-manifest.json',2*1024**2)
    for name,row in read(HERE/'integration-manifest.json')['files'].items():copy(args.workspace/name,'source/'+name,16*1024**2)
    for name in ('report.json','seed-report.json','installed-packages.lock'):
        if (args.base/name).exists():copy(args.base/name,'producer/'+name,2*1024**2)
    if args.output.exists():
        copy(args.output/'owner.json','owner.json',2*1024**2)
        for name in ('state.json','trial.profile'):
            if (args.output/'apparmor'/name).exists():copy(args.output/'apparmor'/name,'apparmor/'+name,128*1024)
        for directory,prefix in [(args.output/'snapshot-public','snapshot'),(args.output/'inner/public','interruption')]:
            if directory.exists():
                for path in sorted(directory.iterdir()):copy(path,prefix+'/'+path.name,64*1024**2)
        for name in ('owner.json','lease'):
            if (args.output/'inner'/name).exists():copy(args.output/'inner'/name,'inner/'+name,2*1024**2)
        for path in sorted(args.output.glob('command-*.std*')):copy(path,'owner-commands/'+path.name,1024**2)
        if (args.output/'inputs/interruption-input.json').exists():copy(args.output/'inputs/interruption-input.json','binding/interruption-input.json',2*1024**2)
        for name in ('input-policy.json','source-manifest.json'):
            if (args.output/'interruption-runner'/name).exists():copy(args.output/'interruption-runner'/name,'binding/'+name,2*1024**2)
    # Exact immutable packet/source licenses and actual normal-client receipts remain retrievable in the export.
    try:
        root,value=packet(args.workspace,args.packet_root);copy(root/'packet.json','input-packet/packet.json',2*1024**2)
        for name,row in value['files'].items():copy(root/name,'input-packet/'+name,256*1024**2)
    except BaseException as error:result['errors'].append(dict(file='input-packet',error=str(error)[:256]))
    try:
        owner=read(args.output/'owner.json');ordered=read(args.receipt)
        need({'apparmor/state.json','apparmor/trial.profile'}<=result['files'].keys(),'closed actual profile/registration evidence required')
        state=read(args.output/'apparmor/state.json',128*1024);profile=args.output/'apparmor/trial.profile'
        need(state==owner['apparmor'] and state['profile']==dict(bytes=ordinary(profile,65536).st_size,sha256=sha(profile)),'exported actual profile bytes and registration join owner')
        need(owner['apparmor']['status']=='PASS_OWNED_PROFILE_REMOVED_AFTER_ALL_CONSUMERS' and ordered['apparmor']==owner['apparmor'],'actual owned trial profile load/enforce/removal evidence required')
        result['capabilities']=capability_records(args.workspace,args.output,owner)
        need(result['capabilities']==owner['capabilities'],'executed/exported capability records join')
        result['consumer_records']=consumer_records(args.output,owner['source_snapshot']['observation']['node_sha256'])
        needed={'source-proof.json','ordered-cleanup.json','owner.json','inner/owner.json',
                'binding/interruption-input.json','binding/input-policy.json','binding/source-manifest.json',
                'snapshot/snapshot.json','snapshot/original574-root.json.gz','producer/report.json',
                'producer/installed-packages.lock'}|{'interruption/'+n for n in result['consumer_records']['files']}
        need(needed<=set(result['files']),'all required actual interruption records retained')
        need(owner['status']=='PASS_INTERRUPTION_PENDING_ORDERED_PRODUCER_CLEANUP' and owner['consumer_cleanup']=='PASS_ALL_ACTORS_CLONES_AND_SOURCE_DATA_RETIRED' and ordered['status']=='PASS_ORDERED_ALL_CONSUMERS_THEN_PRODUCER' and not result['errors'],'closed native lifecycle and ordered teardown')
        result['status']='PASS_CLOSED_GENERIC_ARM_PROVIDER_INTERRUPTION_RECOVERY'
    except BaseException as error:result['errors'].append(dict(file='acceptance',error=str(error)[:256]))
    save(args.public/'export.json',result);return int(result['status']!='PASS_CLOSED_GENERIC_ARM_PROVIDER_INTERRUPTION_RECOVERY')


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=('proof','packet','execute','cleanup','retain'))
    for name in ('workspace','proof','base','output','receipt','public','packet-root'):parser.add_argument('--'+name,type=Path)
    args=parser.parse_args()
    if args.mode=='proof':proof(args);return 0
    if args.mode=='packet':packet(args.workspace,args.packet_root);return 0
    return {'execute':execute,'cleanup':cleanup,'retain':retain}[args.mode](args)

if __name__=='__main__':
    def cancel(*_):raise KeyboardInterrupt()
    for sig in (signal.SIGINT,signal.SIGTERM):signal.signal(sig,cancel)
    raise SystemExit(main())
