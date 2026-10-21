# SPDX-License-Identifier: MIT
"""Fresh core actor owner; exact original snapshot/process/retirement operations."""
import argparse,fcntl,hashlib,importlib.util,json,os,re,shutil,signal,stat,subprocess,sys,time
from contextlib import contextmanager
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
HERE=Path(__file__).resolve().parent
LABEL='org.cachy-asahi.core-native-lifecycle-owner'
INNER_LABEL=C.LABEL
LANE='scripts/ci/glibc-gnu-provider-lifecycle'
LOCK='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
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

def load(name,path):
    spec=importlib.util.spec_from_file_location('provider_owner_'+name,path);module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module);return module

def runtime(workspace):return load('held_process_runtime',workspace/'scripts/ci/glibc-owned-runtime/runner.py')

def inspect(name,command):
    row=command(['/usr/bin/docker','container','inspect',name],False)
    if row['code']:
        text=(row['out']+row['err']).decode(errors='replace').lower()
        need(row['code']==1 and name.lower() in text and ('no such container' in text or 'no such object' in text),'unknown daemon state');return None
    rows=json.loads(row['out']);need(len(rows)==1,'unique actor identity');return rows[0]

def verify_actor(value,name,image,label,token,cid=None):
    need(value['Name']=='/'+name and value['Image']==image and value['Config']['Labels'].get(label)==token and re.fullmatch('[0-9a-f]{64}',value['Id']) and cid in (None,value['Id']),'foreign actor preserved')
    exports={LABEL:'caa-gnu-provider-owner-','org.cachy-asahi.apps-full574-native':'caa-apps574-','org.cachy-asahi.orphans-full574-native':'caa-apps574-'}
    if value['AppArmorProfile']=='' and label in exports and name==exports[label]+token+'-export':
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
    name='caa-gnu-provider-owner-'+report['token']+'-'+role
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
    argv+=['--env=CACHY_GNU_PROVIDER_SNAPSHOT=1','--env=CACHY_GNU_PROVIDER_LIFECYCLE=1','--env=OWNER_TOKEN='+report['token'],'--env=OUTPUT_UID='+str(os.getuid()),'--env=OUTPUT_GID='+str(os.getgid()),'--env=PYTHONDONTWRITEBYTECODE=1']
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

def assembly(args,report,command,deadline):
 row=dict(role='assembly',name='caa-core-native-assembly-'+report['token'],id=None,status='RESERVED');need(not any(r['role']=='assembly'for r in report['actors']),'one owned assembly role');report['actors'].append(row);save(args.output/'owner.json',report);need(inspect(row['name'],command)is None,'fresh isolated signing actor')
 argv=['/usr/bin/docker','run','--name',row['name'],'--label',LABEL+'='+report['token'],'--pull=never','--platform=linux/arm64','--network=none','--read-only','--user=0:0','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=128','--memory=4g','--cpus=2','--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=128m','--tmpfs=/authority:rw,nosuid,nodev,noexec,size=32m,mode=0700']
 argv+=['--cap-add='+n for n in('CHOWN','DAC_OVERRIDE','FOWNER')];argv+=['--env=CACHY_CORE7_ASSEMBLY=1','--env=OUTPUT_UID='+str(os.getuid()),'--env=OUTPUT_GID='+str(os.getgid()),'--env=PYTHONDONTWRITEBYTECODE=1']
 for source,target in((HERE,'/runner'),(args.workspace,'/runtime'),(args.core7,'/core7'),(args.core64,'/core64'),(args.base/'context/deps','/base-cache')):argv+=['--mount','type=bind,src='+str(source)+',dst='+target+',readonly']
 argv+=['--mount','type=bind,src='+str(args.output/'inputs')+',dst=/out','--entrypoint=/usr/bin/python3',report['image'],'-I','-B','/runner/assemble.py'];result=command(argv,False,min(1070,max(.001,deadline-time.monotonic())));value=inspect(row['name'],command);need(value is not None,'assembly actor retained identity');row.update(id=verify_actor(value,row['name'],report['image'],LABEL,report['token']),status='EXITED',exit=result['code']);save(args.output/'owner.json',report);need(result['code']==0,'complete current64 authentication and private TEST assembly')
 result=read(args.output/'inputs/assembly.json');need(result['status']=='SIGNED_CORE7_TEST_ASSEMBLY_DATA_ONLY','complete owned TEST assembly DATA');report['assembly']=result;retire([row],report['image'],LABEL,report['token'],command,args.output,report)

def binding(args,report):
 root=args.output/'inputs';aliases={};files={}
 for p in root.rglob('*'):
  if p.is_symlink():aliases[p.relative_to(root).as_posix()]=p.readlink().as_posix()
  elif p.is_file():files[p.relative_to(root).as_posix()]=dict(bytes=ordinary(p,128*1024**2).st_size,sha256=sha(p))
  else:need(p.is_dir(),'ordinary derived signing/input closure')
 profile=C.profile();base_lock=json.loads(C.read(args.workspace/'scripts/ci/maintained-desktop574-inputs.json'));rows={r['name']:r for r in base_lock['packages']};value=dict(schema=1,scope='DISPOSABLE_CORE7_NATIVE_LIFECYCLE',token=report['token'],image_id=report['image'],core7_source=profile['core7']['source'],accepted_build=profile['accepted_build'],base_lock=LOCK,source_capabilities=report['source_snapshot']['observation']['security_capabilities'],source_capabilities_sha256=report['source_snapshot']['observation']['source_capabilities_sha256'],source_nodes_sha256=report['source_snapshot']['observation']['node_sha256'],test_signer=report['assembly']['signer'],rollback_rows={n:rows[n]for n in C.REPLACED},assembly_files=files,assembly_aliases=aliases)
 save(root/'lifecycle-input.json',value);C.configuration(root,sha(root/'lifecycle-input.json'));report['binding']=dict(index_sha256=sha(root/'lifecycle-input.json'),assembly_files=len(files),source_capabilities_sha256=value['source_capabilities_sha256']);save(args.output/'owner.json',report);return value

def failure_data(report):
 """Only fixed phase/outcome scalars and hashes; no raw argv/path/output."""
 try:
  need(report.get('status')=='FAIL','failure-only diagnostic')
  phase=report.get('active_phase');need(phase in('APPARMOR','SOURCE_SNAPSHOT','AUTH_AND_TEST_ASSEMBLY','BIND_INPUTS','CORE_LIFECYCLE'),'finite source-owned phase')
  kinds=('ValueError','RuntimeError','TimeoutError','FileNotFoundError','PermissionError','OSError','KeyboardInterrupt','SystemExit','AssertionError')
  error=report.get('error','');need(type(error)is str and len(error)<=512,'bounded existing original error')
  commands=report.get('commands');need(type(commands)is list and len(commands)<=256,'original command records')
  last=commands[-1]if commands else None
  outcome=None
  if last is not None:
   need(type(last)is dict,'original command DATA')
   outcome={key:last.get(key)for key in('exit_code','group_absence_verified','time_limit','output_limit')}
   need(type(outcome['exit_code'])in(int,type(None))and type(outcome['group_absence_verified'])in(bool,type(None)),'typed original command outcome')
   for key in('time_limit','output_limit'):need(outcome[key]is None or type(outcome[key])in(int,float),'scalar command limits')
  row=dict(schema=1,status='CORE7_OWNER_FAILURE_DATA_NOT_ACCEPTANCE',phase=phase,
   error_type=report.get('error_type')if report.get('error_type')in kinds else'OTHER',
   error=dict(bytes=len(error.encode()),sha256=hashlib.sha256(error.encode()).hexdigest()),
   commands=len(commands),last=outcome,source_snapshot_complete='source_snapshot'in report,
   assembly_complete='assembly'in report,binding_complete='binding'in report,
   acceptance=False,hardware='NOT_RUN')
  raw=json.dumps(row,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
  need(len(raw)<=2048,'finite failure diagnostic cap');sys.stderr.write('CORE7_OWNER_FAILURE_DATA '+raw.decode()+'\n');sys.stderr.flush()
 except BaseException:pass  # DATA cannot replace the original failure/cleanup.

def execute(args):
 need(not any(k.startswith(('DOCKER_','LD_'))for k in os.environ),'daemon/loader overrides refused')
 for path in(args.workspace,args.base,args.core7,args.core64,args.output.parent):need(path.is_absolute()and path.is_dir()and not any(p.is_symlink()for p in(path,*path.parents))and','not in str(path),'explicit ordinary source/producer/carrier/output ancestry')
 need(not args.output.exists()and not any(args.output.is_relative_to(p)or p.is_relative_to(args.output)for p in(args.workspace,args.base,args.core7,args.core64))and shutil.disk_usage(args.output.parent).free>=40*1024**3,'fresh disjoint40GiB owner output')
 proof=read(args.proof);base=read(args.base/'report.json');need(base['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION'and base['packages']==574 and base['ownership']['token']==proof['producer_token']and sha(args.base/'installed-packages.lock')==LOCK,'fresh exact owned574 producer')
 helper=load('core_original574_owner',args.workspace/'scripts/ci/maintained_desktop574.py');image=helper.inspect_image(base['image'],proof['producer_token']);need(image['Id']==base['image']and image['Id']not in base['ownership']['before_images']and image['Size']<=8*1024**3,'fresh bounded original574 image')
 args.output.mkdir(mode=0o700)
 for n in('data','inputs'):(args.output/n).mkdir(mode=0o700)
 report=dict(status='FAIL',token=proof['consumer_token'],producer_token=proof['producer_token'],image=base['image'],source_sha=proof['source_sha'],producer_lease='EXCLUSIVE_ORIGINAL574_BASE_DIRECTORY_FLOCK',actors=[],commands=[],producer_cleanup='NOT_ATTEMPTED',hardware='NOT_RUN',release_admission=False,old_target261='UNCHANGED_UNACCEPTED');deadline=time.monotonic()+4800
 with producer_lease(args.base),lease(args.output/'owner.lock',True):
  original_command=command_api(args.workspace,args.output,report)
  def command(argv,required=True,seconds=30,private_stdout=False):return original_command(argv,required,min(seconds,max(.001,deadline-time.monotonic())),private_stdout)
  save(args.output/'owner.json',report)
  try:
   report['active_phase']='APPARMOR'
   apparmor=load('core_original_apparmor',args.workspace/'scripts/ci/glibc-gnu-trial-apparmor/profile.py');report['apparmor']=apparmor.load(args.output/'apparmor',proof,base,'lifecycle',command,(args.base/'probe-cid').read_text().strip());save(args.output/'owner.json',report)
   report['active_phase']='SOURCE_SNAPSHOT'
   snapshot_source(args.workspace,args.output,report,command)
   report['active_phase']='AUTH_AND_TEST_ASSEMBLY'
   assembly(args,report,command,deadline)
   report['active_phase']='BIND_INPUTS'
   index=binding(args,report)
   report['active_phase']='CORE_LIFECYCLE'
   result=command([sys.executable,'-I','-B',str(HERE/'run.py'),'--inputs',str(args.output/'inputs'),'--input-sha256',sha(args.output/'inputs/lifecycle-input.json'),'--source-root',str(args.workspace),'--held-root',str(args.output/'data/original574'),'--output',str(args.output/'inner'),'--apparmor-state',str(args.output/'apparmor')],False,3800)
   inner=read(args.output/'inner/owner.json');need(result['code']==0 and inner['status']=='PASS_CORE7_INSTALLED_AND_TEARDOWN','all installed Core7 cases and inner teardown');child=read(args.output/'inner/public/result.json',2*1024**2);C.validate_child(index,child);report['status']='PASS_CORE7_PENDING_ORDERED_PRODUCER_CLEANUP'
  except BaseException as error:report.update(error_type=type(error).__name__,error=str(error)[:512])
  finally:
   # Retirement has its original independent bounded calls even after parent expiry.
   retirement=command_api(args.workspace,args.output,report)
   try:retire(report['actors'],report['image'],LABEL,report['token'],retirement,args.output,report)
   except BaseException as error:report.update(status='FAIL',outer_cleanup_error=str(error)[:512])
   if(args.output/'apparmor/state.json').exists():report['apparmor']=read(args.output/'apparmor/state.json',128*1024)
   save(args.output/'owner.json',report)
 if report['status']=='FAIL':failure_data(report)
 return int(report['status']!='PASS_CORE7_PENDING_ORDERED_PRODUCER_CLEANUP')


def cleanup(args):
    import entry;entry.source(args.source);proof_value=read(args.proof);result=dict(status='FAIL',consumer='UNKNOWN',producer='PRESERVED');base_fd=None
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
                        for row in inner['actors']:need(row['name']=='caa-glibc-provider-'+report['token']+'-'+row['role'],'exact inner name')
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
                    report['apparmor']=apparmor.unload(args.output/'apparmor',proof_value,read(args.base/'report.json'),'lifecycle',command) if (args.output/'apparmor/state.json').exists() else apparmor.unregistered_absent(proof_value['consumer_token'],'lifecycle',command)
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
 need(not args.public.exists(),'fresh public original evidence');args.public.mkdir(mode=0o700);result=dict(schema=1,status='FAIL_OR_INCOMPLETE',files={},errors=[],bytes=0,hardware='NOT_RUN',old_target261='UNCHANGED_UNACCEPTED')
 def copy(source,name,cap=64*1024**2):
  try:
   size=ordinary(source,cap).st_size;need(result['bytes']+size<=768*1024**2,'original768MiB public evidence cap');destination=args.public/relative(name);destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,destination);result['files'][name]=dict(bytes=size,sha256=sha(destination));result['bytes']+=size
  except BaseException as error:result['errors'].append(dict(file=name,error=str(error)[:256]))
 copy(args.proof,'source-proof.json',65536);copy(args.receipt,'ordered-cleanup.json',2*1024**2)
 copy(args.output.parent/'legacy-prefill.json','retained/legacy-prefill.json',2*1024**2);copy(args.output.parent/'retained-custody.json','retained/retained-custody.json',2*1024**2)
 for n in('report.json','seed-report.json','installed-packages.lock','build.log'):
  if(args.base/n).exists():copy(args.base/n,'producer/'+n)
 if args.output.exists():
  copy(args.output/'owner.json','owner.json',2*1024**2)
  for n in('state.json','trial.profile'):
   if(args.output/'apparmor'/n).exists():copy(args.output/'apparmor'/n,'apparmor/'+n,128*1024)
  for directory,prefix in((args.output/'snapshot-public','snapshot'),(args.output/'inner/public','lifecycle'),(args.output/'inputs','inputs')):
   if directory.exists():
    for p in sorted(directory.rglob('*')):
     if p.is_symlink():need(prefix=='inputs'and p.name in('core7-test.db','core7-test.db.sig','core7-test.files','core7-test.files.sig'),'only exact already-validated repository aliases omitted');continue
     if p.is_file():copy(p,prefix+'/'+p.relative_to(directory).as_posix(),128*1024**2 if prefix=='inputs'and p.parent.name=='packages'else 64*1024**2)
  if(args.output/'inner/owner.json').exists():copy(args.output/'inner/owner.json','inner/owner.json',2*1024**2)
  for p in sorted(args.output.glob('command-*.std*')):copy(p,'owner-commands/'+p.name,1024**2)
 try:
  report=read(args.output/'owner.json');child=read(args.output/'inner/public/result.json');index=read(args.output/'inputs/lifecycle-input.json');ordered=read(args.receipt);C.validate_child(index,child);C.graph_exports(args.output/'inner/public',index,child)
  import cache_data;cache=read(args.output.parent/'retained-custody.json');cache_data.validate(cache['complete'],cache['legacy'])
  need(report['status']=='PASS_CORE7_PENDING_ORDERED_PRODUCER_CLEANUP'and report['consumer_cleanup']=='PASS_ALL_ACTORS_CLONES_AND_SOURCE_DATA_RETIRED'and ordered['status']=='PASS_ORDERED_ALL_CONSUMERS_THEN_PRODUCER'and ordered['producer']['status']=='PASS','actual full new lifecycle and ordered producer teardown')
  need(report['apparmor']['status']=='PASS_OWNED_PROFILE_REMOVED_AFTER_ALL_CONSUMERS'and ordered['apparmor']==report['apparmor']and not result['errors'],'complete profile lifetime and raw evidence');result['status']='PASS_CLOSED_CORE7_NATIVE_LIFECYCLE'
 except BaseException as error:result['errors'].append(dict(file='acceptance',error=str(error)[:512]))
 save(args.public/'export.json',result);return int(result['status']!='PASS_CLOSED_CORE7_NATIVE_LIFECYCLE')

def transport(args):
 """Two upload-safe leaves carry the unchanged complete original public tree."""
 import zipfile
 public=args.public;target=args.output;cap=768*1024**2
 need(public.is_absolute()and public.is_dir()and not any(p.is_symlink()for p in(public,*public.parents)),'ordinary original public export')
 need(target.is_absolute()and target.parent.is_dir()and not target.exists()and not any(p.is_symlink()for p in(target,*target.parents))and not target.is_relative_to(public)and not public.is_relative_to(target),'fresh disjoint opaque transport')
 export=read(public/'export.json',2*1024**2);wanted=export['files'];actual={};total=0
 for p in sorted(public.rglob('*')):
  need(not p.is_symlink()and(p.is_file()or p.is_dir()),'ordinary complete original public closure')
  if not p.is_file():continue
  name=p.relative_to(public).as_posix();relative(name);size=ordinary(p,128*1024**2).st_size;total+=size;need(total<=cap,'original768MiB transport cap');actual[name]=dict(bytes=size,sha256=sha(p))
 need(set(actual)==set(wanted)|{'export.json'}and all(actual[n]==r for n,r in wanted.items()),'whole original export membership/bytes before transport')
 need(0<len(actual)<=4096,'finite original public member count')
 target.mkdir(mode=0o700);archive=target/'public.zip'
 with zipfile.ZipFile(archive,'x',compression=zipfile.ZIP_STORED,allowZip64=False)as z:
  for name in sorted(actual):
   raw=C.read(public/name,128*1024**2);need(C.pin(raw)==actual[name],'stable full original public read');info=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0));info.create_system=3;info.external_attr=(stat.S_IFREG|0o600)<<16;z.writestr(info,raw)
 need(ordinary(archive,cap).st_size<=cap,'opaque archive original768MiB cap')
 with zipfile.ZipFile(archive)as z:
  need(z.testzip()is None and len(z.namelist())==len(set(z.namelist()))==len(actual),'complete inner CRC/membership')
  need({n:C.pin(z.read(n))for n in z.namelist()}==actual,'all unchanged original public bytes inside opaque transport')
 value=dict(schema=1,status='OPAQUE_CORE7_PUBLIC_DATA_ONLY',archive='public.zip',pin=dict(bytes=archive.stat().st_size,sha256=sha(archive)),members=len(actual),bytes=total,export=actual['export.json'],acceptance=False)
 save(target/'transport.json',value)
 need(sum(p.stat().st_size for p in target.iterdir())+4096<=cap,'outer transport retains original768MiB API cap')
 return 0

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__+' Use entry.py for source-bound operations.');parser.parse_args();parser.error('use the source-bound entry.py CLI')
