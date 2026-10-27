# SPDX-License-Identifier: MIT
"""Fresh607 producer, confined actors, reverse cleanup and raw retention."""
import argparse,contextlib,fcntl,hashlib,importlib.util,json,os,platform,re,shutil,signal,stat,sys,tempfile,time,types
from pathlib import Path
OPERATION='recover-apps16-reinstall607';LABEL='org.cachy-asahi.apps607-fresh-recovery-owner';LANE='scripts/ci/apps7-full574-repair-native'
RUN_SECONDS=4870;CLEANUP_SECONDS=650;MAX_PUBLIC=192*1024**2
ACTOR_SECONDS={'install':4500,'snapshot':900,'consumer':4320,'signer':240,'cleanup':240,'tooling':1900}
BASE_CAPS=('CHOWN','DAC_OVERRIDE','FOWNER','FSETID')
ROLE_CAPS={'install':(*BASE_CAPS,'SETGID','SETUID','SYS_CHROOT'),'snapshot':(*BASE_CAPS,'SETFCAP'),'consumer':(*BASE_CAPS,'SETFCAP','SYS_CHROOT'),'cleanup':BASE_CAPS,'signer':BASE_CAPS,'tooling':BASE_CAPS}
def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def identity(s):return[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def canonical(value):
 raw=os.fspath(value);need(os.path.isabs(raw)and raw==os.path.normpath(raw)and not raw.startswith('//'),'absolute normalized607 path');p=Path(raw);need(not any(q.is_symlink()for q in(p,*p.parents)),'ordinary607 ancestry');return p
def read(path,cap=16*1024**2):
 p=canonical(path);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded singlelink607 input');raw=bytearray()
  while b:=os.read(fd,65536):raw.extend(b);need(len(raw)<=a.st_size,'607 input growth')
  need(len(raw)==a.st_size and identity(a)==identity(os.fstat(fd))==identity(p.lstat()),'complete stable607 FD/path');return bytes(raw)
 finally:os.close(fd)
def decode(raw):
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate607 key');out[k]=v
  return out
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite607 JSON'))
def save(path,value):
 raw=encoded(value);need(len(raw)<=4*1024**2,'bounded607 report');fd,temporary=tempfile.mkstemp(prefix='.'+path.name+'.',dir=path.parent)
 with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 os.replace(temporary,path);fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:os.fsync(fd)
 finally:os.close(fd)
def scan(root,cap=64*1024**2):
 root=canonical(root);out={};dirs=set();total=0;queued=1;todo=[root]
 while todo:
  p=todo.pop();need(not p.is_symlink(),'607 source alias')
  if p.is_dir():
   if p!=root:dirs.add(p.relative_to(root).as_posix())
   with os.scandir(p)as children:
    for child in children:queued+=1;need(queued<=4096,'finite607 source namespace');todo.append(Path(child.path))
  else:
   raw=read(p);total+=len(raw);need(total<=cap,'bounded607 source bytes');out[p.relative_to(root).as_posix()]=pin(raw)
 need(dirs=={q.as_posix()for n in out for q in Path(n).parents if str(q)!='.'},'closed607 source directories');return out

def source_gate(args):
 root=canonical(args.operation_root);raw=read(root/'profile.json');need(re.fullmatch('[0-9a-f]{64}',args.operation_profile_sha256 or '')and pin(raw)['sha256']==args.operation_profile_sha256,'independent Root607 profile pin');p=decode(raw)
 need(p['schema_version']==1 and p['operation']==OPERATION and p['actual']is None and p['Root_acceptance']is None,'source-only exact607 profile')
 need({'native_owner607.py','producer607.py','provider607.py','consumer607.py','backend607.py','entry607.py'}<=p['operation_files'].keys(),'complete executable607 chain')
 need(scan(root)==dict(p['operation_files'],**{'profile.json':pin(raw)})and p['operation_files']['native_owner607.py']==pin(read(Path(__file__))),'whole Root607 operation and current owner bytes')
 args.recovery_source=canonical(root.parent/'repair-source');need(canonical(args.source)==args.recovery_source,'explicit public245 --source');need(scan(args.recovery_source)==p['source_files']and len(p['source_files'])==245,'whole held public245');args.operation_root=root;return p

def current_identity(args):
 e=os.environ;source=e.get('SOURCE_SHA','');need(re.fullmatch('[0-9a-f]{40}',source)and source==e.get('GITHUB_SHA')==e.get('GITHUB_WORKFLOW_SHA'),'actual same-source607 workflow');run,attempt=e.get('GITHUB_RUN_ID',''),e.get('GITHUB_RUN_ATTEMPT','');need(run.isdecimal()and int(run)>0 and attempt.isdecimal()and int(attempt)>0,'actual607 run/attempt');token=pin(('apps607-consumer:'+run+':'+attempt+':'+source).encode())['sha256'][:32]
 need(canonical(args.owner_output)==Path('/tmp')/('caa-apps607-'+token),'fixed607 source/run/attempt directory');return dict(source_sha=source,run_id=int(run),attempt=int(attempt),token=token,operation=OPERATION,operation_profile_sha256=args.operation_profile_sha256)
def native_guard():need(platform.machine()=='aarch64'and platform.system()=='Linux'and os.getuid()==os.geteuid()>0 and not any(k.startswith('DOCKER_')for k in os.environ),'ordinary native ARM local-daemon coordinator')
def load(name,path):
 spec=importlib.util.spec_from_file_location('_native607_'+name,path);m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m);return m

def modules(args,cleanup=False):
 source_gate(args);route=load('route',args.operation_root/'route607.py');old_route=sys.modules.get('route607');sys.modules['route607']=route
 try:producer=load('producer',args.operation_root/'producer607.py')
 finally:
  if old_route is None:sys.modules.pop('route607',None)
  else:sys.modules['route607']=old_route
 if not cleanup:
  temporary,clean,fact=producer.stage_source(args)
  try:route.source_contract(clean,args.fresh_authorization,'fresh4k');producer.recovery_source(args.recovery_root)
  finally:temporary.cleanup()
 C=load('contract',args.recovery_source/LANE/'contract.py');C.source(args.recovery_source)
 selected=load('selected_pair',args.recovery_source/'apps16-repair/selection.py');ordinary=C.checked;facade=types.SimpleNamespace(**vars(C))
 def inputs(root,packet):C.source(root);return selected.inputs(root,packet,carrier_root=args.apps16_pair,git_dir=args.apps16_pair/'.git')
 def checked(root,row):return selected.checked(root,row,carrier_root=args.apps16_pair)if row['path'].startswith('APPS16_CARRIER/')else ordinary(root,row)
 facade.inputs=inputs;facade.checked=checked;api=C.load('native607_owner',args.recovery_source/'scripts/ci/glibc-gnu-provider-lifecycle-owner/job.py');api.save=save;prior=sys.modules.get('contract');sys.modules['contract']=C
 try:H=load('held_job',args.recovery_source/'scripts/ci/apps-full574-native/job.py')
 finally:
  if prior is None:sys.modules.pop('contract',None)
  else:sys.modules['contract']=prior
 H.C=facade;packet=None
 if not cleanup:packet,payload,origins=facade.inputs(args.recovery_source,args.packet)
 provider=load('provider',args.operation_root/'provider607.py');old_provider=sys.modules.get('provider607');sys.modules['provider607']=provider
 try:consumer=load('consumer',args.operation_root/'consumer607.py')
 finally:
  if old_provider is None:sys.modules.pop('provider607',None)
  else:sys.modules['provider607']=old_provider
 return types.SimpleNamespace(C=C,H=H,api=api,packet=packet,producer=producer,provider=provider,consumer=consumer)
@contextlib.contextmanager
def budget(seconds):
 old=signal.getsignal(signal.SIGALRM);prior=signal.setitimer(signal.ITIMER_REAL,0)
 if prior!=(0.0,0.0):signal.setitimer(signal.ITIMER_REAL,*prior);raise ValueError('no unaccounted inherited owner timer')
 def expired(*unused):raise TimeoutError('fixed607 owner deadline')
 signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,seconds)
 try:yield
 finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,old)
@contextlib.contextmanager
def lease(root,new):
 fd=os.open(root/'owner.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC|(os.O_CREAT|os.O_EXCL if new else 0),0o600)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode)and s.st_uid==os.getuid()and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600,'exact private607 lease');fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
 finally:os.close(fd)

class Runtime:
 def __init__(self,args,mods,report):
  self.args,self.mods,self.report=args,mods,report;self.output=canonical(args.owner_output);self.receipts=self.output/'receipts';self.repair_inputs=self.output/'inputs';self.identity=dict(source=report['source_sha'],run_id=report['run_id'],attempt=report['attempt'],token=report['token']);self.deadline=time.monotonic()+RUN_SECONDS;self.prepared=None;self.installed=None
  self.base_command=mods.api.command_api(args.recovery_source,self.output,report)
 def persist(self):save(self.output/'owner.json',self.report)
 def command(self,argv,required=True,seconds=30,private_stdout=False):
  remaining=self.deadline-time.monotonic();need(remaining>0 and type(seconds)in(int,float)and 0<seconds<=4500,'original bounded607 command');return self.base_command(argv,required,seconds=min(seconds,remaining),private_stdout=private_stdout)
 def set_prepared(self,prepared):
  need(re.fullmatch('sha256:[0-9a-f]{64}',prepared.image),'actual pinned native builder image');self.prepared=prepared;self.report.update(image=prepared.image,producer_token=prepared.token,bundle607=str(canonical(prepared.bundle607)),candidate=str(canonical(prepared.candidate)));self.persist()
  need(self.command(['/usr/bin/docker','context','show'])['out'].decode().strip()=='default'and self.command(['/usr/bin/docker','info','--format','{{.Architecture}}'])['out'].decode().strip()in('aarch64','arm64'),'local native ARM daemon')
  value=decode(self.command(['/usr/bin/docker','context','inspect','default'])['out']);need(len(value)==1 and value[0]['Endpoints']['docker']['Host']=='unix:///var/run/docker.sock','local default daemon only')
  need(self.command(['/usr/bin/docker','image','inspect','--format','{{.Os}}/{{.Architecture}}',prepared.image])['out'].decode().strip()=='linux/arm64','exact native builder image platform')
 def actor_plan(self,role,context_sha=None):
  need(role in ACTOR_SECONDS and role!='tooling'and self.prepared is not None,'fixed fresh607 actor role/prepared owner');p=self.prepared;name='caa-apps607-'+self.report['token']+'-'+role
  argv=['/usr/bin/docker','run','--name',name,'--label',LABEL+'='+self.report['token'],'--pull=never','--platform=linux/arm64','--network=none','--read-only','--user=0:0','--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=128','--memory=4g','--cpus=2','--ulimit=nofile=8192:8192']
  argv+=['--cap-add='+c for c in ROLE_CAPS[role]]
  argv+=['--tmpfs','/tmp:rw,nosuid,nodev,exec,size=1g,mode=1777']
  env=dict(PATH='/usr/bin:/bin',PYTHONDONTWRITEBYTECODE='1',SOURCE_SHA=self.report['source_sha'],GITHUB_SHA=self.report['source_sha'],GITHUB_WORKFLOW_SHA=self.report['source_sha'],GITHUB_RUN_ID=str(self.report['run_id']),GITHUB_RUN_ATTEMPT=str(self.report['attempt']),OWNER_TOKEN=self.report['token'],CACHY_ASAHI_APPS_TRANSACTION=self.report['token'],OUTPUT_UID=str(os.getuid()),OUTPUT_GID=str(os.getgid()),APPS16_INTERRUPTION_PROFILE_SHA256=self.args.operation_profile_sha256,CACHY_APPS574_SNAPSHOT='1',CACHY_APPS574_FIXTURE='1',CACHY_APPS574_LIFECYCLE='1',CACHY_APPS574_OPERATION=OPERATION,CACHY_APPS574_REPAIR_CASE='repair-bytes')
  if role=='signer':env['FRESH607_SIGNER']='1'
  if role=='consumer':need(re.fullmatch('[0-9a-f]{64}',context_sha or ''),'independent provider context pin');env['NATIVE607_CONTEXT_SHA256']=context_sha
  if role=='cleanup':env['NATIVE607_ABSENCE_SHA256']=pin(read(self.output/'authority/native607-absence.json'))['sha256']
  for k,v in env.items():argv+=['--env='+k+'='+v]
  mounts=[(self.args.recovery_source,'/source',True),(self.args.operation_root,'/operation',True),(self.args.operation_root,'/fresh-operation',True)]
  if role!='cleanup':mounts +=[(p.runtime.source,'/fresh-source',True),(self.args.fresh_authorization,'/fresh-authorization.json',True),(p.bundle607,'/bundle',True),(p.candidate,'/candidate',True),(p.args.legacy_source,'/installer-code',True)]
  public=self.output/({'install':'install-public','snapshot':'snapshot-public','consumer':'lifecycle-public','cleanup':'cleanup-public','signer':'fixture-public'}[role]);mounts.append((public,'/out',False))
  if role=='signer':
   for path,readonly in((p.runtime.source,True),(self.args.fresh_authorization,True),(self.args.recovery_root,True),(p.bundle607,True),(p.signing_home,False),(p.repair_inputs,False),(self.signing_spec,True),(self.signing_inventory,True)):mounts.append((path,str(canonical(path)),readonly))
  elif role=='consumer':mounts +=[(self.output/'data/source607','/seed',True),(self.output/'consumer-work','/work',False),(self.receipts,'/inputs',False),*[(self.repair_inputs/n,'/inputs/'+n,True)for n in('apps-source','candidate','release')]]
  else:
   mounts +=[(self.output/'work','/work',role=='snapshot'),(self.receipts,'/receipts',False)]
   if role=='snapshot':mounts +=[(self.output/'work/installed607/root','/installed',True),(self.output/'data','/data',False)]
   if role=='cleanup':mounts +=[(self.output/'data','/data',False),(self.output/'consumer-work','/consumer-work',False),(self.output/'authority','/authority',False)]
  for source,target,readonly in mounts:argv+=['--mount','type=bind,src='+str(canonical(source))+',dst='+target+(',readonly'if readonly else '')]
  script='/fresh-operation/producer607.py'if role=='signer'else'/fresh-operation/'+('consumer607.py'if role=='consumer'else'provider607.py');extra=['sign','--spec',str(self.signing_spec),'--spec-sha256',self.signing_spec_pin['sha256']]if role=='signer'else['--run'if role=='consumer'else'--'+role]
  argv+=['--entrypoint=/usr/bin/python3',self.report.get('image',p.image),'-I','-B',script,*extra];return name,argv,public
 def actor(self,role,context_sha=None):
  phase='cleanup'if role=='cleanup-final'else role;name,argv,public=self.actor_plan(phase,context_sha)
  if role=='cleanup-final':
   name+='-final';argv[argv.index('--name')+1]=name;public=self.output/'cleanup-final-public';old='type=bind,src='+str(self.output/'cleanup-public')+',dst=/out';need(argv.count(old)==1,'one bounded final-cleanup output seam');argv[argv.index(old)]='type=bind,src='+str(public)+',dst=/out'
  need(not any(r['role']==role for r in self.report['actors'])and len(self.report['actors'])<8,'finite unique607 actor role');need(self.mods.api.inspect(name,self.command)is None,'fresh607 actor name')
  row=dict(role=role,name=name,id=None,status='RESERVED');self.report['actors'].append(row);self.persist();outcome=None
  try:outcome=self.command(argv,False,ACTOR_SECONDS[phase])
  finally:
   observed=self.mods.api.inspect(name,self.command)
   if observed is not None:row.update(id=self.mods.api.verify_actor(observed,name,self.report['image'],LABEL,self.report['token']),status='EXITED',inspect=observed,exit=None if outcome is None else outcome['code']);self.persist()
  self.mods.api.retire([row],self.report['image'],LABEL,self.report['token'],self.command,self.output,self.report);need(row['status']=='PASS_ABSENCE_VERIFIED'and outcome['code']==0,'actual607 actor successful and absent')
  result=dict(status='ACTOR_EXITED_AND_ABSENCE_VERIFIED',actor=dict(row),public_dir=str(public),work_dir=str(self.output/'work'),data_dir=str(self.output/'data'));self.report.setdefault('phase_receipts',{})[role]=result;self.persist();return result
 def retire_all(self):
  for row in self.report['actors']:
   if row['role']=='tooling'and row['status']!='PASS_ABSENCE_VERIFIED':
    value=self.mods.api.inspect(row['name'],self.command)
    if value is not None and value.get('AppArmorProfile')=='':
     need(value['Id']==row['id']and value['Name']=='/'+row['name']and value['Image']==self.report['base_image']and value['Config']['Labels'].get(LABEL)==self.report['token'],'exact never-started tooling DATA object');need(value['State']['Running']is False and value['State']['Pid']==0 and value['State']['StartedAt'].startswith('0001-')and value['State']['FinishedAt'].startswith('0001-')and value['State']['ExitCode']==0 and value['State']['Error']==''and value['HostConfig']['ReadonlyRootfs']is False,'never-executed tooling DATA only, no running-profile acceptance');need(value['State']['Status']=='created'and all(value['State'][k]is False for k in('Paused','Restarting','OOMKilled','Dead'))and value['RestartCount']==0 and value['HostConfig']['Privileged']is False and value['HostConfig']['CapDrop']==['ALL']and set(value['HostConfig']['CapAdd'])==set(BASE_CAPS)and value['HostConfig']['NetworkMode']=='none'and value['HostConfig']['SecurityOpt']==['no-new-privileges'],'complete never-executed tooling confinement');self.command(['/usr/bin/docker','rm',row['id']]);need(self.mods.api.inspect(row['name'],self.command)is None,'never-started tooling DATA absence');row.update(status='PASS_ABSENCE_VERIFIED',never_started_data_only=True);self.persist()
  if self.report['actors']:self.mods.api.retire(self.report['actors'],self.report['image'],LABEL,self.report['token'],self.command,self.output,self.report)
  need(all(r['status']=='PASS_ABSENCE_VERIFIED'and self.mods.api.inspect(r['name'],self.command)is None for r in self.report['actors']),'fresh all-owned607 actor absence');return dict(status='ALL_OWNED_NATIVE607_ACTORS_ABSENT',**self.identity,all_absent=True,actors=self.report['actors'],roots=self.report['roots'])
 def install607(self,prepared):
  need(prepared is self.prepared,'same actual prepared607 object');self.installed=self.actor('install');return self.installed
 def snapshot607(self,installed):
  need(installed is self.installed and installed['status']=='ACTOR_EXITED_AND_ABSENCE_VERIFIED','same retired607 installer receipt');return self.actor('snapshot')
 def consume607(self,provided):
  need(provided.prepared is self.prepared and pin(read(self.receipts/'native607-context.json'))['sha256']==provided.context_sha256,'actual provider context raw pin');return self.actor('consumer',provided.context_sha256)
 def prepare_repair_inputs(self):
  p=self.prepared;need(p.repair_inputs is not None,'actual staged current607 repair sources');self.repair_inputs=canonical(p.repair_inputs);manifest=decode(read(p.bundle607/'manifest.json'));rows={r['name']:r for r in manifest['packages']};packet=self.mods.packet;joins={}
  for name,old in packet['packages'].items():
   row=rows[name];raw=read(p.bundle607/row['archive'],16*1024**2);prior=self.mods.H.C.checked(self.args.packet,old['files']['a']);need(row['version']==old['version']and pin(raw)==dict(bytes=row['size'],sha256=row['sha256'])and raw==prior,'all four old accepted archive bodies equal actual current Ready607')
   report=p.runtime.checks.package(p.bundle607/row['archive']);need(not report['errors'],'original four candidate package gate');payload={n:r for n,r in report['members'].items()if n not in('.PKGINFO','.BUILDINFO','.MTREE')and r['type']!='5'};joins[name]=dict(version=row['version'],archive=pin(raw),metadata_sha256=pin(encoded(report['metadata']))['sha256'],payload_sha256=pin(encoded(payload))['sha256'],byte_equal_to_original_accepted_pair=True)
  need(set(joins)==set(self.mods.C.VERSIONS)and joins['cachy-asahi-apps']['archive']['sha256']=='319cc1db4738945ad3b146490ea0fabd80f8c8d89d8c41a11750dd0ba5d5b8af','real Apps16 and whole four candidate input join');save(self.output/'repair-candidate-joins.json',dict(status='FOUR_READY607_ARCHIVES_METADATA_PAYLOAD_JOIN_ORIGINAL_ACCEPTED_INPUTS',candidates=joins,same_archive_bytes_imply_identical_metadata_and_payload=True));self.report['repair_inputs']=str(self.repair_inputs);self.persist()
 def sign607(self,provided):
  self.signing_inventory=Path(provided.snapshot['public_dir'])/'source-inventory.json';self.signing_spec,self.signing_spec_pin=self.prepared.signing_spec(self.signing_inventory,self.args.recovery_root,self.report['source_sha']);result=self.actor('signer');need((self.repair_inputs/'release/control.json').is_file(),'real normal signed repair release');self.report['repair_release']=pin(read(self.repair_inputs/'release/control.json'));self.persist();return result
 def cleanup607(self):
  absence=self.retire_all();path=self.output/'authority/native607-absence.json'
  if path.exists():
   prior=decode(read(path));need(all(prior[k]==v for k,v in self.identity.items())and prior['roots']==self.report['roots'],'same owned earlier absence DATA')
  save(path,absence);roles={r['role']for r in self.report['actors']};role='cleanup'if 'cleanup'not in roles else'cleanup-final';need(role not in roles,'two bounded cleanup attempts exhausted; preserve producer');phase=self.actor(role);receipt=decode(read(Path(phase['public_dir'])/'cleanup.json'));need(receipt['status']=='PROVIDER607_WHOLE_OWNED_SOURCE_AND_INSTALL_ROOTS_DISPOSED'and all(receipt[k]==v for k,v in self.identity.items())and receipt['all_actors_absent']is True,'actual fixed607 data disposal receipt')
  for name in('work','data','consumer-work','receipts','authority'):need(not list((self.output/name).iterdir()),'owned607 backing remains after guarded cleanup: '+name)
  self.report['data_cleanup']=receipt;self.persist();return receipt
 def image_inspect(self,name):
  value=self.command(['/usr/bin/docker','image','inspect',name],False,20)
  if value['code']:
   text=(value['out']+value['err']).decode(errors='replace').lower();need(value['code']==1 and name.lower()in text and ('no such image'in text or 'no such object'in text),'unambiguous owned image lookup');return None
  rows=decode(value['out']);need(type(rows)is list and len(rows)==1,'one immutable owned image');return rows[0]
 def tooling607(self,prepared,selection):
  need(prepared is self.prepared and selection['status']=='HELD_NATIVE607_TOOLING_SELECTION_READY'and pin(read(selection['selection']/'vm-contract.json'))==selection['contract_pin'],'whole source-owned native tooling contract');c=selection['contract'];need(c['nonce']==self.identity['token']and c['active_image']==prepared.image,'same original producer image/nonce for tooling')
  need(pin(read(selection['candidate']/'run.py'))==prepared.runner_files['run.py'],'held whole tooling controller before import');controller=load('exact_tooling_controller',selection['candidate']/'run.py');name='caa-apps607-'+self.report['token']+'-tooling';tag='caa-apps607-tooling:'+self.report['token'];need(self.mods.api.inspect(name,self.command)is None and self.image_inspect(tag)is None,'fresh unique tooling container/image tag')
  row=dict(role='tooling',name=name,id=None,status='RESERVED');self.report['actors'].append(row);self.report.update(base_image=prepared.image,base_image_inspect=self.image_inspect(prepared.image),derived_tag=tag,commit_attempted=False);self.persist()
  mounts=[(selection['bundle'],'/inputs'),(selection['installer_code'],'/code'),(selection['installer_code']/'scripts','/runner'),(selection['candidate'],'/candidate'),(selection['tooling_cache'],'/tooling-cache'),(selection['selection'],'/selection')];public=self.output/'tooling-public';argv=controller.container_args(c,'tooling',prepared.image,mounts,public,name);need(argv[:2]==['docker','create']and '--read-only'not in argv and set(v for v in argv if v.startswith('--cap-add='))=={'--cap-add='+v for v in BASE_CAPS}and '--network=none'in argv and '--security-opt=no-new-privileges'in argv,'whole held tooling-only writable overlay confinement');argv[0]='/usr/bin/docker';argv[2:2]=['--label',LABEL+'='+self.report['token']];argv+=['tooling','--contract-sha256',selection['contract_pin']['sha256']]
  created=self.command(argv);cid=created['out'].decode().strip();need(re.fullmatch('[0-9a-f]{64}',cid),'actual reserved tooling CID');row.update(id=cid,status='CREATED_NOT_STARTED');self.persist();result=self.command(['/usr/bin/docker','start','-a',name],False,1900);observed=self.mods.api.inspect(name,self.command);self.mods.api.verify_actor(observed,name,prepared.image,LABEL,self.report['token'],cid);need(observed['State']['Running']is False and observed['State']['Pid']==0 and observed['State']['ExitCode']==0 and result['code']==0,'tooling exited before private image commit')
  receipt=decode(read(public/'tooling.json'));need(receipt['status']=='TOOLING_READY'and receipt['nonce']==c['nonce']and receipt['contract_sha256']==selection['contract_pin']['sha256']and receipt['package_inventory']==c['tooling_inventory'],'original signed tooling verification/union/agent retirement receipt');row.update(status='EXITED',exit=0,inspect=observed);self.report['commit_attempted']=True;self.persist()
  result=self.command(['/usr/bin/docker','commit',name,tag],True,120);derived=result['out'].decode().strip();need(re.fullmatch('sha256:[0-9a-f]{64}',derived)and derived!=prepared.image,'one actual private tooling image');image=self.image_inspect(derived);need(image is not None and image['Id']==derived and image['Config']['Labels'].get(LABEL)==self.report['token']and image['RootFS']['Layers'][:len(self.report['base_image_inspect']['RootFS']['Layers'])]==self.report['base_image_inspect']['RootFS']['Layers'],'owned derived image label and unchanged original rootfs layer prefix');self.report['derived_image']=dict(id=derived,tag=tag,inspect=image,status='OWNED_TOOLING_IMAGE_HELD_UNTIL_CONSUMER_ABSENCE');self.persist()
  self.mods.api.retire([row],prepared.image,LABEL,self.report['token'],self.command,self.output,self.report);self.report['image']=derived;self.persist();return dict(status='TOOLING_READY_PRIVATE_IMAGE_NATIVE_ONLY',image=derived,actor=dict(row),receipt=pin(read(public/'tooling.json')),VM='NOT_RUN')
 def retire_image(self):
  if not self.report.get('commit_attempted'):return dict(status='NOT_CREATED')
  record=self.report.get('derived_image');image=self.image_inspect(self.report['derived_tag'])
  if record is None:
   need(image is not None,'daemon commit terminal state UNKNOWN; preserve producer');record=dict(id=image['Id'],tag=self.report['derived_tag'],inspect=image);self.report['derived_image']=record
  if record.get('status')=='PASS_DERIVED_IMAGE_ABSENCE_VERIFIED':need(image is None and self.image_inspect(record['id'])is None,'earlier private image absence held');return record
  need(image is not None and image['Id']==record['id']and image['Config']['Labels'].get(LABEL)==self.report['token']and record['id']!=self.report['base_image'],'foreign tooling image preserved');self.command(['/usr/bin/docker','image','rm','--no-prune',record['id']]);need(self.image_inspect(record['id'])is None and self.image_inspect(record['tag'])is None,'private tooling image absence');record['status']='PASS_DERIVED_IMAGE_ABSENCE_VERIFIED';self.persist();return record

def new_output(args,who):
 root=canonical(args.owner_output);need(not os.path.lexists(root)and root.parent==Path('/tmp')and shutil.disk_usage(root.parent).free>=40*1024**3,'fresh607 directory and held40GiB margin');need(all(root!=canonical(p)and root not in canonical(p).parents and canonical(p)not in root.parents for p in(args.output,args.operation_root,args.fresh_source,args.packet,args.apps16_pair)),'disjoint607 owner/source/producer');root.mkdir(mode=0o700)
 for name in('work','data','consumer-work','receipts','install-public','snapshot-public','lifecycle-public','cleanup-public','cleanup-final-public','tooling-public','authority','fixture-public','retained'):(root/name).mkdir(mode=0o700)
 return dict(schema_version=1,status='RUNNING_FRESH607_NOT_ACCEPTED',**who,owner_identity=identity(root.stat())[:2],actors=[],commands=[],roots={n:identity((root/n).stat())[:2]for n in('work','data','consumer-work','receipts','authority')},producer_output=str(args.output),hardware='NOT_RUN',Root_acceptance=None,rollback='NOT_CLAIMED',repair_success=False,cleanup='NOT_ESTABLISHED')

def stash(args,report,prepared=None,provided=None):
 """Raw public DATA only, never private signing homes or retained callbacks."""
 root=canonical(args.owner_output);target=root/'retained';files=report.setdefault('retained_files',{});total=sum(p['bytes']for p in files.values())
 def copy(path,name,cap):
  nonlocal total
  need(type(name)is str and name and not name.startswith('/')and all(p not in('','.','..')for p in name.split('/')),'ordinary retained607 role');raw=read(path,cap);want=pin(raw)
  if name in files:need(files[name]==want and pin(read(target/name,cap))==want,'immutable raw607 role');return
  need(total+len(raw)<=MAX_PUBLIC,'held192MiB607 public cap');out=target/name;out.parent.mkdir(parents=True,exist_ok=True);fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
  files[name]=want;total+=len(raw)
 for role in('install-public','snapshot-public','lifecycle-public','cleanup-public','cleanup-final-public','tooling-public'):
  for path in sorted((root/role).iterdir()):copy(path,role+'/'+path.name,64*1024**2 if path.name.endswith('.gz')else 16*1024**2)
 for i,row in enumerate(report['commands']):
  for side in('stdout','stderr'):
   name='command-%03d.%s'%(i,side);copy(root/name,'runtime/'+name,1024**2);need(files['runtime/'+name]==dict(bytes=row[side+'_bytes'],sha256=row[side+'_sha256']),'complete original607 transcript joins')
 for relative in('repair-candidate-joins.json','tooling-selection.json','tooling-selection/vm-contract.json'):
  if(root/relative).exists():copy(root/relative,relative,16*1024**2)
 if prepared is not None:
  for name,path in prepared.public_files().items():
   if name.startswith('repair-inputs/')and not name.startswith(('repair-inputs/apps-source/','repair-inputs/candidate/','repair-inputs/release/'))and name!='repair-inputs/fixture-specification-derivation.json':continue
   need(not any(p in('test-signing','authority','private-keys-v1.d','openpgp-revocs.d')for p in Path(name).parts),'no signing secrets in607 export');copy(path,'producer/'+name,16*1024**2)
 copy(args.operation_root/'profile.json','source/operation-profile.json',4*1024**2);copy(args.fresh_authorization,'source/fresh1197-authorization.json',4*1024**2);report['retained_bytes']=total;save(root/'owner.json',report)
 return dict(status='RAW607_PUBLIC_DATA_STASHED_NOT_ACCEPTANCE',files=files,bytes=total,Root_acceptance=None)
def cleanup_chain(args,mods,runtime,prepared=None,provided=None):
 report=runtime.report;runtime.deadline=time.monotonic()+CLEANUP_SECONDS
 with budget(CLEANUP_SECONDS):
  report['actor_absence']=runtime.retire_all();runtime.persist()
  if report['actors']:
   if 'data_cleanup'not in report:runtime.cleanup607()
   else:
    for name in('work','data','consumer-work','receipts','authority'):need(not list((runtime.output/name).iterdir()),'earlier607 backing cleanup remains empty')
  else:need(all(not list((runtime.output/n).iterdir())for n in('work','data','consumer-work','receipts','authority')),'anonymous607 private backing preserved')
  stash(args,report,prepared,provided);report['derived_cleanup']=runtime.retire_image()
  if type(report.get('producer_cleanup'))is dict and report['producer_cleanup'].get('status')=='PASS_FRESH607_PRODUCER_BACKING_ABSENCE':
   need(not any(p.exists()for p in(args.output/'ready604',args.output/'candidate',args.output.with_name(args.output.name+'-producer')/'private')),'prior producer backing remains absent');prepared=None
  elif prepared is None and Path(args.output/'owner.json').is_file():prepared=mods.producer.resume(args)
  if prepared is not None:
   closed=prepared.close();need(closed['status']=='PASS_FRESH607_PRODUCER_BACKING_ABSENCE'and closed['bundle_absent']and closed['candidate_absent'],'original607 producer absence');report['producer_cleanup']=closed
  elif 'producer_cleanup'not in report:report['producer_cleanup']='NOT_STARTED'
  report['cleanup']='PASS_ACTORS_SOURCE_COPIES_RECEIPTS_AUTHORITY_THEN_PRODUCER';runtime.persist()
 return report

def execute(args):
 started=time.monotonic();report=runtime=mods=prepared=provided=None
 with contextlib.ExitStack()as custody:
  try:
   with budget(RUN_SECONDS):
    mods=modules(args);who=current_identity(args);native_guard();report=new_output(args,who);runtime=Runtime(args,mods,report);runtime.deadline=started+RUN_SECONDS;args.runtime=runtime;custody.enter_context(lease(runtime.output,True));runtime.persist()
    prepared=mods.producer.prepare(args);runtime.set_prepared(prepared);runtime.prepare_repair_inputs();provided=mods.provider.prepare(args,prepared);runtime.sign607(provided);consumer=mods.consumer.run(args,provided);report['consumer']=consumer;need(consumer['status']=='NATIVE607_RECOVERY_CONSUMER_RETIRED_RETAINED_VALIDATED'and consumer['repair_success']is True,'actual607 consumer, never provisioning inference');stash(args,report,prepared,provided);report.update(status='PASS_FRESH607_NATIVE_RECOVERY_PENDING_ORDERED_CLEANUP',repair_success=True)
  except BaseException as error:
   if report is None:raise
   if prepared is None:prepared=getattr(error,'prepared',None)
   report.update(status='FAIL_FRESH607_RECOVERY_UNKNOWN',error_type=type(error).__name__,error=str(error)[:1024],repair_success=False)
  finally:
   if runtime is not None:
    try:cleanup_chain(args,mods,runtime,prepared,provided)
    except BaseException as error:report.update(cleanup='UNKNOWN_PRESERVE_PRODUCER_AND_AUTHORITY',cleanup_error_type=type(error).__name__,cleanup_error=str(error)[:1024])
    runtime.persist()
 return report

def existing_report(args,who):
 root=canonical(args.owner_output);need(root.is_dir()and root.stat().st_uid==os.getuid()and stat.S_IMODE(root.stat().st_mode)==0o700,'ordinary owned607 report root');report=decode(read(root/'owner.json',4*1024**2));need(all(report[k]==v for k,v in who.items())and report['owner_identity']==identity(root.stat())[:2]and report['producer_output']==str(args.output),'exact persisted607 source/run/token/root')
 need(set(report['roots'])=={'work','data','consumer-work','receipts','authority'}and all(identity((root/n).stat())[:2]==v for n,v in report['roots'].items()),'original five owned607 bind roots');return report

def cleanup(args):
 mods=modules(args,cleanup=True);who=current_identity(args);native_guard();report=existing_report(args,who)
 with lease(args.owner_output,False):
  runtime=Runtime(args,mods,report);runtime.deadline=time.monotonic()+CLEANUP_SECONDS;args.runtime=runtime
  if report['actors']:need(re.fullmatch('sha256:[0-9a-f]{64}',report['image']),'exact persisted image');runtime.prepared=types.SimpleNamespace(image=report['image'])
  try:cleanup_chain(args,mods,runtime)
  except BaseException as error:report.update(cleanup='UNKNOWN_PRESERVE_PRODUCER_AND_AUTHORITY',cleanup_error_type=type(error).__name__,cleanup_error=str(error)[:1024]);runtime.persist()
 return report

def publish(args):
 source_gate(args);who=current_identity(args);need(args.handoff is not None,'complete outer607 physical handoff required');S=load('retained_outer_supervisor',args.recovery_source/'scripts/ci/orphans-full574-native/supervise.py');S.check(canonical(args.handoff),who);handoff_raw=read(args.handoff,16384);report=existing_report(args,who);root=canonical(args.owner_output);target=canonical(args.public);need(not os.path.lexists(target)and target!=root and root not in target.parents and target not in root.parents,'fresh disjoint607 public export');target.mkdir(mode=0o700);files={};total=0
 for name,want in report.get('retained_files',{}).items():
  need(name and not name.startswith('/')and all(p not in('','.','..')for p in name.split('/')),'safe raw607 retention member');raw=read(root/'retained'/name,64*1024**2);need(pin(raw)==want and total+len(raw)<=MAX_PUBLIC,'complete192MiB607 retained raw body');path=target/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);files[name]=want;total+=len(raw)
 need(total+len(handoff_raw)<=MAX_PUBLIC,'bounded final outer607 handoff');(target/'outer-handoff.json').write_bytes(handoff_raw);files['outer-handoff.json']=pin(handoff_raw);total+=len(handoff_raw)
 raw=read(root/'owner.json',4*1024**2);need(total+len(raw)<=MAX_PUBLIC,'final607 owner export cap');(target/'owner.json').write_bytes(raw);files['owner.json']=pin(raw);total+=len(raw)
 result=dict(schema_version=1,status='RETAINED_FRESH607_RECOVERY_DATA_NOT_ROOT_ACCEPTANCE',files=files,bytes=total,source=who,repair_success=report['repair_success']and report['cleanup']=='PASS_ACTORS_SOURCE_COPIES_RECEIPTS_AUTHORITY_THEN_PRODUCER',cleanup=report['cleanup'],Root_acceptance=None,hardware='NOT_RUN',rollback='NOT_CLAIMED');need(total+len(encoded(result))<=MAX_PUBLIC,'retention index included in192MiB cap');save(target/'retention.json',result);return result

PATH_ARGS=('source','legacy-source','preparation-source','product','updater','desktop','updater-v2-source','native','fdk','cache','setup4-pair','fresh-source','fresh-authorization','six-record','six-public','tooling-inputs','implementation','eight-source','seven-source','management-source','setup-source','welcome-source','apps6-source','apps6-authority-source','fresh600-decisions','native604-decisions','audio-inputs','output','owner-output','operation-root','recovery-root','packet','apps16-pair')
def parser():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('run','cleanup','retain','supervised-run','supervised-cleanup'))
 for name in PATH_ARGS:p.add_argument('--'+name,type=Path,required=True)
 for name in('fresh-source-revision','implementation-revision','operation-profile-sha256'):p.add_argument('--'+name,required=True)
 p.add_argument('--installer604-source',type=Path);p.add_argument('--handoff',type=Path);p.add_argument('--job-outcome',choices=('success','failure','cancelled','skipped'));p.add_argument('--public',type=Path);return p

def main(argv=None):
 argv=list(sys.argv[1:]if argv is None else argv);args=parser().parse_args(argv)
 for name in PATH_ARGS:setattr(args,name.replace('-','_'),canonical(getattr(args,name.replace('-','_'))))
 if args.installer604_source is not None:need(args.installer604_source==args.implementation,'same qualified274 installer source')
 if args.mode.startswith('supervised-'):
  source_gate(args);who=current_identity(args);native_guard();need(args.handoff is not None,'explicit owned607 outer handoff');handoff=canonical(args.handoff);need(handoff.name=='apps607-handoff-'+who['token']+'.json','exact607 handoff role');S=load('held_supervisor',args.recovery_source/'scripts/ci/orphans-full574-native/supervise.py')
  if args.mode=='supervised-run':
   command=[sys.executable,'-I','-B',str(Path(__file__).resolve()),'run',*argv[1:]];result=S.handoff(command,handoff,who);print(encoded(result).decode(),end='');return 128+result['cancellation_signal']if result['cancellation_signal']is not None else result['exit_code']if result['exit_code']>=0 else 128-result['exit_code']
  need(args.job_outcome is not None,'actual workflow outcome before607 cleanup');S.check(handoff,who,args.job_outcome=='skipped');args.mode='cleanup'
 result=execute(args)if args.mode=='run'else cleanup(args)if args.mode=='cleanup'else publish(args);print(encoded(dict(status=result['status'],cleanup=result.get('cleanup'),Root_acceptance=None)).decode(),end='');return int(not(result.get('cleanup')=='PASS_ACTORS_SOURCE_COPIES_RECEIPTS_AUTHORITY_THEN_PRODUCER'and result.get('status')=='PASS_FRESH607_NATIVE_RECOVERY_PENDING_ORDERED_CLEANUP'and result.get('repair_success')is True))if args.mode=='run'else int(result.get('cleanup')!='PASS_ACTORS_SOURCE_COPIES_RECEIPTS_AUTHORITY_THEN_PRODUCER')if args.mode=='cleanup'else 0
if __name__=='__main__':raise SystemExit(main())
