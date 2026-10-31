#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CI-only owned AppArmor lifetime; trial mounts only, unchanged other limits."""
from contextlib import contextmanager
import fcntl,hashlib,json,os,platform,re,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
REVISION='4b8214fc4971e06172938a1f1554ccff6647ee80'
PINS={'apparmor/template.go':dict(bytes=6196,sha256='7da15d81aa5c507f5002b844fdc49a969904681447a2cc29222bd6cbe797163b'),'apparmor/apparmor.go':dict(bytes=4974,sha256='7bf6c04caeedb59df89e8de2b3fa335c73477b34efa2f0af3a0ad22484e3cb21'),'LICENSE':dict(bytes=11358,sha256='cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30')}
LANES={'lifecycle':('caa-glibc-provider-','org.cachy-asahi.glibc-gnu-provider-lifecycle','org.cachy-asahi.glibc-provider-lifecycle-owner'),'interruption':('caa-glibc-interruption-','org.cachy-asahi.glibc-gnu-provider-interruption','org.cachy-asahi.glibc-provider-interruption-owner')}
MOUNTS='''  # Exact GNU trial mounts; every other mount remains implicitly denied.
  mount fstype=proc options=(ro,nosuid,nodev,noexec) proc -> /work/.gnu-readonly-proc-probe/,
  mount fstype=proc options=(ro,nosuid,nodev,noexec) proc -> /work/pristine/root/proc/,
  mount fstype=proc options=(ro,nosuid,nodev,noexec) proc -> /work/modified/root/proc/,
  mount options=(bind) /dev/null -> /work/pristine/root/dev/null,
  mount options=(bind) /dev/null -> /work/modified/root/dev/null,
'''
REGISTRY=Path('/sys/kernel/security/apparmor/profiles');PARSER=Path('/usr/sbin/apparmor_parser')
def need(ok,message):
 if not ok:raise ValueError(message)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(path,cap=128*1024):
 path=Path(path);need(not any(p.is_symlink() for p in (path,*path.parents)),'ordinary owned AppArmor input');s=path.stat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size<=cap,'bounded single-link AppArmor input');raw=path.read_bytes();after=path.stat();need((s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'AppArmor input changed');return raw
def decode(raw):
 def pairs(rows):
  value={}
  for k,v in rows:need(k not in value,'duplicate profile JSON key');value[k]=v
  return value
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite profile JSON'))
def save(path,value):
 raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode();need(len(raw)<=128*1024,'AppArmor receipt bound');temporary=path.with_name(path.name+'.partial');fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:need(os.write(fd,raw)==len(raw),'complete profile receipt write');os.fsync(fd)
 finally:os.close(fd)
 temporary.replace(path)
def profile_name(token,lane):
 need(lane in LANES and re.fullmatch('[0-9a-f]{32}',token or ''),'finite lane and exact consumer token');return 'caa-gnu-'+lane+'-'+token

def template():
 for n,row in PINS.items():need(pin(read(HERE/'vendor'/n,32768))==row,'pinned Moby source/license changed: '+n)
 source=decode(read(HERE/'vendor/source.json'));need(source['revision']==REVISION and source['license']=='Apache-2.0','pinned upstream revision/license')
 raw=read(HERE/'vendor/apparmor/template.go').decode();start=raw.index('const baseTemplate = `')+len('const baseTemplate = `');end=raw.index('`',start);value=raw[start:end];need(value.count('  deny mount,\n')==1,'one inherited blanket mount deny');return value

def render(token,lane,*,abi,global_include,base_include,daemon_profile):
 name=profile_name(token,lane);need(daemon_profile=='unconfined' or re.fullmatch('[A-Za-z0-9_.:/-]{1,200}',daemon_profile),'finite literal daemon peer');raw=template()
 # Exact finite Go-template expansion, matching pinned generate() host choices.
 replacements=(('{{if .Abi}}abi <{{.Abi}}>,\n{{- end}}','abi <abi/3.0>,' if abi else ''),('{{range $value := .Imports}}\n{{$value}}\n{{- end}}','\n'+('#include <tunables/global>' if global_include else '@{PROC}=/proc/')),('{{- range $value := .InnerImports}}\n  {{$value}}\n{{- end}}{{if .InnerImports}}\n{{end}}','\n  #include <abstractions/base>\n' if base_include else ''),('{{.Name}}','"'+name+'"'),('{{.PeerName}}','"'+name+'"'),('{{.DaemonProfile}}','unconfined' if daemon_profile=='unconfined' else '"'+daemon_profile+'"'))
 for before,after in replacements:
  count=2 if before=='{{.PeerName}}' else 1;need(raw.count(before)==count,'exact inherited template expansion anchor');raw=raw.replace(before,after)
 need('{{' not in raw and '}}' not in raw,'unexpanded Moby template');baseline=raw;raw=raw.replace('  deny mount,\n',MOUNTS);need(raw.replace(MOUNTS,'  deny mount,\n')==baseline,'only mount-policy delta allowed');return raw.encode(),baseline.encode()

def registry(command):
 raw=observe(command,REGISTRY,private=True)
 need(len(raw)<=1024**2,'kernel profile registry bound');value={}
 for line in raw.decode('utf8','strict').splitlines():
  m=re.fullmatch(r'(.{1,512}) \((enforce|complain|kill|unconfined)\)',line);need(m is not None and m[1] not in value,'finite unambiguous kernel profile registry');value[m[1]]=m[2]
 return value

def snapshot_profiles(value,name):return dict(target_mode=value.get(name),docker_default=value.get('docker-default'),profiles=len(value),registry_sha256=pin(json.dumps(value,sort_keys=True).encode())['sha256'])
def ci_gate():
 need(os.environ.get('GITHUB_ACTIONS')=='true' and platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0 and os.getgid()==os.getegid() and not any(k.startswith(('DOCKER_','LD_')) for k in os.environ),'ordinary native local CI-only profile lifetime')
 parser=PARSER.resolve(strict=True);s=parser.stat();need(parser.parent==Path('/usr/sbin') and stat.S_ISREG(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'trusted existing root-owned system parser');return parser

def observe(command,path,private=False):
 value=str(path);need(value==str(REGISTRY) and private or re.fullmatch(r'/proc/[1-9][0-9]{0,9}/attr/current',value) and not private,'only exact authorized CI LSM observer paths')
 kwargs=dict(seconds=10)
 if private:kwargs['private_stdout']=True
 row=command(['/usr/bin/sudo','-n','--','/usr/bin/cat','--',value],**kwargs);raw=row['out'];need(len(raw)<=(1024**2 if private else 512),'bounded CI LSM observation');return raw

def host_facts(command):
 current=command(['/usr/bin/docker','context','show']);need(current['out'].strip()==b'default','local default Docker context');row=command(['/usr/bin/docker','context','inspect','default']);need(decode(row['out'])[0]['Endpoints']['docker']['Host']=='unix:///var/run/docker.sock','local Unix daemon only')
 # Read the actual dockerd peer context; do not assume the caller is the daemon.
 pidfile=Path('/run/docker.pid').resolve(strict=True);s=pidfile.stat();need(s.st_uid==0 and stat.S_ISREG(s.st_mode) and not s.st_mode&0o022 and s.st_size<=32,'root-owned bounded existing Docker PID file');pid=pidfile.read_bytes();need(re.fullmatch(b'[1-9][0-9]{0,9}\n?',pid),'finite Docker PID');pid=pid.decode().strip();proc=Path('/proc')/pid
 service=command(['/usr/bin/systemctl','show','--property=MainPID','--value','docker.service']);need(service['out'].strip()==pid.encode(),'root-owned PID matches Docker service MainPID');before=(proc/'stat').read_bytes();need(len(before)<=4096 and proc.stat().st_uid==0 and (proc/'comm').read_bytes()==b'dockerd\n','PID identifies root dockerd')
 with (proc/'cmdline').open('rb') as f:argv=f.read(4096)
 executable=argv.split(b'\0',1)[0].decode('ascii');need(executable in ('/usr/bin/dockerd','/usr/sbin/dockerd'),'expected Docker daemon executable');es=Path(executable).stat();need(es.st_uid==0 and stat.S_ISREG(es.st_mode) and not es.st_mode&0o022,'root-owned actual daemon executable')
 context=observe(command,proc/'attr/current').decode().strip();daemon=context.removesuffix(' (enforce)');need(context=='unconfined' or context==daemon+' (enforce)','known actual daemon confinement');after=(proc/'stat').read_bytes();start=before.split(b') ',1)[1].split()[19];need(len(after)<=4096 and after.split(b') ',1)[1].split()[19]==start,'Docker PID incarnation changed')
 service_after=command(['/usr/bin/systemctl','show','--property=MainPID','--value','docker.service']);need(service_after['out'].strip()==pid.encode(),'Docker service PID changed');namespaces={}
 for n in ('mnt','pid','user'):
  try:namespaces[n]=os.readlink(proc/'ns'/n)
  except OSError as error:namespaces[n]=dict(available=False,errno=error.errno)

 macros={}
 for n in ('abi/3.0','tunables/global','abstractions/base'):
  p=Path('/etc/apparmor.d')/n
  if p.exists():
   p=p.resolve(strict=True);s=p.stat();need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022 and s.st_size<=1024**2,'trusted bounded host AppArmor import');macros[n]=pin(p.read_bytes())
 return dict(daemon_profile=daemon,daemon_pid=int(pid),daemon_executable=executable,daemon_starttime=start.decode(),namespaces=namespaces,macros=macros)

def inspected(command,name):
 row=command(['/usr/bin/docker','container','inspect',name]);values=decode(row['out']);need(len(values)==1,'single Docker identity');return values[0]
def producer_default(command,state):
 # Producer's successful --rm probe is already gone; never invent live readback.
 row=command(['/usr/bin/docker','image','inspect',state['image']]);values=decode(row['out']);need(len(values)==1,'single original producer image');value=values[0]
 need(value['Id']==state['image'] and value['Architecture']=='arm64' and value['Os']=='linux' and value['Config']['Labels'].get('org.cachy-asahi.bootstrap574.job')==state['producer_token'],'producer exact fresh image identity preserved')
 for query in ('name=^/'+state['producer_probe']['name']+'$','id='+state['producer_probe']['id']):
  row=command(['/usr/bin/docker','container','ls','--all','--quiet','--no-trunc','--filter',query]);need(not row['out'].strip(),'original auto-removed producer probe must remain absent')
 return dict(status='PASS_ORIGINAL_FRESH_IMAGE_AND_COMPLETED_AUTO_REMOVED_PROBE_ABSENCE',image=value['Id'],probe=state['producer_probe'],live_producer_profile_readback='UNAVAILABLE_PROBE_ALREADY_AUTO_REMOVED')

def no_users(command,state):
 # No owned consumer may survive; no foreign profile user may be deconfined.
 for label in LANES[state['lane']][1:]:
  row=command(['/usr/bin/docker','container','ls','--all','--quiet','--no-trunc','--filter','label='+label+'='+state['token']]);need(not row['out'].strip(),'owned consumers remain; retain profile')
 row=command(['/usr/bin/docker','container','ls','--all','--quiet','--no-trunc']);ids=row['out'].decode().splitlines();need(len(ids)<=32 and len(set(ids))==len(ids) and all(re.fullmatch('[0-9a-f]{64}',x) for x in ids),'bounded exact all-container inventory')
 for cid in ids:
  row=command(['/usr/bin/docker','container','inspect','--format','{{json .AppArmorProfile}}',cid]);need(decode(row['out'])!=state['name'],'remaining/foreign profile user; retain profile')
 return dict(status='PASS_ALL_OWNED_CONSUMERS_AND_PROFILE_USERS_ABSENT',inspected_containers=len(ids))

@contextmanager
def lease(directory):
 fd=os.open(directory/'lease',os.O_RDWR|os.O_CLOEXEC|os.O_NOFOLLOW)
 try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);yield
 finally:os.close(fd)

def validate(directory,token,lane,image,*,loaded=True):
 need(directory.is_absolute() and not any(p.is_symlink() for p in (directory,*directory.parents)),'ordinary explicit AppArmor owner directory');s=directory.stat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==os.geteuid() and stat.S_IMODE(s.st_mode)==0o700,'private caller-owned AppArmor directory');state=decode(read(directory/'state.json'));need(state['schema_version']==1 and state['token']==token and state['lane']==lane and state['name']==profile_name(token,lane) and state['image']==image and state['source_revision']==REVISION,'owned profile registration binding');need(pin(read(directory/'trial.profile',65536))==state['profile'],'owned profile bytes changed')
 if loaded:need(state['status']=='LOADED_ENFORCE','known owned loaded enforce profile required')
 return state

def load(directory,proof,base,lane,command,producer_cid):
 parser=ci_gate();token=proof['consumer_token'];name=profile_name(token,lane);need(not directory.exists() and directory.is_absolute() and not any(p.is_symlink() for p in (directory,*directory.parents)),'fresh ordinary profile registration');need(re.fullmatch('[0-9a-f]{40}',proof['source_sha']) and re.fullmatch('sha256:[0-9a-f]{64}',base['image']) and proof['producer_token']==base['ownership']['token'],'source/proof/producer profile binding')
 need(re.fullmatch('[0-9a-f]{64}',producer_cid) and base['ownership']['image']==base['image'] and base['image'] not in base['ownership']['before_images'] and base['ownership']['probe_started'] is True and base['ownership']['probe_complete'] is True,'actual fresh completed original producer ownership')
 before=registry(command);need(name not in before and before.get('docker-default')=='enforce','fresh profile name and enforcing original Docker default');facts=host_facts(command);raw,baseline=render(token,lane,abi='abi/3.0' in facts['macros'],global_include='tunables/global' in facts['macros'],base_include='abstractions/base' in facts['macros'],daemon_profile=facts['daemon_profile']);directory.mkdir(mode=0o700);fd=os.open(directory/'lease',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
 state=dict(schema_version=1,status='RESERVED_NOT_LOADED',add_attempted=False,token=token,lane=lane,name=name,image=base['image'],producer_token=proof['producer_token'],source_sha=proof['source_sha'],source_revision=REVISION,profile=pin(raw),baseline=pin(baseline),host=facts,before=snapshot_profiles(before,name),producer_probe=dict(name=base['ownership']['probe_name'],id=producer_cid),hardware='NOT_RUN',native_counterfactual='NOT_RUN',policy_delta='EXACT3_READONLY_PROC_FLAGS15_PLUS2_DEV_NULL_BINDS_ONLY')
 fd=os.open(directory/'trial.profile',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
 try:need(os.write(fd,raw)==len(raw),'complete private profile write');os.fsync(fd)
 finally:os.close(fd)
 with lease(directory):
  save(directory/'state.json',state)
  try:
   state['producer_before']=producer_default(command,state);state['users_before']=no_users(command,state);save(directory/'state.json',state)
   command([str(parser),'--skip-kernel-load','--skip-cache','--jobs=1',str(directory/'trial.profile')],seconds=30)
   # --add rejects collisions atomically; never replace docker-default or any name.
   state['status']='ADD_ATTEMPTED_OUTCOME_UNCONFIRMED';state['add_attempted']=True;save(directory/'state.json',state)
   command(['/usr/bin/sudo','-n','--',str(parser),'--add','--skip-cache','--jobs=1',str(directory/'trial.profile')],seconds=30)
   after=registry(command);need(after==dict(before,**{name:'enforce'}),'exact enforcing profile addition and default registry preserved');state.update(status='LOADED_ENFORCE',after_load=snapshot_profiles(after,name));save(directory/'state.json',state)
  except BaseException as error:
   state.update(status='FAIL_RETAIN_PROFILE_OUTCOME_UNCERTAIN' if state['add_attempted'] else 'FAIL_BEFORE_ADD_NO_PROFILE_OWNERSHIP',error_type=type(error).__name__,error=str(error)[:512]);save(directory/'state.json',state);raise
 return state

def binding(directory,token,lane,image):return validate(directory,token,lane,image)
def docker_profile(value,token,lane,role):
 need(role in ('trial','scrub'),'finite inner profile role');expected=profile_name(token,lane) if role=='trial' else 'docker-default';need(value['AppArmorProfile']==expected,'actual Docker AppArmor profile differs');options=value['HostConfig']['SecurityOpt'];need('no-new-privileges' in options and not any(x.startswith('seccomp=') for x in options),'inherited NNP/default seccomp unchanged')
 if role=='trial':need('apparmor='+expected in options,'explicit trial custom profile request')
 else:need(not any(x.startswith('apparmor=') and x!='apparmor=docker-default' for x in options),'scrub retains Docker default')
 return dict(status='PASS_DOCKER_INSPECT_EXACT_PROFILE',AppArmorProfile=expected,SecurityOpt=options)
def inside(token,lane):
 name=profile_name(token,lane);need(os.environ.get('GNU_TRIAL_APPARMOR_PROFILE')==name,'explicit owned expected trial profile');raw=Path('/proc/self/attr/current').read_bytes();need(len(raw)<=512 and raw.decode().strip()==name+' (enforce)','inside exact owned AppArmor enforce profile');return dict(status='PASS_INSIDE_OWNED_TRIAL_APPARMOR_ENFORCE',name=name,context=raw.decode().strip(),bytes=len(raw),sha256=pin(raw)['sha256'])

def unload(directory,proof,base,lane,command):
 parser=ci_gate()
 with lease(directory):
  state=validate(directory,proof['consumer_token'],lane,base['image'],loaded=False);need(state['source_sha']==proof['source_sha'] and state['producer_token']==proof['producer_token'],'cleanup original source/producer binding')
  try:
   before=registry(command);need(before.get('docker-default')=='enforce','producer/default protection must remain enforcing');state['users_before_remove']=no_users(command,state)
   if state['status']=='PASS_OWNED_PROFILE_REMOVED_AFTER_ALL_CONSUMERS' or not state.get('add_attempted',True):
    need(state['name'] not in before,'existing/unowned profile must not be unloaded');state['status']='PASS_OWNED_PROFILE_REMOVED_AFTER_ALL_CONSUMERS' if state.get('add_attempted') else 'PASS_NEVER_ADDED_PROFILE_ABSENT';save(directory/'state.json',state);return state
   need(state['status']=='LOADED_ENFORCE' and before.get(state['name'])=='enforce','uncertain/unowned load preserved; no removal')
   state['producer_before_remove']=producer_default(command,state);save(directory/'state.json',state)
   command(['/usr/bin/sudo','-n','--',str(parser),'--remove','--skip-cache','--jobs=1',str(directory/'trial.profile')],seconds=30)
   after=registry(command);expected=dict(before);del expected[state['name']];need(after==expected,'exact owned profile removal/default registry preserved');state.update(status='PASS_OWNED_PROFILE_REMOVED_AFTER_ALL_CONSUMERS',after_remove=snapshot_profiles(after,state['name']));save(directory/'state.json',state)
  except BaseException as error:
   state.update(status='FAIL_RETAIN_PROFILE_OR_REMOVAL_UNCERTAIN',cleanup_error_type=type(error).__name__,cleanup_error=str(error)[:512]);save(directory/'state.json',state);raise
 return state


def unregistered_absent(token,lane,command):
 ci_gate()
 need(profile_name(token,lane) not in registry(command),'profile without owned registration preserved; cleanup fails')
 return dict(status='PASS_PROFILE_NOT_REGISTERED_AND_ABSENT',name=profile_name(token,lane))
