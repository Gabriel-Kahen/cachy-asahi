# SPDX-License-Identifier: MIT
"""Exact role setup inside a nonce-owned ARM guest namespace, never on the host."""
import argparse,ctypes as C,hashlib,json,os,re,stat,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import guest_seccomp as SC
BASE=Path('/kit77');SOURCE=BASE/'source';LANE='scripts/ci/offline-kit-accepted-native'
ROLES={'produce':('/feature','/trial-code','/accepted','/trial'),'receive':('/trial-code','/media','/trusted','/result'),'candidate':('/trial-code','/source','/inputs','/builder-packages.lock','/media','/out')}
FORBIDDEN=('/producer','/trial','/build-one','/build-two','/feature','/recipe','/signing','/accepted')

def need(v,why):
 if not v:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def read(path,cap=16*1024**2):
 path=Path(path);need(path.is_absolute()and '..'not in path.parts and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary fixed file');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded input');raw=b''
  while part:=os.read(fd,65536):raw+=part;need(len(raw)<=a.st_size,'stable size')
  key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  need(len(raw)==a.st_size and key(a)==key(os.fstat(fd))==key(path.lstat()),'stable complete input');return raw
 finally:os.close(fd)
def status():
 rows=dict(x.split(':',1)for x in Path('/proc/self/status').read_text().splitlines()if ':'in x)
 return dict(caps={k:rows[k].strip()for k in('CapInh','CapPrm','CapEff','CapBnd','CapAmb')},nnp=rows['NoNewPrivs'].strip(),seccomp=rows['Seccomp'].strip(),filters=rows.get('Seccomp_filters','').strip())

def mount_rows(tool,phase):
 work='/kit77/work/'+tool;code='/kit77/source/'+LANE;trial_code=code+'/guest-vm/fresh-test/trial-code'
 rows={'produce':[(code+'/feature','/feature'),(trial_code,'/trial-code'),('/kit77/work/accepted-carrier','/accepted'),(work+'/trial','/trial')],
 'receive':[(trial_code,'/trial-code'),(work+'/trial/public/transport','/media'),(work+'/trial/public/trust','/trusted'),(work+'/receiver','/result')],
 'candidate':[(trial_code,'/trial-code'),(code+'/candidate-source','/source'),(work+'/candidate-inputs','/inputs'),(code+'/expected-packages.lock','/builder-packages.lock'),(work+'/trial/public/transport','/media'),(work+'/candidate-output','/out')]}
 need(tool in('maintenance','diagnostics')and phase in ROLES,'finite phase')
 return [dict(source=s,target=t,rw=i==len(rows[phase])-1,type='file'if t=='/builder-packages.lock'else'directory')for i,(s,t)in enumerate(rows[phase])]

def descriptor(v):
 keys={'schema_version','identity','nonce','image_origin','tool','phase','source_map_sha256','kernel_release','mounts','env','argv','seconds','receipt_path','cgroup_path'}
 need(type(v)is dict and set(v)==keys and type(v['schema_version'])is int and v['schema_version']==1,'closed descriptor');need(v['tool']in('maintenance','diagnostics')and v['phase']in ROLES and type(v['nonce'])is str and re.fullmatch('[a-f0-9]{32}',v['nonce']),'finite phase/nonce')
 need(v['argv']==['/usr/bin/python','-I','-B','/trial-code/trial.py',v['phase']]and type(v['seconds'])is int and v['seconds']==(1500 if v['phase']=='candidate'else 300),'original argv/budget')
 need(v['mounts']==mount_rows(v['tool'],v['phase'])and all(type(x['rw'])is bool for x in v['mounts']),'exact fixed role paths/write flags')
 need(v['cgroup_path']=='/sys/fs/cgroup/kit77-'+v['nonce']+'/'+v['tool']+'-'+v['phase'],'fixed owned cgroup')
 need(v['receipt_path']=='/kit77/work/vm/phases/'+v['tool']+'-'+v['phase']+'-boundary.json','fixed witness path')
 need(type(v['env'])is dict and all(type(k)is str and type(x)is str and '\x00'not in k+x for k,x in v['env'].items()),'literal clean environment');return v

def actual_guard(selection):
 need(os.getpid()==1 and os.getppid()==0 and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64'and os.sysconf('SC_PAGE_SIZE')==16384,'phase PID1 in native owned guest')
 need(not os.path.lexists('/.dockerenv')and os.uname().release==selection['kernel']['profile']['release'],'exact kernel/no container marker');words=Path('/proc/cmdline').read_text().split()
 need(all([w for w in words if w.startswith(k+'=')]==[k+'='+selection['nonce']]for k in('kit77_vm','caa_core_vm')),'owned unique kernel nonce');need(not any(x in words for x in('apparmor=0','selinux=0','enforcing=0','security=none','lsm=none')),'no LSM-disable route')
 need({p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'private network')
def mount(lib,source,target,flags,fs=None,data=None):
 enc=lambda x:x.encode()if isinstance(x,str)else x
 need(lib.mount(enc(source),str(target).encode(),enc(fs),C.c_ulong(flags),enc(data))==0,'owned guest mount')

def environment(identity,tool,phase,selection_raw=None,profile_sha=None):
 v=dict(PATH='/usr/bin:/bin',HOME='/tmp/kit-home',LANG='C.UTF-8',LC_ALL='C.UTF-8',TZ='UTC',PYTHONDONTWRITEBYTECODE='1',FEATURE_CODE_SHA=identity['feature_code_sha'],CONTEXT_SOURCE_SHA=identity['source_sha'],ACCEPTED_TOOL=tool)
 if phase=='produce':
  need(type(profile_sha)is str and re.fullmatch('[a-f0-9]{64}',profile_sha),'exact fresh TEST profile pin');v['FRESH_TEST_PROFILE_SHA256']=profile_sha
 if phase=='candidate':
  need(type(selection_raw)is bytes,'original selection bytes');s=SC.decode(selection_raw);v.update(CACHY_ASAHI_INSTALL_NONCE=s['nonce'],CACHY_ASAHI_INSTALL_IMAGE=s['image_id'],CANDIDATE_SELECTION_SHA=sha(selection_raw))
 return v

def effective_mounts(opened):
 table=Path('/proc/self/mountinfo').read_text();need(len(table)<=1024**2,'bounded mount table');lines=[x.split()for x in table.splitlines()];result=[]
 for row,fd in opened:
  a=os.fstat(fd);b=os.stat(row['target'],follow_symlinks=False);hits=[x for x in lines if len(x)>9 and x[4]==row['target']and '-'in x];need(len(hits)==1,'one effective role mount')
  need((a.st_dev,a.st_ino,a.st_mode,a.st_uid,a.st_gid)==(b.st_dev,b.st_ino,b.st_mode,b.st_uid,b.st_gid),'bind inode/type/owner readback');ro=bool(os.statvfs(row['target']).f_flag&os.ST_RDONLY);need(ro is not row['rw'],'effective write flag')
  fields=hits[0];split=fields.index('-');result.append(dict(target=row['target'],source_device=a.st_dev,source_inode=a.st_ino,device=b.st_dev,inode=b.st_ino,mode=stat.S_IMODE(b.st_mode),uid=b.st_uid,gid=b.st_gid,readonly=ro,mount_id=int(fields[0]),filesystem=fields[split+1],mount_options=fields[5]))
 return result

def no_block_fds():
 for p in Path('/proc/self/fd').iterdir():
  try:need(not stat.S_ISBLK(os.stat(p).st_mode),'no raw block descriptor')
  except FileNotFoundError:pass
 return True

def resources(v):
 p=Path(v['cgroup_path']);st=p.lstat();need(stat.S_ISDIR(st.st_mode)and st.st_uid==st.st_gid==0 and not p.is_symlink(),'root-owned phase cgroup')
 memory=(p/'memory.max').read_text().strip();pids=(p/'pids.max').read_text().strip();need(memory=='1073741824'and pids=='128','actual memory/pid limits');need(Path('/sys/devices/system/cpu/online').read_text().strip()=='0-1','whole VM SMP2')
 with(p/'cgroup.procs').open('w')as f:f.write('0\n')
 membership=Path('/proc/self/cgroup').read_text().strip();relative='/kit77-'+v['nonce']+'/'+v['tool']+'-'+v['phase'];need(membership=='0::'+relative,'actual self cgroup membership')
 return dict(path=str(p),relative=relative,device=st.st_dev,inode=st.st_ino,uid=st.st_uid,gid=st.st_gid,memory_max=int(memory),pids_max=int(pids),membership=membership,cpu_scope='WHOLE_VM_SMP2',online_cpus='0-1',docker_cpu_quota='NOT_CLAIMED_KERNEL_CFS_BANDWIDTH_N')

def run(path,expected):
 need(Path(__file__).resolve()==Path('/kit77/runtime/guest_phase.py'),'fixed canonical phase runtime path')
 raw=read(path,65536);need(sha(raw)==expected,'independent descriptor bytes');v=descriptor(SC.decode(raw));s=SC.decode(read(BASE/'selection.json',4*1024**2));actual_guard(s)
 need(v['nonce']==s['nonce']and v['identity']==s['identity']and v['image_origin']==s['image']and v['source_map_sha256']==s['source_map_sha256']and v['kernel_release']==s['kernel']['profile']['release'],'selected context')
 selected=read('/kit77/work/'+v['tool']+'/candidate-inputs/candidate-selection.json',1024**2)if v['phase']=='candidate'else None
 need(v['env']==environment(s['identity'],v['tool'],v['phase'],selected,s['accepted_manifest']['profile.json']['sha256']),'exact phase environment')
 resource=resources(v)
 before=status();last=int(Path('/proc/sys/kernel/cap_last_cap').read_text());need(0<last<64,'finite guest caps');full=(1<<(last+1))-1
 need(before['nnp']=='0'and before['seccomp']=='0'and all(int(before['caps'][k],16)==full for k in('CapEff','CapPrm','CapBnd'))and all(int(before['caps'][k],16)==0 for k in('CapInh','CapAmb')),'guest root, no inherited updater fence')
 plan=SC.plan(read(SOURCE/LANE/'candidate-policy.json',256*1024),v['phase'],v['kernel_release']);libseccomp=SC.library(read)
 lib=C.CDLL(None,use_errno=True);lib.mount.argtypes=[C.c_char_p,C.c_char_p,C.c_char_p,C.c_ulong,C.c_void_p];lib.mount.restype=C.c_int
 opened=[];devices={}
 try:
  for row in v['mounts']:
   p=Path(row['source']);need(not any(x.is_symlink()for x in(p,*p.parents)),'ordinary role ancestry');fd=os.open(p,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC);st=os.fstat(fd);need(stat.S_ISDIR(st.st_mode)if row['type']=='directory'else stat.S_ISREG(st.st_mode),'role type');opened.append((row,fd))
  for n,minor in [('null',3),('zero',5),('random',8),('urandom',9)]:
   fd=os.open('/dev/'+n,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC);st=os.fstat(fd);need(stat.S_ISCHR(st.st_mode)and os.major(st.st_rdev)==1 and os.minor(st.st_rdev)==minor,'fixed device identity');devices[n]=fd
  os.chdir('/');mount(lib,None,'/',278528);mount(lib,'/','/',20480)
  class Attr(C.Structure):_fields_=[(k,C.c_uint64)for k in('set','clear','propagation','userns')]
  attr=Attr(1,0,0,0);need(lib.syscall(442,-100,b'/',0x8000,C.byref(attr),C.sizeof(attr))==0,'recursive readonly phase root')
  mount(lib,'tmpfs','/kit77',6,'tmpfs','size=1m,mode=0700');mount(lib,'tmpfs','/tmp',6,'tmpfs','size=256m,mode=1777');mount(lib,'tmpfs','/dev',2,'tmpfs','size=1m,mode=0755')
  os.symlink('/proc/self/fd','/dev/fd')
  for n,fd in devices.items():
   p=Path('/dev')/n;p.touch();mount(lib,'/proc/self/fd/'+str(fd),p,4096);mount(lib,None,p,4131)
  for row,fd in opened:mount(lib,'/proc/self/fd/'+str(fd),row['target'],4096);mount(lib,None,row['target'],4096|32|2|4|(0 if row['rw']else 1))
  if v['phase']=='receive':need(not any(os.path.lexists(p)for p in FORBIDDEN),'receiver private/source roles absent')
  observed_mounts=effective_mounts(opened);hidden=not os.path.lexists('/kit77/selection.json')
  os.setgroups([])
  for cap in range(last+1):need(lib.prctl(24,cap,0,0,0)==0,'drop every bounding cap')
  need(lib.prctl(47,4,0,0,0)==0 and lib.prctl(8,0,0,0,0)==0,'no ambient or kept caps');os.setresgid(1001,1001,1001);os.setresuid(1001,1001,1001);need(lib.prctl(38,1,0,0,0)==0,'phase NNP')
  facts=status();need(os.getuid()==os.geteuid()==os.getgid()==os.getegid()==1001 and not os.getgroups()and all(int(x,16)==0 for x in facts['caps'].values())and facts['nnp']=='1','ordinary zero-cap phase')
  installed=SC.install(plan,libseccomp);after=status();need(after['seccomp']=='2'and after['filters']=='1','one observed filter')
  for _,fd in opened:os.close(fd)
  for fd in devices.values():os.close(fd)
  opened=[];devices={}
  witness=dict(schema_version=1,delivery='BOUNDED_PREEXEC_STDOUT_FRAME',status='PREEXEC_VM_PHASE_BOUNDARY_OBSERVED_NO_TRANSACTION_CREDIT',identity=v['identity'],nonce=v['nonce'],tool=v['tool'],phase=v['phase'],image_origin=v['image_origin'],kernel=v['kernel_release'],uid=os.getuid(),gid=os.getgid(),groups=os.getgroups(),pid=os.getpid(),ppid=os.getppid(),status_fields=after,resources=dict(resource,cgroup_readonly=bool(os.statvfs('/sys/fs/cgroup').f_flag&os.ST_RDONLY)),mounts=v['mounts'],effective_mounts=observed_mounts,policy=installed,policy_plan_sha256=sha(encoded(plan)),original_argv=v['argv'],descriptor_sha256=sha(raw),kit77_hidden=hidden,root_readonly=bool(os.statvfs('/').f_flag&os.ST_RDONLY),no_raw_blocks=not any(p.is_block_device()for p in Path('/dev').iterdir())and no_block_fds(),interfaces=[x.split(':',1)[0].strip()for x in Path('/proc/net/dev').read_text().splitlines()[2:]],acceptance=False)
  need(witness['resources']['cgroup_readonly']and witness['kit77_hidden']and witness['root_readonly']and witness['no_raw_blocks']and witness['interfaces']==['lo'],'actual closed boundary')
  body=json.dumps(witness,sort_keys=True,separators=(',',':'),allow_nan=False).encode();need(len(body)<=65536,'bounded witness')
  frame=b'KIT77_PHASE_BOUNDARY '+v['nonce'].encode()+b' '+body+b'\n';written=0
  while written<len(frame):n=os.write(1,frame[written:]);need(n>0,'complete boundary frame');written+=n
  os.closerange(3,65536);os.execve(v['argv'][0],v['argv'],v['env'])
 finally:
  for _,fd in opened:os.close(fd)
  for fd in devices.values():os.close(fd)

def main():
 p=argparse.ArgumentParser();p.add_argument('--descriptor',required=True);p.add_argument('--sha256',required=True);a=p.parse_args();need(re.fullmatch(r'/kit77/work/vm/phases/(maintenance|diagnostics)-(produce|receive|candidate)\.descriptor\.json',a.descriptor)and re.fullmatch('[a-f0-9]{64}',a.sha256),'fixed phase request');run(a.descriptor,a.sha256)
if __name__=='__main__':main()
