# SPDX-License-Identifier: MIT
"""Exact bounded same-trial proc/dev-null mount lifetimes and preflight."""
from contextlib import contextmanager
import ctypes,errno,hashlib,json,os,re,signal,stat,time
from pathlib import Path
TARGET=Path('/work/.gnu-readonly-proc-probe')
FLAGS=15
BIND=4096
ROOTS=(Path('/work/pristine/root'),Path('/work/modified/root'))
MASK=2149843195
STATUS=('Uid','Gid','Groups','CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs','Seccomp','Seccomp_filters')

def need(ok,why):
 if not ok:raise ValueError(why)
def identity(info):return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)
def bounded(path,cap):
 try:
  with Path(path).open('rb') as stream:raw=stream.read(cap+1)
  need(len(raw)<=cap,'proc diagnostic input bound');return raw
 except OSError as error:return dict(available=False,errno=error.errno)
def text_fact(path):
 raw=bounded(path,4096)
 if type(raw) is dict:return raw
 value=raw.decode('utf8','strict').strip()
 need(all(32<=ord(c)<127 for c in value),'finite security profile text')
 return dict(available=True,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),value=value[:512],clipped=len(value)>512)
def mounts():
 raw=bounded('/proc/self/mountinfo',4*1024**2);need(type(raw) is bytes,'self mount inventory unavailable')
 rows=[]
 for line in raw.splitlines():
  f=line.split();need(len(f)>=10 and f.count(b'-')==1,'self mount row shape')
  if f[4] in (b'/',b'/proc',b'/sys',b'/work',b'/held',b'/source',b'/inputs',bytes(TARGET)) or f[4].startswith(b'/proc/'):
   need(len(line)<=4096 and len(rows)<64,'selected proc mount inventory bound');rows.append(line.decode('ascii','strict'))
 need(sum(map(len,rows))<=32768,'selected proc mount bytes bound');return rows

def facts():
 raw=bounded('/proc/self/status',128*1024);need(type(raw) is bytes,'self security status unavailable')
 lines={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in raw.decode('ascii').splitlines() if ':' in line}
 status={}
 for key in STATUS:
  value=lines.get(key)
  if value is None:status[key]=None;continue
  need(len(value)<=1024 and (key=='Groups' and value=='' or re.fullmatch(r'[0-9a-fA-F\s]+',value) is not None),'finite self status field');status[key]=value
 namespaces={}
 for name in ('mnt','pid','pid_for_children','user'):
  path=Path('/proc/self/ns')/name
  try:
   value=os.readlink(path);need(re.fullmatch(r'[a-z_]+:\[[0-9]+\]',value),'namespace identity encoding');info=path.stat();namespaces[name]=dict(link=value,device=info.st_dev,inode=info.st_ino)
  except OSError as error:namespaces[name]=dict(available=False,errno=error.errno)
 maps={}
 for name in ('uid_map','gid_map'):
  raw=bounded('/proc/self/'+name,4096)
  if type(raw) is dict:maps[name]=raw;continue
  values=[list(map(int,line.split())) for line in raw.splitlines()];need(len(values)<=16 and all(len(r)==3 and all(0<=n<2**64 for n in r) for r in values),'finite namespace id map');maps[name]=values
 return dict(kernel=dict(release=os.uname().release,architecture=os.uname().machine),status=status,namespaces=namespaces,id_maps=maps,
             security_profile=text_fact('/proc/self/attr/current'),lsm=text_fact('/sys/kernel/security/lsm'),apparmor_enabled=text_fact('/sys/module/apparmor/parameters/enabled'),mounts=mounts())

def syscall(target,*,unmount=False,bind=False,libc=None):
 """Only exact legacy proc15, dev/null bind4096, ordinary umount2(0)."""
 need(not (unmount and bind),'one exact mount API operation')
 libc=libc or ctypes.CDLL(None,use_errno=True)
 if unmount:
  fn=libc.umount2;fn.argtypes=[ctypes.c_char_p,ctypes.c_int];fn.restype=ctypes.c_int;args=(os.fsencode(target),0)
 else:
  fn=libc.mount;fn.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_ulong,ctypes.c_void_p];fn.restype=ctypes.c_int
  args=(b'/dev/null',os.fsencode(target),None,BIND,None) if bind else (b'proc',os.fsencode(target),b'proc',FLAGS,None)
 ctypes.set_errno(0);code=fn(*args);number=ctypes.get_errno() if code else 0
 need(code in (-1,0) and (code==0 or number>0),'exact mount syscall result')
 return dict(api='umount2' if unmount else 'mount',returncode=code,errno=number,errno_name=errno.errorcode.get(number,'UNKNOWN') if number else None,flags=0 if unmount else BIND if bind else FLAGS)

def invoke(target,*,unmount=False,bind=False):
 # Same trial process; never extend a caller deadline or alter capability bounds.
 started=time.monotonic();handler=signal.getsignal(signal.SIGALRM);timer=signal.getitimer(signal.ITIMER_REAL)
 def expired(*_):raise TimeoutError('exact legacy mount operation10s deadline')
 signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,min(10,timer[0]) if timer[0]>0 else 10)
 try:return syscall(target,unmount=unmount,bind=bind)
 finally:
  signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,handler)
  if timer[0]>0:signal.setitimer(signal.ITIMER_REAL,max(0.000001,timer[0]-(time.monotonic()-started)),timer[1])

def inventory():
 raw=bounded('/proc/self/mountinfo',4*1024**2);need(type(raw) is bytes,'self mount inventory unavailable');lines=raw.splitlines();need(0<len(lines)<=32768,'finite mount row count');result=[]
 for line in lines:
  f=line.split();need(len(f)>=10 and f.count(b'-')==1 and len(line)<=16384,'finite mount row shape');result.append(line.decode('ascii','strict'))
 return result

def mounted(target=None):
 target=TARGET if target is None else target;return [r for r in inventory() if r.split()[4]==str(target)]

def verify_mount(target=None):
 target=TARGET if target is None else target;rows=mounted(target);need(len(rows)==1,'exact readonly proc mount row required');f=rows[0].split();separator=f.index('-')
 need(f[3]=='/' and f[separator+1:separator+3]==['proc','proc'] and {'ro','nosuid','nodev','noexec'}<=set(f[5].split(',')) and 'rw' not in f[5].split(','),'actual required proc mount flags/type/source/root')
 fd=os.open(target,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  info=os.fstat(fd);need(f[2]==str(os.major(info.st_dev))+':'+str(os.minor(info.st_dev)) and os.fstatvfs(fd).f_flag&os.ST_RDONLY,'actual proc device and superblock readonly')
 finally:os.close(fd)
 return dict(status='PASS_EXACT_READONLY_PROC_FLAGS',mount_row=rows[0])

def dev_identity(info):return identity(info)+(info.st_rdev,)
def source_mount():
 rows=[r for r in inventory() if '/dev/null'==r.split()[4] or '/dev/null'.startswith(r.split()[4].rstrip('/')+'/')];need(rows,'dev/null source mount available');length=max(len(r.split()[4]) for r in rows);rows=[r for r in rows if len(r.split()[4])==length];need(len(rows)==1,'unambiguous dev/null covering mount');return rows[0]

def verify_bind(target,source_info,source_row):
 rows=mounted(target);need(len(rows)==1,'one exact dev/null bind mount row');f=rows[0].split();s=source_row.split();i=f.index('-');j=s.index('-');relative=Path('/dev/null').relative_to(s[4]);root=(Path(s[3])/relative).as_posix();info=target.lstat()
 need(stat.S_ISCHR(info.st_mode) and os.major(info.st_rdev)==1 and os.minor(info.st_rdev)==3 and dev_identity(info)==dev_identity(source_info),'actual target is exact source dev/null inode/device/rdev/mode/owner')
 need(f[0]!=s[0] and f[2]==s[2] and f[3]==root and f[i+1:i+3]==s[j+1:j+3] and set(f[5].split(','))==set(s[5].split(',')),'actual dev/null bind source root/device/fs/flags mount row')
 return dict(status='PASS_EXACT_DEV_NULL_BIND_IDENTITY',mount_row=rows[0],source_mount_row=source_row,inode=info.st_ino,device=info.st_dev,rdev=info.st_rdev,mode=info.st_mode,uid=info.st_uid,gid=info.st_gid)

def caps(value):
 status=value['status'];need(all(int(status[k],16)==MASK for k in ('CapEff','CapPrm','CapBnd')) and all(int(status[k],16)==0 for k in ('CapInh','CapAmb')) and status['NoNewPrivs']=='1' and status['Seccomp']=='2','original bounded native10cap/NNP/seccomp readback')

def ordinary(path,directory=True):
 need(not any(p.is_symlink() for p in (path,*path.parents)),'owned mount path has no symlink alias');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|(os.O_DIRECTORY if directory else 0));info=os.fstat(fd)
 try:need((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)) and info.st_uid==os.geteuid() and not stat.S_IMODE(info.st_mode)&0o022 and identity(path.lstat())==identity(info),'owned mount path identity/mode')
 except BaseException:os.close(fd);raise
 return fd,info

def stable(path,fd,info):need(identity(os.fstat(fd))==identity(path.lstat())==identity(info),'owned mount target or parent identity changed')

def unmount_owned(target,row,receipt):
 need(mounted(target)==[row],'only exact registered owned mount may be retired');result=invoke(target,unmount=True);calls=receipt.setdefault('calls',[]);need(len(calls)<8,'finite direct mount operation receipts');calls.append(dict(target=str(target),**result));need(result['returncode']==0 and not mounted(target),'exact legacy unmount/absence required');return result

@contextmanager
def runtime_mounts(root,report):
 guard(Path('/work'));need(root in ROOTS,'two exact owned GNU case runtime roots only');before=facts();caps(before);rows=report.setdefault('runtime_mounts',[]);need(len(rows)<10,'at most ten original interruption runtime mount lifetimes');receipt=dict(status='FAIL',root=str(root),api='EXACT_LEGACY_PROC15_DEV_NULL_BIND4096_UMOUNT0',calls=[],cleanup='NOT_RUN',dev_null_native_counterfactual='NOT_YET_ESTABLISHED_BY_PRIOR_PROC_ONLY_RUN38993545529');rows.append(receipt)
 held=[];registered=[];placeholder=root/'dev/null';created=False;primary=None
 try:
  for path in (root,root/'proc',root/'dev'):
   fd,info=ordinary(path);held.append((path,fd,info))
  need(not os.listdir(held[1][1]) and not mounted(root/'proc') and not mounted(placeholder),'fresh empty proc and unmounted dev/null targets');need(not placeholder.exists() and not placeholder.is_symlink(),'no preexisting dev/null placeholder')
  fd=os.open('null',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=held[2][1]);os.close(fd);created=True;fd,info=ordinary(placeholder,False);need(info.st_nlink==1 and info.st_size==0,'fresh single-link empty placeholder');held.append((placeholder,fd,info))
  null_fd=os.open('/dev/null',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);null_info=os.fstat(null_fd);held.append((Path('/dev/null'),null_fd,null_info));need(stat.S_ISCHR(null_info.st_mode) and os.major(null_info.st_rdev)==1 and os.minor(null_info.st_rdev)==3 and null_info.st_uid==null_info.st_gid==0 and dev_identity(Path('/dev/null').lstat())==dev_identity(null_info),'exact root-owned source dev/null character device');null_row=source_mount()
  for target,bind in ((root/'proc',False),(placeholder,True)):
   for n in (0,2):stable(*held[n])
   if not bind:stable(*held[1])
   need(not mounted(target),'owned mount target unexpectedly occupied')
   if bind:stable(*held[3])
   result=invoke(target,bind=bind);receipt['calls'].append(dict(target=str(target),**result));need(result['returncode']==0,'required exact legacy mount failed')
   actual=mounted(target);need(len(actual)==1,'one newly owned mount row');registered.append((target,actual[0]));receipt['dev_null' if bind else 'proc']=verify_bind(target,null_info,null_row) if bind else verify_mount(target)
  yield receipt
  receipt['status']='PASS_EXACT_LEGACY_RUNTIME_MOUNTS'
 except BaseException as error:primary=error;receipt['primary_error']=dict(type=type(error).__name__,message=str(error)[:512]);raise
 finally:
  errors=[]
  try:
   for target,row in reversed(registered):
    try:unmount_owned(target,row,receipt)
    except BaseException as error:errors.append(str(error)[:256])
   need(not errors and not mounted(root/'proc') and not mounted(placeholder),'runtime mount retirement incomplete: '+str(errors))
   for path,fd,info in held:stable(path,fd,info)
   if created:placeholder.unlink();created=False
   need(facts()==before,'runtime security/namespace/mount source drift');receipt['cleanup']='PASS_EXACT_MOUNTS_ABSENT_PLACEHOLDER_REMOVED'
  except BaseException as error:
   receipt.update(status='FAIL',cleanup='FAIL_RETAIN_OUTER_OWNED_CONTAINER',cleanup_error=dict(type=type(error).__name__,message=str(error)[:512]))
   if primary is not None:primary.add_note('exact legacy runtime cleanup also failed; see runtime_mounts receipt')
   else:raise
  finally:
   for _,fd,_ in reversed(held):os.close(fd)
  need(len(json.dumps(receipt,allow_nan=False).encode())<=16384,'bounded runtime mount receipt')

def guard(work):
 # Subordinate to either exact unchanged caller guard, including guarded16K.
 markers={k:v for k,v in os.environ.items() if k.startswith('CACHY_GNU_PROVIDER_')}
 need(markers in ({'CACHY_GNU_PROVIDER_LIFECYCLE':'1'},{'CACHY_GNU_PROVIDER_INTERRUPTION':'1'}),'one exact known same-role GNU marker only')
 need(work==Path('/work') and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and work.is_mount() and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'owned same-role GNU proc diagnostic only')

def check(commands,work):
 guard(work)
 report=dict(schema_version=2,status='FAIL_PROC_MOUNT_PREFLIGHT',source_mutation='NONE',policy_changes='NONE',purpose='EXACT_LEGACY_READONLY_PROC_REQUIRED',utility='NOT_RUN_PRIOR_NATIVE38993545529_DIFFERS_NO_UNIQUE_UTILITY_CAUSE_CLAIM',target=str(TARGET),mount_flags=FLAGS,cleanup='NOT_RUN')
 parent=None;created=False;before=None;owned_row=None
 try:
  report['before']=facts();caps(report['before']);parent=os.open(work,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);parent_info=identity(os.fstat(parent));need(os.fstat(parent).st_uid==os.geteuid() and not stat.S_IMODE(os.fstat(parent).st_mode)&0o022,'owned private probe parent')
  os.mkdir(TARGET.name,0o700,dir_fd=parent);created=True;before=identity(os.stat(TARGET.name,dir_fd=parent,follow_symlinks=False));need(not mounted(),'fresh unmounted proc target');report['legacy']=invoke(TARGET);need(report['legacy']['returncode']==0,'required exact legacy readonly proc mount failed')
  rows=mounted();need(len(rows)==1,'one newly owned proc mount');owned_row=rows[0];report['legacy']['mount']=verify_mount();report['legacy_unmount']=unmount_owned(TARGET,owned_row,report);owned_row=None
  report['after']=facts();need(report['after']==report['before'],'caller security/namespace/readonly mount metadata drift');report.update(classification='LEGACY_READONLY_PROC_SUCCEEDED_UTILITY_ROUTE_NOT_REQUIRED',status='PASS_READONLY_PROC_PREFLIGHT')
 except BaseException as error:report['error']=dict(type=type(error).__name__,message=str(error)[:512]);report['classification']='LEGACY_READONLY_PROC_REQUIRED_FAILED'
 finally:
  try:
   if created:
    if owned_row is not None:report['cleanup_unmount']=unmount_owned(TARGET,owned_row,report)
    need(not mounted() and identity(os.stat(TARGET.name,dir_fd=parent,follow_symlinks=False))==before and identity(os.fstat(parent))==parent_info,'probe cleanup path/parent/mount drift');current=os.open(work,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:need(identity(os.fstat(current))==parent_info,'named probe parent changed')
    finally:os.close(current)
    os.rmdir(TARGET.name,dir_fd=parent)
   report['cleanup']='PASS_OWNED_EMPTY_PROBE_REMOVED' if created else 'NOT_CREATED_NO_REMOVAL'
  except BaseException as error:report.update(status='FAIL_PROC_MOUNT_PREFLIGHT',cleanup='FAIL_RETAIN_OUTER_OWNED_CONTAINER',cleanup_error=dict(type=type(error).__name__,message=str(error)[:512]))
  finally:
   if parent is not None:os.close(parent)
 need(len(json.dumps(report,allow_nan=False).encode())<=96*1024,'proc receipt bound');return report
