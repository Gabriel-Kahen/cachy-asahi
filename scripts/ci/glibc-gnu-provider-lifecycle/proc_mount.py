# SPDX-License-Identifier: MIT
"""Finite same-trial readonly-proc diagnostic before any complete574 copy."""
import ctypes,errno,hashlib,json,os,re,stat
from pathlib import Path
TARGET=Path('/work/.gnu-readonly-proc-probe')
FLAGS=15
MASK=2149843163
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
  need(len(value)<=1024 and re.fullmatch(r'[0-9a-fA-F\s]+',value) is not None,'finite self status field');status[key]=value
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

def syscall(target,*,unmount=False,libc=None):
 """No flag/API exploration: exact original legacy mount flags, ordinary umount."""
 libc=libc or ctypes.CDLL(None,use_errno=True)
 if unmount:
  fn=libc.umount2;fn.argtypes=[ctypes.c_char_p,ctypes.c_int];fn.restype=ctypes.c_int;args=(os.fsencode(target),0)
 else:
  fn=libc.mount;fn.argtypes=[ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_ulong,ctypes.c_void_p];fn.restype=ctypes.c_int
  args=(b'proc',os.fsencode(target),b'proc',FLAGS,None)
 ctypes.set_errno(0);code=fn(*args);number=ctypes.get_errno() if code else 0
 need(code in (-1,0) and (code==0 or number>0),'exact mount syscall result')
 return dict(api='umount2' if unmount else 'mount',returncode=code,errno=number,errno_name=errno.errorcode.get(number,'UNKNOWN') if number else None,flags=0 if unmount else FLAGS)

def mounted():
 return [r for r in mounts() if r.split()[4]==str(TARGET)]
def verify_mount():
 rows=mounted();need(len(rows)==1,'exact readonly proc mount row required');f=rows[0].split();separator=f.index('-')
 need(f[separator+1]=='proc' and {'ro','nosuid','nodev','noexec'}<=set(f[5].split(',')),'actual required proc mount flags')
 fd=os.open(TARGET,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:need(os.fstatvfs(fd).f_flag&os.ST_RDONLY,'actual proc superblock readonly')
 finally:os.close(fd)
 return dict(status='PASS_EXACT_READONLY_PROC_FLAGS',mount_row=rows[0])

def guard(work):
 # Subordinate to the unchanged caller guard; also valid in its guarded16K guest.
 need(work==Path('/work') and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and os.environ.get('CACHY_GNU_PROVIDER_LIFECYCLE')=='1' and work.is_mount() and {p.name for p in Path('/sys/class/net').iterdir()}=={'lo'},'owned same-role GNU proc diagnostic only')

def check(commands,work):
 guard(work)
 report=dict(schema_version=1,status='FAIL_PROC_MOUNT_PREFLIGHT',source_mutation='NONE',policy_changes='NONE',purpose='EXACT_UTILITY_VS_LEGACY_READONLY_PROC_DIAGNOSTIC',target=str(TARGET),mount_flags=FLAGS,cleanup='NOT_RUN')
 parent=None;created=False;before=None;utility_absent=True
 try:
  report['before']=facts();status=report['before']['status']
  need(all(int(status[k],16)==MASK for k in ('CapEff','CapPrm','CapBnd')) and all(int(status[k],16)==0 for k in ('CapInh','CapAmb')) and status['NoNewPrivs']=='1' and status['Seccomp']=='2','original native9cap/NNP/seccomp readback')
  parent=os.open(work,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);parent_info=identity(os.fstat(parent))
  need(os.fstat(parent).st_uid==os.geteuid() and not stat.S_IMODE(os.fstat(parent).st_mode)&0o022,'owned private probe parent')
  os.mkdir(TARGET.name,0o700,dir_fd=parent);created=True;before=identity(os.stat(TARGET.name,dir_fd=parent,follow_symlinks=False));need(not mounted(),'fresh unmounted proc diagnostic target')
  first=len(commands.report['commands']);utility_absent=False
  try:commands.call(['/usr/bin/mount','-t','proc','-o','ro,nosuid,nodev,noexec','proc',str(TARGET)],seconds=10)
  except ValueError as error:report['utility_error']=dict(type=type(error).__name__,message=str(error)[:256])
  need(len(commands.report['commands'])==first+1,'one exact utility diagnostic command')
  row=commands.report['commands'][-1];utility_absent=row['group_absence_verified'];report['utility']=dict(command_number=first,exit_code=row['exit_code'],group_absence_verified=row['group_absence_verified'])
  need(row['group_absence_verified'],'utility absence unknown; do not change mounts')
  if row['exit_code']==0:report['utility']['mount']=verify_mount()
  if mounted():
   commands.call(['/usr/bin/umount',str(TARGET)],seconds=10);need(not mounted(),'utility probe mount remains')
  report['legacy']=syscall(TARGET)
  if report['legacy']['returncode']==0:report['legacy']['mount']=verify_mount()
  if mounted():report['legacy_unmount']=syscall(TARGET,unmount=True);need(report['legacy_unmount']['returncode']==0 and not mounted(),'legacy probe mount remains')
  report['after']=facts();need(report['after']==report['before'],'caller security/namespace/readonly mount metadata drift')
  report['classification']='BOTH_MOUNT_ROUTES_SUCCEEDED' if row['exit_code']==report['legacy']['returncode']==0 else 'UTILITY_AND_LEGACY_DIFFER' if (row['exit_code']==0)!=(report['legacy']['returncode']==0) else 'BOTH_ROUTES_DENIED_SECURITY_LAYER_NOT_DISAMBIGUATED'
  if report['classification']=='BOTH_MOUNT_ROUTES_SUCCEEDED':report['status']='PASS_READONLY_PROC_PREFLIGHT'
 except BaseException as error:
  report['error']=dict(type=type(error).__name__,message=str(error)[:512])
 finally:
  try:
   if created:
    need(utility_absent,'utility group absence unknown; retain probe and outer actor')
    if mounted():
     report['cleanup_unmount']=syscall(TARGET,unmount=True);need(report['cleanup_unmount']['returncode']==0,'failed proc probe retained')
    need(not mounted() and identity(os.stat(TARGET.name,dir_fd=parent,follow_symlinks=False))==before and identity(os.fstat(parent))==parent_info,'probe cleanup path/parent/mount drift')
    current=os.open(work,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:need(identity(os.fstat(current))==parent_info,'named probe parent changed')
    finally:os.close(current)
    os.rmdir(TARGET.name,dir_fd=parent)
   report['cleanup']='PASS_OWNED_EMPTY_PROBE_REMOVED' if created else 'NOT_CREATED_NO_REMOVAL'
  except BaseException as error:report.update(status='FAIL_PROC_MOUNT_PREFLIGHT',cleanup='FAIL_RETAIN_OUTER_OWNED_CONTAINER',cleanup_error=dict(type=type(error).__name__,message=str(error)[:512]))
  finally:
   if parent is not None:os.close(parent)
 need(len(json.dumps(report,allow_nan=False).encode())<=96*1024,'proc diagnostic receipt bound')
 return report
