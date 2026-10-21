# SPDX-License-Identifier: MIT
"""Fixed systemd-only private scratch and USER-only chroot preflight, no privilege grant."""
import hashlib,importlib.util,json,math,os,re,stat,subprocess,sys,time
from pathlib import Path
PROFILE='CORE_SYSTEMD_262_1_2_PRIVATE_SCRATCH_CHILD_USERNS_V1'
SOURCES=('caa-owned-userns.h','probe.c','probe_receipt.py')
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(v):return (json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def need(value,message):
 if not value:raise ValueError(message)
def read(path,cap=128*1024**2):
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size<=cap,'ordinary bounded source/receipt');blocks=[];size=0
  while b:=os.read(fd,min(1024**2,cap+1-size)):
   blocks.append(b);size+=len(b);need(size<=cap,'complete bounded read')
  z=os.fstat(fd);ident=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_nlink,s.st_mtime_ns,s.st_ctime_ns)
  need(size==a.st_size and ident(a)==ident(z),'same complete source/receipt');return b''.join(blocks)
 finally:os.close(fd)
def save(path,raw):
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  view=memoryview(raw)
  while view:view=view[os.write(fd,view):]
 finally:os.close(fd)
def module(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def scratch_args(kind,uid,gid):
 need(kind in('systemd','pacman')and type(uid)is int and uid>0 and type(gid)is int and gid>=0,'exact ordinary actor scratch identity')
 return []if kind=='pacman'else['--tmpfs','/var/tmp:rw,nosuid,nodev,exec,size=2g,mode=1777','--tmpfs',f'/run:rw,nosuid,nodev,noexec,size=16m,mode=0700,uid={uid},gid={gid}','--env','CACHY_ASAHI_CORE_TESTLOG_EXPORT=1']

def entry(raw):
 text=raw.decode();a='makepkg --config /tmp/core-makepkg.conf --verifysource --noconfirm\n'
 need(text.count(a)==1,'one pre-build mechanism seam')
 b='if [[ $CORE_RECIPE == systemd ]]; then\n  python3 -I -B /test_environment.py\nfi\n'+a
 return text.replace(a,b,1).encode()

def mounted(path):
 rows=[]
 fd=os.open('/proc/self/mountinfo',os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  raw=b''
  while chunk:=os.read(fd,65536):
   raw+=chunk;need(len(raw)<=1024**2,'complete bounded current mountinfo')
 finally:os.close(fd)
 for line in raw.decode().splitlines():
  left,sep,right=line.partition(' - ');a=left.split();b=right.split()
  need(sep and len(a)>=6 and len(b)>=3,'complete mountinfo row')
  if a[4]==path:rows.append((a,b))
 need(len(rows)==1,'one exact private scratch mount')
 a,b=rows[0];opts=set(a[5].split(','));superopts=set(b[2].split(','));s=os.stat(path,follow_symlinks=False)
 need(b[0]=='tmpfs'and {'rw','nosuid','nodev'}<=opts and stat.S_ISDIR(s.st_mode),'private ordinary writable scratch tmpfs')
 if path=='/run':need('noexec'in opts and stat.S_IMODE(s.st_mode)==0o700 and s.st_uid==os.getuid()and s.st_gid==os.getgid(),'private ordinary actor run scratch')
 else:need('noexec'not in opts and stat.S_IMODE(s.st_mode)==0o1777,'bounded executable var/tmp scratch')
 need(str(s.st_dev)==str(os.stat(path).st_dev),'stable scratch identity')
 return dict(path=path,mount_id=int(a[0]),parent_id=int(a[1]),device=a[2],root=a[3],mount_options=sorted(opts),super_options=sorted(superopts),fstype=b[0],dev=s.st_dev,inode=s.st_ino,mode=stat.S_IMODE(s.st_mode),uid=s.st_uid,gid=s.st_gid)

def validate_receipt(v,source,owner,user):
 need(type(v)is dict and set(v)=={'schema','status','profile','owner','uid','gid','source','compiler','probe','scratch','clock','scope'},'whole environment receipt')
 uid,gid=map(int,user.split(':'));need(v['schema']==1 and type(v['schema'])is int and v['status']=='PASS_PRIVATE_SCRATCH_AND_NATIVE_USERNS_MECHANISM_ONLY'and v['profile']==PROFILE and v['owner']==owner and type(v['uid'])is int and type(v['gid'])is int and (v['uid'],v['gid'])==(uid,gid)and uid>0,'exact owned ordinary environment identity')
 need(v['source']==source and v['scope']=='NO_CORE_BUILD_INSTALL_OR_CLEANUP_ACCEPTANCE','whole mechanism sources, no transferred authority')
 compiler=v['compiler'];need(set(compiler)=={'command','returncode','stdout','stderr','binary'}and compiler['command']==['/usr/bin/cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-o','/tmp/core-home/owned-userns-probe','/mechanism/probe.c']and compiler['returncode']==0 and type(compiler['returncode'])is int and compiler['stdout']==pin(b'')and compiler['stderr']==pin(b'')and set(compiler['binary'])=={'bytes','sha256'}and type(compiler['binary']['bytes'])is int and 0<compiler['binary']['bytes']<=128*1024**2 and re.fullmatch('[0-9a-f]{64}',compiler['binary']['sha256']),'full successful native compiler receipt')
 probe=v['probe'];need(set(probe)=={'command','returncode','stdout','stderr','result'}and probe['command']==['/tmp/core-home/owned-userns-probe','--native-preflight']and probe['returncode']==0 and type(probe['returncode'])is int and probe['stderr']==pin(b''),'fixed completed probe process')
 expected=dict(schema=1,status='PASS_OWNED_USERNS_CHROOT_MECHANISM_ONLY',mode='native-preflight',parent_namespace='UNCHANGED',child_namespace='USER_ONLY',mapping='SELF_ONLY',retained_capabilities='SYS_CHROOT_ONLY',before_chroot=[True,True],after_chroot=[False,False],original_child1=True,chroot='/usr',retirement='BOTH_OWNED_CHILDREN_REAPED',checks=58,systemd_test='NOT_EXECUTED',native_ARM='NOT_ESTABLISHED_BY_THIS_PROBE')
 need(enc(probe['result'])==enc(expected)and probe['stdout']==pin((json.dumps(expected,separators=(',',':'))+'\n').encode()),'complete exact native causal probe')
 need(set(v['scratch'])=={'/var/tmp','/run'},'both bounded scratch mounts required')
 for path,row in v['scratch'].items():
  need(set(row)=={'before','after','write_read_unlink'}and row['before']==row['after']and row['write_read_unlink']is True,'fresh stable scratch mount before/after and real I/O')
  m=row['before'];need(all(type(m.get(k))is int for k in('mount_id','parent_id','dev','inode','mode','uid','gid')),'typed complete mount identity');need(set(m)=={'path','mount_id','parent_id','device','root','mount_options','super_options','fstype','dev','inode','mode','uid','gid'}and m['path']==path and m['fstype']=='tmpfs'and type(m['mount_id'])is int and m['mount_id']>0 and type(m['inode'])is int and m['inode']>0 and {'rw','nosuid','nodev'}<=set(m['mount_options']),'complete scratch mount identity')
  if path=='/run':need(m['mode']==0o700 and(m['uid'],m['gid'])==(uid,gid)and 'noexec'in m['mount_options'],'run scratch identity')
  else:need(m['mode']==0o1777 and 'noexec'not in m['mount_options'],'var/tmp scratch identity')
 clock=v['clock'];need(set(clock)=={'started_monotonic','elapsed_seconds','limit_seconds'}and type(clock['started_monotonic'])in(int,float)and math.isfinite(clock['started_monotonic'])and clock['started_monotonic']>0 and type(clock['elapsed_seconds'])in(int,float)and math.isfinite(clock['elapsed_seconds'])and 0<=clock['elapsed_seconds']<60 and clock['limit_seconds']==60,'fixed nonreserved preflight sub-bound, old owner/package caps held')
 return v

def main():
 started=time.monotonic();need(len(sys.argv)==1 and os.getuid()>0 and os.geteuid()==os.getuid()and os.environ.get('CORE_RECIPE')=='systemd'and os.environ.get('CACHY_ASAHI_CORE_CONTAINER')=='1'and os.environ.get('CACHY_ASAHI_CORE_TESTLOG_EXPORT')=='1','fixed owned systemd actor only')
 owner=os.environ.get('CACHY_ASAHI_CORE_CATALOG_OWNER','');need(re.fullmatch('cachy-asahi-new-core-[0-9a-f]{16}',owner),'same whole catalog/package owner')
 source={n:pin(read(Path('/mechanism')/n))for n in SOURCES};scratch={}
 for path in('/var/tmp','/run'):
  before=mounted(path);name=Path(path)/('caa-owned-probe-'+os.urandom(8).hex());save(name,b'owned scratch\n');need(read(name)==b'owned scratch\n','scratch readback');name.unlink();after=mounted(path);need(before==after,'stable complete scratch mount');scratch[path]=dict(before=before,after=after,write_read_unlink=True)
 compiler=['/usr/bin/cc','-std=gnu11','-O2','-Wall','-Wextra','-Werror','-o','/tmp/core-home/owned-userns-probe','/mechanism/probe.c'];need(not Path(compiler[-2]).exists(),'fresh owned probe binary')
 command=['/tmp/core-home/owned-userns-probe','--native-preflight'];results=[]
 for label,argv,seconds in(('compiler',compiler,30),('probe',command,15)):
  run=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=seconds,env=dict(os.environ));save('/out/userns-'+label+'.stdout',run.stdout);save('/out/userns-'+label+'.stderr',run.stderr)
  need(run.returncode==0 and not run.stderr and len(run.stdout)<=4096,'fixed mechanism failed; complete retained diagnostics')
  results.append(dict(command=argv,returncode=run.returncode,stdout=pin(run.stdout),stderr=pin(run.stderr)))
 result=module('/mechanism/probe_receipt.py','source_owned_namespace_receipt').parse(run.stdout,'native-preflight');results[0]['binary']=pin(read('/tmp/core-home/owned-userns-probe'));results[1]['result']=result
 v=dict(schema=1,status='PASS_PRIVATE_SCRATCH_AND_NATIVE_USERNS_MECHANISM_ONLY',profile=PROFILE,owner=owner,uid=os.getuid(),gid=os.getgid(),source=source,compiler=results[0],probe=results[1],scratch=scratch,clock=dict(started_monotonic=started,elapsed_seconds=time.monotonic()-started,limit_seconds=60),scope='NO_CORE_BUILD_INSTALL_OR_CLEANUP_ACCEPTANCE')
 # Probe canonical output is checked from its original bytes below, not a reserialization guess.
 validate_receipt(v,source,owner,f'{os.getuid()}:{os.getgid()}');save('/out/systemd-test-environment.json',enc(v));print(enc(v).decode(),end='')
if __name__=='__main__':main()
