"""Source-only PID1 bootstrap mechanism. Never run this in a host process.

No fast lookup is activated. The current GNU lifecycle requires a separate
copy-scope/mount-broker adaptation; default authority refuses before mutation.
"""
import ctypes,os,re,stat
from pathlib import Path
from common import need,obj,ordinary,encoded,pin,PROFILE,SOURCE
import dm
from borrowed import reader as R
WORKER_MASK=sum(1<<n for n in(0,1,3,4,5,6,7,18,31))


def selection(value):
 need(type(value)is dict and set(value)=={'status','source','kernel','nonce','image','tree','snapshot','producer_retirement'},'finite source-owned bootstrap selection')
 need(value['status']=='ROOT_BOUND_GNU_VERITY_BOOTSTRAP'and value['source']==SOURCE and type(value['kernel'])is dict and value['kernel'].get('profile')==PROFILE and re.fullmatch('[0-9a-f]{32}',value.get('nonce')or''),'NULL source/kernel/nonce authority; no mutation')
 need(value['kernel'].get('boot_page_size')==16384 and type(value['kernel'].get('release'))is str and value['kernel'].get('configured_symbols')==['MD','BLK_DEV_DM','DM_VERITY','CRYPTO_SHA256'],'fresh dedicated configured/built/booted kernel required; old kernel not eligible')
 need(value['producer_retirement']=={'status':'ROOT_VERIFIED_SOURCE_PRODUCERS_RETIRED','source':SOURCE},'source writer retirement authority required')
 image=value['image'];tree=value['tree'];need(type(image)is dict and type(tree)is dict and set(image)=={'bytes','sha256'}and set(tree)=={'bytes','sha256','data_blocks','root_hash','salt'},'exact source image/hash layout')
 need(type(image['bytes'])is int and image['bytes']==8*1024**3 and type(tree['bytes'])is int and 0<tree['bytes']<=128*1024**2 and tree['bytes']%4096==0 and type(tree['data_blocks'])is int and tree['data_blocks']*4096==image['bytes'],'finite disk-backed8GiB source; no source memfd')
 for v in(image['sha256'],tree['sha256'],tree['root_hash'],tree['salt']):need(type(v)is str and re.fullmatch('[0-9a-f]{64}',v),'exact SHA256 authority')
 need(type(value['snapshot'])is dict and set(value['snapshot'])=={'bytes','sha256'}and type(value['snapshot']['bytes'])is int and 0<value['snapshot']['bytes']<=128*1024**2 and re.fullmatch('[0-9a-f]{64}',value['snapshot']['sha256']),'full original source map operand required')
 return value


def drop_worker():
 """Irrevocable bounding+P/E drop in disposable child, never in PID1/host."""
 need(os.getpid()!=1 and os.getppid()==1 and os.getuid()==os.geteuid()==0,'direct owned PID1 child only');libc=ctypes.CDLL(None,use_errno=True)
 need(libc.prctl(38,1,0,0,0)==0,'NNP required before cap reduction')
 for bit in range(64):
  if WORKER_MASK&(1<<bit):continue
  rc=libc.prctl(24,bit,0,0,0)
  if rc!=0:need(ctypes.get_errno()==22,'irrevocable bounding drop');break
 need(libc.prctl(47,4,0,0,0)==0,'ambient clear')
 class H(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
 class V(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
 h=H(0x20080522,0);v=(V*2)(V(WORKER_MASK&0xffffffff,WORKER_MASK&0xffffffff,0),V(WORKER_MASK>>32,WORKER_MASK>>32,0));need(libc.capset(ctypes.byref(h),v)==0,'exact no-admin worker capset');masks=R.restricted(R.status());need(all(masks[k]==WORKER_MASK for k in('CapEff','CapPrm','CapBnd')),'exact9-cap worker without SYS_ADMIN');return masks


def mount(source,target,fs,flags,options):
 dm.pid1();fn=ctypes.CDLL(None,use_errno=True).mount;fn.argtypes=(ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_ulong,ctypes.c_char_p);fn.restype=ctypes.c_int
 need(fn(None if source is None else os.fsencode(source),os.fsencode(target),None if fs is None else fs.encode(),flags,None if options is None else options.encode())==0,'source-owned guest mount failed')


def _mount_rows(path):
 """Fresh bounded mountinfo DATA; never retain an FD across umount2."""
 raw=Path('/proc/self/mountinfo').read_bytes();need(len(raw)<=1024**2,'bounded guest mount inventory');rows=[]
 for line in raw.decode().splitlines():
  left,right=line.split(' - ',1);a,b=left.split(),right.split();need(len(a)>=6 and len(b)>=3 and a[0].isdigit()and a[1].isdigit(),'typed guest mount inventory')
  if a[4]==path or a[4].startswith(path+'/'):
   need(len(rows)<16 and len(a[4])<=256,'bounded guest mount subtree')
   rows.append(dict(id=int(a[0]),parent=int(a[1]),device=a[2],root=a[3],path=a[4],fs=b[0],source=b[1]))
 return rows


def _retirement_failure(path,rc,error,before,after):
 """Failure DATA only; no cleanup or acceptance authority."""
 try:
  import json
  value=dict(status='GUEST_MOUNT_RETIREMENT_FAILURE_DATA_ONLY',path=path,umount_flags=0,returncode=rc,errno=error,before=before,after=after,cleanup_authority=False,acceptance_authority=False)
  raw=json.dumps(value,sort_keys=True,separators=(',',':'));need(len(raw.encode())<=8192,'bounded mount failure diagnostic');print('GNU_MOUNT_RETIREMENT_FAILURE '+raw,file=__import__('sys').stderr,flush=True)
 except Exception:pass


def _umount_call(path):
 fn=ctypes.CDLL(None,use_errno=True).umount2;fn.argtypes=(ctypes.c_char_p,ctypes.c_int);fn.restype=ctypes.c_int;ctypes.set_errno(0);rc=fn(os.fsencode(path),0);return rc,ctypes.get_errno()


def umount(path):
 dm.pid1();before=_mount_rows(path);rc,error=_umount_call(path);after=_mount_rows(path)
 ok=rc==0 and not os.path.ismount(path)
 if not ok:_retirement_failure(path,rc,error,before,after)
 need(ok,'strict guest mount retirement')


def _fresh_mount_id(path,rows):
 fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  info=os.fstat(fd);need(stat.S_ISDIR(info.st_mode)and info.st_uid==0,'owned guest device mount root')
  raw=Path('/proc/self/fdinfo/'+str(fd)).read_bytes();need(len(raw)<=4096,'bounded fresh mount FD metadata');values=[line.split(':',1)[1].strip()for line in raw.decode().splitlines()if line.startswith('mnt_id:')];need(len(values)==1 and values[0].isdigit(),'one fresh descriptor mount identity');result=int(values[0]);need(result in {r['id']for r in rows},'fresh named mount identity belongs to admitted stack')
  class Statx(ctypes.Structure):_fields_=[('mask',ctypes.c_uint32),('prefix',ctypes.c_ubyte*140),('mnt_id',ctypes.c_uint64),('reserved',ctypes.c_ubyte*104)]
  need(ctypes.sizeof(Statx)==256 and Statx.mnt_id.offset==144 and __import__('sys').byteorder=='little','exact ordinary statx mount ABI');libc=ctypes.CDLL(None,use_errno=True);call=libc.statx;call.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_uint,ctypes.POINTER(Statx));call.restype=ctypes.c_int;value=Statx();need(call(fd,b'',0x1000,0x1000,ctypes.byref(value))==0 and value.mask&0x1000 and value.mnt_id==result,'fresh statx/fdinfo ordinary mount IDs agree')
 finally:os.close(fd)
 need(_mount_rows(path)==rows,'mount inventory stable across fresh descriptor query');return result


def retire_bootstrap_dev():
 """Only one or two known bootstrap devtmpfs layers; strict final absence."""
 dm.pid1();path='/dev';before=_mount_rows(path);rc=None;error=None;after=before
 try:
  need(1<=len(before)<=2 and all(r['path']==path and r['root']=='/'and r['fs']==r['source']=='devtmpfs'for r in before),'only one or two exact bootstrap devtmpfs layers; no descendants')
  need(len({r['id']for r in before})==len(before)and len({r['device']for r in before})==1,'distinct mounts of one original devtmpfs')
  top=_fresh_mount_id(path,before);table={r['id']:r for r in before};order=[top]
  if len(before)==2:need(table[top]['parent']in table and table[top]['parent']!=top,'exact stacked devtmpfs parent');order.append(table[top]['parent'])
  need(set(order)==set(table)and table[order[-1]]['parent']not in table,'complete finite bootstrap mount chain')
  remaining=before
  for expected in order:
   current=_mount_rows(path);need(current==remaining and _fresh_mount_id(path,current)==expected,'exact current admitted top mount before strict retirement')
   rc,error=_umount_call(path);after=_mount_rows(path);need(rc==0,'strict guest mount retirement')
   wanted=[r for r in remaining if r['id']!=expected];need(after==wanted,'only exact admitted top mount retired');remaining=after
  need(not remaining and not _mount_rows(path)and not os.path.ismount(path),'strict guest mount retirement')
 except BaseException:
  _retirement_failure(path,rc,error,before,after);raise


def attest(prepared,work,out,value):
 """Real descriptors/mounts only; called before drop and again in child."""
 root=prepared.fd;identity=R.identity(os.fstat(root));need(identity==prepared.root_identity and stat.S_ISDIR(identity[2]),'retained source root FD identity')
 named=os.open('/held',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:need(R.identity(os.fstat(named))==identity and R.mount_id(named)==prepared.mount,'original named source and retained descriptor must remain identical')
 finally:os.close(named)
 selected=[]
 for point in(work,out):
  fd=os.open(point,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:
   s=os.fstat(fd);need(stat.S_ISDIR(s.st_mode)and s.st_uid==0 and not stat.S_IMODE(s.st_mode)&0o022 and s.st_dev!=identity[0]and not os.fstatvfs(fd).f_flag&os.ST_RDONLY,'separate owned RW work/output filesystem');selected.append(dict(path=str(point),identity=list(R.identity(s)),mount=R.mount_id(fd)))
  finally:os.close(fd)
 need(selected[0]['identity'][:2]!=selected[1]['identity'][:2]and not Path(work).is_relative_to(out)and not Path(out).is_relative_to(work),'disjoint work/output directories')
 need(R.mount_table()==prepared.mounts,'exact pinned mount inventory');return dict(status='LIVE_KERNEL_ATTESTED_PRE_DROP_NOT_LIFECYCLE_ACCEPTANCE',nonce=value['nonce'],root_identity=list(identity),source_mount=prepared.mount,verity=prepared.verity,work=selected[0],out=selected[1])


def prepare_pid1(value):
 """Requires existing trusted private /dev bootstrap; no implicit host fallback."""
 value=selection(value);dm.pid1();need(os.uname().release==value['kernel']['release'],'actual fresh selected kernel release')
 need(all(Path(p).is_dir()and not Path(p).is_symlink()and not os.path.ismount(p)and not any(Path(p).iterdir())for p in('/held','/volume')),'fresh reserved mount points')
 source=dm.block('/dev/vdc',value['image']['bytes'],True);hashdev=dm.block('/dev/vdd',value['tree']['bytes'],True);need(source!=hashdev,'distinct source/hash blocks')
 device=dm.Device(value['nonce']);mounted=False
 try:
  dev=device.create(value['tree'],source,hashdev);node=Path('/dev/gnu-source-verity');need(not node.exists()and not node.is_symlink(),'fresh owned DM node');os.mknod(node,stat.S_IFBLK|0o600,dev)
  try:dm.block(node,value['image']['bytes'],True);mount(node,'/held','ext4',15,'noload');mounted=True
  finally:node.unlink()
  workdev=dm.block('/dev/vdb',24*1024**3,False);need(workdev not in(source,hashdev,dev),'distinct writable work block device')
  mount('/dev/vdb','/volume','ext4',6,'')
  for name in ('work','out'):
   point=Path('/volume')/name;info=point.lstat();need(stat.S_ISDIR(info.st_mode)and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700 and not any(point.iterdir()),'fresh owned original work/output directories');mount(point,Path('/')/name,None,4096,None)
  umount('/volume');retire_bootstrap_dev();mount('tmpfs','/dev','tmpfs',2,'size=1m,mode=0755')
  for name,minor in(('null',3),('zero',5),('random',8),('urandom',9)):os.mknod(Path('/dev')/name,stat.S_IFCHR|0o666,os.makedev(1,minor));os.chmod(Path('/dev')/name,0o666)
  Path('/dev/mapper').mkdir(mode=0o700);os.mknod('/dev/mapper/control',stat.S_IFCHR|0o600,os.makedev(10,236))
  need({p.name for p in Path('/dev').iterdir()}=={'null','zero','random','urandom','mapper'},'raw device retirement must precede retained-root preparation')
  need({p.name for p in Path('/dev/mapper').iterdir()}=={'control'},'only temporary exact DM control node')
  prepared=R.Prepared('/held',value['tree']);attest(prepared,Path('/work'),Path('/out'),value)
  Path('/dev/mapper/control').unlink();Path('/dev/mapper').rmdir()
  return device,prepared
 except BaseException as e:
  # Never remove active/unknown-use mappings or mounts speculatively.
  e.add_note('BOOTSTRAP_FAILED_RETAIN_OWNED_DISKS_UNTIL_CHILD_ABSENCE_AND_MOUNT_RETIREMENT');raise


def install_worker_fences():
 # Original source-owned IPC and mount-topology filters; no original apply()
 # call because that function would retain SYS_ADMIN in its old capability mask.
 import ast,errno,importlib.util
 rows=obj(ordinary(Path(__file__).with_name('runtime-pins.json'),65536));raws={name:ordinary(name,256*1024)for name in rows}
 for name,raw in raws.items():need(pin(raw)==rows[name],'exact original IPC/mount-fence source')
 spec=importlib.util.spec_from_file_location('_verity_held_ipc','/source/scripts/install/local_transaction.py');held=importlib.util.module_from_spec(spec);spec.loader.exec_module(held);held.block_service_ipc(architecture='aarch64')
 tree=ast.parse(raws['/installed16k/sandbox.py']);names={'ENOSYS_CALLS','EPERM_CALLS'};nodes=[n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id in names for t in n.targets)or isinstance(n,ast.FunctionDef)and n.name=='filter_rows'];space=dict(errno=errno);exec(compile(ast.Module(body=nodes,type_ignores=[]),'<whole-held-GNU-mount-fence>', 'exec'),space)
 class F(ctypes.Structure):_fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
 class P(ctypes.Structure):_fields_=[('length',ctypes.c_ushort),('filters',ctypes.POINTER(F))]
 data=space['filter_rows']();filters=(F*len(data))(*(F(*r)for r in data));program=P(len(data),filters);need(ctypes.CDLL(None,use_errno=True).prctl(22,2,ctypes.byref(program),0,0)==0,'original mount topology fence')
 need(R.status()['Seccomp'].strip()=='2','actual original worker syscall fences')


def activate_in_child(prepared,value):
 value=selection(value);need(os.getpid()!=1 and os.getppid()==1,'direct PID1 child activation only');need({p.name for p in Path('/dev').iterdir()}=={'null','zero','random','urandom'},'no worker raw/control device paths')
 for path in Path('/proc/self/fd').iterdir():
  try:info=path.stat()
  except FileNotFoundError:continue
  need(not stat.S_ISBLK(info.st_mode),'no worker inherited raw block descriptor')
 install_worker_fences();drop_worker();prepared.activate();receipt=attest(prepared,Path('/work'),Path('/out'),value);receipt.update(status='LIVE_NO_ADMIN_SOURCE_CONTEXT_ONLY_NOT_GNU_LIFECYCLE',caps=R.restricted(R.status()),fastpath='NOT_ACTIVATED');return receipt

if __name__=='__main__':
 # The source-owned template is NULL; refusal happens before PID1/devices/IO.
 selection(obj(ordinary(Path(__file__).with_name('selection-template.json'),65536)))
 raise SystemExit('Source-only mechanism: integrate trusted PID1 stages before executing')
