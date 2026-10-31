# SPDX-License-Identifier: MIT
"""Finite software-VM authority; no imports admit actors or hardware."""
import base64,hashlib,importlib.util,json,os,re,stat,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;LANE=HERE.parent.parent;ROOT=LANE.parents[2]
PURPOSE='KIT138_FRESH_ROOT_TEST_SOFTWARE_ARM_GUEST_FULL_LIFECYCLE_V1';OPERATION='kit-vm-fresh-test-lifecycle'
BUDGET=dict(overall=15840,prepare=2400,qemu=10380,export=1200,cleanup=300,kit=4500,produce=300,receive=300,candidate=1500)
NATIVE_OWNER_SHA='c5bd5168155af5ca8db22ac3f6581207c588e48bd8dfa98629408385c8705b5e'
LOCK='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
def need(v,s):
 if not v:raise ValueError(s)
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def decode(b):
 def pairs(rows):
  d={}
  for k,v in rows:need(k not in d,'duplicate JSON key');d[k]=v
  return d
 return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def read(p,cap=16*1024**2):
 p=Path(p);need(p.is_absolute()and not any(q.is_symlink()for q in(p,*p.parents)),'ordinary absolute path')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<=s.st_size<=cap,'bounded ordinary file');raw=b''
  while chunk:=os.read(fd,65536):raw+=chunk;need(len(raw)<=s.st_size,'input grew')
  key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  need(len(raw)==s.st_size and key(s)==key(os.fstat(fd))==key(p.lstat()),'stable descriptor/path input');return raw
 finally:os.close(fd)
def row(p):
 p=Path(p);s=p.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and not p.is_symlink(),'ordinary hash input')
 with p.open('rb')as f:d=hashlib.file_digest(f,'sha256').hexdigest()
 need((s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns)==(p.stat().st_dev,p.stat().st_ino,p.stat().st_size,p.stat().st_mtime_ns),'stable streaming input');return dict(bytes=s.st_size,sha256=d)
def save(p,v):
 p=Path(p)
 with p.open('x')as f:f.write(encoded(v).decode())
 p.chmod(0o600)
def update(p,v):Path(p).write_bytes(encoded(v));Path(p).chmod(0o600)
def fresh(p):
 p=Path(p);need(p.is_absolute()and not os.path.lexists(p)and not any(q.is_symlink()for q in p.parents),'fresh owned output');p.mkdir(mode=0o700);return p

def load(name,path,expected=None):
 raw=read(Path(path))
 if expected is not None:need(pin(raw)==expected,'exact helper source')
 spec=importlib.util.spec_from_file_location('_kit77_vm_'+name,path);m=importlib.util.module_from_spec(spec);exec(compile(raw,str(path),'exec'),m.__dict__);return m

def original():return load('original_owner',LANE/'owner.py',dict(bytes=42654,sha256=NATIVE_OWNER_SHA))
def selected(env=None):
 env=os.environ if env is None else env;need(env.get('NATIVE_OPERATION')==OPERATION,'explicit software VM operation required');return OPERATION

def disk_serial(nonce,role):
 """20 ASCII bytes encoding128 digest bits, bound to role and the full128-bit nonce."""
 need(type(nonce)is str and re.fullmatch('[a-f0-9]{32}',nonce)and role in('boot','data'),'exact full nonce and block role')
 raw=hashlib.sha256(b'cachy-asahi/core7/virtio-blk/serial-v1\0'+role.encode('ascii')+b'\0'+bytes.fromhex(nonce)).digest()[:16]
 value=base64.b85encode(raw).decode('ascii')
 need(len(value)==20 and all(33<=ord(c)<=126 and c not in ',\0'for c in value),'literal20-byte virtio block property')
 return value

def qemu(image,boot,data,nonce,epoch):
 need(type(epoch)is int and 1700000000<=epoch<2**32,'explicit current launcher UTC epoch')
 return ['/usr/bin/qemu-system-aarch64','-nodefaults','-machine','virt','-accel','tcg,thread=multi','-cpu','max','-smp','2','-m','4096','-nic','none','-display','none','-monitor','none','-no-reboot','-kernel',str(image),'-append','console=ttyAMA0 root=/dev/vda rw rootwait init=/init-kit77 panic=1 arm64.nomops caa_core_vm='+nonce+' caa_core_phase=1 caa_core_realtime='+str(epoch)+' kit77_vm='+nonce,'-drive','if=none,id=boot,format=raw,file='+str(boot),'-device','virtio-blk-pci,drive=boot,serial='+disk_serial(nonce,'boot'),'-drive','if=none,id=data,format=raw,file='+str(data),'-device','virtio-blk-pci,drive=data,serial='+disk_serial(nonce,'data'),'-serial','stdio']

def source_rows(manifest,map_sha):
 rows=dict(manifest['files']);mapname='scripts/ci/offline-kit-accepted-native/source-map.json'
 for n in(mapname,'.github/workflows/native-arm-build.yml','.github/workflows/native-arm-offline-kit-accepted.yml'):rows[n]=dict(row(ROOT/n),mode=stat.S_IMODE((ROOT/n).stat().st_mode))
 need(rows[mapname]['sha256']==map_sha,'map source authority');return rows

def accepted_policy():
 p=decode(read(HERE/'accepted-policy.json'));need(type(p)is dict and set(p)=={'schema','source','ref','tree','files','history_files','current_files','profile','fingerprints'}and type(p['schema'])is int and p['schema']==2,'finite fresh TEST carrier policy')
 need(all(type(p[n])is str and re.fullmatch('[a-f0-9]{40}',p[n])for n in('source','tree'))and type(p['ref'])is str and p['ref'].startswith('codex/'),'actual public carrier selectors required')
 need(type(p['profile'])is dict and p['profile']and type(p['fingerprints'])is dict and set(p['fingerprints'])=={'maintenance','diagnostics'}and all(type(x)is str and re.fullmatch('[A-F0-9]{40}',x)for x in p['fingerprints'].values()),'actual fresh profile and fingerprints required')
 need(all(type(p[n])is dict and len(p[n])==count for n,count in [('files',47),('history_files',23),('current_files',23)]),'exact47 carrier cardinality')
 need(set(p['files'])=={'history/'+n for n in p['history_files']}|{'current/'+n for n in p['current_files']}|{'profile.json'}and all(p['files'][role+'/'+n]==r for role in('history','current')for n,r in p[role+'_files'].items()),'exact historical/current47 policy topology')
 for n,r in p['files'].items():need(type(n)is str and not n.startswith('/')and all(x not in('','..','.')for x in n.split('/'))and type(r)is dict and set(r)=={'bytes','sha256','mode'}and type(r['bytes'])is int and 0<=r['bytes']<=16*1024**2 and type(r['mode'])is int and r['mode']==420 and type(r['sha256'])is str and re.fullmatch('[a-f0-9]{64}',r['sha256']),'bounded ordinary public policy rows')
 return p

def key_preflight(directory,now=None,cover=18610):
 p=accepted_policy();now=int(time.time())if now is None else now
 need(type(now)is int and type(cover)is int and cover>=BUDGET['overall'],'current real clock and full route cover');F=load('fresh_profile',HERE/'fresh_profile.py');directory=Path(directory)
 return(F.validate_public if directory.name=='accepted-public'else F.validate_carrier)(directory,p,now,cover)

def carrier_namespace(directory,rows):
 directory=Path(directory);need(directory.is_dir()and not any(p.is_symlink()for p in(directory,*directory.parents)),'ordinary public carrier root');actual=set();dirs=set();count=0;expected={p.as_posix()for n in rows for p in Path(n).parents if p!=Path('.')}
 for folder,children,files in os.walk(directory,followlinks=False):
  for name in tuple(children):
   q=Path(folder)/name;count+=1;need(count<=4096,'bounded carrier namespace')
   if Path(folder)==directory and name=='.git':need(not q.is_symlink(),'ordinary checkout metadata');children.remove(name);continue
   need(not q.is_symlink()and q.is_dir(),'ordinary public input directory');dirs.add(q.relative_to(directory).as_posix())
  for name in files:
   q=Path(folder)/name;count+=1;need(count<=4096,'bounded carrier namespace');need(not q.is_symlink()and q.is_file(),'ordinary public input leaf');actual.add(q.relative_to(directory).as_posix())
 need(actual==set(rows)and dirs==expected,'exact47 public input namespace');return rows
