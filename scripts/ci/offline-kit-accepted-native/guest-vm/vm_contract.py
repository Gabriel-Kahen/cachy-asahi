# SPDX-License-Identifier: MIT
"""Finite software-VM authority; no imports admit actors or hardware."""
import base64,hashlib,importlib.util,json,os,re,stat,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;LANE=HERE.parent;ROOT=LANE.parents[2]
PURPOSE='KIT77_SOFTWARE_ARM_GUEST_FULL_LIFECYCLE_V1';OPERATION='kit-vm-lifecycle'
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
 p=decode(read(HERE/'accepted-policy.json'));need(p['schema']==1 and p['scope']=='ORIGINAL_ACCEPTED_ARCHIVES_AND_SIGNATURES_WITH_CURRENT_PUBLIC_TEST_CERTIFICATES','finite accepted input policy')
 need(type(p['files'])is dict and len(p['files'])==23 and re.fullmatch('[a-f0-9]{40}',p['source']or'')and re.fullmatch('[a-f0-9]{40}',p['tree']or''),'exact reviewed public carrier');return p

def key_preflight(directory,now=None,cover=18610):
 p=accepted_policy();K=load('public_keys',HERE/'public_keys.py');now=int(time.time())if now is None else now
 need(type(now)is int and type(cover)is int and cover>=BUDGET['overall'],'current real clock and full route cover');keys={}
 for short in('maintenance','diagnostics'):
  name=short+'.TEST-public.asc';raw=read(Path(directory)/name,65536);need(pin(raw)=={k:p['files'][name][k]for k in('bytes','sha256')},'exact reviewed certificate')
  k=K.certificate(raw);need(k['fingerprint']==p['fingerprints'][short],'original accepted signing fingerprint preserved')
  need(k['created']<=now and k['expires']>=now+cover,'EXPIRED_OR_TOO_SHORT_ORIGINAL_TEST_CERTIFICATE_'+short);keys[short]=dict(k,public_certificate=pin(raw))
 return dict(status='PUBLIC_CERTIFICATE_TIME_WINDOW_CHECKED_CRYPTO_STILL_REQUIRED',observed_epoch=now,required_cover_seconds=cover,keys=keys,cryptographic_verification='ORIGINAL_GPGV_MUST_RUN_IN_GUEST',acceptance=False)
