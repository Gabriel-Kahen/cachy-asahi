# SPDX-License-Identifier: MIT
"""Exact public cache DATA in two explicit original-lock modes; no authentication."""
import argparse,hashlib,json,os,stat,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
LOCKS={'native248':dict(bytes=328101,sha256='beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'),'desktop574':dict(bytes=623664,sha256='b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9')}
IDENTITY=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def ordinary(path):
 p=Path(path).absolute();need(not any(q.is_symlink()for q in(p,*p.parents)),'ordinary cache/input ancestry');return p
def tick(deadline):need(time.monotonic()<deadline,'caller original cache deadline exhausted')
def read(path,cap=128*1024**2):
 p=ordinary(path);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded singlelink public DATA');raw=os.read(fd,a.st_size+1)
  while len(raw)<a.st_size:
   part=os.read(fd,a.st_size+1-len(raw))
   if not part:break
   raw+=part
  need(len(raw)==a.st_size and IDENTITY(a)==IDENTITY(os.fstat(fd))==IDENTITY(p.lstat()),'stable whole public DATA');return raw
 finally:os.close(fd)
def exact(path,want,deadline,owned):
 p=ordinary(path);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size==want['bytes']and(not owned or a.st_uid==os.getuid()),'owned ordinary exact cache leaf');h=hashlib.sha256();size=0
  while True:
   tick(deadline);raw=os.read(fd,1024**2)
   if not raw:break
   size+=len(raw);need(size<=a.st_size,'bounded cache leaf');h.update(raw)
  need(size==want['bytes']and h.hexdigest()==want['sha256']and IDENTITY(a)==IDENTITY(os.fstat(fd))==IDENTITY(p.lstat()),'whole stable cache inode metadata bytes');return list(IDENTITY(a))
 finally:os.close(fd)
def rows(lock):
 out={}
 def add(n,size,sha):
  need(type(n)is str and Path(n).name==n and n not in('.','..')and n not in out,'unique simple original input');out[n]=dict(bytes=size,sha256=sha)
 for r in lock['packages']:
  add(r['filename'],r['size'],r['sha256']);add(r['filename']+'.sig',r['signature_size'],r['signature_sha256'])
 package=dict(out);r=lock['rootfs'];add(r['filename'],r['size'],r['sha256']);add(r['filename']+'.sig',r['signature_size'],r['signature_sha256'])
 for r in lock['keyring_files']:add(r['filename'],r['size'],r['sha256'])
 return package,out

def join(cache,packages,selected,allowed,deadline):
 cache=ordinary(cache);info=cache.lstat();need(stat.S_ISDIR(info.st_mode)and info.st_uid==os.getuid()and stat.S_IMODE(info.st_mode)==0o700,'existing caller-owned0700 cache required');directory=list(IDENTITY(info)[:6]);before={}
 for p in cache.iterdir():
  need(p.name in allowed,'foreign existing cache input refused');before[p.name]=exact(p,allowed[p.name],deadline,True)
 for n,want in selected.items():exact(Path(packages)/n,want,deadline,False)
 for n,want in selected.items():
  if n in before:continue
  tick(deadline);body=read(Path(packages)/n);need(pin(body)==want,'exact bytes rechecked before copy');fd=os.open(cache/n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  with os.fdopen(fd,'wb')as stream:stream.write(body);stream.flush();os.fsync(stream.fileno())
 expected=dict({n:allowed[n]for n in before},**selected);need({p.name for p in cache.iterdir()}==set(expected),'only exact selected additions');after={n:exact(cache/n,want,deadline,True)for n,want in expected.items()};need(all(after[n]==v for n,v in before.items()),'all previous inode metadata bytes preserved');now=cache.lstat();need(list(IDENTITY(now)[:6])==directory,'same existing cache directory identity');tick(deadline)
 return dict(before_files={n:allowed[n]for n in before},after_files=expected,before_identity=before,after_previous_identity={n:after[n]for n in before},directory_identity=directory,after_directory_identity=list(IDENTITY(now)[:6]),mode=0o700,owner='CALLER_UID',added=len(set(selected)-set(before)),fresh_cache=False,all_previous_inode_metadata_bytes_unchanged=True)

def seed(lock,cache,mode,deadline):
 need(mode in LOCKS,'explicit original native248 or desktop574 mode');tick(deadline);raw=read(lock,1024**2);need(pin(raw)==LOCKS[mode],'exact complete selected original input lock');selected_lock=json.loads(raw);package,allowed=rows(selected_lock);need(len(selected_lock['packages'])==({'native248':248,'desktop574':574}[mode]),'exact original package membership')
 native=read(HERE/'native-inputs.lock.json',1024**2);desktop=read(HERE/'desktop574-inputs.lock.json',1024**2);need(pin(native)==LOCKS['native248']and pin(desktop)==LOCKS['desktop574'],'both whole original locks');native_packages,native_allowed=rows(json.loads(native));desktop_packages,desktop_allowed=rows(json.loads(desktop));need(all(desktop_allowed.get(n)==v for n,v in native_allowed.items()),'all original native248 package/rootfs/keyring pins join unchanged574');allowed=desktop_allowed;index=json.loads(read(HERE/'index.json',2*1024**2));all_inputs=index['files']
 need(index==dict(original_lock=LOCKS['native248'],original574_lock=LOCKS['desktop574'],files=all_inputs)and len(all_inputs)==1148 and all_inputs==desktop_packages and all(all_inputs.get(n)==v for n,v in native_packages.items()),'entire original5741148 and native248496 exact package subset')
 need({p.name for p in(HERE/'packages').iterdir()}==set(all_inputs),'closed1148 public archive/signature payload')
 for n,want in all_inputs.items():exact(HERE/'packages'/n,want,deadline,False)
 chosen=native_packages if mode=='native248'else all_inputs;need(all(package.get(n)==v for n,v in chosen.items()),'all selected package inputs join exact original mode lock');receipt=join(cache,HERE/'packages',chosen,allowed,deadline)
 return dict(schema=1,status='EXACT_PUBLIC_CACHE_INPUTS_JOINED_NOT_AUTHENTICATED',mode=mode,original_lock=LOCKS[mode],inputs=chosen,cache=receipt,versions='UNCHANGED',trust='ORIGINAL_FULL_SIGNATURE_METADATA_ACQUIRE_NATIVE_AND_PACKAGE_CHECKS_REQUIRED',actual_authority=False)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--lock',type=Path,required=True);p.add_argument('--cache',type=Path,required=True);p.add_argument('--mode',choices=tuple(LOCKS),required=True);p.add_argument('--deadline',type=float,required=True);a=p.parse_args();print(json.dumps(seed(a.lock,a.cache,a.mode,a.deadline),sort_keys=True))
