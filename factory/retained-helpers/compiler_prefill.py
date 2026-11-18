# SPDX-License-Identifier: MIT
"""Exact DATA preparation before unchanged frozen574 archive6 transports."""
import hashlib,json,math,os,stat,time
from pathlib import Path
ROOT_PINS={'LICENSE': (1081, '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7'), 'NOTICE.md': (689, '6d93925f21faf6b1bab202e85d6d1455e8be7d7769ccbbaad2d7900dbbf84cc7'), 'archive6-policy.json': (2036, '4d83dbda592b8b6575d02df65de829226cae3ddffc7268e3d47873ac83f3b322'), 'index.json': (1102, 'cdc98720842d5c09bab34f19d0ca053f12767ddb83b85310ada2a10a4771df74'), 'original-extension.lock.json': (14048, '287b627528f3fd9cf4a63ef3a3bbf269e83f83d35c87dd3b3efd69e91a92a56f')}
POLICIES={6:'4d83dbda592b8b6575d02df65de829226cae3ddffc7268e3d47873ac83f3b322'}
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def need(ok,why):
 if not ok:raise ValueError(why)
def identity(s):return tuple(getattr(s,k)for k in FIELDS)
def tick(deadline):need(type(deadline)in(int,float)and math.isfinite(deadline)and time.monotonic()<deadline,'original caller deadline exhausted')
def ordinary(path,directory=False):
 p=Path(path);need(p.is_absolute()and not any(q.is_symlink()for q in(p,*p.parents)),'ordinary explicit prefill ancestry');s=p.lstat();need(stat.S_ISDIR(s.st_mode)if directory else stat.S_ISREG(s.st_mode)and s.st_nlink==1,'ordinary singlelink prefill object');return identity(s)
def exact(path,row,deadline,copy_to=None):
 tick(deadline);before=ordinary(path);need(before[6]==row['bytes'],'exact prefill size');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK);h=hashlib.sha256();count=0
 try:
  need(identity(os.fstat(fd))==before,'opened exact input identity')
  while True:
   tick(deadline);b=os.read(fd,1024**2)
   if not b:break
   count+=len(b);need(count<=row['bytes'],'bounded prefill input');h.update(b)
   if copy_to is not None:
    view=memoryview(b)
    while view:view=view[os.write(copy_to,view):]
  need(count==row['bytes']and h.hexdigest()==row['sha256']and identity(os.fstat(fd))==ordinary(path)==before,'full stable input bytes and identity');return before
 finally:os.close(fd)
def verify(carrier,deadline):
 carrier=Path(carrier);ordinary(carrier,True);need({p.name for p in carrier.iterdir()}- {'.git'}==set(ROOT_PINS)|{'packages'},'closed complete11 carrier')
 for n,(size,sha)in ROOT_PINS.items():exact(carrier/n,dict(bytes=size,sha256=sha),deadline)
 before=ordinary(carrier/'index.json');raw=(carrier/'index.json').read_bytes();need(before==ordinary(carrier/'index.json')and(len(raw),hashlib.sha256(raw).hexdigest())==ROOT_PINS['index.json'],'stable hard-pinned whole index');index=json.loads(raw);rows=index['files'];need(len(rows)==6 and {p.name for p in(carrier/'packages').iterdir()}==set(rows),'closed6 exact original payload');ordinary(carrier/'packages',True)
 for n,row in rows.items():need(Path(n).name==n and n not in('.','..'),'simple exact input name');exact(carrier/'packages'/n,row,deadline)
 return rows

def prefill(carrier,cache,v,deadline):
 tick(deadline);n=len(v['files']);raw=(json.dumps(v,sort_keys=True,indent=2)+'\n').encode();need(n in POLICIES and hashlib.sha256(raw).hexdigest()==POLICIES[n],'exact whole held6 policy returned by original validator');rows=verify(carrier,deadline);selected={name:{k:r[k]for k in('bytes','sha256')}for name,r in v['files'].items()};need(all(rows.get(name)==row for name,row in selected.items()),'whole policy joins immutable original extension payload')
 cache=Path(cache);need(cache.is_absolute()and not os.path.lexists(cache),'fresh original legacy-cache namespace required');parent=ordinary(cache.parent,True);need(parent[3]==os.getuid(),'caller-owned cache parent');cache.mkdir(mode=0o700);directory=ordinary(cache,True);need(directory[3]==os.getuid()and stat.S_IMODE(directory[2])==0o700,'private0700 caller cache')
 for name,row in selected.items():
  tick(deadline);fd=os.open(cache/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  try:exact(Path(carrier)/'packages'/name,row,deadline,fd);os.fsync(fd)
  finally:os.close(fd)
  exact(cache/name,row,deadline)
 need({p.name for p in cache.iterdir()}==set(selected)and ordinary(cache,True)[:6]==directory[:6],'exact subset only; same owned cache directory');tick(deadline)
 return dict(status='EXACT_POLICY_CACHE_PREFILLED_NOT_AUTHENTICATED',files=selected,requests=0,index='NOT_CREATED_ORIGINAL_CLI_REQUIRED',original_inputs=v['original_inputs'],actual_authority=False)
