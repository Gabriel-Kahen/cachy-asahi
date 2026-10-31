# SPDX-License-Identifier: MIT
"""Exact DATA preparation before unchanged frozen574 archive32/20/8 transports."""
import hashlib,json,math,os,stat,time
from pathlib import Path
ROOT_PINS={'LICENSE':(1081,'51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7'),'NOTICE.md':(1018,'6a3649fc4e0d0ee18a7399ada57d9fa8c1b8c97232ba46efd5da511c72a74141'),'native-inputs.lock.json':(328101,'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'),'desktop574-inputs.lock.json':(623664,'b2a234c76c3a820382238023203a8b699a503153f63b938376fd16433c4d90f9'),'seed.py':(6658,'76b787fa71b121ec1bf83b86e4d5db849913614bc90e03239b869d7061af1db4'),'index.json':(184344,'51a53c9e0d9eab1728f350f9ab8d3d7b8932891ab0ed68c7876a1440166ff486')}
POLICIES={32:'4f6ce49214422579f1cc448ff95d9f311cbfaf47a0d0c4f32d828c9edf843585',20:'1f966afe0c24bb9a928154cb0638a8bb78292c799ffd544132633caddf6217ae',8:'2b21c05d30a9c5efd2f717cfa8475c9de3150d7729f710b348b70a84f5b16e20'}
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
 carrier=Path(carrier);ordinary(carrier,True);need({p.name for p in carrier.iterdir()}- {'.git'}==set(ROOT_PINS)|{'packages'},'closed complete1154 carrier')
 for n,(size,sha)in ROOT_PINS.items():exact(carrier/n,dict(bytes=size,sha256=sha),deadline)
 before=ordinary(carrier/'index.json');raw=(carrier/'index.json').read_bytes();need(before==ordinary(carrier/'index.json')and(len(raw),hashlib.sha256(raw).hexdigest())==ROOT_PINS['index.json'],'stable hard-pinned whole index');index=json.loads(raw);rows=index['files'];need(len(rows)==1148 and {p.name for p in(carrier/'packages').iterdir()}==set(rows),'closed1148 exact original payload');ordinary(carrier/'packages',True)
 for n,row in rows.items():need(Path(n).name==n and n not in('.','..'),'simple exact input name');exact(carrier/'packages'/n,row,deadline)
 return rows

def prefill(carrier,cache,v,deadline):
 tick(deadline);n=len(v['files']);raw=(json.dumps(v,sort_keys=True,indent=2)+'\n').encode();need(n in POLICIES and hashlib.sha256(raw).hexdigest()==POLICIES[n],'exact whole held32/20/8 policy returned by original validator');rows=verify(carrier,deadline);selected={name:{k:r[k]for k in('bytes','sha256')}for name,r in v['files'].items()};need(all(rows.get(name)==row for name,row in selected.items()),'whole policy joins immutable original574 payload')
 cache=Path(cache);need(cache.is_absolute()and not os.path.lexists(cache),'fresh original legacy-cache namespace required');parent=ordinary(cache.parent,True);need(parent[3]==os.getuid(),'caller-owned cache parent');cache.mkdir(mode=0o700);directory=ordinary(cache,True);need(directory[3]==os.getuid()and stat.S_IMODE(directory[2])==0o700,'private0700 caller cache')
 for name,row in selected.items():
  tick(deadline);fd=os.open(cache/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  try:exact(Path(carrier)/'packages'/name,row,deadline,fd);os.fsync(fd)
  finally:os.close(fd)
  exact(cache/name,row,deadline)
 need({p.name for p in cache.iterdir()}==set(selected)and ordinary(cache,True)[:6]==directory[:6],'exact subset only; same owned cache directory');tick(deadline)
 return dict(status='EXACT_POLICY_CACHE_PREFILLED_NOT_AUTHENTICATED',files=selected,requests=0,index='NOT_CREATED_ORIGINAL_CLI_REQUIRED',original_inputs=v['original_inputs'],actual_authority=False)
