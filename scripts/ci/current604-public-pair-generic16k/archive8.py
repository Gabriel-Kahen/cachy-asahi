#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact frozen574 archive bytes only. No version, signature or trust substitution."""
import argparse,email.utils,hashlib,json,os,re,signal,stat,time,urllib.error,urllib.parse,urllib.request,uuid
from pathlib import Path
HERE=Path(__file__).resolve().parent
SECONDS=180;PACE=2;MAX_REQUESTS=48;MAX_RETRY_AFTER=30;TOTAL=2220315

def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def tick(deadline):need(time.monotonic()<deadline,'archive8 prefetch deadline')
def ordinary(path,directory=False,private=False):
 p=Path(path);need(p.is_absolute()and not any(q.is_symlink()for q in(p,*p.parents)),'ordinary archive8 path');s=p.lstat();need(s.st_uid==os.getuid()and(stat.S_ISDIR(s.st_mode)if directory else stat.S_ISREG(s.st_mode)and s.st_nlink==1),'caller-owned ordinary archive8 object')
 if private:need(stat.S_IMODE(s.st_mode)==0o700,'private0700 archive8 cache')
 return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read(path,cap):
 before=ordinary(path);need(0<before[6]<=cap,'bounded archive8 DATA');raw=Path(path).read_bytes();need(len(raw)==before[6]and before==ordinary(path),'archive8 DATA drift');return raw
def policy(path,inputs):
 v=json.loads(read(path,65536));raw=read(inputs,1024**2);need(set(v)=={'schema_version','purpose','archive_date','archive_host','files','original_inputs'}and v['schema_version']==1 and v['purpose']=='EXACT_FROZEN574_8_ROTATED_INPUT_BYTES_NO_VERSION_OR_TRUST_CHANGE'and v['archive_date']=='2026/10/13'and v['archive_host']=='pkgmirror.sametimetomorrow.net'and pin(raw)==v['original_inputs'],'exact frozen574 archive policy/whole original lock')
 lock=json.loads(raw);rows=lock['packages'];expected={}
 for r in rows:
  for suffix,size,digest in(('',r['size'],r['sha256']),('.sig',r['signature_size'],r['signature_sha256'])):expected[r['filename']+suffix]=dict(bytes=size,sha256=digest)
 need(type(v['files'])is dict and len(v['files'])==8 and sum(r['bytes']for r in v['files'].values())==TOTAL,'exact8 bounded archive membership')
 for n,r in v['files'].items():
  need(type(n)is str and re.fullmatch('[A-Za-z0-9._+@:~-]{1,255}',n)and type(r)is dict and set(r)=={'bytes','sha256','url'}and type(r['bytes'])is int and 0<r['bytes']<=80*1024**2 and re.fullmatch('[0-9a-f]{64}',r['sha256'])and {k:r[k]for k in('bytes','sha256')}==expected.get(n),'exact original package/signature bytes')
  u=urllib.parse.urlsplit(r['url']);need(u.scheme=='https'and u.netloc==v['archive_host']and u.path in tuple('/aarch64/repos/2026/10/'+day+'/'+repo+'/'+n for day in('13',)for repo in('core','extra'))and not(u.query or u.fragment or u.username or u.password),'fixed credential-free archive URL, no redirect')
 need(all(n+'.sig'in v['files']for n in v['files']if not n.endswith('.sig'))and sum(not n.endswith('.sig')for n in v['files'])==4,'four whole package/signature pairs');return v

def digest_file(path,row,deadline=None):
 before=ordinary(path);need(before[6]==row['bytes'],'archive8 existing size differs');h=hashlib.sha256();count=0
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  need((os.fstat(fd).st_dev,os.fstat(fd).st_ino)==before[:2],'archive8 opened identity')
  while True:
   if deadline is not None:tick(deadline)
   b=os.read(fd,1024**2)
   if not b:break
   count+=len(b);need(count<=row['bytes'],'archive8 existing growth');h.update(b)
 finally:os.close(fd)
 need(before==ordinary(path)and count==row['bytes']and h.hexdigest()==row['sha256'],'archive8 existing hash/identity differs');return before

def cache_root(cache,rows,create=False):
 cache=Path(cache);need(cache.is_absolute()and not cache.is_symlink(),'explicit archive8 cache')
 if create and not cache.exists():ordinary(cache.parent,True);cache.mkdir(mode=0o700)
 identity=ordinary(cache,True,True);need({p.name for p in cache.iterdir()}<=set(rows)|{'archive8-index.json'},'foreign archive8 cache entry');return identity[:2]

def checked_index(cache,v):
 value=json.loads(read(Path(cache)/'archive8-index.json',65536));expected={n:{k:r[k]for k in('bytes','sha256')}for n,r in v['files'].items()}
 need(type(value)is dict and set(value)=={'schema_version','status','original_inputs','files','bytes','requests','reused','seconds_limit'}and type(value['schema_version'])is int and value['schema_version']==1 and value['status']=='EXACT_FROZEN574_ARCHIVE8_BYTES_ONLY_NOT_NATIVE_ACCEPTANCE'and value['files']==expected and value['original_inputs']==v['original_inputs']and value['bytes']==TOTAL and value['seconds_limit']==SECONDS and type(value['requests'])is int and 0<=value['requests']<=MAX_REQUESTS and type(value['reused'])is int and 0<=value['reused']<=8,'exact whole archive8 index DATA');return value

class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise ValueError('archive8 redirect refused')
def opener():return urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
def retry_delay(value,now=None):
 need(type(value)is str and 0<len(value)<=128,'bounded Retry-After required')
 if re.fullmatch('[0-9]{1,3}',value):delay=int(value)
 else:
  when=email.utils.parsedate_to_datetime(value);need(when.tzinfo is not None,'Retry-After timezone');delay=max(0,when.timestamp()-(time.time()if now is None else now))
 need(0<=delay<=MAX_RETRY_AFTER,'Retry-After exceeds finite prefetch bound');return delay

def prefetch(cache,v,open_url=None,seconds=SECONDS):
 need(seconds==SECONDS,'one exact separate180s prefetch profile');deadline=time.monotonic()+SECONDS;cache=Path(cache);identity=cache_root(cache,v['files'],True);op=open_url or opener().open;requests=0;last=None;downloaded=0;retry_wait=0;reused=0
 if os.path.lexists(cache/'archive8-index.json'):checked_index(cache,v)
 for name,row in sorted(v['files'].items()):
  tick(deadline);target=cache/name
  if os.path.lexists(target):digest_file(target,row,deadline);reused+=1;continue
  failures=0
  while True:
   tick(deadline);need(requests<MAX_REQUESTS,'archive8 request count bound')
   delay=0 if last is None else max(0,PACE-(time.monotonic()-last));need(time.monotonic()+delay<deadline,'archive8 pacing deadline')
   if delay:time.sleep(delay)
   last=time.monotonic();requests+=1;partial=cache/('.archive8-'+uuid.uuid4().hex);owned=None
   try:
    with op(urllib.request.Request(row['url'],headers={'User-Agent':'cachy-asahi-frozen574-exact8/1','Accept-Encoding':'identity'}),timeout=min(15,deadline-time.monotonic()))as response:
     need(response.status==200 and response.geturl()==row['url'],'exact200 archive response without redirects');length=response.headers.get('Content-Length');need(length is None or length==str(row['bytes']),'archive8 HTTP length differs');need(response.headers.get('Content-Encoding','identity')=='identity','archive8 encoded body refused')
     fd=os.open(partial,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);s=os.fstat(fd);owned=(s.st_dev,s.st_ino);h=hashlib.sha256();count=0
     try:
      while True:
       tick(deadline);b=response.read(min(1024**2,row['bytes']+1-count))
       if not b:break
       count+=len(b);downloaded+=len(b);need(count<=row['bytes']and downloaded<=TOTAL,'archive8 body/aggregate output bound');h.update(b)
       view=memoryview(b)
       while view:view=view[os.write(fd,view):]
      need(count==row['bytes']and h.hexdigest()==row['sha256'],'archive8 body pin differs');os.fsync(fd)
     finally:os.close(fd)
    need(ordinary(partial)[:2]==owned and ordinary(cache,True,True)[:2]==identity,'archive8 partial/cache identity');os.link(partial,target,follow_symlinks=False);partial.unlink();owned=None;break
   except urllib.error.HTTPError as error:
    code=error.code;value=error.headers.get('Retry-After');error.close();need(code==429 and failures<2,'archive8 HTTP refusal/no generic retry');wait=retry_delay(value);retry_wait+=wait;need(retry_wait<=60 and time.monotonic()+wait<deadline,'archive8 Retry-After deadline');time.sleep(wait);failures+=1
   finally:
    if owned is not None:
     need(ordinary(partial)[:2]==owned,'owned archive8 partial drift; retained');partial.unlink()
 for name,row in v['files'].items():digest_file(cache/name,row,deadline)
 need(cache_root(cache,v['files'])==identity,'archive8 cache lifetime drift');index=dict(schema_version=1,status='EXACT_FROZEN574_ARCHIVE8_BYTES_ONLY_NOT_NATIVE_ACCEPTANCE',original_inputs=v['original_inputs'],files={n:{k:r[k]for k in('bytes','sha256')}for n,r in v['files'].items()},bytes=TOTAL,requests=requests,reused=reused,seconds_limit=SECONDS)
 # The index is DATA only. Existing indexes must already declare this same byte set.
 dest=cache/'archive8-index.json'
 if dest.exists():
  checked_index(cache,v)
 else:
  with dest.open('xb')as f:f.write(encoded(index))
 return index

def seed_exact(cache,deps,v):
 cache=Path(cache);deps=Path(deps);identity=cache_root(cache,v['files']);ordinary(deps,True);need(cache!=deps and not(cache.is_relative_to(deps)or deps.is_relative_to(cache)),'disjoint producer/archive caches');checked_index(cache,v)
 for name,row in v['files'].items():
  source=cache/name;before=digest_file(source,row);target=deps/name
  if os.path.lexists(target):digest_file(target,row);continue
  partial=deps/('.archive8-'+uuid.uuid4().hex);owned=None
  try:
   fd=os.open(partial,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);st=os.fstat(fd);owned=(st.st_dev,st.st_ino)
   try:
    with os.fdopen(os.open(source,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC),'rb')as inp:
     need((os.fstat(inp.fileno()).st_dev,os.fstat(inp.fileno()).st_ino)==before[:2],'source opened identity')
     while True:
      b=inp.read(1024**2)
      if not b:break
      view=memoryview(b)
      while view:view=view[os.write(fd,view):]
    os.fsync(fd)
   finally:os.close(fd)
   need(ordinary(source)==before and ordinary(partial)[:2]==owned and cache_root(cache,v['files'])==identity,'archive8 seed identity');digest_file(partial,row);os.link(partial,target,follow_symlinks=False);partial.unlink();owned=None
  finally:
   if owned is not None:
    need(ordinary(partial)[:2]==owned,'owned seed partial drift; retained');partial.unlink()
 return dict(status='EXACT_ORIGINAL8_SEEDED_BEFORE_UNCHANGED_BUILD',files=8,bytes=TOTAL,original_inputs=v['original_inputs'])

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--policy',type=Path,required=True);p.add_argument('--inputs',type=Path,required=True);p.add_argument('--cache',type=Path,required=True);a=p.parse_args();v=policy(a.policy,a.inputs)
 def expired(_signum,_frame):raise TimeoutError('archive8 hard180s deadline')
 previous=signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,SECONDS)
 try:print(json.dumps(prefetch(a.cache,v),sort_keys=True))
 finally:signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
