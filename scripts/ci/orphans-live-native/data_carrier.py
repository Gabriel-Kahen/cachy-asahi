#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One-fetch immutable archive DATA transport; never execute or Git-checkout DATA."""
import gzip,hashlib,math,os,re,stat,tarfile,time,urllib.request
from pathlib import Path
import contract as C
SOURCE='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'
URL='https://codeload.github.com/Gabriel-Kahen/cachy-asahi/tar.gz/'+SOURCE
PROFILE='scripts/ci/setup6-retained-helpers/carrier-profile.json'
PREFIX='cachy-asahi-'+SOURCE+'/'
CHUNK=1024**2;OVERHEAD=16*1024**2;MAX_SECONDS=1200
need=C.need


def tick(deadline):need(type(deadline) in (int,float) and math.isfinite(deadline) and time.monotonic()<deadline,'carrier DATA deadline exhausted')
def identity(info):return [info.st_dev,info.st_ino,stat.S_IMODE(info.st_mode),info.st_uid,info.st_gid]
def node(info):return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
def ordinary(path,directory=False):
 path=C.safe(Path(path).absolute());info=path.lstat()
 need(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink==1,'ordinary DATA object required')
 need(info.st_uid==os.getuid() and stat.S_IMODE(info.st_mode)==(0o700 if directory else 0o600),'private normalized DATA modes/owner required')
 return info

def expected(root):
 profile=C.read(root/PROFILE);files=profile.get('files')
 need(profile.get('source')==SOURCE and type(files) is dict and len(files)==1154,'complete fixed1154 DATA profile required')
 check_files(files);return profile

def check_files(files):
 need(type(files) is dict and 1<=len(files)<=1154,'bounded DATA file map required')
 for name,row in files.items():
  need(type(name) is str and 0<len(name)<=256 and name not in ('.','packages') and not any(c in name for c in '\r\n\0\\') and not name.startswith('/') and Path(name).as_posix()==name and '..' not in Path(name).parts and str(Path(name).parent) in ('.','packages'),'ordinary complete DATA leaf required')
  need(type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int and 0<=row['bytes']<=128*1024**2 and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']),'exact bounded DATA pin required')
 return sum(row['bytes'] for row in files.values())


class Bounded:
 def __init__(self,stream,cap,deadline):self.stream=stream;self.cap=cap;self.deadline=deadline;self.count=0;self.hashed=hashlib.sha256()
 def read(self,size):
  need(type(size) is int and 0<=size<=CHUNK,'bounded DATA read required');tick(self.deadline);raw=self.stream.read(size);tick(self.deadline)
  need(type(raw) is bytes and len(raw)<=size,'ordinary bounded DATA stream required');self.count+=len(raw);need(self.count<=self.cap,'carrier DATA byte cap');self.hashed.update(raw);return raw


def exact_read(stream,size):
 parts=[];remaining=size
 while remaining:
  raw=stream.read(min(CHUNK,remaining));need(bool(raw),'truncated carrier DATA');parts.append(raw);remaining-=len(raw)
 return b''.join(parts)

def extension(raw):
 result={}
 while raw:
  split=raw.find(b' ');need(0<split<=10 and raw[:split].isdigit(),'ordinary bounded PAX record')
  length=int(raw[:split]);need(split+3<=length<=len(raw) and raw[length-1:length]==b'\n','complete PAX record')
  field=raw[split+1:length-1];key,sep,value=field.partition(b'=');need(sep and key not in result and key in (b'path',b'comment',b'mtime',b'atime',b'ctime'),'unsupported PAX semantics')
  need(b'\0' not in value and len(value)<=4096,'bounded PAX value');result[key]=value.decode('utf8');raw=raw[length:]
 return result


def unpack(response,destination,files,deadline):
 """Validate bounded gzip/tar, exact leaves and closure; normalize rather than extract."""
 tick(deadline);total=check_files(files);destination=C.safe(Path(destination).absolute());need(not os.path.lexists(destination),'new carrier DATA directory required')
 parent=destination.parent.lstat();need(stat.S_ISDIR(parent.st_mode) and parent.st_uid==os.getuid() and not parent.st_mode&0o022,'owned non-writable carrier parent required')
 destination.mkdir(mode=0o700);compressed=Bounded(response,total+OVERHEAD,deadline)
 expanded=Bounded(gzip.GzipFile(fileobj=compressed,mode='rb'),total+OVERHEAD,deadline)
 seen=set();directories=set();pending={};headers=0;global_pax_seen=False
 while True:
  header=exact_read(expanded,512)
  if header==b'\0'*512:
   need(exact_read(expanded,512)==b'\0'*512 and not pending,'complete two-block tar end required')
   while True:
    raw=expanded.read(CHUNK)
    if not raw:break
    need(not raw.strip(b'\0'),'trailing nonzero tar DATA refused')
   break
  headers+=1;need(headers<=2*len(files)+16,'carrier tar header cap')
  member=tarfile.TarInfo.frombuf(header,'utf8','strict');need(0<=member.size<=128*1024**2,'carrier member size cap')
  if member.type in (tarfile.XHDTYPE,tarfile.XGLTYPE,tarfile.GNUTYPE_LONGNAME):
   need(0<member.size<=16384,'bounded tar extension required');body=exact_read(expanded,member.size);padding=exact_read(expanded,(-member.size)%512);need(not padding.strip(b'\0'),'nonzero extension padding')
   if member.type==tarfile.GNUTYPE_LONGNAME:
    need(not pending and body.endswith(b'\0') and b'\0' not in body[:-1],'single bounded long DATA name');pending={b'path':body[:-1].decode('utf8')}
   else:
    values=extension(body)
    if member.type==tarfile.XGLTYPE:
     need(not global_pax_seen and not seen and set(values)<={b'comment'} and values.get(b'comment',SOURCE)==SOURCE,'fixed immutable global DATA comment');global_pax_seen=True
    else:need(not pending and b'comment' not in values,'single file PAX only');pending=values
   continue
  need(member.type in (tarfile.REGTYPE,tarfile.AREGTYPE,tarfile.DIRTYPE) and not member.linkname and not member.sparse,'links/devices/sparse DATA refused')
  name=pending.pop(b'path',member.name);pending={};need(not member.mode&0o7000,'setid/sticky archive DATA modes refused')
  need(name.startswith(PREFIX) or member.isdir() and name==PREFIX.rstrip('/'),'fixed immutable archive root required')
  relative=name[len(PREFIX):].rstrip('/');need(relative in ('','packages') or relative in files,'unexpected carrier DATA leaf/directory')
  need(name in (PREFIX+relative,PREFIX+relative+'/',PREFIX.rstrip('/') if relative=='' else PREFIX+relative) and not name.startswith('/') and '..' not in Path(name).parts,'canonical archive DATA name')
  if member.isdir():
   need(relative in ('','packages') and member.size==0 and relative not in directories,'unexpected/duplicate DATA directory');directories.add(relative)
   if relative:(destination/relative).mkdir(mode=0o700,exist_ok=True)
   continue
  need(relative in files and relative not in seen and not name.endswith('/'),'duplicate/unexpected DATA file')
  row=files[relative];need(member.size==row['bytes'],'carrier member exact size differs');target=destination/relative;target.parent.mkdir(mode=0o700,exist_ok=True)
  handle=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);hashed=hashlib.sha256();remaining=member.size
  try:
   while remaining:
    raw=exact_read(expanded,min(CHUNK,remaining));hashed.update(raw);remaining-=len(raw);view=memoryview(raw)
    while view:
     written=os.write(handle,view);need(written>0,'DATA write failed');view=view[written:]
   need(hashed.hexdigest()==row['sha256'],'carrier member SHA256 differs');os.fsync(handle)
  finally:os.close(handle)
  need(not exact_read(expanded,(-member.size)%512).strip(b'\0'),'nonzero DATA padding');seen.add(relative)
 need(seen==set(files) and directories=={'','packages'},'complete whole carrier DATA closure required')
 verify(destination,files,deadline)
 return dict(status='EXACT_IMMUTABLE_ARCHIVE_DATA_NO_NATIVE_AUTHORITY',source=SOURCE,url=URL,requests=1,files=len(files),file_map=files,content_bytes=total,archive=dict(bytes=compressed.count,sha256=compressed.hashed.hexdigest()),expanded_bytes=expanded.count,normalized_files_mode=0o600,normalized_directories_mode=0o700,native_authority=False,git_authority=False)


def verify(carrier,files,deadline):
 ordinary(carrier,True);actual=set();dirs={''}
 for directory,children,names in os.walk(carrier,followlinks=False):
  for child in children:
   p=Path(directory)/child;ordinary(p,True);dirs.add(p.relative_to(carrier).as_posix())
  for name in names:
   path=Path(directory)/name;relative=path.relative_to(carrier).as_posix();need(relative in files,'extra carrier DATA file');exact(path,files[relative],deadline);actual.add(relative)
 need(actual==set(files) and dirs=={'','packages'},'complete normalized carrier DATA closure required')

def exact(path,row,deadline,output=None):
 before=ordinary(path);need(before.st_size==row['bytes'],'exact DATA size');handle=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK);hashed=hashlib.sha256();count=0
 try:
  need(node(os.fstat(handle))==node(before),'opened DATA identity differs')
  while True:
   tick(deadline);raw=os.read(handle,CHUNK)
   if not raw:break
   count+=len(raw);need(count<=row['bytes'],'bounded exact DATA input');hashed.update(raw)
   if output is not None:
    view=memoryview(raw)
    while view:
     written=os.write(output,view);need(written>0,'DATA copy failed');view=view[written:]
  need(count==row['bytes'] and hashed.hexdigest()==row['sha256'] and node(os.fstat(handle))==node(ordinary(path))==node(before),'stable complete DATA bytes required')
 finally:os.close(handle)


class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):raise ValueError('carrier redirects forbidden; exactly one DATA fetch required')

def acquire(root,carrier,deadline,opener=None):
 profile=expected(root);deadline=min(deadline,time.monotonic()+MAX_SECONDS);tick(deadline)
 carrier=C.safe(Path(carrier).absolute());parent=carrier.parent.lstat()
 need(stat.S_ISDIR(parent.st_mode) and parent.st_uid==os.getuid() and not parent.st_mode&0o022 and not os.path.lexists(carrier),'new carrier DATA directory under owned parent required before fetch')
 if opener is None:opener=urllib.request.build_opener(NoRedirect()).open
 response=opener(urllib.request.Request(URL,headers={'User-Agent':'cachy-asahi-orphans03-data/1','Accept-Encoding':'identity'}),timeout=min(30,max(.01,deadline-time.monotonic())))
 with response:
  need(response.status==200 and response.geturl()==URL,'one exact immutable DATA response required')
  receipt=unpack(response,carrier,profile['files'],deadline)
 receipt['profile_sha256']=C.digest(root/PROFILE);return receipt


def pairs(root):
 inputs=C.read(root/'scripts/ci/maintained-desktop574-inputs.json');rows={}
 for row in inputs['packages']:
  rows[row['filename']]=dict(bytes=row['size'],sha256=row['sha256']);rows[row['filename']+'.sig']=dict(bytes=row['signature_size'],sha256=row['signature_sha256'])
 need(len(rows)==1148,'exact original1148 package/signature DATA required');return rows

def seed(root,carrier,cache,deadline,transport):
 profile=expected(root);rows=pairs(root);need({n.removeprefix('packages/'):r for n,r in profile['files'].items() if n.startswith('packages/')}==rows,'carrier DATA joins original1148 package pins')
 validate_receipt(root,transport);verify(carrier,profile['files'],deadline);before=ordinary(cache,True);need(not list(cache.iterdir()),'existing empty fresh producer DATA cache required')
 for name,row in rows.items():
  handle=os.open(cache/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  try:exact(carrier/'packages'/name,row,deadline,handle);os.fsync(handle)
  finally:os.close(handle)
  exact(cache/name,row,deadline)
 need(set(p.name for p in cache.iterdir())==set(rows) and identity(ordinary(cache,True))==identity(before),'complete same-owned cache only')
 lock=root/'scripts/ci/maintained-desktop574-inputs.json'
 return dict(status='EXACT_RETAINED_DATA_ARCHIVE_PREPARATION',source=SOURCE,mode='desktop574',actual=None,carrier=transport,receipt=dict(actual_authority=False,mode='desktop574',inputs=rows,original_lock=dict(bytes=lock.stat().st_size,sha256=C.digest(lock)),cache=dict(before_files={},before_identity={},after_previous_identity={},added=1148,after_files=rows,fresh_cache=False,all_previous_inode_metadata_bytes_unchanged=True,directory_identity=identity(before),after_directory_identity=identity(ordinary(cache,True)),normalized_files_mode=0o600)))


def validate_receipt(root,receipt):
 profile=expected(root);total=check_files(profile['files'])
 need(type(receipt) is dict and set(receipt)=={'status','source','url','requests','files','file_map','content_bytes','archive','expanded_bytes','normalized_files_mode','normalized_directories_mode','native_authority','git_authority','profile_sha256'},'exact DATA-only receipt schema; no Git/blob claims')
 need(type(receipt.get('requests')) is int and type(receipt.get('files')) is int and type(receipt.get('content_bytes')) is int,'integer DATA counts required')
 need(receipt.get('status')=='EXACT_IMMUTABLE_ARCHIVE_DATA_NO_NATIVE_AUTHORITY' and receipt.get('source')==SOURCE and receipt.get('url')==URL and receipt.get('requests')==1 and receipt.get('files')==1154 and receipt.get('file_map')==profile['files'] and receipt.get('profile_sha256')==C.digest(root/PROFILE),'complete pinned whole DATA receipt required')
 need(receipt.get('content_bytes')==total and receipt.get('normalized_files_mode')==0o600 and receipt.get('normalized_directories_mode')==0o700 and receipt.get('native_authority') is False and receipt.get('git_authority') is False,'normalized DATA only; no native/Git authority')
 archive=receipt.get('archive');need(type(archive) is dict and set(archive)=={'bytes','sha256'} and type(archive['bytes']) is int and 0<archive['bytes']<=total+OVERHEAD and type(archive['sha256']) is str and re.fullmatch('[0-9a-f]{64}',archive['sha256']) and type(receipt.get('expanded_bytes')) is int and total<=receipt['expanded_bytes']<=total+OVERHEAD,'bounded observed archive receipt required')
 return receipt
