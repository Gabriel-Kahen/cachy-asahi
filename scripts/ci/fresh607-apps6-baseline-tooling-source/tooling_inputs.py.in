# SPDX-License-Identifier: MIT
"""Exact public tooling DATA into the original newly owned cache; no actors."""
import json,os,re,stat,time
from pathlib import Path
import common as C
from loaders import load
SOURCE='fb515d735a81194f06ea117539dee60438bb8d87'
REF='codex/gui16-controller-tooling-v1'
KEYS=('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
def identity(s):return tuple(getattr(s,k)for k in KEYS)
def canonical(value):
 p=Path(value);C.need(p.is_absolute()and str(p)==os.path.normpath(str(p))and p==p.resolve()and not any(q.is_symlink()for q in(p,*p.parents)),'canonical ordinary tooling path');return p
def tick(deadline):C.need(time.monotonic()<deadline,'tooling input preparation deadline')
def read(path,deadline,cap=32*1024**2):
 tick(deadline);p=canonical(path);fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);C.need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded ordinary singlelink tooling input');out=bytearray()
  while part:=os.read(fd,min(65536,a.st_size+1-len(out))):tick(deadline);out.extend(part);C.need(len(out)<=a.st_size,'tooling input growth')
  C.need(len(out)==a.st_size and identity(a)==identity(os.fstat(fd))==identity(p.lstat()),'tooling input identity drift');return bytes(out),identity(a)
 finally:os.close(fd)
def snapshot(root,deadline):
 root=canonical(root);C.need(root.is_dir(),'complete tooling input directory');values={};identities={'.':identity(root.lstat())};dirs=set()
 for p in sorted(root.rglob('*')):
  tick(deadline);n=p.relative_to(root)
  if n.parts[0]=='.git':continue
  C.need('.git'not in n.parts and not p.is_symlink()and(p.is_file()or p.is_dir()),'ordinary complete tooling input namespace')
  if p.is_dir():dirs.add(n.as_posix());identities[n.as_posix()+'/']=identity(p.lstat())
  else:values[n.as_posix()],identities[n.as_posix()]=read(p,deadline)
 C.need(dirs=={p.as_posix()for n in values for p in Path(n).parents if p.as_posix()!='.'},'foreign empty tooling directory')
 for n,w in identities.items():C.need(identity((root if n=='.'else root/n.rstrip('/')).lstat())==w,'tooling namespace identity drift')
 return values,identities

def configuration():
 p=json.loads(C.read(C.HERE/'tooling-profile.json'));C.need(p['source']==SOURCE and p['ref']==REF and len(p['carrier_files'])==89 and len(p['downloads'])==35 and len(p['rows'])==16 and p['seed_seconds']==240,'exact89/35/16 tooling input profile')
 C.need(p['publication']==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source=SOURCE,ref=REF,files=89,git_joins=89,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and p['git']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=SOURCE,ref=REF,files=p['carrier_files'])and p['authorization']==p['carrier_files'],'whole issued public89 metadata/Git/lock map')
 C.need(all(p[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance'))and p['authority']=='DATA_ONLY_ORIGINAL_GPG_AND_VM_CHECKS_MANDATORY','no tooling input/native acceptance transfer');return p

def selection(profile,carrier,legacy,deadline):
 values,ids=snapshot(carrier,deadline);C.need({n:C.pin(b)for n,b in values.items()}==profile['carrier_files'],'every public89 tooling source byte')
 for n,w in profile['legacy_files'].items():C.need(C.pin(read(legacy/n,deadline)[0])==w and values['source/'+Path(n).name]==read(legacy/n,deadline)[0],'exact source-relative legacy tooling primitive')
 raw=read(legacy/'scripts/virtual/tooling.lock.json',deadline)[0];C.need(raw==values['tooling.lock.json']and C.pin(raw)==profile['tooling_lock'],'whole legacy and carrier tooling lock identical');lock=json.loads(raw)
 builder=C.read(C.HERE/'tooling-builder574.lock');C.need(C.pin(builder)==profile['builder574'],'original574 readable builder selection');base=dict(line.split()for line in builder.decode().splitlines());C.need(len(base)==574,'all574 original builder rows')
 selector=C.ROOT/'parent604/prepare.py';C.need(C.pin(C.read(selector))==profile['selector'],'entire original tooling selector source');original=load('_fresh607_original_tooling_selection',selector)
 signature=lambda r:dict(filename=r['filename']+'.sig',url=r['url']+'.sig',size=r['signature_size'],sha256=r['signature_sha256']);rows=original.tooling_additions(base,lock['packages']);downloads=original.tooling_inputs(base,lock,signature)
 C.need(C.enc(rows)==C.enc(profile['rows'])and C.enc(downloads)==C.enc(profile['downloads']),'exact original16 rows and35 typed operands')
 policy=json.loads(values['tooling32-policy.json']);index=json.loads(values['index.json']);C.need(policy['rows']==rows and policy['tooling_lock']==profile['tooling_lock']and policy['original574']==profile['desktop574'],'original whole tooling policy/desktop574 selectors')
 C.need(index['files']=={n:C.pin(b)for n,b in values.items()if n!='index.json'},'complete original tooling index')
 expected={}
 for row in downloads:
  name=row['filename'];C.need(type(name)is str and name and'/'not in name and'\\'not in name,'flat exact tooling filename');member=('keyring/'if name in{r['filename']for r in lock['keyring_files']}else'packages/')+name;wanted=dict(bytes=row['size'],sha256=row['sha256']);C.need(C.pin(values[member])==wanted==profile['mapping'][name]['pin']and member==profile['mapping'][name]['carrier_path'],'all35 original raw bytes/signatures/keyring pins');expected[name]=values[member]
 C.need(len(expected)==35 and sum(map(len,expected.values()))==13203918,'closed exact35 byte bound');return values,ids,expected

def preflight(carrier,legacy):
 p=configuration();selection(p,canonical(carrier),canonical(legacy),time.monotonic()+p['seed_seconds']);return dict(status='SOURCE_BOUND89_EXACT35_DATA_ONLY',source=SOURCE,ref=REF,files=35,authority=p['authority'])

def seed(carrier,legacy,downloads,cache,owner):
 p=configuration();deadline=time.monotonic()+p['seed_seconds'];carrier,legacy,cache=map(canonical,(carrier,legacy,cache));root=cache.parent
 C.need(cache==root/'tooling-cache'and all(not cache.is_relative_to(r)and not r.is_relative_to(cache)for r in(carrier,legacy,C.ROOT)),'exact isolated original tooling-cache destination')
 for path in(root,cache):
  s=path.lstat();C.need(stat.S_ISDIR(s.st_mode)and s.st_uid==os.geteuid()and stat.S_IMODE(s.st_mode)==0o700,'fresh owned0700 tooling ancestry')
 C.need(type(owner)is dict and set(owner)=={'schema_version','purpose','token','output','producer','vm','legacy_source'}and type(owner['schema_version'])is int and owner['schema_version']==1 and owner['purpose']=='latest607-fresh-installer'and re.fullmatch('[0-9a-f]{32}',owner['token'])and owner['output']==str(root)and owner['producer']==str(root.with_name(root.name+'-producer'))and owner['vm']==str(root.with_name(root.name+'-vm'))and owner['legacy_source']=='b6b17e5f6b322f160f7eeb22c8a01380a3c854cd','same original fresh caller owner')
 owner_raw,owner_id=read(root/'owner.json',deadline);C.need(json.loads(owner_raw)==owner and not list(cache.iterdir()),'same owner and empty newly created cache; no overwrite')
 values,ids,expected=selection(p,carrier,legacy,deadline);C.need(C.enc(downloads)==C.enc(p['downloads']),'complete actual original downloader operands')
 C.need(not list(cache.iterdir())and read(root/'owner.json',deadline)==(owner_raw,owner_id),'late untouched original owner/cache')
 directory=os.open(cache,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);created={}
 key=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid'));opened=key(os.fstat(directory))
 try:
  C.need(identity(os.fstat(directory))==identity(cache.lstat()),'same original cache FD/path')
  for n,b in expected.items():
   tick(deadline);C.need(key(os.fstat(directory))==key(cache.lstat())==opened,'original cache FD/path identity held');fd=os.open(n,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
   try:
    view=memoryview(b)
    while view:
     tick(deadline);written=os.write(fd,view);C.need(written>0,'complete tooling copy progress');view=view[written:]
    os.fsync(fd);created[n]=identity(os.fstat(fd))
   finally:os.close(fd)
  C.need(snapshot(carrier,deadline)==(values,ids)and read(root/'owner.json',deadline)==(owner_raw,owner_id),'all original input/owner identities held after35 copies')
  written,written_ids=snapshot(cache,deadline);C.need(key(os.fstat(directory))==key(cache.lstat())==opened and written==expected and{n:written_ids[n]for n in expected}==created,'whole exact copied35 bytes and original new inodes')
 finally:os.close(directory)
 return dict(status='EXACT35_TOOLING_INPUT_CACHE_PREPARED_NOT_AUTHENTICATION',source=SOURCE,ref=REF,files=35,bytes=13203918,original_fetch='HASH_SIZE_MANDATORY_UNCHANGED',authentication='ORIGINAL_SIGNATURE_METADATA_VM_GATES_STILL_REQUIRED',native='NOT_RUN')
