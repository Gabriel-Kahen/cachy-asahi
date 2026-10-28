# SPDX-License-Identifier: MIT
"""Six exact public compiler inputs into the existing private cache; no authentication."""
import argparse,json,math,os,stat,time,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as C
PROFILE={'bytes': 25836, 'sha256': '7e5e1bf47f029bef1cbbcd6c799b9528d1cc760af82967fa95bf2cf6aa94eeed'}
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def identity(s):return[getattr(s,n)for n in FIELDS]
def tick(deadline):C.need(type(deadline)in(int,float)and time.monotonic()<deadline,'compiler6 preparation deadline')
def configuration():
 p=json.loads(C.checked(C.HERE/'compiler6-profile.json',PROFILE));C.need(p['carrier_source']=='8ee14069b7a74455a7bea1171ba319932c9df304'and p['updater_source']=='1aea667aec50a62ba0ab2dad44be24a4dc3bd098'and len(p['carrier_files'])==11 and len(p['updater_files'])==4,'whole pinned compiler6/original354 context');C.need(p['packages']=={'compiler-rt':'23.1.1-1','lld':'23.1.1-1','rust':'1:1.99.0-1'}and all(p[n]is None for n in('source','ref','run','actual'))and p['acceptance']is False,'source-only exact3 compiler versions');return p

def inputs(lock):
 rows={}
 def add(name,size,sha):
  C.need(type(name)is str and Path(name).name==name and name not in('.','..')and name not in rows,'closed unique original input filename');rows[name]=dict(bytes=size,sha256=sha)
 for row in lock['packages']:
  add(row['filename'],row['size'],row['sha256']);add(row['filename']+'.sig',row['signature_size'],row['signature_sha256'])
 packages=dict(rows);row=lock['rootfs'];add(row['filename'],row['size'],row['sha256']);add(row['filename']+'.sig',row['signature_size'],row['signature_sha256'])
 for row in lock['keyring_files']:add(row['filename'],row['size'],row['sha256'])
 return packages,rows

def cache_snapshot(cache,expected):
 cache=C.safe(cache);s=cache.lstat();C.need(stat.S_ISDIR(s.st_mode)and s.st_uid==os.geteuid()and stat.S_IMODE(s.st_mode)==0o700,'existing caller-owned0700 cache required');out={}
 for leaf in cache.iterdir():
  t=leaf.lstat();C.need(stat.S_ISREG(t.st_mode)and t.st_nlink==1 and t.st_uid==os.geteuid()and leaf.name in expected and t.st_size==expected[leaf.name]['bytes'],'closed ordinary existing cache members');out[leaf.name]=identity(t)
 C.need(set(out)==set(expected),'entire existing1148 package inputs and original trust/rootfs required');return out,[s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid]

def carrier_snapshot(root,expected):
 root=C.safe(root);actual={};directories=set()
 for path in root.rglob('*'):
  rel=path.relative_to(root)
  if rel.parts[0]=='.git':
   C.need((root/'.git').is_dir()and not(root/'.git').is_symlink(),'only ordinary top-level checkout administration');continue
  s=path.lstat();C.need(stat.S_ISDIR(s.st_mode)or stat.S_ISREG(s.st_mode)and s.st_nlink==1,'ordinary closed compiler6 input')
  if stat.S_ISDIR(s.st_mode):directories.add(rel.as_posix())
  else:actual[rel.as_posix()]=identity(s)
 C.need(set(actual)==set(expected)and directories=={'packages'},'all11 original compiler6 leaves only');return actual

def prepare(carrier,updater,desktop_lock,cache,deadline):
 C.need(type(deadline)in(int,float)and math.isfinite(deadline)and 0<deadline-time.monotonic()<=240,'finite original240 preparation allowance');tick(deadline);p=configuration();carrier=C.safe(carrier);updater=C.safe(updater);cache=C.safe(cache);desktop_lock=C.safe(desktop_lock)
 for root in(carrier,updater):C.need(not cache.is_relative_to(root)and not root.is_relative_to(cache),'cache disjoint from immutable inputs')
 originals={n:C.checked(updater/n,w)for n,w in p['updater_files'].items()};desktop_raw=C.checked(desktop_lock,p['desktop_lock']);desktop=json.loads(desktop_raw);package_rows,prior=inputs(desktop);C.need(len(package_rows)==1148,'whole held complete574 package input set')
 base=json.loads(originals['scripts/ci/inputs.lock.json']);extension_raw=originals['scripts/port/updater-extension/builder-extension.lock.json'];extension=json.loads(extension_raw);C.need(desktop['rootfs']==base['rootfs']and desktop['keyring_files']==base['keyring_files']and extension['base_inputs_lock_sha256']==C.pin(originals['scripts/ci/inputs.lock.json'])['sha256'],'same held rootfs/trust/base selectors');before,directory=cache_snapshot(cache,prior);targets={};selected={}
 for row in extension['packages']:
  if row['name']not in p['packages']:continue
  C.need(row['name']not in selected and row['version']==p['packages'][row['name']],'exact original3 package selectors');selected[row['name']]=row
  for suffix,size,sha in(('',row['size'],row['sha256']),('.sig',row['signature_size'],row['signature_sha256'])):
   name=row['filename']+suffix;C.need(name not in targets and name not in before,'no existing cache overwrite');targets[name]=dict(bytes=size,sha256=sha)
 C.need(set(selected)==set(p['packages'])and len(extension['packages'])==13 and len(targets)==6,'original13 extension and exactly6 compiler inputs')
 initial=carrier_snapshot(carrier,p['carrier_files']);bodies={}
 for name,w in p['carrier_files'].items():tick(deadline);bodies[name]=C.checked(carrier/name,w)
 policy=json.loads(bodies['archive6-policy.json']);index=json.loads(bodies['index.json']);lock_pin=C.pin(extension_raw);C.need(bodies['original-extension.lock.json']==extension_raw and policy['original_inputs']==index['original_inputs']==lock_pin and index['files']==targets and{n:{k:v[k]for k in('bytes','sha256')}for n,v in policy['files'].items()}==targets,'whole policy/index/original354 extension six-way join');C.need({n[9:]:w for n,w in p['carrier_files'].items()if n.startswith('packages/')}==targets,'all6 archive and signature members exact')
 created={}
 try:
  for name,w in targets.items():
   tick(deadline);body=bodies['packages/'+name];fd=os.open(cache/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);created[name]=identity(os.fstat(fd))[:2]
   try:
    offset=0
    while offset<len(body):tick(deadline);n=os.write(fd,body[offset:offset+1024**2]);C.need(n>0,'compiler6 cache write');offset+=n
   finally:os.close(fd)
   C.need(C.pin(C.read(cache/name,w['bytes']))==w,'whole copied compiler archive/signature pin')
  after,now=cache_snapshot(cache,dict(prior,**targets));C.need({n:after[n]for n in before}==before and now==directory,'all prior cache inode/metadata and directory held');C.need(carrier_snapshot(carrier,p['carrier_files'])==initial and all(C.checked(updater/n,w)==originals[n]for n,w in p['updater_files'].items())and C.checked(desktop_lock,p['desktop_lock'])==desktop_raw,'all immutable source inputs held through copy');tick(deadline)
 except BaseException:
  for name,owned in created.items():
   path=cache/name
   if path.exists()and not path.is_symlink()and identity(path.lstat())[:2]==owned and path.stat().st_nlink==1:path.unlink()
  C.need(cache_snapshot(cache,prior)==(before,directory),'failed compiler6 copy preserves original cache');raise
 return dict(status='EXACT_COMPILER6_CACHE_DATA_NOT_AUTHENTICATED',carrier_source=p['carrier_source'],updater_source=p['updater_source'],files=targets,prior_packages=1148,prior_files=len(before),before_identity=before,after_prior_identity={n:after[n]for n in before},directory_identity=directory,original_GPG_metadata_build='MANDATORY_UNCHANGED',acceptance_authority=False,cleanup_authority=False)


# Fixed retained dependency DATA prefill. Original acquire/auth/GPG still run.
def dependency_configuration():
 p=configuration();d=p['dependency_cache']
 C.need(d['source']=='405761af52cdfa92b97bbf5b0519f32230d9a254'and d['ref']=='codex/current606-incoming31-v1'and len(d['carrier_files'])==108 and
  d['preparation_source']=='93bc9bfac7343ee3b443ae3332c0942ed1ba5b55'and d['packages']=={'archlinux-contrib':'20261009-1','htmlq':'0.4.0-3','pacman-contrib':'1.13.1-1','pyalpm':'0.12.0-1','xdg-utils':'1.2.1-2'}and
  d['status']=='FIXED_EIGHT_RETAINED_DEPENDENCY_INPUTS_UNAUTHENTICATED_DATA_ONLY'and d['acceptance']is False and all(d[k]is None for k in('actual_source','actual_ref','actual_run')),
  'fixed five dependency identities and public incoming31 context only');return p,d

def dependency_carrier_snapshot(root,expected):
 root=C.safe(root);root_identity=identity(root.lstat());files={};directories={}
 for path in root.rglob('*'):
  rel=path.relative_to(root)
  if rel.parts[0]=='.git':
   C.need((root/'.git').is_dir()and not(root/'.git').is_symlink(),'only ordinary top-level checkout administration');continue
  C.need('.git'not in rel.parts and not path.is_symlink(),'foreign Git or input alias refused');s=path.lstat()
  if stat.S_ISDIR(s.st_mode):directories[rel.as_posix()]=identity(s)
  else:
   name=rel.as_posix();C.need(name in expected and stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size==expected[name]['bytes'],'closed declared incoming31 file extent');files[name]=identity(s)
 required={q.as_posix()for n in expected for q in Path(n).parents if q.as_posix()!='.'}
 C.need(set(files)==set(expected)and set(directories)==required and identity(root.lstat())==root_identity,'whole declared incoming31 namespace; selected eight bodies separately checked');return files,root_identity,directories

def prepare_dependency_cache(incoming,preparation,desktop_lock,cache,deadline):
 C.need(type(deadline)in(int,float)and math.isfinite(deadline)and 0<deadline-time.monotonic()<=240,'same finite original240 preparation deadline');tick(deadline)
 p,d=dependency_configuration();incoming=C.safe(incoming);preparation=C.safe(preparation);desktop_lock=C.safe(desktop_lock);cache=C.safe(cache)
 for root in(incoming,preparation):C.need(not cache.is_relative_to(root)and not root.is_relative_to(cache),'cache disjoint from immutable dependency inputs')
 source_identity={n:identity((preparation/n).lstat())for n in d['preparation_files']};preparation_identity=identity(preparation.lstat());desktop_identity=identity(desktop_lock.lstat());source={n:C.checked(preparation/n,w)for n,w in d['preparation_files'].items()};C.need({n:identity((preparation/n).lstat())for n in source}==source_identity,'stable dependency source descriptors');raw=source['scripts/ci/full-development-composition/dependencies/inputs.lock.json'];lock=json.loads(raw)
 C.need(lock['signer_fingerprint']=='68B3537F39A313B3E574D06777193F152BDBE6A6'and len(lock['packages'])==5 and{r['name']:r['version']for r in lock['packages']}==d['packages'],'whole original fixed five lock/signature identity')
 desktop_raw=C.checked(desktop_lock,p['desktop_lock']);desktop=json.loads(desktop_raw);packages,prior=inputs(desktop)
 C.need(len(packages)==1148,'entire held complete574 input set')
 prior.update({n.removeprefix('packages/'):w for n,w in p['carrier_files'].items()if n.startswith('packages/')})
 C.need(len(prior)==1159,'entire prior1153 plus six original compiler inputs required')
 before,directory=cache_snapshot(cache,prior);original=dependency_carrier_snapshot(incoming,d['carrier_files']);targets={};allten={};bodies={}
 for row in lock['packages']:
  for suffix,size,sha in(('',row['size'],row['sha256']),('.sig',row['signature_size'],row['signature_sha256'])):
   name=row['filename']+suffix;w=dict(bytes=size,sha256=sha);C.need(name not in allten,'unique fixed dependency archive/signature');allten[name]=w
   if row['name']=='xdg-utils':
    C.need(prior.get(name)==w and C.pin(C.read(cache/name,size))==w,'exact already-retained xdg-utils pair; never overwritten')
   else:
    member=('upstream-signatures/'if suffix else'packages/')+name
    C.need(name not in before and d['selected'].get(member)==w==d['carrier_files'].get(member),'exact selected eight declared incoming inputs; no overwrite')
    targets[name]=w;tick(deadline);bodies[name]=C.checked(incoming/member,w)
 C.need(len(allten)==10 and len(targets)==len(d['selected'])==8 and sum(w['bytes']for w in allten.values())<1024**2,'closed ten bytes below original dependency bound')
 created={}
 try:
  for name,w in targets.items():
   tick(deadline);fd=os.open(cache/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);created[name]=identity(os.fstat(fd))[:2]
   try:
    offset=0;body=bodies[name]
    while offset<len(body):tick(deadline);n=os.write(fd,body[offset:offset+65536]);C.need(n>0,'retained dependency cache copy');offset+=n
   finally:os.close(fd)
   C.need(C.pin(C.read(cache/name,w['bytes']))==w,'whole copied dependency archive/signature')
  after,now=cache_snapshot(cache,dict(prior,**targets))
  C.need({n:after[n]for n in before}==before and now==directory,'complete prior1159 file metadata/identity and owned cache directory preserved')
  for name,w in allten.items():tick(deadline);C.need(C.pin(C.read(cache/name,w['bytes']))==w,'all ten exact cache-hit objects before unchanged180 acquisition')
  C.need(dependency_carrier_snapshot(incoming,d['carrier_files'])==original and all(C.checked(preparation/n,w)==source[n]for n,w in d['preparation_files'].items())and C.checked(desktop_lock,p['desktop_lock'])==desktop_raw and identity(desktop_lock.lstat())==desktop_identity and identity(preparation.lstat())==preparation_identity and{n:identity((preparation/n).lstat())for n in source}==source_identity,'whole declared incoming namespace and source lock held');tick(deadline)
 except BaseException:
  for name,owned in created.items():
   path=cache/name
   if path.exists()and not path.is_symlink()and identity(path.lstat())[:2]==owned and path.stat().st_nlink==1:path.unlink()
  C.need(cache_snapshot(cache,prior)==(before,directory),'failed new8 preparation preserves entire prior1159 metadata');raise
 return dict(status='EXACT_EIGHT_RETAINED_DEPENDENCY_CACHE_DATA_NOT_AUTHENTICATED',source=d['source'],preparation_source=d['preparation_source'],new_files=targets,all_ten=allten,prior_files=len(before),before_identity=before,after_prior_identity={n:after[n]for n in before},directory_identity=directory,
  namespace='WHOLE_DECLARED108_MEMBERS_AND_SIZES_ONLY',content='EXACT_SELECTED8_AND_EXISTING_XDG2_FULL_BYTES',original180_GPG_metadata_URLs='MANDATORY_UNCHANGED',acceptance_authority=False,cleanup_authority=False)

def prepare_with_dependencies(carrier,updater,desktop_lock,cache,deadline,incoming,preparation):
 C.need(incoming is not None and preparation is not None,'both immutable dependency roots required')
 # The old six-copy function and its globals/default route remain unchanged.
 compiler=prepare(carrier,updater,desktop_lock,cache,deadline)
 dependency=prepare_dependency_cache(incoming,preparation,desktop_lock,cache,deadline)
 return dict(compiler6=compiler,dependency_cache=dependency,shared_original_deadline=deadline,acceptance_authority=False)

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__)
 for name in('carrier','updater','desktop-lock','cache'):parser.add_argument('--'+name,type=Path,required=True)
 parser.add_argument('--incoming31',type=Path);parser.add_argument('--preparation',type=Path)
 parser.add_argument('--deadline',type=float,required=True);a=parser.parse_args();result=prepare(a.carrier,a.updater,a.desktop_lock,a.cache,a.deadline)if a.incoming31 is None and a.preparation is None else prepare_with_dependencies(a.carrier,a.updater,a.desktop_lock,a.cache,a.deadline,a.incoming31,a.preparation);print(C.enc(result).decode(),end='')
