# SPDX-License-Identifier: MIT
"""Pinned external public cache DATA, before unchanged full64 authentication."""
import hashlib,json,os,re,stat,subprocess,time,types
from pathlib import Path
import common as C
PROFILE_SHA='b24447a99ad04ef207143ad6179cb9d698184a75fb6cf8d9a1977f394e1d6424'

def profile():
 raw=C.read(C.ROOT/'lane/recovery-cache-profile.json',1024**2);C.need(C.pin(raw)['sha256']==PROFILE_SHA,'whole complete64 cache profile differs');p=json.loads(raw)
 C.need(type(p['schema'])is int and p['schema']==1 and p['purpose']=='EXACT_COMPLETE64_PUBLIC_CACHE_NOT_AUTHENTICATION'and len(p['files'])==133 and len(p['inputs'])==128 and all(p[k]is None for k in('actual_source','actual_ref','actual_run')),'finite133/128 source-only cache profile required')
 C.need(p['source']=='7dfce898755583bbf8081aae04d8b8579f66be58'and p['checkout']=='core64-recovered-inputs','exact public carrier and fixed checkout required');return p

def fixed_carrier():
 workspace=Path(os.environ['GITHUB_WORKSPACE']).absolute()
 C.need(C.ROOT==workspace/'core-source','closed source checkout must be separate from carrier')
 return workspace/'core64-recovered-inputs'

def git(carrier,*argv,deadline):
 C.need(time.monotonic()<deadline,'original prefetch envelope exhausted')
 env=dict(PATH='/usr/bin:/bin',HOME='/tmp',LC_ALL='C',GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_NO_REPLACE_OBJECTS='1',GIT_NO_LAZY_FETCH='1',GIT_TERMINAL_PROMPT='0')
 r=subprocess.run(['/usr/bin/git','-C',str(carrier),*argv],stdin=subprocess.DEVNULL,capture_output=True,timeout=min(30,max(.01,deadline-time.monotonic())),env=env)
 C.need(r.returncode==0 and len(r.stdout)+len(r.stderr)<=64*1024**2,'bounded immutable carrier Git proof failed');return r.stdout

def prove(carrier,deadline):
 p=profile();carrier=Path(carrier).absolute();C.need(carrier.name==p['checkout']and carrier.is_dir()and not any(x.is_symlink()for x in(carrier,*carrier.parents)),'fixed ordinary external carrier checkout required')
 C.need(not carrier.is_relative_to(C.ROOT)and not C.ROOT.is_relative_to(carrier),'carrier must remain outside closed source')
 C.need(C.files(carrier)==p['files'],'whole public133 carrier filesystem differs')
 head=git(carrier,'rev-parse','HEAD',deadline=deadline).decode().strip();C.need(head==p['source'],'exact immutable carrier HEAD required')
 entries={}
 for line in git(carrier,'ls-tree','-rz','--full-tree',p['source'],deadline=deadline).split(b'\0'):
  if not line:continue
  meta,name=line.split(b'\t',1);mode,kind,oid=meta.split();name=name.decode()
  C.need(name in p['files']and name not in entries and kind==b'blob'and mode in(b'100644',b'100755')and re.fullmatch(b'[a-f0-9]{40}',oid),'ordinary exact carrier Git blob required');entries[name]=dict(mode=mode.decode(),oid=oid.decode())
 C.need(set(entries)==set(p['files']),'complete133 committed carrier tree required')
 for name,want in p['files'].items():
  raw=git(carrier,'cat-file','blob',p['source']+':'+name,deadline=deadline)
  C.need(C.pin(raw)==want and raw==C.read(carrier/name),'whole carrier Git/blob/filesystem pin differs')
  C.need(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==entries[name]['oid'],'exact Git object hash differs')
 return dict(source=p['source'],ref=p['ref'],checkout=p['checkout'],files=p['files'],git_head=head,git_tree=entries)

def seed(core,deadline,carrier=None):
 p=profile();core=Path(core).absolute();carrier=fixed_carrier()if carrier is None else Path(carrier).absolute();proof=prove(carrier,deadline)
 cache=C.private(core/'builder-context/deps');C.need({q.name for q in cache.iterdir()}=={'SHA256SUMS'},'fresh checksum-only private cache required')
 before=C.pin(C.read(cache/'SHA256SUMS'));C.need(C.pin(C.read(core/'builder-inputs.lock.json'))==p['original_lock'],'original signed64 lock required')
 expected={}
 for row in C.load(core/'builder-inputs.lock.json')['packages']:
  for suffix,size,digest in(('',row['size'],row['sha256']),('.sig',row['signature_size'],row['signature_sha256'])):expected[row['filename']+suffix]=dict(bytes=size,sha256=digest)
 C.need(expected==p['inputs']and len(expected)==128,'all128 exact original64 lock inputs required')
 # Execute only the fully pinned committed source helper; packages remain DATA.
 module=types.ModuleType('_pinned_public_core64_cache');module.__file__=str(carrier/'seed.py')
 raw=C.read(carrier/'seed.py');C.need(C.pin(raw)==p['files']['seed.py'],'exact consumed public seeder source required')
 exec(compile(raw,module.__file__,'exec'),module.__dict__);result=module.seed(core)
 C.need(result==dict(status='ALL128_EXACT_PUBLIC_INPUTS_SEEDED_NOT_AUTHENTICATED',files=expected,trust='ORIGINAL_FULL64_GPG_AND_METADATA_CHECKS_REQUIRED'),'exact public-only seeder outcome required')
 C.private(cache);after=C.files(cache);C.need(after==dict(expected,SHA256SUMS=before),'whole129 cache readback differs')
 C.need(time.monotonic()<deadline,'original prefetch envelope exhausted after cache seed')
 return dict(schema=1,status='COMPLETE_PUBLIC64_CACHE_SEEDED_NOT_AUTHENTICATED',carrier=proof,original_lock=p['original_lock'],seed_helper=p['files']['seed.py'],inputs=expected,cache=dict(before_files={'SHA256SUMS':before},after_files=after,mode=0o700,owner='CALLER_UID',fresh=True),trust='UNCHANGED_ORIGINAL_FULL64_CURRENT_GPG_AND_PKGINFO_MANDATORY',actual_authority=False)
