# SPDX-License-Identifier: MIT
"""Complete public248 DATA into the already-owned574 cache; no authentication."""
import hashlib,json,os,re,stat,time
from pathlib import Path
import common as C
PROFILE_SHA='4c0e3147606d55429007bade1dc9ff42a78af3d0c503a2d5fd7f128b5c7f103f'
KEY=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)

def tick(deadline):C.need(time.monotonic()<deadline,'original890s prefetch envelope exhausted')
def profile():
 raw=C.read(C.ROOT/'lane/native248-cache-profile.json',2*1024**2);C.need(C.pin(raw)['sha256']==PROFILE_SHA,'complete native248 cache profile');p=json.loads(raw)
 C.need(p['source']=='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'and p['checkout']=='core-native248-recovered-inputs'and len(p['files'])==1154 and len(p['inputs'])==1148 and len(p['before_inputs'])==80 and p['actual']is None,'exact source-only1154/1148/80 profile');return p

def git(carrier,*argv,deadline):
 import subprocess
 tick(deadline);env=dict(PATH='/usr/bin:/bin',HOME='/tmp',LC_ALL='C',GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_NO_REPLACE_OBJECTS='1',GIT_NO_LAZY_FETCH='1',GIT_TERMINAL_PROMPT='0')
 r=subprocess.run(['/usr/bin/git','-C',str(carrier),*argv],stdin=subprocess.DEVNULL,capture_output=True,timeout=min(30,max(.01,deadline-time.monotonic())),env=env)
 C.need(r.returncode==0 and len(r.stdout)+len(r.stderr)<=128*1024**2,'bounded immutable native248 Git proof');return r.stdout

def prove(carrier,deadline,p):
 carrier=Path(carrier).absolute();C.need(carrier.name==p['checkout']and carrier.is_dir()and not any(q.is_symlink()for q in(carrier,*carrier.parents))and not carrier.is_relative_to(C.ROOT)and not C.ROOT.is_relative_to(carrier),'separate fixed ordinary carrier checkout')
 C.need(C.files(carrier)==p['files'],'whole1154 external carrier physical closure');head=git(carrier,'rev-parse','HEAD',deadline=deadline).decode().strip();C.need(head==p['source'],'exact immutable native248 HEAD');table={}
 for line in git(carrier,'ls-tree','-rz','--full-tree',p['source'],deadline=deadline).split(b'\0'):
  if not line:continue
  meta,name=line.split(b'\t',1);mode,kind,oid=meta.split();name=name.decode();C.need(name in p['files']and name not in table and mode in(b'100644',b'100755')and kind==b'blob'and re.fullmatch(b'[0-9a-f]{40}',oid),'ordinary exact native248 committed leaf');table[name]=dict(mode=mode.decode(),oid=oid.decode())
 C.need(set(table)==set(p['files']),'complete1154 committed carrier tree')
 for name,want in p['files'].items():
  raw=git(carrier,'cat-file','blob',p['source']+':'+name,deadline=deadline);C.need(C.pin(raw)==want and raw==C.read(carrier/name)and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==table[name]['oid'],'complete carrier Git/blob/filesystem join')
 return dict(source=p['source'],ref=p['ref'],checkout=p['checkout'],files=p['files'],git_head=head,git_tree=table)

def seed(out,deadline,carrier=None):
 import types
 p=profile();out=C.private(Path(out).absolute());cache=C.private(out/'context/deps');workspace=C.ROOT.parent;C.need(C.ROOT.is_absolute()and C.ROOT.name=='core-source'and not any(q.is_symlink()for q in(C.ROOT,*C.ROOT.parents))and C.ROOT==workspace/'core-source','fixed separate closed Core checkout');carrier=workspace/p['checkout']if carrier is None else Path(carrier).absolute();proof=prove(carrier,deadline,p)
 raw=C.read(C.ROOT/'baseline/maintained-desktop574-inputs.json');C.need(C.pin(raw)==p['baseline_lock']==p['original_lock'],'entire original574 lock');C.need(C.files(cache)==p['before_inputs'],'exact original80 cache closure after unchanged public14/rootfs companion')
 # Only the immediately re-pinned committed seeder runs; package bodies are DATA.
 body=C.read(carrier/'seed.py');C.need(C.pin(body)==p['files']['seed.py'],'exact consumed complete574 seeder body');module=types.ModuleType('_pinned_complete574_cache');module.__file__=str(carrier/'seed.py');exec(compile(body,module.__file__,'exec'),module.__dict__)
 receipt=module.seed(C.ROOT/'baseline/maintained-desktop574-inputs.json',cache,'desktop574',deadline)
 C.need(receipt['status']=='EXACT_PUBLIC_CACHE_INPUTS_JOINED_NOT_AUTHENTICATED'and receipt['mode']=='desktop574'and receipt['original_lock']==p['original_lock']and receipt['inputs']==p['inputs']and receipt['actual_authority']is False,'whole explicit574 source-owned cache receipt')
 v=receipt['cache'];C.need(v['before_files']==p['before_inputs']and v['after_files']==p['inputs']and v['added']==1068 and v['before_identity']==v['after_previous_identity']and v['all_previous_inode_metadata_bytes_unchanged']is True,'exact80 to1148 preserving all prior identities');C.need(C.files(cache)==p['inputs'],'full1148 destination byte readback');tick(deadline)
 return dict(schema=1,status='COMPLETE_PUBLIC574_JOINED_EXISTING574_CACHE_NOT_AUTHENTICATED',carrier=proof,original_lock=p['original_lock'],inputs=p['inputs'],cache=receipt,trust='UNCHANGED_ORIGINAL_FULL574_CURRENT_GPG_METADATA_ACQUIRE_AND_FULL64_AUTHENTICATION_REQUIRED',actual_authority=False)
