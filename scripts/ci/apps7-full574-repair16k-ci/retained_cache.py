# SPDX-License-Identifier: MIT
"""Full public574 cache DATA before unchanged producer; same outer2300s envelope."""
import argparse,hashlib,json,os,re,stat,subprocess,sys,time,types
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
PROFILE_SHA='2a6bb0048ea2217cb54afba98b73f5bf8f28bdd3b6f46ce0a3946fdabeaf8025'
KEY=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def read(path,cap=128*1024**2):
 path=Path(path).absolute();need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary retained input ancestry');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  before=os.fstat(fd);need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=cap,'bounded singlelink retained input');parts=[];total=0
  while True:
   block=os.read(fd,1024**2)
   if not block:break
   total+=len(block);need(total<=before.st_size,'bounded retained input');parts.append(block)
  need(total==before.st_size and KEY(before)==KEY(os.fstat(fd))==KEY(path.lstat()),'stable retained input bytes');return b''.join(parts)
 finally:os.close(fd)
def tick(deadline):need(time.monotonic()<deadline,'original2300s producer envelope exhausted')
def profile():
 raw=read(HERE/'retained-cache-profile.json',2*1024**2);need(pin(raw)['sha256']==PROFILE_SHA,'complete retained574 source profile');p=json.loads(raw);need(p['source']=='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'and len(p['files'])==1154 and len(p['inputs'])==1148 and len(p['before_inputs'])==80 and p['actual']is None,'exact1154/1148/80 source-only cache closure');return p
def physical(carrier,deadline):
 result={}
 for path in sorted(Path(carrier).rglob('*')):
  name=path.relative_to(carrier).as_posix()
  if name=='.git'or name.startswith('.git/'):continue
  tick(deadline);need(not path.is_symlink()and(path.is_file()or path.is_dir()),'ordinary closed retained carrier')
  if path.is_file():result[name]=pin(read(path))
 return result
def git(carrier,*args,deadline):
 tick(deadline);env=dict(PATH='/usr/bin:/bin',HOME='/tmp',LC_ALL='C',GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_NO_REPLACE_OBJECTS='1',GIT_NO_LAZY_FETCH='1',GIT_TERMINAL_PROMPT='0')
 row=subprocess.run(['/usr/bin/git','-C',str(carrier),*args],stdin=subprocess.DEVNULL,capture_output=True,timeout=min(30,max(.01,deadline-time.monotonic())),env=env);need(row.returncode==0 and len(row.stdout)+len(row.stderr)<=128*1024**2,'bounded retained574 Git source proof');return row.stdout

def prove(carrier,deadline,p,root=ROOT):
 carrier=Path(carrier).absolute();root=Path(root).absolute();need(carrier.name==p['checkout']and carrier.is_dir()and not any(q.is_symlink()for q in(carrier,*carrier.parents))and not carrier.is_relative_to(root)and not root.is_relative_to(carrier),'separate fixed external retained574 checkout');need(physical(carrier,deadline)==p['files'],'whole1154 retained carrier filesystem closure');head=git(carrier,'rev-parse','HEAD',deadline=deadline).decode().strip();need(head==p['source'],'immutable retained574 HEAD');tree={}
 for line in git(carrier,'ls-tree','-rz','--full-tree',p['source'],deadline=deadline).split(b'\0'):
  if not line:continue
  meta,name=line.split(b'\t',1);mode,kind,oid=meta.split();name=name.decode();need(name in p['files']and name not in tree and mode in(b'100644',b'100755')and kind==b'blob'and re.fullmatch(b'[0-9a-f]{40}',oid),'ordinary exact retained574 Git tree leaf');tree[name]=dict(mode=mode.decode(),oid=oid.decode())
 need(set(tree)==set(p['files']),'full1154 committed retained carrier tree')
 for name,want in p['files'].items():
  raw=git(carrier,'cat-file','blob',p['source']+':'+name,deadline=deadline);need(pin(raw)==want and raw==read(carrier/name)and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==tree[name]['oid'],'all1154 Git/blob/filesystem bytes join')
 return dict(source=p['source'],ref=p['ref'],checkout=p['checkout'],files=p['files'],git_head=head,git_tree=tree)
def seed(cache,carrier,deadline,root=ROOT):
 p=profile();root=Path(root).absolute();cache=Path(cache).absolute();need(cache.name=='deps'and cache.parent.name=='context'and not cache.is_relative_to(root),'fixed caller-owned producer cache outside closed source');proof=prove(carrier,deadline,p,root)
 lock=read(root/'scripts/ci/maintained-desktop574-inputs.json',1024**2);need(pin(lock)==p['original574_lock']==p['files']['desktop574-inputs.lock.json'],'same whole original574 input lock');rows=json.loads(lock)['packages'];expected={}
 for r in rows:expected[r['filename']]=dict(bytes=r['size'],sha256=r['sha256']);expected[r['filename']+'.sig']=dict(bytes=r['signature_size'],sha256=r['signature_sha256'])
 need(len(rows)==574 and expected==p['inputs']and len(expected)==1148 and sum(v['bytes']for v in expected.values())==1045287299,'all original1148 package/signature pins');need({path.name for path in cache.iterdir()}==set(p['before_inputs']),'whole original80 preexisting cache leaves')
 # Re-pin consumed code immediately after whole Git proof, before executing it.
 raw=read(Path(carrier)/'seed.py');need(pin(raw)==p['files']['seed.py'],'exact consumed retained574 seeder');module=types.ModuleType('_source_held_retained574_seed');module.__file__=str(Path(carrier)/'seed.py');exec(compile(raw,module.__file__,'exec'),module.__dict__)
 receipt=module.seed(root/'scripts/ci/maintained-desktop574-inputs.json',cache,'desktop574',deadline);need(receipt['inputs']==expected and receipt['cache']['before_files']==p['before_inputs']and len(receipt['cache']['after_files'])==1148 and receipt['cache']['added']==1068 and receipt['actual_authority']is False,'complete source-owned80 to1148 exact seeding receipt')
 return dict(schema=1,status='REPAIR_FULL574_CACHE_JOINED_NOT_AUTHENTICATED',carrier=proof,original574_lock=p['original574_lock'],seed=receipt,original_producer=p['producer'],producer_outer_seconds=2300,versions='UNCHANGED',trust='UNCHANGED_FULL574_CURRENT_GPG_METADATA_AND_NATIVE_TRANSACTION_REQUIRED',actual_authority=False)
def main():
 a=sys.argv[1:];need(len(a)==7 and a[0]=='build'and a[1]=='--inputs'and a[3]=='--output'and a[5]=='--job-token','exact unchanged producer argv');inputs=Path(a[2]).absolute();output=Path(a[4]).absolute();workspace=Path(os.environ['GITHUB_WORKSPACE']).absolute();need(ROOT==workspace/'repair-source'and inputs==ROOT/'scripts/ci/maintained-desktop574-inputs.json'and output==Path(os.environ['RUNNER_TEMP'])/'desktop574','fixed separated source and original producer paths');p=profile();deadline=time.monotonic()+2300;tick(deadline);source=os.environ['SOURCE_SHA'];run=os.environ['GITHUB_RUN_ID'];attempt=os.environ['GITHUB_RUN_ATTEMPT'];case=os.environ['REPAIR_CASE'];need(re.fullmatch('[0-9a-f]{40}',source)and source==os.environ['GITHUB_SHA']==os.environ['GITHUB_WORKFLOW_SHA']and re.fullmatch('[1-9][0-9]{0,19}',run)and re.fullmatch('[1-9][0-9]{0,19}',attempt)and case in('repair-bytes','repair-missing'),'original source/workflow/run/case identity');receipt=seed(output/'context/deps',workspace/p['checkout'],deadline);receipt['identity']=dict(source=source,run=int(run),attempt=int(attempt),case=case);target=Path(os.environ['RUNNER_TEMP'])/'repair16k-retained-cache.json';need(not target.exists()and not target.is_symlink(),'fresh retained-cache receipt');fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as stream:stream.write(encoded(receipt));stream.flush();os.fsync(stream.fileno())
 producer=ROOT/'scripts/ci/maintained_desktop574.py';need(pin(read(producer))==p['producer'],'whole unchanged producer code before exec');tick(deadline);os.execve(sys.executable,[sys.executable,'-I','-B',str(producer),*a],dict(os.environ))
if __name__=='__main__':main()
