"""Finite source custody and private files for one immutable GNU native lane."""
import hashlib,importlib.util,json,os,re,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;LANE='scripts/ci/gnu-immutable-source-native';ROOT=HERE.parents[2];VM='runtime/runtime-vm';INST='scripts/ci/glibc-debian-maintained-installed16k';OWNER='scripts/ci/glibc-debian-maintained-public-provider-lifecycle-owner';REPO='Gabriel-Kahen/cachy-asahi'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def obj(b):
 def pairs(rows):
  d={}
  for k,v in rows:need(k not in d,'duplicate field');d[k]=v
  return d
 return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def read(p,cap=4*1024**2):
 p=Path(p).absolute();need(not any(q.is_symlink()for q in(p,*p.parents)),'ordinary noalias input');fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded singlelink input');b=bytearray()
  while len(b)<a.st_size:
   x=os.read(fd,min(1024**2,a.st_size-len(b)));need(bool(x),'whole input');b.extend(x)
  identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  need(identity(a)==identity(os.fstat(fd))==identity(p.lstat()),'input drift');return bytes(b)
 finally:os.close(fd)
def write(p,raw):
 p=Path(p);fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  with os.fdopen(os.dup(fd),'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
 finally:os.close(fd)
def private(p):
 p=Path(p).absolute();need(not p.exists()and not p.is_symlink()and p.parent.is_dir()and not any(q.is_symlink()for q in p.parents),'fresh private path');s=p.parent.stat();need(s.st_uid==os.getuid()and stat.S_IMODE(s.st_mode)==0o700,'private caller-owned0700 parent');p.mkdir(mode=0o700);return p
def load(name,p):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
def source(root=ROOT):
 root=Path(root).absolute();m=obj(read(root/LANE/'source-manifest.json',2*1024**2));rows=m['files'];actual=set()
 for p in root.rglob('*'):
  if p.relative_to(root).parts[0]=='.git':continue
  need(not p.is_symlink()and(p.is_dir()or p.is_file()),'ordinary source closure')
  if p.is_file():actual.add(p.relative_to(root).as_posix())
 need(actual==set(rows)|{LANE+'/source-manifest.json','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-gnu-immutable-source.yml'},'exact source closure; only top-level Git metadata ignored')
 for n,v in rows.items():need(pin(read(root/n,16*1024**2))==v,'whole source differs: '+n)
 expected=read(root/LANE/'workflow.yml.in').decode().replace('@ENTRY_SHA@',rows[LANE+'/entry.py']['sha256']).replace('@MANIFEST_SHA@',pin(read(root/LANE/'source-manifest.json',2*1024**2))['sha256']).encode();need(read(root/'.github/workflows/native-arm-build.yml')==read(root/'.github/workflows/native-arm-gnu-immutable-source.yml')==expected,'exact dedicated/registered alias and actual workflow stamps')
 p=obj(read(root/LANE/'input-policy.json'));need(p['purpose']=='GNU_IMMUTABLE_RUNTIME_NATIVE_V1'and p['actual_source']is p['actual_ref']is p['actual_run']is None,'default actual authority NULL')
 return dict(status='PASS_CLOSED_SOURCE_ONLY_NO_ACTORS',files=len(actual),actual_source=None,actual_ref=None,actual_run=None)
def environment(e):
 source=e.get('SOURCE_SHA');run=e.get('GITHUB_RUN_ID');ref=e.get('GITHUB_REF_NAME');need(re.fullmatch('[a-f0-9]{40}',source or'')and source==e.get('GITHUB_SHA')==e.get('WORKFLOW_SHA')and re.fullmatch('[1-9][0-9]{0,19}',run or'')and re.fullmatch('codex/[a-z0-9-]+',ref or'')and e.get('GITHUB_RUN_ATTEMPT')=='1'and e.get('GITHUB_REPOSITORY')==REPO and e.get('GITHUB_EVENT_NAME')=='workflow_dispatch'and e.get('RUNNER_ARCH')=='ARM64','genuine first native source/ref/run environment');return dict(source=source,run=run,ref=ref)
