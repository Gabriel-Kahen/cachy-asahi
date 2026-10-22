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

# BEGIN_PRIVATE_IMMUTABLE_NODE_MAP_SOURCE
# Full original745 source remains a mandatory independent source predicate.
def immutable_node_map_source(root,fact,profile_pin):
 import base64,importlib.util,tempfile
 root=Path(root);proof=obj(read(root/LANE/'runtime-derivation.json',4*1024**2))['immutable_node_map_successor'];need(pin(encoded(proof))==profile_pin,'whole exact immutable node-map successor proof');before=proof['before'];changed=set(proof['before_bodies']);actual={}
 for path in root.rglob('*'):
  if path.relative_to(root).parts[0]=='.git':continue
  need(not path.is_symlink()and(path.is_file()or path.is_dir()),'ordinary source closure')
  if path.is_file():actual[path.relative_to(root).as_posix()]=pin(read(path,16*1024**2))
 need(len(before)==len(actual)==745 and set(actual)==set(before)and {n for n in before if actual[n]!=before[n]}==changed,'full745 finite source inverse');need(proof['scope']=='PRIVATE_IMMUTABLE_COPY_LOOP_NODES_NO_FILESYSTEM_CACHE'and all(proof[n]is None for n in('actual_source','actual_ref','actual_run','Root_acceptance')),'fixed immutable map scope and actualNULL')
 pub=proof['publication'];need(pub==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source='406d5a3a8902570c8fb1fa5043c557b18d15b308',ref='codex/gnu745-boundary-diagnostic-v1',files=745,git_joins=745,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and proof['git']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=pub['source'],ref=pub['ref'],files=before)and proof['authorization']==before,'whole genuine745 source/Git authority');need(all(actual[n]==w for n,w in proof['helpers'].items()),'exact proposed runtime/adapter/test bodies')
 bodies={n:base64.b64decode(proof['before_bodies'][n],validate=True)if n in changed else read(root/n,16*1024**2)for n in before};need(all(pin(bodies[n])==w for n,w in before.items()),'all745 original bodies held or reconstructed')
 adapter=load('_node_map_exact_source_adapter',root/LANE/'runtime_adapter.py');need(adapter.immutable_node_map_derivative(bodies['runtime/immutable/worker_api.py'])==read(root/'runtime/immutable/worker_api.py'),'entire worker outside two finite immutable map seams')
 path=proof['deploy'];text=read(root/path,16*1024**2).decode();marker='\n# BEGIN_PRIVATE_IMMUTABLE_NODE_MAP_SOURCE\n';parts=text.split(marker);footer="\n_IMMUTABLE_NODE_MAP_PREVIOUS_SOURCE=source\n_IMMUTABLE_NODE_MAP_PROFILE_PIN="+repr(profile_pin)+"\ndef source(root=ROOT):\n fact=_IMMUTABLE_NODE_MAP_PREVIOUS_SOURCE(root)\n return immutable_node_map_source(root,fact,_IMMUTABLE_NODE_MAP_PROFILE_PIN)\n";need(len(parts)==2 and parts[0].encode()==bodies[path]and parts[1].endswith(footer)and pin(parts[1].removesuffix(footer).encode())==proof['guard_fragment'],'whole original deploy body plus fixed mandatory guard')
 need(fact['files']==745,'complete current source/manifest/workflow gate')
 saved,paths=dict(sys.modules),sys.path[:]
 try:
  with tempfile.TemporaryDirectory(prefix='gnu-whole745-')as td:
   old=Path(td)/'source';old.mkdir()
   for n,b in bodies.items():p=old/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b)
   for p in(old/LANE).glob('*.py'):sys.modules.pop(p.stem,None)
   sys.path.insert(0,str(old/LANE));s=importlib.util.spec_from_file_location('_gnu_whole_original745_deploy',old/LANE/'deploy.py');m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m);old_fact=m.source(old);need(old_fact['files']==745,'complete original745 source predicate')
 finally:
  sys.path[:]=paths
  for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
  sys.modules.update(saved)
 return dict(fact,whole_original745=old_fact,copy_node_map='PRIVATE_IMMUTABLE_FULL_OBSERVATIONS_HELD',native_fit='UNKNOWN')

_IMMUTABLE_NODE_MAP_PREVIOUS_SOURCE=source
_IMMUTABLE_NODE_MAP_PROFILE_PIN={'bytes': 1815397, 'sha256': 'c0ac563ea5f6fab84f4acdb0cc5aa33a46410e051233af217b757f9c9585b97c'}
def source(root=ROOT):
 fact=_IMMUTABLE_NODE_MAP_PREVIOUS_SOURCE(root)
 return immutable_node_map_source(root,fact,_IMMUTABLE_NODE_MAP_PROFILE_PIN)
