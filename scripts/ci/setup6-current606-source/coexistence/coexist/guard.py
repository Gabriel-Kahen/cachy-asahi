# SPDX-License-Identifier: MIT
"""Closed coexistence source and whole immutable636/608 ancestry, no actual credit."""
import base64,hashlib,importlib.util,json,stat,sys,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent;PARENT_SOURCE='a8eb556eed8813762b2ad50598741a2e3d51a022'
WFS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-current606-doctor2-owned-copy.yml')
def need(v,n):
 if not v:raise ValueError(n)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def raw(path):
 path=Path(path).absolute();need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary source path');a=path.lstat();need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=16*1024**2,'singlelink bounded source');b=path.read_bytes();key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns);need(len(b)==a.st_size and key(a)==key(path.lstat()),'source changed during read');return b
def files(root):
 out={}
 for p in sorted(root.rglob('*')):
  if p.relative_to(root).parts[0]=='.git':continue
  need(not p.is_symlink()and(p.is_file()or p.is_dir()),'closed ordinary source nodes')
  if p.is_file():out[p.relative_to(root).as_posix()]=pin(raw(p))
 return out
def module(name,path,aliases=None):
 saved={n:sys.modules.get(n)for n in(aliases or{})};sys.modules.update(aliases or{})
 try:
  spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
 finally:
  for n,v in saved.items():
   if v is None:sys.modules.pop(n,None)
   else:sys.modules[n]=v

def verify():
 need(not sys.flags.optimize,'optimized checks refused');mf=json.loads(raw(HERE/'source-manifest.json'));actual=files(ROOT);need(mf['purpose']=='FULL606_APPS7_SETUP6_COEXISTENCE_NATIVE_CORRECTNESS'and mf['actual']is None and len(actual)==mf['source_files']and mf['files']=={n:r for n,r in actual.items()if n not in{*WFS,'coexist/source-manifest.json'}},'entire exact coexistence source')
 for name in WFS:
  text=raw(ROOT/name).decode();need(text.count(pin(raw(HERE/'source-manifest.json'))['sha256'])==1 and text.count(actual['coexist/run.py']['sha256'])==1,'exact workflow stamps')
 parent=json.loads(raw(HERE/'parent636.json'));need(len(parent['files'])==636 and parent['authority']=='GENUINE_ROOT_PUBLISHED_SOURCE_ONLY_NO_NATIVE_ACCEPTANCE'and parent['publication']==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source='a8eb556eed8813762b2ad50598741a2e3d51a022',ref='codex/setup6-full606-real-modules-transport-v1',files=636,git_joins=636,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and parent['git']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=parent['publication']['source'],ref=parent['publication']['ref'],files=parent['files']),'whole source-only636 parent, no transfer');bodies={n:base64.b64decode(parent['workflow_before'][n],validate=True)if n in WFS else raw(ROOT/n)for n in parent['files']};need({n:pin(v)for n,v in bodies.items()}==parent['files'],'all original636 bytes held outside explicit workflow inverse')
 saved,paths=dict(sys.modules),sys.path[:]
 try:
  with tempfile.TemporaryDirectory(prefix='coexist-original636-')as temp:
   old=Path(temp)/'source';old.mkdir()
   for n,v in bodies.items():p=old/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(v)
   for n in('guard','latest_plan','integration','contract','selection'):sys.modules.pop(n,None)
   g=module('_whole_immutable_636_source_guard',old/'real606/guard.py');fact=g.verify();need(fact['files']==636 and fact['original_files']==608,'whole636 plus original608 guards')
 finally:
  sys.path[:]=paths
  for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
  sys.modules.update(saved)
 home=HERE/'apps7-prerequisite';profile=json.loads(raw(home/'profile.json'));need(profile['source']=='3660e6cb87b4cb5591b1d295c62c8b02cca4b7e6'and profile['run']==39320580643 and profile['new_actual']is None,'exact accepted Apps7 prerequisite')
 for n,row in profile['files'].items():need(pin(raw(home/n))==row,'whole accepted prerequisite input pins')
 acceptance=json.loads(raw(home/'Root-component-acceptance.json'));result=raw(home/'Root-corrected-reader-result.json');need(acceptance['status']=='ROOT_ACCEPTED_FINITE_CURRENT606_APPS7_NATIVE_ARTIFACT_PRESERVATION'and acceptance['source']==profile['source']and acceptance['run']==profile['run']and acceptance['corrected_positive']==pin(result),'full separately accepted Apps7 result no coexistence transfer')
 return dict(status='SOURCE_ONLY_FULL606_APPS7_SETUP6_COEXISTENCE_NOT_RUN',files=len(actual),parent_files=636,original_files=608,bounds=mf['bounds'],actual=None,hardware='NOT_RUN')
def anchor():
 lane=ROOT/'scripts/ci/current606-doctor2-closed-owner';sys.path.insert(0,str(lane))
 for n in('contract','selection','runtime','builds','producer_diagnostic'):sys.modules.pop(n,None)
 return module('_whole_original608_owner_api',lane/'owner.py')
