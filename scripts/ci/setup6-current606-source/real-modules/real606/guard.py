# SPDX-License-Identifier: MIT
"""Whole source608 mechanism held; new normal-consumer source is separately closed."""
import base64,hashlib,importlib.util,json,os,stat,sys,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent;PARENT_SOURCE='55e37c5fb0c01899cd474028c266a0208006db99'
WFS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-current606-doctor2-owned-copy.yml')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def raw(path):
 path=Path(path).absolute();need(not any(p.is_symlink()for p in(path,*path.parents)),'source aliases refused');a=path.lstat();need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=16*1024**2,'ordinary bounded singlelink source');value=path.read_bytes();key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns);need(len(value)==a.st_size and key(a)==key(path.lstat()),'whole stable source read');return value
def files(root):
 rows={}
 for path in sorted(root.rglob('*')):
  if path.relative_to(root).parts[0]=='.git':continue
  need(not path.is_symlink()and(path.is_file()or path.is_dir()),'ordinary closed source nodes')
  if path.is_file():rows[path.relative_to(root).as_posix()]=pin(raw(path))
 return rows
def module(name,path,aliases=None):
 saved={n:sys.modules.get(n)for n in(aliases or{})};sys.modules.update(aliases or{})
 try:
  spec=importlib.util.spec_from_file_location(name,path);out=importlib.util.module_from_spec(spec);sys.modules[name]=out;spec.loader.exec_module(out);return out
 finally:
  for n,v in saved.items():
   if v is None:sys.modules.pop(n,None)
   else:sys.modules[n]=v

def verify():
 need(not sys.flags.optimize,'optimized guards refused');mf=json.loads(raw(HERE/'source-manifest.json'));actual=files(ROOT);need(mf['purpose']=='FULL606_SETUP6_REAL_MODULES_NATIVE_CORRECTNESS'and mf['actual']is None and len(actual)==mf['source_files']and mf['files']=={n:r for n,r in actual.items()if n not in{'real606/source-manifest.json',*WFS}},'whole closed native source membership')
 for name in WFS:
  text=raw(ROOT/name).decode();need(text.count(pin(raw(HERE/'source-manifest.json'))['sha256'])==1 and text.count(actual['real606/run.py']['sha256'])==1,'exact emitted workflow manifest/entry stamps')
 proof=json.loads(raw(HERE/'parent.json'));before=proof['files'];need(len(before)==608 and proof['publication']==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source=PARENT_SOURCE,ref='codex/setup6-current606-v1',files=608,git_joins=608,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and proof['git']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=PARENT_SOURCE,ref='codex/setup6-current606-v1',files=before),'whole genuine608 publication/source/Git')
 bodies={n:base64.b64decode(proof['before_bodies'][n],validate=True)if n in proof['before_bodies'] else raw(ROOT/n)for n in before};need({n:pin(v)for n,v in bodies.items()}==before,'all608 original bytes inverse')
 old_policy=json.loads(bodies['scripts/ci/native-evidence-transport/doctor-policy.json']);new_policy=json.loads(raw(ROOT/'scripts/ci/native-evidence-transport/doctor-policy.json'));need(old_policy['workflow_name']=='native-arm-current606-doctor2-owned-copy'and new_policy==dict(old_policy,workflow_name='native-arm-current606-setup6-real-modules'),'exact original transport policy with only genuine emitted workflow-name correction')
 saved,paths=dict(sys.modules),sys.path[:]
 try:
  with tempfile.TemporaryDirectory(prefix='setup-original608-')as temp:
   old=Path(temp)/'source';old.mkdir()
   for name,value in bodies.items():p=old/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(value)
   lane=old/'scripts/ci/current606-doctor2-closed-owner';sys.path.insert(0,str(lane))
   for name in('contract','selection'):sys.modules.pop(name,None)
   C=module('_whole_original608_guard',lane/'contract.py');fact=C.verify();need(fact['files']==608 and fact['roles']['setup240']==240 and fact['roles']['held606']==263,'complete608 guard/240/263 original roles')
 finally:
  sys.path[:]=paths
  for name in set(sys.modules)-set(saved):sys.modules.pop(name,None)
  sys.modules.update(saved)
 return dict(status='SOURCE_ONLY_FULL606_REAL_MODULES_READY_NOT_RUN',files=len(actual),original_files=608,bounds=mf['bounds'],actual=None,Apps7='NOT_RUN_BASELINE_APPS6',hardware='NOT_RUN')

def anchor():
 lane=ROOT/'scripts/ci/current606-doctor2-closed-owner';sys.path.insert(0,str(lane))
 for name in('contract','selection','runtime','builds','producer_diagnostic'):sys.modules.pop(name,None)
 return module('_whole_original608_owner_api',lane/'owner.py')
