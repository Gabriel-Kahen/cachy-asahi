# SPDX-License-Identifier: MIT
"""Whole closed new source and genuine immutable676 mechanism; no new acceptance."""
import ast,base64,hashlib,importlib.util,json,stat,sys,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent;PARENT_SOURCE='5a45919d81890c3196cb712b0b67272d4469f570';WFS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-current606-doctor2-owned-copy.yml')
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def raw(path):
 path=Path(path).absolute();need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary noalias source');a=path.lstat();need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=16*1024**2,'finite singlelink source');v=path.read_bytes();key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns);need(len(v)==a.st_size and key(a)==key(path.lstat()),'stable full source read');return v
def files(root):
 out={}
 for path in sorted(root.rglob('*')):
  if path.relative_to(root).parts[0]=='.git':continue
  need(not path.is_symlink()and(path.is_dir()or path.is_file()),'closed ordinary source nodes')
  if path.is_file():out[path.relative_to(root).as_posix()]=pin(raw(path))
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
 need(not sys.flags.optimize,'optimized checks refused');mf=json.loads(raw(HERE/'source-manifest.json'));actual=files(ROOT);need(mf['purpose']=='FULL606_APPS7_SETUP6_FRESH_USER_SOFTWARE_ONBOARDING'and mf['actual']is None and len(actual)==mf['source_files']and mf['files']=={n:r for n,r in actual.items()if n not in{*WFS,'developer/source-manifest.json'}},'whole exact source closure')
 for n in WFS:
  text=raw(ROOT/n).decode();need(text.count(pin(raw(HERE/'source-manifest.json'))['sha256'])==1 and text.count(actual['developer/run.py']['sha256'])==1,'exact isolated entry and manifest workflow stamps')
 proof=json.loads(raw(HERE/'parent676.json'));expected=dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source=PARENT_SOURCE,ref='codex/setup6-apps7-current606-v1',files=676,git_joins=676,actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED');need(proof['publication']==expected and proof['git']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=PARENT_SOURCE,ref=expected['ref'],files=proof['files'])and len(proof['files'])==676,'whole genuine published676 source/Git context')
 bodies={n:base64.b64decode(proof['workflow_before'][n],validate=True)if n in WFS else base64.b64decode(proof['changed_before'][n],validate=True)if n in proof['changed_before']else raw(ROOT/n)for n in proof['files']};need({n:pin(v)for n,v in bodies.items()}==proof['files'],'all676 original bytes and complete workflow inverse')
 saved,paths=dict(sys.modules),sys.path[:]
 try:
  with tempfile.TemporaryDirectory(prefix='developer-original676-')as temp:
   root=Path(temp)/'source';root.mkdir()
   for n,v in bodies.items():p=root/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(v)
   for n in('guard','integration','latest_plan','contract','selection'):sys.modules.pop(n,None)
   original=module('_whole_original676_source_guard',root/'coexist/guard.py');prior=original.verify();need(prior['files']==676 and prior['parent_files']==636 and prior['original_files']==608,'entire original676/636/608 guards')
 finally:
  sys.path[:]=paths
  for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
  sys.modules.update(saved)
 profile=json.loads(raw(HERE/'mechanism-profile.json'));need(profile['original_run']==38237127237 and profile['original_component']=='PASS'and profile['original_aggregate']=='FAIL'and profile['new_actual']is None,'separate old onboarding mechanism context; no acceptance transfer')
 for n,row in profile['held'].items():need(pin(raw(HERE/n))==row,'whole reviewed journey/source/license/mechanism receipt')
 need(json.loads(raw(HERE/'held/component-status.json'))==dict(status='PASS')and json.loads(raw(HERE/'held/summary.json'))['status']=='FAIL','old component PASS and aggregate FAIL retained')
 original=raw(HERE/'held/onboarding-original.py');current=raw(HERE/'held/onboarding.py');prior=json.loads(raw(HERE/'held/original-result.json'));need(prior['contract']['entry_sha256']==pin(original)['sha256']and prior['status']=='SOFTWARE PASS','exact old actual engine pin and software result')
 index={r['path']:dict(bytes=r['bytes'],sha256=r['sha256'])for r in json.loads(raw(HERE/'held/onboarding-export.json'))['accepted']}
 for source,destination in(('artifacts/result.json','held/original-result.json'),('artifacts/journey-commands.json','held/original-journey-commands.json')):need(index[source]==pin(raw(HERE/destination)),'whole retained original onboarding export pins')
 def section(raw,name):
  text=raw.decode();return ast.get_source_segment(text,next(n for n in ast.parse(text).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))and n.name==name))
 for name in('journey','home_snapshot','spawn_signals','defer_cancellation','Failure','sha','now','save'):need(section(original,name)==section(current,name),'all used original journey/helper bodies held')
 before=section(original,'Commands');after=section(current,'Commands');needle='                os.close(slave)\n                slave = None';replacement='                    os.close(slave)\n                    slave = None';need(before.count(needle)==after.count(replacement)==1 and before.replace(needle,replacement,1)==after,'only current safer deferred PTY close in full original Commands body')
 return dict(status='SOURCE_ONLY_FULL606_FRESH_USER_ONBOARDING_NOT_RUN',files=len(actual),parent_files=676,graphs=29,transactions=14,real_suites=4,bounds=mf['bounds'],actual=None,hardware='NOT_RUN',independent_new_user_install='NOT_RUN')

def anchor():
 lane=ROOT/'scripts/ci/current606-doctor2-closed-owner';sys.path.insert(0,str(lane))
 for n in('contract','selection','runtime','builds','producer_diagnostic'):sys.modules.pop(n,None)
 return module('_whole_original608_owner_api',lane/'owner.py')
