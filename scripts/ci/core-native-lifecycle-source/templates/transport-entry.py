# SPDX-License-Identifier: MIT
"""Finite native Core7 lifecycle entry; frozen sources before secrets or actors."""
import argparse,hashlib,importlib.util,json,os,re,stat,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
HERE=Path(__file__).resolve().parent;LANE='scripts/ci/core-native-lifecycle';VM='runtime/runtime-vm';DEPLOY='scripts/ci/gnu-immutable-source-native';WORKFLOWS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core-lifecycle.yml')

def source(root):
 root=Path(root).absolute();manifest=root/LANE/'source-manifest.json';raw=C.read(manifest);v=json.loads(raw);need=C.need;need(v['purpose']=='CORE7_NATIVE_DISPOSABLE_LIFECYCLE'and v['actual_source']is v['actual_ref']is v['actual_run']is None,'new actual bindings NULL');rows=v['files'];expected=set(rows)|{LANE+'/source-manifest.json',*WORKFLOWS};actual={};need(not any(p.is_symlink()for p in(root,*root.parents)),'ordinary source ancestry')
 for p in root.rglob('*'):
  if p.relative_to(root).parts[0]=='.git':continue
  need(not p.is_symlink()and(p.is_file()or p.is_dir()),'ordinary complete source closure')
  if p.is_file():actual[p.relative_to(root).as_posix()]=C.pin(C.read(p,32*1024**2))
 need(set(actual)==expected and all(actual[n]==r for n,r in rows.items()),'whole closed native source bytes')
 template=C.read(root/LANE/'workflow.yml.in').decode().replace('@ENTRY_SHA@',rows[LANE+'/entry.py']['sha256']).replace('@MANIFEST_SHA@',C.pin(raw)['sha256']).encode();need(all(C.read(root/n)==template for n in WORKFLOWS),'exact generated registered workflows')
 return dict(status='PASS_CLOSED_CORE7_SOURCE_ONLY',files=len(actual),actual=None,hardware='NOT_RUN')

def identity(root):
 e=os.environ;s=e.get('SOURCE_SHA');C.need(re.fullmatch('[a-f0-9]{40}',s or'')and s==e.get('GITHUB_SHA')==e.get('WORKFLOW_SHA')and e.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi'and e.get('GITHUB_EVENT_NAME')=='workflow_dispatch'and e.get('GITHUB_RUN_ATTEMPT')=='1'and e.get('RUNNER_ARCH')=='ARM64'and re.fullmatch('codex/[a-z0-9-]+',e.get('GITHUB_REF_NAME','')),'genuine first native workflow source/ref/attempt')
 value=source(root);value.update(source_sha=s,run_id=e['GITHUB_RUN_ID'],attempt=1,ref=e['GITHUB_REF_NAME']);C.need(re.fullmatch('[1-9][0-9]{0,19}',value['run_id']),'typed native run');stamp=value['run_id']+':1:'+s;value.update(producer_token=hashlib.sha256(('core-native574:'+stamp).encode()).hexdigest()[:16],consumer_token=hashlib.sha256(('core-native7:'+stamp).encode()).hexdigest()[:32]);proof=C.S.prove(Path(root).absolute(),Path(root).absolute()/'.git',dict(source=s,ref=value['ref'],files={p.relative_to(root).as_posix():C.pin(C.read(p,32*1024**2))for p in Path(root).rglob('*')if p.is_file()and'.git'not in p.relative_to(root).parts}),time.monotonic()+180);value['git']=proof;return value

def load(name,path):return C.load(name,path)

def prefill(args):
 source(args.source);sys.path.insert(0,str(HERE/'retained'));import legacy_prefill as L
 end=time.monotonic()+230;lane=args.source/DEPLOY;lock=args.source/VM/'scripts/ci/maintained-desktop574-inputs.json';records={}
 for n in(32,20,8):
  m=load('core_unchanged_archive'+str(n),lane/('archive'+str(n)+'.py'));v=m.policy(lane/('archive'+str(n)+'-policy.json'),lock);records[str(n)]=L.prefill(args.carrier,args.temp/('core-lifecycle-archive'+str(n)),v,end,git_dir=args.carrier/'.git',profile_dir=HERE/'retained')
 args.receipt.write_bytes(C.encoded(dict(status='EXACT_LEGACY_PREFILL_DATA_ONLY',records=records,authentication='UNCHANGED_ORIGINAL_CLI_INDEX_GPG_REQUIRED')));return 0

def seed(args):
 source(args.source);lane=args.source/DEPLOY;lock=args.source/VM/'scripts/ci/maintained-desktop574-inputs.json';records={}
 for n in(32,20,8):
  m=load('core_unchanged_seed'+str(n),lane/('archive'+str(n)+'.py'));v=m.policy(lane/('archive'+str(n)+'-policy.json'),lock);cache=args.temp/('core-lifecycle-archive'+str(n));index=m.checked_index(cache,v);C.need(index['requests']==0 and index['reused']==n,'all original legacy policy inputs reused with zero HTTP');records[str(n)]=dict(index=index,custody=m.seed_exact(cache,args.base/'context/deps',v))
 sys.path.insert(0,str(HERE/'retained'));import prepare as R
 complete=R.prepare(args.carrier,args.base/'context/deps','desktop574',lock,time.monotonic()+230,args.carrier/'.git');import cache_data;cache_data.validate(complete,records);args.receipt.write_bytes(C.encoded(dict(status='EXACT_ALL_LEGACY_AND_COMPLETE1148_CACHE_DATA_ONLY',legacy=records,complete=complete,authentication='UNCHANGED_ORIGINAL574_CURRENT_SIGNATURE_METADATA_BUILD_REQUIRED')));return 0

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('source','proof','prefill','seed','execute','cleanup','retain','transport'));p.add_argument('--source',type=Path,required=True)
 for name in('proof','carrier','core7','core64','temp','base','output','receipt','public'):p.add_argument('--'+name,type=Path)
 a=p.parse_args();a.source=a.source.absolute();a.workspace=a.source/VM
 if a.mode=='source':print(C.encoded(source(a.source)).decode(),end='');return 0
 if a.mode=='proof':
  C.need(a.proof is not None and not a.proof.exists(),'fresh source proof');value=identity(a.source);a.proof.write_bytes(C.encoded(value))
  with open(os.environ['GITHUB_OUTPUT'],'a')as out:out.write('job_token='+value['producer_token']+'\n')
  return 0
 if a.mode=='prefill':return prefill(a)
 if a.mode=='seed':return seed(a)
 source(a.source);import owner
 if a.mode=='transport':return owner.transport(a)
 if a.mode=='execute':
  end=time.monotonic()+180;profile=C.profile();C.S.prove(a.core7,a.core7/'.git',profile['core7'],end);C.S.prove(a.core64,a.core64/'.git',profile['retained64'],end);C.packet(a.core7);return owner.execute(a)
 if a.mode=='cleanup':return owner.cleanup(a)
 return owner.retain(a)
if __name__=='__main__':
 def cancelled(*_):raise KeyboardInterrupt()
 import signal
 for number in(signal.SIGTERM,signal.SIGINT):signal.signal(number,cancelled)
 raise SystemExit(main())
