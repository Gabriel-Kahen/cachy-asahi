# SPDX-License-Identifier: MIT
"""Source/Root build-only input authority. NULL refuses before actors or work."""
import hashlib,importlib.util,json,os,re,stat,sys,tempfile
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
import protocol as P
HERE=Path(__file__).resolve().parent;LANE='scripts/ci/gnu-verity-mapping-smoke';ROOT=HERE.parents[2]
need,pin,obj=P.need,P.pin,P.obj

def encoded(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def read(path,cap=1024**2):
 p=Path(path).absolute();need(not any(x.is_symlink()for x in(p,*p.parents)),'ordinary absolute input');a=p.lstat();need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded singlelink input');raw=p.read_bytes();b=p.lstat();need(len(raw)==a.st_size and(a.st_dev,a.st_ino,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_mtime_ns,b.st_ctime_ns),'input lifetime drift');return raw

def source(root):
 root=Path(root).absolute();lane=root/LANE;m=obj(read(lane/'source-manifest.json'));need(m['schema_version']==1 and m['purpose']=='GNU_VERITY_STANDALONE_MAPPING_INTEGRITY_SMOKE_V1','exact boot-only source manifest');actual=set()
 for p in root.rglob('*'):
  if p.relative_to(root).parts[0]=='.git':continue
  need(not p.is_symlink()and(p.is_file()or p.is_dir()),'ordinary source closure')
  if p.is_file():actual.add(p.relative_to(root).as_posix())
 need(actual==set(m['files'])|{LANE+'/source-manifest.json','.github/workflows/native-arm-build.yml','.github/workflows/native-arm-gnu-verity-mapping-smoke.yml'},'complete source closure')
 for n,v in m['files'].items():need(pin(read(root/n,4*1024**2))==v,'whole source pin: '+n)
 need(read(root/'.github/workflows/native-arm-build.yml')==read(root/'.github/workflows/native-arm-gnu-verity-mapping-smoke.yml'),'identical registered workflow')
 p=obj(read(lane/'input-policy.json'));need(p['scope']==P.SCOPE and all(p[k]is None for k in('actual_source','actual_ref','actual_run')),'boot-only default actuals NULL');return dict(status='PASS_SOURCE_ONLY_NO_ACTORS',files=len(actual),manifest=pin(read(lane/'source-manifest.json')),policy=p)

def bound(lane=None):
 lane=HERE if lane is None else lane
 p=obj(read(lane/'input-policy.json'));d=json.loads(read(lane/'kernel-descriptor.json'));decision=json.loads(read(lane/'Root-build-decision.json'));result=json.loads(read(lane/'kernel-build-result.json'))
 need(type(d)is dict and type(decision)is dict and type(result)is dict,'NULL kernel descriptor/Root build decision/result; refuse BEFORE actors')
 fields={'schema_version','status','source','ref','run_id','attempt','artifact','members','Root_decision','Root_strict_result','Image','config','profile','kernel_release','historical_transport'};need(set(d)==fields and d['schema_version']==1 and d['status']=='ROOT_BOUND_KERNEL_BUILD_INPUT_ONLY','exact kernel input descriptor')
 k=p['kernel_recipe'];need((d['source'],d['ref'],d['run_id'],d['attempt'],d['profile'],d['kernel_release'])==(k['source'],k['ref'],k['run'],1,k['profile'],P.RELEASE)and type(d['attempt'])is int,'only genuine new GNU source20/kernel run/first-attempt/profile')
 a=d['artifact'];need(set(a)=={'id','name','bytes','sha256'}and type(a['id'])is int and a['id']>0 and a['name']=='gnu-verity-kernel-build-only-'+d['run_id']+'-1'and type(a['bytes'])is int and 0<a['bytes']<=p['bounds']['input_artifact_bytes']and re.fullmatch('[0-9a-f]{64}',a['sha256']),'exact bounded genuine Actions artifact identity/digest')
 need(pin(read(lane/'Root-build-decision.json'))==d['Root_decision']and pin(read(lane/'kernel-build-result.json',2*1024**2))==d['Root_strict_result'],'whole Root build-only decision/strict-result bytes')
 need(decision.get('schema_version')==1 and decision.get('status')=='ROOT_ACCEPTED_GNU_VERITY_DIAGNOSTIC16K_BUILD_ONLY'and(decision.get('source'),decision.get('ref'),str(decision.get('run')))==(d['source'],d['ref'],d['run_id'])and decision.get('scope')=='NATIVE_BUILD_CONFIG_HEADER_AND_SOURCE_ENFORCED_OWNED_WORK_REMOVAL_ONLY'and decision.get('artifact')==dict(id=a['id'],name=a['name'],bytes=a['bytes'],digest='sha256:'+a['sha256'])and decision.get('Image')==d['Image']and decision.get('config')==d['config']and decision.get('strict_replay')==d['Root_strict_result']and all(decision.get(x)=='NOT_RUN'for x in('boot','VM','hardware'))and decision.get('release')=='NOT_ADMITTED','independent Root BUILD-ONLY decision required; no boot authority inherited')
 need(result.get('status')=='PASS_ORIGINAL_GNU_VERITY_DIAGNOSTIC16K_BUILD_ONLY_REPLAY'and(result.get('source'),result.get('ref'),result.get('run'))==(d['source'],d['ref'],d['run_id'])and result.get('scope')==decision['scope']and result['files']['Image']==d['Image']and result['files']['config']==d['config']and result['original_transport']['artifact']=={x:a[x]for x in('bytes','sha256')},'exact genuine strict kernel build result joins')
 need(decision.get('attempt')==1 and decision.get('workflow_id')==381664314 and decision.get('repository')=='Gabriel-Kahen/cachy-asahi'and decision.get('profile')==d['profile']and decision.get('source_files')==20 and decision.get('configuration',{}).get('active_changes')==14 and decision.get('configuration',{}).get('inactive_domain')==189 and decision.get('files')==d['members'],'held kernel20 source/profile/configuration and entire Root closure')
 need(type(d['members'])is dict and len(d['members'])==30 and sum(v['bytes']for v in d['members'].values())<=48*1024**2 and d['members']['Image']==d['Image']and d['members']['config']==d['config']and d['Image']['bytes']<=16*1024**2 and d['config']['bytes']<=262144,'finite whole kernel artifact members')
 for n,v in d['members'].items():need(re.fullmatch('[A-Za-z0-9_.-]+',n)and set(v)=={'bytes','sha256'}and type(v['bytes'])is int and 0<=v['bytes']<=16*1024**2 and re.fullmatch('[0-9a-f]{64}',v['sha256']),'finite exact member pins')
 historical=d['historical_transport'];need(set(historical)=={'run.json','artifacts.json','logs.zip','collection-outcome.json','bound-original.json'},'finite Root historical provenance DATA')
 for n,v in historical.items():need(pin(read(lane/'kernel-provenance'/n,8*1024**2))==v,'source-pinned Root historical input: '+n)
 need(historical['run.json']==decision['original_transport']['metadata']and historical['artifacts.json']==decision['original_transport']['artifact_metadata']and historical['logs.zip']==decision['original_transport']['logs'],'historical Root original transport joins')
 basis=obj(read(lane/'Root-boot-basis-decision.json'));need(basis['status']=='ROOT_ACCEPTED_GNU_VERITY_STANDALONE_BOOT_DM_TARGET_AVAILABILITY_ONLY'and basis['scope']=='BOOT_AND_DM_TARGET_AVAILABILITY_ONLY'and basis['source']=='bd31022395cc9231dfd966a4c0efc589ac1d49c2'and basis['ref']=='codex/gnu-verity-kernel-boot-probe-v1'and str(basis['run'])=='39159992802'and basis['attempt']==1 and basis['source_files']==72 and basis['source_authorization']==pin(read(lane/'boot-basis-source-authorization.json',2*1024**2))and basis['kernel_input']==dict(source=d['source'],ref=d['ref'],run_id=d['run_id'],artifact=d['artifact'],Image=d['Image'],config=d['config'])and basis['verity_mapping']==basis['integrity']==basis['lifecycle']=='NOT_TESTED'and basis['hardware']=='NOT_RUN','pinned genuine accepted availability basis only; no inherited mapping authority')
 return p,d,decision,result

@contextmanager
def kernel(d):
 folder=HERE/'kernel-reader';paths=list(sys.path);prior=sys.modules.pop('custody',None);sys.path.insert(0,str(folder))
 try:
  spec=importlib.util.spec_from_file_location('_boot_trusted_kernel_reader',folder/'replay.py');R=importlib.util.module_from_spec(spec);spec.loader.exec_module(R)
  with patch.object(R,'SOURCE',d['source']),patch.object(R,'REF',d['ref']),patch.object(R,'RUN',d['run_id']),patch.dict(sys.modules,{'replay':R}):
   R.preflight(folder/'source');yield R
 finally:
  sys.path[:]=paths;sys.modules.pop('custody',None)
  if prior is not None:sys.modules['custody']=prior

def input_replay(originals,d,output):
 for n,v in d['historical_transport'].items():need(pin(read(originals/n,8*1024**2))==v and read(originals/n,8*1024**2)==read(HERE/'kernel-provenance'/n,8*1024**2),'Root original small DATA held; fresh metadata never relabelled original')
 with kernel(d)as R:
  binding=R.read(originals/'bound-original.json');selected=dict(source_sha=d['source'],ref=d['ref'],run_id=d['run_id'],run_attempt='1');R.selected(binding,selected);run=R.read(originals/'run.json');R.run_identity(run,binding);api=R.read(originals/'artifacts.json');C=R.load('_boot_trusted_kernel_transport',R.HERE/'collect.py');a=C.artifact_row(api,binding)
  need((a['id'],a['name'],a['size_in_bytes'],a.get('digest'))==(d['artifact']['id'],d['artifact']['name'],d['artifact']['bytes'],'sha256:'+d['artifact']['sha256']),'exact descriptor/API artifact id/name/bytes/digest')
  raw=R.ordinary(originals/'artifact.zip',32*1024**2);need(pin(raw)=={k:d['artifact'][k]for k in('bytes','sha256')},'whole source-bound input artifact');files,index=R.archive_files(raw);need({n:pin(b)for n,b in files.items()}==d['members'],'entire original kernel artifact member closure')
  checked=R.replay(R.HERE/'source',originals/'artifact.zip',originals/'run.json',binding,selected,output);need(checked['files']['Image']==d['Image']and checked['files']['config']==d['config']and checked==obj(read(HERE/'kernel-build-result.json',2*1024**2)),'complete Root original strict result equality; same accepted Image/config only')
  return files,checked
