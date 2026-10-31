"""Existing kernel20 artifact only; prior provenance is never a fresh collection."""
import argparse,contextlib,os,re,resource,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import deploy as D
NAMES={'metadata':'run.json','artifact_metadata':'artifacts.json','logs':'logs.zip'}
@contextlib.contextmanager
def reader():
 folder=D.HERE/'kernel-reader';oldpath=list(sys.path);prior={n:sys.modules.pop(n,None)for n in('custody','replay','collect')};sys.path.insert(0,str(folder))
 try:
  R=D.load('_immutable_kernel20_trusted_replay',folder/'replay.py');R.preflight(folder/'source');yield R
 finally:
  sys.path[:]=oldpath
  for n,v in prior.items():
   sys.modules.pop(n,None)
   if v is not None:sys.modules[n]=v
def known():
 k=D.obj(D.read(D.HERE/'known-kernel.json'));v=D.obj(D.read(D.HERE/'kernel-provenance/Root-acceptance.json'));D.need(D.pin(D.read(D.HERE/'kernel-provenance/Root-acceptance.json'))==k['kernel_decision']and v['source']==k['source']=='4056e2505ed7081674e949e0460258672cce14ff'and str(v['run'])==k['run']=='39156901928'and v['artifact']['id']==k['artifact']['id']==12147995917 and v['status']=='ROOT_ACCEPTED_GNU_VERITY_DIAGNOSTIC16K_BUILD_ONLY'and v['scope']=='NATIVE_BUILD_CONFIG_HEADER_AND_SOURCE_ENFORCED_OWNED_WORK_REMOVAL_ONLY'and all(v[n]=='NOT_RUN'for n in('boot','VM','hardware'))and v['files']==k['members']and len(k['members'])==30,'exact genuine Root BUILD-only20, never boot')
 for kind,n in NAMES.items():D.need(D.pin(D.read(D.HERE/'kernel-provenance'/n,8*1024**2))==k['transport'][kind],'whole prior Root transport provenance '+kind)
 D.need(D.pin(D.read(D.HERE/'kernel-provenance/Root-strict-result.json'))==v['strict_replay']==k['kernel_strict_result'],'whole Root strict result');return k,v
def get(endpoint,target,cap,seconds,token):
 D.need(re.fullmatch(r'repos/Gabriel-Kahen/cachy-asahi/actions/(?:runs/39156901928(?:/artifacts\?per_page=100)?|artifacts/12147995917/zip)',endpoint)is not None and type(token)is str and token and '\0'not in token,'fixed GET endpoint/token')
 with target.open('xb')as out,target.with_suffix(target.suffix+'.stderr').open('xb')as err:
  r=subprocess.run(['/usr/bin/gh','api','--hostname','github.com','--method','GET',endpoint],stdin=subprocess.DEVNULL,stdout=out,stderr=err,env=dict(PATH='/usr/bin:/bin',HOME=str(target.parent),GH_CONFIG_DIR=str(target.parent/'gh-config'),GITHUB_TOKEN=token,GH_PROMPT_DISABLED='1',GH_NO_UPDATE_NOTIFIER='1'),timeout=seconds,preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_FSIZE,(cap,cap)))
 D.need(r.returncode==0,'single existing-artifact GET failed; no retry')
def replay(originals,output):
 k,v=known();originals=Path(originals).absolute();output=Path(output).absolute()
 for kind,n in NAMES.items():D.need(D.pin(D.read(originals/n,8*1024**2))==k['transport'][kind],'exact PRIOR original transport '+kind)
 with reader()as R:
  binding=R.read(originals/'bound-original.json');selected={n:binding[n]for n in('source_sha','ref','run_id','run_attempt')};R.selected(binding,selected);R.run_identity(R.read(originals/'run.json'),binding)
  raw=R.ordinary(originals/'artifact.zip',32*1024**2);D.need(D.pin(raw)==k['transport']['artifact'],'whole SAME existing artifact bytes');files,index=R.archive_files(raw);D.need({n:D.pin(b)for n,b in files.items()}==k['members'],'whole30 original member closure')
  result=R.replay(R.HERE/'source',originals/'artifact.zip',originals/'run.json',binding,selected,output);D.need(result==D.obj(D.read(D.HERE/'kernel-provenance/Root-strict-result.json')),'whole strict20 replay equals Root accepted original DATA')
 return files,result
def acquire(output,fetch=get,token=None):
 k,v=known();token=os.environ.get('GITHUB_TOKEN')if token is None else token;D.need(type(token)is str and bool(token),'actions:read token only');output=D.private(output);start=time.monotonic();deadline=start+300
 D.write(output/'acquisition-intent.json',D.encoded(dict(context='INPUT_API_ACQUISITION_KERNEL20',once=True,retry=False,original_Root_collection=False,artifact_id=12147995917,seconds=300)));(output/'gh-config').mkdir(mode=0o700)
 def take(name,endpoint,cap,seconds):
  remain=deadline-time.monotonic();D.need(remain>0,'shared300s acquisition deadline');p=output/(name+'.partial');fetch(endpoint,p,cap,min(seconds,remain),token);D.read(p,cap);D.need(not(output/name).exists(),'exclusive complete input');os.link(p,output/name,follow_symlinks=False);p.unlink();return output/name
 try:
  current=take('fresh-run.json','repos/'+D.REPO+'/actions/runs/39156901928',1024**2,40);api=take('fresh-artifacts.json','repos/'+D.REPO+'/actions/runs/39156901928/artifacts?per_page=100',2*1024**2,40)
  with reader()as R:
   binding=dict(source_sha=k['source'],ref=k['ref'],run_id=k['run'],run_attempt='1',artifact_sha256=k['artifact']['sha256']);R.run_identity(D.obj(D.read(current)),binding);T=R.load('_immutable_trusted_artifact_row',R.HERE/'collect.py');item=T.artifact_row(D.obj(D.read(api)),binding);D.need((item['id'],item['name'],item['size_in_bytes'],item.get('digest'))==(k['artifact']['id'],k['artifact']['name'],k['artifact']['bytes'],'sha256:'+k['artifact']['sha256']),'fresh unique unexpired same-source artifact identity before download')
  archive=take('artifact.zip','repos/'+D.REPO+'/actions/artifacts/12147995917/zip',k['artifact']['bytes'],120);D.need(D.pin(D.read(archive,32*1024**2))==k['transport']['artifact'],'existing whole original artifact ZIP digest')
  originals=output/'prior-originals';originals.mkdir(mode=0o700)
  for n in('run.json','artifacts.json','logs.zip','bound-original.json','collection-outcome.json'):D.write(originals/n,D.read(D.HERE/'kernel-provenance'/n,8*1024**2))
  D.write(originals/'artifact.zip',D.read(archive,32*1024**2));files,checked=replay(originals,output/'strict-replay');D.need(time.monotonic()<=deadline,'same300s complete acquisition/replay')
  for n in('Image','config'):D.write(output/n,files[n])
  descriptor=dict(purpose='EXISTING_ACTIONS_KERNEL_ARTIFACT_INPUT_ONLY',source=k['source'],run=k['run'],artifact_id=k['artifact']['id'],artifact_name=k['artifact']['name'],archive=k['transport']['artifact'],Image=k['Image'],config=k['config'],kernel_build_decision=k['kernel_decision'],scope='BUILD_ONLY_NOT_BOOT_OR_MAPPING_OR_LIFECYCLE');D.write(output/'Root-artifact-replay.json',D.encoded(descriptor))
  result=dict(context='INPUT_API_ACQUISITION_KERNEL20',status='EXACT_EXISTING_ARTIFACT_AND_PRIOR_STRICT20_REPLAY',fresh_metadata=D.pin(D.read(current)),fresh_artifact_metadata=D.pin(D.read(api)),prior_transport=k['transport'],original_Root_collection=False,artifact=k['transport']['artifact'],members=30,boot='NOT_RUN',new_Root_acceptance=False);D.write(output/'acquisition-result.json',D.encoded(result));return result
 except BaseException as error:D.write(output/'acquisition-failure.json',D.encoded(dict(status='FAILED_OR_UNKNOWN_NO_RETRY',error_type=type(error).__name__,original_Root_collection=False,acceptance=False)));raise
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(D.encoded(acquire(a.output)).decode(),end='')
