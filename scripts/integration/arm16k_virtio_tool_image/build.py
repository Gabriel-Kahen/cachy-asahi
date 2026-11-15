#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-admitted offline one-package tool-image successor; never boots a guest."""
import argparse,datetime,hashlib,importlib.util,json,os,re,secrets,shutil,stat,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent

def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);exec(compile(Path(path).read_bytes(),str(path),'exec'),m.__dict__);return m
C=load('virtio_image_contract',HERE/'contract.py')
def source_manifest():
 return {p.relative_to(HERE).as_posix():C.pin(p.read_bytes())for p in sorted(HERE.rglob('*'))if p.is_file()and '__pycache__'not in p.parts}
def held(fd):
 canonical=Path('/home/gabe/Documents/ChatGPT/cachy-asahi/artifacts/development/orchestrator-resume-20261025/shared-GUI-ancestor-collection.lock');s=os.fstat(fd);p=canonical.lstat();key=lambda x:(x.st_dev,x.st_ino,x.st_mode,x.st_uid,x.st_gid,x.st_nlink,x.st_size,x.st_mtime_ns,x.st_ctime_ns)
 C.need(key(s)==key(p)and stat.S_ISREG(s.st_mode)and s.st_uid==os.getuid()and s.st_size==0 and not canonical.is_symlink(),'borrowed canonical lease FD/path identity');C.need(os.readlink('/proc/self/fd/'+str(fd))==str(canonical)and re.search(r'lock:\s+\d+: FLOCK\s+ADVISORY\s+WRITE\s+',Path('/proc/self/fdinfo/'+str(fd)).read_text()),'preexisting exclusive canonical flock required; never acquire/unlock here')
def authority(a,v):
 raw=C.read(a.authority.resolve(),65536);C.need(C.pin(raw)['sha256']==a.authority_sha256,'whole external Root authority');r=json.loads(raw);when=datetime.datetime.fromisoformat(r['issued_at']);C.need(when.utcoffset()is not None and 0<=(datetime.datetime.now(datetime.timezone.utc)-when).total_seconds()<=3600,'fresh independent Root authority')
 C.need(r['issuer']=='Root'and r['approved']is True and r['operation']==v['operation']and r['parent_image_id']==v['parent_image_id']and r['resources']==v['resources']and r['output']==str(a.output.resolve())and r['once']is True and r['retry']is False and r['source_manifest']==source_manifest()and r['archive']==v['package']['archive']and r['signature']==v['package']['signature'],'exact reviewed source/material/resource authority');return r

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-offline-image-build',action='store_true')
 for name in('packages','runtime-root','authority','output'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--authority-sha256',required=True);p.add_argument('--lock-fd',type=int,required=True);a=p.parse_args()
 if not(a.allow_offline_image_build and sys.version_info>=(3,14)and sys.flags.isolated and __debug__ and os.getuid()!=0):p.error('explicit admitted isolated ordinary-user invocation required')
 v=C.lock();review=authority(a,v);held(a.lock_fd);package_root=a.packages.resolve(strict=True);package=package_root/v['package']['filename'];C.need({p.name for p in package_root.iterdir()}=={package.name,package.name+'.sig'},'only exact two public package inputs may be mounted');C.archive(package);C.checked(str(package)+'.sig',v['package']['signature'])
 root=a.runtime_root.resolve(strict=True)
 for n,row in v['runtime'].items():C.checked(root/n,row)
 B=load('virtio_existing_owned_container',root/'reference_controller.py');R=load('virtio_existing_command_runtime',root/'command_runtime.py');out=a.output.resolve();C.need(not out.exists()and out!=HERE and not out.is_relative_to(HERE)and not any(n.is_symlink()for n in(out,*out.parents)),'fresh disjoint owned output');out.mkdir(mode=0o700);os.chmod(out,0o700);runner=R.Runner(v['resources']['whole_seconds'],dict(os.environ),out);state=B.Cancellation();state.__enter__();scopes=[];candidate=None;tag=None;report=dict(kind='ARM16K_VIRTIO_TOOL_IMAGE_V1',status='HOLD',parent_image_id=v['parent_image_id'],image_id=None,guest_boot='NOT RUN',native16K='NOT RUN',M2='NOT RUN',release_accepted=False,resource_authority=C.pin(C.read(a.authority.resolve())),source_manifest=source_manifest())
 def budget():
  held(a.lock_fd);mem={line.split(':',1)[0]:line.split(':',1)[1].strip()for line in Path('/proc/meminfo').read_text().splitlines()};C.need(int(mem['MemAvailable'].split()[0])*1024>=v['resources']['memory_bytes']+v['resources']['memory_host_reserve_bytes'],'live RAM cap plus host reserve');allocated=sum(p.lstat().st_blocks*512 for p in(out,*out.rglob('*'))if not p.is_symlink());C.need(allocated<=v['resources']['output_bytes'],'bounded owned output');C.need(shutil.disk_usage(out).free>=v['resources']['host_reserve_bytes']and shutil.disk_usage('/home').free>=v['resources']['additional_disk_bytes']+v['resources']['host_reserve_bytes'],'disk reserve for bounded image and RW layer')
 def cmd(label,argv,timeout=60):
  budget();r=runner.run(argv,timeout=timeout,limit=1024**2,log=label+'.log');C.need(r.returncode==0,'exact command failed: '+label);return r.stdout
 def image(identity,label):return json.loads(cmd(label,['docker','image','inspect',identity]))[0]
 class Scope(B.OwnedContainer):
  def validate(self,row):C.confinement(row,self.name,self.image,self.labels,self.stage,self.mounts)

 def run(stage,identity,number):
  receipts=out/stage;receipts.mkdir(mode=0o700);name='cachy-virtio-tool-'+stage+'-'+secrets.token_hex(12);labels=dict(parent['Config'].get('Labels')or{});labels.update({'org.cachy-asahi.virtio-tool-owner':str(os.getuid()),'org.cachy-asahi.virtio-tool-operation':name})
  s=Scope(name,out/(stage+'.cid'),identity,labels,package_root,out);s.stage=stage;s.mounts={(str(HERE),'/recipe',False),(str(root/'owned_process.py'),'/runtime/owned_process.py',False),(str(receipts),'/receipts',True)}
  if stage=='install':s.mounts.add((str(package_root),'/packages',False))
  scopes.append(s);C.need(s.listing(time.monotonic()+8)is None,'fresh unique owned name');s.submitted=True
  argv=['docker','create','--cidfile',str(s.cidfile),'--name',name,'--init=false',*[x for k,val in labels.items()for x in('--label',k+'='+val)],'--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--cpus=1','--memory=512m','--memory-swap=512m','--pids-limit=64','--tmpfs','/tmp:rw,noexec,nodev,nosuid,size=32m']
  if stage=='probe':argv+=['--read-only']
  for source,dest,rw in sorted(s.mounts):argv+=['--mount','type=bind,source='+source+',target='+dest+(''if rw else',readonly')]
  argv+=['--env','CACHY_VIRTIO_TOOL_IMAGE=ROOT_ADMITTED_V1','--entrypoint','/usr/bin/python3',identity,'-I','-B','/recipe/actor.py',stage];cmd(stage+'-create',argv);s.recover(time.monotonic()+8)
  try:cmd(stage+'-run',['docker','start','-a',name],180)
  finally:
   # Preserve Docker/actor diagnostics before any owned cleanup, even on failure.
   r=runner.run(['docker','logs',name],timeout=15,limit=1024**2,log=stage+'-console.log')
  row=s.recover(time.monotonic()+8);C.need(not row['State']['Running']and row['State']['ExitCode']==0 and not row['State']['OOMKilled'],'natural successful container exit')
  result=json.loads(C.read(receipts/'actor-result.json',1024**2));C.need(result['children_absent_twice']is True,'actual empty actor namespace');return s,result
 try:
  security=json.loads(cmd('docker-security',['docker','info','--format','{{json .SecurityOptions}}']));C.need('name=rootless'in security,'existing rootless daemon only');parent=image(v['parent_image_id'],'parent-image');C.need(parent['Id']==v['parent_image_id']and parent['Architecture']=='amd64'and parent['Os']=='linux','exact x86 parent')
  s,installed=run('install',v['parent_image_id'],1);C.need(installed['status']=='EXACT_OFFLINE_ONE_PACKAGE_INSTALLED','actual normal signed transaction');report['install_result']=C.pin(C.read(out/'install/actor-result.json'))
  tag='cachy-arm16k-virtio-tools:'+secrets.token_hex(12);cmd('commit',['docker','commit','--change','ENTRYPOINT '+json.dumps(parent['Config'].get('Entrypoint')or[]),'--change','CMD '+json.dumps(parent['Config'].get('Cmd')or[]),s.cid,tag]);new=image(tag,'candidate-image');candidate=new['Id'];C.need(candidate!=v['parent_image_id']and new['RootFS']['Layers'][:len(parent['RootFS']['Layers'])]==parent['RootFS']['Layers']and 0<new['Size']-parent['Size']<=v['resources']['image_delta_bytes'],'bounded distinct append-only successor image');report.update(image_id=candidate,image_delta_bytes=new['Size']-parent['Size'])
  _,probe=run('probe',candidate,2);C.need(probe['status']=='THREE_ACTUAL_VIRTIO_DEVICES_OBSERVED','real new-image device probe');C.need(review['source_manifest']==source_manifest(),'source unchanged after actual stages');C.archive(package);C.checked(str(package)+'.sig',v['package']['signature']);report.update(status='TOOL_IMAGE_DEVICES_QUALIFIED_NO_GUEST',required_devices=probe['required_devices'],device_help=probe['device_help'],actual_observed_utc=probe['actual_observed_utc'],package=v['package'],qemu=v['qemu'],module=v['module'],providers=v['providers'],probe_result=C.pin(C.read(out/'probe/actor-result.json')))
 except BaseException as error:report.update(status='HOLD',failure=dict(type=type(error).__name__,message=str(error)[:1000]))
 finally:
  state.cleaning=True;report['cleanup']=[]
  for scope in reversed(scopes):
   row={};scope.cleanup(row);report['cleanup'].append(row)
  report['owned_containers_absent']=bool(scopes)and all(r.get('owned_container_absence_verified')is True and not r.get('cleanup_errors')for r in report['cleanup'])
  if not report['owned_containers_absent']or state.pending:report['status']='HOLD_CLEANUP_OR_CANCELLED'
  if report['status']!='TOOL_IMAGE_DEVICES_QUALIFIED_NO_GUEST'and candidate:
   try:
    row=image(tag,'failed-image-identity');C.need(row['Id']==candidate,'only exact owned candidate may retire');cmd('failed-image-remove',['docker','image','rm',candidate]);report['failed_candidate_removed']=True
   except BaseException as error:report['candidate_cleanup_error']=str(error)[:500]
  if report['status']=='TOOL_IMAGE_DEVICES_QUALIFIED_NO_GUEST':
   try:
    C.qualified(report);metadata=C.tool_metadata(report);(out/'Root-device-help.json').write_text(json.dumps(metadata,sort_keys=True,indent=2)+'\n');report['Root_device_help_metadata']=C.pin(C.read(out/'Root-device-help.json'))
   except BaseException as error:report.update(status='HOLD_QUALIFICATION',failure=dict(type=type(error).__name__,message=str(error)[:1000]))
  report['lease']='BORROWED_EXISTING_FD_NEVER_ACQUIRED_OR_UNLOCKED';(out/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');state.__exit__(None,None,None)
 if report['status']=='TOOL_IMAGE_DEVICES_QUALIFIED_NO_GUEST':
  print(json.dumps(report));return 0
 return 2
if __name__=='__main__':raise SystemExit(main())
