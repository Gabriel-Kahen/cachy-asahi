"""One finite native core cell: fresh574, offline638, one package build, retirement."""
import argparse,importlib.util,json,os,platform,re,resource,shutil,signal,subprocess,sys,time,traceback
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import common as C

def module(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m

def group_absent(pid):
 try:os.killpg(pid,0);return False
 except ProcessLookupError:return True

def run_role(command,output,role,seconds,deadline,env,capture=False):
 C.need(time.monotonic()<deadline,'whole owner deadline')
 stdout=output/(role+'.stdout');stderr=output/(role+'.stderr');started=time.monotonic();process=None
 receipt=dict(role=role,command=command,seconds_limit=seconds,status='NOT_STARTED')
 try:
  with stdout.open('xb')as out,stderr.open('xb')as err:
   process=subprocess.Popen(command,stdin=subprocess.DEVNULL,stdout=out,stderr=err,env=env,start_new_session=True,preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_FSIZE,(128*1024**2,128*1024**2)))
   receipt.update(pid=process.pid,pgid=process.pid,status='RUNNING')
   try:code=process.wait(timeout=min(seconds,max(0.01,deadline-time.monotonic())))
   except BaseException:
    for sig,wait in((signal.SIGTERM,5),(signal.SIGKILL,5)):
     if not group_absent(process.pid):
      try:os.killpg(process.pid,sig)
      except ProcessLookupError:pass
     try:process.wait(timeout=wait)
     except subprocess.TimeoutExpired:pass
     until=time.monotonic()+wait
     while not group_absent(process.pid)and time.monotonic()<until:time.sleep(0.01)
     if group_absent(process.pid):break
    raise
   receipt.update(returncode=code,direct_child_reaped=process.poll()is not None,group_absent=group_absent(process.pid))
   C.need(code==0 and receipt['direct_child_reaped']and receipt['group_absent'],'role nonzero or lifetime incomplete: '+role)
   receipt['status']='PASS'
   return receipt
 finally:
  receipt['elapsed_seconds']=time.monotonic()-started
  if stdout.exists():receipt['stdout']=C.pin(C.read(stdout,128*1024**2))
  if stderr.exists():receipt['stderr']=C.pin(C.read(stderr,128*1024**2))
  if process is not None:receipt.update(direct_child_reaped=process.poll()is not None,group_absent=group_absent(process.pid))
  C.save(output/(role+'-role.json'),receipt)

PROBE='''import hashlib,json,os,platform,subprocess
from pathlib import Path
lock=subprocess.check_output(['/usr/bin/pacman','-Q'],text=True)
lock=''.join(sorted(lock.splitlines(keepends=True)))
print(json.dumps(dict(packages_lock=lock,config_sha256={n:hashlib.sha256(Path(n).read_bytes()).hexdigest()for n in('/etc/makepkg.conf','/etc/pacman.conf')},uname=list(platform.uname()),page_size=os.sysconf('SC_PAGE_SIZE')),sort_keys=True))
'''

def export(out,identity,token,status,error=None,deadline=None):
 started=time.monotonic()
 """Only fixed role evidence, full build output and logs; no binary input cache."""
 dest=out/'export';C.need(not dest.exists(),'fresh export required');dest.mkdir(mode=0o700)
 allowed=['owner.json','identity.json','selection.json','environment.json','candidate-probe.json','materialized403.json','prefetch.json','authentication64','seed-report.json','failure.traceback']
 for n in('32','20','8'):allowed.append('archive'+n+'-index.json')
 for name in allowed:
  p=out/name
  if p.is_file():shutil.copyfile(p,dest/name)
  elif p.is_dir():shutil.copytree(p,dest/name)
 for p in sorted(out.glob('*')):
  if p.is_file()and(p.name.endswith(('.stdout','.stderr','-role.json'))):shutil.copyfile(p,dest/p.name)
 for kind in('baseline','candidate'):
  root=out if kind=='baseline'else out/'candidate';target=dest/kind;target.mkdir()
  for name in('report.json','seed-report.json','installed-packages.lock','image-id','probe-cid'):
   p=root/name
   if p.is_file():shutil.copyfile(p,target/name)
 if(out/'package-build').is_dir():
  target=dest/'package-build';target.mkdir()
  for name in('provenance.json','validation.json','expected-packages.lock','expected-config.sha256','build.log'):
   p=out/'package-build'/name
   if p.is_file():shutil.copyfile(p,target/name)
  if(out/'package-build/artifacts').is_dir():shutil.copytree(out/'package-build/artifacts',target/'artifacts')
 # Hash every exported ordinary file after copying; never synthesize success leaves.
 files=C.files(dest)
 elapsed=time.monotonic()-started;within=elapsed<C.BUDGET['export']and(deadline is None or time.monotonic()<deadline)
 if not within:status='FAIL'
 C.save(dest/'index.json',dict(export_seconds=elapsed,export_seconds_limit=C.BUDGET['export'],owner_deadline_satisfied_after_export=within,schema=1,scope=C.SCOPE,identity=identity,nonce=token,status=status,error=error,files=files,source_manifest=C.pin(C.read(C.ROOT/'source-manifest.json')),source403=C.load(C.ROOT/'authority.json')['frozen_core_manifest'],source_policy=C.pin(C.read(C.ROOT/'lane/root-source-authorization.json')),budget=C.BUDGET,hardware='NOT_RUN',target261_credit=False))
 return status

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--source',required=True);p.add_argument('--run',type=int,required=True);p.add_argument('--attempt',type=int,required=True);p.add_argument('--cell',required=True);a=p.parse_args()
 os.umask(0o077)
 C.preflight();policy=C.policy();identity=C.identity(a.source,a.run,a.attempt,a.cell);out=C.private(a.output)
 C.need(not(out/'owner.json').exists(),'fresh owner state required')
 C.need(platform.system()=='Linux'and platform.machine()in('arm64','aarch64'),'native Linux ARM host required')
 core=C.materialized(out/'materialized-core');C.need(C.load(out/'authentication64/authentication.json')['status']=='PASS_CURRENT_OFFICIAL_SIGNATURE_AND_COMPLETE_PKGINFO_64','complete fresh signed64 authentication required')
 token=os.urandom(8).hex();candidate_token=os.urandom(8).hex();started=time.monotonic();deadline=started+C.BUDGET['owner'];status='FAIL';error=None;roles=[]
 env={'PATH':'/usr/bin:/bin','LC_ALL':'C.UTF-8','LANG':'C.UTF-8','HOME':str(out/'home')}
 # Never inherit CI tokens, remote-systemd/GPG overrides, proxies or compiler knobs.
 os.environ.clear();os.environ.update(env)
 M=module(C.ROOT/'baseline/maintained_desktop574.py','core_original574')
 before=dict(identity=identity,nonce=token,candidate_nonce=candidate_token,status='RUNNING',budget=C.BUDGET,source_manifest=C.pin(C.read(C.ROOT/'source-manifest.json')),roles=roles)
 C.save(out/'owner.json',before);C.save(out/'identity.json',identity)
 C.save(out/'environment.json',dict(uname=list(platform.uname()),page_size=os.sysconf('SC_PAGE_SIZE'),python=sys.version,environment=env))
 C.save(out/'materialized403.json',dict(status='EXACT_ORIGINAL403_RESTORED',files=C.load(C.ROOT/'authority.json')['whole_core'],manifest=C.load(C.ROOT/'authority.json')['frozen_core_manifest']))
 try:
  command=[sys.executable,'-I','-B',str(C.ROOT/'baseline/maintained_desktop574.py'),'build','--inputs',str(C.ROOT/'baseline/maintained-desktop574-inputs.json'),'--output',str(out),'--job-token',token]
  roles.append(run_role(command,out,'baseline-build',C.BUDGET['baseline'],deadline,env))
  baseline=C.load(out/'report.json');C.need(baseline['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION','original574 transaction must pass')
  base_image=baseline['image'];M.inspect_image(base_image,token)
  C.need(C.read(out/'installed-packages.lock')==C.read(core/'builder-context/expected574.lock'),'fresh exact574 lock')
  candidate=out/'candidate';candidate.mkdir(mode=0o700);context=out/'candidate-context';shutil.copytree(core/'builder-context',context)
  owner=M.owner_begin(candidate,candidate_token);report=dict(status='RUNNING',ownership=owner,packages=638);M.save_report(candidate,report)
  command=['/usr/bin/docker','build','--progress=plain','--pull=false','--network=none','--platform=linux/arm64','--build-arg','BASE_IMAGE='+base_image,'--tag',owner['image_tag'],'--label',M.OWNER_LABEL+'='+candidate_token,'--iidfile',str(candidate/'image-id'),str(context)]
  owner['build_started']=True;M.save_report(candidate,report)
  roles.append(run_role(command,out,'candidate-build',C.BUDGET['candidate'],deadline,env));report['build_returncode']=0;owner['build_complete']=True
  image=C.read(candidate/'image-id').decode().strip();metadata=M.inspect_image(image,candidate_token);owner['image']=image;C.need(image not in owner['before_images'],'candidate image must be fresh')
  owner['probe_started']=True;M.save_report(candidate,report)
  command=['/usr/bin/docker','run','--rm','--name',owner['probe_name'],'--cidfile',str(candidate/owner['probe_cidfile']),'--label',M.OWNER_LABEL+'='+candidate_token,'--pull=never','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--entrypoint=/usr/bin/python3',image,'-I','-B','-c',PROBE]
  roles.append(run_role(command,out,'candidate-probe',C.BUDGET['probes'],deadline,env));owner['probe_complete']=True
  observed=json.loads(C.read(out/'candidate-probe.stdout'));C.need(observed['packages_lock'].encode()==C.read(context/'expected638.lock'),'exact native638 lock')
  expected_config={line.split()[1]:line.split()[0]for line in C.read(context/'base-config.sha256').decode().splitlines()}
  C.need(observed['config_sha256']==expected_config and observed['uname'][0]=='Linux'and observed['uname'][4]in('aarch64','arm64'),'candidate config/native environment differs')
  (candidate/'installed-packages.lock').write_text(observed['packages_lock']);C.save(out/'candidate-probe.json',observed)
  report.update(status='PASS_NATIVE_OFFLINE_638_TRANSACTION',image=image,image_inspect=metadata);M.save_report(candidate,report)
  selection=dict(schema=1,scope='UNSELECTED_CORE_NATIVE_BUILD_ONLY',image=image,profile=C.pin(C.read(C.ROOT/'core/profile/profile.json')),expected_packages=dict(path=str(context/'expected638.lock'),pin=C.pin(C.read(context/'expected638.lock'))),image_config_sha256=observed['config_sha256'],source_date_epoch=policy['source_date_epoch'],root_source_authorization=dict(path=str(C.ROOT/'lane/root-source-authorization.json'),pin=C.pin(C.read(C.ROOT/'lane/root-source-authorization.json'))))
  C.save(out/'selection.json',selection)
  command=[sys.executable,'-B',str(C.ROOT/'lane/build_one.py'),'--recipe',a.cell.rsplit('-',1)[0],'--selection',str(out/'selection.json'),'--output',str(out/'package-build'),'--timeout',str(C.BUDGET['makepkg'])]
  roles.append(run_role(command,out,'package-build',C.BUDGET['package'],deadline,env))
  built=C.load(out/'package-build/provenance.json');C.need(built['status']=='NATIVE_BUILD_METADATA_AND_STRUCTURAL_ELF_ONLY'and built['container_absence']is True,'full frozen package predicate and strict container retirement')
  status='PASS_NATIVE_CORE_BUILD_CELL'
 except BaseException as e:
  error=dict(kind=type(e).__name__,message=str(e));(out/'failure.traceback').write_text(traceback.format_exc());status='FAIL'
 finally:
  # Only unchanged original ownership retirement, never prune or erase foreign refs.
  cleanup_started=time.monotonic();cleanup={}
  for kind,folder,nonce in(('candidate',out/'candidate',candidate_token),('baseline',out,token)):
   try:
    C.need(time.monotonic()-cleanup_started<C.BUDGET['cleanup'],'strict cleanup phase deadline')
    old=C.load(folder/'report.json');result=M.retire_owned(folder,nonce,old);old['owned_cleanup']=result;M.save_report(folder,old);cleanup[kind]=result
   except BaseException as e:cleanup[kind]=dict(status='FAIL',error_kind=type(e).__name__)
  if any(v.get('status')!='PASS'for v in cleanup.values()):status='FAIL'
  bookkeeping=time.monotonic()-started-sum(r['elapsed_seconds']for r in roles)-(time.monotonic()-cleanup_started)
  if bookkeeping>C.BUDGET['selection']:status='FAIL'
  before.update(bookkeeping_seconds=bookkeeping,selection_seconds_limit=C.BUDGET['selection'],status=status,error=error,roles=roles,cleanup=cleanup,owner_seconds_limit=C.BUDGET['owner'],owner_deadline_satisfied=time.monotonic()<deadline)
  if not before['owner_deadline_satisfied']:status='FAIL';before['status']=status
  C.save(out/'owner.json',before)
  status=export(out,identity,token,status,error,deadline)
 return 0 if status=='PASS_NATIVE_CORE_BUILD_CELL'else 1
if __name__=='__main__':raise SystemExit(main())
