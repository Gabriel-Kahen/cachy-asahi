#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Only original FDK341 and Updater354 native pairs; historical body equality or fail."""
import argparse,hashlib,importlib.util,json,os,re,shutil,signal,subprocess,sys,tempfile,time
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import admission as A
CODE=ROOT/'bootstrap-code'
def load(n,p):s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m
def execute(argv,log,limit,deadline,commands):
 original_limit=limit;argv=list(map(str,argv));remaining=deadline-time.monotonic();A.need(remaining>0,'unchanged6600 owner exhausted');limit=min(limit,remaining);common=load('_bootstrap2_original_process',ROOT/'original/scripts/virtual/common.py');active=common.LoggedProcess(argv,log,env=dict(PATH='/usr/local/bin:/usr/bin:/bin',HOME=str(log.parent),LANG='C.UTF-8',LC_ALL='C.UTF-8',TZ='UTC'),limit=16*1024**2);started=time.monotonic();absent=False
 try:active.process.wait(timeout=limit);active.finish();A.need(active.process.returncode==0,'original narrow2 command failed: '+log.name)
 finally:
  if active.process.poll()is None:
   for sig,seconds in((signal.SIGTERM,10),(signal.SIGKILL,5)):
    try:os.killpg(active.process.pid,sig)
    except ProcessLookupError:pass
    try:active.process.wait(timeout=seconds);break
    except subprocess.TimeoutExpired:continue
  active.finish()
  try:os.killpg(active.process.pid,0)
  except ProcessLookupError:absent=True
  commands.append(dict(argv=argv,limit=limit,original_limit_seconds=original_limit,seconds=time.monotonic()-started,exit=active.process.returncode,group_absent=absent));A.need(absent,'original narrow2 process group retirement')
 return log.read_text(errors='replace')

def core341(code,cache,out):
 """Unchanged original APIs; empty reviews expressly do not build originalfour."""
 sys.path.insert(0,str(code/'scripts/checks'));N=load('_bootstrap2_original_native_arm',code/'scripts/ci/native_arm.py');inputs=A.obj(code/'scripts/ci/inputs.lock.json');N.probe(out);N.save(out/'inputs.lock.json',inputs);N.audit(inputs,cache,out);image=N.build(inputs,cache,out,{})
 lock=A.read(out/'packages.lock');A.need(A.pin(lock)==dict(bytes=6674,sha256='fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25')and len(lock.splitlines())==341,'exact original341 FDK builder');return image

def build(state,base,retained,incoming,official,compiler,legacy,selected,out):
 A.prove(ROOT);proof=A.obj(state/'source-proof.json');deadline=proof['owner_deadline'];A.need(proof['owner_seconds']==6600 and deadline==proof['started_monotonic']+6600 and time.monotonic()<deadline,'original complete owner6600');A.need(os.getuid()>0 and os.uname().machine=='aarch64'and os.environ.get('GITHUB_ACTIONS')=='true','native disposable hosted nonroot only');A.need(not out.exists()and out.parent==state,'fresh source-owned bootstrap output');out.mkdir(mode=0o700);(out/'packages').mkdir();(out/'evidence').mkdir()
 selected_carrier=Path(selected).absolute();selected=selected_carrier/'fdk-aac-3.0.0-selected-source.tar';A.need(A.pin(A.read(selected,32*1024**2))==dict(bytes=17387520,sha256='1065c4b30e0c2deee7965faa0257e10ac482a2516d51b5b8f17b1406b3ecb2f4'),'exact retained FDK selected-source tar')
 profile=A.obj(ROOT/'bootstrap-source-profile.json');A.closed(CODE,profile['files']);plan=A.obj(ROOT/'bootstrap-plan.json');required=A.obj(incoming/'index.json')['native_build_required'];A.need(required==plan['required'],'exact mandatory historical two-body targets');borrowed=A.obj(base/'report.json')['image'];work=Path(tempfile.mkdtemp(prefix='gui606-bootstrap2-',dir='/tmp'));work.chmod(0o700);cache=work/'cache';cache.mkdir(mode=0o700);commands=[];images=[];success=False;error=None
 result=dict(status='FAIL',required=required,base_image=borrowed,source=proof['source'],run=proof['run'],attempt=proof['attempt'],case=proof['case'],owner_seconds=6600,owner_deadline=deadline,commands=commands,builders={},cleanup=[])
 def interrupted(*_):raise TimeoutError('original6600 bootstrap owner interrupted')
 previous={s:signal.signal(s,interrupted)for s in(signal.SIGTERM,signal.SIGINT,signal.SIGALRM)};signal.setitimer(signal.ITIMER_REAL,deadline-time.monotonic())
 try:
  # Native248 archive subset is a separate owned cache. Compiler13 additions
  # never enter the desktop574 composition cache or its completed seed gate.
  sys.path.insert(0,str(ROOT/'factory/retained-helpers'));P=load('_bootstrap2_exact_native248_prepare',ROOT/'factory/retained-helpers/prepare.py');custody=P.prepare(retained,cache,'native248',CODE/'scripts/ci/inputs.lock.json',deadline,retained/'.git');result['native248_custody']=custody;L=sys.modules['legacy_prefill'];result['selected_FDK_custody']=L.prove(selected_carrier,selected_carrier/'.git',A.obj(ROOT/'selected-fdk-carrier-profile.json'),deadline)
  inputs=A.obj(CODE/'scripts/ci/inputs.lock.json')
  for name,src in [(inputs['rootfs']['filename'],base/'context/rootfs.tar.gz'),(inputs['rootfs']['filename']+'.sig',base/'context/rootfs.tar.gz.sig')]+[(r['filename'],base/'context/keys'/r['filename'])for r in inputs['keyring_files']]:
   row=next((r for r in inputs['keyring_files']if r['filename']==name),None)
   if row is None:row=dict(size=inputs['rootfs']['signature_size'if name.endswith('.sig')else'size'],sha256=inputs['rootfs']['signature_sha256'if name.endswith('.sig')else'sha256'])
   A.need(A.pin(A.read(src,1024**3))==dict(bytes=row['size'],sha256=row['sha256']),'exact original rootfs/trust input carryover');shutil.copyfile(src,cache/name)
  external=A.obj(ROOT/'official3-carrier-profile.json');L=sys.modules['legacy_prefill'];result['official3_custody']=L.prove(official,official/'.git',external,deadline);extra=A.obj(CODE/'scripts/port/updater-extension/builder-extension.lock.json')['packages']
  compiler_profile=A.obj(ROOT/'compiler6-carrier-profile.json');legacy_profile=A.obj(ROOT/'legacy2-carrier-profile.json');result['compiler6_custody']=L.prove(compiler,compiler/'.git',compiler_profile,deadline);result['legacy2_custody']=L.prove(legacy,legacy/'.git',legacy_profile,deadline)
  router=load('_original13_exact_four_namespace_router',ROOT/'extension_inputs.py');result['extension_materialization']=router.prepare(extra,dict(retained574=(retained,A.obj(ROOT/'factory/retained-helpers/carrier-profile.json')),compiler6=(compiler,compiler_profile),official3=(official,external),legacy2=(legacy,legacy_profile)),cache,deadline)
  core=work/'native341';core.mkdir();execute([sys.executable,'-I','-B',__file__,'--core341',str(CODE),str(cache),str(core)],work/'core341.log',1800,deadline,commands);image=(core/'image-id').read_text().strip();A.need(re.fullmatch('sha256:[0-9a-f]{64}',image)and image!=borrowed,'distinct original341 image');images.append(image)
  fdk=work/'fdk';fdk.mkdir();package=CODE/'packages/libraries/cachy-asahi-fdk-aac';shutil.copyfile(ROOT/'fdk-template-inputs.json',fdk/'template-inputs.json');shutil.copyfile(ROOT/'fdk-reviewed-inputs.json',fdk/'reviewed-inputs.json')
  execute([sys.executable,'-B',package/'select-source.py','--input',selected,'--output',fdk/'selected-source.tar'],fdk/'select.log',120,deadline,commands);execute([sys.executable,'-B',package/'materialize.py','--archive',fdk/'selected-source.tar','--output',fdk/'recipe','--reviewed-template',fdk/'template-inputs.json','--reviewed-template-sha256',A.pin(A.read(fdk/'template-inputs.json'))['sha256']],fdk/'materialize.log',120,deadline,commands)
  caller=load('_bootstrap2_original_full_caller',CODE/'scripts/ci/full-root-upgrade-caller/run.py');records=[]
  for i in(1,2):
   b=fdk/('build-'+str(i));execute([sys.executable,'-B',CODE/'scripts/build/build.py',fdk/'recipe','--image',image,'--output',b,'--mode','native','--source-date-epoch','1791748800','--network','none','--timeout','600','--expected-packages',core/'packages.lock','--reviewed-inputs',fdk/'reviewed-inputs.json'],fdk/('build-'+str(i)+'.log'),600,deadline,commands);path,sha=caller.standard(b,'774803633213d77e9879005608ff23528b6780465c7bd00f3234430c9a7346df',image);A.need(A.pin(A.read(path,8*1024**2))==dict(bytes=1209964,sha256='237b7812435bd78456d72c157f5703f258f5b6b7455cb99e5b075f642071c247'),'fresh FDK must match historical exact body');pr=A.obj(b/'provenance.json');name=pr['clean_environment_id'];A.need(re.fullmatch('cachy-asahi-[a-f0-9]{16}',name),'exact original FDK worker name');absent=subprocess.run(['docker','container','inspect',name],capture_output=True,timeout=20);A.need(absent.returncode!=0 and b'No such'in absent.stderr,'fresh exact FDK container absence');records.append(dict(provenance=pr,validation=A.obj(b/'validation.json'),container_absence_verified=True))
  execute([sys.executable,'-B',CODE/'scripts/build/compare.py',fdk/'build-1',fdk/'build-2','--require-bytes'],fdk/'comparison.json',120,deadline,commands);comparison=A.obj(fdk/'comparison.json');A.need(not comparison['errors']and comparison['bytes_equal']is True,'complete original FDK comparison');shutil.copyfile(path,out/'packages'/path.name);result['builders']['FDK']=dict(image=image,inventory=A.pin(A.read(core/'packages.lock')),inventory_count=341,epoch=1791748800,builds=records,comparison=comparison)
  # Keep the complete original updater() validation body. Only its subprocess
  # callback is bounded by the remaining owner time; private sources stay /tmp.
  caller.command=lambda argv,log,seconds:execute(argv,log,seconds,deadline,commands)
  updater_root=work/'updater-v2';updater_root.mkdir();path,sha=caller.updater(CODE,updater_root,cache,materializer_pin='601283adb9deeca949a857ee136896e8d1559ab4ecf6fed3928531059965c6f9');A.need(A.pin(A.read(path,8*1024**2))==dict(bytes=3083884,sha256='88e6ebad51700499bc2f0c608409e06983b0146ebf555101b526c7a32d5ba4f6'),'fresh Updater must match historical exact body')
  checks=load('_bootstrap2_original_updater_checks',CODE/'scripts/checks/package_checks.py');B=load('_bootstrap2_original_build_bind',CODE/'scripts/build/build.py');report=checks.package(path);meta=checks.metadata((CODE/'packages/tools/cachy-asahi-update/.SRCINFO').read_text());A.need(not report['errors']and not B.bind_artifact(meta,report,'251009c63e3a9c2e62cd899b077c70f0f6a418ba38beac00a0323e3bf60dafa0')and'.INSTALL'not in report['members'],'complete original Updater static/recipe binding')
  native=updater_root/'updater/native';uimage=(native/'image-id').read_text().strip();A.need(uimage not in(images+[borrowed])and re.fullmatch('sha256:[0-9a-f]{64}',uimage),'distinct original354 updater image');images.append(uimage);shutil.copyfile(path,out/'packages'/path.name);result['builders']['Updater']=dict(image=uimage,inventory=A.pin(A.read(native/'packages.lock')),inventory_count=354,epoch=1789753605,result=A.obj(native/'result.json'),comparison=A.obj(native/'comparison.json'),builds=[dict(provenance=A.obj(native/('build-'+str(i))/'provenance.json'),controller=A.obj(native/('build-'+str(i))/'inputs/controller-input.json'))for i in(1,2)],inspection=report)
  success=True
 except BaseException as e:error=e;result.update(error_type=type(e).__name__,error=str(e)[:1024])
 finally:
  signal.setitimer(signal.ITIMER_REAL,0)
  for s in previous:signal.signal(s,signal.SIG_IGN)
  try:
   for image in reversed(images):
    subprocess.run(['docker','image','rm','--no-prune',image],check=True,capture_output=True,timeout=30);r=subprocess.run(['docker','image','inspect',image],capture_output=True,timeout=20);A.need(r.returncode!=0 and b'No such image'in r.stderr,'exact owned bootstrap image absence');result['cleanup'].append(dict(image=image,absence_verified=True))
   if(core if'core'in locals()else work/'native341').exists()and(work/'native341/gpg').exists():subprocess.run(['gpgconf','--homedir',str(work/'native341/gpg'),'--kill','all'],check=True,capture_output=True,timeout=15)
   # Preserve bounded public metadata/provenance, never original artwork/vendor
   # caches or private Updater body in public exports.
   A.need(error is None,'failed bootstrap retains uncertain private work and producer')
   for home in (work/'native341/gpg',work/'updater-v2/updater/native/gpg'):
    if home.exists():subprocess.run(['gpgconf','--homedir',str(home),'--kill','all'],check=True,capture_output=True,timeout=15)
   result['private_work_path']=str(work);shutil.rmtree(work);A.need(not work.exists(),'owned temporary private source/vendor retirement');result['private_retired']=True;result['cleanup_status']='PASS_EXACT_OWNED_BUILDERS_PRIVATE_INPUTS_RETIRED'
  except BaseException as e:error=error or e;result.update(cleanup_status='FAIL_UNCERTAIN_PRESERVE_PRODUCER',cleanup_error=str(e)[:512])
  for s,v in previous.items():signal.signal(s,v)
  if success and error is None:result['status']='PASS_EXACT_TWO_BOOTSTRAP_ARCHIVE_BODIES_ORIGINAL_BUILDERS'
  (out/'result.json').write_bytes(A.enc(result))
 if error:raise error
 return result
if __name__=='__main__':
 if sys.argv[1:2]==['--core341']:
  A.prove(ROOT);core341(*(Path(p)for p in sys.argv[2:]));raise SystemExit(0)
 p=argparse.ArgumentParser(description=__doc__)
 for n in('state','base','retained','incoming','official','compiler','legacy','selected','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(build(*(getattr(a,n).absolute()for n in('state','base','retained','incoming','official','compiler','legacy','selected','output'))),sort_keys=True))
