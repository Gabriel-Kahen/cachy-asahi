#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Separate UI-seat operation; frozen RTC two-stage build logic. No installation, VM or workflow dispatch."""
import argparse,datetime,hashlib,importlib.util,json,math,os,resource,shutil,signal,subprocess,sys,tarfile,time
from pathlib import Path,PurePosixPath
HERE=Path(__file__).resolve().parent


def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def extract(path,workspace,root):
 total=0;count=0
 with tarfile.open(path,'r|gz') as archive:
  for member in archive:
   name=PurePosixPath(member.name);count+=1;total+=member.size
   if not name.parts or name.parts[0]!=root or name.is_absolute() or '..' in name.parts or not(member.isfile() or member.isdir() or member.issym() or member.islnk()) or member.size>64*1024**2 or total>4*1024**3 or count>150000:raise ValueError('bounded exact-source extraction refused')
   archive.extract(member,workspace,filter='data')
 return {'members':count,'logical_bytes':total}


def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat()


class OwnedCommandError(RuntimeError):
 def __init__(self,error,retirement):
  super().__init__(str(error));self.retirement=retirement


def owned_command(O,argv,*,cap,max_output,env=None,preexec_fn=None,retirement=2,grace=.5):
 # Match every caller-controlled pre-transfer check in the pinned helper BEFORE
 # Popen. Fresh binary stdout/stderr pipes, no prior wait/poll and log_fd=None
 # satisfy its remaining fixed launch contract.
 if any(type(v) not in (int,float) or not math.isfinite(v) for v in (cap,retirement,grace)) or not 0<retirement<cap or not 0<=grace<retirement:raise ValueError('valid finite owned-command deadlines required before launch')
 if type(max_output) is not int or not 0<=max_output<=16*1024**2:raise ValueError('bounded integer output cap required before launch')
 if signal.getsignal(signal.SIGCHLD)!=signal.SIG_DFL:raise ValueError('SIG_DFL child ownership required before launch')
 child=None
 try:
  child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True,env=env,preexec_fn=preexec_fn)
  return O.supervise(child,cap=cap,retirement=retirement,grace=grace,max_output=max_output,log_fd=None)
 except BaseException as error:
  if child is None:raise
  # The frozen helper returns an error report after ownership transfer. If it
  # instead refused before transfer, retire this SAME child; never retry argv.
  # Its own WNOWAIT/ECHILD checks forbid signaling a released/reused identity.
  recovery={'passed':False,'ownership':'NOT_REENTERED_AFTER_RELEASE','output':b''}
  if child.returncode is None and child._child_created:
   recovery=O.supervise(child,cap=1.5,retirement=.5,grace=.1,max_output=min(max_output,65536),log_fd=None)
  raise OwnedCommandError(error,recovery) from error


def retain_image(C,image,out):
 # Preserve first-failure DATA before any release/config/header validation.
 raw,fields=C.header_fields(image);(out/'image-header.bin').write_bytes(raw)
 (out/'image-header.json').write_text(json.dumps(fields,indent=2,sort_keys=True)+'\n')
 retained=sum(p.stat().st_size for p in out.rglob('*') if p.is_file())
 if fields['file_bytes']>C.IMAGE_FILE_CAP or retained+fields['file_bytes']+1024**2>C.IMAGE_FILE_CAP:raise ValueError('64MiB total persistent output budget prevents Image retention; header retained')
 target=out/'observed-Image';shutil.copyfile(image,target)
 return target,fields


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-kernel-source-execution',action='store_true');p.add_argument('--stage',choices=['configure','compile'],required=True);p.add_argument('--archive',type=Path,required=True);p.add_argument('--tool-profile',type=Path,required=True);p.add_argument('--tool-profile-sha256',required=True);p.add_argument('--owned-process',type=Path,required=True);p.add_argument('--configured-result',type=Path);p.add_argument('--approved-config',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 if not(a.allow_kernel_source_execution and __debug__ and sys.flags.isolated):p.error('explicit separately admitted isolated kernel-source execution required')
 os.umask(0o077);C=load('rtc_build_contract',HERE/'contract.py');T=load('rtc_build_tools',HERE/'frozen/rtc/toolchain.py');T.confinement(C);C.data();C.checked(a.archive,C.lock()['archive']);C.checked(a.owned_process,C.lock()['owned_process']);profile,tools=T.profile(a.tool_profile,a.tool_profile_sha256,C,a.stage=='compile')
 if a.stage=='compile':
  if a.configured_result is None or a.approved_config is None:raise ValueError('separately reviewed configure output/config required')
  C.checked(a.configured_result,{'bytes':a.configured_result.stat().st_size,'sha256':profile['configured_result_sha256']});configured=json.loads(a.configured_result.read_text())
  if configured['status']!='CONFIGURED_REVIEW_REQUIRED' or configured['operation']!=C.lock()['operation'] or configured['tool_environment']!=profile['environment_sha256']:raise ValueError('actual configure/environment join differs')
  C.checked(a.approved_config,configured['config']);C.final_config(a.approved_config.read_bytes(),profile['compiler_facts'])
 # /work is a fresh hard-capped tmpfs; only small reports/config/bundle go to the
 # separately owned /outputs mount. No retained configure workspace is replayed.
 work=Path('/work/ui-seat-kernel')
 if work.exists() or work.is_symlink():raise ValueError('fresh once build workspace required')
 out=a.output.resolve()
 if not out.is_relative_to('/outputs') or out.exists() or out.is_symlink():raise ValueError('fresh owned /outputs child required')
 out.mkdir(mode=0o700);work.mkdir(mode=0o700)
 report={'schema_version':1,'operation':C.lock()['operation'],'status':'HOLD','stage':a.stage,'actual_started_utc':utc(),'commands':[],'kernel_compile':'NOT RUN','guest_boot':'NOT RUN','native16K':'NOT RUN','M2':'NOT RUN','release_accepted':False}
 O=load('rtc_exact_owned_process',a.owned_process);O.prepare();deadline=time.monotonic()+C.lock()['build']['whole_seconds']
 def limits():
  resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_FSIZE,(C.lock()['build']['per_file_bytes'],)*2);resource.setrlimit(resource.RLIMIT_AS,(C.lock()['build']['memory_bytes'],)*2)
 def command(label,argv):
  cap=min(300 if label=='configure' else 3600,deadline-time.monotonic())
  if cap<=3:raise TimeoutError('whole build deadline')
  with (out/(label+'.log')).open('xb') as log:
   refusal=None
   try:result=owned_command(O,argv,cap=cap,max_output=C.lock()['build']['log_bytes_per_command'],env=env,preexec_fn=limits)
   except OwnedCommandError as error:refusal=error;result=error.retirement
   output=result.pop('output',b'');row={'label':label,'argv':argv,'retirement':result,'log':None};report['commands'].append(row)
   if refusal is not None:row['supervision_refusal']=str(refusal)
   # Regular files are durable sinks AFTER owned supervision, never borrowed
   # log_fd pipes. A write failure cannot strand the already-retired child.
   log.write(output)
  row['log']=C.pin(out/(label+'.log'))
  if refusal is not None:raise refusal
  if not result.get('passed'):raise RuntimeError('owned command failed: '+label)
 try:
  report['extraction']=extract(a.archive,work,C.lock()['archive']['root']);source=work/C.lock()['archive']['root'];build=work/'build';build.mkdir()
  seed=C.construct(C.data()) if a.stage=='configure' else a.approved_config.read_bytes();(build/'.config').write_bytes(seed)
  # Fixed historical reproducible build timestamp is metadata, never a guest
  # clock setting. Actual invocation UTC is recorded separately above/below.
  env={'PATH':'/tools/bin:/usr/bin:/bin','HOME':str(work),'TMPDIR':str(work),'LC_ALL':'C','TZ':'UTC','ARCH':'arm64','LLVM':'1','KBUILD_BUILD_USER':'generic16k','KBUILD_BUILD_HOST':'ui-seat-reference-new-toolchain','KBUILD_BUILD_VERSION':'1','KBUILD_BUILD_TIMESTAMP':'Fri Oct 16 00:00:00 UTC 2026'}
  argv=['/usr/bin/make','-C',str(source),'O='+str(build),'ARCH=arm64','LLVM=1']
  command('configure',argv+['olddefconfig']);raw=(build/'.config').read_bytes();requested=C.construct(C.data());facts=C.delta(requested,raw)
  # Retain actual configure DATA even if strict feature classification refuses;
  # /work is ephemeral and must not be the only copy of a first failure.
  (out/'observed.config').write_bytes(raw);report['observed_config']=C.pin(out/'observed.config');report['unreviewed_config_delta']=facts;proof=C.final_config(raw,facts)
  if a.stage=='configure':
   shutil.copyfile(build/'.config',out/'config');receipt={'schema_version':1,'operation':C.lock()['operation'],'status':'CONFIGURED_REVIEW_REQUIRED','config':C.pin(out/'config'),'tool_environment':profile['environment_sha256'],'tool_profile_sha256':a.tool_profile_sha256,'candidate_compiler_facts':facts,'config_proof':proof,'commands':report['commands'],'compile':'NOT RUN','guest_boot':'NOT RUN'};(out/'configure-result.json').write_text(json.dumps(receipt,indent=2,sort_keys=True)+'\n');report['status']='CONFIGURED_REVIEW_REQUIRED'
  else:
   if C.pin(build/'.config')!=configured['config'] or facts!=profile['compiler_facts']:raise ValueError('fresh compile-stage configure changed the exact approved config/facts')
   proof=C.final_config(raw,profile['compiler_facts']);command('Image',argv+['-j2','Image'])
   image,report['observed_image_header']=retain_image(C,build/'arch/arm64/boot/Image',out);report['observed_image']=C.pin(image)
   if (build/'include/config/kernel.release').read_text().strip()!=C.lock()['kernel_release']:raise ValueError('distinct RTC kernel release differs')
   if C.pin(build/'.config')!=configured['config']:raise ValueError('compile altered approved configuration')
   report['image_header']=C.header(image)
   metadata=C.bundle(image,build/'.config',profile,a.tool_profile_sha256,tools,report['commands'],report['actual_started_utc'],utc())
   bundle=out/'bundle';bundle.mkdir();image.rename(bundle/'Image');shutil.copyfile(build/'.config',bundle/'config')
   (bundle/'bundle.json').write_text(json.dumps(metadata,indent=2,sort_keys=True)+'\n');report.update(status=metadata['status'],kernel_compile='PASS',bundle=C.pin(bundle/'bundle.json'))
 except BaseException as e:report['failure']={'category':type(e).__name__,'message':str(e)[:2048]}
 finally:
  report['actual_finished_utc']=utc();(out/'build-report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 print(json.dumps({'status':report['status'],'report':str(out/'build-report.json')}))
 return 0 if report['status'] in ('CONFIGURED_REVIEW_REQUIRED','BUILT_ONLY_UI_SEAT_BOOT_NOT_RUN') else 1


if __name__=='__main__':raise SystemExit(main())
