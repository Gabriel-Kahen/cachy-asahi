#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite same-process owner for original574 producer and frozen KSM VM driver."""
import argparse,json,os,signal,stat,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import hosted as O
import archive32 as A
import archive20 as A20
import archive8 as A8

SECRET_NAMES=('CACHY_OLD_FOUR_SCHEMA','CACHY_OLD_FOUR_SOURCE_EPOCH','CACHY_RETAINED_BUBBLEWRAP_V1_PACKAGE_01','CACHY_RETAINED_BUBBLEWRAP_V1_PACKAGE_02','CACHY_RETAINED_BUBBLEWRAP_V1_SIGNATURE_01','CACHY_OLD_FOUR_JBIGKIT_01','CACHY_OLD_FOUR_JBIGKIT_02','CACHY_OLD_FOUR_JBIGKIT_SIG_01','CACHY_OLD_FOUR_LIBTIFF_SIG_01')+tuple('CACHY_OLD_FOUR_LIBTIFF_'+str(n).zfill(2)for n in range(1,16))

class OwnerInterrupted(RuntimeError):pass

def interrupted(signum,_frame):raise OwnerInterrupted('owned KSM hosted interruption '+str(signum))

def seed_archive20(root,runtime,archive32_cache,deps,work):
 """Seed only whole-pinned original20; no version/trust or producer command changes."""
 cache=archive32_cache.parent/'ksm2-archive20'
 policy_path=root/O.LANE/'archive20-policy.json'
 value=A20.policy(policy_path,runtime/'borrowed/maintained574-inputs.json')
 custody=A20.seed_exact(cache,deps,value)
 custody.update(policy=O.pin(O.read(policy_path)),files={n:{k:r[k]for k in('bytes','sha256')}for n,r in value['files'].items()},versions='UNCHANGED_FROZEN574_LOCK',trust='UNCHANGED_ORIGINAL_SIGNATURE_AND_KEYRING_CHECKS')
 O.save(work/'archive20-custody.json',custody)
 return custody

def seed_archive8(root,runtime,archive32_cache,deps,work):
 """Seed only whole-pinned original8; no version/trust or producer command changes."""
 cache=archive32_cache.parent/'ksm2-archive8'
 policy_path=root/O.LANE/'archive8-policy.json'
 value=A8.policy(policy_path,runtime/'borrowed/maintained574-inputs.json')
 custody=A8.seed_exact(cache,deps,value)
 custody.update(policy=O.pin(O.read(policy_path)),files={n:{k:r[k]for k in('bytes','sha256')}for n,r in value['files'].items()},versions='UNCHANGED_FROZEN574_LOCK',trust='UNCHANGED_ORIGINAL_SIGNATURE_AND_KEYRING_CHECKS')
 O.save(work/'archive8-custody.json',custody)
 return custody

def run(a):
 root=a.source.absolute();v=O.selected(O.policy(root));proof=O.prove(root,os.environ);runtime=root/'runtime';sys.path.insert(0,str(runtime));import contract as C
 # All native/kernel immutable inputs and Root qualifications precede secrets/actors.
 s,custody=O.components(root,v,proof,a.native,a.kernel,a.inputs)
 O.need(a.work.is_absolute()and not a.work.exists()and not a.work.is_symlink()and a.work.parent.is_dir(),'fresh private outer workspace');a.work.mkdir(mode=0o700);st=a.work.stat();O.save=lambda p,value:Path(p).write_bytes(O.encoded(value));O.save(a.work/'owner-lease.json',dict(source=proof['source'],run=proof['run'],identity=[st.st_dev,st.st_ino,st.st_uid]));O.save(a.work/'source-proof.json',proof);O.save(a.work/'component-custody.json',custody)
 for sig in(signal.SIGINT,signal.SIGTERM,signal.SIGALRM):signal.signal(sig,interrupted)
 signal.setitimer(signal.ITIMER_REAL,6600)
 R=O.load('_ksm_hosted_held_runtime',runtime/'borrowed/runtime.py');started=time.monotonic();deadline=started+6600;records=[];producer=a.work/'producer';result=dict(status='FAIL_OR_INCOMPLETE',source=proof,cleanup='UNKNOWN',VM='NOT_ACCEPTED')
 safe={k:os.environ[k]for k in('SOURCE_SHA','GITHUB_SHA','GITHUB_WORKFLOW_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','GITHUB_REF_NAME','GITHUB_REPOSITORY','GITHUB_EVENT_NAME')}
 env=dict(safe,PATH='/usr/local/bin:/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',TZ='UTC',HOME=str(a.work),TMPDIR=str(a.work),PYTHONDONTWRITEBYTECODE='1')
 def command(argv,seconds,secret=False):
  limit=min(seconds,deadline-time.monotonic());O.need(limit>0,'unchanged whole6600 owner envelope')
  supplied=dict(env)
  if secret:
   # Exact original secret names only; never broad inheritance or credential logging.
   for name in SECRET_NAMES:
    if name in os.environ:supplied[name]=os.environ[name]
  row,out,err,error=R.run_command(argv,a.work,supplied,limit,2*1024**2);records.append(row);n=str(len(records)).zfill(2);(a.work/('command-'+n+'.stdout')).write_bytes(out);(a.work/('command-'+n+'.stderr')).write_bytes(err);O.save(a.work/'commands.json',records);O.need(error is None and row['exit_code']==0 and row['group_absence_verified']is True,'original acquisition/build command retirement');return row
 try:
  command(['/usr/bin/python3','-I','-B',str(runtime/'borrowed/maintained_desktop574.py'),'seed','--inputs',str(runtime/'borrowed/maintained574-inputs.json'),'--output',str(producer)],120,secret=True)
  for n in SECRET_NAMES:os.environ.pop(n,None)
  for n,pin in O.SEED_PINS.items():O.need(O.pin(O.read(a.seed/n))['sha256']==pin,'whole trusted original public seed source')
  O.need(O.git(a.seed,'rev-parse','HEAD').decode().strip()==O.SEED_SOURCE,'exact public seed checkout')
  command(['/usr/bin/python3','-I','-B',str(a.seed/'seed.py'),'--cache',str(producer/'context/deps')],120)
  archive_policy=A.policy(root/O.LANE/'archive32-policy.json',runtime/'borrowed/maintained574-inputs.json')
  archive_custody=A.seed_exact(a.archive_cache,producer/'context/deps',archive_policy)
  archive_custody.update(policy=O.pin(O.read(root/O.LANE/'archive32-policy.json')),files={n:{k:r[k]for k in('bytes','sha256')}for n,r in archive_policy['files'].items()},versions='UNCHANGED_FROZEN574_LOCK',trust='UNCHANGED_ORIGINAL_SIGNATURE_AND_KEYRING_CHECKS')
  O.save(a.work/'archive32-custody.json',archive_custody)
  seed_archive20(root,runtime,a.archive_cache,producer/'context/deps',a.work)
  seed_archive8(root,runtime,a.archive_cache,producer/'context/deps',a.work)
  command(['/usr/bin/python3','-I','-B',str(runtime/'borrowed/maintained_desktop574.py'),'build','--inputs',str(runtime/'borrowed/maintained574-inputs.json'),'--output',str(producer),'--job-token',proof['job_token']],2300)
  p=a.inputs/'producer/report.json';p.parent.mkdir(mode=0o700);raw=O.read(producer/'report.json');p.write_bytes(raw);p.chmod(0o600);s['producer_report']=dict(path='producer/report.json',**O.pin(raw));O.save(a.work/'runtime-binding.json',s)
  configure=O.load('_ksm_hosted_configure',runtime/'configure.py');selection=a.work/'selection.json';configure.configure(a.work/'runtime-binding.json',a.inputs,selection)
  # Direct calls retain the owner signal handler: the innermost original
  # run_command retires Docker/QEMU groups before exceptions unwind.
  result['phase']='PREPARATION';P=O.load('_ksm_hosted_preparer',runtime/'prepare_driver.py');H=O.load('_ksm_hosted_host',runtime/'host.py');P.run(argparse.Namespace(selection=selection,inputs=a.inputs,work=a.work/'prepare',media=a.work/'media'));O.need(time.monotonic()<deadline,'whole owner before actual QEMU')
  result['phase']='VM';guest=H.run(argparse.Namespace(selection=selection,inputs=a.inputs,media=a.work/'media',prepare_work=a.work/'prepare',producer_output=producer,output=a.work/'runtime'));O.need(time.monotonic()<=deadline,'whole original owner6600, no borrowed extra VM time')
  result.update(status='PASS_SOURCE_BOUND_GENERIC16K_KSM_SCALAR_ONLY',guest=guest,seconds=round(time.monotonic()-started,6),owner_seconds=6600,cleanup='PASS_CONSUMER_VM_MEDIA_THEN_ORIGINAL_PRODUCER',hardware='NOT_RUN',performance='NOT_MEASURED',release='NOT_ADMITTED',Root_acceptance='NOT_GRANTED');return result
 except BaseException as error:
  result.update(error_type=type(error).__name__,error=str(error)[:1024],seconds=round(time.monotonic()-started,6));raise
 finally:
  signal.setitimer(signal.ITIMER_REAL,0)
  O.save(a.work/'owner-result.json',result)
  if result['status']!='PASS_SOURCE_BOUND_GENERIC16K_KSM_SCALAR_ONLY':
   for n in SECRET_NAMES:os.environ.pop(n,None)
   try:
    cleanup=O.load('_ksm_hosted_failure_cleanup',root/O.LANE/'cleanup.py');result['failure_cleanup']=cleanup.run(root,a.work,proof)
   except BaseException as error:result['failure_cleanup']=dict(status='UNKNOWN_RETAINED',error_type=type(error).__name__,error=str(error)[:512])
   O.save(a.work/'owner-result.json',result)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('source','native','kernel','seed','inputs','work','archive-cache'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(run(a),sort_keys=True))
