#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit nativeARM4K interruption/recovery cases; original b21 native owner remains a distinct input."""
import argparse,json,os,re,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import case as C

def without(argv,*names):
 out=list(argv)
 for name in names:
  if name in out:i=out.index(name);C.need(out.count(name)==1 and i+1<len(out),'one explicit '+name);del out[i:i+2]
 return out

def prerequisites(held,mode,args):
 contract,W,A=C.apis(held);C.need('--case'in args and args.count('--case')==1,'one explicit prerequisite recovery case');selected_case=args[args.index('--case')+1];old,policy,binding=W.authorize(held,C.HELD,C.HELD,selected_case);forward=list(args)
 if '--updater-decisions'in forward:
  i=forward.index('--updater-decisions');decisions=Path(forward[i+1]);contract.accepted(old,decisions,binding);forward=without(forward,'--updater-decisions')
 elif mode!='preflight':raise ValueError('all three original updater prerequisite decisions mandatory')
 for name in('--source','--workflow-sha'):
  if name in forward:forward[forward.index(name)+1]=C.HELD
 gate=W.old_gate(held,old)
 if mode=='preflight':forward+=['--preflight']
 elif mode=='decisions':forward+=['--decisions-only']
 result=gate.main(forward)
 if mode=='preflight':W.output('updater_decisions',binding['decision_carrier_source'])
 return result

def worker(args,a,proof):
 import runtime
 forwarded=without(args,'--source','--workflow-sha','--updater-decisions');C.need('--implementation-revision'not in forwarded,'held owner revision cannot be supplied by caller');forwarded+=['--implementation-revision',C.HELD];rc=error=None
 try:rc=runtime.execute(a.implementation,forwarded);return rc
 except BaseException as e:error=dict(type=type(e).__name__,message=str(e)[:1024]);raise
 finally:
  if a.output is not None and a.output.is_dir()and not a.output.is_symlink():
   p=a.output/'native4k-wrapper.json';C.need(not p.exists(),'fresh wrapper custody output');p.write_bytes(C.enc(dict(status='NATIVE4K_WRAPPER_RETURNED_NOT_ACCEPTANCE',wrapper=proof,held_owner_source=C.HELD,held_owner_result=C.pin(C.read(a.output/'result.json'))if(a.output/'result.json').is_file()else None,returncode=rc,error=error,page_size_after=os.sysconf('SC_PAGE_SIZE'),hardware='NOT_RUN',root_acceptance='NOT_ISSUED')))

def parent(args,a,proof):
 contract,W,A=C.apis(a.implementation);api=W.load(a.implementation,'scripts/ci/glibc-owned-runtime/runner.py');output=a.output;C.need(output is not None and output.parent==Path('/tmp')and not output.exists(),'fresh original /tmp owner output');home=output.with_name(output.name+'-job-home');config=output.with_name(output.name+'-docker-config');C.need(not home.exists()and not config.exists()and not any(p.is_symlink()for p in(home,config,*home.parents)),'fresh job HOME/Docker config');home.mkdir(mode=0o700);config.mkdir(mode=0o700);identity=config.stat();env=dict(PATH='/usr/local/bin:/usr/bin:/bin',HOME=str(home),DOCKER_CONFIG=str(config),LANG='C.UTF-8',TZ='UTC',PYTHONDONTWRITEBYTECODE='1');env.update({k:os.environ[k]for k in('GITHUB_REPOSITORY','GITHUB_SHA','GITHUB_EVENT_NAME','GITHUB_RUN_ATTEMPT','GITHUB_RUN_ID','GITHUB_REF','GITHUB_WORKFLOW_REF','GITHUB_WORKFLOW')});(home/'child.json').write_bytes(C.enc(dict(status='LAUNCH_ATTEMPTED_TERMINAL_UNKNOWN',source=proof['source'],case=a.case,docker_config=dict(path=str(config),identity=[identity.st_dev,identity.st_ino],source=proof['source'],case=a.case))))
 row,out,err,error=api.run_command(['/usr/bin/python3','-I','-B',str(C.HERE/'entry.py'),'worker',*args],home,env,15600,4*1024**2);(home/'child.json').write_bytes(C.enc(dict(status='WAIT_RETURNED',source=proof['source'],case=a.case,docker_config=dict(path=str(config),identity=[identity.st_dev,identity.st_ino],source=proof['source'],case=a.case),child=row,error=None if error is None else dict(type=type(error).__name__,message=str(error)[:1024]))));C.need(output.is_dir()and not output.is_symlink(),'original owner output required');own=C.obj(output/'owner.json');C.need(own['purpose']=='expanded604-apps6-public-pair-updater'and own['case']==a.case and own['output']==str(output),'whole original child-owned output identity');(output/'wiring-child.stdout').write_bytes(out);(output/'wiring-child.stderr').write_bytes(err);(output/'wiring-owner.json').write_bytes(C.enc(dict(status='PASS'if error is None and row['exit_code']==0 and row['group_absence_verified']is True else'FAIL',wrapper=proof,child=row,error=None if error is None else dict(type=type(error).__name__,message=str(error)[:1024]),scope='NATIVE_ARM4K_NOT_16K_NOT_HARDWARE')))
 if error is not None:raise error
 C.need(row['exit_code']==0 and row['group_absence_verified']is True,'whole owner exit/group absence');return 0

def main(argv=None):
 args=list(sys.argv[1:]if argv is None else argv);p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('preflight','decisions','inputs','run','worker'));p.add_argument('--implementation',type=Path,required=True);p.add_argument('--source',required=True);p.add_argument('--workflow-sha',required=True);p.add_argument('--case',choices=C.CASES,required=True);p.add_argument('--output',type=Path);p.add_argument('--updater-decisions',type=Path);a,_=p.parse_known_args(args);a.implementation=a.implementation.absolute();a.output=a.output.absolute()if a.output else None;proof=C.authenticate(a.implementation,a.source,a.workflow_sha,a.case)
 if a.mode in('run','worker'):
  C.need(a.updater_decisions is not None,'three original updater prerequisites before child');contract,W,A=C.apis(a.implementation);old,policy,binding=W.authorize(a.implementation,C.HELD,C.HELD,a.case);contract.accepted(old,a.updater_decisions.absolute(),binding);return (parent if a.mode=='run'else worker)(args[1:],a,proof)
 return prerequisites(a.implementation,a.mode,args[1:])
if __name__=='__main__':raise SystemExit(main())
