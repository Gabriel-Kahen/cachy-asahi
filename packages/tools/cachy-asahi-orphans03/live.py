#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit-target live orphan preview, reviewed plan and exact ALPM removal."""
import argparse,ctypes as C,errno,importlib.util,json,os,signal,stat,threading,time
from pathlib import Path
HERE=Path(__file__).resolve().parent

def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
R=load('orphans_live_remove',HERE/'remove.py');O=R.O
need=O.need
P=load('orphans_live_policy',HERE/'live_policy.py')
SCOPE='EXPLICIT_LIVE_ORPHAN_TARGET_V1'

class LiveTransaction(R.Transaction):
 """Keep dependency/version/conflict/lock checks; no recursive transaction flags."""
 def __init__(self,root,db):
  super().__init__(root,db)
  for name,args,result in [('alpm_trans_get_flags',[C.c_void_p],C.c_int),('alpm_option_get_logfile',[C.c_void_p],C.c_char_p),('alpm_option_get_usesyslog',[C.c_void_p],C.c_int)]:
   function=getattr(self.lib,name);function.argtypes=args;function.restype=result
 def begin(self):
  # Direct ALPM deliberately does not parse or rewrite pacman configuration.
  # The operator's private recovery receipt is the transaction log for this CLI.
  O.need(self.lib.alpm_option_get_logfile(self.handle) is None,'unconfigured direct-ALPM logfile required')
  O.need(self.lib.alpm_option_get_usesyslog(self.handle)==0,'unconfigured direct-ALPM syslog required')
  super().begin();O.need(self.lib.alpm_trans_get_flags(self.handle)==R.FLAGS,'exact NOHOOKS|NOSCRIPTLET flags required')


def runtime():
 path=Path('/usr/lib/libalpm.so.16').resolve(strict=True)
 O.need(path.parent==Path('/usr/lib'),'trusted ALPM runtime location required')
 with O.directory(path.parent) as (fd,_):record,_=O.read(fd,path.name,O.limits(),16*1024**2)
 O.need(record['uid']==0 and not record['mode']&0o022,'trusted ALPM runtime required')
 return dict(path=str(path),identity=record)


def _installed(root,db,policy,selected=(),*,owned_lock=None):
 report,lost=O.inspect(root,db,[],selected,owned_lock=owned_lock)
 rows=report['packages'];P.validate_inventory(policy,rows,O)
 protected=(P.protect(policy,O)&set(rows))|{n for n in rows if P.is_platform_name(n)}
 pending=list(protected)
 while pending:
  for values in rows[pending.pop()]['satisfiers'].values():
   for name in values.values():
    if name is not None and name not in protected:protected.add(name);pending.append(name)
 for name,row in rows.items():
  row['protected']=name in protected
  row['candidate']=row['candidate'] and name not in protected
 report['candidates']=sorted(n for n,r in rows.items() if r['candidate'])
 report['protected_closure']=sorted(protected)
 return report,lost


def _guard(api,root,policy,installed,selected):
 before={n:r['version'] for n,r in installed['packages'].items()}
 O.need(api.inventory()==before,'transaction cache differs from installed assessment')
 chosen,shared=R.payload_guard(api,root,before,selected,allow_ldconfig=policy['ldconfig']['mode']=='reviewed')
 paths=[]
 for name in selected:paths.extend(api.files(name,before[name]))
 effects=P.effects(root,policy,selected,paths,O)
 return dict(files=chosen,shared_directories=shared),effects


def assess(root,db,policy_path,policy_sha256):
 root,db=O.absolute(root),O.absolute(db)
 policy,identity=P.read_policy(policy_path,policy_sha256,O)
 target=P.validate_target(root,db,policy,O);backend=runtime()
 installed,lost=_installed(root,db,policy)
 O.need(not lost,'inconsistent unselected installed state')
 eligibility={n:dict(eligible=False,reasons=['explicit, protected, hard/optional needed, or unknown reason']) for n in installed['packages']}
 api=None
 try:
  api=LiveTransaction(root,db);until=time.monotonic()+30
  for name in installed['candidates']:
   O.need(time.monotonic()<until,'live eligibility preview deadline exceeded')
   if installed['broken_dependencies']:
    eligibility[name]=dict(eligible=False,reasons=['baseline has unsatisfied dependencies']);continue
   try:
    payload,effects=_guard(api,root,policy,installed,[name]);eligibility[name]=dict(eligible=True,reasons=[],payload=payload,effects=effects)
   except (O.Refused,OSError,ValueError) as error:eligibility[name]=dict(eligible=False,reasons=[str(error)[:500]])
 finally:
  if api is not None:api.close()
 snapshot,_=O.database_snapshot(db);O.unlocked(db)
 O.need(snapshot==installed['database'],'database changed during live eligibility preview')
 O.need(P.validate_target(root,db,policy,O)==target and runtime()==backend,'target or ALPM runtime changed')
 return dict(schema_version=1,status='NOT_APPLIED',scope=SCOPE,target=target,root=str(root),dbpath=str(db),policy_path=str(O.absolute(policy_path)),policy=policy,policy_identity=identity,runtime=backend,installed=installed,eligibility=eligibility,eligible_candidates=sorted(n for n,r in eligibility.items() if r['eligible']),mutation_requires='EXPLICIT_TARGET_POLICY_PLAN_SHA_SELECTION_AND_AUTHORIZE_LIVE_REMOVAL',hardware='NOT_RUN')


def selections(names):
 O.need(type(names) is list and 0<len(names)<=O.MAX_PACKAGES and len(names)==len(set(names)) and all(type(n) is str and O.NAME.fullmatch(n) for n in names),'nonempty unique exact selections required')


def plan(assessment_path,selected,root,db,policy_path,policy_sha256,output=None):
 selections(selected);saved,record=O.json_file(assessment_path)
 O.need(saved.get('scope')==SCOPE and saved.get('status')=='NOT_APPLIED','explicit live assessment required')
 current=assess(root,db,policy_path,policy_sha256);O.need(current==saved,'live assessment/target/policy/database/payload eligibility changed')
 O.need(not current['installed']['broken_dependencies'],'baseline has unsatisfied dependencies')
 O.need(set(selected)<=set(current['eligible_candidates']),'selection is not an eligible orphan preview')
 installed,lost=_installed(O.absolute(root),O.absolute(db),current['policy'],selected)
 O.need(installed==current['installed'] and not lost,'selected set loses dependency/provider or installed state changed')
 api=LiveTransaction(O.absolute(root),O.absolute(db))
 try:payload,effects=_guard(api,O.absolute(root),current['policy'],installed,selected)
 finally:api.close()
 snapshot,_=O.database_snapshot(O.absolute(db));O.unlocked(O.absolute(db));O.need(snapshot==installed['database'],'database drift during plan')
 value=dict(schema_version=1,status='NOT_APPLIED',scope=SCOPE,operation='EXPLICIT_LIVE_ORPHAN_REMOVAL_PLAN',assessment=str(O.absolute(assessment_path)),assessment_identity=record,target=current['target'],root=str(root),dbpath=str(db),policy_path=current['policy_path'],policy_identity=current['policy_identity'],policy_sha256=policy_sha256,runtime=current['runtime'],database_sha256=installed['database']['sha256'],dependency_facts_sha256=O.digest(O.encoded(installed['packages'])),selected={n:installed['packages'][n] for n in sorted(selected)},payload=payload,effects=effects,transaction_flags=R.FLAGS)
 if output:return O.publish(output,value,O.absolute(db))
 return value


def _reviewed(args):
 selections(args.select)
 O.need(args.authorize_live_removal is True,'explicit --authorize-live-removal required')
 # Refuse an unprivileged explicit '/' before touching private inputs or target DB.
 if O.absolute(args.target_root)==Path('/'):O.need(os.geteuid()==0,'live root removal requires an already authorized root operator; no auto-sudo')
 O.need(type(args.plan_sha256) is str and O.re.fullmatch('[0-9a-f]{64}',args.plan_sha256),'exact reviewed plan SHA256 required')
 saved,record=O.json_file(args.plan)
 O.need(record['sha256']==args.plan_sha256 and saved.get('operation')=='EXPLICIT_LIVE_ORPHAN_REMOVAL_PLAN' and saved.get('scope')==SCOPE,'exact live plan bytes required')
 O.need(set(saved['selected'])==set(args.select),'exact reviewed selected set required')
 current=plan(Path(saved['assessment']),args.select,args.target_root,args.target_dbpath,args.policy,args.policy_sha256)
 O.need(current==saved,'live plan is stale or changed')
 assessment,_=O.json_file(Path(saved['assessment']))
 return saved,record,assessment


def initial_result():
 value=R.initial_result();value.update(scope=SCOPE,configuration='NO_SELECTED_BACKUPS_ETC_HOME_OR_UNOWNED_PAYLOAD',transaction_flags=R.FLAGS,automatic_retry=False);return value


def execute(args,save,*,factory=LiveTransaction):
 result=initial_result();api=None
 try:
  saved,record,assessment=_reviewed(args)
  root,db=O.absolute(args.target_root),O.absolute(args.target_dbpath);policy=assessment['policy'];selected={n:r['version'] for n,r in saved['selected'].items()}
  binding=dict(root=str(root),dbpath=str(db),selected=selected,plan_identity=record,assessment_identity=saved['assessment_identity'],policy_identity=saved['policy_identity'],target=saved['target'],effects=saved['effects'])
  O.need(len(O.encoded(binding))+2*len(O.encoded(selected))<R.MAX_RECEIPT-16384,'selection exceeds finite recovery receipt bound')
  result.update(binding);save(result);api=factory(root,db);api.begin();result['phase']='locked-revalidation';save(result)
  O.need(P.validate_target(root,db,policy,O)==saved['target'] and runtime()==saved['runtime'],'target/runtime changed while acquiring lock')
  current,lost=_installed(root,db,policy,args.select,owned_lock=api.lock)
  R.same_snapshot(current['database'],assessment['installed']['database'],locked=True)
  O.need({k:v for k,v in current.items() if k!='database'}=={k:v for k,v in assessment['installed'].items() if k!='database'},'dependency/reason/provider/protected state changed')
  O.need(not lost and not current['broken_dependencies'] and all(current['packages'][n]['candidate'] for n in selected),'protected/needed or inconsistent selection')
  payload,effects=_guard(api,root,policy,current,selected)
  O.need(payload==saved['payload'] and effects==saved['effects'],'reviewed payload/hook/helper/config state changed')
  before={n:r['version'] for n,r in current['packages'].items()};result.update(before_count=len(before),before_inventory_sha256=O.digest(O.encoded(before)),phase='prepare');save(result)
  for name,version in selected.items():api.remove(name,version)
  additions,removals=api.prepare();result.update(prepared_add=additions,prepared_remove=removals)
  O.need(additions=={} and removals==selected,'ALPM solver prepared a different selection')
  # Reopen all policy/input and installed facts after solver preparation, before
  # committing. The same owner retains the database lock throughout this window.
  api.lock.check();R.recheck_inputs(args.plan,record,saved)
  policy_now,policy_identity=P.read_policy(args.policy,args.policy_sha256,O)
  O.need(policy_now==policy and policy_identity==saved['policy_identity'],'reviewed policy replaced or changed')
  O.need(P.validate_target(root,db,policy,O)==saved['target'] and runtime()==saved['runtime'],'precommit target/runtime drift')
  final,lost=_installed(root,db,policy,args.select,owned_lock=api.lock)
  O.need(final==current and not lost,'precommit database/dependency/protected drift')
  payload,effects=_guard(api,root,policy,final,selected)
  O.need(payload==saved['payload'] and effects==saved['effects'],'precommit ownership/config/hook/helper drift')
  result.update(phase='commit',commit_started=True,packages_committed='UNKNOWN');save(result)
  api.commit();result.update(packages_committed=True,phase='postcommit');save(result);api.lock.check()
  after,_=_installed(root,db,policy,owned_lock=api.lock)
  O.need({n:r['version'] for n,r in after['packages'].items()}=={n:v for n,v in before.items() if n not in selected},'postcommit package set differs')
  R.same_snapshot(after['database'],assessment['installed']['database'],locked=True,removed=tuple(selected.items()))
  O.need(not after['broken_dependencies'],'postcommit dependency state broken')
  for path in payload['files']:O.need(not os.path.lexists(root/path),'selected owned payload remains')
  for path,node in payload['shared_directories'].items():
   after_dir=R.payload_node(root,Path(path),O.limits());O.need(all(after_dir[k]==node[k] for k in ('kind','dev','ino','mode','uid','gid')),'unselected-owned directory removed/replaced')
  result.update(status='APPLIED',phase='complete',after_count=len(after['packages']),after_inventory_sha256=O.digest(O.encoded({n:r['version'] for n,r in after['packages'].items()})))
 except BaseException as error:result.update(status='FAILED' if result['commit_started'] else 'REFUSED',error_type=type(error).__name__,reason=str(error)[:500])
 finally:
  if api is not None:api.cleanup(result)
  if 'dbpath' in result:
   try:O.unlocked(Path(result['dbpath']));result['lock_state']='ABSENT'
   except BaseException:result['lock_state']='PRESENT_OR_UNCERTAIN'
  if result['cleanup_errors'] or result['lock_state']=='PRESENT_OR_UNCERTAIN':result['status']='FAILED'
  if result['commit_started'] and result['status']!='APPLIED':result['recovery']='OUTCOME_UNCERTAIN_REVIEW_DURABLE_RECEIPT_TARGET_AND_LOCK_DO_NOT_RETRY_OR_AUTO_UNLOCK'
  save(result)
 return result


def supervise(args,receipt,*,work=execute):
    """Own one live session; reserve its leader through the last group signal."""
    need(threading.current_thread() is threading.main_thread() and threading.active_count()==1,'single main-thread child owner required')
    need(signal.getsignal(signal.SIGCHLD)==signal.SIG_DFL,'default owned-child reaping disposition required')
    need(hasattr(os,'waitid') and hasattr(os,'WNOWAIT'),'WNOWAIT child ownership required')
    signal.signal(signal.SIGCHLD,signal.SIG_DFL)  # Clear inherited SA_NOCLDWAIT.
    receipt.save(initial_result());parent=os.getpid()
    requested=[];old={};pid=None;owned=False;wait_status=None;termination=None;fault=None;old_mask=None;group_ready=False
    ready_r=ready_w=grant_r=grant_w=None
    cancellation={signal.SIGTERM,signal.SIGINT,signal.SIGALRM}
    def request(signum,frame):requested.append(signum)
    def observe():
        nonlocal owned,fault
        if not owned:return None
        try:
            row=os.waitid(os.P_PID,pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
            if row is not None:need(row.si_pid==pid and row.si_code in (os.CLD_EXITED,os.CLD_KILLED,os.CLD_DUMPED),'unexpected child observation')
            return row
        except BaseException as error:
            owned=False;fault=type(error).__name__+': '+str(error)[:300];return None
    def send(signum):
        nonlocal owned,fault
        observe()
        if not owned:return False
        try:
            if group_ready:os.killpg(pid,signum)
            else:os.kill(pid,signum)  # Worker has not received permission to run work.
            return True
        except BaseException as error:
            owned=False;fault=type(error).__name__+': '+str(error)[:300];return False
    try:
        for signum in cancellation:old[signum]=signal.signal(signum,request)
        old_mask=signal.pthread_sigmask(signal.SIG_BLOCK,cancellation)
        ready_r,ready_w=os.pipe2(os.O_CLOEXEC);grant_r,grant_w=os.pipe2(os.O_CLOEXEC)
        pid=os.fork()
        if pid==0:
            try:
                os.close(ready_r);os.close(grant_w);os.setsid()
                libc=C.CDLL(None,use_errno=True);libc.prctl.argtypes=[C.c_int,C.c_ulong,C.c_ulong,C.c_ulong,C.c_ulong];libc.prctl.restype=C.c_int
                need(libc.prctl(1,signal.SIGKILL,0,0,0)==0 and os.getppid()==parent,'parent-death guard failed')
                def cancel(signum,frame):raise InterruptedError('removal worker interrupted')
                for signum in cancellation:signal.signal(signum,cancel)
                signal.pthread_sigmask(signal.SIG_SETMASK,old_mask)
                os.write(ready_w,b'R');os.close(ready_w)
                need(os.read(grant_r,1)==b'G','parent did not grant registered session work');os.close(grant_r)
                value=work(args,receipt.save);os._exit(0 if value['status']=='APPLIED' else 1)
            except BaseException:os._exit(2)
        owned=True
        os.close(ready_w);ready_w=None;os.close(grant_r);grant_r=None
        # Pending cancellation is delivered only after the PID has an owner.
        signal.pthread_sigmask(signal.SIG_SETMASK,old_mask);old_mask=None
        until=time.monotonic()+args.timeout_seconds;kill_at=None
        os.set_blocking(ready_r,False)
        while not group_ready:
            if requested:termination='CANCELLED';raise InterruptedError('cancelled before session grant')
            need(time.monotonic()<until,'live session registration deadline')
            need(observe() is None and owned,'worker exited or ownership lost before session registration')
            try:token=os.read(ready_r,1)
            except BlockingIOError:time.sleep(.01);continue
            need(token==b'R','worker session readiness failed')
            observe();need(owned and os.getpgid(pid)==pid,'unverified worker session identity')
            group_ready=True  # Register before granting any ALPM/helper work.
            os.write(grant_w,b'G');os.close(grant_w);grant_w=None
        os.close(ready_r);ready_r=None
        while owned:
            if observe() is not None:break
            if not owned:break
            now=time.monotonic()
            if termination is None and (requested or now>=until):
                termination='CANCELLED' if requested else 'TIMEOUT'
                if not send(signal.SIGTERM):break
                kill_at=now+2
            elif kill_at is not None and now>=kill_at:
                send(signal.SIGKILL);break
            time.sleep(0.02)
    except BaseException as error:
        termination=termination or 'SUPERVISOR_ERROR';fault=type(error).__name__+': '+str(error)[:300]
    finally:
        # Every numeric signal is preceded by a successful WNOWAIT observation.
        # No wait/poll has released the PID yet. Lost ownership is permanent.
        row=observe()
        if owned and (group_ready or row is None):send(signal.SIGKILL)
        cleanup_until=time.monotonic()+2
        while owned:
            row=observe()
            if not owned:break
            if row is not None:
                try:
                    child,status=os.waitpid(pid,os.WNOHANG)
                    need(child==pid,'terminal child final reap not observed')
                    wait_status=status;owned=False
                except OSError as error:
                    fault=type(error).__name__+': '+str(error)[:300];termination='SUPERVISOR_ERROR'
                    if isinstance(error,ChildProcessError) or error.errno==errno.ECHILD:owned=False
                    elif time.monotonic()<cleanup_until:continue  # Reobserve; no later signals.
                except BaseException as error:
                    owned=False;fault=type(error).__name__+': '+str(error)[:300];termination='SUPERVISOR_ERROR'
                break
            if time.monotonic()>=cleanup_until:break
            time.sleep(0.02)
        for descriptor in (ready_r,ready_w,grant_r,grant_w):
            if descriptor is not None:
                try:os.close(descriptor)
                except OSError:pass
        if old_mask is not None:signal.pthread_sigmask(signal.SIG_SETMASK,old_mask)
        for signum,handler in old.items():signal.signal(signum,handler)
    try:result=receipt.read()
    except (ValueError,OSError):result=dict(initial_result(),commit_started='UNKNOWN',packages_committed='UNKNOWN',reason='incomplete worker receipt')
    code=os.waitstatus_to_exitcode(wait_status) if wait_status is not None else None
    result['worker']=dict(reaped=wait_status is not None,exitcode=code,termination=termination,ownership='REAPED' if wait_status is not None else 'UNKNOWN',session_registered=group_ready,descendant_exit='UNKNOWN_NOT_DIRECTLY_REAPED',descendant_scope='REVIEWED_SAME_SESSION_HELPERS_ONLY_NO_DETACHMENT_OR_FATAL_PARENT_CLEANUP_CLAIM')
    if fault:result['worker']['error']=fault
    if wait_status is None:
        result.update(status='FAILED',last_durable_commit_started=result.get('commit_started'),last_durable_packages_committed=result.get('packages_committed'),commit_started='UNKNOWN',packages_committed='UNKNOWN')
    elif termination or code!=0 or result.get('status')!='APPLIED':
        result['status']='FAILED' if result.get('commit_started') else 'REFUSED'
        if result.get('phase')=='commit' and result.get('packages_committed') is not True:result['packages_committed']='UNKNOWN'
    if result['status']!='APPLIED':result['recovery']='REVIEW_RECEIPT_TARGET_AND_LOCK_NO_AUTOMATIC_RETRY_OR_UNLOCK'
    receipt.save(result);return result



def main(argv=None):
 parser=argparse.ArgumentParser(description=__doc__);sub=parser.add_subparsers(dest='command',required=True)
 for name in ('assess','plan','remove'):
  command=sub.add_parser(name);command.add_argument('--target-root',type=Path,required=True);command.add_argument('--target-dbpath',type=Path,required=True);command.add_argument('--policy',type=Path,required=True);command.add_argument('--policy-sha256',required=True)
  if name!='assess':command.add_argument('assessment' if name=='plan' else 'plan',type=Path);command.add_argument('--select',action='append',required=True)
  if name!='remove':command.add_argument('--output',type=Path,required=True)
  else:command.add_argument('--plan-sha256',required=True);command.add_argument('--authorize-live-removal',action='store_true',required=True);command.add_argument('--result',type=Path,required=True);command.add_argument('--timeout-seconds',type=int,default=60)
 args=parser.parse_args(argv);receipt=None;delegated=False
 try:
  if args.command=='assess':result=O.publish(args.output,assess(args.target_root,args.target_dbpath,args.policy,args.policy_sha256),args.target_dbpath)
  elif args.command=='plan':result=plan(args.assessment,args.select,args.target_root,args.target_dbpath,args.policy,args.policy_sha256,args.output)
  else:
   O.need(1<=args.timeout_seconds<=120,'timeout must be between1 and120 seconds');_reviewed(args)
   O.need(not O.absolute(args.result).is_relative_to(O.absolute(args.target_dbpath)),'receipt must be outside target database')
   # A '/' target naturally contains its operator receipt; exclude selected
   # payload and integration/configuration paths instead of banning all paths.
   for relative in ('usr','etc','var/lib/pacman','var/cache/ldconfig','var/log','boot','home'):O.need(not O.absolute(args.result).is_relative_to(O.absolute(args.target_root)/relative),'private operator receipt outside target payload/configuration required')
   receipt=R.Receipt(args.result);delegated=True;result=supervise(args,receipt,work=execute)
  print(json.dumps(result,sort_keys=True));return 0 if args.command!='remove' or result['status']=='APPLIED' else 1
 except (O.Refused,OSError,ValueError,TypeError,KeyError,RecursionError) as error:
  result=initial_result()
  if delegated:
   result.update(status='FAILED',commit_started='UNKNOWN',packages_committed='UNKNOWN',recovery='REVIEW_TARGET_AND_LAST_DURABLE_RECEIPT_NO_AUTO_RETRY_OR_UNLOCK')
   try:
    last=receipt.read()
    if last.get('commit_started') is True or last.get('packages_committed') is True:result.update(last,status='FAILED')
   except BaseException:pass
  result.update(reason=str(error)[:500],error_type=type(error).__name__);print(json.dumps(result,sort_keys=True));return 1
 finally:
  if receipt is not None:receipt.close()

if __name__=='__main__':raise SystemExit(main())
