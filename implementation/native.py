#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One exact current606 GUI case using the original native574 producer and GUI clocks."""
import argparse,ast,fcntl,hashlib,importlib.util,json,os,re,shutil,signal,sys,time,types
from pathlib import Path
_POSITIVE_PROGRAM_STARTED_NS=time.monotonic_ns()
if __name__=='__main__'and sys.argv[1:2]in(['positive-run'],['positive-bootstrap']):
 def _positive_startup_expired(*_):raise TimeoutError('positive program startup exceeded20 seconds')
 _POSITIVE_PREVIOUS_ALARM=signal.signal(signal.SIGALRM,_positive_startup_expired);signal.setitimer(signal.ITIMER_REAL,20)
HERE=Path(__file__).resolve().parent
ROOT=HERE.parent/'parent574'
sys.path.insert(0,str(ROOT))
import admission as _original_admission
sys.path.insert(0,str(HERE))
import source_guard
A=types.SimpleNamespace(**vars(_original_admission));A.prove=lambda root:source_guard.old_prove(root,_original_admission.prove)
CASES=tuple(p+'-'+m for m in('generic4k','generic16k')for p in('minimal','overlay'))
SUCCESS='PASS_ONE_LATEST607_WELCOME8_GUI_METADATA_PIXELS_PENDING_ROOT'
VIEWS=('home','terminal-action','files-action','system','first-steps','updates','recovery','management-absent','management-doctor','management-orphans','management-failure','management-dns','management-closing','welcome8-stopped','welcome8-retry')
def load(n,p):s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m
def save(p,v):
 p=Path(p);A.need(not p.exists(),'exclusive native receipt');p.write_bytes(A.enc(v));return v
def original():
 home=ROOT/'original/scripts/ci/welcome5-native-gui';sys.path.insert(0,str(home));return load('_fresh607_live_ingress',HERE/'fresh_adaptation.py').job(load('_current606_complete_original_job',home/'job.py'),ROOT/'original')
def factory():
 sys.path.insert(0,str(ROOT/'factory'));return load('_installed607_observer_facade',HERE/'observer_apply.py').factory(load('_fresh607_live_ingress',HERE/'fresh_adaptation.py').factory(load('_current606_source_bound_factory',HERE/'factory/factory.py'),ROOT/'original').service1800())
def selected(case):A.need(case in CASES,'one independent source-owned case');return case.split('-',1)
def proof(case,state,env):
 fact=A.prove(ROOT);profile,mode=selected(case)
 if mode=='generic16k':
  media=A.obj(ROOT/'kernel-media-profile.json');A.need(re.fullmatch('[a-f0-9]{40}',media['source']or'')and media['ready']is True,'16K blocked until exact Root-published managed media profile is bound;4K independent')
 A.need(state.is_absolute()and not state.exists()and not any(p.is_symlink()for p in(state,*state.parents)),'fresh fixed owner state');state.mkdir(mode=0o700);old=original().prove(ROOT/'original',profile,env,state/'welcome5-runtime')
 value=dict(status='SOURCE_BOUND_LATEST607_GUI_NATIVE_CASE',source=env['SOURCE_SHA'],run=int(env['GITHUB_RUN_ID']),attempt=int(env['GITHUB_RUN_ATTEMPT']),profile=profile,mode=mode,case=case,state=str(state),source_files=fact['files'],job_token=old['job_token'],owner_seconds=6600,started_monotonic=time.monotonic(),original348=old,actual_GUI='NOT_RUN',Root_acceptance='NOT_ISSUED');value['owner_deadline']=value['started_monotonic']+6600;save(state/'source-proof.json',value)
 with open(env['GITHUB_OUTPUT'],'a')as s:
  s.write('job_token='+old['job_token']+'\n')
  if mode=='generic16k':s.write('kernel_source='+media['source']+'\n')
 return value
def binding(case,state):
 A.prove(ROOT);p=A.obj(state/'source-proof.json');profile,mode=selected(case);A.need(p['case']==case and p['profile']==profile and p['mode']==mode and p['state']==str(state)and p['status']=='SOURCE_BOUND_LATEST607_GUI_NATIVE_CASE','exact proof-bound current case');original().binding(ROOT/'original',profile,p['original348']);return p

def run(case,state,base,assets,carrier,tooling,bootstrap,kernel_carrier,welcome8,apps16,six_record,six_public,actual_argv):
 p=binding(case,state);F=factory();deadline=p['owner_deadline'];expected=['run','--case',case,'--state',str(state),'--base',str(base),'--assets',str(assets),'--carrier',str(carrier),'--tooling',str(tooling),'--bootstrap',str(bootstrap),'--kernel-carrier',str(kernel_carrier),'--welcome8',str(welcome8),'--apps16',str(apps16),'--six-record',str(six_record),'--six-public',str(six_public)];A.need(actual_argv==expected,'complete actual fixed native CLI argument order/paths');A.need(time.monotonic()<deadline,'original6600 full preparation/runtime owner deadline')
 def interrupted(*_):raise TimeoutError('unchanged6600 native owner interrupted')
 previous={s:signal.signal(s,interrupted)for s in(signal.SIGTERM,signal.SIGINT,signal.SIGALRM)};signal.setitimer(signal.ITIMER_REAL,deadline-time.monotonic())
 try:
  import latest_input607 as input606
  prepared=input606.prepare(ROOT,carrier,bootstrap,base,state/'ready606',deadline,welcome8,apps16,six_record,six_public);save(state/'input-preparation.json',prepared)
  kernel=None
  if p['mode']=='generic16k':
   sys.path.insert(0,str(ROOT/'factory/retained-helpers'));L=load('_gui606_whole_managed_media_source',ROOT/'factory/retained-helpers/legacy_prefill.py');media=A.obj(ROOT/'kernel-media-profile.json');kernel_proof=L.prove(kernel_carrier,kernel_carrier/'.git',media,deadline);A.need(kernel_proof['tree']==media['tree'],'exact whole original kernel carrier tree');save(state/'kernel-media-custody.json',dict(status='CURRENT_CASE_ORIGINAL_MEDIA_CUSTODY_NOT_VM_ACCEPTANCE',source=p['source'],run=p['run'],attempt=p['attempt'],case=case,job_token=p['job_token'],media_profile=A.pin(A.read(ROOT/'kernel-media-profile.json')),carrier=kernel_proof));kernel=tuple(kernel_carrier/media['paths'][n]for n in('Image','config','profile'))
  runner=state/'runner';F.emit(ROOT/'original',assets,state/'ready606',runner,p['profile'],p['mode'],kernel,tooling,tooling/'.git',deadline)
  owner=load('_selected607_owner_context',HERE/'runner_context.py').owner(load('_current606_full_original_runtime_owner',HERE/'factory/run.py'));result=owner.run_service1800(ROOT/'original',runner,base,state/'welcome5-runtime',p['profile'],p['mode']);save(state/'actual-invocation.json',dict(purpose='CURRENT606_GUI_NATIVE_ACTUAL_INVOCATION',case=case,profile=p['profile'],mode=p['mode'],source_proof=A.pin(A.read(state/'source-proof.json')),runner_proof=A.pin(A.read(runner/'current606-proof.json')),argv=actual_argv));return result
 finally:
  signal.setitimer(signal.ITIMER_REAL,0)
  for s,v in previous.items():signal.signal(s,v)

def cleanup(case,state,base):
 p=binding(case,state);factory();out=state/'ordered-cleanup.json'
 if (state/'gui606-private').exists()or(state/'ready606/private-retirement-refusal.json').exists()or((state/'bootstrap2').exists()and (not(state/'bootstrap2/result.json').exists()or A.obj(state/'bootstrap2/result.json').get('cleanup_status')!='PASS_EXACT_OWNED_BUILDERS_PRIVATE_INPUTS_RETIRED')):return save(out,dict(status='FAIL_UNCERTAIN_PRIVATE_SIGNER_RETIREMENT_PRODUCER_PRESERVED'))
 job=original();raw=(ROOT/'original/scripts/ci/welcome5-native-gui/job.py').read_text();tree=ast.parse(raw);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='cleanup');body=ast.get_source_segment(raw,node);A.need(body.count("runtime/'runtime.lock'")==1,'one exact original owner lease seam');body=body.replace("runtime/'runtime.lock'","runtime/'runtime.lease'",1);env=dict(vars(job));owner=load('_current606_cleanup15',HERE/'factory/run.py');body=body.replace("validate_cleanup(gui);value['runtime']=gui['cleanup']","value['runtime_retirement']=validate_cleanup(gui,terminal,lease,proof,runtime,base);value['runtime']=gui['cleanup']",1);env['validate_cleanup']=lambda gui,terminal,lease,proof,runtime,base:load('_fixed607_build_retirement',HERE/'build_inventory.py').lease_retirement(owner.retirement,gui,terminal,lease,proof,runtime,base,p);exec(compile(body,'<whole-original-ordered-producer-cleanup-lease-only>','exec'),env);return env['cleanup'](ROOT/'original',p['profile'],p['original348'],base,state/'welcome5-runtime',out)

def export_cap(n):
 if n.startswith('frames/'):return 8*1024**2
 if n.startswith('generated/'):return 96*1024**2
 if n.endswith('.log'):return 16*1024**2
 return 16*1024**2

def retain(case,state,base,out):
 p=binding(case,state);A.need(not out.exists(),'fresh original export');out.mkdir(mode=0o700);v=dict(status='FAIL_OR_INCOMPLETE',case=case,profile=p['profile'],mode=p['mode'],scope='ONE_CASE_NOT_PAIR_OR_ROOT_GUI_ADMISSION',files={},private_generated_members={},errors=[],total_bytes=0,GUI='NOT_ACCEPTED',hardware='NOT_RUN',visual_review='NOT_RUN',release='NOT_ADMITTED')
 def copy(src,n,required=True):
  if not required and not src.exists():return
  try:
   raw=A.read(src,export_cap(n));A.need(v['total_bytes']+len(raw)<=512*1024**2,'unchanged512MiB whole export bound');q=out/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(raw);v['files'][n]=A.pin(raw);v['total_bytes']+=len(raw)
  except Exception as e:v['errors'].append(n+': '+str(e)[:200])
 # Failure DATA is a fixed metadata projection, created before any positive
 # runner/closure gate. Never walk bootstrap private source/vendor/package work.
 failure=dict(status='SAME_ACTOR_FAILURE_DATA_NOT_ACCEPTANCE',source=p['source'],run=p['run'],attempt=p['attempt'],case=case,job_token=p['job_token'],source_proof=A.pin(A.read(state/'source-proof.json')),bootstrap=None)
 if (state/'bootstrap2/result.json').exists():
  try:
   b=A.obj(state/'bootstrap2/result.json');failure['bootstrap']={k:b[k]for k in('status','error_type','error','cleanup_status','cleanup_error')if k in b};failure['bootstrap']['commands']=[dict(log_command=Path(r['argv'][0]).name,exit=r['exit'],group_absent=r['group_absent'],seconds=r['seconds'],limit=r['limit'],original_limit_seconds=r['original_limit_seconds'])for r in b['commands']];failure['bootstrap']['original_receipt']=A.pin(A.read(state/'bootstrap2/result.json',16*1024**2))
  except Exception as e:failure['projection_error']=type(e).__name__+': '+str(e)[:200]
 save(out/'failure-data.json',failure);v['files']['failure-data.json']=A.pin(A.read(out/'failure-data.json'));v['total_bytes']+=v['files']['failure-data.json']['bytes']
 for n in('source-proof.json','ordered-cleanup.json','actual-invocation.json','input-preparation.json','retained574-custody.json','positive-run-lease.json','positive-host-clock.json','positive-bootstrap-lease.json','positive-bootstrap-clock.json','positive-preparation-children.json'):copy(state/n,n)
 if p['mode']=='generic16k':copy(state/'kernel-media-custody.json','kernel-media-custody.json')
 for n in('report.json','installed-packages.lock'):copy(base/n,'base/'+n)
 runtime=state/'welcome5-runtime'
 for n in('result.json','runtime-terminal.json','runtime-child.log','positive-owner-clock.json'):copy(runtime/n,n,n!='runtime-child.log')
 gui=runtime/'runtime'
 for n in('runtime.json','events.log','guest.log','configuration.log','runtime-image.log','qemu-image.log','runtime606-build-proof.json','controller590-build-proof.json','fixture.log','base-reference.log','config/desktop/desktop.json'):copy(gui/n,'gui/'+n,n in('runtime.json','events.log','guest.log'))
 for view in VIEWS:copy(gui/'frames'/(p['profile']+'-'+view+'.ppm'),'frames/'+p['profile']+'-'+view+'.ppm')
 runner=state/'runner'
 if runner.exists():
  for q in sorted(runner.rglob('*')):
   if q.is_file():
    name=str(q.relative_to(runner))
    if q.name=='diagnostic.Image' or name=='install-context606/bundle/packages/cachy-asahi-update-4.4.2-2-aarch64.pkg.tar.xz':v['private_generated_members'][name]=A.pin(A.read(q,256*1024**2))
    else:copy(q,'generated/'+name)
 try:
  F=factory();load('_selected607_export_context',HERE/'runner_context.py').authorize_runner(runner)
  ordered=A.obj(state/'ordered-cleanup.json');original_report=A.obj(base/'report.json');result=A.obj(runtime/'result.json');g=A.obj(gui/'runtime.json');terminal=A.obj(runtime/'runtime-terminal.json');A.need(ordered['status']=='PASS_RUNTIME_RETIRED_BEFORE_ORIGINAL_PRODUCER'and ordered['producer']==original_report['owned_cleanup']and original_report['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION'and original_report['ownership']['token']==p['job_token']and original_report['owned_cleanup']['status']=='PASS'and terminal['reaped']is terminal['group_absent']is terminal['natural_exit']is True and terminal['returncode']==0,'complete native runtime-before-producer ownership/retirement')
  owner=load('_current606_export_cleanup',HERE/'factory/run.py');owner.cleanup(g);A.need(ordered['runtime']==g['cleanup'],'complete runtime15 rows before producer')
  A.need(result['status']=='PASS_ONE_LATEST607_WELCOME8_GUI_PROFILE_PENDING_ROOT'and result['profile']==p['profile']and result['mode']==p['mode']and g['status']=='PASS_LATEST607_WELCOME8_'+p['mode'].upper()+'_GUI_METADATA'and g['runtime_package_count']==g['guest_packages']==607 and g['controller_packages']==590 and g['base_image']==original_report['image'],'exact actual606/590/page/profile result')
  sys.path.insert(0,str(runner));K=load('_current606_source_regenerated_export_contract',runner/'contract.py');verified=K.verify_result(g['events'],A.obj(runner/'candidate-lock.json'));A.need(verified==result['GUI']==g['gui_contract'],'whole actual original13view/DNS/Doctor2 plus exact Apps16/KSM2/preservation chain')
  image=load('_current606_original_PPM',ROOT/'original/scripts/ci/desktop574_runtime.py');A.need(set(g['frames'])=={p['profile']+'-'+view for view in VIEWS},'exact13 source-owned frame rows')
  for n,row in g['frames'].items():A.need(image.ppm(out/'frames'/(n+'.ppm'))==row,'full original PPM identity')
  A.need(not v['errors'],'complete bounded original export');v.update(status=SUCCESS,GUI='NATIVE_METADATA_PASS_PIXELS_PENDING_REVIEW',contract=verified)
 except Exception as e:v['errors'].append(str(e)[:512])
 save(out/'retention.json',v);return v

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=('preflight','proof','assets','run','cleanup','retain','transport'));p.add_argument('--case',choices=CASES);p.add_argument('--state',type=Path)
 for n in('base','assets','carrier','tooling','bootstrap','public','project','renewal','output','kernel-carrier','welcome8','apps16','six-record','six-public'):p.add_argument('--'+n,type=Path)
 a=p.parse_args();A.prove(ROOT)
 if a.phase=='preflight':return print(json.dumps(A.prove(ROOT),sort_keys=True))or 0
 state=a.state.absolute();selected(a.case)
 if a.phase=='proof':v=proof(a.case,state,os.environ)
 else:
  q=binding(a.case,state)
  if a.phase=='assets':v=original().assets.prepare(ROOT/'original',a.public.absolute(),a.project.absolute(),a.output.absolute(),a.renewal.absolute())
  elif a.phase=='run':v=run(a.case,state,a.base.absolute(),a.assets.absolute(),a.carrier.absolute(),a.tooling.absolute(),a.bootstrap.absolute(),a.kernel_carrier.absolute(),a.welcome8.absolute(),a.apps16.absolute(),a.six_record.absolute(),a.six_public.absolute(),list(sys.argv[1:]))
  elif a.phase=='cleanup':v=cleanup(a.case,state,a.base.absolute())
  elif a.phase=='transport':v=load('_current606_safe_public_transport',HERE/'transport.py').pack(a.public.absolute(),a.output.absolute(),q)
  else:v=retain(a.case,state,a.base.absolute(),a.output.absolute())
 print(json.dumps(v,sort_keys=True));return int(v.get('status','FAIL').startswith('FAIL'))
def _positive_helpers():
 return load('_positive607_phase_helpers',HERE/'presecret_control.py')

def _positive_policy(seconds,local=20):
 return dict(schema=1,phases={n:dict(seconds=max(21,seconds if n=='prep'else 21),local_io_seconds=local if n=='prep'else 1,fixed_tail_seconds=0)for n in('prep','vm','contract','cleanup')})

def _positive_full_subprocess_calls(deadline):
 import contextlib,math,subprocess,threading
 @contextlib.contextmanager
 def selected():
  original_run,original_output=subprocess.run,subprocess.check_output;gate=threading.Lock();calls=[]
  def full(argv,kwargs):
   A.need(type(argv)in(list,tuple)and argv,'fixed Source child argv required');program=Path(str(argv[0])).name;caps={'git':30,'gpg':30,'gpgv':30,'gpgconf':15};A.need(program in caps,'unprofiled preparation subprocess refused');requested=caps[program];remaining=deadline-time.monotonic();A.need(math.isfinite(remaining)and remaining>=requested+30,'full preparation child and retirement reserve required');options=dict(kwargs);options['timeout']=requested
   with gate:A.need(len(calls)<2048,'bounded preparation child count');calls.append(dict(program=program,seconds=requested))
   return options
  def run(argv,*args,**kwargs):return original_run(argv,*args,**full(argv,kwargs))
  def output(argv,*args,**kwargs):return original_output(argv,*args,**full(argv,kwargs))
  subprocess.run,subprocess.check_output=run,output
  try:yield calls
  finally:subprocess.run,subprocess.check_output=original_run,original_output
 return selected()

def positive_run(*args):
 import textwrap
 H=_positive_helpers();P=H.POSITIVE_PROFILE;A.need(args[0]==P['case'],'positive profile requires exact minimal-generic4k case');state=Path(args[1]);timing=[];outer_policy=_positive_policy(P['native_seconds'],20)
 with H.phase(outer_policy,'prep',report=timing.append)as outer:
  with outer.child('source-and-identity-admission',300,0,tail=10640):
   proof=binding(args[0],state);save(state/'positive-run-lease.json',dict(schema=1,profile=P,source_proof=A.pin(A.read(state/'source-proof.json')),source=proof['source'],run=proof['run'],attempt=proof['attempt'],case=proof['case'],host_started_ns=outer.started_ns,host_deadline_ns=outer.deadline,acceptance=False))
   raw=(HERE/'native.py').read_text();node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='run');body=ast.get_source_segment(raw,node)
  def change(a,b):
   nonlocal body
   A.need(body.count(a)==1,'exact positive native seam '+a[:70]);body=body.replace(a,b,1)
  change('def run(','def _selected_positive_run(')
  change("deadline=p['owner_deadline']","deadline=_positive_outer.deadline/10**9")
  change(';signal.setitimer(signal.ITIMER_REAL,deadline-time.monotonic())',' # Relative phase leases own the selected alarm.')
  change('  signal.setitimer(signal.ITIMER_REAL,0)','  # Relative phase context restores the inherited alarm.')
  start=body.index('  import latest_input607 as input606\n');end=body.index('  owner=load(',start);prep=body[start:end];new="  with _positive_H.phase(_positive_prep_policy,'prep',report=_positive_timing.append,outer_tail=7380)as _positive_prep:\n   deadline=_positive_prep.deadline/10**9\n   with _positive_full_subprocess_calls(deadline)as _positive_calls:\n"+textwrap.indent(prep,'  ')+"   save(state/'positive-preparation-children.json',dict(profile='GUI607_POSITIVE_PHASES_V1',calls=_positive_calls,acceptance=False))\n";body=body[:start]+new+body[end:]
  space=dict(globals(),_positive_H=H,_positive_outer=outer,_positive_timing=timing,_positive_prep_policy=_positive_policy(P['prepare_seconds'],120))
  original_save=save
  def positive_save(path,value):
   if Path(path)==state/'actual-invocation.json':value=dict(value,purpose='POSITIVE607_GUI_NATIVE_ACTUAL_INVOCATION',argv=['positive-run',*value['argv'][1:]],positive_budget_profile=P,positive_actual_argv=['positive-run',*value['argv'][1:]],normalized_legacy_argv=value['argv'])
   return original_save(path,value)
  space['save']=positive_save;exec(compile(body,str(HERE/'native.py')+'::<positive-run>','exec'),space)
  outer.admit('complete-positive-prepare-and-owner',P['prepare_seconds']+P['owner_work_seconds']+P['owner_retirement_seconds'],0)
  try:return space['_selected_positive_run'](*args)
  finally:
   with outer.local_io('positive-host-clock-receipt'):save(state/'positive-host-clock.json',dict(profile=P['profile'],timing_DATA=timing,acceptance=False))

def positive_bootstrap(argv):
 import textwrap
 started=time.monotonic();H=_positive_helpers();P=H.POSITIVE_PROFILE;p=argparse.ArgumentParser()
 for n in('state','base','retained','incoming','official','compiler','legacy','selected','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args(argv);state=a.state.absolute();A.need(binding(P['case'],state)['case']==P['case'],'exact positive bootstrap case');B=load('_whole_positive_bootstrap_predecessor',ROOT/'bootstrap2.py');raw=(ROOT/'bootstrap2.py').read_text();node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='build');text=ast.get_source_segment(raw,node);timing=[];old_obj=B.A.obj;lease=None;private_proof=old_obj(state/'source-proof.json');private_proof=dict(private_proof,owner_seconds=P['bootstrap_work_seconds'],started_monotonic=started,owner_deadline=started+P['bootstrap_work_seconds'])
 save(state/'positive-bootstrap-lease.json',dict(schema=1,profile=P,source_proof=A.pin(A.read(state/'source-proof.json')),source=private_proof['source'],run=private_proof['run'],attempt=private_proof['attempt'],case=P['case'],started_monotonic=started,deadline=private_proof['owner_deadline'],acceptance=False))
 space=dict(vars(B));space['A']=types.SimpleNamespace(**dict(vars(B.A),obj=lambda path:private_proof if Path(path)==state/'source-proof.json'else old_obj(path)));count=0;old_execute=B.execute
 def execute(argv,log,limit,deadline,commands):
  nonlocal count
  A.need(count<len(P['bootstrap_child_seconds'])and limit==P['bootstrap_legacy_child_seconds'][count],'exact positive bootstrap command order and legacy cap');requested=P['bootstrap_child_seconds'][count];position=count;count+=1;remaining=deadline-time.monotonic();A.need(remaining>=requested+40,'whole selected child and retirement allowance required');result=old_execute(argv,log,requested,deadline,commands);commands[-1].update(positive_child_ordinal=position+1,legacy_limit_seconds=limit,positive_requested_seconds=requested);A.need(commands[-1]['limit']==requested,'positive child cap may not be clipped');return result
 space['execute']=execute
 # These are fixed clock operands only; every archive/build/inventory/equality
 # and private-retirement predicate in the original function stays present.
 A.need(text.count('6600')==5,'five whole bootstrap clock operands');text=text.replace('6600',str(P['bootstrap_work_seconds']))
 begin=text.index(' try:\n');final=text.index(' finally:\n',begin);restore=text.index('  for s,v in previous.items():signal.signal(s,v)',final);cleanup_start=text.index('  try:\n',final)
 prefix=text[:begin];work=text[begin:final];cleanup=text[cleanup_start:restore];suffix=text[restore:]
 # Existing worker SIGALRM provides the work cap. A fresh cleanup phase survives
 # the original alarm cancellation and is never swallowed by except Exception.
 cleanup="  with _positive_H.phase(_positive_cleanup_policy,'cleanup',report=_positive_rows.append):\n"+textwrap.indent(cleanup,' ')
 text=prefix+work+text[final:cleanup_start]+cleanup+suffix;ast.parse(text);space.update(_positive_H=H,_positive_rows=timing,_positive_cleanup_policy=dict(schema=1,phases={n:dict(seconds=P['bootstrap_cleanup_seconds']if n=='cleanup'else 21,local_io_seconds=20 if n=='cleanup'else 1,fixed_tail_seconds=0)for n in('prep','vm','contract','cleanup')}));exec(compile(text,str(ROOT/'bootstrap2.py')+'::<positive-bootstrap>','exec'),space)
 try:
  result=space['build'](*(getattr(a,n).absolute()for n in('state','base','retained','incoming','official','compiler','legacy','selected','output')));A.need(count==9 and result['status']=='PASS_EXACT_TWO_BOOTSTRAP_ARCHIVE_BODIES_ORIGINAL_BUILDERS','all nine positive bootstrap commands and every original builder predicate');return result
 finally:save(state/'positive-bootstrap-clock.json',dict(profile=P['profile'],timing_DATA=timing,commands_started=count,acceptance=False))

def positive_entry():
 H=_positive_helpers();P=H.POSITIVE_PROFILE;phase_name=sys.argv[1];actual_argv=sys.argv[:]
 if __name__=='__main__':
  A.need(time.monotonic_ns()-_POSITIVE_PROGRAM_STARTED_NS<=20*10**9,'bounded positive program startup');signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,_POSITIVE_PREVIOUS_ALARM)
 A.need(phase_name in('positive-run','positive-bootstrap'),'explicit positive route only')
 if phase_name=='positive-bootstrap':return print(json.dumps(positive_bootstrap(sys.argv[2:]),sort_keys=True))or 0
 # Exactly one renamed phase word; all original strict option order/path checks
 # still execute in the copied current source main/run functions.
 try:
  sys.argv=[sys.argv[0],'run',*sys.argv[2:]];scope=dict(globals(),run=positive_run);raw=(HERE/'native.py').read_text();node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='main');body=ast.get_source_segment(raw,node);needle='a=p.parse_args();A.prove(ROOT)';A.need(body.count(needle)==1,'one duplicate Source-only admission before positive run');body=body.replace(needle,'a=p.parse_args()',1);exec(compile(body,str(HERE/'native.py')+'::<positive-main>','exec'),scope);return scope['main']()
 finally:sys.argv=actual_argv

if __name__=='__main__':raise SystemExit(positive_entry()if sys.argv[1:2]in(['positive-run'],['positive-bootstrap'])else main())
