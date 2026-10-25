#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One exact current606 GUI case using the original native574 producer and GUI clocks."""
import argparse,ast,fcntl,hashlib,importlib.util,json,os,re,shutil,signal,sys,time,types
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import admission as A
CASES=tuple(p+'-'+m for m in('generic4k','generic16k')for p in('minimal','overlay'))
SUCCESS='PASS_ONE_CURRENT606_WELCOME8_GUI_METADATA_PIXELS_PENDING_ROOT'
VIEWS=('home','terminal-action','files-action','system','first-steps','updates','recovery','management-absent','management-doctor','management-orphans','management-failure','management-dns','management-closing','welcome8-stopped','welcome8-retry')
def load(n,p):s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m
def save(p,v):
 p=Path(p);A.need(not p.exists(),'exclusive native receipt');p.write_bytes(A.enc(v));return v
def original():
 home=ROOT/'original/scripts/ci/welcome5-native-gui';sys.path.insert(0,str(home));return load('_current606_complete_original_job',home/'job.py')
def factory():
 sys.path.insert(0,str(ROOT/'factory'));return load('_current606_source_bound_factory',ROOT/'factory/factory.py')
def selected(case):A.need(case in CASES,'one independent source-owned case');return case.split('-',1)
def proof(case,state,env):
 fact=A.prove(ROOT);profile,mode=selected(case)
 if mode=='generic16k':
  media=A.obj(ROOT/'kernel-media-profile.json');A.need(re.fullmatch('[a-f0-9]{40}',media['source']or'')and media['ready']is True,'16K blocked until exact Root-published managed media profile is bound;4K independent')
 A.need(state.is_absolute()and not state.exists()and not any(p.is_symlink()for p in(state,*state.parents)),'fresh fixed owner state');state.mkdir(mode=0o700);old=original().prove(ROOT/'original',profile,env,state/'welcome5-runtime')
 value=dict(status='SOURCE_BOUND_CURRENT606_GUI_NATIVE_CASE',source=env['SOURCE_SHA'],run=int(env['GITHUB_RUN_ID']),attempt=int(env['GITHUB_RUN_ATTEMPT']),profile=profile,mode=mode,case=case,state=str(state),source_files=fact['files'],job_token=old['job_token'],owner_seconds=6600,started_monotonic=time.monotonic(),original348=old,actual_GUI='NOT_RUN',Root_acceptance='NOT_ISSUED');value['owner_deadline']=value['started_monotonic']+6600;save(state/'source-proof.json',value)
 with open(env['GITHUB_OUTPUT'],'a')as s:
  s.write('job_token='+old['job_token']+'\n')
  if mode=='generic16k':s.write('kernel_source='+media['source']+'\n')
 return value
def binding(case,state):
 A.prove(ROOT);p=A.obj(state/'source-proof.json');profile,mode=selected(case);A.need(p['case']==case and p['profile']==profile and p['mode']==mode and p['state']==str(state)and p['status']=='SOURCE_BOUND_CURRENT606_GUI_NATIVE_CASE','exact proof-bound current case');original().binding(ROOT/'original',profile,p['original348']);return p

def run(case,state,base,assets,carrier,tooling,bootstrap,kernel_carrier,welcome8,apps14,actual_argv):
 p=binding(case,state);F=factory();deadline=p['owner_deadline'];expected=['run','--case',case,'--state',str(state),'--base',str(base),'--assets',str(assets),'--carrier',str(carrier),'--tooling',str(tooling),'--bootstrap',str(bootstrap),'--kernel-carrier',str(kernel_carrier),'--welcome8',str(welcome8),'--apps14',str(apps14)];A.need(actual_argv==expected,'complete actual fixed native CLI argument order/paths');A.need(time.monotonic()<deadline,'original6600 full preparation/runtime owner deadline')
 def interrupted(*_):raise TimeoutError('unchanged6600 native owner interrupted')
 previous={s:signal.signal(s,interrupted)for s in(signal.SIGTERM,signal.SIGINT,signal.SIGALRM)};signal.setitimer(signal.ITIMER_REAL,deadline-time.monotonic())
 try:
  import input606
  prepared=input606.prepare(ROOT,carrier,bootstrap,base,state/'ready606',deadline,welcome8,apps14);save(state/'input-preparation.json',prepared)
  kernel=None
  if p['mode']=='generic16k':
   sys.path.insert(0,str(ROOT/'factory/retained-helpers'));L=load('_gui606_whole_managed_media_source',ROOT/'factory/retained-helpers/legacy_prefill.py');media=A.obj(ROOT/'kernel-media-profile.json');kernel_proof=L.prove(kernel_carrier,kernel_carrier/'.git',media,deadline);A.need(kernel_proof['tree']==media['tree'],'exact whole original kernel carrier tree');save(state/'kernel-media-custody.json',dict(status='CURRENT_CASE_ORIGINAL_MEDIA_CUSTODY_NOT_VM_ACCEPTANCE',source=p['source'],run=p['run'],attempt=p['attempt'],case=case,job_token=p['job_token'],media_profile=A.pin(A.read(ROOT/'kernel-media-profile.json')),carrier=kernel_proof));kernel=tuple(kernel_carrier/media['paths'][n]for n in('Image','config','profile'))
  runner=state/'runner';F.emit(ROOT/'original',assets,state/'ready606',runner,p['profile'],p['mode'],kernel,tooling,tooling/'.git',deadline)
  owner=load('_current606_full_original_runtime_owner',ROOT/'factory/run.py');result=owner.run(ROOT/'original',runner,base,state/'welcome5-runtime',p['profile'],p['mode']);save(state/'actual-invocation.json',dict(purpose='CURRENT606_GUI_NATIVE_ACTUAL_INVOCATION',case=case,profile=p['profile'],mode=p['mode'],source_proof=A.pin(A.read(state/'source-proof.json')),runner_proof=A.pin(A.read(runner/'current606-proof.json')),argv=actual_argv));return result
 finally:
  signal.setitimer(signal.ITIMER_REAL,0)
  for s,v in previous.items():signal.signal(s,v)

def cleanup(case,state,base):
 p=binding(case,state);factory();out=state/'ordered-cleanup.json'
 if (state/'gui606-private').exists()or(state/'ready606/private-retirement-refusal.json').exists()or((state/'bootstrap2').exists()and (not(state/'bootstrap2/result.json').exists()or A.obj(state/'bootstrap2/result.json').get('cleanup_status')!='PASS_EXACT_OWNED_BUILDERS_PRIVATE_INPUTS_RETIRED')):return save(out,dict(status='FAIL_UNCERTAIN_PRIVATE_SIGNER_RETIREMENT_PRODUCER_PRESERVED'))
 job=original();raw=(ROOT/'original/scripts/ci/welcome5-native-gui/job.py').read_text();tree=ast.parse(raw);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='cleanup');body=ast.get_source_segment(raw,node);A.need(body.count("runtime/'runtime.lock'")==1,'one exact original owner lease seam');body=body.replace("runtime/'runtime.lock'","runtime/'runtime.lease'",1);env=dict(vars(job));owner=load('_current606_cleanup15',ROOT/'factory/run.py');body=body.replace("validate_cleanup(gui);value['runtime']=gui['cleanup']","value['runtime_retirement']=validate_cleanup(gui);value['runtime']=gui['cleanup']",1);env['validate_cleanup']=owner.retirement;exec(compile(body,'<whole-original-ordered-producer-cleanup-lease-only>','exec'),env);return env['cleanup'](ROOT/'original',p['profile'],p['original348'],base,state/'welcome5-runtime',out)

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
 for n in('source-proof.json','ordered-cleanup.json','actual-invocation.json','input-preparation.json','retained574-custody.json'):copy(state/n,n)
 if p['mode']=='generic16k':copy(state/'kernel-media-custody.json','kernel-media-custody.json')
 for n in('report.json','installed-packages.lock'):copy(base/n,'base/'+n)
 runtime=state/'welcome5-runtime'
 for n in('result.json','runtime-terminal.json','runtime-child.log'):copy(runtime/n,n,n!='runtime-child.log')
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
  F=factory();load('_current606_fresh_whole_runner_export',ROOT/'factory/context606.py').authorize_runner(runner)
  ordered=A.obj(state/'ordered-cleanup.json');original_report=A.obj(base/'report.json');result=A.obj(runtime/'result.json');g=A.obj(gui/'runtime.json');terminal=A.obj(runtime/'runtime-terminal.json');A.need(ordered['status']=='PASS_RUNTIME_RETIRED_BEFORE_ORIGINAL_PRODUCER'and ordered['producer']==original_report['owned_cleanup']and original_report['status']=='PASS_NATIVE_OFFLINE_574_TRANSACTION'and original_report['ownership']['token']==p['job_token']and original_report['owned_cleanup']['status']=='PASS'and terminal['reaped']is terminal['group_absent']is terminal['natural_exit']is True and terminal['returncode']==0,'complete native runtime-before-producer ownership/retirement')
  owner=load('_current606_export_cleanup',ROOT/'factory/run.py');owner.cleanup(g);A.need(ordered['runtime']==g['cleanup'],'complete runtime15 rows before producer')
  A.need(result['status']=='PASS_ONE_CURRENT606_WELCOME8_GUI_PROFILE_PENDING_ROOT'and result['profile']==p['profile']and result['mode']==p['mode']and g['status']=='PASS_CURRENT606_WELCOME8_'+p['mode'].upper()+'_GUI_METADATA'and g['runtime_package_count']==g['guest_packages']==606 and g['controller_packages']==590 and g['base_image']==original_report['image'],'exact actual606/590/page/profile result')
  sys.path.insert(0,str(runner));K=load('_current606_source_regenerated_export_contract',runner/'contract.py');verified=K.verify_result(g['events'],A.obj(runner/'candidate-lock.json'));A.need(verified==result['GUI']==g['gui_contract'],'whole actual original13view/DNS/Doctor2 plus exact Apps14/KSM2/preservation chain')
  image=load('_current606_original_PPM',ROOT/'original/scripts/ci/desktop574_runtime.py');A.need(set(g['frames'])=={p['profile']+'-'+view for view in VIEWS},'exact13 source-owned frame rows')
  for n,row in g['frames'].items():A.need(image.ppm(out/'frames'/(n+'.ppm'))==row,'full original PPM identity')
  A.need(not v['errors'],'complete bounded original export');v.update(status=SUCCESS,GUI='NATIVE_METADATA_PASS_PIXELS_PENDING_REVIEW',contract=verified)
 except Exception as e:v['errors'].append(str(e)[:512])
 save(out/'retention.json',v);return v

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('phase',choices=('preflight','proof','assets','run','cleanup','retain','transport'));p.add_argument('--case',choices=CASES);p.add_argument('--state',type=Path)
 for n in('base','assets','carrier','tooling','bootstrap','public','project','renewal','output','kernel-carrier','welcome8','apps14'):p.add_argument('--'+n,type=Path)
 a=p.parse_args();A.prove(ROOT)
 if a.phase=='preflight':return print(json.dumps(A.prove(ROOT),sort_keys=True))or 0
 state=a.state.absolute();selected(a.case)
 if a.phase=='proof':v=proof(a.case,state,os.environ)
 else:
  q=binding(a.case,state)
  if a.phase=='assets':v=original().assets.prepare(ROOT/'original',a.public.absolute(),a.project.absolute(),a.output.absolute(),a.renewal.absolute())
  elif a.phase=='run':v=run(a.case,state,a.base.absolute(),a.assets.absolute(),a.carrier.absolute(),a.tooling.absolute(),a.bootstrap.absolute(),a.kernel_carrier.absolute(),a.welcome8.absolute(),a.apps14.absolute(),list(sys.argv[1:]))
  elif a.phase=='cleanup':v=cleanup(a.case,state,a.base.absolute())
  elif a.phase=='transport':v=load('_current606_safe_public_transport',ROOT/'transport.py').pack(a.public.absolute(),a.output.absolute(),q)
  else:v=retain(a.case,state,a.base.absolute(),a.output.absolute())
 print(json.dumps(v,sort_keys=True));return int(v.get('status','FAIL').startswith('FAIL'))
if __name__=='__main__':raise SystemExit(main())
