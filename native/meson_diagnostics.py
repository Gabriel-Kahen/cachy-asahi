# SPDX-License-Identifier: MIT
"""Pinned Source Meson stage DATA before the unchanged aggregate guard."""
import hashlib,json,math,re
from pathlib import Path
from capsule import _ordinary
from common import pin,save
from consumer_diagnostics import safe_text
from privacy_diagnostics import inspect_privacy,validate_context
ROOT=Path(__file__).resolve().parents[1]
PRODUCERS={
 'scripts/workflows/developer_build_systems.py':dict(bytes=20558,sha256='8c5025f3d748fb2e5aebb304310852158ebaac0bcaf9ef44cad8676ed5963fbc'),
 'scripts/workflows/developer_workflow.py':dict(bytes=29699,sha256='531c124cde3fa41d46888acfc638c823196bb2f297b19ab68ab3d001b05f16ba'),
 'scripts/virtual/owned_process.py':dict(bytes=25140,sha256='83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f')}
TOOLS=('cmake','ctest','meson','ninja','cc','c++')
AGGREGATE={'PASS_AVAILABLE_LOCAL_WORKFLOWS','NOT_RUN_NO_BUILD_SYSTEM','FAIL','UNKNOWN','ABSENT'}
PROJECT={'PASS_REAL_PROJECT_WORKFLOW','NOT_RUN','FAIL','RUNNING','UNKNOWN','ABSENT'}
TOOL={'PRESENT','MISSING','UNKNOWN','ABSENT'}
BUILD=('initial-build','unchanged-build','changed-build','broken-build','compile-recovery-build','test-failure-build','test-recovery-build')
TEST=('initial-test','changed-test','compile-recovery-test','broken-test','test-recovery-test')
RUN=('initial-run','changed-run','compile-recovery-run','test-recovery-run')
INSTALLED=('installed-run-without-build-source','installed-missing-library-control','installed-restored-library-run')
STEPS={'version-meson':('TOOL_VERSION','MESON_VERSION'),'meson-configure':('CONFIGURE','MESON_CONFIGURE'),'meson-install':('INSTALL','MESON_INSTALL')}
for names,stage,role in ((BUILD,'BUILD','MESON_BUILD'),(TEST,'TEST','MESON_TEST'),(RUN,'BUILD_RUNTIME','BUILT_PRODUCT_RUN'),(INSTALLED,'INSTALLED_RUNTIME','INSTALLED_PRODUCT_RUN')):STEPS.update({'meson-'+s:(stage,role) for s in names})
SUP_KEYS={'exit','reaped','ownership','timeout','signals','output_complete','group_census','error','seconds','passed'}
ERRORS={'ABSENT','COMMAND_FAILURE_MESSAGE','WORKFLOW_DEADLINE_EXHAUSTED_BEFORE_LAUNCH','CANCELLED_PRIOR_CHILD_RETIRED','OTHER_SOURCE_COMMAND_FAILED','UNKNOWN'}
FAILURE_STAGES={'NONE_REPORTED','COMMAND_FAILURE_OR_RETIREMENT_UNKNOWN','AFTER_LAST_COMMAND_OR_RECORD_FAILURE_OR_UNKNOWN','OTHER_SOURCE_STAGE_OR_UNKNOWN','BEFORE_MESON_COMMAND_OR_NOT_RUN'}
CAP=512*1024
RESULT_CAP=16*1024**2
LOG_CAP=256*1024
WINDOW=64*1024
class Guard(ValueError):pass
def check(ok,code):
 if not ok:raise Guard(code)
def canonical(value):return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode('utf-8')
def typed_pin(value,cap):
 check(type(value) is dict and set(value)=={'bytes','sha256'} and type(value['bytes']) is int and 0<=value['bytes']<=cap and type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}',value['sha256']),'PIN_GUARD')
def status(value,allowed,present=True):return value if type(value) is str and value in allowed else 'UNKNOWN' if present else 'ABSENT'
def path(value):
 check(type(value) is str and 0<len(value.encode())<=4096,'COMMAND_GUARD');p=Path(value)
 check(p.is_absolute() and '..' not in p.parts and str(p)==value and not value.startswith('//'),'COMMAND_GUARD');safe_text(value.encode());return p
def source_pins():
 for name,expected in PRODUCERS.items():check(pin(_ordinary(ROOT/name,128*1024))==expected,'SOURCE_GUARD')
 return dict(PRODUCERS)
def report_error(report,step):
 if 'error' not in report:return dict(code='ABSENT',field_pin=None)
 value=report['error'];code='UNKNOWN'
 if type(value) is str:
  if step is not None and value=='Failure: command failed or retirement unknown: '+step:code='COMMAND_FAILURE_MESSAGE'
  elif value=='Failure: workflow deadline exhausted before launch':code='WORKFLOW_DEADLINE_EXHAUSTED_BEFORE_LAUNCH'
  elif value=='Failure: cancellation requested; prior child already retired':code='CANCELLED_PRIOR_CHILD_RETIRED'
  elif value.startswith('Failure: command failed or retirement unknown: cmake-'):code='OTHER_SOURCE_COMMAND_FAILED'
 return dict(code=code,field_pin=pin(canonical(value)))
def _sup_fields(value):
 check(type(value) is dict and set(value)==SUP_KEYS,'SUPERVISION_GUARD')
 check(value['exit'] is None or type(value['exit']) is int and -255<=value['exit']<=255,'SUPERVISION_GUARD')
 check(all(type(value[k]) is bool for k in ('reaped','timeout','output_complete','passed')) and value['ownership'] in {'OWNED','REAPED','UNKNOWN'} and value['group_census'] in {'NOT_OBSERVED','RESERVED_LEADER_ONLY','RESERVED_MEMBERS_REMAIN','UNKNOWN','PRESENT_OR_REUSED','EMPTY_ONCE','EMPTY_TWICE'} and type(value['signals']) is list and len(value['signals'])<=4 and all(type(v) is str and v in {'SIGTERM','SIGKILL','SIGINT','SIGHUP'} for v in value['signals']) and type(value['seconds']) in (int,float) and math.isfinite(value['seconds']) and value['seconds']>=0 and value['error'] is None,'SUPERVISION_GUARD')
 safe_text(canonical(value))
def supervision(value):
 original=pin(canonical(value))
 if value is None:return dict(status='ABSENT',original_pin=original,value=None)
 try:_sup_fields(value);return dict(status='RETAINED',original_pin=original,value=value)
 except Exception:
  known={}
  if type(value) is dict:
   for key in ('exit','reaped','timeout','output_complete','passed'):
    item=value.get(key)
    if key=='exit' and (item is None or type(item) is int and -255<=item<=255) or key!='exit' and type(item) is bool:known[key]=item
  return dict(status='REFUSED',original_pin=original,known=known,reason='SOURCE_SUPERVISION_SCHEMA_OR_PRIVACY_REFUSED')
def meson_tool(report):
 rows=report.get('tools',{});check(type(rows) is dict,'RESULT_GUARD');row=rows.get('meson');kind=status(row.get('status') if type(row) is dict else None,TOOL,'meson' in rows)
 if kind!='PRESENT':return dict(status=kind,path=None,resolved=None,file=None)
 check(row.get('path')=='/usr/bin/meson','COMMAND_GUARD');resolved=str(path(row.get('resolved')));typed_pin(row.get('file'),128*1024**2)
 return dict(status=kind,path='/usr/bin/meson',resolved=resolved,file=row['file'])
def expected_command(step,output,tool):
 check(step in STEPS and tool['status']=='PRESENT','COMMAND_GUARD');base=output/'meson-project';build=base/'build';source=base/'source';prefix=base/'prefix';exe=tool['resolved']
 expected='nonzero' if step in {'meson-broken-build','meson-broken-test','meson-installed-missing-library-control'} else 0
 if step=='version-meson':return [exe,'--version'],str(output),0
 role=STEPS[step][1]
 if role=='MESON_CONFIGURE':argv=[exe,'setup',str(build),str(source),'--backend=ninja','--prefix='+str(prefix),'--libdir=lib','--wrap-mode=nodownload']
 elif role=='MESON_BUILD':argv=[exe,'compile','-C',str(build),'-j','1']
 elif role=='MESON_TEST':argv=[exe,'test','-C',str(build),'--no-rebuild','--verbose','--print-errorlogs']
 elif role=='MESON_INSTALL':argv=[exe,'install','-C',str(build),'--no-rebuild']
 else:argv=[str((prefix/'bin' if role=='INSTALLED_PRODUCT_RUN' else build)/'developer-demo')]
 return argv,str(prefix if role=='INSTALLED_PRODUCT_RUN' else base),expected
def log_window(raw,name):
 context=inspect_privacy(raw,'journey/build-systems/'+name)
 try:safe_text(raw)
 except Exception:return dict(status='REFUSED',reason='SOURCE_LOG_PRIVACY_OR_TEXT_REFUSED',privacy_context=context)
 offset=max(0,len(raw)-WINDOW)
 while offset<len(raw) and raw[offset]&0xc0==0x80:offset+=1
 selected=raw[offset:]
 return dict(status='RETAINED',offset=offset,complete=offset==0,**pin(selected),text=selected.decode('utf-8'))
def selected_record(report,output):
 """Pure deterministic Source selection/normalization; no original body reads."""
 output=path(str(Path(output)));projects=report.get('project_workflows',{});check(type(projects) is dict,'RESULT_GUARD');project=projects.get('meson',{});project=project if type(project) is dict else {}
 missing=project.get('missing',[]);valid=type(missing) is list and all(type(v) is str for v in missing);project_status=status(project.get('status'),PROJECT,'meson' in projects)
 commands=report.get('commands',[]);check(type(commands) is list and len(commands)<=1000 and all(type(row) is dict for row in commands),'COMMAND_GUARD')
 indexes=[i for i,row in enumerate(commands) if type(row.get('step')) is str and (row['step']=='version-meson' or row['step'].startswith('meson-'))]
 tool=meson_tool(report);command=None;stage='ABSENT';role='NO_SOURCE_MESON_COMMAND';failure='BEFORE_MESON_COMMAND_OR_NOT_RUN';step=None
 if indexes:
  index=indexes[-1];row=commands[index];step=row['step'];check(step in STEPS,'COMMAND_GUARD');stage,role=STEPS[step];name='%03d-%s.log'%(index,step)
  keys={'step','argv','cwd','expected','success','log','log_pin','supervision','channels'};check(keys<=set(row)<=keys|{'launch_error'},'COMMAND_GUARD')
  check(row.get('log')==name,'COMMAND_GUARD');typed_pin(row.get('log_pin'),LOG_CAP);argv,cwd,expected=expected_command(step,output,tool)
  check(row.get('argv')==argv and row.get('cwd')==cwd and (type(row.get('expected')) is int and row['expected']==expected if type(expected) is int else row.get('expected')==expected) and type(row.get('success')) is bool and row.get('channels')=='stdout+stderr combined in pipe order','COMMAND_GUARD')
  sup=row.get('supervision');exitcode=sup.get('exit') if type(sup) is dict else None
  if type(exitcode) is not int or not -255<=exitcode<=255:exitcode=None
  command=dict(record_index=index,record_pin=pin(canonical(row)),step=step,argv=argv,cwd=cwd,expected=expected,success=row['success'],exit=exitcode,exit_observed=type(exitcode) is int,supervision=supervision(sup),log=dict(name=name,channel='COMBINED_STDOUT_STDERR',original_pin=row['log_pin']))
  if index!=len(commands)-1:failure='OTHER_SOURCE_STAGE_OR_UNKNOWN'
  elif not row['success']:failure='COMMAND_FAILURE_OR_RETIREMENT_UNKNOWN'
  elif 'error' not in report and project_status=='PASS_REAL_PROJECT_WORKFLOW':failure='NONE_REPORTED'
  else:failure='AFTER_LAST_COMMAND_OR_RECORD_FAILURE_OR_UNKNOWN'
 return dict(aggregate=status(report.get('status'),AGGREGATE,'status' in report),meson_status=project_status,missing={t:bool(valid and t in missing) for t in TOOLS},missing_unknown=not valid or any(v not in TOOLS for v in missing),report_error=report_error(report,step),meson_tool=tool,last_command_stage=stage,last_command_role=role,failure_stage=failure,command=command)
def capture(output,report,map_hash):
 """Observe actual bounded originals; refuses tamper without echoing unknowns."""
 check(type(map_hash) is str and re.fullmatch('[0-9a-f]{64}',map_hash),'MAP_GUARD');evidence=dict(result_pin=None,log_pin=None)
 try:
  output=path(str(Path(output)));raw=_ordinary(output/'result.json',RESULT_CAP);evidence['result_pin']=pin(raw);check(json.loads(raw)==report and type(report) is dict,'RESULT_GUARD');sources=source_pins()
  check(type(report.get('sources')) is dict and report['sources'].get('runner')==PRODUCERS['scripts/workflows/developer_build_systems.py'] and report['sources'].get('helper')==PRODUCERS['scripts/workflows/developer_workflow.py'] and report['sources'].get('owned_process')==PRODUCERS['scripts/virtual/owned_process.py'],'SOURCE_GUARD')
  data=selected_record(report,output);command=data['command']
  if command is not None:
   log=_ordinary(output/command['log']['name'],LOG_CAP);evidence['log_pin']=pin(log);check(evidence['log_pin']==command['log']['original_pin'],'LOG_PIN_GUARD');command['log']['window']=log_window(log,command['log']['name'])
  value=dict(schema=1,status='MESON_STAGE_DIAGNOSTIC_DATA_ONLY',source_map_sha256=map_hash,source_producers=sources,result_pin=evidence['result_pin'],**data,native='NOT_ADMITTED',physical_M2='NOT_RUN')
  validate_summary(value,map_hash);return value
 except Exception as error:
  code=str(error) if isinstance(error,Guard) and str(error) in {'SOURCE_GUARD','RESULT_GUARD','COMMAND_GUARD','LOG_PIN_GUARD'} else 'DIAGNOSTIC_GUARD'
  return dict(schema=1,status='REFUSED_MESON_STAGE_DIAGNOSTIC_DATA',source_map_sha256=map_hash,reason=code,**evidence,native='NOT_ADMITTED',physical_M2='NOT_RUN')
def validate_summary(value,map_hash):
 check(type(map_hash) is str and re.fullmatch('[0-9a-f]{64}',map_hash) and type(value) is dict and type(value.get('schema')) is int and value['schema']==1 and value.get('source_map_sha256')==map_hash and value.get('native')=='NOT_ADMITTED' and value.get('physical_M2')=='NOT_RUN','MAP_GUARD')
 if value.get('status')=='REFUSED_MESON_STAGE_DIAGNOSTIC_DATA':
  check(set(value)=={'schema','status','source_map_sha256','reason','result_pin','log_pin','native','physical_M2'} and value['reason'] in {'SOURCE_GUARD','RESULT_GUARD','COMMAND_GUARD','LOG_PIN_GUARD','DIAGNOSTIC_GUARD'},'SCHEMA_GUARD')
  for name,cap in (('result_pin',RESULT_CAP),('log_pin',LOG_CAP)):
   if value[name] is not None:typed_pin(value[name],cap)
  return True
 keys={'schema','status','source_map_sha256','source_producers','result_pin','aggregate','meson_status','missing','missing_unknown','report_error','meson_tool','last_command_stage','last_command_role','failure_stage','command','native','physical_M2'}
 check(set(value)==keys and value['status']=='MESON_STAGE_DIAGNOSTIC_DATA_ONLY' and value['source_producers']==PRODUCERS and type(value['aggregate']) is str and value['aggregate'] in AGGREGATE and type(value['meson_status']) is str and value['meson_status'] in PROJECT,'SCHEMA_GUARD');typed_pin(value['result_pin'],RESULT_CAP)
 check(type(value['missing']) is dict and set(value['missing'])==set(TOOLS) and all(type(v) is bool for v in value['missing'].values()) and type(value['missing_unknown']) is bool and value['failure_stage'] in FAILURE_STAGES,'SCHEMA_GUARD')
 error=value['report_error'];check(type(error) is dict and set(error)=={'code','field_pin'} and error['code'] in ERRORS,'SCHEMA_GUARD')
 if error['code']=='ABSENT':check(error['field_pin'] is None,'SCHEMA_GUARD')
 else:typed_pin(error['field_pin'],RESULT_CAP)
 tool=value['meson_tool'];check(type(tool) is dict and set(tool)=={'status','path','resolved','file'} and tool['status'] in TOOL,'SCHEMA_GUARD')
 if tool['status']=='PRESENT':check(tool['path']=='/usr/bin/meson','COMMAND_GUARD');path(tool['resolved']);typed_pin(tool['file'],128*1024**2)
 else:check(tool['path'] is tool['resolved'] is tool['file'] is None,'SCHEMA_GUARD')
 command=value['command']
 if command is None:check(value['last_command_stage']=='ABSENT' and value['last_command_role']=='NO_SOURCE_MESON_COMMAND' and value['failure_stage']=='BEFORE_MESON_COMMAND_OR_NOT_RUN','SCHEMA_GUARD')
 else:
  check(type(command) is dict and set(command)=={'record_index','record_pin','step','argv','cwd','expected','success','exit','exit_observed','supervision','log'} and type(command['record_index']) is int and 0<=command['record_index']<1000 and command['step'] in STEPS and (value['last_command_stage'],value['last_command_role'])==STEPS[command['step']] and type(command['success']) is bool and type(command['exit_observed']) is bool and (command['exit'] is None or type(command['exit']) is int and -255<=command['exit']<=255) and command['exit_observed'] is (type(command['exit']) is int),'COMMAND_GUARD');typed_pin(command['record_pin'],RESULT_CAP)
  output=path(command['cwd']) if command['step']=='version-meson' else path(command['cwd']).parent.parent if value['last_command_role']=='INSTALLED_PRODUCT_RUN' else path(command['cwd']).parent
  argv,cwd,expected=expected_command(command['step'],output,tool)
  check(command['argv']==argv and command['cwd']==cwd and (type(command['expected']) is int and command['expected']==expected if type(expected) is int else command['expected']==expected),'COMMAND_GUARD')
  check(value['failure_stage']!='BEFORE_MESON_COMMAND_OR_NOT_RUN','SCHEMA_GUARD')
  if value['failure_stage']=='COMMAND_FAILURE_OR_RETIREMENT_UNKNOWN':check(command['success'] is False,'SCHEMA_GUARD')
  elif value['failure_stage']=='AFTER_LAST_COMMAND_OR_RECORD_FAILURE_OR_UNKNOWN':check(command['success'] is True and not(value['report_error']['code']=='ABSENT' and value['meson_status']=='PASS_REAL_PROJECT_WORKFLOW'),'SCHEMA_GUARD')
  elif value['failure_stage']=='NONE_REPORTED':check(command['success'] is True and value['report_error']['code']=='ABSENT' and value['meson_status']=='PASS_REAL_PROJECT_WORKFLOW','SCHEMA_GUARD')
  sup=command['supervision'];check(type(sup) is dict,'SUPERVISION_GUARD');typed_pin(sup.get('original_pin'),RESULT_CAP)
  if sup.get('status')=='RETAINED':check(set(sup)=={'status','original_pin','value'} and pin(canonical(sup['value']))==sup['original_pin'],'SUPERVISION_GUARD');_sup_fields(sup['value']);check(command['exit']==sup['value']['exit'],'SUPERVISION_GUARD')
  elif sup.get('status')=='ABSENT':check(sup==dict(status='ABSENT',original_pin=pin(canonical(None)),value=None) and command['exit'] is None,'SUPERVISION_GUARD')
  else:
   check(set(sup)=={'status','original_pin','known','reason'} and sup['status']=='REFUSED' and sup['reason']=='SOURCE_SUPERVISION_SCHEMA_OR_PRIVACY_REFUSED' and type(sup['known']) is dict and set(sup['known'])<={'exit','reaped','timeout','output_complete','passed'},'SUPERVISION_GUARD')
   for key,item in sup['known'].items():check(item is None or type(item) is int and -255<=item<=255 if key=='exit' else type(item) is bool,'SUPERVISION_GUARD')
   if 'exit' in sup['known']:check(command['exit']==sup['known']['exit'],'SUPERVISION_GUARD')
  log=command['log'];check(type(log) is dict and set(log)=={'name','channel','original_pin','window'} and log['name']=='%03d-%s.log'%(command['record_index'],command['step']) and log['channel']=='COMBINED_STDOUT_STDERR','LOG_PIN_GUARD');typed_pin(log['original_pin'],LOG_CAP);window=log['window']
  check(type(window) is dict,'WINDOW_GUARD')
  if window.get('status')=='REFUSED':
   check(set(window)=={'status','reason','privacy_context'} and window['reason']=='SOURCE_LOG_PRIVACY_OR_TEXT_REFUSED','WINDOW_GUARD')
   if window['privacy_context'] is not None:validate_context(window['privacy_context'],'journey/build-systems/'+log['name']);check(window['privacy_context']['whole_file']==log['original_pin'],'WINDOW_GUARD')
  else:
   check(set(window)=={'status','offset','complete','bytes','sha256','text'} and window['status']=='RETAINED' and type(window['text']) is str and type(window['offset']) is int and type(window['complete']) is bool,'WINDOW_GUARD');raw=window['text'].encode();safe_text(raw);typed_pin({k:window[k] for k in ('bytes','sha256')},WINDOW);start=max(0,log['original_pin']['bytes']-WINDOW)
   check((window['offset']==0 if start==0 else start<=window['offset']<=start+3) and window['offset']+len(raw)==log['original_pin']['bytes'] and window['complete'] is (window['offset']==0) and pin(raw)=={k:window[k] for k in ('bytes','sha256')} and (not window['complete'] or pin(raw)==log['original_pin']),'WINDOW_GUARD')
 check(len(canonical(value))<=CAP,'DIAGNOSTIC_CAP');safe_text(canonical(value));return True
def emit(output,report,map_hash,write_root,emit_line=print):
 try:value=capture(output,report,map_hash)
 except Exception:value=dict(schema=1,status='REFUSED_MESON_STAGE_DIAGNOSTIC_DATA',source_map_sha256=map_hash,reason='DIAGNOSTIC_GUARD',result_pin=None,log_pin=None,native='NOT_ADMITTED',physical_M2='NOT_RUN')
 try:
  validate_summary(value,map_hash);save(Path(write_root)/'meson-diagnostic.json',value)
  emit_line('NATIVE_MESON_STAGE_DIAGNOSTIC '+json.dumps(value,sort_keys=True,allow_nan=False),flush=True)
 except Exception:pass
 return value

def validate_bound(value,own,map_hash):
 check(type(own) is dict and set(own)=={'source','ref','run','attempt','token'} and type(own['source']) is str and re.fullmatch('[0-9a-f]{40}',own['source']) and type(own['ref']) is str and own['ref'].startswith('refs/heads/codex/') and type(own['run']) is str and re.fullmatch('[1-9][0-9]*',own['run']) and type(own['attempt']) is int and own['attempt']==1 and own['token']==hashlib.sha256((own['source']+':'+own['ref']+':'+own['run']).encode()).hexdigest()[:24],'BOUND_GUARD')
 check(type(value) is dict and set(value)=={'schema','status','binding','source_map_sha256','guest_summary_pin','guest_summary'} and type(value['schema']) is int and value['schema']==1 and value['status']=='BOUND_MESON_STAGE_DIAGNOSTIC_DATA_ONLY' and value['binding']==own and value['source_map_sha256']==map_hash,'BOUND_GUARD')
 typed_pin(value['guest_summary_pin'],CAP);validate_summary(value['guest_summary'],map_hash);return True

def bind(output,own,map_hash):
 output=Path(output)
 try:raw=_ordinary(output/'journey/meson-diagnostic.json',CAP)
 except FileNotFoundError:return None
 summary=json.loads(raw);validate_summary(summary,map_hash)
 value=dict(schema=1,status='BOUND_MESON_STAGE_DIAGNOSTIC_DATA_ONLY',binding=own,source_map_sha256=map_hash,guest_summary_pin=pin(raw),guest_summary=summary)
 validate_bound(value,own,map_hash);save(output/'meson-diagnostic.json',value);return value
