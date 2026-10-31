# SPDX-License-Identifier: MIT
"""Installed Welcome8 Stop + actual Doctor2 retry, inside the original owned VM."""
import base64
import time
import management_contract as C
VIEWS=('welcome8-stopped','welcome8-retry')
STOP='Stop check';RUN='Run Doctor';SCOPE='Doctor'

def doctor_report(raw,inventory):
 value,summary=C.report(raw,'doctor',inventory);C.need(value['version']=='0.2.0','actual installed Doctor2 report version');return value,summary

def snapshot(value,pid,view,expected):
 C.need(view in VIEWS,'fixed Welcome8 view')
 summary=C.snapshot(value,pid,'management-doctor'if view==VIEWS[1]else'management-closing',expected)
 buttons=[r for name,r,_ in C.names(value)if name==STOP and r['role']==43]
 C.need(len(buttons)==4 and all(r['enabled']is False and r['sensitive']is False for r in buttons),'all four Stop controls idle after owned retirement')
 return dict(original=summary,stop_buttons=4,active_stop_buttons=0)

def active(value,pid):
 C.snapshot(value,pid,'management-closing',dict(text=['Running check…'],buttons={RUN:False}))
 buttons=[r for name,r,_ in C.names(value)if name==STOP and r['role']==43]
 C.need(len(buttons)==4 and sum(r['enabled']is True and r['sensitive']is True for r in buttons)==1 and all(r['enabled']is r['sensitive']for r in buttons),'only live Doctor Stop control enabled')
 return value

def exercise(base,stage,current,inventory,hooks,request,stable):
 """No command replacement or fabricated report: stop the exact installed child."""
 pid=current.process.pid;before=stable();actions=[]
 def action(label,scope=None,scroll=False):
  value=hooks['a11y']('scroll'if scroll else'activate',label,scope=scope);row=dict(pid=pid,label=label,scope=scope,scroll=scroll,proof=value,window=hooks['window'](pid)if scroll else None,physical_input='NOT_RUN');C.action(row,pid,label,scope,scroll);actions.append(row);base.emit('welcome8_action',stage=stage,sequence=len(actions),**row)
 def observed(stopped):
  request('arm',tool='doctor',welcome_pid=pid,stop=stopped);action(RUN)
  def sample():
   row=request('observed')['process'];return row if row is not None else None
  row=hooks['wait'](sample,hooks['healthy'],20,'actual installed Welcome8 Doctor2 owned child');C.process(row,'doctor',pid,stopped);return row
 def retire(child):
  import management_phase as G
  pending={};return G.closing_retirement(hooks['wait'],pending,child,inventory)
 def capture(view,expected):
  def sample():
   value=hooks['a11y']('snapshot')
   try:summary=snapshot(value,pid,view,expected)
   except ValueError:return None
   return dict(snapshot=value,snapshot_sha256=C.sha(C.encoded(value)),summary=summary,expected=expected)
  semantic=hooks['wait'](sample,hooks['healthy'],45,'actual installed Welcome8 '+view);hooks['capture'](view,semantic);return semantic
 action(RUN,scroll=True)
 child=observed(True)
 # The existing privileged fixture SIGSTOPs only this held actual child's pidfd.
 # GTK and supervisor remain live; no synthetic helper or report is substituted.
 def running():
  value=hooks['a11y']('snapshot')
  try:return active(value,pid)
  except ValueError:return None
 running_snapshot=hooks['wait'](running,hooks['healthy'],20,'installed Stop enabled during actual owned check')
 action(STOP,SCOPE);fast,proof=retire(child)
 stopped=capture(VIEWS[0],dict(text=['Check cancelled.','The command was cancelled and its processes were retired.'],buttons={RUN:True}))
 C.need(stable()==before,'Stop changed original readonly package metadata')
 retry=observed(False);C.need((retry['pid'],retry['starttime'])!=(child['pid'],child['starttime']),'fresh retry child identity')
 import management_phase as G
 retry_until=G.wait_before_report(hooks['wait'],hooks['healthy']);fast2,proof2=retire(retry);action('View report',SCOPE)
 def report():
  value=hooks['a11y']('snapshot');found=[]
  for _,row,text in C.names(value):
   if row['showing']and text and text.startswith('{'):
    try:_,summary=doctor_report(text.encode(),inventory)
    except (ValueError,KeyError,TypeError):continue
    found.append((text,summary))
  return found[0]if len(found)==1 else None
 raw,summary=hooks['wait'](report,hooks['healthy'],G.remaining(retry_until),'actual installed Doctor2 retry report');raw=raw.encode();C.need(len(raw)<=65536,'entire actual Doctor2 report fits original preview')
 retried=capture(VIEWS[1],dict(text=['Elapsed:',summary,raw.decode()],buttons={RUN:True}));G.remaining(retry_until);action('View report',SCOPE);C.need(stable()==before,'actual retry changed original readonly package metadata')
 base.emit('welcome8_stop_result',stage=stage,status='PASS_INSTALLED_WELCOME8_STOP_AND_ACTUAL_DOCTOR2_RETRY_PENDING_ROOT',welcome_pid=pid,stopped_process=child,running_snapshot=running_snapshot,retirement_observation=fast,retirement_proof=proof,retry_process=retry,retry_retirement_observation=fast2,retry_retirement_proof=proof2,report=dict(base64=base64.b64encode(raw).decode(),bytes=len(raw),sha256=C.sha(raw)),inventory=inventory,metadata_readonly=True,scope='ACTUAL_INSTALLED_HELPER_WITH_SOURCE_OWNED_PIDFD_SIGSTOP_NO_SYNTHETIC_REPORT',hardware='NOT_RUN')

def validate(events,lock,G):
 rows=[e for e in events if e.get('event')=='welcome8_stop_result'];C.need(len(rows)==1,'one actual installed Stop/retry result');r=rows[0];stage=lock['profile'];pid=r['welcome_pid'];C.need(r['status']=='PASS_INSTALLED_WELCOME8_STOP_AND_ACTUAL_DOCTOR2_RETRY_PENDING_ROOT'and r['stage']==stage and r['metadata_readonly']is True and r['scope']=='ACTUAL_INSTALLED_HELPER_WITH_SOURCE_OWNED_PIDFD_SIGSTOP_NO_SYNTHETIC_REPORT'and r['hardware']=='NOT_RUN','exact installed Stop/retry scope')
 C.need(lock['products']['cachy-asahi-welcome']['version']=='0.1.0-8'and lock['products']['cachy-asahi-doctor']['version']=='0.2.0-1','actual Welcome8/Doctor2 input identities')
 original=next(e for e in events if e.get('event')=='management_result');C.need(r['inventory']==original['inventory']and len(r['inventory'])==606,'entire same606 readonly inventory')
 C.process(r['stopped_process'],'doctor',pid,True);C.process(r['retry_process'],'doctor',pid,False);C.need((r['stopped_process']['pid'],r['stopped_process']['starttime'])!=(r['retry_process']['pid'],r['retry_process']['starttime']),'fresh retry identity')
 C.retirement_proof(r['retirement_observation'],r['retirement_proof'],r['stopped_process'],r['inventory']);C.retirement_proof(r['retry_retirement_observation'],r['retry_retirement_proof'],r['retry_process'],r['inventory']);active(r['running_snapshot'],pid)
 raw=base64.b64decode(r['report']['base64'],validate=True);C.need(len(raw)==r['report']['bytes']<=65536 and C.sha(raw)==r['report']['sha256'],'entire real retry report bytes');_,summary=doctor_report(raw,r['inventory'])
 frames=[e for e in events if e.get('event')=='frame_ready'and e.get('view')in VIEWS];C.need([e['view']for e in frames]==list(VIEWS),'both new ordered original-style firstframes')
 wanted=[dict(text=['Check cancelled.','The command was cancelled and its processes were retired.'],buttons={RUN:True}),dict(text=['Elapsed:',summary,raw.decode()],buttons={RUN:True})]
 reference=next(e for e in events if e.get('event')=='frame_ready'and e.get('view')=='management-dns')
 for f,expected in zip(frames,wanted):
  s=f['semantic'];C.need(f['welcome_pid']==pid and f['stage']==stage and s['expected']==expected and C.sha(C.encoded(s['snapshot']))==s['snapshot_sha256']and snapshot(s['snapshot'],pid,f['view'],expected)==s['summary'],'raw actual Stop/retry accessibility and report join');C.need(f['capture_after_ms']>=5000 and f['physical_input']==f['hardware']=='NOT_RUN','original firstframe delay/scope');G.together(list(f['windows'].values()),pid,f['doctor_pid'],f['view']);C.need(all(f[k]==reference[k]for k in('welcome_pid','doctor_pid','worker','compositor_pid','managed_identity','doctor_proof_sha256','producer_lifecycle')),'same owned visible window/Doctor/bus/source epoch')
 actions=[e for e in events if e.get('event')=='welcome8_action'];plan=[(RUN,None,True),(RUN,None,False),(STOP,SCOPE,False),(RUN,None,False),('View report',SCOPE,False),('View report',SCOPE,False)];C.need(len(actions)==len(plan),'exact Stop and retry accessibility actions')
 for i,(a,(label,scope,scroll))in enumerate(zip(actions,plan)):
  C.need(a['sequence']==i+1 and a['stage']==stage,'ordered sameprofile Stop/retry action');C.action(a,pid,label,scope,scroll)
 closing=next(e for e in events if e.get('event')=='frame_ready'and e.get('view')=='management-closing');order=[reference,actions[0],actions[1],actions[2],frames[0],actions[3],actions[4],frames[1],actions[5],r,closing];C.need(all(events.index(a)<events.index(b)for a,b in zip(order,order[1:])),'Stop, retirement, actual retry and closing order')
 return dict(status='PASS_INSTALLED_WELCOME8_STOP_RETIRED_AND_REAL_DOCTOR2_RETRY_METADATA_ONLY',report_sha256=C.sha(raw),views=list(VIEWS),native_visual_review='REQUIRED',hardware='NOT_RUN')
