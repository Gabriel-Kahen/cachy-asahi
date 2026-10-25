# SPDX-License-Identifier: MIT
"""Actual optional-tool absence, reports, refusal and close during an owned real check."""
import base64
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import time
from types import SimpleNamespace
import management_contract as C

SEQUENCE=0
CHANNEL=Path('/home/desktop574/management-channel')


def request(operation,**fields):
    global SEQUENCE
    nonce=C.read(CHANNEL/'nonce',64,0).decode();number=SEQUENCE;SEQUENCE+=1
    payload=dict(nonce=nonce,sequence=number,operation=operation,**fields);path=CHANNEL/('request-'+str(number)+'.json');pending=path.with_suffix('.pending')
    with pending.open('xb') as stream:stream.write(C.encoded(payload));stream.flush();os.fsync(stream.fileno())
    pending.chmod(0o600);C.need(not path.exists(),'fresh fixture request required');pending.rename(path);reply=CHANNEL/('reply-'+str(number)+'.json');until=time.monotonic()+90
    while not reply.exists():C.need(time.monotonic()<until,'owned fixture reply deadline');time.sleep(.01)
    value=json.loads(C.read(reply,65536,0));C.need(value.get('nonce')==nonce and value.get('sequence')==number and value.get('status')=='PASS','owned root fixture result differs');return value



def closing_retirement(wait,pending,closing,inventory):
    def retired():
        value=request('retired')
        # Keep the last raw reply even when the unchanged fast wait refuses it.
        pending['retirement_observation']=value
        return value if C.retirement_reply(value,closing,'retired') else None
    fast=wait(retired,lambda:None,10,'owned management group retirement')
    pending['phase']='retirement-preservation-proof'
    proof=request('retired-proof');pending['retirement_proof']=proof
    C.retirement_proof(fast,proof,closing,inventory)
    return fast,proof


def report_command(base,tool,path,env,expected=0):
    argv=['/usr/bin/cachy-asahi-doctor','--json'] if tool=='doctor' else (['/usr/bin/cachy-asahi-dns','--json','profiles'] if tool=='dns' else ['/usr/bin/cachy-asahi-orphans','assess'])
    error_path=path.with_suffix('.stderr');process=None
    with path.open('xb') as out,error_path.open('xb') as err:
        path.chmod(0o600);error_path.chmod(0o600)
        process=subprocess.Popen(argv,env=env,stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True,close_fds=True)
        until=time.monotonic()+40
        try:
            while process.poll() is None:
                C.need(time.monotonic()<until and path.stat().st_size<=C.REPORT_CAP and error_path.stat().st_size<=65536,'actual independent helper report bound/deadline');time.sleep(.02)
            C.need(process.returncode==expected,'actual independent helper return code differs')
        finally:base.terminate(process)
    raw=C.read(path);C.need(not C.read(error_path,65536),'unexpected helper stderr');return raw


def completed_report_state(remember=None):
    # Even an accessibility action traverses the GTK tree. Observe only owned
    # pidfds until both processes retire; never compete with the live helper.
    state=request('observed')
    for key in ('helper_absent','supervisor_absent'):
        C.need(type(state.get(key)) is bool,'owned helper completion state absent')
    observed={k:state[k] for k in ('helper_absent','supervisor_absent')}
    if 'gui_progress' in state:
        value=state['gui_progress']
        if type(value) is dict and value.get('schema_version')==1 and len(C.encoded(value))<=16384:
            observed['gui_progress']=value
        else:observed['gui_progress']=dict(status='UNAVAILABLE_OR_REFUSED')
    if remember is not None:remember(observed)
    return state['helper_absent'] and state['supervisor_absent']


def completed_report_snapshot(a11y,remember=None):
    if not completed_report_state(remember):return None
    return a11y('snapshot')


def remaining(until):
    seconds=until-time.monotonic()
    C.need(seconds>0,'actual management report shared45s deadline')
    return seconds


def wait_before_report(wait,healthy,remember=None):
    until=time.monotonic()+45
    wait(lambda:True if completed_report_state(remember) else None,healthy,remaining(until),'actual owned management completion')
    return until


def open_completed_report(wait,healthy,activate,scope,remember=None):
    until=wait_before_report(wait,healthy,remember)
    activate('View report',scope=scope)
    remaining(until)
    return until


def product_timeout(snapshot,pid):
    C.need(snapshot.get('pid')==pid,'owned failure snapshot PID differs')
    return any(row['showing'] and text and text.startswith('Check stopped: time limit reached.')
               for _,row,text in C.names(snapshot))


def retain_failure(base,stage,pending,snapshot,error):
    """Failure-only original operands; never a substitute for a completed result."""
    value=dict(stage=stage,status='FAIL',error_type=type(error).__name__,reason=str(error)[:512],
               counterpart=pending,hardware='NOT_RUN',physical_input='NOT_RUN',acceptance='NOT_ISSUED')
    if snapshot is not None:
        raw=C.encoded(snapshot);C.need(len(raw)<=C.REPORT_CAP,'failure snapshot byte bound')
        value.update(snapshot=snapshot,snapshot_bytes=len(raw),snapshot_sha256=C.sha(raw))
    C.need(len(C.encoded(value))<=C.REPORT_CAP,'failure diagnostic byte bound')
    base.emit('management_failure',**value)


def exercise(base,stage,env,logs,workspace,old_welcome,doctor,policy,lock,hooks):
    base.guard(False);C.need(os.getuid()==os.geteuid()==23001 and not os.access('/var/lib/pacman',os.W_OK),'ordinary caller must lack database write/lock access')
    ui=C.interface(policy);reports={};current=old_welcome;closed=None;action_sequence=0
    pending=None;last_snapshot=None
    def completion(state):
        if pending is not None:pending['gui_completion']=state
    M=SimpleNamespace(**runpy.run_path('/usr/bin/cachy-asahi-orphans',run_name='independent_snapshot'))
    def stable():
        value=M.database_snapshot(Path('/var/lib/pacman'))[0]
        C.need(all(row['uid']==0 and not row['mode']&0o022 for row in value['nodes'].values()),'actual root-owned nonwritable metadata required')
        return value
    def healthy():hooks['healthy']()
    def a11y(operation,label=None,scope=None):return hooks['a11y'](operation,label,scope=scope)
    def action(label,scope=None,scroll=False):
        nonlocal action_sequence
        value=a11y('scroll' if scroll else 'activate',label,scope)
        window=hooks['window'](current.process.pid) if scroll else None
        if scroll:C.visible_control(value,current.process.pid,label,window,report_scope=scope)
        else:C.need(value.get('actions')==1 and value.get('action_name') in ('click','activate','press','switch'),'actual management action failed')
        action_sequence+=1
        base.emit('management_action',stage=stage,sequence=action_sequence,pid=current.process.pid,label=label,scope=scope,scroll=scroll,proof=value,window=window,physical_input='NOT_RUN')
    def page(view,expected,deadline=None):
        def probe():
            nonlocal last_snapshot
            value=completed_report_snapshot(a11y,completion) if view in ('management-doctor','management-orphans','management-failure') else a11y('snapshot')
            if value is None:return None
            try:summary=C.snapshot(value,current.process.pid,view,expected)
            except ValueError:
                if product_timeout(value,current.process.pid):
                    last_snapshot=value
                    raise ValueError('actual '+view+' reached original product30s command limit')
                return None
            last_snapshot=value
            return dict(snapshot=value,snapshot_sha256=C.sha(C.encoded(value)),summary=summary,expected=expected)
        return hooks['wait'](probe,healthy,45 if deadline is None else remaining(deadline),'actual '+view)
    def capture(view,expected,deadline=None):
        proof=page(view,expected,deadline)
        if deadline is not None:remaining(deadline)
        hooks['capture'](view,proof)
        if deadline is not None:remaining(deadline)
    def close(actor,finish=True):
        target='address:'+hooks['window'](actor.process.pid)['address']
        C.need(hooks['command'](['/usr/bin/hyprctl','dispatch',f'hl.dsp.window.close({{window="{target}"}})'],'management-close').strip()=='ok','actual Welcome close failed')
        actor.process.wait(timeout=15);C.need(actor.process.returncode==0,'Welcome management close exit differs');hooks['adopt'](None)
        if finish:actor.finish()
    def start():
        actor=base.Logged(['/usr/bin/cachy-asahi-welcome'],stage+'-management-welcome-'+str(SEQUENCE),logs,env)
        hooks['adopt'](actor);hooks['place'](actor.process.pid,'welcome',initial=True)
        hooks['wait'](lambda:hooks['a11y']('snapshot',pending=True),hooks['healthy'],45,'actual owned Welcome accessibility')
        return actor
    def observed(tool,stop=False):
        request('arm',tool=tool,welcome_pid=current.process.pid,stop=stop);action(ui['labels'][tool])
        def probe():
            row=request('observed')['process']
            return row if row is not None else None
        result=hooks['wait'](probe,healthy,20,'original default '+tool+' process')
        C.process(result,tool,current.process.pid,stop);return result
    try:
        close(old_welcome);missing=request('remove');C.need(len(missing['inventory'])==604,'optional tools not actually removed')
        current=start();action(ui['labels']['management']);action(ui['labels']['orphans'],scroll=True)
        capture('management-absent',dict(text=[ui['strings']['unavailable']],buttons={ui['labels']['doctor']:False,ui['labels']['orphans']:False}))
        close(current);restored=request('restore');inventory=restored['inventory'];C.need(len(inventory)==606,'exact optional helper profile not restored')
        current=start();action(ui['labels']['management'])
        for kind in ('doctor','orphans','failure'):
            pending=dict(kind=kind,phase='before-counterpart');last_snapshot=None
            before=stable()
            if kind=='failure':request('lock')
            started=time.monotonic_ns()
            raw=report_command(base,kind,workspace/(kind+'-actual.json'),env,1 if kind=='failure' else 0)
            elapsed=time.monotonic_ns()-started
            pending.update(phase='counterpart-completed-before-GUI',counterpart_elapsed_ns=elapsed,expected_returncode=1 if kind=='failure' else 0,
                base64=base64.b64encode(raw).decode(),bytes=len(raw),sha256=C.sha(raw))
            data,summary=C.report(raw,kind,inventory);C.need(len(raw)<=ui['max_output_bytes'],'actual report exceeds product bound; no limit waiver')
            tool='doctor' if kind=='doctor' else 'orphans';action(ui['labels'][tool],scroll=True)
            child=observed(tool);pending['gui_process']=child
            # The expander action also walks the complete GTK tree. Keep it
            # after owned process retirement, within one shared readiness budget.
            report_until=open_completed_report(hooks['wait'],healthy,action,
                'Doctor' if tool=='doctor' else 'Orphan assessment',completion)
            if kind=='failure':
                remaining(report_until)
                action('View report',scope='Orphan assessment',scroll=True)
                remaining(report_until)
            gui_report=None
            if kind=='doctor':
                # Doctor includes collected_utc and live service observations. Retain its actual GTK report,
                # then derive its own conclusion; the independent actual run remains separate evidence.
                def actual_doctor():
                    nonlocal last_snapshot
                    snap=completed_report_snapshot(a11y,completion);matches=[]
                    if snap is None:return None
                    if product_timeout(snap,current.process.pid):
                        last_snapshot=snap
                        raise ValueError('actual management-doctor reached original product30s command limit')
                    for _,row,text in C.names(snap):
                        if row['showing'] and text and text.startswith('{'):
                            try:value,conclusion=C.report(text.encode(),'doctor',inventory)
                            except (ValueError,KeyError,TypeError):continue
                            matches.append((text,conclusion))
                    return matches[0] if len(matches)==1 else None
                preview,summary=hooks['wait'](actual_doctor,healthy,remaining(report_until),'actual GTK Doctor report')
                gui_raw=preview.encode();gui_report=dict(base64=base64.b64encode(gui_raw).decode(),sha256=C.sha(gui_raw),bytes=len(gui_raw))
            else:preview=C.preview(raw,ui,kind)
            expected=dict(text=[ui['strings']['failure' if kind=='failure' else 'complete'],summary,preview],buttons={ui['labels'][tool]:True})
            capture('management-'+kind,expected,report_until)
            reports[kind]=dict(gui_report=gui_report,base64=base64.b64encode(raw).decode(),sha256=C.sha(raw),bytes=len(raw),gui_process=child,metadata_only=True)
            action('View report',scope='Doctor' if tool=='doctor' else 'Orphan assessment')
            if kind=='failure':
                request('unlock');after=stable()
                C.need({n:r for n,r in before['nodes'].items() if n!='.'}=={n:r for n,r in after['nodes'].items() if n!='.'},'held-lock case changed nonlock metadata')
            else:C.need(stable()==before and not Path('/var/lib/pacman/db.lck').exists(),'actual management/independent commands changed metadata or created lock')
        import dns_phase
        dns_phase.exercise(base,stage,env,workspace,current,hooks,request,stable,C)
        import welcome8_stop
        welcome8_stop.exercise(base,stage,current,inventory,hooks,request,stable)
        closing_before=stable();action(ui['labels']['orphans'],scroll=True);closing=observed('orphans',True)
        pending=dict(kind='closing',phase='before-GUI-close',gui_process=closing)
        last_snapshot=None
        capture('management-closing',dict(text=[ui['strings']['running']],buttons={ui['labels']['orphans']:False}))
        close(current,False);closed=current
        pending.update(phase='welcome-close-returned',welcome_exit=closed.process.returncode)
        retirement,proof=closing_retirement(hooks['wait'],pending,closing,inventory)
        C.need(stable()==closing_before and not Path('/var/lib/pacman/db.lck').exists(),'closing check changed metadata or created lock')
        base.emit('management_result',stage=stage,reports=reports,closing_process=closing,welcome_exit=closed.process.returncode,
            retirement_observation=retirement,retirement_proof=proof,
            owned_group_absent=True,owned_helper_absent=True,owned_supervisor_absent=True,metadata_readonly=True,
            nonselected_database='PRESERVED',inventory=inventory,present_count=606,absent_count=604,
            scope='CURRENT606_GENERIC16K_UNPRIVILEGED_ACTUAL_DEFAULT_TOOLS',hardware='NOT_RUN')
        return closed
    except BaseException as error:
        try:retain_failure(base,stage,pending,last_snapshot,error)
        except BaseException as diagnostic:
            try:base.emit('management_failure_diagnostic_unavailable',stage=stage,error_type=type(diagnostic).__name__,acceptance='NOT_ISSUED')
            except BaseException:pass # Reporting cannot mask the original failure or skip teardown.
        raise
    finally:
        if closed is None and current is not None:
            base.terminate(current.process);current.finish();hooks['adopt'](None)
