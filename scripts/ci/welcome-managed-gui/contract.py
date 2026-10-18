# SPDX-License-Identifier: MIT
"""Closed event contract for the installed product GUI trial; pixels stay pending."""
import importlib.util
import json
from pathlib import Path
import re
import candidates
import gui_contract as C
import managed_contract as M

verify_source=candidates.verify_source


def verify_result(events,lock):
    managed=M.verify_result(events)
    user=next(e for e in events if e.get('event')=='managed_user_ready')
    session=next(e for e in events if e.get('event')=='session_pass')
    expected_identity={k:user[k] for k in ('address','uid','manager_pid','default_target')}
    C.need(lock['status']=='VERIFIED_NATIVE_CANDIDATES' and lock['eligibility']=='PRIVATE_GUI_TRIAL_ONLY' and
           set(lock['products'])=={'cachy-asahi-welcome','cachy-asahi-doctor'},'verified trial candidates required')
    phases=[];compositor_logs={}
    for stage in ('minimal','overlay'):
        def one(name):
            rows=[e for e in events if e.get('event')==name and e.get('stage')==stage]
            C.need(len(rows)==1,'one installed GUI event required: '+name);return rows[0]
        doctor=one('doctor_result');phase=one('phase_pass');retired=one('welcome_terminal_retired');files_retired=one('welcome_files_retired');phases.append(phase)
        log=one('compositor_log_summary');streams=log.get('streams')
        C.need(log.get('returncode')==0 and type(log.get('returncode')) is int and
               log.get('overflow') is False and log.get('drain_errors')==0 and type(log.get('drain_errors')) is int and
               log.get('drains_complete') is True and type(streams) is list and len(streams)==2,
               'clean bounded compositor logs required')
        for stream,suffix,limit in zip(streams,('stdout','stderr'),(2*1024*1024,256*1024)):
            C.need(stream.get('path')=='/home/desktop574/logs/'+stage+'.'+suffix and
                   type(stream.get('limit_bytes')) is int and stream['limit_bytes']==limit and
                   type(stream.get('observed_bytes')) is int and 0<=stream['observed_bytes']<=limit,
                   'compositor stream identity/budget differs')
        compositor_logs[stage]=log
        frames=[e for e in events if e.get('event')=='frame_ready' and e.get('stage')==stage]
        C.need([e.get('view') for e in frames]==list(C.VIEWS),'seven exact ordered GUI captures required')
        raw=(json.dumps(doctor['proof'],sort_keys=True,indent=2)+'\n').encode()
        C.need(C.sha(raw)==doctor['proof_sha256'],'Doctor proof digest differs')
        pid=frames[0]['doctor_pid'];welcome_pid=frames[0]['welcome_pid'];comp=frames[0]['compositor_pid']
        C.need(type(log.get('pid')) is int and log['pid']==comp and
               events.index(frames[-1])<events.index(log)<events.index(phase),'owned compositor log receipt/order differs')
        proof=doctor['proof'];C.validate_doctor(proof,stage,proof['nonce'],pid)
        indices=[events.index(e) for e in (user,doctor,*frames,phase,session)]
        C.need(indices==sorted(indices),'managed Doctor/GUI/capture order differs')
        for frame in frames:
            view=frame['view'];windows=frame['windows'];action=windows.get('action')
            C.together(list(windows.values()),welcome_pid,pid,view,action['pid'] if action else None)
            C.need(frame['welcome_pid']==welcome_pid and frame['doctor_pid']==pid and frame['compositor_pid']==comp and
                   type(comp) is int and comp>0 and comp not in (pid,welcome_pid) and
                   frame['doctor_proof_sha256']==doctor['proof_sha256'] and frame['managed_identity']==expected_identity and
                   frame['worker']==dict(pid=proof['worker_pid'],parent_pid=pid,uid=23001), 'same managed process/bus/proof join required')
            C.need(type(frame.get('capture_after_ms')) is int and frame['capture_after_ms']>=5000 and
                   frame.get('physical_input')==frame.get('hardware')=='NOT_RUN' and
                   frame.get('producer_lifecycle')==lock['producer_lifecycle'],'capture timing/scope differs')
            semantic=frame['semantic'];summary=semantic['summary']
            C.need(type(summary.get('node_count')) is int and 1<=summary['node_count']<=192 and
                   re.fullmatch('[0-9a-f]{64}',semantic.get('snapshot_sha256','')),'bounded semantic proof required')
            snapshot=semantic['snapshot']
            C.need(C.sha((json.dumps(snapshot,sort_keys=True)+'\n').encode())==semantic['snapshot_sha256'] and
                   C.validate_snapshot(snapshot,welcome_pid,view,semantic.get('expected_text_sha256'))==summary,
                   'retained raw accessibility snapshot/digest/summary differs')
            if view in C.LABELS:
                guide='first-run' if view=='first-steps' else view
                expected=lock['products']['cachy-asahi-welcome']['payload']['usr/share/doc/cachy-asahi-welcome/'+guide+'.txt']['sha256']
                C.need(semantic.get('expected_text_sha256')==expected and C.LABELS[view] in summary['selected_names'] and expected in summary['showing_text_sha256'],
                       'actual selected installed guide proof differs')
            if view=='system':
                C.need(re.fullmatch('[0-9a-f]{64}',semantic.get('expected_text_sha256','')) and
                       semantic['expected_text_sha256'] in summary['showing_text_sha256'],'System refresh/CLI text hash join differs')
        actions=[e for e in events if e.get('event')=='welcome_action' and e.get('stage')==stage]
        C.need([e.get('label') for e in actions]==['Open Terminal','Open Files','System','Refresh system status',
            'Welcome','First steps','Updates','Recovery'],'eight exact GTK actions required')
        for action in actions:
            C.need(action.get('welcome_pid')==welcome_pid and
                   action.get('method')==C.validate_action(action['proof'],welcome_pid,action['label']) and
                   action.get('physical_input')=='NOT_RUN','actual owned GTK action/guide selection proof differs')
        identity=retired.get('identity');opened=frames[1]['action_identity']
        C.need(identity==opened and identity.get('uid')==[23001]*4 and identity.get('executable')=='/usr/bin/alacritty' and
               identity.get('pid')==frames[1]['windows']['action']['pid'] and type(identity.get('starttime')) is int and
               retired.get('absence')=='PIDFD_EXITED' and retired.get('exit_status')=='UNOBSERVED_NONCHILD',
               'stable Welcome-launched terminal retirement/exit qualification required')
        C.need(events.index(frames[1])<events.index(retired)<events.index(frames[2]),'Terminal action retirement order differs')
        C.need(files_retired.get('pid')==frames[2]['windows']['action']['pid'] and files_retired.get('exit_status')==0 and
               files_retired.get('window_absent') is True and
               files_retired.get('location_verification')=='VISUAL_REVIEW_REQUIRED' and
               events.index(frames[2])<events.index(files_retired)<events.index(frames[3]),'owned Files retirement/location qualification differs')
        C.need(phase.get('config_preserved') is True and all(phase.get(k)=='PASS' for k in
            ('welcome_gui','doctor_report','guide_navigation','launch_actions')) and
            phase.get('terminal_action_exit')=='UNOBSERVED_NONCHILD','GUI phase acceptance/limits absent')
    C.need(events.index(phases[0])<events.index(phases[1]),'minimal/overlay order differs')
    C.need(all(session.get(k)=='PASS' for k in ('welcome_gui','doctor_report','guide_navigation','launch_actions')) and
           session.get('managed_session')=='SELECTED_REAL_USER_MANAGER' and session.get('physical_input')=='NOT_RUN',
           'managed GUI session acceptance absent')
    return dict(managed_session=managed,compositor_logs=compositor_logs,producer_lifecycle=lock['producer_lifecycle'],
                GUI='NATIVE_METADATA_PASS_PIXELS_PENDING_REVIEW',hardware='NOT_RUN')
