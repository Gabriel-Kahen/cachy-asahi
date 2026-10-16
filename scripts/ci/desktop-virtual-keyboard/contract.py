# SPDX-License-Identifier: MIT
"""Replay managed ownership plus exact nonce-bound QMP keyboard/event evidence."""
import hashlib
import json
from pathlib import Path
import keyboard as K
import managed_contract as M


def verify_source(source):
    for name,pin in json.loads(Path(__file__).with_name('source-pins.json').read_text()).items():
        path=Path(source)/name
        K.need(path.is_file() and not path.is_symlink() and hashlib.sha256(path.read_bytes()).hexdigest()==pin,'keyboard dependency drift: '+name)


def identity(value,exe):
    K.need(type(value) is dict and type(value.get('pid')) is int and 0<value['pid']<2**32 and
           value.get('uid')==[23001]*4 and value.get('executable')==exe and
           type(value.get('starttime')) is int and value['starttime']>0,'stable process identity absent')


def verify_result(events):
    managed=M.verify_result(events)
    K.need(not any(r.get('event') in ('phase_failed','failure','failed','keyboard_failure_diagnostic') for r in events),'failed keyboard phase')
    def one(name,stage):
        rows=[(i,r) for i,r in enumerate(events) if r.get('event')==name and r.get('stage')==stage]
        K.need(len(rows)==1,'one '+stage+' '+name+' required');return rows[0]
    previous=-1
    for stage in ('minimal','overlay'):
        start,ready=one('keyboard_ready',stage);nonce=ready['nonce'];expected=K.expected(nonce)
        K.need(start>previous,'keyboard phases overlap')
        expected_policy='SHIPPED_UNCHANGED' if stage=='overlay' else 'DECLARED_MINIMAL_SUPER_RETURN_SUPER_Q'
        K.need(ready.get('shortcut_policy')==expected_policy and
               ready.get('kernel_device',{}).get('name')=='QEMU Virtio Keyboard' and
               ready['kernel_device'].get('driver')=='virtio_input','virtual input/shortcut policy absent')
        K.verify_startup(ready.get('startup_windows'))
        keyboards=ready.get('keyboards')
        K.verify_keyboards(keyboards,ready.get('board_device'))
        if stage=='overlay':
            pins=json.loads(Path(__file__).with_name('source-pins.json').read_text())
            K.need(ready.get('configuration_sha256')==pins['packages/desktop/cachy-asahi-hyprland-settings/hyprland.lua'],'shipped overlay configuration bytes changed')
        terminal_at,joined=one('keyboard_terminal',stage)
        terminal=joined['terminal'];shell=joined['shell'];identity(terminal,'/usr/bin/alacritty');identity(shell,'/usr/bin/bash')
        K.need(joined['nonce']==nonce and shell.get('parent_pid')==terminal['pid'] and
               str(shell.get('pty','')).startswith('/dev/pts/'),'terminal shell/PTY identity absent')
        last=start;steps={}
        for step in K.STEPS:
            req=[(i,r) for i,r in enumerate(events) if r.get('event')=='keyboard_request' and r.get('stage')==stage and r.get('step')==step]
            sent=[(i,r) for i,r in enumerate(events) if r.get('event')=='qmp_keyboard_input' and r.get('stage')==stage and r.get('step')==step]
            K.need(len(req)==len(sent)==1,'one request/send for '+step+' required')
            i,request=req[0];j,receipt=sent[0];plan=K.plan(stage,nonce,step);digest=K.sha(K.encoded(plan))
            K.need(last<i<j and request.get('nonce')==receipt.get('nonce')==nonce and
                   request.get('plan_sha256')==receipt.get('plan_sha256')==digest and
                   receipt.get('chords')==len(plan) and receipt.get('qmp_calls')==len(plan) and receipt.get('key_events')==sum(2*len(c) for c in plan) and
                   receipt.get('delivery_policy')==K.DELIVERY_POLICY and receipt.get('all_keys_released') is True and receipt.get('route')=='input-send-event/virtio-keyboard-pci',
                   'keyboard plan/order/receipt differs')
            steps[step]=(i,j);last=j
        K.need(steps['launch'][1]<terminal_at<steps['workspace'][0] and
               type(joined.get('initial_settle_ms')) is int and joined['initial_settle_ms']>=K.DELIVERY_POLICY['initial_settle_ms'],
               'terminal shortcut ownership/initial settle differs')
        workspace_at,workspace=one('keyboard_workspace',stage)
        K.need(steps['workspace'][1]<workspace_at<steps['shell'][0] and workspace.get('nonce')==nonce and
               workspace.get('shell')==shell and workspace.get('method')=='passive-proc-cwd' and
               workspace.get('cwd')==dict(status='READ',path='/home/desktop574/keyboard-'+stage+'-'+nonce),
               'typed workspace cd/independent cwd proof differs')
        frame_positions={}
        for view in K.VIEWS:
            index,row=one('frame_ready',stage+'-'+view);frame_positions[view]=index
            K.need(row.get('phase')==stage and row.get('view')==view and row.get('nonce')==nonce and
                   row.get('terminal_identity')==terminal and row.get('capture_after_ms',0)>=5000 and
                   row.get('physical_input')==row.get('hardware')=='NOT_RUN','frame identity/scope absent')
            window=row.get('terminal',{})
            K.need(window.get('pid')==terminal['pid'] and window.get('class') in ('Alacritty','alacritty') and
                   window.get('mapped') is True and window.get('visible') is True and window.get('hidden') is False and
                   window.get('xwayland') is False and window.get('focusHistoryID')==0,'visible focused terminal absent')
            bus=row.get('managed_bus',{})
            root=next(r for r in events if r.get('event')=='managed_session_ready')
            K.need(bus.get('manager_pid')==root['manager_pid'] and bus.get('uid')==23001 and
                   bus.get('address')==M_ADDRESS and bus.get('default_target')=='GetUnit-PASS','frame managed bus changed')
            proof=row['proof'];K.need(proof.get('shell')==shell,'shell identity changed')
            files=proof.get('files',[proof.get('file')])
            wanted=['shell.txt'] if view=='shell' else ['edit.txt'] if view=='editor' else list(expected)
            K.need(type(files) is list and len(files)==len(wanted),'keyboard result file count differs')
            for value,name in zip(files,wanted):
                K.need(value==dict(name=name,bytes=len(expected[name]),sha256=K.sha(expected[name])),'typed file content differs')
            if view=='editor':
                identity(proof['editor'],'/usr/bin/vim')
                K.need(proof['editor'].get('parent_pid')==shell['pid'],'interactive editor parent differs')
        K.need(steps['shell'][1]<frame_positions['shell']<steps['editor-open'][0] and
               steps['editor-save'][1]<frame_positions['editor']<steps['editor-quit'][0] and
               steps['result'][1]<frame_positions['result']<steps['close'][0],'capture/input order differs')
        editor_closed_at,editor_closed=one('keyboard_editor_closed',stage)
        editor_frame=next(r for r in events if r.get('event')=='frame_ready' and r.get('stage')==stage+'-editor')
        K.need(steps['editor-quit'][1]<editor_closed_at<steps['result'][0] and editor_closed.get('nonce')==nonce and
               editor_closed.get('editor')==editor_frame['proof']['editor'] and editor_closed.get('pidfd_exited') is True and
               editor_closed.get('exit')=='UNOBSERVED_NONCHILD','Vim keyboard quit/retirement absent')
        closed_at,closed=one('keyboard_closed',stage);passed_at,passed=one('phase_pass',stage)
        K.need(steps['close'][1]<closed_at<passed_at and closed.get('terminal')==terminal and closed.get('nonce')==nonce
               and closed.get('exit')=='UNOBSERVED_NONCHILD' and closed.get('pidfd_exited') is True
               and closed.get('shell')==shell and closed.get('shell_pidfd_exited') is True
               and closed.get('window_absent') is True and closed.get('method')=='SUPER_Q_QMP'
               and passed.get('nonce')==nonce and passed.get('configuration_preserved') is True,'keyboard close/preservation failed')
        exits=[r for r in events[closed_at:passed_at] if r.get('event')=='process_exit' and r.get('name')==stage]
        K.need(len(exits)==1 and exits[0].get('returncode')==0,'compositor retirement failed')
        log_at,log=one('compositor_log_summary',stage)
        K.need(closed_at<log_at<passed_at and type(log.get('pid')) is int and
               log['pid']==ready['startup_windows']['compositor']['pid'] and
               type(log.get('returncode')) is int and log['returncode']==0 and
               log.get('overflow') is False and type(log.get('drain_errors')) is int and
               log['drain_errors']==0 and log.get('drains_complete') is True,
               'clean owned compositor log receipt required')
        streams=log.get('streams')
        K.need(type(streams) is list and len(streams)==2,'two compositor log streams required')
        for stream,suffix,limit in zip(streams,('stdout','stderr'),(2*1024*1024,256*1024)):
            K.need(stream.get('path')=='/home/desktop574/logs/'+stage+'.'+suffix and
                   type(stream.get('limit_bytes')) is int and stream['limit_bytes']==limit and
                   type(stream.get('observed_bytes')) is int and 0<=stream['observed_bytes']<=limit,
                   'compositor log stream identity/bound differs')
        previous=passed_at
    K.need(len([r for r in events if r.get('event')=='keyboard_request'])==18 and
           len([r for r in events if r.get('event')=='qmp_keyboard_input'])==18 and
           len([r for r in events if r.get('event')=='frame_ready'])==6,'extra keyboard requests/captures refused')
    for name in ('session_pass','complete'):
        r=next(r for r in events if r.get('event')==name)
        K.need(r.get('virtual_keyboard')=='PASS' and r.get('editor_ui')=='PASS_QMP_TYPED_VIM' and
               r.get('physical_input')==r.get('hardware')=='NOT_RUN','scope qualification absent')
    return dict(status='PASS_KEYBOARD_ROUTE_METADATA_PIXELS_PENDING_REVIEW',managed_session=managed,
                physical_input='NOT_RUN',hardware='NOT_RUN',visual_review='NOT_RUN',frames=6)


M_ADDRESS='unix:path=/run/user/23001/bus'
