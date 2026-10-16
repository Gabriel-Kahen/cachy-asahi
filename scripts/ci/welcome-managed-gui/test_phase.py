"""Full fixed GUI phase with mocked native actors and real bounded fixture files."""
import copy
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import session as S
from test_gui import ROOT, ASSETS, doctor, node
import candidates
import contract


class Process:
    def __init__(self,pid,code=None):self.pid,self.returncode=pid,code
    def poll(self):return self.returncode
    def wait(self,timeout):
        if self.returncode is None:raise AssertionError('fixture process not retired')
        return self.returncode


def unit(name,active='inactive',sub='dead',pid=0):
    return dict(Id=name,LoadState='loaded',ActiveState=active,SubState=sub,Result='success',MainPID=pid,ExecMainCode=0,ExecMainStatus=0)


def managed_events(first):
    second=copy.deepcopy(first);result=next(e for e in second if e['event']=='doctor_result');result['proof']['stage']='overlay'
    result['proof_sha256']=S.C.sha((json.dumps(result['proof'],sort_keys=True,indent=2)+'\n').encode())
    for event in second:
        event['stage']='overlay'
        if event['event']=='frame_ready':event['doctor_proof_sha256']=result['proof_sha256']
        if event['event']=='compositor_log_summary':
            for stream in event['streams']:stream['path']=stream['path'].replace('/minimal.','/overlay.')
    identity=dict(address='unix:path=/run/user/23001/bus',uid=23001,manager_pid=422,default_target='GetUnit-PASS')
    states={'systemd-user-sessions.service':unit('systemd-user-sessions.service','active','exited'),
        'user-runtime-dir@23001.service':unit('user-runtime-dir@23001.service','active','exited'),
        'user@23001.service':unit('user@23001.service','active','running',422)}
    return [dict(event='managed_session_ready',status='PASS',units=states,**identity),
        dict(event='managed_user_ready',status='PASS',**identity)]+first+second+[
        dict(event='session_pass',status='PASS',welcome_gui='PASS',doctor_report='PASS',guide_navigation='PASS',launch_actions='PASS',
            managed_session='SELECTED_REAL_USER_MANAGER',physical_input='NOT_RUN'),
        dict(event='managed_session_cleanup',status='PASS',units=['user@23001.service','user-runtime-dir@23001.service'],
            unit_states={name:unit(name) for name in ('user@23001.service','user-runtime-dir@23001.service')},
            runtime_absent=True,owned_units_stopped=True),dict(event='complete',status='PASS')]


class AccessibilityResult(unittest.TestCase):
    def test_actual_nonzero_empty_stdout_retains_command_and_stderr(self):
        stderr=b'Welcome accessibility failure: one showing control required: contract refused\n'
        with self.assertRaisesRegex(ValueError,'activate System; exit=2; stderr=Welcome accessibility failure: one showing control required'):
            S.accessibility_result(b'',stderr,2,551,'activate','System')

    def test_zero_exit_empty_malformed_and_nonobject_json_stay_fatal(self):
        for raw in (b'',b' \n',b'not-json',b'{',b'\xff',b'null',b'[]'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):S.accessibility_result(raw,b'',0,551,'snapshot')

    def test_success_cannot_override_nonzero_exit_wrong_pid_or_status(self):
        for code,value in ((2,dict(status='PASS',pid=551)),(0,dict(status='PASS',pid=999)),(0,dict(status='FAIL',pid=551))):
            with self.subTest(code=code,value=value),self.assertRaises(ValueError):
                S.accessibility_result(json.dumps(value).encode(),b'',code,551,'activate','System')

    def test_owned_success_and_exact_initial_pending_contract(self):
        raw=b'{"status":"PASS","pid":551,"actions":1}'
        self.assertEqual(S.accessibility_result(raw,b'',0,551,'activate','System'),json.loads(raw))
        waiting=b'{"status":"WAITING_FOR_OWNED_WELCOME"}\n'
        self.assertIsNone(S.accessibility_result(waiting,b'',75,551,'snapshot',pending=True))
        for output,stderr,pending in ((waiting,b'',False),(waiting,b'error',True),(b'',b'',True),(raw,b'',True)):
            with self.subTest(output=output,stderr=stderr,pending=pending),self.assertRaises(ValueError):
                S.accessibility_result(output,stderr,75,551,'snapshot',pending=pending)


class Phase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lock=dict(status='VERIFIED_NATIVE_CANDIDATES',eligibility='PRIVATE_GUI_TRIAL_ONLY',
            producer_lifecycle='FAIL_USER_PRESERVATION_CHECK',products=candidates.verify(ROOT,ASSETS),
            transport=json.loads((Path(__file__).with_name('transport.json')).read_text()))

    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.config=self.root/'config';self.config.mkdir();(self.config/'owned').write_text('preserve')
        self.share=self.root/'share';self.share.mkdir();(self.share/'candidate-lock.json').write_text(json.dumps(self.lock))
        self.events=[];self.actors=[];self.major={};self.rows={};self.counter=100;self.clock=0;self.view='home'
        self.bad_action=None;self.config_drift=False;self.bad_welcome_exit=False;self.capture_failure=False
        self.doctor_failure=None;self.doctor_exits=False;self.diagnostic_error=False;self.compositor_finish_error=None
        self.original_publish=S.C.publish;self.original_read=S.C.read;self.original_lstat=Path.lstat
        self.base=SimpleNamespace(HOME=self.root,SHARE=self.share,RUNTIME=SimpleNamespace(glob=lambda p:
            [SimpleNamespace(name='wayland-0',is_socket=lambda:True)] if self.major else []),
            Logged=self.launch,command=self.command,ipc=lambda *a:dict(a[2]),terminate=self.terminate,
            emit=self.emit)

    def emit(self,event,**values):
        if self.diagnostic_error and event=='welcome_phase_failed':raise RuntimeError('secondary diagnostic emit failure')
        self.events.append(dict(event=event,**copy.deepcopy(values)))

    def read(self,path,cap=256*1024):
        if path.parent==Path('/usr/share/doc/cachy-asahi-welcome'):return (ROOT/'packages/tools/cachy-asahi-welcome'/path.name).read_bytes()
        return self.original_read(path,cap)

    def row(self,pid,kind):
        return dict(pid=pid,address='0x'+format(pid,'x'),mapped=True,visible=True,hidden=False,xwayland=False,
            floating=False,size=[1014,758],at=[5,5],monitor=0,workspace=dict(id=1,name='1'),title=
            S.C.TITLE if kind=='welcome' else S.C.DOCTOR_TITLE if kind=='doctor' else 'Home - Thunar' if kind=='thunar' else 'Alacritty',
            **{'class':'io.github.GabrielKahen.CachyAsahiWelcome' if kind=='welcome' else S.C.DOCTOR_ID if kind=='doctor' else 'thunar' if kind=='thunar' else 'Alacritty'})

    def launch(self,argv,name,logs,env):
        self.counter+=1;actor=SimpleNamespace(argv=argv,name=name,env=dict(env),process=Process(self.counter),finished=False)
        actor.healthy=lambda:S.C.need(actor.process.poll() is None,'owned GUI actor exited')
        actor.finish=lambda:setattr(actor,'finished',True);self.actors.append(actor)
        if argv[0]=='/usr/local/bin/welcome-a11y':
            operation=argv[2];pid=int(argv[1]);result=dict(status='PASS',pid=pid)
            if operation=='activate':
                label=argv[3]
                if label==self.bad_action:actor.process.returncode=2;result=dict(status='FAIL')
                else:
                    actor.process.returncode=0;result.update(actions=1,action_name='click')
                    if label in ('Updates','Recovery'):
                        result.update(action_name='select-child',interface='Selection',target_role=37,parent_role=38,
                            child_index=1 if label=='Updates' else 2,child_count=3,selected=True,selected_count=1)
                    if label=='Open Terminal':self.rows[900]=self.row(900,'terminal')
                    elif label=='Open Files':self.rows[self.major['thunar'].process.pid]=self.row(self.major['thunar'].process.pid,'thunar')
                    else:self.view={'System':'system','Welcome':'home','First steps':'first-steps','Updates':'updates','Recovery':'recovery'}.get(label,self.view)
                    if self.config_drift and label=='Refresh system status':(self.config/'owned').write_text('changed')
            else:
                actor.process.returncode=0
                if self.view=='home':nodes=[node(n) for n in ('Open Terminal','Open Files','First steps','Updates','Recovery')]
                elif self.view=='system':nodes=[node('Refresh system status'),node('status',text=b'fixture status\n')]
                else:
                    label=S.C.LABELS[self.view];guide='first-run' if self.view=='first-steps' else self.view
                    text=(ROOT/'packages/tools/cachy-asahi-welcome'/(guide+'.txt')).read_bytes()
                    nodes=[node(label,selected=True,role=37),node('text',text=text)]
                result['nodes']=nodes
            actor.paths=[logs/(name+'.stdout'),logs/(name+'.stderr')]
            actor.paths[0].write_text(json.dumps(result));actor.paths[1].write_text('')
            return actor
        kind='compositor' if argv[0].endswith('/Hyprland') else 'doctor' if argv[0].endswith('/alacritty') else \
            'welcome' if argv[0].endswith('/cachy-asahi-welcome') else 'settings' if argv[0].endswith('/xfconfd') else 'thunar'
        self.major[kind]=actor
        if kind=='compositor':
            def finish():
                actor.finished=True
                self.emit('compositor_log_summary',stage='minimal',pid=actor.process.pid,returncode=actor.process.returncode,
                    drains_complete=True,overflow=bool(self.compositor_finish_error),drain_errors=0,
                    streams=[dict(path='/home/desktop574/logs/minimal.'+suffix,observed_bytes=0,limit_bytes=limit)
                             for suffix,limit in (('stdout',2*1024*1024),('stderr',256*1024))])
                if self.compositor_finish_error:raise ValueError(self.compositor_finish_error)
            actor.finish=finish
        if kind in ('doctor','welcome'):self.rows[actor.process.pid]=self.row(actor.process.pid,kind)
        return actor

    def terminate(self,process):
        if process.returncode is None:process.returncode=-15

    def command(self,argv,env,logs,name,timeout=20):
        if argv[0]=='/usr/bin/busctl':
            if 'GetConnectionUnixUser' in argv:return 'u 23001\n'
            if 'GetConnectionUnixProcessID' in argv:return 'u 422\n'
            if 'GetUnit' in argv:return 'o "/org/freedesktop/systemd1/unit/default_2etarget"\n'
        if argv[0]=='/usr/bin/gdbus':
            method=argv[argv.index('--method')+1].split('.')[-1]
            if method=='GetAddress':return "('unix:path=/run/user/23001/at-spi/bus_0',)\n"
            if method=='NameHasOwner':return '(true,)\n'
            kind='settings' if argv[-1]=='org.xfce.Xfconf' else 'thunar'
            return '(uint32 '+str(self.major[kind].process.pid)+',)\n'
        if 'monitors' in argv:return json.dumps([dict(width=1024,height=768,scale=1)])
        if 'clients' in argv:
            if self.capture_failure and any(e.get('event')=='doctor_result' for e in self.events):raise ValueError('strict capture IPC failure')
            return json.dumps(list(self.rows.values()))
        if argv[0]=='/usr/bin/cachy-asahi-welcome':return 'fixture status\n'
        if '--quit' in argv:
            actor=self.major['thunar'];actor.process.returncode=0;self.rows.pop(actor.process.pid,None);return ''
        if 'dispatch' in argv:
            expression=argv[-1]
            if expression=='hl.dsp.exit()':self.major['compositor'].process.returncode=0;return 'ok\n'
            address=re.search('address:(0x[0-9a-f]+)',expression)[1]
            row=next(r for r in self.rows.values() if r['address']==address)
            if '.close(' in expression:
                if row['pid']==900:self.observed.exited_flag=True
                else:self.major['welcome'].process.returncode=1 if self.bad_welcome_exit else 0
                self.rows.pop(row['pid']);return 'ok\n'
            if '.float(' in expression:row['floating']=not row['floating']
            else:row['size' if '.resize(' in expression else 'at']=list(map(int,re.search(r'x=([0-9]+),y=([0-9]+)',expression).groups()))
            return 'ok\n'
        raise AssertionError(argv)

    def publish(self,path,value):
        self.original_publish(path,value)
        if path.name=='start.json':
            proof=doctor(nonce=value['nonce'],pid=value['terminal_pid'])
            raw=(json.dumps(proof['doctor'],sort_keys=True,indent=2)+'\n').encode()
            report=path.parent/'doctor-report.json';report.write_bytes(raw);report.chmod(0o600)
            proof['report_sha256']=S.C.sha(raw);self.original_publish(path.parent/'result.json',proof)
            if self.doctor_failure:
                (path.parent/'result.json').unlink()
                self.original_publish(path.parent/'result.json',self.doctor_failure)
            if self.doctor_exits:self.major['doctor'].process.returncode=0
        elif path.name=='release.json':
            actor=self.major['doctor'];actor.process.returncode=0;self.rows.pop(actor.process.pid,None)

    def observed_factory(self,pid):
        obj=SimpleNamespace(proof=dict(pid=pid,uid=[23001]*4,starttime=123,executable='/usr/bin/alacritty'),exited_flag=False,closed=False)
        obj.healthy=lambda:S.C.need(not obj.exited_flag,'observed terminal exited')
        obj.wait=lambda seconds:S.C.need(obj.exited_flag,'observed terminal not retired')
        def close():obj.closed=True;obj.exited_flag=True;self.rows.pop(pid,None)
        obj.close=close;self.observed=obj;return obj

    def now(self):self.clock+=.2;return self.clock
    def lstat(self,path,*args,**kwargs):
        if str(path)=='/run/user/23001/at-spi/bus_0':return SimpleNamespace(st_mode=stat.S_IFSOCK|0o600,st_uid=23001)
        value=self.original_lstat(path,*args,**kwargs)
        if path.name=='doctor-report.json':
            fields=list(value);fields[4]=23001;return os.stat_result(fields)
        return value

    def run_phase(self):
        clock=SimpleNamespace(monotonic=self.now,sleep=lambda n:None)
        with patch.object(S.L,'launch',side_effect=lambda base,stage,config,logs,env:
                 self.launch(['/usr/bin/Hyprland','--config',str(config)],stage,logs,env)),\
             patch.object(S,'base',self.base),patch.object(S,'time',clock),patch.object(S.C,'read',side_effect=self.read),\
             patch.object(S.C,'publish',side_effect=self.publish),patch.object(S.S,'startup_clients',side_effect=lambda *a:list(self.rows.values())),\
             patch.object(S.S,'worker_identity',side_effect=lambda pid,parent:dict(pid=pid,parent_pid=parent,uid=23001)),\
             patch.object(S.O,'ObservedTerminal',side_effect=self.observed_factory),\
             patch.object(Path,'lstat',autospec=True,side_effect=self.lstat),\
             patch.dict(S.os.environ,CACHY_MANAGED_MANAGER_PID='422'):
            S.phase('minimal',self.root/'minimal.lua',dict(XDG_CONFIG_HOME=str(self.config),HOME=str(self.root),
                XDG_RUNTIME_DIR='/run/user/23001',DBUS_SESSION_BUS_ADDRESS='unix:path=/run/user/23001/bus'),self.root)

    def retired(self):self.assertTrue(all(a.finished and a.process.poll() is not None for a in self.actors))

    def test_exact_real_interface_sequence_seven_frames_preservation_and_retirement(self):
        self.run_phase();self.retired()
        self.assertEqual([e['view'] for e in self.events if e['event']=='frame_ready'],list(S.C.VIEWS))
        self.assertEqual(len([e for e in self.events if e['event']=='welcome_action']),8)
        selections=[e for e in self.events if e['event']=='welcome_action' and e['proof']['action_name']=='select-child']
        self.assertEqual([e['label'] for e in selections],['Updates','Recovery'])
        self.assertTrue(all(e['method']=='installed GTK AT-SPI notebook selection' for e in selections))
        self.assertEqual(self.events[-1]['event'],'phase_pass');self.assertTrue(self.observed.closed)
        self.assertEqual((self.config/'owned').read_text(),'preserve')
        self.assertEqual([self.major[k].process.returncode for k in ('welcome','doctor','thunar','compositor')],[0,0,0,0])
        self.assertTrue(all(a.env.get('DBUS_SESSION_BUS_ADDRESS')=='unix:path=/run/user/23001/bus' for a in self.major.values()))

    def test_cleanup_log_failure_after_seven_frames_stays_fatal(self):
        self.compositor_finish_error='compositor process log overflow/failure'
        with self.assertRaisesRegex(ValueError,'compositor process log overflow/failure'):self.run_phase()
        self.retired()
        self.assertEqual(len([e for e in self.events if e['event']=='frame_ready']),7)
        self.assertNotIn('phase_pass',[e['event'] for e in self.events])
        self.assertEqual(self.events[-1]['checkpoint'],'cleanup')

    def test_compositor_log_receipt_mutations_refuse_acceptance(self):
        self.run_phase();events=managed_events(self.events)
        for mutation in ('missing','duplicate','exit','overflow','drain','cap','count','path','pid'):
            bad=copy.deepcopy(events);log=next(e for e in bad if e.get('event')=='compositor_log_summary')
            if mutation=='missing':bad.remove(log)
            elif mutation=='duplicate':bad.append(copy.deepcopy(log))
            elif mutation=='exit':log['returncode']=1
            elif mutation=='overflow':log['overflow']=True
            elif mutation=='drain':log['drains_complete']=False
            elif mutation=='cap':log['streams'][0]['limit_bytes']=4*1024*1024
            elif mutation=='count':log['streams'][0]['observed_bytes']=2*1024*1024+1
            elif mutation=='path':log['streams'][0]['path']='/another/stdout'
            else:log['pid']+=1
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):contract.verify_result(bad,self.lock)

    def test_failed_gtk_action_retires_every_actor_without_phase_pass(self):
        self.bad_action='Updates'
        with self.assertRaisesRegex(ValueError,'accessibility command failed'):self.run_phase()
        self.retired();self.assertNotIn('phase_pass',[e['event'] for e in self.events])

    def test_worker_failure_reason_is_retained_before_welcome_and_after_cleanup(self):
        self.doctor_failure=dict(status='FAIL',error_type='ValueError',reason='event port unavailable')
        with self.assertRaisesRegex(ValueError,'Doctor worker failed: event port unavailable'):self.run_phase()
        self.retired();self.assertNotIn('welcome',self.major)
        diagnostic=next(e for e in self.events if e['event']=='welcome_phase_failed')
        self.assertEqual(diagnostic['checkpoint'],'doctor-validation')
        self.assertEqual(diagnostic['doctor_result']['reason'],'event port unavailable')
        self.assertEqual(diagnostic['reason'],'Doctor worker failed: event port unavailable')
        self.assertNotIn('doctor_result',[e['event'] for e in self.events]);self.assertNotIn('phase_pass',[e['event'] for e in self.events])

    def test_early_terminal_exit_stays_fatal_but_worker_failure_is_diagnosed(self):
        self.doctor_failure=dict(status='FAIL',error_type='ValueError',reason='event port unavailable');self.doctor_exits=True
        with self.assertRaisesRegex(ValueError,'owned GUI actor exited'):self.run_phase()
        self.retired();self.assertNotIn('welcome',self.major)
        diagnostic=next(e for e in self.events if e['event']=='welcome_phase_failed')
        self.assertEqual(diagnostic['checkpoint'],'doctor-result')
        self.assertEqual(diagnostic['reason'],'owned GUI actor exited')
        self.assertEqual(diagnostic['doctor_result']['reason'],'event port unavailable')

    def test_secondary_diagnostic_emit_failure_cannot_mask_first_or_cleanup(self):
        self.doctor_failure=dict(status='FAIL',reason='primary worker failure');self.diagnostic_error=True
        with self.assertRaisesRegex(ValueError,'Doctor worker failed: primary worker failure'):self.run_phase()
        self.retired();self.assertNotIn('phase_pass',[e['event'] for e in self.events])

    def test_diagnostic_fields_are_bounded_and_unsafe_result_not_followed(self):
        work=self.root/'diagnostic';work.mkdir();outside=self.root/'outside';outside.write_text('private')
        (work/'result.json').symlink_to(outside)
        value=S.failure('minimal','doctor-result',ValueError('x'*4096),work)
        self.assertEqual(len(value['reason']),512);self.assertEqual(value['doctor_result']['status'],'UNREADABLE')
        self.assertNotIn('private',json.dumps(value));self.assertEqual(outside.read_text(),'private')

    def test_user_configuration_drift_refuses_acceptance(self):
        self.config_drift=True
        with self.assertRaisesRegex(ValueError,'existing user configuration changed'):self.run_phase()
        self.retired();self.assertNotIn('phase_pass',[e['event'] for e in self.events])

    def test_nonzero_welcome_exit_refuses_phase_pass(self):
        self.bad_welcome_exit=True
        with self.assertRaisesRegex(ValueError,'unclean Welcome exit'):self.run_phase()
        self.retired();self.assertNotIn('phase_pass',[e['event'] for e in self.events])

    def test_post_startup_clients_failure_stays_fatal(self):
        self.capture_failure=True
        with self.assertRaisesRegex(ValueError,'strict capture IPC failure'):self.run_phase()
        self.retired();self.assertNotIn('phase_pass',[e['event'] for e in self.events])

    def test_full_managed_contract_and_semantic_digest_identity_mutations(self):
        self.run_phase();events=managed_events(self.events)
        self.assertEqual(contract.verify_result(events,self.lock)['GUI'],'NATIVE_METADATA_PASS_PIXELS_PENDING_REVIEW')
        for change in ('manager','guide','physical','retired','method','selection-index','selection-method','global-select','missing-frame'):
            bad=copy.deepcopy(events)
            frame=next(e for e in bad if e.get('event')=='frame_ready' and e.get('view')=='first-steps')
            if change=='manager':frame['managed_identity']['manager_pid']=999
            elif change=='guide':frame['semantic']['summary']['showing_text_sha256']=[]
            elif change=='physical':frame['physical_input']='PASS'
            elif change=='retired':next(e for e in bad if e.get('event')=='welcome_terminal_retired')['exit_status']=0
            elif change=='method':next(e for e in bad if e.get('event')=='welcome_action')['method']='direct shell command'
            elif change=='selection-index':next(e for e in bad if e.get('event')=='welcome_action' and e.get('label')=='Updates')['proof']['child_index']=2
            elif change=='selection-method':next(e for e in bad if e.get('event')=='welcome_action' and e.get('label')=='Updates')['method']='installed GTK AT-SPI action'
            elif change=='global-select':next(e for e in bad if e.get('event')=='welcome_action' and e.get('label')=='Updates')['label']='System'
            else:bad.remove(frame)
            with self.subTest(change=change),self.assertRaises(ValueError):contract.verify_result(bad,self.lock)


if __name__=='__main__':unittest.main()
