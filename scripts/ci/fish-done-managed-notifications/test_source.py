# SPDX-License-Identifier: MIT
"""Source/data controls only; no compiler, package installation, bus, Fish, GUI or VM."""
import ast,base64,copy,hashlib,importlib.util,json,os,subprocess,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
import observation as O
import packet
import fish_terminal as F
import contract as C
import capture as P
import session as S

HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ.get('DONE_MANAGED_SOURCE_ROOT',Path.cwd())).resolve()
MODULES=Path(os.environ.get('DONE_MANAGED_INPUTS',ROOT/'artifacts/development/setup5-six-module-inputs-20261016/payload')).resolve()


def messages(outcome=0,kind='Foreground command'):
    title='Done in 5s' if outcome==0 else 'Failed (7) after 5s'
    call=dict(type='method_call',**{'timestamp-realtime':1000000},sender=':1.9',destination='org.freedesktop.Notifications',path='/org/freedesktop/Notifications',interface='org.freedesktop.Notifications',member='Notify',cookie=42,
              payload=dict(type='susssasa{sv}i',data=['fish',0,'',title,kind+' completed.',[],{'image-path':{'type':'s','data':'utilities-terminal'},'urgency':{'type':'y','data':1 if outcome==0 else 2},'transient':{'type':'i','data':1}},3000]))
    reply=dict(type='method_return',**{'timestamp-realtime':1100000},sender=':1.7',destination=':1.9',reply_cookie=42,payload=dict(type='u',data=[23]))
    return [call,reply]


class Wire(unittest.TestCase):
    def test_success_and_failure_require_real_call_reply_and_mako_payload(self):
        for outcome in (0,7):
            rows=messages(outcome);wire=O.notify(rows,':1.7',outcome)
            self.assertEqual((wire['id'],wire['sender'],wire['recipient']),(23,':1.9',':1.7'))
            notice={k:wire[k] for k in ('id','app_name','summary','body')}
            self.assertEqual(O.listing([notice],wire),notice)

    def test_missing_reply_cannot_prove_delivery(self):self.assertIsNone(O.notify(messages()[:1],':1.7',0))

    def test_wrong_receiver_or_sender_refused(self):
        for member,value in (('destination','org.foreign'),('sender',':1.7')):
            rows=messages();rows[0][member]=value
            with self.subTest(member=member),self.assertRaises(ValueError):O.notify(rows,':1.7',0)

    def test_reply_must_come_from_mako_owner(self):
        rows=messages();rows[1]['sender']=':1.99'
        with self.assertRaises(ValueError):O.notify(rows,':1.7',0)

    def test_duplicate_call_or_reply_refused(self):
        for duplicate in (0,1):
            rows=messages();rows.append(copy.deepcopy(rows[duplicate]))
            with self.subTest(duplicate=duplicate),self.assertRaises(ValueError):O.notify(rows,':1.7',0)

    def test_no_fixture_app_expiry_or_body_substitution(self):
        for index,value in ((0,'cachy-asahi-smoke'),(4,'fake'),(7,0),(2,'other')):
            rows=messages();rows[0]['payload']['data'][index]=value
            with self.subTest(index=index),self.assertRaises(ValueError):O.notify(rows,':1.7',0)

    def test_wrong_urgency_refused(self):
        rows=messages(7);rows[0]['payload']['data'][6]['urgency']['data']=1
        with self.assertRaises(ValueError):O.notify(rows,':1.7',7)

    def test_mako_listing_must_match_wire(self):
        wire=O.notify(messages(),':1.7',0);row={k:wire[k] for k in ('id','app_name','summary','body')};row['body']='other'
        with self.assertRaises(ValueError):O.listing([row],wire)

    def test_bounded_complete_json_observer(self):
        raw=b'\n'.join(json.dumps(r).encode() for r in messages())+b'\n';self.assertEqual(O.messages(raw),messages())
        with self.assertRaises(ValueError):O.messages(b'x'*262145)
        with self.assertRaises((ValueError,json.JSONDecodeError)):O.messages(b'{partial')

    def test_legacy_private_recorder_receipt_is_not_managed_delivery(self):
        with self.assertRaises(ValueError):C.verify_result([dict(status='PASS_FISH_DONE_INSTALLED_LIFECYCLE',notifications=True)])


class Protocol(unittest.TestCase):
    def fixture(self):
        identity=dict(address='unix:path=/run/user/23001/bus',uid=23001,manager_pid=101,default_target='GetUnit-PASS')
        units={n:dict(Id=n,LoadState='loaded',ActiveState='active',SubState=s,Result='success',ExecMainStatus=0,MainPID=101 if n=='user@23001.service' else 0) for n,s in (('systemd-user-sessions.service','exited'),('user-runtime-dir@23001.service','exited'),('user@23001.service','running'))}
        events=[dict(event='boot',architecture='aarch64',kernel='7.2.10-1-aarch64-ARCH',page_size=4096),dict(event='managed_session_ready',status='PASS',units=units,**identity),dict(event='managed_user_ready',status='PASS',**identity)]
        for stage,(case,outcome) in O.CASES.items():
            kind='Watched job' if stage=='background' else 'Foreground command'
            wire=O.notify(messages(outcome,kind),':1.7',outcome,kind)
            row=lambda namespace,pid,x,y,w,h:dict(namespace=namespace,pid=pid,x=x,y=y,w=w,h=h,alpha=1,level='2',monitor='Virtual-1')
            activation=dict(values=dict(WAYLAND_DISPLAY='wayland-1',HYPRLAND_INSTANCE_SIGNATURE='test-owned',XDG_SESSION_TYPE='wayland',XDG_CURRENT_DESKTOP='Hyprland'),manager_pid=101,systemd_verified=True,dbus_updated=True)
            installed=dict(status='PASS_ACTUAL_INSTALLED_DONE_PAYLOAD_METADATA',version='0.1.0-2',archive_sha256='9ce3c7ba89467f04660014c1b12056dce28bd0c4e69b4cab8a9c2c98e1cce54f',files={str(i):'a'*64 for i in range(8)},executables={n:{} for n in ('fish','notify-send','timeout')})
            caller=dict(pid=205,command=F.COMMANDS[outcome],outcome=outcome,prompt_status=outcome,caller_continuation=outcome)
            frame=dict(event='frame_ready',stage=stage,case=case,outcome=outcome,managed_identity=identity,activation='normal-shipped-config-no-reload',trace_waybar=False,notification_timeout_ms=3000,notification_age_ms=1000,timing=O.capture_timing(wire,2000000,123456),caller_pending=True,capture_after_ms=5000,activation_environment=activation,compositor_pid=201,waybar_pid=202,mako_pid=203,fish_pid=205,bar=row('waybar',202,0,0,1024,30),mako=row('notifications',203,650,40,300,100),wire=wire,notification={k:wire[k] for k in ('id','app_name','summary','body')},recipient=dict(service='org.freedesktop.Notifications',unique=':1.7',pid=203,owner_reply='s ":1.7"'),installed=installed)
            visibility={key:frame.pop(key) for key in ('bar','mako','notification')}
            visibility.update(request_sha256=C.request_digest(frame),realtime_us=2100000,monotonic_ns=124000)
            raw=b'\n'.join(json.dumps(r).encode() for r in messages(outcome,kind))+b'\n';pty=('FDM_PROMPT_2_'+str(outcome)+'\nFDM_CONT_'+str(outcome)).encode()
            if stage=='background':
                child=dict(pid=206,parent_pid=205,process_group=206,start_ticks=1234,executable='/usr/bin/sleep',argv=['sleep','8'])
                caller.update(command=F.BACKGROUND_COMMAND,watch=dict(child=child,registration_status=0,handler_registered=True,caller_before_completion=True))
                pty=b'\nFDM_WATCH_206_0\n'+pty+b'\nFDM_BG_RETIRED_206\n'
            events.extend([frame,dict(event='frame_captured',stage=stage,first_capture=True,request_sha256=C.request_digest(frame),managed_identity=identity,visual_review='NOT_RUN',capture_ms=20,sha256='a'*64,visibility_sha256=C.request_digest(visibility),notification_pixels=dict(status='PASS_PIXEL_PRESENCE_PENDING_READABILITY',frame_sha256='a'*64,roi={k:visibility['mako'][k] for k in ('x','y','w','h')},roi_sha256='b'*64,pixels=30000,counts=dict(background=20000,border=2000,text=200),color_tolerance=6,style_sha256=P.STYLE_SHA256,visual_review='NOT_RUN'),host_started_realtime_us=3000000,host_qmp_returned_realtime_us=3001000,host_finished_realtime_us=3002000,host_started_monotonic_ns=345678,host_received_realtime_us=2999000,host_received_monotonic_ns=245678,host_visibility_received_realtime_us=2999500,host_visibility_received_monotonic_ns=300678,scheduled_visibility_sha256=C.request_digest(visibility)),dict(event='frame_visibility',stage=stage,case=case,wire=wire,visibility=visibility,capture_request_sha256=C.request_digest(frame),managed_identity=identity),dict(event='done_transport',stage=stage,case=case,wire=wire,caller=caller,visibility=visibility,capture_request_sha256=C.request_digest(frame),post_request_identity=identity,monitor=dict(raw_base64=base64.b64encode(raw).decode(),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),exit=0),fish=dict(exit=0,pty_base64=base64.b64encode(pty).decode(),pty_bytes=len(pty),pty_sha256=hashlib.sha256(pty).hexdigest()),mako_exit=0,payload_preserved=True,user_config_preserved=True),dict(event='phase_pass',stage=stage,case=case,config_preserved=True,fish='PASS')])
            events[-4],events[-3]=events[-3],events[-4]
            if stage=='background':
                events[-2]['fish']['watch_retirement']=dict(child=child,handler_absent=True,pid_absent=True,process_group_absent=True)
        stopped={n:dict(Id=n,LoadState='loaded',ActiveState='inactive',SubState='dead',MainPID=0) for n in ('user@23001.service','user-runtime-dir@23001.service')}
        events.extend([dict(event='session_pass',status='PASS',fish_done='PASS_REAL_MANAGED_FOREGROUND_TWO_CASES',watched_background='PASS_REAL_MANAGED_SINGLE_SUCCESS'),dict(event='managed_session_cleanup',status='PASS',runtime_absent=True,owned_units_stopped=True,units=list(stopped),unit_states=stopped),dict(event='complete',status='PASS')])
        return events

    def test_complete_synthetic_protocol_is_metadata_only(self):
        result=C.verify_result(self.fixture());self.assertEqual(result['foreground_cases'],2);self.assertEqual(result['visual_review'],'NOT_RUN')

    def test_bad_bus_payload_exit_cleanup_or_capture_cannot_pass(self):
        for kind,key,value in (('done_transport','mako_exit',3),('done_transport','payload_preserved',False),('frame_captured','first_capture',False),('managed_session_cleanup','runtime_absent',False),('boot','page_size',16384)):
            events=self.fixture();next(e for e in events if e['event']==kind)[key]=value
            with self.subTest(kind=kind,key=key),self.assertRaises(ValueError):C.verify_result(events)

    def test_wire_sender_and_listing_cannot_be_replaced_by_boolean(self):
        events=self.fixture();next(e for e in events if e['event']=='done_transport')['wire']=dict(status='PASS')
        with self.assertRaises(ValueError):C.verify_result(events)


class Background(unittest.TestCase):
    def events(self):return Protocol().fixture()

    def test_actual_body_is_watched_job_and_cannot_be_foreground(self):
        wire=O.notify(messages(0,'Watched job'),':1.7',0,'Watched job')
        self.assertEqual(wire['body'],'Watched job completed.')
        with self.assertRaises(ValueError):O.notify(messages(),':1.7',0,'Watched job')
        with self.assertRaises(ValueError):O.notify(messages(0,'Watched job'),':1.7',0)

    def test_single_positive_case_has_no_failure_or_cancellation_credit(self):
        result=C.verify_result(self.events())
        self.assertEqual(result['foreground_cases'],2);self.assertEqual(result['background_cases'],1)
        for key in ('background_failure','background_cancellation','background_duplicate_watch','visual_review'):
            self.assertEqual(result[key],'NOT_RUN')

    def test_missing_background_phase_cannot_pass(self):
        events=[e for e in self.events() if e.get('stage')!='background']
        with self.assertRaises(ValueError):C.verify_result(events)

    def test_background_receipt_cannot_substitute_foreground_receipt(self):
        events=self.events();frame=next(e for e in events if e.get('stage')=='background' and e['event']=='done_transport')
        frame['caller'].pop('watch')
        with self.assertRaises((ValueError,KeyError)):C.verify_result(events)

    def test_actual_handler_pid_group_and_child_must_retire(self):
        for key in ('handler_absent','pid_absent','process_group_absent'):
            events=self.events();row=next(e for e in events if e.get('stage')=='background' and e['event']=='done_transport')
            row['fish']['watch_retirement'][key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):C.verify_result(events)

    def test_child_cannot_be_fish_or_foreign_or_wrong_executable(self):
        for key,value in (('pid',205),('parent_pid',999),('process_group',205),('executable','/tmp/notify-shim'),('argv',['sleep','0.1']),('start_ticks',0)):
            events=self.events();frame=next(e for e in events if e.get('stage')=='background' and e['event']=='done_transport')
            frame['caller']['watch']['child'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):C.verify_result(events)

    def test_no_caller_continuation_after_completion_can_claim_live_job(self):
        events=self.events();frame=next(e for e in events if e.get('stage')=='background' and e['event']=='done_transport')
        frame['caller']['watch']['caller_before_completion']=False
        with self.assertRaises(ValueError):C.verify_result(events)

    def test_raw_watch_marker_binds_one_successful_exact_pid(self):
        self.assertEqual(F.watched_pid(b'\nFDM_WATCH_206_0\n'),206)
        self.assertEqual(F.retired_pid(b'\nFDM_BG_RETIRED_206\n'),206)
        with self.assertRaises(ValueError):F.retired_pid(b'\nFDM_BG_RETIRED_206\nFDM_BG_RETIRED_207\n')
        for raw in (b'FDM_WATCH_%s_%s',b'\nFDM_WATCH_206_7\n',b'\nFDM_WATCH_206_0\nFDM_WATCH_207_0\n'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):F.watched_pid(raw)

    def test_registration_and_retirement_markers_cannot_be_reordered_or_rebound(self):
        events=self.events();frame=next(e for e in events if e.get('stage')=='background' and e['event']=='done_transport')
        row=next(e for e in events if e.get('stage')=='background' and e['event']=='done_transport')
        raw=base64.b64decode(row['fish']['pty_base64']);watch=frame['caller']['watch'];retired=row['fish']['watch_retirement']
        F.verify_background(watch,205,raw,retired)
        for bad in (raw.replace(b'FDM_BG_RETIRED_206',b'FDM_BG_RETIRED_2060'),b'\nFDM_BG_RETIRED_206\nFDM_PROMPT_2_0\nFDM_CONT_0\nFDM_WATCH_206_0\n'):
            with self.subTest(raw=bad),self.assertRaises(ValueError):F.verify_background(watch,205,bad,retired)
        watch['registration_status']=False
        with self.assertRaises(ValueError):F.verify_background(watch,205,raw,retired)

    def test_foreground_terminal_init_commands_and_methods_unchanged(self):
        baseline=HERE/'fixtures/foreground-fish-terminal.py.txt'
        self.assertTrue((HERE/'fish_terminal.py').read_bytes().startswith(baseline.read_bytes()))
        old=ast.parse(baseline.read_bytes());new=ast.parse((HERE/'fish_terminal.py').read_bytes())
        for name in ('COMMANDS','INIT','Terminal'):
            def select(tree):
                return next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name==name or isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in n.targets))
            self.assertEqual(ast.dump(select(old)),ast.dump(select(new)),name)
        self.assertEqual(O.CASES['minimal'],('foreground-success',0));self.assertEqual(O.CASES['overlay'],('foreground-failure',7))

    def test_capture_preserves_one_original_qmp_frame_and_fixed_budget(self):
        text=(HERE/'capture.py').read_text()
        self.assertEqual(text.count("qmp.execute('screendump'"),1)
        self.assertIn("elapsed > 5000",text)
        self.assertLess(text.index('shutil.copyfile(source, target)'),text.index('presence=notification_pixels('))
        self.assertIn("('minimal', 'overlay', 'background')",text)

    def test_actual_original_watch_function_and_default_timing_preserved(self):
        self.assertIn('caa_done_watch $__fdm_job',F.BACKGROUND_COMMAND)
        self.assertIn('command sleep 8 &;',F.BACKGROUND_COMMAND)
        self.assertNotIn('__done_notify',F.BACKGROUND_COMMAND)
        self.assertNotIn('caa_done_min_duration',F.INIT+F.BACKGROUND_COMMAND)
        self.assertTrue(issubclass(F.BackgroundTerminal,F.Terminal))
        tree=ast.parse((HERE/'fish_terminal.py').read_bytes())
        self.assertFalse(any(isinstance(n,ast.FunctionDef) and n.name.startswith('__done') for n in ast.walk(tree)))

    def test_generated_and_guest_controller_require_third_first_frame(self):
        text=(Path(os.environ['DONE_MANAGED_PREPARED_RUNNER'])/'desktop574_runtime.py').read_text()
        self.assertIn("phases == {'minimal', 'overlay', 'background'}",text)
        self.assertIn("stage in ('minimal', 'overlay', 'background')",text)
        self.assertIn("session.phase('background',config,env,logs,trace_waybar=False)",(HERE/'desktop574_guest.py').read_text())
        self.assertIn("for stage in ('minimal', 'overlay', 'background'):",(HERE/'ci/caller.py').read_text())


class ActualWire38952906070(unittest.TestCase):
    def rows(self):
        raw=(HERE/'fixtures/run38952906070-bus.jsonl').read_bytes()
        self.assertEqual(len(raw),8505)
        self.assertEqual(hashlib.sha256(raw).hexdigest(),'925095fdbf524d07785869e4bf24ed78a17f304d0914b324d9e59122028c3f52')
        return O.messages(raw)

    def test_original_real_notify_uses_empty_icon_and_typed_image_path(self):
        calls=[r for r in self.rows() if r.get('member')=='Notify']
        self.assertEqual(len(calls),1);call=calls[0];data=call['payload']['data']
        self.assertEqual((call['sender'],call['destination'],call['cookie']),(':1.73',':1.25',9))
        self.assertEqual(data[2],'');self.assertEqual(data[6]['image-path'],dict(type='s',data='utilities-terminal'))
        self.assertEqual(data[7],3000)

    def test_actual_incomplete_monitor_requires_reply_and_cannot_pass_run(self):
        rows=self.rows();self.assertIsNone(O.notify(rows,':1.25',0))
        with self.assertRaises(ValueError):C.verify_result(rows)

    def test_original_call_with_constructed_reply_is_only_a_parser_control(self):
        rows=self.rows()
        # This reply did NOT occur in the retained prefix. It exercises the parser
        # only and is never saved as an actual run, delivery or frame receipt.
        rows.append(dict(type='method_return',sender=':1.25',destination=':1.73',reply_cookie=9,payload=dict(type='u',data=[23])))
        wire=O.notify(rows,':1.25',0)
        self.assertEqual((wire['sender'],wire['recipient'],wire['summary'],wire['body']),(':1.73',':1.25','Done in 5s','Foreground command completed.'))
        with self.assertRaises(ValueError):C.verify_result(rows)

    def test_icon_hint_cannot_be_missing_wrong_type_or_different_icon(self):
        for hint in (None,dict(type='s',data='wrong'),dict(type='i',data=1)):
            rows=self.rows();call=next(r for r in rows if r.get('member')=='Notify')
            if hint is None:call['payload']['data'][6].pop('image-path')
            else:call['payload']['data'][6]['image-path']=hint
            with self.subTest(hint=hint),self.assertRaises(ValueError):O.notify(rows,':1.25',0)

    def test_nonempty_icon_field_cannot_replace_actual_pinned_wire_format(self):
        rows=self.rows();next(r for r in rows if r.get('member')=='Notify')['payload']['data'][2]='utilities-terminal'
        with self.assertRaises(ValueError):O.notify(rows,':1.25',0)


class ExpiringCapture(unittest.TestCase):
    def pixel_cases(self):return json.loads((HERE/'fixtures/real-notification-pixels.json').read_bytes())['cases']

    def test_real_root_viewed_absent_frames_rejected_accepted_mako_regions_pass(self):
        for case in self.pixel_cases():
            raw=base64.b64decode(case['rgb_base64'],validate=True)
            self.assertEqual(hashlib.sha256(raw).hexdigest(),case['roi_sha256'])
            receipt=P.rgb_receipt(raw,case['roi'],case['original_first_ppm_sha256'])
            if case['expected_presence']:
                P.verify_pixel_receipt(receipt,case['roi'],case['original_first_ppm_sha256'])
                self.assertEqual(receipt['visual_review'],'NOT_RUN')
            else:
                self.assertEqual(receipt['counts'],dict(background=0,border=0,text=0))
                with self.assertRaisesRegex(ValueError,'no shipped Mako'):P.verify_pixel_receipt(receipt,case['roi'],case['original_first_ppm_sha256'])

    def test_presence_cannot_be_boolean_wrong_frame_or_wrong_geometry(self):
        case=self.pixel_cases()[0];raw=base64.b64decode(case['rgb_base64']);receipt=P.rgb_receipt(raw,case['roi'],case['original_first_ppm_sha256'])
        for value in (True,{},dict(receipt,frame_sha256='a'*64),dict(receipt,roi=dict(x=0,y=0,w=320,h=75))):
            with self.subTest(value=str(value)[:80]),self.assertRaises(ValueError):P.verify_pixel_receipt(value,case['roi'],case['original_first_ppm_sha256'])

    def test_pixels_cannot_claim_readability_or_use_wrong_style(self):
        case=self.pixel_cases()[0];receipt=P.rgb_receipt(base64.b64decode(case['rgb_base64']),case['roi'],case['original_first_ppm_sha256'])
        for key,value in (('visual_review','PASS'),('style_sha256','a'*64),('color_tolerance',99)):
            bad=dict(receipt);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):P.verify_pixel_receipt(bad,case['roi'],case['original_first_ppm_sha256'])

    def test_accurate_age_includes_reply_time_and_reserves_one_second(self):
        wire=O.notify(messages(),':1.7',0);timing=O.capture_timing(wire,2500000,123)
        self.assertEqual((timing['age_ms'],timing['reserve_us']),(1500,1500000))
        for now in (999999,1099999,3000001):
            with self.subTest(now=now),self.assertRaises(ValueError):O.capture_timing(wire,now,123)
        bad=copy.deepcopy(wire);bad['call'].pop('timestamp-realtime')
        with self.assertRaises(ValueError):O.capture_timing(bad,2500000,123)

    def test_actual_old_late_manager_queries_exhaust_new_request_budget(self):
        fixture=json.loads((HERE/'fixtures/real-expiring-notification-timing.json').read_bytes())
        for case in fixture['cases']:
            wire=case['wire'];last=case['last_pre_emit_manager_reply']['timestamp-realtime'];closed=case['actual_closed']['timestamp-realtime']
            self.assertLess(case['reported_notification_age_ms'],2000)
            self.assertGreater(last-wire['call']['timestamp-realtime'],2000000)
            self.assertLess(last,closed)  # Exact host capture timing was not retained.
            with self.assertRaisesRegex(ValueError,'one second'):O.capture_timing(wire,last,123)

    def test_original_pending_caller_must_join_after_request(self):
        events=Protocol().fixture();request=next(e for e in events if e['event']=='frame_ready')
        self.assertTrue(request['caller_pending']);self.assertNotIn('caller',request)
        for key,value in (('capture_request_sha256','bad'),('post_request_identity',{})):
            altered=copy.deepcopy(events);next(e for e in altered if e['event']=='done_transport')[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):C.verify_result(altered)

    def test_capture_request_precedes_caller_and_manager_rechecks(self):
        text=Path(S.__file__).read_text();start=text.index("base.emit('frame_ready',**request)")
        self.assertLess(start,text.index('continuation=terminal.continuation(outcome)'))
        self.assertLess(start,text.index('post_identity=identity()'))
        self.assertIn('timing=O.capture_timing_facts(wire,time.time_ns()//1000,time.monotonic_ns())',text)
        self.assertLess(start,text.index("current=B.wait_ready(visible,healthy,2,"))
        self.assertIn('notification_pixels(runtime/',(HERE/'ci/caller.py').read_text())

    def test_protocol_rejects_missing_pixels_or_stale_age_or_future_host_clock(self):
        for key,value in (('notification_pixels',{}),('host_finished_realtime_us',1)):
            events=Protocol().fixture();next(e for e in events if e['event']=='frame_captured')[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):C.verify_result(events)
        events=Protocol().fixture();next(e for e in events if e['event']=='frame_ready')['notification_age_ms']=100
        with self.assertRaises(ValueError):C.verify_result(events)


class StartupIPC(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.logs=Path(self.tmp.name)
        blocked=patch.object(subprocess,'Popen',side_effect=AssertionError('no actual actor'));blocked.start();self.addCleanup(blocked.stop)
        self.timeout_text=b"Hyprland IPC didn't respond in time\n\nCouldn't read (6)\n"

    def api(self,code=0,out=b'{"Virtual-1":{"levels":{"2":[]}}}',err=b'',failure=None,cleanup_error=None):
        from types import SimpleNamespace
        history=[];events=[]
        class Process:
            returncode=None
            def wait(self,timeout):
                history.append(('wait',timeout))
                if failure is not None:raise failure
                self.returncode=code
        class Logged:
            def __init__(logged,argv,name,logs,env):
                history.append(('spawn',argv));logged.process=Process()
                logged.paths=[logs/(name+'.stdout'),logs/(name+'.stderr')]
                for path,raw in zip(logged.paths,(out,err)):path.write_bytes(raw)
            def finish(logged):
                history.append(('finish',logged.process.returncode))
                if cleanup_error is not None:raise cleanup_error
        def terminate(process):
            history.append(('terminate',process.returncode))
            if process.returncode is None:process.returncode=-15
        return SimpleNamespace(Logged=Logged,terminate=terminate,emit=lambda event,**row:events.append(dict(event=event,**row)),history=history,events=events)

    def test_exact_actual_read_timeout_retries_after_owned_probe_retirement(self):
        api=self.api(6,self.timeout_text)
        self.assertIsNone(S.startup_layers(api,{},self.logs,'minimal-done-35-layers'))
        self.assertEqual([n[0] for n in api.history],['spawn','wait','terminate','finish'])
        self.assertEqual(api.history[1],('wait',7));self.assertEqual(api.events[0]['reason'],'EXACT_HYPRCTL_IPC_READ_TIMEOUT_6')
        self.assertTrue(api.events[0]['probe_retired'])

    def test_success_requires_actual_json_response(self):
        api=self.api();actual=S.startup_layers(api,{},self.logs,'probe')
        self.assertEqual(actual,{'Virtual-1':{'levels':{'2':[]}}});self.assertFalse(api.events)

    def test_non_timeout_exit_wrong_bytes_or_stderr_never_retries(self):
        for n,(code,out,err) in enumerate(((1,self.timeout_text,b''),(6,b'other error',b''),(6,self.timeout_text,b'foreign'),(6,self.timeout_text+b'extra',b''))):
            api=self.api(code,out,err)
            with self.subTest(code=code,out=out,err=err),self.assertRaises(ValueError):
                S.startup_layers(api,{},self.logs,'probe'+str(n))
            self.assertFalse(api.events)
        api=self.api(0,b'not json')
        with self.assertRaises(ValueError):S.startup_layers(api,{},self.logs,'bad-json')

    def test_existing_seven_second_wait_timeout_retries_only_when_retired(self):
        api=self.api(failure=subprocess.TimeoutExpired(['hyprctl'],7))
        self.assertIsNone(S.startup_layers(api,{},self.logs,'wait-timeout'))
        self.assertEqual(api.events[0]['reason'],'BOUNDED_STARTUP_PROBE_WAIT_TIMEOUT')
        self.assertEqual(api.history[-1],('finish',-15))

    def test_cleanup_failure_refuses_even_for_known_timeout(self):
        for n,failure in enumerate((None,subprocess.TimeoutExpired(['hyprctl'],7))):
            api=self.api(6,self.timeout_text,failure=failure,cleanup_error=ValueError('retirement unknown'))
            with self.subTest(failure=failure),self.assertRaises((ValueError,subprocess.TimeoutExpired)):
                S.startup_layers(api,{},self.logs,'failed-cleanup'+str(n))
            self.assertFalse(api.events)

    def test_cancelled_probe_propagates_after_cleanup(self):
        api=self.api(failure=KeyboardInterrupt())
        with self.assertRaises(KeyboardInterrupt):S.startup_layers(api,{},self.logs,'cancelled')
        self.assertEqual(api.history[-1][0],'finish');self.assertFalse(api.events)

    def test_repeated_not_ready_does_not_extend_original_thirty_seconds(self):
        import bar_helpers as B
        with patch.object(B.time,'monotonic',side_effect=[0,0,31]),patch.object(B.time,'sleep'):
            with self.assertRaisesRegex(ValueError,'readiness deadline'):
                B.wait_ready(lambda:None,lambda:None,30,'normal bar/Mako readiness')

    def test_retry_can_only_be_requested_by_pretrigger_ready_function(self):
        tree=ast.parse(Path(S.__file__).read_bytes())
        phase=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='phase')
        ready=next(n for n in ast.walk(phase) if isinstance(n,ast.FunctionDef) and n.name=='ready')
        visible=next(n for n in ast.walk(phase) if isinstance(n,ast.FunctionDef) and n.name=='visible')
        calls=[n for n in ast.walk(phase) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='layers' and n.keywords]
        self.assertEqual(len(calls),1);self.assertIn(calls[0],list(ast.walk(ready)))
        self.assertFalse(any(isinstance(n,ast.keyword) and n.arg=='startup' for n in ast.walk(visible)))
        self.assertIn("B.wait_ready(ready,healthy,30,'normal bar/Mako readiness')",Path(S.__file__).read_text())

    def test_successful_probe_does_not_waive_owned_layer_identity(self):
        import bar_helpers as B
        value={'Virtual-1':{'levels':{'2':[dict(namespace='waybar',pid=999,x=0,y=0,w=1024,h=30,alpha=1)]}}}
        api=self.api(0,json.dumps(value).encode());actual=S.startup_layers(api,{},self.logs,'foreign-layer')
        with self.assertRaisesRegex(ValueError,'foreign waybar'):B.owned_layer(actual,'waybar',100)

    def test_transient_then_success_has_no_cached_geometry_fallback(self):
        api=self.api(6,self.timeout_text);self.assertIsNone(S.startup_layers(api,{},self.logs,'first'))
        other=self.api(0,b'{"fresh":{"levels":{"2":[]}}}')
        self.assertEqual(S.startup_layers(other,{},self.logs,'second'),{'fresh':{'levels':{'2':[]}}})


class EarlyCapture(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.fixture=self.root/'fixture';self.frames=self.root/'frames';self.fixture.mkdir();self.frames.mkdir()
        blocked=patch.object(subprocess,'Popen',side_effect=AssertionError('no native actor'));blocked.start();self.addCleanup(blocked.stop)

    def request(self):return next(e for e in Protocol().fixture() if e.get('event')=='frame_ready' and e['stage']=='minimal')

    def test_request_precedes_listing_layers_caller_and_manager_queries(self):
        text=Path(S.__file__).read_text();request=text.index("base.emit('frame_ready',**request)")
        for marker in ("current=B.wait_ready(visible,healthy,2,",'continuation=terminal.continuation(outcome)','post_identity=identity()'):
            self.assertLess(request,text.index(marker))
        self.assertNotIn('**current',text[:request])

    def test_late_clock_facts_do_not_grant_timing_acceptance(self):
        wire=O.notify(messages(),':1.7',0)
        facts=O.capture_timing_facts(wire,3000001,123)
        self.assertGreater(facts['age_us'],2000000)
        with self.assertRaisesRegex(ValueError,'one second'):O.capture_timing(wire,3000001,123)

    def test_late_request_retains_one_original_capture_then_refuses(self):
        from types import SimpleNamespace
        request=self.request();request['timing']=O.capture_timing_facts(request['wire'],3000001,123456)
        request['notification_age_ms']=request['timing']['age_ms'];data=b'unchanged original first capture bytes'
        calls=[]
        def execute(method,args):calls.append((method,args));(self.fixture/'minimal.ppm').write_bytes(data)
        decode=lambda path:dict(sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        report=dict(frames={},events=[request])
        with self.assertRaisesRegex(ValueError,'one second'):
            P.capture_frame(request,SimpleNamespace(execute=execute),self.fixture,self.frames,report,decode)
        self.assertEqual((self.frames/'minimal.ppm').read_bytes(),data);self.assertEqual(len(calls),1)
        self.assertTrue(report['frames']['minimal']['observer']['first_capture'])
        self.assertNotIn('notification_pixels',report['frames']['minimal']['observer'])
        with self.assertRaises(ValueError):P.capture_frame(request,SimpleNamespace(execute=execute),self.fixture,self.frames,report,decode)
        self.assertEqual(len(calls),1)

    def finalize_fixture(self):
        events=Protocol().fixture();request=next(e for e in events if e.get('event')=='frame_ready')
        observer=copy.deepcopy(next(e for e in events if e.get('event')=='frame_captured'))
        pixels=observer.pop('notification_pixels');observer.pop('visibility_sha256')
        transport=next(e for e in events if e.get('event')=='frame_visibility')
        return transport,pixels,dict(events=[request,observer,transport],frames={'minimal':dict(sha256='a'*64,observer=observer)})

    def test_fresh_visibility_finalizes_original_pixels_without_recapture(self):
        transport,pixels,report=self.finalize_fixture()
        with patch.object(P,'notification_pixels',return_value=pixels) as decode,patch.object(P.time,'monotonic_ns',return_value=500345678):
            P.finalize_capture(transport,self.frames,report)
        observer=report['frames']['minimal']['observer'];self.assertEqual(observer['notification_pixels'],pixels)
        self.assertEqual(observer['visibility_sha256'],C.request_digest(transport['visibility']))
        decode.assert_called_once_with(self.frames/'minimal.ppm',transport['visibility']['mako'])
        with self.assertRaisesRegex(ValueError,'one visibility'):P.finalize_capture(transport,self.frames,report)

    def test_wrong_first_image_or_request_cannot_finalize(self):
        transport,pixels,report=self.finalize_fixture();pixels['frame_sha256']='b'*64
        with patch.object(P,'notification_pixels',return_value=pixels),patch.object(P.time,'monotonic_ns',return_value=500345678),self.assertRaises(ValueError):P.finalize_capture(transport,self.frames,report)
        transport,pixels,report=self.finalize_fixture();transport['capture_request_sha256']='bad'
        with self.assertRaisesRegex(ValueError,'request join'):P.finalize_capture(transport,self.frames,report)

    def test_missing_stale_or_foreign_late_visibility_never_passes(self):
        for key,value in (('request_sha256','bad'),('realtime_us',1),('monotonic_ns',1)):
            events=Protocol().fixture();next(e for e in events if e.get('event')=='done_transport')['visibility'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):C.verify_result(events)
        events=Protocol().fixture();next(e for e in events if e.get('event')=='done_transport')['visibility']=None
        with self.assertRaises(ValueError):C.verify_result(events)
        events=Protocol().fixture();next(e for e in events if e.get('event')=='done_transport')['visibility']['mako']['pid']=999
        with self.assertRaises(ValueError):C.verify_result(events)

    def test_first_capture_without_visibility_pixels_cannot_pass(self):
        events=Protocol().fixture();observer=next(e for e in events if e.get('event')=='frame_captured');observer.pop('notification_pixels')
        with self.assertRaises(ValueError):C.verify_result(events)
        events=Protocol().fixture();next(e for e in events if e.get('event')=='frame_ready')['mako']={}
        with self.assertRaises(ValueError):C.verify_result(events)

    def test_deferred_pixel_check_keeps_original_five_second_budget(self):
        transport,pixels,report=self.finalize_fixture()
        with patch.object(P,'notification_pixels',return_value=pixels),patch.object(P.time,'monotonic_ns',return_value=5001345678):
            with self.assertRaisesRegex(ValueError,'five-second observation budget'):
                P.finalize_capture(transport,self.frames,report)
        self.assertGreater(report['frames']['minimal']['observer']['capture_ms'],5000)

    def test_transport_cannot_replace_fresh_visibility_after_first_frame(self):
        events=Protocol().fixture();transport=next(e for e in events if e.get('event')=='done_transport')
        transport['visibility']=copy.deepcopy(transport['visibility']);transport['visibility']['notification']['body']='different'
        with self.assertRaises(ValueError):C.verify_result(events)

    def test_generated_host_schedules_visibility_before_phase_acceptance(self):
        text=Path(P.__file__).with_name('prepare.py').read_text()
        self.assertIn('arm_capture(event,fixture,frames,report)',text)
        self.assertIn("frame_visibility': capture_ready(event,qmp,fixture,frames,report,ppm)",text)
        self.assertIn("capture_pending_failure(qmp,fixture,frames,report,ppm)",text)
        runtime=(Path(os.environ['DONE_MANAGED_PREPARED_RUNNER'])/'desktop574_runtime.py').read_text()
        self.assertIn('deadline = time.monotonic() + 900',runtime)
        self.assertIn('signal.setitimer(signal.ITIMER_REAL, 1750)',runtime)


class RenderSynchronization(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.fixture=self.root/'fixture';self.frames=self.root/'frames';self.fixture.mkdir();self.frames.mkdir()
        blocked=patch.object(subprocess,'Popen',side_effect=AssertionError('no actual actor'));blocked.start();self.addCleanup(blocked.stop)
        events=Protocol().fixture();self.request=next(e for e in events if e.get('event')=='frame_ready')
        self.visible=next(e for e in events if e.get('event')=='frame_visibility')
        self.pixels=copy.deepcopy(next(e for e in events if e.get('event')=='frame_captured')['notification_pixels'])
        self.report=dict(events=[self.request],frames={});self.calls=[];self.data=b'original first diagnostic bytes'
        from types import SimpleNamespace
        def execute(method,args):
            self.calls.append((method,args));(self.fixture/'minimal.ppm').write_bytes(self.data)
        self.qmp=SimpleNamespace(execute=execute)
        self.decode=lambda path:dict(sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        self.pixels['frame_sha256']=hashlib.sha256(self.data).hexdigest()

    def arm(self):P.arm_capture(self.request,self.fixture,self.frames,self.report)

    def capture(self):
        self.report['events'].append(self.visible)
        with patch.object(P,'notification_pixels',return_value=self.pixels):
            P.capture_ready(self.visible,self.qmp,self.fixture,self.frames,self.report,self.decode)

    def test_request_arms_without_any_qmp_or_image(self):
        self.arm();self.assertFalse(self.calls);self.assertFalse(any(self.frames.iterdir()))
        self.assertEqual(self.report['capture_requests']['minimal']['request_sha256'],C.request_digest(self.request))

    def test_first_qmp_waits_for_valid_fresh_owned_visibility(self):
        self.arm();self.capture();self.assertEqual(len(self.calls),1)
        observer=self.report['frames']['minimal']['observer']
        self.assertEqual(observer['scheduled_visibility_sha256'],C.request_digest(self.visible['visibility']))
        self.assertLessEqual(observer['host_received_monotonic_ns'],observer['host_visibility_received_monotonic_ns'])
        self.assertLessEqual(observer['host_visibility_received_monotonic_ns'],observer['host_started_monotonic_ns'])
        self.assertEqual((self.frames/'minimal.ppm').read_bytes(),self.data)

    def test_duplicate_arm_or_visibility_cannot_recapture(self):
        self.arm()
        with self.assertRaises(ValueError):self.arm()
        self.capture()
        with self.assertRaises(ValueError):self.capture()
        self.assertEqual(len(self.calls),1)

    def test_foreign_or_stale_geometry_cannot_trigger_accepted_capture(self):
        self.arm();original=copy.deepcopy(self.visible)
        for key,value in [('pid',999),('alpha',.5)]:
            self.visible=copy.deepcopy(original);self.visible['visibility']['mako'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.capture()
        self.visible=copy.deepcopy(original);self.visible['visibility']['realtime_us']=1
        with self.assertRaises(ValueError):self.capture()
        self.assertFalse(self.calls)

    def test_bad_request_or_live_notification_join_cannot_trigger_capture(self):
        self.arm();original=copy.deepcopy(self.visible)
        self.visible['capture_request_sha256']='bad'
        with self.assertRaises(ValueError):self.capture()
        self.visible=copy.deepcopy(original);self.visible['visibility']['notification']['body']='other'
        with self.assertRaises(ValueError):self.capture()
        self.assertFalse(self.calls)

    def test_one_first_diagnostic_survives_missing_visibility_failure(self):
        self.arm();P.capture_pending_failure(self.qmp,self.fixture,self.frames,self.report,self.decode)
        self.assertEqual(len(self.calls),1);self.assertEqual((self.frames/'minimal.ppm').read_bytes(),self.data)
        self.assertEqual(self.report['frames']['minimal']['observer']['diagnostic_only'],'NO_ACCEPTED_FRESH_VISIBILITY')
        P.capture_pending_failure(self.qmp,self.fixture,self.frames,self.report,self.decode)
        self.assertEqual(len(self.calls),1)

    def test_rgb_failure_keeps_first_original_and_cannot_recapture(self):
        self.arm();self.pixels.update(status='FAIL_NOTIFICATION_PIXELS_ABSENT',counts=dict(background=0,border=0,text=0))
        self.capture()
        self.assertEqual((self.frames/'minimal.ppm').read_bytes(),self.data)
        with self.assertRaisesRegex(P.PixelPresenceFailure,'no shipped Mako'):P.raise_deferred_capture_failure(self.report)
        with self.assertRaises(ValueError):self.capture()
        self.assertEqual(len(self.calls),1)

    def test_waiting_for_readiness_uses_original_five_second_total(self):
        import time
        self.arm();self.report['capture_requests']['minimal']['host_received_monotonic_ns']=time.monotonic_ns()-6_000_000_000
        with self.assertRaisesRegex(ValueError,'five-second observation budget'):self.capture()
        self.assertEqual(len(self.calls),1);self.assertTrue((self.frames/'minimal.ppm').is_file())

    def test_old_capture_before_visibility_order_cannot_pass(self):
        events=Protocol().fixture();visible=next(e for e in events if e.get('event')=='frame_visibility');captured=next(e for e in events if e.get('event')=='frame_captured')
        a,b=events.index(visible),events.index(captured);events[a],events[b]=events[b],events[a]
        with self.assertRaises(ValueError):C.verify_result(events)

    def test_diagnostic_or_missing_host_readiness_proof_never_passes(self):
        for change in ({'diagnostic_only':'NO_ACCEPTED_FRESH_VISIBILITY'},{'scheduled_visibility_sha256':'bad'},{'host_visibility_received_monotonic_ns':999999}):
            events=Protocol().fixture();next(e for e in events if e.get('event')=='frame_captured').update(change)
            with self.subTest(change=change),self.assertRaises(ValueError):C.verify_result(events)


class PresentationDiagnostics(unittest.TestCase):
    def test_only_visual_absence_waits_for_original_transport_then_still_fails(self):
        fixture=RenderSynchronization();fixture.setUp()
        try:
            fixture.arm();fixture.pixels.update(status='FAIL_NOTIFICATION_PIXELS_ABSENT',counts=dict(background=0,border=0,text=0))
            fixture.capture()
            reached=[];reached.append('original caller/bus/manager drain remains reachable')
            self.assertEqual(fixture.report['frames']['minimal']['observer']['notification_pixels']['status'],'FAIL_NOTIFICATION_PIXELS_ABSENT')
            self.assertEqual(fixture.report['deferred_capture_failures'][0]['scope'],'DIAGNOSTIC_DRAIN_ONLY_STILL_FAIL')
            with self.assertRaisesRegex(P.PixelPresenceFailure,'original first frame has no shipped Mako notification pixels'):
                P.raise_deferred_capture_failure(fixture.report)
            self.assertEqual(len(reached),1);self.assertEqual(len(fixture.calls),1)
        finally:fixture.doCleanups()

    def test_frame_identity_or_clock_errors_are_not_deferred(self):
        fixture=RenderSynchronization();fixture.setUp()
        try:
            fixture.arm();fixture.pixels['frame_sha256']='b'*64
            with self.assertRaises(ValueError):fixture.capture()
            self.assertFalse(fixture.report.get('deferred_capture_failures'))
        finally:fixture.doCleanups()

    def test_deferred_error_never_clears_or_changes_original_failure(self):
        report=dict(deferred_capture_failures=[dict(stage='minimal',error='original first frame has no shipped Mako notification pixels')])
        for _ in range(2):
            with self.assertRaisesRegex(P.PixelPresenceFailure,'no shipped Mako'):P.raise_deferred_capture_failure(report)
        self.assertEqual(len(report['deferred_capture_failures']),1)
        P.raise_deferred_capture_failure({})

    def test_diagnostics_cannot_turn_failed_pixels_into_metadata_pass(self):
        events=Protocol().fixture();observed=next(e for e in events if e.get('event')=='frame_captured')
        observed['notification_pixels'].update(status='FAIL_NOTIFICATION_PIXELS_ABSENT',counts=dict(background=0,border=0,text=0))
        next(e for e in events if e.get('event')=='done_transport')['diagnostics']=dict(scope='DIAGNOSTIC_ONLY',all_transport_collected=True)
        with self.assertRaisesRegex(P.PixelPresenceFailure,'no shipped Mako'):C.verify_result(events)

    def close(self,wire,reason=1,sender=':1.7',identifier=23,timestamp=5000000):
        return dict(type='signal',path='/org/freedesktop/Notifications',interface='org.freedesktop.Notifications',member='NotificationClosed',
                    sender=sender,**{'timestamp-realtime':timestamp},payload=dict(type='uu',data=[identifier,reason]))

    def test_matching_raw_closed_signal_and_same_guest_clock_delta_retained(self):
        wire=O.notify(messages(),':1.7',0);closed=self.close(wire)
        facts=O.closure_facts((json.dumps(closed)+'\n').encode(),wire)
        self.assertEqual(facts['matching_closed_signals'][0]['signal'],closed)
        self.assertEqual(facts['matching_closed_signals'][0]['notify_to_closed_realtime_us'],4000000)
        self.assertIn('NO_EXPIRY_OR_PRESENTATION_ACCEPTANCE',facts['scope'])

    def test_missing_foreign_or_other_id_signal_is_not_inferred_expiry(self):
        wire=O.notify(messages(),':1.7',0)
        for rows in ([],[self.close(wire,sender=':1.foreign')],[self.close(wire,identifier=99)]):
            raw=b'\n'.join(json.dumps(r).encode() for r in rows)
            facts=O.closure_facts(raw,wire)
            self.assertEqual(facts['status'],'NO_MATCHING_CLOSED_SIGNAL_OBSERVED')
            self.assertFalse(facts['matching_closed_signals'])

    def test_close_reason_is_preserved_raw_without_presentation_credit(self):
        wire=O.notify(messages(),':1.7',0);closed=self.close(wire,reason=999)
        facts=O.closure_facts(json.dumps(closed).encode(),wire)
        self.assertEqual(facts['matching_closed_signals'][0]['signal']['payload']['data'],[23,999])
        self.assertNotIn('PASS',facts['status'])

    def test_existing_normal_output_is_byte_exact_and_bounded(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            paths=[Path(directory)/name for name in ('normal.stdout','normal.stderr')]
            for path,raw in zip(paths,(b'existing normal compositor bytes',b'')):path.write_bytes(raw)
            result=S.normal_compositor_output(SimpleNamespace(paths=paths))
            self.assertIn('DIAGNOSTIC_ONLY',result['scope'])
            for path,record in zip(paths,result['streams']):
                self.assertEqual(base64.b64decode(record['raw_base64']),path.read_bytes())
                self.assertEqual(record['sha256'],hashlib.sha256(path.read_bytes()).hexdigest())
            paths[0].write_bytes(b'x'*(256*1024+1))
            with self.assertRaises(ValueError):S.normal_compositor_output(SimpleNamespace(paths=paths))

    def test_ordinary_wait_is_measured_without_new_sleep_or_selector(self):
        tree=ast.parse(Path(S.__file__).read_bytes())
        loop=next(n for n in ast.walk(tree) if isinstance(n,ast.While) and isinstance(n.test,ast.Compare) and ast.unparse(n.test)=='wire is None')
        text=ast.unparse(loop)
        self.assertIn('wait_iterations += 1',text);self.assertIn('healthy()',text);self.assertIn('O.notify(observer.rows()',text)
        self.assertNotIn('sleep',text)
        source=Path(S.__file__).read_text();self.assertIn('time.thread_time_ns()-wait_cpu_started_ns',source)
        self.assertIn("deadline=time.monotonic()+15",source)
        self.assertIn("while time.monotonic()<until:healthy();time.sleep(.1)",source)

    def test_host_failure_gate_is_before_any_metadata_acceptance(self):
        source=Path(P.__file__).with_name('prepare.py').read_text()
        self.assertIn("raise_deferred_capture_failure(report)\n",source.replace('\\n','\n'))
        self.assertIn("verify_result(report['events'])",source)
        self.assertIn('raise_deferred_capture_failure',source)
        self.assertIn('capture_ready(event,qmp,fixture,frames,report,ppm)',source)


class HostedProof(unittest.TestCase):
    def caller(self):
        spec=importlib.util.spec_from_file_location('done_hosted_control',HERE/'ci/caller.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

    def manifest(self):return json.loads((HERE/'ci/source-manifest.json').read_bytes())

    def test_all_source_and_generated_pins_match_actual_bytes(self):
        module=self.caller();manifest=self.manifest();runner=Path(os.environ['DONE_MANAGED_PREPARED_RUNNER'])
        module.verify_files(ROOT,manifest['files']);module.verify_files(runner,manifest['generated_runner'])
        actual={str(p.relative_to(runner)) for p in runner.rglob('*') if p.is_file() and '__pycache__' not in p.parts}
        self.assertEqual(set(manifest['generated_runner']),actual)
        self.assertFalse(any('__pycache__' in n or n.endswith('.pyc') for n in manifest['files']))

    def test_hosted_source_proof_is_only_identity_data(self):
        environment=dict(SOURCE_SHA='a'*40,GITHUB_SHA='a'*40,GITHUB_WORKFLOW_SHA='a'*40,RUNNER_ARCH='ARM64',RUNNER_OS='Linux',GITHUB_RUN_ID='1',GITHUB_RUN_ATTEMPT='1')
        with patch.object(subprocess,'Popen',side_effect=AssertionError('actor')):
            result=self.caller().prove(ROOT,self.manifest(),environment)
        self.assertEqual(result['status'],'SOURCE_PROOF_PASS')
        self.assertEqual(result['module_ref'],'de35c384a2e5b14b664d4156897f271b81e467ba')
        self.assertIs(result['mako_wayland_protocol_probe'],packet.diagnostic_policy()['mako_wayland_protocol_probe'])

    def test_source_workflow_disagreement_refused_before_file_or_packet_reads(self):
        module=self.caller();environment=dict(SOURCE_SHA='a'*40,GITHUB_SHA='a'*40,GITHUB_WORKFLOW_SHA='b'*40)
        with patch.object(module,'verify_files',side_effect=AssertionError('too late')),self.assertRaisesRegex(ValueError,'revision must agree'):
            module.prove(ROOT,{},environment)

    def test_stale_generated_file_refused(self):
        module=self.caller();manifest=self.manifest();runner=Path(os.environ['DONE_MANAGED_PREPARED_RUNNER'])
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp)/'desktop574_runtime.py';target.write_bytes((runner/target.name).read_bytes()+b'\n')
            with self.assertRaisesRegex(ValueError,'source pin differs'):
                module.verify_files(Path(tmp),{target.name:manifest['generated_runner'][target.name]})


class Data(unittest.TestCase):
    def test_original_native_pair_stages_without_actors_or_rebuild(self):
        with tempfile.TemporaryDirectory() as tmp,patch.object(subprocess,'Popen',side_effect=AssertionError('native actor')):
            result=packet.stage(ROOT,MODULES,Path(tmp)/'done')
        self.assertEqual(result['version'],'0.1.0-2');self.assertEqual(len(result['payload']),8)
        self.assertEqual(result['native_run'],38921031485)

    def test_changed_input_index_refused_before_inspection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'index.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'packet index'):packet.stage(ROOT,root,root/'done')
            self.assertFalse((root/'done').exists())

    def test_input_policy_no_unknown_or_unbound_packet(self):
        original=json.loads((HERE/'input-policy.json').read_bytes());original['status']='UNBOUND'
        with patch.object(packet,'read',return_value=json.dumps(original).encode()),self.assertRaises(ValueError):packet.policy()

    def test_shared_manager_capture_and_bar_helpers_unchanged(self):
        for name,original in (('bar_helpers.py','desktop-bar-notifications/session.py'),('managed_session.py','desktop-user-session/managed_session.py'),('managed_contract.py','desktop-user-session/managed_contract.py')):
            self.assertEqual((HERE/name).read_bytes(),(ROOT/'scripts/ci'/original).read_bytes(),name)

    def test_pty_uses_installed_opt_in_default_threshold_and_real_transport(self):
        text=(HERE/'fish_terminal.py').read_text()
        self.assertIn('source /usr/share/cachy-asahi/fish-done/opt-in.fish',F.INIT)
        self.assertNotIn('caa_done_min_duration',F.INIT)
        self.assertFalse(any(line.strip().startswith('__done_notify') for line in F.INIT.splitlines()))
        self.assertIn("'--interactive'",text);self.assertIn("'/usr/bin/fish'",text)
        self.assertIn('notify-send) = /usr/bin/notify-send',F.INIT)
        self.assertEqual(set(F.COMMANDS),{0,7});self.assertTrue(all('5.25' in c for c in F.COMMANDS.values()))

    def test_phase_never_sends_a_fixture_notify_or_uses_logging_startup(self):
        tree=ast.parse((HERE/'session.py').read_bytes())
        calls=[n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id=='dbus']
        self.assertFalse(any(any(isinstance(a,ast.Constant) and a.value=='Notify' for a in c.args) for c in calls))
        self.assertIn('monitor.Monitor(selected)',(HERE/'session.py').read_text())
        self.assertNotIn("selected['G_DBUS_DEBUG']",(HERE/'session.py').read_text())

    def test_generated_runner_closes_source_and_preserves_resource_bounds(self):
        runner=Path(os.environ['DONE_MANAGED_PREPARED_RUNNER'])
        for p in runner.glob('*.py'):ast.parse(p.read_bytes())
        subprocess.run(['bash','-n',runner/'desktop574_fixture.sh'],check=True,capture_output=True)
        text=(runner/'desktop574_runtime.py').read_text()
        self.assertIn('done.pkg.tar.xz && ldconfig',text)
        self.assertLess(text.index('done.pkg.tar.xz && ldconfig'),text.index("execute(cmd + ['/runner/desktop574_fixture.sh']"))
        for marker in ('deadline = time.monotonic() + 900','signal.setitimer(signal.ITIMER_REAL, 1750)','format=raw,snapshot=on','-accel tcg -cpu max -smp 2 -m 4096'):
            self.assertIn(marker,text)
        self.assertNotIn('notify_recorder',text);self.assertNotIn('done-check',text)
        self.assertEqual(json.loads((runner/'done-lock.json').read_text())['native_run'],38921031485)

    def test_new_files_parse(self):
        for p in HERE.rglob('*.py'):ast.parse(p.read_bytes())

    def test_manual_workflow_preserves_owners_and_uses_bound_packet(self):
        text=(HERE.parents[2]/'.github/workflows/native-arm-fish-done-managed-notifications.yml').read_text()
        self.assertIn('workflow_dispatch:',text);self.assertNotIn('inputs.trace_waybar',text)
        self.assertNotIn('\n  push:',text);self.assertNotIn('\n  schedule:',text)
        self.assertIn('de35c384a2e5b14b664d4156897f271b81e467ba',text)
        self.assertLess(text.index('caller.py" proof'),text.index('secrets.CACHY_'))
        self.assertIn('2050s',text);self.assertIn('maintained_desktop574.py cleanup',text)


if __name__=='__main__':unittest.main()
