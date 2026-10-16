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

HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ.get('DONE_MANAGED_SOURCE_ROOT',Path.cwd())).resolve()
MODULES=Path(os.environ.get('DONE_MANAGED_INPUTS',ROOT/'artifacts/development/setup5-six-module-inputs-20261016/payload')).resolve()


def messages(outcome=0,kind='Foreground command'):
    title='Done in 5s' if outcome==0 else 'Failed (7) after 5s'
    call=dict(type='method_call',sender=':1.9',destination='org.freedesktop.Notifications',path='/org/freedesktop/Notifications',interface='org.freedesktop.Notifications',member='Notify',cookie=42,
              payload=dict(type='susssasa{sv}i',data=['fish',0,'',title,kind+' completed.',[],{'image-path':{'type':'s','data':'utilities-terminal'},'urgency':{'type':'y','data':1 if outcome==0 else 2},'transient':{'type':'i','data':1}},3000]))
    reply=dict(type='method_return',sender=':1.7',destination=':1.9',reply_cookie=42,payload=dict(type='u',data=[23]))
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
            caller=dict(pid=205,outcome=outcome,prompt_status=outcome,caller_continuation=outcome)
            frame=dict(event='frame_ready',stage=stage,case=case,outcome=outcome,managed_identity=identity,activation='normal-shipped-config-no-reload',trace_waybar=False,notification_timeout_ms=3000,notification_age_ms=100,capture_after_ms=5000,activation_environment=activation,compositor_pid=201,waybar_pid=202,mako_pid=203,fish_pid=205,bar=row('waybar',202,0,0,1024,30),mako=row('notifications',203,650,40,300,100),wire=wire,notification={k:wire[k] for k in ('id','app_name','summary','body')},recipient=dict(service='org.freedesktop.Notifications',unique=':1.7',pid=203,owner_reply='s ":1.7"'),caller=caller,installed=installed)
            raw=b'\n'.join(json.dumps(r).encode() for r in messages(outcome,kind))+b'\n';pty=('FDM_PROMPT_2_'+str(outcome)+'\nFDM_CONT_'+str(outcome)).encode()
            if stage=='background':
                child=dict(pid=206,parent_pid=205,process_group=206,start_ticks=1234,executable='/usr/bin/sleep',argv=['sleep','8'])
                caller.update(command=F.BACKGROUND_COMMAND,watch=dict(child=child,registration_status=0,handler_registered=True,caller_before_completion=True))
                pty=b'\nFDM_WATCH_206_0\n'+pty+b'\nFDM_BG_RETIRED_206\n'
            events.extend([frame,dict(event='frame_captured',stage=stage,first_capture=True,request_sha256=C.request_digest(frame),managed_identity=identity,visual_review='NOT_RUN',capture_ms=20),dict(event='done_transport',stage=stage,case=case,wire=wire,caller=caller,monitor=dict(raw_base64=base64.b64encode(raw).decode(),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),exit=0),fish=dict(exit=0,pty_base64=base64.b64encode(pty).decode(),pty_bytes=len(pty),pty_sha256=hashlib.sha256(pty).hexdigest()),mako_exit=0,payload_preserved=True,user_config_preserved=True),dict(event='phase_pass',stage=stage,case=case,config_preserved=True,fish='PASS')])
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
        events=self.events();frame=next(e for e in events if e.get('stage')=='background' and e['event']=='frame_ready')
        frame['caller'].pop('watch')
        with self.assertRaises((ValueError,KeyError)):C.verify_result(events)

    def test_actual_handler_pid_group_and_child_must_retire(self):
        for key in ('handler_absent','pid_absent','process_group_absent'):
            events=self.events();row=next(e for e in events if e.get('stage')=='background' and e['event']=='done_transport')
            row['fish']['watch_retirement'][key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):C.verify_result(events)

    def test_child_cannot_be_fish_or_foreign_or_wrong_executable(self):
        for key,value in (('pid',205),('parent_pid',999),('process_group',205),('executable','/tmp/notify-shim'),('argv',['sleep','0.1']),('start_ticks',0)):
            events=self.events();frame=next(e for e in events if e.get('stage')=='background' and e['event']=='frame_ready')
            frame['caller']['watch']['child'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):C.verify_result(events)

    def test_no_caller_continuation_after_completion_can_claim_live_job(self):
        events=self.events();frame=next(e for e in events if e.get('stage')=='background' and e['event']=='frame_ready')
        frame['caller']['watch']['caller_before_completion']=False
        with self.assertRaises(ValueError):C.verify_result(events)

    def test_raw_watch_marker_binds_one_successful_exact_pid(self):
        self.assertEqual(F.watched_pid(b'\nFDM_WATCH_206_0\n'),206)
        self.assertEqual(F.retired_pid(b'\nFDM_BG_RETIRED_206\n'),206)
        with self.assertRaises(ValueError):F.retired_pid(b'\nFDM_BG_RETIRED_206\nFDM_BG_RETIRED_207\n')
        for raw in (b'FDM_WATCH_%s_%s',b'\nFDM_WATCH_206_7\n',b'\nFDM_WATCH_206_0\nFDM_WATCH_207_0\n'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):F.watched_pid(raw)

    def test_registration_and_retirement_markers_cannot_be_reordered_or_rebound(self):
        events=self.events();frame=next(e for e in events if e.get('stage')=='background' and e['event']=='frame_ready')
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

    def test_capture_only_adds_one_background_stage_to_original_helper(self):
        text=(HERE/'capture.py').read_text().replace("('minimal', 'overlay', 'background')","('minimal', 'overlay')")
        self.assertEqual(text,(ROOT/'scripts/ci/desktop-bar-notifications/capture.py').read_text())

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
