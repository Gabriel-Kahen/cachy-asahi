"""Inert controls: no clients, compositor, package or VM actors are executed."""
import copy
import importlib.util
import json
from pathlib import Path
import signal
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import contract
import prepare
import session


def row(namespace='waybar', pid=102):
    return dict(namespace=namespace, pid=pid, x=0, y=0, w=1024, h=28, alpha=1)


def layer(value):
    return {'Virtual-1': {'levels': {'2': [value]}}}


def managed_events(events):
    identity=dict(address='unix:path=/run/user/23001/bus',uid=23001,manager_pid=777,default_target='GetUnit-PASS')
    def unit(name,active,substate,pid):
        return dict(Id=name,LoadState='loaded',ActiveState=active,SubState=substate,Result='success',ExecMainStatus=0,MainPID=pid)
    units={name:unit(name,'active',sub,pid) for name,sub,pid in (
        ('systemd-user-sessions.service','exited',0),('user-runtime-dir@23001.service','exited',0),('user@23001.service','running',777))}
    result=[dict(event='managed_session_ready',status='PASS',units=units,**identity),
            dict(event='managed_user_ready',status='PASS',**identity)]
    for event in copy.deepcopy(events):
        if event.get('event')=='frame_ready':
            event.update(managed_identity=identity,activation='normal-shipped-config-no-reload',notification_timeout_ms=0,compositor_pid=3,
                activation_environment=dict(values=dict(WAYLAND_DISPLAY='wayland-1',HYPRLAND_INSTANCE_SIGNATURE='fixture_'+event['stage'],
                    XDG_SESSION_TYPE='wayland',XDG_CURRENT_DESKTOP='Hyprland'),manager_pid=777,systemd_verified=True,dbus_updated=True))
        result.append(event)
        if event.get('event')=='frame_ready':
            result.append(dict(event='frame_captured',stage=event['stage'],request_sha256=contract.request_digest(event),
                first_capture=True,capture_ms=20,sha256='a'*64,managed_identity=identity,visual_review='NOT_RUN'))
    stopped=['user@23001.service','user-runtime-dir@23001.service']
    result.extend([dict(event='managed_session_cleanup',status='PASS',runtime_absent=True,owned_units_stopped=True,units=stopped,
        unit_states={n:unit(n,'inactive','dead',0) for n in stopped}),dict(event='complete',status='PASS')])
    return result


class DataTests(unittest.TestCase):
    def test_layer_requires_unique_pid_namespace_positive_onscreen_geometry(self):
        self.assertIsNotNone(session.owned_layer(layer(row()), 'waybar', 102))
        for change in (dict(pid=True), dict(pid=99), dict(w=-1), dict(x=-1),
                       dict(w=1025), dict(h=2), dict(alpha=float('nan'))):
            with self.subTest(change=change), self.assertRaises(ValueError):
                session.owned_layer(layer(row() | change), 'waybar', 102)
        duplicate = layer(row());duplicate['Virtual-1']['levels']['2'].append(row())
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            session.owned_layer(duplicate, 'waybar', 102)

    def test_transitional_layer_is_not_capture_ready(self):
        for change in (dict(alpha=.5), dict(w=0), dict(h=0)):
            self.assertIsNone(session.owned_layer(layer(row() | change), 'waybar', 102))
        self.assertIsNone(session.owned_layer({}, 'waybar', 102))

    def test_mako_layer_namespace_matches_pinned_wayland_source(self):
        text=(Path(__file__).parent/'upstream/mako-wayland.c').read_text()
        self.assertIn('surface->layer, "notifications"',text)
        self.assertEqual(session.MAKO_NAMESPACE,'notifications')

    def test_layer_shape_rejects_malformed_and_background_surfaces(self):
        for value in ([], {'m': {}}, {'m': {'levels': {'2': {}}}}):
            with self.assertRaises(ValueError):session.layer_rows(value)
        value={'m': {'levels': {'0': [row()]}}}
        with self.assertRaises(ValueError):session.owned_layer(value,'waybar',102)

    def test_notification_identity_payload_and_duplicates(self):
        value=dict(id=2, app_name=session.APP, summary=session.SUMMARY, body=session.BODY)
        self.assertEqual(session.notifications([value],2),value)
        for wrong in ([],[value,value],[value | dict(body='other')],[value | dict(id=True)]):
            with self.assertRaises(ValueError):session.notifications(wrong,2)

    def test_bus_reply_requires_nonzero_uint(self):
        self.assertEqual(session.uint_reply('u 23\n'),23)
        for text in ('u 0','u -1','b true','u 4294967296','u 2 extra'):
            with self.assertRaises(ValueError):session.uint_reply(text)

    def test_private_config_snapshot_preserves_symlink_and_detects_content_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'custom').write_text('keep');(root/'alias').symlink_to('custom')
            before=session.snapshot(root)
            self.assertEqual(before['alias']['target'],'custom')
            self.assertEqual(session.snapshot(root),before)
            (root/'custom').write_text('changed')
            self.assertNotEqual(session.snapshot(root),before)

    def test_finite_readiness_never_accepts_late_probe_success(self):
        with patch.object(session.time,'monotonic',side_effect=[0,1,4]):
            with self.assertRaisesRegex(ValueError,'deadline'):
                session.wait_ready(lambda:True,lambda:None,3,'probe')

    def test_source_drift_and_fresh_stage_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'source').write_text('one')
            pins={'source':contract.digest(root/'source')}
            contract.verify_source(root,pins)
            (root/'source').write_text('two')
            with self.assertRaisesRegex(ValueError,'differs'):contract.verify_source(root,pins)
        with self.assertRaisesRegex(ValueError,'fresh stage'):
            with patch.object(prepare,'verify_source'):
                prepare.prepare(Path('/inert'),Path(__file__).parent)

    def test_package_input_rejects_missing_version_replacement_and_duplicates(self):
        proposal=dict(closure_packages=[dict(name='waybar',version='1')],additional_packages=[],replacement_packages=[])
        contract.verify_package_input(proposal,dict(waybar='1'))
        with self.assertRaises(ValueError):contract.verify_package_input(proposal,dict(waybar='2'))
        for field in ('additional_packages','replacement_packages','closure_packages'):
            value=copy.deepcopy(proposal);value[field].append(dict(name='waybar',version='1'))
            with self.assertRaises(ValueError):contract.verify_package_input(value,dict(waybar='1'))

    def test_old_591_result_is_not_new_client_acceptance(self):
        events=[]
        for stage in ('minimal','overlay'):
            events += [dict(event='frame_ready',stage=stage),dict(event='phase_pass',stage=stage)]
        with self.assertRaises(ValueError):contract.verify_result(events)

    def test_new_result_needs_two_phases_and_preserved_config(self):
        events=[]
        for stage in ('minimal','overlay'):
            events += [dict(event='frame_ready',stage=stage,
                bar=row(pid=1)|dict(monitor='Virtual-1',level='2'),
                mako=row('notifications',2)|dict(monitor='Virtual-1',level='3',x=684,y=40,w=330,h=100),
                notification=dict(id=7,app_name=session.APP,summary=session.SUMMARY,body=session.BODY),
                waybar_pid=1,mako_pid=2,capture_after_ms=5000),
                dict(event='phase_pass',stage=stage,waybar='PASS',mako='PASS',config_preserved=True)]
        events.append(dict(event='session_pass',status='PASS',waybar='PASS',mako='PASS'))
        events=managed_events(events)
        contract.verify_result(events)
        for mutation in ('duplicate','configuration','session','owner','hidden'):
            value=copy.deepcopy(events)
            if mutation=='duplicate':value.append(value[0])
            elif mutation=='configuration':next(e for e in value if e.get('event')=='phase_pass')['config_preserved']=1
            elif mutation=='session':next(e for e in value if e.get('event')=='session_pass')['mako']='NOT_RUN'
            elif mutation=='owner':next(e for e in value if e.get('event')=='frame_ready')['mako']['pid']=22
            else:next(e for e in value if e.get('event')=='frame_ready')['bar']['alpha']=.5
            with self.assertRaises(ValueError):contract.verify_result(value)


class FakeProcess:
    def __init__(self,pid):self.pid=pid;self.returncode=None
    def poll(self):return self.returncode
    def wait(self,timeout):
        if self.returncode is None:raise AssertionError('wait on unretired fake process')
        return self.returncode


class PhaseTests(unittest.TestCase):
    def setUp(self):
        observer=patch.object(session,'process_observation',return_value=dict(scope='MOCKED_OWNED_PROCESS'))
        observer.start();self.addCleanup(observer.stop)
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.config=self.root/'config';self.config.mkdir()
        (self.config/'user').write_text('preserve')
        self.processes=[];self.emitted=[];self.commands=[];self.notice=False;self.ticks=0
        self.bad_environment=False;self.bad_activation_reply=False;self.activation_values={};self.wrong_owner=False;self.bad_payload=False;self.bad_stop=False;self.mutate=False;self.bad_finish=False
        self.helper=SimpleNamespace(Logged=self.launch,command=self.command,ipc=lambda *a:dict(a[2],HYPRLAND_INSTANCE_SIGNATURE='fixture_instance'),
            usable_monitors=lambda x:True,emit=lambda name,**data:self.emitted.append(dict(event=name,**data)),
            terminate=self.terminate,RUNTIME=Mock())
        socket=Mock();socket.is_socket.return_value=True;socket.name='wayland-1'
        self.helper.RUNTIME.glob.side_effect=lambda _: [] if not self.processes else [socket]

    def launch(self,argv,name,logs,env):
        item=SimpleNamespace(argv=argv,name=name,process=FakeProcess(101+len(self.processes)),env=dict(env),command_count=len(self.commands))
        item.healthy=lambda: self.assertIsNone(item.process.returncode)
        def finish():
            self.assertIsNotNone(item.process.returncode)
            item.finished=True
            if self.bad_finish:raise RuntimeError('secondary finish fault')
        item.finish=finish;item.finished=False;self.processes.append(item);return item

    def terminate(self,process):
        if process.poll() is None:process.returncode=-15
        return process.returncode

    def signal(self,pid,sig):
        item=next(p for p in self.processes if p.process.pid==pid)
        item.process.returncode=-2 if self.bad_stop and sig==signal.SIGINT else 0

    def now(self):self.ticks+=.1;return self.ticks

    def sleep(self,seconds):self.ticks+=seconds

    def command(self,argv,env,logs,name,timeout):
        self.commands.append(argv)
        if argv[:3]==['/usr/bin/systemctl','--user','set-environment']:
            self.activation_values=dict(x.split('=',1) for x in argv[3:]);return ''
        if argv[:3]==['/usr/bin/systemctl','--user','show-environment']:
            values=self.activation_values|({'WAYLAND_DISPLAY':'stale'} if self.bad_environment else {})
            return ''.join(k+'='+v+'\n' for k,v in values.items())
        if 'UpdateActivationEnvironment' in argv:
            fields=argv[argv.index('a{ss}')+1:]
            self.assertEqual(fields[0],'4');self.assertEqual(dict(zip(fields[1::2],fields[2::2])),self.activation_values)
            return 'unexpected' if self.bad_activation_reply else ''
        if argv[0]=='/usr/bin/hyprctl':
            if 'monitors' in argv:return json.dumps([dict(width=1024,height=768,scale=1)])
            if 'layers' in argv:
                rows=[]
                for item in self.processes[1:]:
                    namespace='waybar' if 'waybar' in item.name else session.MAKO_NAMESPACE
                    if item.process.poll() is None and (namespace=='waybar' or self.notice):
                        value=row(namespace,item.process.pid)
                        if namespace==session.MAKO_NAMESPACE:value.update(x=684,y=40,w=330,h=100)
                        rows.append(value)
                return json.dumps({'Virtual-1':{'levels':{'2':rows}}})
            if 'dispatch' in argv:
                self.processes[0].process.returncode=0;return 'ok\n'
        if argv[0]=='/usr/bin/makoctl':
            return json.dumps([dict(id=7,app_name=session.APP,summary=session.SUMMARY,
                body='wrong' if self.bad_payload else session.BODY)] if self.notice else [])
        if 'NameHasOwner' in argv:
            return 'b true\n' if len(self.processes)>2 and self.processes[2].process.poll() is None else 'b false\n'
        if 'GetConnectionUnixProcessID' in argv:
            return 'u '+str(666 if self.wrong_owner else self.processes[2].process.pid)+'\n'
        if 'Notify' in argv:
            self.notice=True
            if self.mutate:(self.config/'user').write_text('clobbered')
            return 'u 7\n'
        if 'CloseNotification' in argv:self.notice=False;return ''
        raise AssertionError(argv)

    def run_phase(self,trace_waybar=False):
        with patch.object(session,'base',self.helper),patch.object(session.os,'killpg',self.signal),\
             patch.object(session.time,'monotonic',self.now),patch.object(session.time,'sleep',self.sleep),\
             patch.dict(session.os.environ,{'CACHY_MANAGED_MANAGER_PID':'777'}),\
             patch.object(session.managed,'bus_probe',return_value=dict(address=session.managed.ADDRESS,uid=23001,manager_pid=777,default_target='GetUnit-PASS')):
            session.phase('minimal',Path('/explicit.lua'),dict(XDG_CONFIG_HOME=str(self.config),XDG_RUNTIME_DIR=str(session.managed.RUNTIME),DBUS_SESSION_BUS_ADDRESS=session.managed.ADDRESS),self.root,trace_waybar=trace_waybar)

    def assert_retired(self):
        self.assertTrue(all(p.process.poll() is not None and p.finished for p in self.processes))

    def test_full_owned_lifecycle_capture_dismissal_clean_stops_and_preservation(self):
        self.run_phase();self.assert_retired()
        self.assertEqual([p.process.returncode for p in self.processes],[0,0,0])
        self.assertEqual([e['event'] for e in self.emitted],['frame_ready','phase_pass'])
        self.assertGreaterEqual(self.emitted[0]['capture_after_ms'],5000)
        self.assertTrue(self.emitted[-1]['config_preserved'])
        self.assertEqual((self.config/'user').read_text(),'preserve')
        self.assertEqual(len([c for c in self.commands if c[0]=='/usr/bin/systemctl']),2)
        self.assertEqual(self.emitted[0]['activation_environment']['values'],self.activation_values)
        self.assertIn('--config',self.processes[1].argv)
        self.assertEqual(self.processes[1].argv[-1],str(session.TEMPLATES/'waybar.css'))
        self.assertGreater(self.ticks,13)

    def test_activation_environment_is_verified_before_any_bar_or_mako_launch(self):
        self.run_phase();self.assert_retired()
        updated=[i for i,c in enumerate(self.commands) if c[0]=='/usr/bin/systemctl' or 'UpdateActivationEnvironment' in c]
        self.assertEqual(len(updated),3);self.assertLess(max(updated),self.processes[1].command_count)
        self.assertEqual(self.activation_values['WAYLAND_DISPLAY'],'wayland-1')

    def test_stale_manager_environment_fails_before_clients_and_cleans_compositor(self):
        self.bad_environment=True
        with self.assertRaisesRegex(ValueError,'managed activation environment differs'):self.run_phase()
        self.assert_retired();self.assertEqual(len(self.processes),1);self.assertEqual([e['event'] for e in self.emitted],['bar_phase_diagnostic'])

    def test_bad_activation_reply_fails_before_clients_and_preserves_failure(self):
        self.bad_activation_reply=True
        with self.assertRaisesRegex(ValueError,'D-Bus activation update reply differs'):self.run_phase()
        self.assert_retired();self.assertEqual(len(self.processes),1);self.assertEqual([e['event'] for e in self.emitted],['bar_phase_diagnostic'])

    def test_foreign_notification_owner_refuses_and_retires_all(self):
        self.wrong_owner=True
        with self.assertRaisesRegex(ValueError,'foreign notification owner'):self.run_phase()
        self.assert_retired();self.assertEqual([e['event'] for e in self.emitted],['bar_phase_diagnostic'])

    def test_changed_notification_payload_refuses_and_retires_all(self):
        self.bad_payload=True
        with self.assertRaisesRegex(ValueError,'payload differs'):self.run_phase()
        self.assert_retired();self.assertEqual([e['event'] for e in self.emitted],['bar_phase_diagnostic'])

    def test_secondary_observation_failure_preserves_original_and_all_retirement(self):
        self.bad_payload=True
        with patch.object(session,'failure_observation',side_effect=RuntimeError('secondary diagnostic failure')):
            with self.assertRaisesRegex(ValueError,'notification payload differs'):self.run_phase()
        self.assert_retired();self.assertEqual(self.emitted,[])

    def test_unclean_client_stop_is_not_phase_pass(self):
        self.bad_stop=True
        with self.assertRaisesRegex(ValueError,'did not exit cleanly'):self.run_phase()
        self.assert_retired();self.assertNotIn('phase_pass',[e['event'] for e in self.emitted])

    def test_configuration_change_is_detected_after_all_retirements(self):
        self.mutate=True
        with self.assertRaisesRegex(ValueError,'configuration changed'):self.run_phase()
        self.assert_retired();self.assertNotIn('phase_pass',[e['event'] for e in self.emitted])

    def test_first_failure_survives_log_finish_failure_and_remaining_cleanup_runs(self):
        self.wrong_owner=True;self.bad_finish=True
        with self.assertRaisesRegex(ValueError,'foreign notification owner'):self.run_phase()
        self.assert_retired()


if __name__=='__main__':unittest.main()
