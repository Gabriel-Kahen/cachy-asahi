"""Inert unit/identity/lifecycle controls; never touch host services or users."""
import ast
from contextlib import ExitStack
import copy
import importlib.util
import json
import itertools
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
from types import ModuleType
import unittest
from unittest.mock import Mock, MagicMock, patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


m = load('managed_controls_api', HERE / 'managed_session.py')
c = load('managed_controls_contract', HERE / 'managed_contract.py')
p = load('managed_controls_prepare', HERE / 'prepare.py')


def row(unit, state='inactive', sub='dead', pid=0):
    return dict(Id=unit, LoadState='loaded', ActiveState=state, SubState=sub,
                Result='success', MainPID=pid, ExecMainCode=0, ExecMainStatus=0)


class Backend:
    def __init__(self):
        self.events, self.commands = [], []
        self.started, self.stopped = False, False
        self.fail = False
        self.preexisting = False
        self.bus_uid, self.bus_pid = m.UID, 422
        self.owner, self.owner_replies = True, [True]
        self.target = 'o "/org/freedesktop/systemd1/unit/default_2etarget"\n'

    def emit(self, event, **values):
        self.events.append(dict(event=event, **values))

    def command(self, argv, env, logs, label, timeout):
        self.commands.append((argv, env, label, timeout))
        if 'show' in argv:
            unit = argv[argv.index('--no-pager') + 1]
            if unit == m.SESSIONS:
                value = row(unit, 'active', 'exited')
            elif self.started and not self.stopped or self.preexisting:
                value = row(unit, 'active', 'running' if unit == m.USER else 'exited',
                            422 if unit == m.USER else 0)
                if self.fail and unit == m.USER:
                    value.update(ActiveState='failed', SubState='failed', ExecMainStatus=224)
            else:
                value = row(unit)
            return ''.join(f'{key}={value[key]}\n' for key in m.PROPERTIES)
        if 'start' in argv:
            self.started = True
            return ''
        if 'stop' in argv:
            self.stopped = True
            return ''
        if 'NameHasOwner' in argv:
            self.owner = self.owner_replies.pop(0) if len(self.owner_replies) > 1 else self.owner_replies[0]
            return 'b ' + str(self.owner).lower() + '\n'
        if 'GetConnectionUnixUser' in argv:
            if not self.owner: raise ValueError('Call failed: The connection does not exist')
            return 'u ' + str(self.bus_uid) + '\n'
        if 'GetConnectionUnixProcessID' in argv:
            return 'u ' + str(self.bus_pid) + '\n'
        if 'GetUnit' in argv:
            return self.target
        if argv[0] == '/usr/bin/journalctl':
            return 'bounded fixture journal\n'
        raise AssertionError('unmodeled command: ' + repr(argv))


class Managed(unittest.TestCase):
    def setUp(self):
        self.base = Backend()
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(m, 'guard'))
        self.nodes = self.stack.enter_context(patch.object(m, 'runtime_nodes'))
        self.stack.enter_context(patch.object(m.os.path, 'lexists',
            side_effect=lambda path: str(path) == str(m.RUNTIME) and self.base.started and not self.base.stopped))
        self.manager = m.ManagedSession(self.base, Path('/inert/logs'), {'PATH': '/usr/bin'})

    def test_real_managed_bus_pid_uid_and_exact_systemd_call_required(self):
        env = self.manager.start()
        self.assertEqual(env['DBUS_SESSION_BUS_ADDRESS'], m.ADDRESS)
        self.assertEqual(env['XDG_RUNTIME_DIR'], '/run/user/23001')
        self.assertEqual(env['CACHY_MANAGED_MANAGER_PID'], '422')
        calls = [argv for argv, _, _, _ in self.base.commands if '/usr/bin/busctl' in argv]
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(argv[:len(m.SETPRIV)] == m.SETPRIV for argv in calls))
        self.assertTrue(all('--address=' + m.ADDRESS in argv and '--auto-start=no' in argv for argv in calls))
        self.manager.stop()
        self.assertFalse(self.manager.owned)
        self.assertEqual([e['event'] for e in self.base.events], ['managed_session_ready', 'managed_session_cleanup'])
        self.assertTrue(self.base.events[-1]['runtime_absent'])

    def test_failed_pam_manager_refuses_then_disposes_owned_attempt(self):
        self.base.fail = True
        with self.assertRaisesRegex(ValueError, 'managed unit failed'):
            self.manager.start()
        self.assertTrue(self.manager.owned)
        self.manager.diagnose(); self.manager.diagnose()
        self.assertEqual(len([e for e in self.base.events if e['event'] == 'managed_session_diagnostic']), 1)
        self.assertEqual(len([a for a, *_ in self.base.commands if a[0] == '/usr/bin/journalctl']), 1)
        self.manager.stop()
        self.assertTrue(self.base.stopped)
        self.assertNotIn('managed_session_ready', [e['event'] for e in self.base.events])

    def test_manager_active_before_bus_name_registration_waits_then_checks_identity(self):
        self.base.owner = False
        self.base.owner_replies = [False,True]
        with patch.object(m.time,'sleep'):
            env = self.manager.start()
        calls = [argv for argv, *_ in self.base.commands if '/usr/bin/busctl' in argv]
        methods = [next(name for name in ('NameHasOwner','GetConnectionUnixUser',
                   'GetConnectionUnixProcessID','GetUnit') if name in argv) for argv in calls]
        self.assertEqual(methods,['NameHasOwner','NameHasOwner','GetConnectionUnixUser',
                                  'GetConnectionUnixProcessID','GetUnit'])
        self.assertEqual(env['CACHY_MANAGED_MANAGER_PID'],'422')
        self.assertEqual(len([e for e in self.base.events if e['event']=='managed_session_ready']),1)

    def test_permanently_unowned_bus_name_expires_without_identity_or_success(self):
        self.base.owner = False;self.base.owner_replies = [False]
        self.manager.seconds = 1
        clock = itertools.count(0,.1)
        with patch.object(m.time,'monotonic',side_effect=lambda:next(clock)),patch.object(m.time,'sleep'):
            with self.assertRaisesRegex(ValueError,'deadline'):self.manager.start()
        self.assertTrue(self.manager.owned)
        self.assertFalse(any('GetConnectionUnixUser' in argv for argv, *_ in self.base.commands))
        self.assertNotIn('managed_session_ready',[e['event'] for e in self.base.events])

    def test_preexisting_manager_refuses_without_stop_or_runtime_removal(self):
        self.base.preexisting = True
        with self.assertRaisesRegex(ValueError, 'preexisting user manager'):
            self.manager.start()
        self.manager.stop()
        self.assertFalse(self.base.started or self.base.stopped)
        self.assertFalse(self.manager.owned)

    def test_nologin_prerequisite_refuses_before_any_managed_start(self):
        with patch.object(m.os.path, 'lexists', return_value=True):
            with self.assertRaisesRegex(ValueError, 'permit-user-sessions prerequisite'):
                self.manager.start()
        self.manager.stop()
        self.assertFalse(self.base.started or self.base.stopped or self.manager.owned)

    def test_journal_failure_stays_unavailable_and_is_not_retried(self):
        self.base.command = Mock(side_effect=TimeoutError('inert bounded capture timeout'))
        self.manager.diagnose(); self.manager.diagnose()
        self.base.command.assert_called_once()
        event = self.base.events[0]
        self.assertEqual(event['status'], 'FAIL')
        self.assertEqual(event['journal_status'], 'UNAVAILABLE')
        self.assertNotIn('journal_tail_base64', event)

    def test_private_bus_owner_wrong_uid_pid_or_non_systemd_api_refuses(self):
        for name, value in (('bus_uid', 0), ('bus_pid', 999), ('target', 'o "/not/systemd"\n')):
            with self.subTest(name=name):
                backend = Backend(); setattr(backend, name, value)
                manager = m.ManagedSession(backend, Path('/inert'), {})
                with self.assertRaises(ValueError):
                    manager.start()
                self.assertFalse(any(e['event'] == 'managed_session_ready' for e in backend.events))

    def test_socket_or_directory_drift_refuses_without_fixing_metadata(self):
        self.nodes.side_effect = ValueError('runtime directory drift')
        with self.assertRaisesRegex(ValueError, 'runtime directory drift'):
            self.manager.start()
        self.assertTrue(self.manager.owned)

    def test_cleanup_requires_inactive_units_and_runtime_absence(self):
        self.manager.start()
        with patch.object(m.os.path, 'lexists', return_value=True):
            with self.assertRaisesRegex(ValueError, 'runtime/socket remained'):
                self.manager.stop()
        self.assertTrue(self.manager.owned)
        self.assertNotIn('managed_session_cleanup', [e['event'] for e in self.base.events])

    def test_diagnostic_is_once_bounded_and_failure_stays_failure(self):
        original = self.base.command
        def command(argv, *args, **kwargs):
            if argv[0] == '/usr/bin/journalctl':
                return 'x' * 20000
            return original(argv, *args, **kwargs)
        self.base.command = command
        self.manager.diagnose(); self.manager.diagnose()
        self.assertEqual(len(self.base.events), 1)
        event = self.base.events[0]
        self.assertEqual(event['status'], 'FAIL')
        self.assertTrue(event['journal_truncated'])
        self.assertEqual(len(m.base64.b64decode(event['journal_tail_base64'])), 12288)

    def test_readiness_deadline_is_finite_and_boolean_budget_refuses(self):
        with self.assertRaises(ValueError):
            m.ManagedSession(self.base, Path('/inert'), {}, seconds=True)
        with patch.object(m.time, 'monotonic', side_effect=[0, 0, 1, 3]), patch.object(m.time, 'sleep'):
            with self.assertRaisesRegex(ValueError, 'deadline'):
                self.manager.wait(lambda: None, 2)

    def test_user_rechecks_exact_environment_and_same_manager(self):
        env = self.manager.start()
        with patch.dict(m.os.environ, CACHY_MANAGED_MANAGER_PID='422'):
            self.assertEqual(m.validate_user(self.base, Path('/inert'), env)['manager_pid'], 422)
            for bad in (dict(DBUS_SESSION_BUS_ADDRESS='unix:path=/tmp/private-bus'),
                        dict(XDG_RUNTIME_DIR='/run/desktop574/runtime')):
                with self.subTest(bad=bad), self.assertRaisesRegex(ValueError, 'environment differs'):
                    m.validate_user(self.base, Path('/inert'), env | bad)


class TypesAndIdentity(unittest.TestCase):
    def test_name_owner_probe_refuses_malformed_reply_and_transport_failure(self):
        self.assertFalse(m.bus_owner_ready(Mock(return_value='b false\n')))
        self.assertTrue(m.bus_owner_ready(Mock(return_value='b true\n')))
        for value in ('s "false"','b 1','b false extra','b true\nb false'):
            with self.subTest(value=value),self.assertRaises(ValueError):m.bus_owner_ready(Mock(return_value=value))
        with self.assertRaises(TimeoutError):m.bus_owner_ready(Mock(side_effect=TimeoutError('transport failed')))
    def test_adapter_binding_keeps_phase_hooks_and_does_not_need_module_registration(self):
        base = SimpleNamespace(guard=Mock(),phase=Mock(),emit=Mock())
        phase, emit = base.phase, base.emit
        self.assertIs(m.bind(base),base)
        self.assertIs(base.managed_base,base)
        self.assertIs(base.managed_session.ManagedSession,m.ManagedSession)
        self.assertIs(base.phase,phase);self.assertIs(base.emit,emit)
        with patch.object(Path,'read_text',return_value='cachy_asahi_managed_user=1'):
            base.guard(False)
    def test_properties_refuse_duplicates_missing_boolean_text_and_nonzero_exit(self):
        good = ''.join(f'{k}={v}\n' for k,v in row(m.USER, 'active', 'running', 5).items())
        value = m.properties(good, m.USER)
        self.assertTrue(m.active(value, 'running', process=True))
        for bad in (good + 'MainPID=5\n', good.replace('Result=success\n', ''), good.replace('MainPID=5', 'MainPID=True')):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                m.properties(bad, m.USER)
        for change in ({'ExecMainStatus': 224}, {'Result': 'exit-code'}, {'MainPID': 0}, {'SubState': 'exited'}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                m.active(value | change, 'running', process=True)

    def test_typed_bus_reply_and_pid_bounds(self):
        for value in ('u true', 's "23001"', 'u -1', 'u 4294967296', 'u 1\nu 2'):
            with self.subTest(value=value), self.assertRaises(ValueError): m.uint(value)
        with self.assertRaises(ValueError): m.bus_probe(Mock(), True)

    def test_guard_requires_original_guest_guard_marker_and_booted_systemd(self):
        base = SimpleNamespace(guard=Mock())
        def text(path):
            return 'systemd\n' if str(path) == '/proc/1/comm' else 'cachy_asahi_managed_user=1\n'
        with patch.object(Path, 'read_text', autospec=True, side_effect=text), patch.object(Path, 'exists', return_value=False):
            m.guard(base, True); base.guard.assert_called_once_with(True)
            base.guard.side_effect = ValueError('guest guard refusal')
            with self.assertRaisesRegex(ValueError, 'guest guard refusal'): m.guard(base, True)
            base.guard.side_effect = None
            with patch.object(Path, 'read_text', return_value='host'):
                with self.assertRaisesRegex(ValueError, 'marker'): m.guard(base, True)

    def test_runtime_directory_and_socket_aliases_or_owner_drift_refuse(self):
        values = {'/run/user':(stat.S_IFDIR | 0o755, 0, 0),
            '/run/user/23001':(stat.S_IFDIR | 0o700, 23001, 23001),
            '/run/user/23001/systemd':(stat.S_IFDIR | 0o755, 23001, 23001),
            '/run/user/23001/bus':(stat.S_IFSOCK | 0o666, 23001, 23001),
            '/run/user/23001/systemd/private':(stat.S_IFSOCK | 0o700, 23001, 23001)}
        def info(path):
            mode, uid, gid = values[str(path)]
            return SimpleNamespace(st_mode=mode, st_uid=uid, st_gid=gid)
        with patch.object(Path, 'lstat', autospec=True, side_effect=info):
            m.runtime_nodes()
            for path, wrong in (('/run/user/23001', (stat.S_IFLNK | 0o700,23001,23001)),
                                ('/run/user/23001/systemd',(stat.S_IFLNK | 0o755,23001,23001)),
                                ('/run/user/23001/bus',(stat.S_IFSOCK | 0o666,0,0))):
                old = values[path]; values[path] = wrong
                with self.subTest(path=path), self.assertRaises(ValueError): m.runtime_nodes()
                values[path] = old


class Profile(unittest.TestCase):
    def test_stages_separate_profile_without_pam_rewrite_private_bus_or_timer_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = p.prepare(ROOT, Path(temporary) / 'runner')
            guest = (out / 'base_guest.py').read_text(); fixture = (out / 'desktop574_fixture.sh').read_text()
            self.assertNotIn('dbus-run-session', guest)
            self.assertNotIn('runuser', guest)
            self.assertIn('for path in (HOME,):', guest)
            self.assertIn('managed_session.SETPRIV', guest)
            self.assertIn('session.wait(timeout=480)', guest)
            self.assertIn('TimeoutStartSec=650', fixture)
            self.assertIn('Requires=basic.target systemd-udevd.service systemd-udev-trigger.service systemd-user-sessions.service', fixture)
            self.assertIn('After=basic.target systemd-udev-trigger.service systemd-user-sessions.service', fixture)
            self.assertNotIn('pam.d', fixture)
            self.assertNotIn('nologin', fixture)
            self.assertIn('verify_result', (out / 'desktop574_runtime.py').read_text())
            for path in out.glob('*.py'): ast.parse(path.read_bytes())
            with self.assertRaisesRegex(ValueError, 'fresh'): p.prepare(ROOT, out)

    def test_source_drift_and_transform_anchor_drift_refuse(self):
        with self.assertRaisesRegex(ValueError, 'anchor'): p.transform_guest('not the selected base')
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError): p.prepare(Path(temporary), Path(temporary) / 'runner')

    def test_result_requires_manager_user_and_disposal_before_complete(self):
        identity = dict(address=m.ADDRESS, uid=23001, manager_pid=422, default_target='GetUnit-PASS')
        events = [dict(event='managed_session_ready', status='PASS', **identity),
                  dict(event='managed_user_ready', status='PASS', **identity),
                  dict(event='phase_pass', stage='minimal'), dict(event='phase_pass', stage='overlay'),
                  dict(event='session_pass', status='PASS'),
                  dict(event='managed_session_cleanup', status='PASS', units=[m.USER,m.DIRECTORY],
                       unit_states={unit:row(unit) for unit in (m.USER,m.DIRECTORY)},
                       runtime_absent=True, owned_units_stopped=True), dict(event='complete', status='PASS')]
        events[0]['units'] = {m.SESSIONS: row(m.SESSIONS,'active','exited'),
            m.DIRECTORY: row(m.DIRECTORY,'active','exited'), m.USER: row(m.USER,'active','running',422)}
        self.assertEqual(c.verify_result(events)['status'], 'PASS')
        for index in (0, 1, 4, 5, 6):
            with self.subTest(missing=index), self.assertRaises(ValueError): c.verify_result(events[:index]+events[index+1:])
        bad = copy.deepcopy(events); bad[1]['manager_pid'] = True
        with self.assertRaises(ValueError): c.verify_result(bad)
        bad = copy.deepcopy(events); bad[5]['runtime_absent'] = False
        with self.assertRaises(ValueError): c.verify_result(bad)
        with self.assertRaises(ValueError): c.verify_result(events + [dict(event='managed_session_diagnostic')])
        with self.assertRaises(ValueError): c.verify_result(events[-1:] + events[:-1])


class GuestIntegration(unittest.TestCase):
    def execute(self, *, start_error=None, stop_error=None):
        source = p.transform_guest((ROOT / 'scripts/ci/desktop574_guest.py').read_text())
        base = ModuleType('managed_boot_inert_control')
        sys.modules[base.__name__] = base
        self.addCleanup(sys.modules.pop, base.__name__, None)
        exec(compile(source, '<managed-boot-control>', 'exec'), base.__dict__)
        calls = []
        manager = Mock()
        manager.start.return_value = {'CACHY_MANAGED_MANAGER_PID':'422'}
        manager.start.side_effect = start_error
        def stop():
            calls.append('manager-stop')
            if stop_error: raise stop_error
        manager.stop.side_effect = stop
        base.managed_session = SimpleNamespace(ManagedSession=Mock(return_value=manager), SETPRIV=m.SETPRIV)
        base.managed_base = base
        share = MagicMock(); (share / 'expected.lock').read_text.return_value = ''
        paths = MagicMock(); paths.parent.is_symlink.return_value = False
        home = MagicMock(); home.is_symlink.return_value = False
        session = Mock(); session.wait.return_value = 0
        with ExitStack() as stack:
            for name, value in {'guard':Mock(), 'EVENTS':None, 'wait_event_port':Mock(return_value=Mock()),
                'HOME':home,'SHARE':share,'Path':Mock(return_value=paths),
                'command':Mock(return_value=''), 'wait_drm_card':Mock(return_value=Mock()),
                'drm_render_node':Mock(return_value=Mock()), 'ready_seat':Mock(return_value=True),
                'Logged':Mock(), 'terminate':Mock(side_effect=lambda child:calls.append('retire-child')),
                'emit':Mock(side_effect=lambda event,**kw:calls.append((event,kw)))}.items():
                stack.enter_context(patch.object(base,name,value))
            stack.enter_context(patch.object(base.platform,'release',return_value='7.2.10-1-aarch64-ARCH'))
            stack.enter_context(patch.object(base.os,'sysconf',return_value=4096))
            stack.enter_context(patch.object(base.os,'chown'))
            stack.enter_context(patch.object(base.os,'umask'))
            stack.enter_context(patch.object(base.os.path,'lexists',return_value=False))
            popen=stack.enter_context(patch.object(base.subprocess,'Popen',return_value=session))
            poweroff=stack.enter_context(patch.object(base.subprocess,'run'))
            error = None
            try: base.boot()
            except BaseException as caught: error = caught
            poweroff.assert_called_once()
        return calls, manager, popen, error

    def test_generated_boot_retires_workload_then_manager_before_complete(self):
        calls, manager, popen, error = self.execute()
        self.assertIsNone(error)
        argv = popen.call_args.args[0]
        self.assertEqual(argv[:len(m.SETPRIV)], m.SETPRIV)
        self.assertNotIn('/usr/bin/dbus-run-session',argv)
        end = next(i for i,v in enumerate(calls) if isinstance(v,tuple) and v[0]=='complete')
        self.assertLess(calls.index('retire-child'), calls.index('manager-stop'))
        self.assertLess(calls.index('manager-stop'), end)
        manager.stop.assert_called_once();manager.diagnose.assert_not_called()

    def test_generated_boot_keeps_original_failure_when_cleanup_also_fails(self):
        first = ValueError('managed start failed'); secondary = RuntimeError('stop failed')
        calls, manager, popen, error = self.execute(start_error=first,stop_error=secondary)
        self.assertIs(error,first)
        popen.assert_not_called();manager.stop.assert_called_once()
        self.assertFalse(any(isinstance(v,tuple) and v[0]=='complete' for v in calls))
        self.assertTrue(any(isinstance(v,tuple) and v[0]=='failed' for v in calls))


if __name__ == '__main__': unittest.main()
