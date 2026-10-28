#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host fixtures and real disposable child controls; no physical acceptance."""
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('session_probe', HERE / 'session_probe.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)
IDENTITY = dict(declared_model_id=None, source_revision='a' * 40, baseline_sha256='b' * 64,
                execution_context='unknown')
BASE_ENV = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}


def encoded(value):
    return json.dumps(value).encode()


def fixture(argv, seconds, env):
    if argv[0].endswith('hyprctl'):
        if argv[-1] == 'version':
            out = encoded(dict(version='0.56.2', commit='a' * 40, commit_message='PRIVATE'))
        elif argv[-1] == 'monitors':
            out = encoded([dict(width=2560, height=1600, refreshRate=60.0, scale=2, transform=0,
                                serial='PRIVATE', description='PRIVATE', activeWorkspace={'name': 'PRIVATE'})])
        else:
            raise AssertionError('unapproved Hyprland request')
    elif argv[0].endswith('eglinfo'):
        out = b'OpenGL ES profile vendor: Mesa\nOpenGL ES profile renderer: Asahi AGX\nOpenGL ES profile version: OpenGL ES 3.2\n'
    elif argv[0].endswith('systemctl'):
        out = b'LoadState=loaded\nActiveState=active\nSubState=running\n'
    elif argv[0].endswith('loginctl'):
        out = b'Type=wayland\nClass=user\nState=active\nActive=yes\nRemote=no\nLockedHint=no\n'
    elif argv[0].endswith('pw-dump'):
        out = encoded([{'type': 'PipeWire:Interface:Node', 'id': 234,
                        'info': {'state': 'running', 'props': {'media.class': 'Audio/Sink',
                         'node.name': 'audio_effect.j413-convolver', 'application.name': 'PRIVATE'}}},
                       {'type': 'PipeWire:Interface:Node', 'info': {'state': 'idle', 'props':
                        {'media.class': 'Stream/Output/Audio', 'node.name': 'PRIVATE'}}},
                       {'type': 'PipeWire:Interface:Link', 'info': {'state': 'active', 'output-node-id': 234}}])
    else:
        out = b's "yes"\n'
    return 'observed', 0, out, b''


def fixed_read(path):
    return {'/sys/power/state': b'freeze mem disk\n', '/sys/power/mem_sleep': b'[s2idle] deep\n',
            '/proc/device-tree/compatible': b'apple,j413\0apple,t8112\0'}.get(path)


def report(**kwargs):
    defaults = dict(run=fixture, read=fixed_read, environ={},
                    context={name: (BASE_ENV, ()) for name in ('local', 'hypr', 'wayland', 'audio', 'user', 'system')})
    defaults.update(kwargs)
    return P.collect(IDENTITY, **defaults)


class Parsers(unittest.TestCase):
    def test_fixture_report_retains_identity_without_physical_pass(self):
        value = report()
        self.assertEqual(value['coverage'], {'checked': 14, 'unknown': 1})
        self.assertEqual(value['identity']['source_revision'], 'a' * 40)
        self.assertEqual(value['identity']['baseline_sha256'], 'b' * 64)
        self.assertEqual(set(value['physical_checks'].values()), {'NOT RUN'})
        self.assertNotIn('PRIVATE', json.dumps(value))
        self.assertEqual(value['record_type'], 'session-observations')

    def test_known_model_requires_aarch64_and_unambiguous_identifier(self):
        with patch.object(P.platform, 'machine', return_value='aarch64'):
            self.assertEqual(report()['identity']['observed_model_id'], 'apple,j413')
            both = lambda path: b'apple,j413\0apple,j415\0' if 'compatible' in path else fixed_read(path)
            self.assertIsNone(report(read=both)['identity']['observed_model_id'])
        with patch.object(P.platform, 'machine', return_value='x86_64'):
            self.assertIsNone(report()['identity']['observed_model_id'])

    def test_monitors_omit_private_fields_and_reject_invalid_scaling(self):
        raw = dict(width=1, height=2, refreshRate=60, scale=2, transform=0, serial='PRIVATE')
        self.assertNotIn('serial', P.monitors(encoded([raw]))[0])
        for key, value in [('scale', float('nan')), ('width', True), ('height', -1), ('refreshRate', '60'), ('transform', 8)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                P.monitors(encoded([dict(raw, **{key: value})]))

    def test_renderer_accepts_brief_formats_and_marks_software_hint(self):
        for suffix in ('', ' string'):
            raw = '\n'.join('OpenGL ES profile ' + k + suffix + ': ' + v for k, v in
                            [('vendor', 'Mesa'), ('renderer', 'llvmpipe (LLVM 20)'), ('version', 'OpenGL ES 3.2')]).encode()
            self.assertTrue(P.renderer(raw)['software_renderer_hint'])
            with self.assertRaises(ValueError):
                P.renderer(raw + b'\nOpenGL ES profile renderer: PRIVATE')
        with self.assertRaises(ValueError):
            P.renderer(b'OpenGL vendor string: PRIVATE')

    def test_audio_graph_whitelists_known_nodes_without_application_ids(self):
        value = next(x for x in report()['checks'] if x['check'] == 'audio/graph')['value']
        self.assertEqual(value['known_asahi_graph_nodes'], ['audio_effect.j413-convolver'])
        self.assertEqual(value['media_class_counts'], {'Audio/Sink': 1})
        self.assertEqual(value['node_state_counts'], {'idle': 1, 'running': 1})
        self.assertEqual(value['speaker_protection'], 'NOT TESTED')
        self.assertNotIn('234', json.dumps(value))

    def test_malformed_outputs_and_duplicates_fail_closed(self):
        for raw in (b'{}', b'null', b'"PRIVATE"', b'[{"type":"PipeWire:Interface:Node","info":{"props":[]}}]',
                    b'[{"type":"PipeWire:Interface:Node","info":{"props":[1]}}]', b'[1]', b'{"x":1,"x":2}'):
            def run(argv, seconds, env):
                return ('observed', 0, raw, b'') if argv[0].endswith('pw-dump') else fixture(argv, seconds, env)
            with self.subTest(raw=raw):
                row = next(x for x in report(run=run)['checks'] if x['check'] == 'audio/graph')
                self.assertEqual(row['state'], 'unknown')
                self.assertNotIn('PRIVATE', json.dumps(row))

    def test_power_capability_is_not_a_suspend_result(self):
        self.assertEqual(P.can_suspend(b's "challenge"\n'), {'logind_can_suspend': 'challenge'})
        self.assertEqual(P.power_tokens(b's2idle [deep]\n', {'s2idle', 'deep'}), ['s2idle', '[deep]'])
        for raw in (b's "yes"\nPRIVATE', b'b true', b's "maybe"'):
            with self.assertRaises(ValueError):
                P.can_suspend(raw)
        for raw in (b'[deep', b'deep]', b'PRIVATE', b''):
            with self.assertRaises(ValueError):
                P.power_tokens(raw, {'deep'})

    def test_service_and_session_properties_require_exact_keys(self):
        for raw in (b'LoadState=loaded', b'LoadState=loaded\nLoadState=masked', b'Name=PRIVATE', b'Type=wayland\nPRIVATE'):
            with self.assertRaises(ValueError):
                P.properties(raw, P.SERVICE_PROPERTIES)


class Collection(unittest.TestCase):
    def test_fixed_argv_and_bounded_time_for_every_command(self):
        events = []
        def run(argv, seconds, env):
            events.append((argv, seconds, env))
            return fixture(argv, seconds, env)
        value = report(run=run)
        self.assertEqual(len(events), 12)
        for argv, seconds, env in events:
            self.assertTrue(argv[0].startswith('/usr/bin/'))
            self.assertGreater(seconds, 0)
            self.assertLessEqual(seconds, 2)
            self.assertFalse(any(x in argv for x in ('suspend', 'lock-session', 'set-volume', 'start', 'restart')))
            self.assertNotIn('systeminfo', argv)
        self.assertEqual(len(value['checks']), 15)

    def test_no_endpoint_means_no_launch_and_no_health_inference(self):
        events = []
        value = report(context={}, run=lambda *args: events.append(args))
        self.assertFalse(events)
        self.assertEqual(value['coverage'], {'unavailable': 12, 'checked': 2, 'unknown': 1})

    def test_missing_denied_warning_and_timeout_remain_visible_without_raw_errors(self):
        for reason in ('command-absent', 'query-denied', 'query-failed', 'query-warning', 'timeout', 'output-limit'):
            value = report(run=lambda *args: (reason, 1, b'PRIVATE', b'PRIVATE'))
            self.assertEqual(value['checks'][0]['reason'], reason)
            self.assertEqual(value['checks'][0]['state'], 'unavailable' if reason == 'command-absent' else 'unknown')
            self.assertNotIn('PRIVATE', json.dumps(value))

    def test_aggregate_deadline_stops_all_further_commands(self):
        events = []
        times = iter([0, .5] + [21] * 11)
        def run(argv, seconds, env):
            events.append(argv)
            return fixture(argv, seconds, env)
        value = report(clock=lambda: next(times), run=run)
        self.assertEqual(len(events), 1)
        self.assertEqual(value['checks'][1]['reason'], 'total-deadline')

    def test_socket_replacement_discards_observations(self):
        context = {'hypr': (BASE_ENV, ((Path('/fixture/socket'), os.getuid()),))}
        with patch.object(P, 'socket_snapshot', side_effect=[('first',), ('second',)] + [None] * 3):
            value = report(context=context)
        self.assertEqual(value['checks'][0]['reason'], 'local-endpoint-changed')
        self.assertIsNone(value['checks'][0]['value'])

    def test_full_environment_and_remote_overrides_are_not_inherited(self):
        original = dict(HYPRLAND_INSTANCE_SIGNATURE='../PRIVATE', WAYLAND_DISPLAY='/PRIVATE',
                        LD_PRELOAD='PRIVATE', HOME='PRIVATE', PIPEWIRE_REMOTE='tcp:PRIVATE',
                        DBUS_SESSION_BUS_ADDRESS='tcp:PRIVATE', XDG_RUNTIME_DIR='/PRIVATE')
        with patch.object(P, 'socket_snapshot', return_value=None):
            value = P.contexts(original)
        self.assertEqual(set(value), {'local'})
        self.assertNotIn('PRIVATE', json.dumps(value))
        self.assertNotIn('HOME', value['local'][0])


class RealProcesses(unittest.TestCase):
    def run_child(self, code, seconds=.5):
        return P.query([sys.executable, '-B', '-I', '-c', code], seconds, BASE_ENV)

    def test_natural_child_retirement_and_combined_streams(self):
        value = self.run_child('import os;os.write(1,b"stdout");os.write(2,b"stderr")')
        self.assertEqual(value, ('query-warning', 0, b'stdout', b'stderr'))

    def test_absent_denied_and_nonzero_queries(self):
        self.assertEqual(P.query(['/nonexistent/cachy-probe-tool'], .5, BASE_ENV)[0], 'command-absent')
        self.assertEqual(self.run_child('import sys;sys.stderr.write("Permission denied PRIVATE");sys.exit(1)')[0], 'query-denied')
        self.assertEqual(self.run_child('import sys;sys.exit(2)')[0], 'query-failed')

    def test_timeout_kills_stalled_command(self):
        start = time.monotonic()
        value = self.run_child('import time;time.sleep(10)', .1)
        self.assertEqual(value[0], 'timeout')
        self.assertLess(time.monotonic() - start, 2)

    def test_selector_failure_retires_child_without_resource_leak(self):
        with patch.object(P.selectors, 'DefaultSelector', side_effect=OSError('fixture')):
            value = self.run_child('import time;time.sleep(10)')
        self.assertEqual(value[0], 'read-failed')
        self.assertIsNotNone(value[1])

    def test_deadline_includes_leader_with_closed_pipes(self):
        value = self.run_child('import os,time;os.close(1);os.close(2);time.sleep(10)', .1)
        self.assertEqual(value[0], 'timeout')

    def test_descendant_retains_pipes_after_leader_exits(self):
        # The grandchild holds the pipes after the parent exits; no poll()/communicate loophole.
        code = 'import os,time\npid=os.fork()\nif pid==0:time.sleep(10)\nelse:os.write(1,str(os.getpid()).encode());os._exit(0)'
        value = self.run_child(code, .15)
        self.assertEqual(value[0], 'timeout')
        leader = int(value[2])
        with self.assertRaises(ProcessLookupError):
            os.kill(leader, 0)
        # The parent has been reaped; a killed grandchild may await the host reaper.

    def test_output_bound_combines_stdout_and_stderr(self):
        with patch.object(P, 'MAX_OUTPUT', 8192):
            exact = self.run_child('import os;os.write(1,b"x"*4096);os.write(2,b"y"*4096)')
            self.assertEqual(exact[0], 'query-warning')
            overflow = self.run_child('import os;os.write(1,b"x"*4096);os.write(2,b"y"*4097)')
            self.assertEqual(overflow[0], 'output-limit')
            self.assertLessEqual(len(overflow[2]) + len(overflow[3]), 8192)

    def test_inherited_loader_and_network_variables_discarded_by_context(self):
        env = P.contexts({})['local'][0]
        result = P.query([sys.executable, '-B', '-I', '-c', 'import os,json;print(json.dumps(dict(os.environ)))'], .5, env)
        value = json.loads(result[2])
        for key in ('HOME', 'LD_PRELOAD', 'DBUS_SESSION_BUS_ADDRESS', 'PIPEWIRE_REMOTE', 'DISPLAY'):
            self.assertNotIn(key, value)

    def test_sigterm_main_interrupt_retires_running_query(self):
        with tempfile.TemporaryDirectory(dir=HERE) as directory:
            ready = Path(directory) / 'ready'
            child_code = 'import os,time,pathlib;pathlib.Path(' + repr(str(ready)) + ').write_text(str(os.getpid()));time.sleep(10)'
            harness = ('import sys;sys.path.insert(0,' + repr(str(HERE)) + ');import session_probe as p;'
                       'p.collect=lambda _:p.query(' + repr([sys.executable, '-B', '-I', '-c', child_code]) + ',10,' + repr(BASE_ENV) + ');'
                       'raise SystemExit(p.main([]))')
            process = subprocess.Popen([sys.executable, '-B', '-I', '-c', harness], env=BASE_ENV,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 2
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(ready.exists())
                pid = int(ready.read_text())
                process.send_signal(signal.SIGTERM)
                out, err = process.communicate(timeout=2)
                self.assertEqual(process.returncode, 130)
                self.assertEqual((out, err), (b'', b''))
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
                process.stdout.close()
                process.stderr.close()


class SocketAndCLI(unittest.TestCase):
    def test_real_socket_ancestry_owner_symlink_and_replacement_guards(self):
        with tempfile.TemporaryDirectory(dir=HERE) as directory:
            root = Path(directory)
            root.chmod(0o700)
            uid = os.getuid()
            run = root / 'run'; run.mkdir(); run.chmod(0o755)
            users = run / 'user'; users.mkdir(); users.chmod(0o755)
            runtime = users / str(uid); runtime.mkdir(); runtime.chmod(0o700)
            path = runtime / 'socket'
            virtual = Path('/run/user') / str(uid) / 'socket'
            real_open = os.open

            def snapshot(target=virtual, owner=uid):
                # A test-only root FD makes checkout ancestry irrelevant. Every
                # descendant open/stat remains real and retains O_NOFOLLOW.
                def fixture_open(name, flags, *args, **kwargs):
                    if name == '/' and 'dir_fd' not in kwargs:
                        return real_open(root, flags, *args, **kwargs)
                    return real_open(name, flags, *args, **kwargs)
                with patch.object(P.os, 'open', side_effect=fixture_open):
                    return P.socket_snapshot(target, owner)

            def bind(server, parent=runtime):
                # Linux limits bind path bytes; the full packet path is much longer.
                old = real_open('.', os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.chdir(parent)
                    server.bind('socket')
                finally:
                    os.fchdir(old)
                    os.close(old)
            with socket.socket(socket.AF_UNIX) as server:
                bind(server)
                first = snapshot()
                self.assertIsNotNone(first)
                self.assertIsNone(snapshot(owner=uid + 1))
                for ancestor in (run, users):
                    ancestor.chmod(0o777)
                    self.assertIsNone(snapshot())
                    ancestor.chmod(0o755)
                runtime.chmod(0o755)
                self.assertIsNone(snapshot())  # /run/user/<uid> must be 0700.
                runtime.chmod(0o700)
                alias = runtime / 'alias'
                alias.symlink_to('.', target_is_directory=True)
                self.assertIsNone(snapshot(virtual.parent / 'alias/socket'))
                link = runtime / 'socket-link'
                os.link(path, link)
                self.assertIsNone(snapshot())  # Socket must have exactly one link.
                link.unlink()
                path.unlink()
                with socket.socket(socket.AF_UNIX) as other:
                    bind(other)
                    second = snapshot()
                    self.assertIsNotNone(second)
                    self.assertNotEqual(first, second)
                path.unlink()
                path.write_text('PRIVATE')
                self.assertIsNone(snapshot())
                path.unlink()
                path.symlink_to(root / 'nonexistent')
                self.assertIsNone(snapshot())
            untrusted = root / 'untrusted'; untrusted.mkdir(); untrusted.chmod(0o1777)
            with socket.socket(socket.AF_UNIX) as server:
                bind(server, untrusted)
                # No root mapping here: the production walk rejects real unsafe ancestry.
                self.assertIsNone(P.socket_snapshot(untrusted / 'socket', uid))
        self.assertIsNone(P.socket_snapshot(Path('relative/socket'), os.getuid()))

    def test_cli_help_and_invalid_identity_never_collect(self):
        with patch.object(P, 'collect', side_effect=AssertionError('must not collect')):
            for argv, code in [(['--help'], 0), (['--source-revision', 'main'], 2),
                               (['--baseline-sha256', 'PRIVATE'], 2), (['--model-id', 'j413'], 2)]:
                with self.subTest(argv=argv), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
                    P.main(argv)
                self.assertEqual(raised.exception.code, code)


class ReapingOwnership(unittest.TestCase):
    def child(self, code='pass'):
        return P.query([sys.executable, '-B', '-I', '-c', code], .5, BASE_ENV)

    def isolated(self, code):
        prefix = 'import sys;sys.path.insert(0,' + repr(str(HERE)) + ');import session_probe as p;import os,signal,json;'
        result = subprocess.run([sys.executable, '-B', '-I', '-c', prefix + code],
                                env=BASE_ENV, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b'')
        return json.loads(result.stdout)

    def test_real_external_reap_echild_never_signals_or_reports_fabricated_zero(self):
        waitid, waitpid = os.waitid, os.waitpid
        def externally_reaped(which, pid, flags):
            waitpid(pid, 0)
            return waitid(which, pid, flags)  # genuine kernel ECHILD
        with patch.object(P.os, 'waitid', side_effect=externally_reaped), patch.object(P.os, 'killpg') as kill:
            value = self.child()
        kill.assert_not_called()
        self.assertEqual(value[:2], ('child-reservation-lost', None))

    def test_real_cleanup_echild_after_selector_failure_never_signals(self):
        popen, waitpid = subprocess.Popen, os.waitpid
        def already_reaped(*args, **kwargs):
            process = popen(*args, **kwargs)
            waitpid(process.pid, 0)
            return process
        with patch.object(P.subprocess, 'Popen', side_effect=already_reaped), patch.object(P.selectors, 'DefaultSelector', side_effect=OSError('fixture')), patch.object(P.os, 'killpg') as kill:
            value = self.child()
        kill.assert_not_called()
        self.assertEqual(value[:2], ('child-reservation-lost', None))

    def test_cached_reaped_status_is_lost_ownership_not_signal_authority(self):
        popen = subprocess.Popen
        def already_reaped(*args, **kwargs):
            process = popen(*args, **kwargs)
            process.wait(timeout=2)
            return process
        with patch.object(P.subprocess, 'Popen', side_effect=already_reaped), patch.object(P.os, 'killpg') as kill:
            value = self.child()
        kill.assert_not_called()
        self.assertEqual(value[:2], ('child-reservation-lost', None))

    def test_policy_setup_failure_never_launches(self):
        with patch.object(P.signal, 'signal', side_effect=OSError('fixture')), patch.object(P.subprocess, 'Popen') as popen:
            value = self.child()
        popen.assert_not_called()
        self.assertEqual(value[:2], ('reaping-policy-unverified', None))

    def test_unverified_waitid_ownership_disables_group_signal(self):
        import errno
        popen, waitpid = subprocess.Popen, os.waitpid
        def already_reaped(*args, **kwargs):
            process = popen(*args, **kwargs)
            waitpid(process.pid, 0)
            return process
        with patch.object(P.subprocess, 'Popen', side_effect=already_reaped), patch.object(P.os, 'waitid', side_effect=OSError(errno.EIO, 'fixture')), patch.object(P.os, 'killpg') as kill:
            value = self.child()
        kill.assert_not_called()
        self.assertEqual(value[:2], ('child-reservation-unverified', None))

    def test_normal_order_is_wnowait_then_last_signal_then_reap(self):
        events = []
        waitid, waitpid, killpg = os.waitid, os.waitpid, os.killpg
        def observe(*args):
            self.assertTrue(args[2] & os.WNOWAIT)
            events.append('observe')
            return waitid(*args)
        def reap(*args):
            events.append('reap')
            return waitpid(*args)
        def kill(*args):
            events.append('signal')
            return killpg(*args)
        with patch.object(P.os, 'waitid', side_effect=observe), patch.object(P.os, 'waitpid', side_effect=reap), patch.object(P.os, 'killpg', side_effect=kill):
            value = self.child()
        self.assertEqual(value[:2], ('observed', 0))
        self.assertEqual(events.count('signal'), 1)
        index = events.index('signal')
        self.assertEqual(events[index - 1], 'observe')
        self.assertTrue(all(x == 'observe' for x in events[:index]))
        self.assertTrue(all(x == 'reap' for x in events[index + 1:]))

    def test_echild_during_reap_is_unknown_with_no_later_group_signal(self):
        import errno
        events = []
        waitpid, killpg = os.waitpid, os.killpg
        def reap(pid, flags):
            events.append('reap')
            if events.count('reap') == 1:
                waitpid(pid, 0)
                raise ChildProcessError(errno.ECHILD, 'externally reaped fixture')
            return waitpid(pid, flags)
        def kill(*args):
            events.append('signal')
            return killpg(*args)
        with patch.object(P.os, 'waitpid', side_effect=reap), patch.object(P.os, 'killpg', side_effect=kill):
            value = self.child()
        self.assertEqual(value[:2], ('child-reservation-lost', None))
        self.assertEqual(events.count('signal'), 1)
        self.assertLess(events.index('signal'), events.index('reap'))

    def test_ignored_and_custom_sigchld_policy_refuses_launch_unchanged(self):
        for handler in ('signal.SIG_IGN', 'lambda *_: None'):
            code = ('from unittest.mock import patch;signal.signal(signal.SIGCHLD,' + handler + ');'
                    'before=signal.getsignal(signal.SIGCHLD);'
                    'manager=patch.object(p.subprocess,"Popen",side_effect=AssertionError("must not launch"));manager.start();'
                    'result=p.query(["/usr/bin/true"],.1,{});'
                    'print(json.dumps([result[:2],signal.getsignal(signal.SIGCHLD)==before]))')
            self.assertEqual(self.isolated(code), [['reaping-policy-incompatible', None], True])

    def test_threaded_caller_refuses_launch(self):
        import threading
        result = []
        with patch.object(P.subprocess, 'Popen') as popen:
            thread = threading.Thread(target=lambda: result.append(self.child()))
            thread.start()
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        popen.assert_not_called()
        self.assertEqual(result[0][:2], ('reaping-policy-incompatible', None))

    def test_real_sa_nocldwait_is_cleared_before_launch(self):
        import shutil
        cc = shutil.which('cc', path='/usr/bin:/bin')
        if cc is None:
            self.skipTest('C compiler unavailable for real SA_NOCLDWAIT fixture')
        with tempfile.TemporaryDirectory(dir=HERE) as directory:
            root = Path(directory)
            source, library = root / 'policy.c', root / 'policy.so'
            source.write_text('#include <signal.h>\nint set_policy(void){struct sigaction a={0};a.sa_handler=SIG_DFL;a.sa_flags=SA_NOCLDWAIT;sigemptyset(&a.sa_mask);return sigaction(SIGCHLD,&a,0);}\nint automatic(void){struct sigaction a;if(sigaction(SIGCHLD,0,&a))return -1;return !!(a.sa_flags&SA_NOCLDWAIT); }\n')
            build = subprocess.run([cc, '-shared', '-fPIC', str(source), '-o', str(library)], capture_output=True, timeout=10)
            self.assertEqual(build.returncode, 0, build.stderr)
            code = ('import ctypes;lib=ctypes.CDLL(' + repr(str(library)) + ');'
                    'assert lib.set_policy()==0;assert lib.automatic()==1;'
                    'result=p.query([sys.executable,"-B","-I","-c","pass"],.5,{"PATH":"/usr/bin:/bin"});'
                    'print(json.dumps([result[:2],lib.automatic()]))')
            self.assertEqual(self.isolated(code), [['observed', 0], 0])


if __name__ == '__main__':
    unittest.main(verbosity=2)
