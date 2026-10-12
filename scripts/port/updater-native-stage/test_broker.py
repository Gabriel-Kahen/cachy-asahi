"""Private fixtures and mocked Docker only; no Docker daemon or builds used."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('broker', Path(__file__).with_name('broker.py'))
b = importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
IMAGE = 'sha256:' + 'a' * 64
NONCE = 'b' * 32
WORKER = 'cachy-asahi-updater-' + 'c' * 32


class Docker:
    def __init__(self, root):
        self.root, self.calls, self.images, self.containers = root, [], {}, {}
        self.cancel_build, self.no_iid, self.bad_label = False, False, False

    def execute(self, c, args, signals, capture=False, **kwargs):
        self.calls.append(args)
        registry = json.loads((self.root / 'broker-registry.json').read_text())
        if args[0] == 'build':
            iid = Path(args[args.index('--iidfile') + 1])
            assert any(row['iidfile'] == str(iid) and row['status'] == 'INTENT' for row in registry['builds'])
            assert registry['invocations'][-1]['status'] == 'INTENT'
            assert args[args.index('--label') + 1] == b.LABEL + '=' + NONCE
            if self.cancel_build: raise b.BrokerError('cancelled')
            self.images[IMAGE] = 'foreign' if self.bad_label else NONCE
            if not self.no_iid: iid.write_text(IMAGE + '\n')
            return 0, b''
        if args[0] == 'run':
            name = args[args.index('--name') + 1]
            assert any(row['name'] == name and row['status'] == 'INTENT' for row in registry['containers'])
            assert args[args.index('--label') + 1] == b.LABEL + '=' + NONCE
            self.containers[name] = NONCE
            if '--rm' in args: del self.containers[name]
            return 0, b'unchanged private stdout'
        if args[:2] == ['image', 'inspect']:
            if args[2] not in self.images: return 1, b''
            return 0, json.dumps([{'Id': args[2], 'Architecture': 'arm64', 'Os': 'linux',
                'Config': {'Labels': {b.LABEL: self.images[args[2]]}}}]).encode()
        if args[0] == 'inspect':
            if args[1] not in self.containers: return 1, b''
            return 0, json.dumps([{'Name': '/' + args[1], 'Config': {'Labels': {b.LABEL: self.containers[args[1]]}}}]).encode()
        if args[0] == 'ps':
            name = args[2][len('--filter=name=^/'):-1]
            return 0, b'fixture-id\n' if name in self.containers else b''
        if args[0] == 'rm':
            self.containers.pop(args[2], None);return 0, b''
        if args[0] == 'rmi':
            self.images.pop(args[1], None);return 0, b''
        if args[:2] == ['image', 'ls']:
            assert args[3] == '--filter=label=' + b.LABEL + '=' + NONCE
            return 0, b'\n'.join(image.encode() for image, label in self.images.items() if label == NONCE)
        return 0, b'private tool stdout unchanged'


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='broker-tests-')
        self.root = Path(self.temp.name);self.root.chmod(0o700)
        self.docker_file = self.root / 'real-docker';self.docker_file.write_bytes(b'never executed fixture');self.docker_file.chmod(0o700)
        self.path = self.root / 'broker-controller.json'
        value = {'schema_version': 1, 'nonce': NONCE, 'root': str(self.root), 'real_docker': str(self.docker_file),
                 'real_docker_sha256': hashlib.sha256(self.docker_file.read_bytes()).hexdigest(),
                 'docker_endpoint': 'unix:///run/docker.sock', 'docker_socket_identity': {'device': 1, 'inode': 2},
                 'deadline_monotonic': time.monotonic() + 3600}
        b.save(self.path, value);self.pin = b.sha(self.path.read_bytes())
        self.socket = mock.patch.object(b, 'socket_info', return_value=SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_dev=1, st_ino=2));self.socket.start()
        self.c = b.load_controller(self.path, self.pin)
        self.docker = Docker(self.root)
        self.exec_mock = mock.patch.object(b, 'execute', side_effect=self.docker.execute);self.exec_mock.start()

    def tearDown(self):
        self.exec_mock.stop();self.socket.stop();self.temp.cleanup()

    def build(self):
        native = self.root / 'native';native.mkdir(exist_ok=True)
        context = native / 'context';context.mkdir(exist_ok=True)
        (context / 'Dockerfile').write_text('FROM scratch\n')
        return b.invoke(self.c, ['build', '--network=none', '--pull=false', '--platform=linux/arm64', '--iidfile', str(native / 'image-id'), str(context)])

    def worker(self):
        native = self.root / 'native';inputs = native / 'build-1/inputs';inputs.mkdir(parents=True)
        out = native / 'build-1/artifacts';out.mkdir()
        entry = native / 'entry.py';entry.write_text('never executed fixture')
        lock = native / 'packages.lock';lock.write_text('fixture 1\n')
        control = {'nonce': 'c' * 32, 'image_id': IMAGE, 'entry_script_sha256': b.sha(entry.read_bytes()), 'builder_inventory_sha256': b.sha(lock.read_bytes())}
        b.save(inputs / 'controller-input.json', control)
        args = ['run', '--name', WORKER, '--pull=never', '--platform=linux/arm64', '--user', f'{os.getuid()}:{os.getgid()}',
                '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only', '--pids-limit=512', '--memory=4g', '--cpus=4', '--network=none',
                '--tmpfs=/tmp:rw,nosuid,nodev,exec,size=4g', '--env=CACHY_ASAHI_CONTAINER=1', '--env=CACHY_ASAHI_IMAGE_ID=' + IMAGE,
                '--env=CACHY_ASAHI_UPDATE_BUILD_NONCE=' + 'c' * 32,
                '--env=CACHY_ASAHI_CONTROLLER_SHA256=' + b.sha((inputs / 'controller-input.json').read_bytes()), '--env=SOURCE_DATE_EPOCH=1789753605']
        for source, target in [(inputs, '/inputs'), (out, '/out'), (entry, '/builder-entry.sh'), (lock, '/expected-packages.lock')]:
            args += ['--mount', f'type=bind,src={source},dst={target}' + (',readonly' if target != '/out' else '')]
        return args + ['--entrypoint=/usr/bin/python', IMAGE, '/builder-entry.sh']

    def cleanup(self):
        return b.cleanup(self.root, NONCE, self.docker_file, self.c['docker_endpoint'], time.monotonic() + 120)

    def test_build_inventory_worker_intents_and_owned_cleanup(self):
        self.assertEqual(self.build(), 0)
        inventory = ['run', '--rm', '--pull=never', '--network=none', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only', '--entrypoint=/bin/cat', IMAGE, '/builder-packages.lock']
        self.assertEqual(b.invoke(self.c, inventory), 0)
        self.assertEqual(b.invoke(self.c, self.worker()), 0)
        data = json.loads((self.root / 'broker-registry.json').read_text())
        self.assertEqual(len(data['containers']), 2)
        self.assertTrue(data['containers'][0]['name'].startswith('cachy-asahi-stage-' + NONCE + '-'))
        self.assertEqual(data['docker_socket_identity'], {'device': 1, 'inode': 2})
        result = self.cleanup()
        self.assertEqual(result['status'], 'PASS');self.assertEqual(result['containers_absent'], 2);self.assertEqual(result['images_absent'], 1)
        self.assertFalse(self.docker.containers);self.assertFalse(self.docker.images)
        self.assertEqual(self.cleanup()['status'], 'PASS')

    def test_partial_build_without_iid_is_ambiguous_never_pruned(self):
        self.docker.cancel_build = True
        with self.assertRaises(b.BrokerError):self.build()
        self.assertEqual(self.cleanup()['status'], 'FAIL')
        self.assertFalse(any(args[0] in ('rmi', 'prune') for args in self.docker.calls))
        self.assertEqual(json.loads((self.root / 'broker-registry.json').read_text())['builds'][0]['status'], 'INTENT')

    def test_success_exit_without_iid_is_rejected(self):
        self.docker.no_iid = True
        with self.assertRaisesRegex(b.BrokerError, 'build-iid-missing'):self.build()
        self.assertEqual(self.cleanup()['status'], 'FAIL')

    def test_foreign_image_and_container_labels_never_removed(self):
        self.docker.bad_label = True
        with self.assertRaisesRegex(b.BrokerError, 'image-label-mismatch'):self.build()
        self.assertEqual(self.cleanup()['status'], 'FAIL')
        self.assertFalse(any(args[0] == 'rmi' for args in self.docker.calls))
        self.docker.images[IMAGE] = NONCE
        b.invoke(self.c, self.worker())
        self.docker.containers[WORKER] = 'foreign'
        result = self.cleanup();self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(self.docker.containers[WORKER], 'foreign')
        self.assertFalse(any(args[0] == 'rm' for args in self.docker.calls))

    def test_existing_name_and_duplicate_registry_claim_refused(self):
        self.build();args = self.worker();self.docker.containers[WORKER] = 'foreign'
        before = len(self.docker.calls)
        with self.assertRaisesRegex(b.BrokerError, 'already-exists'):b.invoke(self.c, args)
        self.assertFalse(any(row[0] == 'run' for row in self.docker.calls[before:]))
        self.docker.containers.clear();b.invoke(self.c, args)
        with self.assertRaisesRegex(b.BrokerError, 'name-claim'):b.invoke(self.c, args)

    def test_unknown_commands_and_scope_changing_options_refused(self):
        for args in (['system', 'prune'], ['image', 'ls'], ['rmi', IMAGE], ['rm', '--force', 'unrelated'], ['info', '--format', '{{.Name}}'], ['run', '--privileged', IMAGE]):
            with self.subTest(args=args), self.assertRaises(b.BrokerError):b.invoke(self.c, args)
        self.assertFalse(self.docker.calls)

    def test_worker_nonreadonly_outside_root_or_wrong_nonce_refused(self):
        self.build();args = self.worker()
        changes = []
        broken = args.copy();i = next(i for i,x in enumerate(broken) if x.startswith('type=bind') and 'dst=/inputs' in x);broken[i] = broken[i].replace(',readonly', '');changes.append(broken)
        broken = args.copy();broken[i] = 'type=bind,src=/etc,dst=/inputs,readonly';changes.append(broken)
        broken = args.copy();broken[2] = 'cachy-asahi-updater-' + 'd' * 32;changes.append(broken)
        for broken in changes:
            with self.subTest(args=broken[:3]), self.assertRaises(b.BrokerError):b.invoke(self.c, broken)
        self.assertFalse(any(row[0] == 'run' for row in self.docker.calls))

    def test_changed_socket_and_controller_pin_fail_before_docker(self):
        with mock.patch.object(b, 'socket_info', return_value=SimpleNamespace(st_mode=stat.S_IFSOCK, st_dev=1, st_ino=3)):
            with self.assertRaisesRegex(b.BrokerError, 'socket-identity-changed'):b.invoke(self.c, ['version'])
        self.assertFalse(self.docker.calls)
        self.path.write_text('{}');self.path.chmod(0o600)
        with self.assertRaisesRegex(b.BrokerError, 'controller-pin-drift'):b.invoke(self.c, ['version'])

    def test_cleanup_on_restarted_daemon_is_failure_without_mutation(self):
        self.build();before = len(self.docker.calls)
        with mock.patch.object(b, 'socket_info', return_value=SimpleNamespace(st_mode=stat.S_IFSOCK, st_dev=9, st_ino=2)):
            self.assertEqual(self.cleanup()['status'], 'FAIL')
        self.assertEqual(len(self.docker.calls), before)

    def test_empty_cleanup_avoids_daemon_and_validates_private_root(self):
        with mock.patch.object(b, 'socket_info', side_effect=AssertionError('socket inspected')):
            self.assertEqual(self.cleanup()['status'], 'PASS')
        self.assertFalse(self.docker.calls)
        self.root.chmod(0o755);self.assertEqual(self.cleanup()['status'], 'FAIL')

    def test_broken_registry_symlink_is_not_empty_success(self):
        (self.root / 'broker-registry.json').symlink_to(self.root / 'absent')
        self.assertEqual(self.cleanup()['status'], 'FAIL')
        self.assertFalse(self.docker.calls)

    def test_daemon_query_failure_cannot_prove_absence(self):
        self.build()
        original = self.docker.execute
        def fails(c, args, signals, **kwargs):
            if args[:2] == ['image', 'ls']: return 1, b''
            return original(c, args, signals, **kwargs)
        with mock.patch.object(b, 'execute', side_effect=fails):self.assertEqual(self.cleanup()['status'], 'FAIL')

    def test_lowlevel_spawn_registration_cancel_restores_masks_reaps_and_strips_env(self):
        self.exec_mock.stop()
        child = mock.Mock(pid=987654, returncode=-15, stdout=None)
        child.poll.return_value = None;child.wait.return_value = -15
        captured = {}
        before = signal.pthread_sigmask(signal.SIG_BLOCK, [])
        def spawn(command, **kwargs):
            captured.update(kwargs);captured['command'] = command
            self.assertIn(signal.SIGTERM, signal.pthread_sigmask(signal.SIG_BLOCK, []))
            os.kill(os.getpid(), signal.SIGTERM)
            return child
        token = {'pid': 987654, 'pgid': 987654, 'start_ticks': 42, 'uid': os.getuid()}
        with mock.patch.dict(os.environ, {'DOCKER_HOST': 'tcp://foreign', 'DOCKER_CONTEXT': 'foreign', 'TOKEN': 'never-forward'}), mock.patch.object(b.subprocess, 'Popen', side_effect=spawn), mock.patch.object(b.os, 'killpg') as kill, mock.patch.object(b, 'client_identity', return_value=token), mock.patch.object(b, 'group_absent', return_value=True):
            with self.assertRaisesRegex(b.BrokerError, 'cancelled'):b.invoke(self.c, ['version'])
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, []), before)
        self.assertIn(mock.call(987654, signal.SIGTERM), kill.call_args_list)
        self.assertTrue(child.wait.called)
        self.assertNotIn('TOKEN', captured['env']);self.assertNotIn('DOCKER_CONTEXT', captured['env'])
        self.assertEqual(captured['command'][:3], [str(self.docker_file), '--host', 'unix:///run/docker.sock'])
        self.assertIsNone(captured['stdout']);self.assertIsNone(captured['stderr'])
        row = json.loads((self.root / 'broker-registry.json').read_text())['clients'][0]
        self.assertEqual(row, dict(token, status='ABSENT'))

    def test_lowlevel_constructor_failure_restores_mask_and_keeps_intent(self):
        self.exec_mock.stop();before = signal.pthread_sigmask(signal.SIG_BLOCK, [])
        with mock.patch.object(b.subprocess, 'Popen', side_effect=OSError('fixture')), mock.patch.object(b.os, 'killpg') as kill:
            with self.assertRaises(OSError):b.invoke(self.c, ['version'])
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, []), before);kill.assert_not_called()
        data = json.loads((self.root / 'broker-registry.json').read_text())
        self.assertEqual(data['invocations'][-1]['status'], 'FAIL')
        self.assertEqual(data['clients'][0]['status'], 'NOT_STARTED')

    def test_first_client_registration_save_failure_still_kills_owned_popen(self):
        self.exec_mock.stop()
        child = mock.Mock(pid=987654, returncode=-15, stdout=None)
        child.poll.return_value = None;child.wait.return_value = -15
        original = b.save;failed = []
        def save(path, value):
            rows = value.get('clients', [])
            if rows and rows[-1]['pid'] == child.pid and rows[-1]['status'] == 'AMBIGUOUS' and not failed:
                failed.append(True);raise OSError('fixture registration save')
            return original(path, value)
        with mock.patch.object(b.subprocess, 'Popen', return_value=child), mock.patch.object(b, 'save', side_effect=save), mock.patch.object(b, 'client_identity', side_effect=AssertionError('unpersisted generation used')), mock.patch.object(b, 'group_absent', return_value=True), mock.patch.object(b.os, 'killpg') as kill:
            with self.assertRaises(OSError):b.invoke(self.c, ['version'])
        kill.assert_called_once_with(child.pid, signal.SIGTERM)
        self.assertTrue(child.wait.called)
        self.assertEqual(json.loads((self.root / 'broker-registry.json').read_text())['clients'][0]['status'], 'ABSENT')

    def test_real_private_child_first_registration_save_failure_reaped(self):
        self.exec_mock.stop()
        real_spawn, real_save, real_kill = subprocess.Popen, b.save, os.killpg
        children, sent, failed = [], [], []
        def spawn(command, **kwargs):
            child = real_spawn([sys.executable, '-I', '-B', '-c', 'import time;time.sleep(10)'], **kwargs)
            children.append(child);return child
        def save(path, value):
            rows = value.get('clients', [])
            if rows and rows[-1]['pid'] is not None and rows[-1]['status'] == 'AMBIGUOUS' and not failed:
                failed.append(True);raise OSError('fixture registration save')
            return real_save(path, value)
        def kill(group, signum):
            if signum: sent.append((group, signum))
            return real_kill(group, signum)
        try:
            with mock.patch.object(b.subprocess, 'Popen', side_effect=spawn), mock.patch.object(b, 'save', side_effect=save), mock.patch.object(b.os, 'killpg', side_effect=kill):
                with self.assertRaises(OSError):b.invoke(self.c, ['version'])
            self.assertEqual(len(children), 1)
            self.assertIsNotNone(children[0].poll())
            self.assertTrue(b.group_absent(children[0].pid))
            self.assertEqual(sent, [(children[0].pid, signal.SIGTERM)])
            self.assertEqual(json.loads((self.root / 'broker-registry.json').read_text())['clients'][0]['status'], 'ABSENT')
        finally:
            for child in children:
                if child.poll() is None:
                    try: real_kill(child.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    child.wait(timeout=3)

    def test_persistent_registration_save_failure_retains_unknown_intent(self):
        self.exec_mock.stop()
        child = mock.Mock(pid=987654, returncode=-15, stdout=None)
        child.poll.return_value = None;child.wait.return_value = -15
        original = b.save
        def save(path, value):
            if any(row['pid'] is not None for row in value.get('clients', [])):
                raise OSError('fixture persistent registration save')
            return original(path, value)
        with mock.patch.object(b.subprocess, 'Popen', return_value=child), mock.patch.object(b, 'save', side_effect=save), mock.patch.object(b, 'group_absent', return_value=True), mock.patch.object(b.os, 'killpg') as kill:
            with self.assertRaises(OSError):b.invoke(self.c, ['version'])
        kill.assert_called_once_with(child.pid, signal.SIGTERM)
        self.assertTrue(child.wait.called)
        row = json.loads((self.root / 'broker-registry.json').read_text())['clients'][0]
        self.assertEqual(row['status'], 'INTENT');self.assertIsNone(row['pid'])
        result = self.cleanup()
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('client-launch-ambiguous', result['failures'])

    def test_lowlevel_deadline_terminates_reaps_and_persists_absence(self):
        self.exec_mock.stop()
        child = mock.Mock(pid=987654, returncode=-15, stdout=None)
        child.poll.return_value = None;child.wait.return_value = -15
        token = {'pid': 987654, 'pgid': 987654, 'start_ticks': 42, 'uid': os.getuid()}
        expired = [False]
        original = time.monotonic
        def started(*args, **kwargs):
            expired[0] = True
            return child
        def clock(): return original() + (4000 if expired[0] else 0)
        with mock.patch.object(b.subprocess, 'Popen', side_effect=started), mock.patch.object(b.time, 'monotonic', side_effect=clock), mock.patch.object(b, 'client_identity', return_value=token), mock.patch.object(b, 'group_absent', return_value=True), mock.patch.object(b.os, 'killpg') as kill:
            with self.assertRaisesRegex(b.BrokerError, 'command-deadline'):b.invoke(self.c, ['version'])
        kill.assert_called_once_with(987654, signal.SIGTERM)
        self.assertTrue(child.wait.called)
        data = json.loads((self.root / 'broker-registry.json').read_text())
        self.assertEqual(data['clients'][0]['status'], 'ABSENT')
        self.assertEqual(data['invocations'][-1]['failure_code'], 'command-deadline')

    def add_client(self, **changes):
        b.invoke(self.c, ['version'])
        path = self.root / 'broker-registry.json';data = json.loads(path.read_text())
        row = {'pid': 987654, 'pgid': 987654, 'start_ticks': 42, 'uid': os.getuid(), 'status': 'LIVE'}
        row.update(changes);data['clients'].append(row);b.save(path, data)

    def test_unknown_launch_and_leaderless_nonempty_group_remain_ambiguous(self):
        self.add_client(pid=None, pgid=None, start_ticks=None, status='INTENT')
        self.assertEqual(self.cleanup()['status'], 'FAIL')
        path = self.root / 'broker-registry.json';data = json.loads(path.read_text());data['clients'].clear();b.save(path, data)
        self.add_client()
        with mock.patch.object(b, 'group_absent', return_value=False), mock.patch.object(b, 'client_identity', side_effect=FileNotFoundError), mock.patch.object(b.os, 'killpg') as kill:
            result = self.cleanup()
        self.assertEqual(result['status'], 'FAIL');self.assertIn('client-group-ambiguous', result['failures']);kill.assert_not_called()

    def test_reused_client_pid_never_signalled(self):
        self.add_client()
        changed = {'pid': 987654, 'pgid': 987654, 'start_ticks': 43, 'uid': os.getuid()}
        with mock.patch.object(b, 'group_absent', return_value=False), mock.patch.object(b, 'client_identity', return_value=changed), mock.patch.object(b.os, 'killpg') as kill, mock.patch.object(b.os, 'waitpid') as reap:
            self.assertEqual(self.cleanup()['status'], 'FAIL')
        kill.assert_not_called();reap.assert_not_called()

    def test_positive_pid_reap_distinguishes_not_our_child_and_generation_drift(self):
        row = {'pid': 987654, 'pgid': 987654, 'start_ticks': 42, 'uid': os.getuid()}
        with mock.patch.object(b, 'client_identity', return_value=row), mock.patch.object(b.os, 'waitpid', side_effect=ChildProcessError) as reap:
            self.assertEqual(b.reap_client(row, row), 'NOT_CHILD')
        reap.assert_called_once_with(row['pid'], os.WNOHANG)
        with mock.patch.object(b, 'client_identity', return_value=dict(row, start_ticks=43)), mock.patch.object(b.os, 'waitpid') as reap:
            with self.assertRaisesRegex(b.BrokerError, 'generation-changed'):b.reap_client(row, row)
        reap.assert_not_called()

    def runtime_adopted_client(self, cancel=False):
        spec = importlib.util.spec_from_file_location('review_runtime', Path(__file__).with_name('runtime.py'))
        runtime = importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
        prior_mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
        prior_handlers = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM)}
        prior_reaper = runtime._subreaper()
        logs = self.root / 'runtime-logs';logs.mkdir(mode=0o700)
        foreign = subprocess.Popen([sys.executable, '-I', '-B', '-c', 'import time;time.sleep(10)'],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        pid = None
        code = ('import subprocess,sys; p=subprocess.Popen([sys.executable,"-I","-B","-c",'
                '"import time;time.sleep(10)"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,'
                'start_new_session=True); print(p.pid,flush=True)')
        if cancel:code += '; import time;time.sleep(10)'
        fired = []
        def tick():
            if cancel and not fired and (logs/'stdout').read_text().strip():
                fired.append(True);os.kill(os.getpid(), signal.SIGTERM)
        try:
            try:
                process = runtime.run_process([sys.executable, '-I', '-B', '-c', code], logs/'stdout', logs/'stderr',
                                              time.monotonic()+2, {'PATH':'/usr/bin:/bin'}, self.root, on_tick=tick)
            except runtime.RuntimeCancelled as error:
                self.assertTrue(cancel);process = error.receipt
            self.assertEqual(process['status'], 'CANCELLED' if cancel else 'PASS');self.assertTrue(process['group_absent'])
            pid = int((logs/'stdout').read_text())
            token = b.client_identity(pid)
            self.assertFalse(b.group_absent(pid))
            b.invoke(self.c, ['version'])
            path = self.root/'broker-registry.json';data = json.loads(path.read_text())
            data['clients'].append(dict(token, status='LIVE'));b.save(path, data)
            start = time.monotonic();result = self.cleanup()
            self.assertEqual(result['status'], 'PASS');self.assertEqual(result['clients_absent'], 1)
            self.assertLess(time.monotonic()-start, 2)
            self.assertTrue(b.group_absent(pid));self.assertFalse(Path('/proc',str(pid)).exists())
            self.assertIsNone(foreign.poll())
            self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, []), prior_mask)
            self.assertEqual({s: signal.getsignal(s) for s in prior_handlers}, prior_handlers)
            self.assertEqual(runtime._subreaper(), prior_reaper)
        finally:
            if pid is None and (logs/'stdout').exists():
                value = (logs/'stdout').read_text().strip()
                if value.isdigit():pid = int(value)
            if pid is not None:
                try:os.killpg(pid, signal.SIGKILL)
                except ProcessLookupError:pass
                try:os.waitpid(pid, 0)
                except ChildProcessError:pass
            if foreign.poll() is None:
                os.killpg(foreign.pid, signal.SIGKILL)
            foreign.wait(timeout=3)

    def test_real_runtime_adopted_separate_session_client_is_killed_and_reaped(self):
        self.runtime_adopted_client()

    def test_real_runtime_cancel_adopted_client_is_killed_and_reaped(self):
        self.runtime_adopted_client(cancel=True)

    def test_matching_client_generation_terminated_and_proven_absent(self):
        self.add_client()
        token = {'pid': 987654, 'pgid': 987654, 'start_ticks': 42, 'uid': os.getuid()}
        with mock.patch.object(b, 'group_absent', side_effect=[False, False, True]), mock.patch.object(b, 'client_identity', return_value=token), mock.patch.object(b.os, 'killpg') as kill:
            result = self.cleanup()
        self.assertEqual(result['status'], 'PASS');self.assertEqual(result['clients_absent'], 1)
        kill.assert_called_once_with(987654, signal.SIGTERM)

    def test_completed_absence_receipt_does_not_target_reused_group(self):
        self.add_client(status='ABSENT')
        with mock.patch.object(b, 'group_absent', side_effect=AssertionError('completed group rechecked')), mock.patch.object(b.os, 'killpg') as kill:
            self.assertEqual(self.cleanup()['status'], 'PASS')
        kill.assert_not_called()

    def test_linux_client_generation_fields_parsed_without_argv_or_environment(self):
        directory = self.root / 'proc/1234';directory.mkdir(parents=True)
        fields = ['S', '1', '1234', '1234'] + ['0'] * 15 + ['42']
        (directory / 'stat').write_text('1234 (docker client) ' + ' '.join(fields))
        with mock.patch.object(b, 'PROC_ROOT', self.root / 'proc'):
            self.assertEqual(b.client_identity(1234), {'pid': 1234, 'pgid': 1234, 'start_ticks': 42, 'uid': os.getuid()})

    def test_waiting_registry_lock_cancellation_does_not_spawn(self):
        def lock(*args):
            os.kill(os.getpid(), signal.SIGTERM)
            raise BlockingIOError
        with mock.patch.object(b.fcntl, 'flock', side_effect=lock):
            with self.assertRaisesRegex(b.BrokerError, 'cancelled'):b.invoke(self.c, ['version'])
        self.assertFalse(self.docker.calls)

    def test_special_mode_executable_rejected_without_changing_pin(self):
        self.docker_file.chmod(0o4700)
        with self.assertRaisesRegex(b.BrokerError, 'special-file-mode'):b.invoke(self.c, ['version'])
        self.assertFalse(self.docker.calls)

    def test_client_generation_persisted_before_parent_unmask(self):
        self.exec_mock.stop()
        child = mock.Mock(pid=987654, returncode=0, stdout=None);child.poll.return_value = 0
        token = {'pid': 987654, 'pgid': 987654, 'start_ticks': 42, 'uid': os.getuid()}
        original = signal.pthread_sigmask;observed = []
        def mask(how, values):
            if how == signal.SIG_SETMASK:
                path = self.root / 'broker-registry.json'
                if path.exists():
                    rows = json.loads(path.read_text())['clients']
                    if rows and rows[-1]['pid'] == 987654 and rows[-1]['status'] == 'LIVE': observed.append(rows[-1].copy())
            return original(how, values)
        with mock.patch.object(b.subprocess, 'Popen', return_value=child), mock.patch.object(b, 'client_identity', return_value=token), mock.patch.object(b, 'group_absent', return_value=True), mock.patch.object(b.signal, 'pthread_sigmask', side_effect=mask):
            self.assertEqual(b.invoke(self.c, ['version']), 0)
        self.assertIn(dict(token, status='LIVE'), observed)


if __name__ == '__main__':unittest.main()
