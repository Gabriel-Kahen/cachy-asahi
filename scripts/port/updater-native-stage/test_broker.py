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
import threading
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
            assert len(args) == 3 and args[1] == '--no-prune' and b.IMAGE.fullmatch(args[2]), 'exact image removal guard'
            self.images.pop(args[2], None);return 0, b''
        if args[:2] == ['image', 'ls']:
            assert args[3] == '--filter=label=' + b.LABEL + '=' + NONCE
            return 0, b'\n'.join(image.encode() for image, label in self.images.items() if label == NONCE)
        return 0, b'private tool stdout unchanged'


class ImageGraphDocker(Docker):
    """Finite image graph: default removal prunes untagged parent images."""
    ANCESTOR = 'sha256:' + 'e' * 64

    def __init__(self, root):
        super().__init__(root)
        self.images[self.ANCESTOR] = 'foreign'
        self.parents = {IMAGE:self.ANCESTOR}
        self.untagged = {self.ANCESTOR}

    def execute(self, c, args, signals, capture=False, **kwargs):
        if args[:1] != ['rmi']:return super().execute(c, args, signals, capture, **kwargs)
        assert args in (['rmi', IMAGE], ['rmi', '--no-prune', IMAGE]), 'no force or foreign target'
        self.calls.append(args)
        self.images.pop(IMAGE, None)
        if '--no-prune' not in args:
            parent = self.parents[IMAGE]
            if parent in self.untagged and not any(child in self.images for child, ancestor in self.parents.items() if ancestor == parent):
                self.images.pop(parent, None)
        return 0, b''


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='broker-tests-')
        self.root = Path(self.temp.name);self.root.chmod(0o700)
        self.docker_file = self.root / 'real-docker';self.docker_file.write_bytes(b'never executed fixture');self.docker_file.chmod(0o700)
        self.daemon_temp = tempfile.TemporaryDirectory(prefix='broker-daemon-tests-')
        self.daemon = Path(self.daemon_temp.name);self.daemon.chmod(0o700)
        real_sample = b.storage_sample
        self.sample_mock = mock.patch.object(b, 'storage_sample', side_effect=lambda path: dict(real_sample(path), free_bytes=64 * b.STORAGE_GIB))
        self.sample_mock.start()
        self.path = self.root / 'broker-controller.json'
        value = {'schema_version': 1, 'nonce': NONCE, 'root': str(self.root), 'real_docker': str(self.docker_file),
                 'real_docker_sha256': hashlib.sha256(self.docker_file.read_bytes()).hexdigest(),
                 'docker_endpoint': 'unix:///run/docker.sock', 'docker_socket_identity': {'device': 1, 'inode': 2},
                 'deadline_monotonic': time.monotonic() + 3600, 'storage_policy': b.storage_policy(self.root, self.daemon)}
        b.save(self.path, value);self.pin = b.sha(self.path.read_bytes())
        self.socket = mock.patch.object(b, 'socket_info', return_value=SimpleNamespace(st_mode=stat.S_IFSOCK | 0o660, st_dev=1, st_ino=2));self.socket.start()
        self.c = b.load_controller(self.path, self.pin)
        b.storage_initialize(self.c)
        self.docker = Docker(self.root)
        self.exec_mock = mock.patch.object(b, 'execute', side_effect=self.docker.execute);self.exec_mock.start()

    def tearDown(self):
        self.exec_mock.stop();self.socket.stop();self.sample_mock.stop();self.daemon_temp.cleanup();self.temp.cleanup()

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
                '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only', '--pids-limit=512', '--memory=4g', '--cpus=4', '--network=none', '--ipc=private',
                '--tmpfs=/tmp:rw,nosuid,nodev,exec,size=4g', '--env=CACHY_ASAHI_CONTAINER=1', '--env=CACHY_ASAHI_IMAGE_ID=' + IMAGE,
                '--env=CACHY_ASAHI_UPDATE_BUILD_NONCE=' + 'c' * 32,
                '--env=CACHY_ASAHI_CONTROLLER_SHA256=' + b.sha((inputs / 'controller-input.json').read_bytes()), '--env=SOURCE_DATE_EPOCH=1789753605']
        for source, target in [(inputs, '/inputs'), (out, '/out'), (entry, '/builder-entry.sh'), (lock, '/expected-packages.lock')]:
            args += ['--mount', f'type=bind,src={source},dst={target}' + (',readonly' if target != '/out' else '')]
        return args + ['--entrypoint=/usr/bin/python', IMAGE, '/builder-entry.sh']

    def cleanup(self):
        return b.cleanup(self.root, NONCE, self.docker_file, self.c['docker_endpoint'], time.monotonic() + 120)

    def test_worker_private_ipc_is_forwarded_without_changing_ownership(self):
        self.build(); args = self.worker()
        data = json.loads((self.root / 'broker-registry.json').read_bytes())
        before = len(self.docker.calls)
        rewritten, resource = b.plan(self.c, args, data)
        self.assertEqual(rewritten, ['run', '--label', b.LABEL + '=' + NONCE, *args[1:]])
        self.assertEqual([value for value in rewritten if value.startswith('--ipc')], ['--ipc=private'])
        self.assertEqual(resource, ('container', {'name': WORKER, 'image_id': IMAGE, 'status': 'INTENT'}))
        self.assertEqual(len(self.docker.calls), before)

    def test_worker_missing_foreign_and_duplicate_ipc_refused_before_actor(self):
        self.build(); args = self.worker()
        data = json.loads((self.root / 'broker-registry.json').read_bytes())
        before = len(self.docker.calls)
        for mode in (None, 'host', 'shareable', 'none', '', 'container:foreign'):
            changed = [value for value in args if value != '--ipc=private']
            if mode is not None:
                changed.insert(3, '--ipc=' + mode)
            with self.subTest(mode=mode), self.assertRaisesRegex(b.BrokerError, 'worker-option-set'):
                b.plan(self.c, changed, data)
        changed = list(args); changed.insert(3, '--ipc=private')
        with self.assertRaisesRegex(b.BrokerError, 'worker-option-duplicate'):
            b.plan(self.c, changed, data)
        self.assertEqual(len(self.docker.calls), before)

    def test_inventory_ipc_grammar_remains_unchanged(self):
        self.build()
        args = ['run', '--rm', '--pull=never', '--network=none', '--cap-drop=ALL',
                '--security-opt=no-new-privileges', '--read-only', '--entrypoint=/bin/cat',
                IMAGE, '/builder-packages.lock']
        data = json.loads((self.root / 'broker-registry.json').read_bytes())
        rewritten, resource = b.plan(self.c, args, data)
        self.assertEqual(rewritten[5:], args[1:])
        self.assertFalse(any(value.startswith('--ipc') for value in rewritten))
        with self.assertRaises(b.BrokerError):
            b.plan(self.c, [args[0], '--ipc=private', *args[1:]], data)

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
        foreign = 'sha256:' + 'f' * 64;self.docker.images[foreign] = 'foreign'
        for _ in range(2):
            result = self.cleanup();self.assertEqual(result['status'], 'FAIL')
            self.assertEqual(result['failures'], ['image-id-missing'])
            self.assertEqual(self.docker.images, {foreign: 'foreign'})
        self.assertFalse(any(args[0] in ('rmi', 'prune') for args in self.docker.calls))
        self.assertEqual(json.loads((self.root / 'broker-registry.json').read_text())['builds'][0]['status'], 'INTENT')

    def test_success_exit_without_iid_is_rejected(self):
        self.docker.no_iid = True
        with self.assertRaisesRegex(b.BrokerError, 'build-iid-missing'):self.build()
        result = self.cleanup();self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['failures'], ['image-id-missing'])

    def test_foreign_image_and_container_labels_never_removed(self):
        self.docker.bad_label = True
        with self.assertRaisesRegex(b.BrokerError, 'image-label-mismatch'):self.build()
        result = self.cleanup();self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['failures'], ['image-owner-unverified'])
        self.assertFalse(any(args[0] == 'rmi' for args in self.docker.calls))
        self.docker.images[IMAGE] = NONCE
        b.invoke(self.c, self.worker())
        self.docker.containers[WORKER] = 'foreign'
        result = self.cleanup();self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(self.docker.containers[WORKER], 'foreign')
        self.assertFalse(any(args[0] == 'rm' for args in self.docker.calls))

    def test_invalid_image_id_cleanup_retains_image_without_removal(self):
        self.build();(self.root/'native/image-id').write_text('invalid-image-id\n')
        for _ in range(2):
            result = self.cleanup();self.assertEqual(result['status'], 'FAIL')
            self.assertEqual(result['failures'], ['image-id-invalid'])
        self.assertEqual(self.docker.images, {IMAGE:NONCE})
        self.assertFalse(any(args[0] in ('rmi', 'prune') for args in self.docker.calls))

    def test_drifted_image_id_cleanup_preserves_owned_and_foreign_images(self):
        self.build();foreign = 'sha256:'+'f'*64;self.docker.images[foreign] = 'foreign'
        (self.root/'native/image-id').write_text(foreign+'\n')
        for _ in range(2):
            result = self.cleanup();self.assertEqual(result['status'], 'FAIL')
            self.assertEqual(result['failures'], ['image-id-drift'])
        self.assertEqual(self.docker.images, {IMAGE:NONCE, foreign:'foreign'})
        self.assertFalse(any(args[0] in ('rmi', 'prune') for args in self.docker.calls))

    def test_image_remains_after_scoped_removal_is_specific_failure(self):
        self.build();original = self.docker.execute
        def retained(c, args, signals, **kwargs):
            if args[:1] == ['rmi']:
                self.assertEqual(args, ['rmi', '--no-prune', IMAGE])
                self.docker.calls.append(args);return 0, b''
            return original(c, args, signals, **kwargs)
        with mock.patch.object(b, 'execute', side_effect=retained):result = self.cleanup()
        self.assertEqual(result['status'], 'FAIL');self.assertEqual(result['failures'], ['image-remains'])
        self.assertEqual(self.docker.images, {IMAGE:NONCE})

    def test_unknown_image_cleanup_error_exports_only_fixed_ambiguity(self):
        self.build()
        with mock.patch.object(b, 'image_owned', side_effect=b.BrokerError('/private/secret detail')):
            result = self.cleanup()
        self.assertEqual(result['status'], 'FAIL');self.assertEqual(result['failures'], ['image-cleanup-ambiguous'])
        self.assertNotIn('secret', json.dumps(result));self.assertEqual(self.docker.images, {IMAGE:NONCE})
        self.assertFalse(any(args[0] in ('rmi', 'prune') for args in self.docker.calls))

    def test_no_prune_cleanup_preserves_foreign_untagged_ancestor(self):
        graph = ImageGraphDocker(self.root)
        with mock.patch.object(b, 'execute', side_effect=graph.execute):
            self.build();result = self.cleanup()
            self.assertEqual(result['status'], 'PASS')
            self.assertNotIn(IMAGE, graph.images)
            self.assertEqual(graph.images, {graph.ANCESTOR:'foreign'})
            self.assertIn(['rmi', '--no-prune', IMAGE], graph.calls)
            self.assertEqual(self.cleanup()['status'], 'PASS')
            self.assertEqual(graph.images, {graph.ANCESTOR:'foreign'})

    def test_default_pruning_source_variant_fails_foreign_ancestor_survival(self):
        source = Path(b.__file__).read_text()
        new = "query(c, ['rmi', '--no-prune', image], signals, False)"
        self.assertEqual(source.count(new), 1)
        variant = type(b)('default_pruning_broker')
        exec(compile(source.replace(new, "query(c, ['rmi', image], signals, False)"), b.__file__, 'exec'), variant.__dict__)
        graph = ImageGraphDocker(self.root)
        with mock.patch.object(b, 'execute', side_effect=graph.execute):self.build()
        with mock.patch.object(variant, 'execute', side_effect=graph.execute), mock.patch.object(variant, 'socket_info', side_effect=b.socket_info):
            result = variant.cleanup(self.root, NONCE, self.docker_file, self.c['docker_endpoint'], time.monotonic()+120)
        self.assertEqual(result['status'], 'PASS')  # nonce absence alone cannot detect foreign ancestry loss
        self.assertNotIn(graph.ANCESTOR, graph.images)
        with self.assertRaises(AssertionError):self.assertEqual(graph.images, {graph.ANCESTOR:'foreign'})
        self.assertIn(['rmi', IMAGE], graph.calls)

    def test_mock_image_remove_rejects_missing_guard_force_and_foreign_target(self):
        self.build()
        for args in (['rmi', IMAGE], ['rmi', '--force', IMAGE], ['rmi', '--no-prune', '--force', IMAGE], ['rmi', '--no-prune', 'foreign-name']):
            with self.subTest(args=args), self.assertRaises(AssertionError):
                self.docker.execute(self.c, args, None)
        self.assertEqual(self.docker.images, {IMAGE:NONCE})

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
        with mock.patch.object(b, 'execute', side_effect=fails):
            result = self.cleanup();self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['failures'], ['image-daemon-query-failed'])

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

    def test_latched_storage_blocks_build_and_run_allows_reads_and_scoped_remove(self):
        self.build();args = self.worker();b.invoke(self.c, args)
        path = self.root/'storage-state.json';state = json.loads(path.read_text())
        state.update(latched=True, reason='observation-failed');b.save(path, state)
        before = len(self.docker.calls)
        with self.assertRaisesRegex(b.BrokerError, 'docker-storage-budget'):
            b.invoke(self.c, ['run', '--rm', '--pull=never', '--network=none', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only', '--entrypoint=/bin/cat', IMAGE, '/builder-packages.lock'])
        native = self.root/'native';context = native/'context'
        with self.assertRaisesRegex(b.BrokerError, 'docker-storage-budget'):
            b.invoke(self.c, ['build', '--network=none', '--pull=false', '--platform=linux/arm64', '--iidfile', str(native/'image-id-2'), str(context)])
        self.assertFalse(any(row[0] in ('build', 'run') for row in self.docker.calls[before:]))
        self.assertEqual(b.invoke(self.c, ['version']), 0)
        self.assertEqual(b.invoke(self.c, ['image','inspect',IMAGE]), 0)
        self.assertEqual(b.invoke(self.c, ['rm','--force',WORKER]), 0)
        self.assertNotIn(WORKER, self.docker.containers)
        self.assertEqual(self.cleanup()['status'], 'PASS')  # rejected create adds no ambiguous resource intent
        self.assertFalse(any(row[0] == 'prune' for row in self.docker.calls))

    def test_spawn_and_generation_registration_hold_admission_release_before_wait(self):
        self.exec_mock.stop()
        child = mock.Mock(pid=987654, returncode=0, stdout=None)
        order = []
        child.poll.return_value = 0
        child.wait.side_effect = lambda **kwargs: order.append('wait') or 0
        token = {'pid':987654, 'pgid':987654, 'start_ticks':42, 'uid':os.getuid()}
        original_admission = b.storage_admission
        @b.contextmanager
        def admission(c):
            with original_admission(c) as state:
                order.append('admit');yield state;order.append('release')
        def spawn(*args, **kwargs):order.append('spawn');return child
        original_save = b.save
        def save(path, value):
            if any(row.get('pid') == child.pid and row.get('status') == 'LIVE' for row in value.get('clients', [])):
                order.append('registered')
            return original_save(path, value)
        try:
            with mock.patch.object(b, 'storage_admission', side_effect=admission), mock.patch.object(b.subprocess, 'Popen', side_effect=spawn), mock.patch.object(b, 'client_identity', return_value=token), mock.patch.object(b, 'save', side_effect=save), mock.patch.object(b, 'group_absent', return_value=True):
                with self.assertRaisesRegex(b.BrokerError, 'build-iid-missing'):self.build()
            spawn_index = order.index('spawn')
            registration_index = order.index('registered', spawn_index)
            release_index = order.index('release', registration_index)
            wait_index = order.index('wait', release_index)
            self.assertLess(spawn_index, registration_index);self.assertLess(registration_index, release_index)
            self.assertLess(release_index, wait_index)
        finally:self.exec_mock.start()

    def test_delayed_admission_deadline_refuses_spawn_without_sleep(self):
        self.exec_mock.stop();base = time.monotonic();expired = [False]
        c = dict(self.c, _client_intent=mock.Mock(return_value={}), _client_started=mock.Mock(), _client_done=mock.Mock())
        original_admission = b.storage_admission
        @b.contextmanager
        def delayed(controller):
            with original_admission(controller) as state:
                expired[0] = True
                try:yield state
                finally:expired[0] = False
        try:
            with b.Signals() as signals, mock.patch.object(b.time, 'monotonic', side_effect=lambda: base+(4000 if expired[0] else 0)), mock.patch.object(b, 'storage_admission', side_effect=delayed), mock.patch.object(b.subprocess, 'Popen') as spawn:
                with self.assertRaisesRegex(b.BrokerError, 'command-deadline'):b.execute(c, ['build'], signals)
            spawn.assert_not_called();c['_client_started'].assert_not_called();c['_client_done'].assert_called_once_with({}, False)
        finally:self.exec_mock.start()

    def test_pending_cancel_during_admission_refuses_spawn_and_restores_mask(self):
        self.exec_mock.stop();before = signal.pthread_sigmask(signal.SIG_BLOCK, [])
        c = dict(self.c, _client_intent=mock.Mock(return_value={}), _client_started=mock.Mock(), _client_done=mock.Mock())
        original_admission = b.storage_admission
        @b.contextmanager
        def cancelled(controller):
            with original_admission(controller) as state:
                os.kill(os.getpid(), signal.SIGTERM);yield state
        try:
            with b.Signals() as signals, mock.patch.object(b, 'storage_admission', side_effect=cancelled), mock.patch.object(b.subprocess, 'Popen') as spawn:
                with self.assertRaisesRegex(b.BrokerError, 'cancelled'):b.execute(c, ['build'], signals)
            spawn.assert_not_called();c['_client_started'].assert_not_called();c['_client_done'].assert_called_once_with({}, False)
            self.assertIn(signal.SIGTERM, signals.seen)
            self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, []), before)
        finally:self.exec_mock.start()


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='storage-tests-')
        self.daemon_temp = tempfile.TemporaryDirectory(prefix='storage-daemon-tests-')
        self.root, self.daemon = Path(self.temp.name), Path(self.daemon_temp.name)
        self.root.chmod(0o700);self.daemon.chmod(0o700)
        self.free = {str(self.root): 30 * b.STORAGE_GIB, str(self.daemon): 30 * b.STORAGE_GIB}
        self.devices = {str(self.root): self.root.stat().st_dev, str(self.daemon): self.daemon.stat().st_dev}
        self.real_sample = b.storage_sample
        self.sample = mock.patch.object(b, 'storage_sample', side_effect=self.sampled);self.sample.start()
        self.c = {'root': str(self.root), 'nonce': NONCE, '_sha256': 'd' * 64}

    def tearDown(self):
        self.sample.stop();self.daemon_temp.cleanup();self.temp.cleanup()

    def sampled(self, path):
        value = self.real_sample(path)
        return dict(value, device=self.devices[str(path)], free_bytes=self.free[str(path)])

    def start(self, separate=False):
        if separate: self.devices[str(self.daemon)] += 1
        self.c['storage_policy'] = b.storage_policy(self.root, self.daemon)
        return b.storage_initialize(self.c)

    def test_shared_private_four_daemon_five_admitted_with_twenty_one_free(self):
        initial = self.start()
        self.assertEqual(initial['mode'], 'shared');self.assertEqual(len(initial['filesystems']), 1)
        self.free.update({str(self.root): 21 * b.STORAGE_GIB, str(self.daemon): 21 * b.STORAGE_GIB})
        result = b.storage_check(self.c, create=True)
        row = result['filesystems'][0]
        self.assertEqual(row['peak_growth_bytes'], 9 * b.STORAGE_GIB)
        self.assertEqual(row['current_free_bytes'], 21 * b.STORAGE_GIB)
        self.assertEqual(row['growth_limit_bytes'], 16 * b.STORAGE_GIB)
        self.assertFalse(result['latched'])
        self.assertFalse(any(str(self.root) in str(value) for value in result.values()))

    def test_cap_exact_boundary_then_overshoot_latches_despite_restoration(self):
        self.start()
        self.free[str(self.root)] = self.free[str(self.daemon)] = 14 * b.STORAGE_GIB
        self.assertFalse(b.storage_check(self.c)['latched'])
        self.free[str(self.root)] -= 1
        with self.assertRaisesRegex(b.BrokerError, 'docker-storage-budget'):b.storage_check(self.c)
        result = b.storage_projection(self.c)
        self.assertTrue(result['latched']);self.assertEqual(result['reason'], 'growth-limit')
        peak = result['filesystems'][0]['peak_growth_bytes']
        self.free[str(self.root)] = self.free[str(self.daemon)] = 40 * b.STORAGE_GIB
        with self.assertRaisesRegex(b.BrokerError, 'docker-storage-budget'):b.storage_check(self.c, create=True)
        result = b.storage_projection(self.c)
        self.assertEqual(result['filesystems'][0]['peak_growth_bytes'], peak)
        self.assertEqual(result['filesystems'][0]['current_free_bytes'], 40 * b.STORAGE_GIB)
        self.assertEqual(result['reason'], 'growth-limit')

    def test_reserve_exact_floor_allowed_then_exhaustion_code_frozen(self):
        self.free[str(self.root)] = self.free[str(self.daemon)] = 18 * b.STORAGE_GIB
        self.start()
        self.free[str(self.root)] = 2 * b.STORAGE_GIB
        b.storage_check(self.c)
        self.free[str(self.root)] -= 1
        with self.assertRaisesRegex(b.BrokerError, 'docker-storage-budget'):b.storage_check(self.c)
        self.assertEqual(b.storage_projection(self.c)['reason'], 'reserve-floor')

    def test_reserve_exhaustion_from_admitted_baseline_records_breach(self):
        self.start()
        self.free[str(self.root)] = b.STORAGE_GIB
        with self.assertRaisesRegex(b.BrokerError, 'docker-storage-budget'):b.storage_check(self.c)
        state = b.storage_projection(self.c)
        self.assertTrue(state['latched']);self.assertEqual(state['reason'], 'reserve-floor')
        self.assertLess(state['filesystems'][0]['current_free_bytes'], b.STORAGE_RESERVE)

    def test_low_initial_free_records_baseline_floor_before_creation(self):
        self.free[str(self.root)] = self.free[str(self.daemon)] = 18 * b.STORAGE_GIB - 1
        self.c['storage_policy'] = b.storage_policy(self.root, self.daemon)
        with self.assertRaisesRegex(b.BrokerError, 'docker-storage-budget'):b.storage_initialize(self.c)
        self.assertEqual(b.storage_projection(self.c)['reason'], 'baseline-floor')
        self.assertEqual(stat.S_IMODE((self.root/'storage-state.json').stat().st_mode), 0o600)
        self.free[str(self.root)] = self.free[str(self.daemon)] = 64 * b.STORAGE_GIB
        with self.assertRaisesRegex(b.BrokerError, 'docker-storage-budget'):b.storage_check(self.c)
        with self.assertRaises(FileExistsError):b.storage_initialize(self.c)

    def test_separate_filesystem_each_eight_gib_counts_once(self):
        state = self.start(separate=True)
        self.assertEqual([row['role'] for row in state['filesystems']], ['private', 'daemon'])
        self.free[str(self.root)] -= 4 * b.STORAGE_GIB
        self.free[str(self.daemon)] -= 5 * b.STORAGE_GIB
        state = b.storage_check(self.c)
        self.assertEqual([row['peak_growth_bytes'] for row in state['filesystems']], [4*b.STORAGE_GIB, 5*b.STORAGE_GIB])
        self.free[str(self.daemon)] -= 3 * b.STORAGE_GIB + 1
        with self.assertRaisesRegex(b.BrokerError, 'docker-storage-budget'):b.storage_check(self.c)
        self.assertEqual(b.storage_projection(self.c)['reason'], 'growth-limit')

    def test_wrong_device_or_inode_observation_latches(self):
        self.start()
        self.devices[str(self.daemon)] += 1
        with self.assertRaisesRegex(b.BrokerError, 'docker-storage-budget'):b.storage_check(self.c)
        self.assertEqual(b.storage_projection(self.c)['reason'], 'observation-failed')
        self.devices[str(self.daemon)] -= 1
        with self.assertRaisesRegex(b.BrokerError, 'docker-storage-budget'):b.storage_check(self.c)

    def test_daemon_replacement_observation_latches(self):
        self.start()
        original = self.daemon.with_name(self.daemon.name+'-old')
        self.daemon.rename(original);self.daemon.mkdir(mode=0o700)
        try:
            with self.assertRaisesRegex(b.BrokerError, 'docker-storage-budget'):b.storage_check(self.c)
            self.assertEqual(b.storage_projection(self.c)['reason'], 'observation-failed')
        finally:self.daemon.rmdir();original.rename(self.daemon)

    def test_missing_existing_state_never_reinitialized(self):
        self.start();(self.root/'storage-state.json').unlink()
        with self.assertRaises(FileNotFoundError):b.storage_check(self.c)
        with self.assertRaises(FileExistsError):b.storage_initialize(self.c)

    def test_forged_state_schema_counters_and_binding_refused(self):
        self.start();path = self.root/'storage-state.json';original = json.loads(path.read_text())
        for change in ('bool-counter', 'wrong-binding', 'missing-latch', 'extra-field', 'bad-reason', 'peak-less-than-growth'):
            state = json.loads(json.dumps(original))
            if change == 'bool-counter':state['filesystems'][0]['current_free_bytes'] = True
            elif change == 'wrong-binding':state['controller_sha256'] = 'e'*64
            elif change == 'missing-latch':del state['latched']
            elif change == 'extra-field':state['rawpath'] = '/private/secret'
            elif change == 'bad-reason':state.update(latched=True, reason='/private/secret')
            else:state['filesystems'][0]['current_free_bytes'] -= 1
            b.save(path, state)
            with self.subTest(change=change), self.assertRaises(b.BrokerError):b.storage_projection(self.c)
        b.save(path, original)

    def test_policy_alias_bool_and_wrong_device_relation_refused(self):
        with self.assertRaisesRegex(b.BrokerError, 'storage-path-alias'):b.storage_policy(self.root, self.root)
        child = self.root/'daemon';child.mkdir(mode=0o700)
        self.free[str(child)] = 30*b.STORAGE_GIB;self.devices[str(child)] = child.stat().st_dev
        with self.assertRaisesRegex(b.BrokerError, 'storage-path-alias'):b.storage_policy(self.root, child)
        policy = b.storage_policy(self.root, self.daemon)
        for key, value in [('private_limit_bytes', True), ('mode', 'separate'), ('reserve_bytes', 0)]:
            with self.subTest(key=key), self.assertRaises(b.BrokerError):b.storage_validate_policy(dict(policy, **{key:value}), str(self.root))

    def test_real_fd_sample_rejects_symlink_and_directory_race_without_leaks(self):
        link = self.root/'link';link.symlink_to(self.daemon, target_is_directory=True)
        before = len(list(Path('/proc/self/fd').iterdir()))
        with self.assertRaises((b.BrokerError, OSError)):self.real_sample(link)
        original = self.daemon.with_name(self.daemon.name+'-race')
        def racing(fd):
            self.daemon.rename(original);self.daemon.mkdir(mode=0o700)
            return SimpleNamespace(f_bavail=30, f_frsize=b.STORAGE_GIB)
        try:
            with mock.patch.object(b.os, 'fstatvfs', side_effect=racing), self.assertRaisesRegex(b.BrokerError, 'storage-identity'):
                self.real_sample(self.daemon)
        finally:self.daemon.rmdir();original.rename(self.daemon)
        self.assertEqual(len(list(Path('/proc/self/fd').iterdir())), before)

    def test_lock_symlink_hardlink_and_root_replacement_refused(self):
        self.start();lock = self.root/'storage.lock';lock.unlink();lock.symlink_to(self.root/'storage-state.json')
        with self.assertRaises(OSError):b.storage_projection(self.c)
        lock.unlink();os.link(self.root/'storage-state.json', lock)
        with self.assertRaisesRegex(b.BrokerError, 'storage-lock-owner'):b.storage_projection(self.c)
        lock.unlink()
        original = self.root.with_name(self.root.name+'-old')
        self.root.rename(original);self.root.mkdir(mode=0o700)
        try:
            with self.assertRaisesRegex(b.BrokerError, 'storage-root-identity'):b.storage_check(self.c)
        finally:self.root.rmdir();original.rename(self.root)

    def test_real_opath_statvfs_supports_unreadable_final_directory(self):
        self.daemon.chmod(0)
        try:
            result = self.real_sample(self.daemon)
            self.assertEqual(result['inode'], self.daemon.stat().st_ino)
            self.assertGreaterEqual(result['free_bytes'], 0)
        finally:self.daemon.chmod(0o700)

    def test_sample_depth_bound_before_open_and_scalar_overflow(self):
        with mock.patch.object(b.os, 'open') as opened:
            with self.assertRaisesRegex(b.BrokerError, 'storage-depth-bound'):
                self.real_sample('/tmp/' + '/'.join('a' for _ in range(129)))
        opened.assert_not_called()
        for available, unit in ((-1, 1), (True, 1), (1, 0), (2**63, 1)):
            with self.subTest(available=available, unit=unit), mock.patch.object(b.os, 'fstatvfs', return_value=SimpleNamespace(f_bavail=available, f_frsize=unit)), self.assertRaisesRegex(b.BrokerError, 'storage-sample-bound'):
                self.real_sample(self.daemon)

    def test_barrier_latch_commit_serializes_with_spawn_admission(self):
        self.start();attempted = threading.Event();committed = threading.Event();outcomes = []
        original_flock = b.fcntl.flock
        def flock(fd, operation):
            if threading.current_thread().name == 'storage-observer':attempted.set()
            return original_flock(fd, operation)
        def observe():
            try:b.storage_check(self.c)
            except b.BrokerError as error:outcomes.append(error.code)
            finally:committed.set()
        with mock.patch.object(b.fcntl, 'flock', side_effect=flock):
            with b.storage_admission(self.c):
                self.free[str(self.root)] = b.STORAGE_GIB
                thread = threading.Thread(target=observe, name='storage-observer');thread.start()
                self.assertTrue(attempted.wait(1));self.assertFalse(committed.is_set())
                outcomes.append('spawn-and-register')
            thread.join(2)
            self.assertFalse(thread.is_alive());self.assertTrue(committed.is_set())
            self.assertEqual(outcomes, ['spawn-and-register', 'docker-storage-budget'])
            with self.assertRaisesRegex(b.BrokerError, 'docker-storage-budget'):
                with b.storage_admission(self.c):outcomes.append('forbidden-spawn')
        self.assertNotIn('forbidden-spawn', outcomes)
        self.assertEqual(b.storage_projection(self.c)['reason'], 'reserve-floor')


class GuardianDiagnosticControls(unittest.TestCase):
    """Exact extracted guardian definitions; every actor primitive is a fake."""
    @staticmethod
    def fixture(faults=None):
        import ast
        import re
        from contextlib import nullcontext
        raw=Path(b.__file__).read_bytes();tree=ast.parse(raw)
        names={'BrokerError','need','sha','guardian_first','guardian_fact','guardian_write',
               'guardian_emit','execute','_guardian_execute'}
        constants={'COMMAND_SECONDS','QUERY_BYTES','GUARDIAN_PHASES','GUARDIAN_ERROR_CLASSES','GUARDIAN_PREDICATES'}
        nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names or
               isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id in constants for t in n.targets)]
        ns={'hashlib':hashlib,'re':re,'json':json,'Path':Path,'sys':sys}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),'<guardian-extracted>','exec'),ns)
        faults=dict(faults or {});events=[];storage={'file':None};client={'status':'INTENT'}
        def hit(name):
            events.append(name);error=faults.pop(name,None)
            if error is not None:raise error
        class Process:
            pid=1234;stdout=None;returncode=0
            def poll(self):hit('WAIT');return self.returncode
            def wait(self,timeout):hit('RETIRE');return self.returncode
        process=Process()
        def popen(*args,**kwargs):hit('SPAWN');return process
        def started(row,pid):hit('REGISTER');row['status']='LIVE'
        def done(row,started):hit('DONE');row['status']='ABSENT' if started else 'NOT_STARTED'
        def mask(how,value):
            hit('UNMASK' if how==2 else 'MASK');return set()
        class Selector:
            def __enter__(self):return self
            def __exit__(self,*args):return False
        def opening(path,flags,mode):
            hit('OPEN')
            assert str(path)=='/tmp/fixture/broker-diagnostic.json' and mode==0o600
            assert flags==os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW
            if storage['file'] is not None:raise FileExistsError()
            storage['file']=b'';return 99
        def writing(fd,raw):
            hit('WRITE');assert fd==99 and len(raw)<=4096
            if faults.pop('SHORT',False):storage['file']=raw[:-1];return len(raw)-1
            storage['file']=raw;return len(raw)
        fakeos=SimpleNamespace(open=opening,write=writing,fsync=lambda fd:hit('FSYNC'),
            close=lambda fd:hit('CLOSE'),killpg=lambda *args:hit('KILLPG'),
            O_WRONLY=os.O_WRONLY,O_CREAT=os.O_CREAT,O_EXCL=os.O_EXCL,O_NOFOLLOW=os.O_NOFOLLOW)
        ns.update(os=fakeos,time=SimpleNamespace(monotonic=lambda:1),
            signal=SimpleNamespace(SIG_BLOCK=1,SIG_SETMASK=2,SIGTERM=15,SIGKILL=9,
                pthread_sigmask=mask,sigpending=lambda:set()),
            subprocess=SimpleNamespace(Popen=popen,PIPE=-1,DEVNULL=-3,TimeoutExpired=subprocess.TimeoutExpired),
            selectors=SimpleNamespace(DefaultSelector=Selector),
            socket_identity=lambda c:hit('SOCKET'),regular=lambda *args:b'exe',
            nullcontext=nullcontext,storage_admission=lambda c:nullcontext())
        c=dict(root='/tmp/fixture',_sha256='a'*64,deadline_monotonic=100,
            real_docker='/bin/fixture',real_docker_sha256=hashlib.sha256(b'exe').hexdigest(),
            docker_endpoint='unix:///fixture',_client_intent=lambda:client,_client_started=started,_client_done=done)
        signals=SimpleNamespace(seen=[],signals={15,2})
        return ns,c,signals,storage,events,faults,process
    def run_call(self,fixture):
        ns,c,signals,*_=fixture
        return ns['execute'](c,['version'],signals)
    def test_success_does_not_publish(self):
        f=self.fixture();self.assertEqual(self.run_call(f),(0,b''));self.assertIsNone(f[3]['file'])
        self.assertNotIn('OPEN',f[4])
    def test_first_error_phase_survives_retirement_failure(self):
        first=ValueError('PRIVATE first');second=OSError('PRIVATE retirement')
        f=self.fixture({'REGISTER':first,'DONE':second})
        with self.assertRaises(OSError) as caught:self.run_call(f)
        self.assertIs(caught.exception,second)  # Existing finally override remains held.
        fact=json.loads(f[3]['file']);self.assertEqual(fact['first_error'],'VALUE_ERROR')
        self.assertEqual(fact['phase'],'CLIENT_REGISTER');self.assertEqual(fact['retirement'],'FAIL')
        self.assertNotIn('PRIVATE',f[3]['file'].decode())
    def test_falsey_original_identity_and_ordinary_writer_fault(self):
        class Falsey(OSError):
            def __bool__(self):return False
        first=Falsey('PRIVATE');f=self.fixture({'REGISTER':first,'OPEN':OSError('writer')})
        with self.assertRaises(Falsey) as caught:self.run_call(f)
        self.assertIs(caught.exception,first);self.assertIsNone(f[3]['file'])
    def test_control_identity_survives_writer_control(self):
        first=KeyboardInterrupt();writer=SystemExit(7)
        f=self.fixture({'REGISTER':first,'WRITE':writer})
        with self.assertRaises(KeyboardInterrupt) as caught:self.run_call(f)
        self.assertIs(caught.exception,first);self.assertEqual(f[3]['file'],b'')
        self.assertEqual(f[4].count('CLOSE'),1)
    def test_retirement_failure_without_work_error(self):
        first=OSError('retirement');f=self.fixture({'RETIRE':first})
        with self.assertRaises(OSError) as caught:self.run_call(f)
        self.assertIs(caught.exception,first)
        fact=json.loads(f[3]['file']);self.assertEqual(fact['phase'],'PROCESS_RETIRE')
        self.assertEqual(fact['retirement'],'FAIL')
    def test_early_error_retirement_unknown(self):
        first=ValueError('socket');f=self.fixture({'SOCKET':first})
        with self.assertRaises(ValueError) as caught:self.run_call(f)
        self.assertIs(caught.exception,first)
        fact=json.loads(f[3]['file']);self.assertEqual(fact['phase'],'SOCKET_PIN')
        self.assertEqual(fact['retirement'],'UNKNOWN');self.assertNotIn('SPAWN',f[4])
    def test_closed_predicate_and_unknown_code_redaction(self):
        for code in ('cancelled','query-output-bound','PRIVATE code'):
            f=self.fixture();error=f[0]['BrokerError'](code);f[5]['REGISTER']=error
            with self.assertRaises(f[0]['BrokerError']):self.run_call(f)
            fact=json.loads(f[3]['file'])
            self.assertEqual(fact['first_predicate'],code if code!='PRIVATE code' else 'UNKNOWN')
            self.assertNotIn('PRIVATE',f[3]['file'].decode())
    def test_first_publication_is_not_overwritten(self):
        f=self.fixture({'REGISTER':ValueError('first')})
        with self.assertRaises(ValueError):self.run_call(f)
        original=f[3]['file'];f[5]['REGISTER']=OSError('later')
        with self.assertRaises(OSError):self.run_call(f)
        self.assertEqual(f[3]['file'],original)
        self.assertEqual(f[4].count('WRITE'),1)
    def test_partial_first_publication_is_not_retried(self):
        f=self.fixture({'REGISTER':ValueError('first'),'SHORT':True})
        with self.assertRaises(ValueError):self.run_call(f)
        partial=f[3]['file'];self.assertFalse(partial.endswith(b'\n'))
        f[5]['REGISTER']=OSError('later')
        with self.assertRaises(OSError):self.run_call(f)
        self.assertEqual(f[3]['file'],partial);self.assertEqual(f[4].count('WRITE'),1)
    def test_fact_closed_shape_and_type_redaction(self):
        f=self.fixture();ns,c=f[:2]
        error=ns['BrokerError']('PRIVATE');error.code=object()
        state=dict(first=error,phase='WAIT',first_phase='WAIT',retirement='PASS')
        fact=ns['guardian_fact'](c,state)
        self.assertEqual(set(fact),{'schema_version','purpose','broker_controller_sha256','phase','first_error','first_predicate','retirement'})
        self.assertEqual(fact['first_predicate'],'UNKNOWN');self.assertLessEqual(len(json.dumps(fact).encode()),4096)
        for key,value in [('first_phase','FOREIGN'),('retirement','FOREIGN')]:
            bad=dict(state);bad[key]=value
            with self.assertRaises(ns['BrokerError']):ns['guardian_fact'](c,bad)
    def test_new_writer_control_propagates_without_active_cause(self):
        f=self.fixture({'OPEN':KeyboardInterrupt()});ns,c=f[:2]
        state=dict(first=ValueError('past'),first_phase='WAIT',retirement='UNKNOWN')
        with self.assertRaises(KeyboardInterrupt):ns['guardian_emit'](c,state)
    def test_writer_preserves_first_control_over_close_fault(self):
        first=KeyboardInterrupt();f=self.fixture({'WRITE':first,'CLOSE':OSError('close')});ns,c=f[:2]
        state=dict(first=ValueError('past'),first_phase='WAIT',retirement='UNKNOWN')
        with self.assertRaises(KeyboardInterrupt) as caught:ns['guardian_write'](c,ns['guardian_fact'](c,state))
        self.assertIs(caught.exception,first);self.assertEqual(f[4].count('CLOSE'),1)
    def test_writer_control_propagates_over_active_ordinary_error(self):
        first=ValueError('first');control=KeyboardInterrupt()
        f=self.fixture({'REGISTER':first,'OPEN':control})
        with self.assertRaises(KeyboardInterrupt) as caught:self.run_call(f)
        self.assertIs(caught.exception,control);self.assertIs(control.__context__,first)
    def test_close_control_propagates_over_ordinary_write_error(self):
        first=OSError('write');control=SystemExit(9)
        f=self.fixture({'WRITE':first,'CLOSE':control});ns,c=f[:2]
        state=dict(first=ValueError('past'),first_phase='WAIT',retirement='UNKNOWN')
        with self.assertRaises(SystemExit) as caught:ns['guardian_write'](c,ns['guardian_fact'](c,state))
        self.assertIs(caught.exception,control);self.assertIs(control.__context__,first)


if __name__ == '__main__':unittest.main()
