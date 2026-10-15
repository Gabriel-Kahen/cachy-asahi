#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Portable stage boundary fixtures only: never runs Docker or native client tests."""
import argparse
import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('client_stage', Path(__file__).with_name('stage.py'))
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
IMAGE = 'sha256:' + 'a' * 64
ENDPOINT = 'unix:///var/run/docker.sock'


def receipt():
    return {'schema_version': 1, 'purpose': s.PURPOSE, 'status': 'PASS', 'image_id': IMAGE,
            'bootstrap_sha256': 'b' * 64, 'packages_sha256': s.PACKAGES_SHA,
            'source_sha256': dict(s.FROZEN), 'architecture': 'aarch64', 'uid': 1001,
            'native_client_tests': 'PASS', 'hardware': 'NOT RUN', 'production_acceptance': 'NOT RUN',
            'cleanup': {'processes': 'PASS', 'private_tmpfs': 'PASS'},
            'suite': {'tests': 48, 'skipped': 0, 'failures': 0, 'errors': 0, 'status': 'PASS',
                      'outcomes': [{'test': ident, 'status': 'PASS'} for ident in sorted(s.TEST_IDS)]}}


class StageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='client-stage-portable-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_read_rejects_symlink_hardlink_fifo_directory(self):
        data = self.root / 'data'
        data.write_bytes(b'fixture')
        symlink = self.root / 'alias'
        symlink.symlink_to(data)
        with self.assertRaises(ValueError):s.read(symlink)
        linked = self.root / 'linked'
        os.link(data, linked)
        with self.assertRaises(ValueError):s.read(data)
        fifo = self.root / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):s.read(fifo)
        with self.assertRaises(ValueError):s.read(self.root)

    def test_read_byte_limit_and_hash_drift(self):
        path = self.root / 'file'
        path.write_bytes(b'abcdef')
        with self.assertRaises(ValueError):s.read(path, 5)
        with self.assertRaises(ValueError):s.checked(path, '0' * 64)
        self.assertEqual(s.checked(path, hashlib.sha256(b'abcdef').hexdigest()), b'abcdef')

    def test_duplicate_json_rejected(self):
        with self.assertRaises(ValueError):s.decode(b'{"status":1,"status":2}')

    def test_inventory_requires_complete_canonical_341(self):
        rows = {f'pkg{i:03}': '1-1' for i in range(341)}
        data = ''.join(f'{k} {v}\n' for k, v in rows.items()).encode()
        self.assertEqual(s.inventory(data), rows)
        for wrong in (data[:-1], b'pkg 1-1\n', data + b'pkg000 1-1\n', b'\n' + data):
            with self.assertRaises(ValueError):s.inventory(wrong)

    def test_bootstrap_actual_inventory_and_image_binding(self):
        lock = Path('scripts/ci/maintained-native/locks/builder-successor.lock').read_bytes()
        value = {'status': 'image-provisioned', 'image_id': IMAGE, 'inputs_sha256': s.INPUTS_SHA,
                 'packages_lock_sha256': s.PACKAGES_SHA}
        self.assertEqual(s.bootstrap(json.dumps(value).encode(), lock, IMAGE), value)
        for field, wrong in [('status', 'PASS'), ('image_id', 'tag'), ('inputs_sha256', '0' * 64), ('packages_lock_sha256', '0' * 64)]:
            changed = dict(value, **{field: wrong})
            with self.assertRaises(ValueError):s.bootstrap(json.dumps(changed).encode(), lock, IMAGE)

    def test_frozen_sources_rechecked_and_guard_is_fixed(self):
        root = Path(__file__).resolve().parents[2]
        files, pins = s.source_pins(root, hashlib.sha256(s.read(root / 'scripts/client/stage.py')).hexdigest(), s.GUARD_SHA)
        self.assertEqual(len(files), 7)
        self.assertEqual({k: pins[k] for k in s.FROZEN}, s.FROZEN)
        with self.assertRaises(ValueError):s.source_pins(root, '0' * 64, s.GUARD_SHA)
        with self.assertRaises(ValueError):s.source_pins(root, '0' * 64, '0' * 64)

    def test_source_delivery_is_required_checked_worker_source(self):
        root = Path(__file__).resolve().parents[2]
        stage_sha = s.digest(s.read(root / 'scripts/client/stage.py'))
        files, pins = s.source_pins(root, stage_sha, s.GUARD_SHA)
        helper = 'scripts/release/source_delivery.py'
        self.assertIn(helper, s.FROZEN)
        self.assertEqual(s.digest(files[helper]), pins[helper])
        for name, data in files.items():
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        s.source_pins(self.root, stage_sha, s.GUARD_SHA)
        path = self.root / helper
        path.write_bytes(files[helper] + b'\n# unreviewed drift\n')
        with self.assertRaisesRegex(ValueError, 'input-pin-mismatch'):
            s.source_pins(self.root, stage_sha, s.GUARD_SHA)
        path.unlink()
        with self.assertRaises(FileNotFoundError):s.source_pins(self.root, stage_sha, s.GUARD_SHA)

    def test_live_host_worker_refusal_precedes_input_or_write(self):
        with mock.patch.object(s, 'worker_guard') as guard:
            with self.assertRaises(ValueError):s.worker(argparse.Namespace())
            guard.assert_not_called()

    def test_live_nonarm_coordinator_refuses_before_docker(self):
        if platform.machine() in ('aarch64', 'arm64') and os.geteuid() != 0:
            return  # Platform-independent guard tests below cover native contract validation.
        with mock.patch.object(s, 'successful') as execute:
            with self.assertRaises(ValueError):s.run_stage(argparse.Namespace())
            execute.assert_not_called()

    def test_actual_guard_requires_all_protected_proc_mounts(self):
        guard = mock.Mock()
        guard.READONLY_PROC = {'/proc/sys', '/proc/fs'}
        guard.environment.return_value = {'mounts': {'/proc/sys': {}}, 'uid': 1001}
        spec = mock.Mock()
        with mock.patch.object(s, 'checked'), mock.patch.object(s.importlib.util, 'spec_from_file_location', return_value=spec), \
                mock.patch.object(s.importlib.util, 'module_from_spec', return_value=guard):
            with self.assertRaisesRegex(ValueError, 'missing-protected-proc'):s.worker_guard(s.GUARD_SHA)

    def test_controlled_environment_has_no_host_session_credentials(self):
        env = s.controlled_env(Path('/tmp/client-stage'))
        self.assertEqual(env['PATH'], '/usr/bin:/bin')
        self.assertEqual(env['GNUPGHOME'], '/tmp/client-stage/gnupg')
        self.assertFalse(set(env) & {'SSH_AUTH_SOCK', 'DBUS_SESSION_BUS_ADDRESS', 'GPG_AGENT_INFO', 'PYTHONPATH', 'LD_PRELOAD'})

    def test_bounded_command_success_and_nonzero(self):
        self.assertEqual(s.bounded([sys.executable, '-I', '-c', 'print("fixture")']), (0, b'fixture\n'))
        with self.assertRaises(ValueError):s.successful([sys.executable, '-I', '-c', 'raise SystemExit(3)'])

    def test_bounded_stream_limit_before_completion(self):
        with self.assertRaisesRegex(ValueError, 'output-bound'):
            s.bounded([sys.executable, '-I', '-c', 'import os,time;os.write(1,b"x"*8192);time.sleep(30)'], limit=4096)

    def test_bounded_deadline_kills_process(self):
        with self.assertRaisesRegex(ValueError, 'timeout'):
            s.bounded([sys.executable, '-I', '-c', 'import time;time.sleep(30)'], timeout=0.1)

    def test_container_command_never_builds_installs_or_fetches(self):
        argv = s.container_command(IMAGE, 'fixture', self.root, self.root / 'out', 1001, 'b' * 64, s.GUARD_SHA, endpoint=ENDPOINT)
        self.assertEqual(argv[:3], ['docker', '--host=' + ENDPOINT, 'create'])
        for required in ('--read-only', '--cap-drop=ALL', '--network=none', '--pull=never', '--pids-limit=64', '-I'):
            self.assertIn(required, argv)
        for forbidden in ('--privileged', '--device', '--net=host', '--pid=host', 'build', 'pull', 'pacman'):
            self.assertNotIn(forbidden, argv)
        self.assertEqual(argv[-4:], ['--contract-sha256', 'b' * 64, '--guard-sha256', s.GUARD_SHA])

    def container(self):
        source, output, uid = str(self.root), str(self.root / 'out'), 1001
        return {'Image': IMAGE, 'Config': {'User': '1001:1001', 'Env': ['HOME=x', 'PATH=x', 'PYTHONDONTWRITEBYTECODE=1',
                   'CACHY_ASAHI_IMAGE_ID=x', 'CACHY_ASAHI_CLIENT_UID=x']}, 'HostConfig': {'ReadonlyRootfs': True,
                   'NetworkMode': 'none', 'Privileged': False, 'CapDrop': ['ALL'], 'CapAdd': [],
                   'SecurityOpt': ['no-new-privileges'], 'Memory': 1024**3, 'MemorySwap': 1024**3,
                   'NanoCpus': 2 * 10**9, 'PidsLimit': 64, 'IpcMode': 'private', 'PidMode': '', 'UTSMode': '',
                   'Devices': [], 'DeviceRequests': [], 'VolumesFrom': [], 'PortBindings': {},
                   'Tmpfs': {'/tmp': 'rw,nosuid,nodev,exec,size=256m,mode=0700,uid=1001,gid=1001'}},
                   'Mounts': [{'Destination': '/source', 'Type': 'bind', 'Source': source, 'RW': False},
                              {'Destination': '/out', 'Type': 'bind', 'Source': output, 'RW': True}]}

    def test_inspection_rejects_runtime_isolation_drift(self):
        value = self.container()
        s.inspect_container(value, IMAGE, self.root, self.root / 'out', 1001)
        for field, wrong in [('ReadonlyRootfs', False), ('NetworkMode', 'host'), ('Privileged', True),
                             ('CapAdd', ['KILL']), ('PidsLimit', 0), ('MemorySwap', -1), ('PidMode', 'host')]:
            bad = copy.deepcopy(value)
            bad['HostConfig'][field] = wrong
            with self.subTest(field=field), self.assertRaises(ValueError):s.inspect_container(bad, IMAGE, self.root, self.root / 'out', 1001)

    def test_inspection_rejects_extra_bind_and_ambient_env(self):
        value = self.container()
        value['Config']['Env'].append('PYTHONPATH=/host')
        with self.assertRaises(ValueError):s.inspect_container(value, IMAGE, self.root, self.root / 'out', 1001)
        value = self.container()
        value['Mounts'][0]['RW'] = True
        with self.assertRaises(ValueError):s.inspect_container(value, IMAGE, self.root, self.root / 'out', 1001)

    def test_receipt_requires_48_unique_passes_zero_skips_and_counts(self):
        s.validate_receipt(receipt())
        for field, wrong in [('tests', 37), ('tests', 47), ('tests', 49), ('tests', True),
                             ('skipped', 1), ('failures', 1), ('errors', 1)]:
            bad = receipt()
            bad['suite'][field] = wrong
            with self.assertRaises(ValueError):s.validate_receipt(bad)
        bad = receipt()
        bad['suite']['outcomes'][-1] = bad['suite']['outcomes'][0]
        with self.assertRaises(ValueError):s.validate_receipt(bad)

    def test_current48_refuses_historical_purpose_missing_or_failed_outcomes(self):
        bad = receipt()
        bad['purpose'] = 'frozen-37-client-native-source-tests'
        with self.assertRaises(ValueError):s.validate_receipt(bad)
        bad = receipt()
        bad['suite']['outcomes'].pop()
        with self.assertRaisesRegex(ValueError, 'incomplete-client-suite'):s.validate_receipt(bad)
        bad = receipt()
        bad['suite']['outcomes'][0]['status'] = 'FAIL'
        with self.assertRaisesRegex(ValueError, 'incomplete-client-suite'):s.validate_receipt(bad)

    def test_receipt_refuses_unexpected_private_text_and_extra_fields(self):
        bad = receipt()
        bad['suite']['outcomes'][0]['test'] = 'PRIVATE KEY fixture'
        with self.assertRaises(ValueError):s.validate_receipt(bad)
        bad = receipt()
        bad['raw_log'] = 'fixture'
        with self.assertRaises(ValueError):s.validate_receipt(bad)
        bad = receipt()
        bad['source_sha256']['fixture'] = 'not a digest'
        with self.assertRaises(ValueError):s.validate_receipt(bad)

    def test_failure_receipt_does_not_claim_pass(self):
        bad = receipt()
        bad.update(status='FAIL', native_client_tests='FAIL')
        bad['suite'].update(status='FAIL', failures=1)
        bad['suite']['outcomes'][0]['status'] = 'FAIL'
        s.validate_receipt(bad)

    def test_daemon_cleanup_requires_private_pid1(self):
        with mock.patch.object(s.os, 'getpid', return_value=22), mock.patch.object(s, 'process_ids') as ids:
            with self.assertRaises(ValueError):s.cleanup_processes()
            ids.assert_not_called()

    def test_daemon_cleanup_signals_only_observed_namespace_pids(self):
        with mock.patch.object(s.os, 'getpid', return_value=1), mock.patch.object(s, 'process_ids', side_effect=[{5}, set()]), \
                mock.patch.object(s.os, 'kill') as kill, mock.patch.object(s.os, 'waitpid', side_effect=ChildProcessError):
            self.assertTrue(s.cleanup_processes())
            kill.assert_called_once_with(5, signal.SIGTERM)

    def test_stopped_state_rejects_oom_nonzero_running_and_error(self):
        state = {'Status': 'exited', 'Running': False, 'Paused': False, 'Restarting': False,
                 'Dead': False, 'OOMKilled': False, 'ExitCode': 0, 'Error': ''}
        s.stopped_state({'State': state})
        for field, wrong in [('Status', 'running'), ('Running', True), ('OOMKilled', True), ('ExitCode', 1), ('Error', 'fixture')]:
            with self.assertRaises(ValueError):s.stopped_state({'State': dict(state, **{field: wrong})})

    def test_signals_raise_and_cleanup_defers_repeated_signal(self):
        before = signal.getsignal(signal.SIGTERM)
        with s.cancellation_handlers():
            with self.assertRaises(s.Cancelled):signal.raise_signal(signal.SIGTERM)
            with s.defer_signals():signal.raise_signal(signal.SIGTERM)
            self.assertTrue(s.CANCELLED)
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)

    def test_remove_requires_daemon_confirmed_name_and_id_absence(self):
        with mock.patch.object(s, 'bounded', return_value=(0, b'')), \
                mock.patch.object(s, 'successful', side_effect=[b'', b'c' * 64]) as query:
            with self.assertRaises(ValueError):s.remove_container('fixture', 'c' * 64, {}, endpoint=ENDPOINT)
            self.assertEqual(query.call_count, 2)

    def controller_fixture(self, *, cancelled=False, malformed=False, cleanup_fails=False, oom=False, context_switch=False):
        # Mock daemon responses only: no native execution or architecture override interface.
        boot = self.root / 'bootstrap.json'
        boot.write_text(json.dumps({'status': 'image-provisioned', 'image_id': IMAGE,
                        'inputs_sha256': s.INPUTS_SHA, 'packages_lock_sha256': s.PACKAGES_SHA}))
        source = Path(__file__).resolve().parents[2]
        args = argparse.Namespace(image=IMAGE, bootstrap=boot, bootstrap_sha256=s.digest(boot.read_bytes()),
                    packages=source / 'scripts/ci/maintained-native/locks/builder-successor.lock',
                    packages_sha256=s.PACKAGES_SHA, source=source,
                    stage_sha256=s.digest(s.read(source / 'scripts/client/stage.py')),
                    guard_sha256=s.GUARD_SHA, output=self.root / 'evidence')
        paths, commands = {}, []
        context = {'endpoint': ENDPOINT}
        def bound(argv):
            self.assertEqual(argv[:2], ['docker', '--host=' + ENDPOINT])
            # The daemon would route an unbound command to the changed remote context.
            if context_switch:
                self.assertEqual(context['endpoint'], 'tcp://unreviewed-daemon.invalid:2375')
            return ['docker', *argv[2:]]
        def execute(argv, **options):
            commands.append(argv)
            if argv[:3] == ['docker', 'context', 'inspect']:
                value = json.dumps([{'Endpoints': {'docker': {'Host': context['endpoint']}}}]).encode()
                if context_switch:
                    context['endpoint'] = 'tcp://unreviewed-daemon.invalid:2375'
                return value
            argv = bound(argv)
            if argv[:2] == ['docker', 'info']:return b'aarch64\n'
            if argv[:3] == ['docker', 'image', 'inspect']:
                return json.dumps([{'Id': IMAGE, 'Architecture': 'arm64', 'Os': 'linux'}]).encode()
            if argv[:2] == ['docker', 'create']:
                mounts = [argv[i+1] for i, x in enumerate(argv) if x == '--mount']
                paths['source'] = Path(mounts[0].split('src=', 1)[1].split(',dst=', 1)[0])
                paths['public'] = Path(mounts[1].split('src=', 1)[1].split(',dst=', 1)[0])
                return b'c' * 64
            if argv[:2] == ['docker', 'inspect']:
                value = self.container()
                value['Mounts'][0]['Source'] = str(paths['source'])
                value['Mounts'][1]['Source'] = str(paths['public'])
                value['State'] = {'Status': 'exited', 'Running': False, 'Paused': False,
                                  'Restarting': False, 'Dead': False, 'OOMKilled': oom, 'ExitCode': 0, 'Error': ''}
                return json.dumps([value]).encode()
            if argv[:3] == ['docker', 'container', 'ls']:
                return b'c' * 64 if cleanup_fails else b''
            raise AssertionError('unexpected mock daemon command')
        def attach(argv, **options):
            commands.append(argv)
            argv = bound(argv)
            if argv[:2] == ['docker', 'rm']:return 0, b''
            self.assertEqual(argv[:3], ['docker', 'start', '--attach'])
            if cancelled:
                s.interrupt()
            value = receipt()
            contract = json.loads((paths['source'] / 'client-stage-inputs.json').read_bytes())
            value.update(source_sha256=contract['source_sha256'], bootstrap_sha256=contract['bootstrap_sha256'])
            if malformed:value['source_sha256']['scripts/client/client.py'] = 'PRIVATE KEY fixture'
            (paths['public'] / 'worker-receipt.json').write_text(json.dumps(value))
            return 0, b'PRIVATE TEST diagnostic discarded'
        with mock.patch.object(s.platform, 'system', return_value='Linux'), \
                mock.patch.object(s.platform, 'machine', return_value='aarch64'), \
                mock.patch.object(s.os, 'geteuid', return_value=1001), \
                mock.patch.object(s, 'successful', side_effect=execute), \
                mock.patch.object(s, 'bounded', side_effect=attach):
            report = s.run_stage(args)
        return report, paths, commands

    def test_controller_pass_requires_cleanup_and_sanitizes_attach(self):
        report, paths, commands = self.controller_fixture()
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(report['container_cleanup'], 'PASS')
        self.assertEqual(report['controller_tmp_removed'], 'PASS')
        self.assertFalse(paths['source'].parent.exists())
        self.assertNotIn('PRIVATE TEST diagnostic', json.dumps(report))
        self.assertEqual(sum(cmd[:3] == ['docker', '--host=' + ENDPOINT, 'inspect'] for cmd in commands), 2)

    def test_controller_cancellation_removes_container_and_private_work(self):
        report, paths, commands = self.controller_fixture(cancelled=True)
        self.assertEqual(report['status'], 'FAIL')
        self.assertEqual(report['container_cleanup'], 'PASS')
        self.assertEqual(report['native_client_tests'], 'NOT RUN')
        self.assertTrue(report['cancelled'])
        self.assertFalse(paths['source'].parent.exists())
        self.assertTrue(any(cmd[2:3] == ['rm'] for cmd in commands))

    def test_controller_malformed_receipt_never_exports_worker_or_private_value(self):
        report, _, _ = self.controller_fixture(malformed=True)
        self.assertEqual(report['status'], 'FAIL')
        self.assertNotIn('worker', report)
        self.assertNotIn('PRIVATE KEY', json.dumps(report))
        self.assertEqual(report['native_client_tests'], 'NOT RUN')

    def test_controller_removal_failure_overrides_success(self):
        report, _, _ = self.controller_fixture(cleanup_fails=True)
        self.assertEqual(report['status'], 'FAIL')
        self.assertEqual(report['container_cleanup'], 'FAIL')

    def test_controller_oom_cannot_pass(self):
        report, _, _ = self.controller_fixture(oom=True)
        self.assertEqual(report['status'], 'FAIL')
        self.assertEqual(report['container_cleanup'], 'PASS')

    def test_worker_signal_during_receipt_sync_rewrites_fail(self):
        value = receipt()
        target = self.root / 'worker-receipt.json'
        actual_sync = s.os.fsync
        fired = []
        def cancel(fd):
            actual_sync(fd)
            if not fired:
                fired.append(True)
                signal.raise_signal(signal.SIGTERM)
        with s.cancellation_handlers(), mock.patch.object(s.os, 'fsync', side_effect=cancel):
            s.finalize_receipt(target, value)
        saved = json.loads(target.read_bytes())
        self.assertEqual(saved['status'], 'FAIL')
        self.assertTrue(saved['cancelled'])
        s.validate_receipt(saved)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_controller_signal_during_receipt_sync_rewrites_fail(self):
        value = {'status': 'PASS', 'container_cleanup': 'PASS'}
        target = self.root / 'controller-receipt.json'
        actual_sync = s.os.fsync
        fired = []
        def cancel(fd):
            actual_sync(fd)
            if not fired:
                fired.append(True)
                signal.raise_signal(signal.SIGINT)
        with s.cancellation_handlers(), mock.patch.object(s.os, 'fsync', side_effect=cancel):
            s.finalize_receipt(target, value)
        self.assertEqual(value['status'], 'FAIL')
        self.assertEqual(json.loads(target.read_bytes())['status'], 'FAIL')

    def test_inspection_handles_reported_tmpfs_without_accepting_extra_mount(self):
        value = self.container()
        value['Mounts'].append({'Type': 'tmpfs', 'Destination': '/tmp', 'RW': True})
        s.inspect_container(value, IMAGE, self.root, self.root / 'out', 1001)
        value['Mounts'][-1]['Destination'] = '/host'
        with self.assertRaises(ValueError):s.inspect_container(value, IMAGE, self.root, self.root / 'out', 1001)

    def test_aborted_worker_has_unknown_counts_and_cannot_pass(self):
        value = receipt()
        value.update(status='FAIL', native_client_tests='FAIL')
        value['suite'] = {'tests': None, 'skipped': None, 'failures': None, 'errors': None,
                          'status': 'FAIL', 'outcomes': [], 'aborted': True}
        s.validate_receipt(value)
        value['status'] = 'PASS'
        with self.assertRaises(ValueError):s.validate_receipt(value)

    def test_every_command_keeps_validated_endpoint_after_default_context_switch(self):
        report, _, commands = self.controller_fixture(context_switch=True)
        self.assertEqual(report['status'], 'PASS')
        self.assertEqual(commands[0], ['docker', 'context', 'inspect'])
        for command in commands[1:]:
            self.assertEqual(command[:2], ['docker', '--host=' + ENDPOINT])
        self.assertEqual(report['docker_endpoint'], ENDPOINT)
        self.assertTrue(any(command[2:3] == ['rm'] for command in commands))
        self.assertEqual(sum(command[2:4] == ['container', 'ls'] for command in commands), 2)

    def test_docker_command_refuses_unreviewed_endpoint(self):
        for endpoint in ('tcp://remote:2375', 'unix:///tmp/unknown.sock', ''):
            with self.assertRaises(ValueError):s.docker_command(endpoint, 'rm', 'fixture')

    def test_expected_ids_match_exact_frozen_19_portable_and_29_gpg_source(self):
        data = Path(__file__).with_name('test_client.py').read_bytes()
        self.assertEqual(s.digest(data), s.FROZEN['scripts/client/test_client.py'])
        classes = [node for node in ast.parse(data).body if isinstance(node, ast.ClassDef)
                   and node.name in {'PortableTests', 'GPGTests'}]
        actual = {f'client_stage_tests.{cls.name}.{method.name}' for cls in classes for method in cls.body
                  if isinstance(method, ast.FunctionDef) and method.name.startswith('test_')}
        self.assertEqual(s.TEST_IDS, actual)
        self.assertEqual(sum('.PortableTests.' in ident for ident in actual), 19)
        self.assertEqual(sum('.GPGTests.' in ident for ident in actual), 29)

    def test_pass_rejects_48_unique_invented_cases_despite_valid_count_and_regex(self):
        value = receipt()
        value['suite']['outcomes'] = [{'test': f'client_stage_tests.PortableTests.test_case_{i}', 'status': 'PASS'} for i in range(48)]
        with self.assertRaisesRegex(ValueError, 'incomplete-client-suite'):s.validate_receipt(value)

    def test_pass_requires_all_29_gpg_cases_in_addition_to_real_portable_cases(self):
        value = receipt()
        portable = [row for row in value['suite']['outcomes'] if '.PortableTests.' in row['test']]
        replacements = [{'test': f'client_stage_tests.PortableTests.test_extra_{i}', 'status': 'PASS'} for i in range(29)]
        value['suite']['outcomes'] = portable + replacements
        self.assertEqual(len({row['test'] for row in value['suite']['outcomes']}), 48)
        with self.assertRaisesRegex(ValueError, 'incomplete-client-suite'):s.validate_receipt(value)

    def test_result_export_omits_tracebacks_and_reasons(self):
        result = s.Result()
        case = mock.Mock()
        case.id.return_value = next(ident for ident in sorted(s.TEST_IDS) if '.PortableTests.' in ident)
        result.addSuccess(case)
        self.assertEqual(result.rows, [{'test': case.id(), 'status': 'PASS'}])
        result.addSkip(case, 'PRIVATE KEY fixture')
        self.assertNotIn('PRIVATE KEY', json.dumps(result.rows))


if __name__ == '__main__':
    unittest.main(verbosity=2)
