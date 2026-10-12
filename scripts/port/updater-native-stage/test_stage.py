"""Finite orchestration fixtures; no native acceptance, Git, Docker or builds.

Authenticated synthetic contracts mock Git/host trust only. Snapshot hashes and
modes, private registration/removal, semantic projection and guards are real.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
STAGE_BYTES = (HERE / 'stage.py').read_bytes()
stage = types.ModuleType('updater_stage_fixture'); stage.__file__ = str(HERE / 'stage.py')
exec(compile(STAGE_BYTES, stage.__file__, 'exec'), stage.__dict__)
PREFIX = 'scripts/port/updater-native-stage/'
H = 'a' * 64
POISON = b'password=DO_NOT_EXPORT_RAW_SOURCE_CACHE_OR_ENV'


class StageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='updater-stage-fixture-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.base.chmod(0o700)
        self.root = self.base / 'checkout'; self.root.mkdir(mode=0o700)
        self.output = self.base / 'evidence'
        self.storage = self.base / 'docker-storage'; self.storage.mkdir(mode=0o700)
        self.rows = {}; self.commands = []; self.guard_inputs = []; self.cleanup_calls = []
        self.mode = 'pass'; self.source_drift = False; self.project_fail = False; self.guard_fail = False
        self.put(PREFIX + 'stage.py', STAGE_BYTES)
        for name in ('runtime.py', 'source.py'):
            self.put(PREFIX + name, (HERE / name).read_bytes())
        self.put(PREFIX + 'public_worker.py', (HERE / 'public_worker.py').read_bytes())
        self.put(PREFIX + 'broker.py', b'#!/usr/bin/env python3\n# never executed fixture\n')
        self.put(stage.PACKAGE + 'runner-inputs.lock.json', b'{}\n')
        for name in ('updater-native.py', 'materialize-inputs.py'):
            self.put(stage.PACKAGE + name, b'# intercepted; never executed\n')
        for name in ('scripts/ci/integration_export.py', 'scripts/ci/log_evidence.py',
                     stage.PACKAGE + 'public-evidence.py'):
            self.put(name, (ROOT / name).read_bytes())
        self.own = self.root / PREFIX
        self.original_module = stage.module
        self.runtime = self.original_module(self.own / 'runtime.py')
        self.actual_guard = self.original_module(self.root / 'scripts/ci/integration_export.py')
        self.actual_selector = self.original_module(self.root / (stage.PACKAGE + 'public-evidence.py'))
        self.actual_bundle = self.original_module(self.root / 'scripts/ci/log_evidence.py')
        self.source = types.SimpleNamespace(verify=self.verify_source)
        self.broker = types.SimpleNamespace(cleanup=self.broker_cleanup)
        self.tool_rows = {}
        for name in ('python', 'docker', 'git', 'gpg', 'gpgconf'):
            path = self.base / ('fixture-' + name); path.write_bytes(b'never executed tool ' + name.encode())
            path.chmod(0o644)
            self.tool_rows[name] = {'path': str(path), 'sha256': stage.digest(path.read_bytes())}
        self.host = {'system': 'Linux', 'machine': 'aarch64', 'release': 'synthetic',
                     'uid': os.getuid(), 'gid': os.getgid(), 'boot_id_sha256': H,
                     'docker_socket_identity': {'device': 1, 'inode': 2}}
        self.contract = {'schema_version': 1, 'scope': 'finite private native updater trial',
                         'budget': copy.deepcopy(stage.BUDGET), 'host': self.host,
                         'docker_endpoint': stage.ENDPOINT, 'tools': self.tool_rows,
                         'source': {'schema_version': 1, 'source_commit': 'a' * 40,
                                    'ready_sha256': stage.READY_SHA, 'files': self.rows}}
        self.controller = self.base / 'controller.json'; stage.save(self.controller, self.contract)
        self.controller_sha = stage.digest(self.controller.read_bytes())
        for patch in (mock.patch.object(stage, 'HERE', self.own),
                      mock.patch.object(stage, 'host', return_value=self.host),
                      mock.patch.object(stage, 'module', side_effect=self.module),
                      mock.patch.object(stage.shutil, 'disk_usage', return_value=shutil._ntuple_diskusage(2**50, 0, 2**50))):
            patch.start(); self.addCleanup(patch.stop)

    def put(self, name, data, mode=0o644):
        path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data); path.chmod(mode)
        self.rows[name] = {'sha256': stage.digest(data), 'git_blob': 'b' * 40,
                           'git_mode': '100644' if mode == 0o644 else '100755', 'file_mode': mode}

    def verify_source(self, root, contract):
        self.assertEqual(root, self.root)
        if self.source_drift or contract['source_commit'] != 'a' * 40:
            raise ValueError('source-contract-drift')
        if {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()} != set(contract['files']):
            raise ValueError('source-package-closure')
        for name, row in contract['files'].items():
            path = root / name
            if stage.digest(stage.regular(path)) != row['sha256'] or (path.stat().st_mode & 0o7777) != row['file_mode']:
                raise ValueError('source-contract-drift')

    def module(self, path, expected=None):
        if expected:
            if stage.digest(stage.regular(path, 32 * 1024**2)) != expected:
                raise ValueError('module-pin')
        if path.name == 'runtime.py': return self.runtime
        if path.name == 'source.py': return self.source
        if path.name == 'broker.py': return self.broker
        if path.name == 'integration_export.py': return types.SimpleNamespace(export_evidence=self.export)
        if path.name == 'public-evidence.py': return types.SimpleNamespace(project_evidence=self.project)
        if path.name == 'log_evidence.py': return self.actual_bundle
        self.fail('unexpected project module import')

    def project(self, raw, output, **kwargs):
        result = self.actual_selector.project_evidence(raw, output, **kwargs)
        if self.project_fail:
            value = stage.load(output / 'projection.json'); value['projection'] = 'FAIL'
            stage.save(output / 'projection.json', value)
        return result

    def export(self, raw, output):
        self.guard_inputs.append(raw)
        self.assertTrue(raw.is_relative_to(self.output))
        self.assertFalse(raw.is_relative_to(self.output / 'private'))
        for path in raw.rglob('*'):
            if path.is_file(): self.assertNotIn(POISON, path.read_bytes())
        result = self.actual_guard.export_evidence(raw, output)
        if ((self.guard_fail is True and raw.name == 'projected') or
                (self.guard_fail == 'terminal' and raw.name == 'terminal-input')):
            result['evidence_export'] = 'FAIL'
        return result

    def broker_cleanup(self, private, nonce, *args, **kwargs):
        self.cleanup_calls.append((private, nonce))
        self.assertTrue(private.is_dir())
        self.assertIn((str(private.parent), private.name, nonce), self.runtime._REGISTERED)
        return {'status': 'PASS', 'containers_absent': True, 'images_absent': True}

    def process_receipt(self, status='PASS'):
        return self.runtime.Receipt(kind='process-lifecycle', schema_version=1, status=status,
                                    reason_code=None if status == 'PASS' else 'fixture-failure',
                                    group_absent=True, group_reaped=0, teardown_errors=[], cancelled_signals=[])

    def fake_run(self, argv, stdout, stderr, deadline, env, cwd, **kwargs):
        phase = stdout.stem; self.commands.append(phase)
        self.assertLessEqual(deadline, time.monotonic() + stage.BUDGET['total_seconds'])
        self.assertEqual(env['DOCKER_HOST'], stage.ENDPOINT)
        self.assertTrue(cwd.is_relative_to(self.output / 'private'))
        stdout.parent.mkdir(parents=True, exist_ok=True)
        stdout.write_bytes(b''); stderr.write_bytes(POISON)
        if phase == 'materialize' and self.mode == 'registration-fail':
            item = self.process_receipt('FAIL'); item['group_absent'] = False
            raise self.runtime.RuntimeFailure(item)
        if kwargs.get('on_spawn'):
            kwargs['on_spawn']({'pid': 2147483000 + len(self.commands),
                                'group': 2147483000 + len(self.commands), 'start_ticks': 2})
        if phase == 'native-daemon':
            stage.save(stdout, {'Architecture': 'aarch64', 'DockerRootDir': str(self.storage)})
        elif phase == 'materialize':
            self.assertIn('--child', argv)
            root = Path(argv[argv.index('--output') + 1])
            self.assertTrue(root.is_dir()); self.assertEqual(root.stat().st_mode & 0o7777, 0o700)
            parent = stage.load(root / 'materializer-result.json')
            self.assertEqual(parent['schema_version'], 1)
            self.assertEqual(parent['scope'], 'private source materialization')
            self.assertEqual(parent['status'], 'RUNNING'); self.assertEqual(parent['phase'], 'launch-data-worker')
            self.assertEqual(parent['runner_inputs_sha256'], argv[argv.index('--pins-sha256') + 1])
            cache = root / 'private-cache'; cache.mkdir(mode=0o700)
            (cache / 'original.tar.gz').write_bytes(POISON)
            (cache / 'cachy-update-vendor.tar.gz').write_bytes(POISON)
            sanitized = root / 'private-sanitized'; sanitized.mkdir(mode=0o700)
            (sanitized / 'cachy-update-e2b1b7144be71cf392809f48d1440f8da1d9c81a-sanitized.tar.gz').write_bytes(POISON)
            failed = self.mode == 'materializer-fail'
            result = {'schema_version': 1, 'status': 'FAIL' if failed else 'PASS', 'phase': 'complete',
                      'source_hashes': {'sanitized': H, 'vendor': H}, 'raw_env': POISON.decode()}
            if failed: result['error_type'] = 'MaterializeError'
            stage.save(root / 'materializer-result.json', result)
            if failed: raise self.runtime.RuntimeFailure(self.process_receipt('FAIL'))
            if self.mode == 'process-cancel':
                receipt = self.process_receipt('CANCELLED'); receipt['cancelled_signals'] = [int(signal.SIGTERM)]
                raise self.runtime.RuntimeCancelled(receipt)
        elif phase == 'freeze':
            root = Path(argv[argv.index('--output') + 1]); root.mkdir(mode=0o700)
            stage.save(root / 'candidate.json', {'schema_version': 1, 'fixture': True})
        elif phase == 'native-pair':
            root = Path(argv[argv.index('--output') + 1]); root.mkdir(mode=0o700)
            failed = self.mode == 'native-fail'
            stage.save(root / 'result.json', {'schema_version': 1, 'native_pair': 'FAIL' if failed else 'PASS',
                                             'stage': 'finalized', 'argv': [POISON.decode()]})
            (root / 'raw-build.log').write_bytes(POISON)
            if failed: raise self.runtime.RuntimeFailure(self.process_receipt('FAIL'))
        elif phase in ('public-projection', 'public-guard', 'public-bundle'):
            operation = argv[argv.index('--operation') + 1]
            self.assertEqual(operation, {'public-projection': 'project', 'public-guard': 'guard', 'public-bundle': 'bundle'}[phase])
            self.assertEqual(Path(argv[argv.index('--stage-output') + 1]), self.output)
            module = Path(argv[argv.index('--module') + 1]); self.assertTrue(module.is_relative_to(cwd))
            self.assertEqual(stage.digest(module.read_bytes()), argv[argv.index('--module-sha256') + 1])
            source = Path(argv[argv.index('--input') + 1]); target = Path(argv[argv.index('--output') + 1])
            self.assertLessEqual(deadline, time.monotonic() + 60)
            if operation == 'project':
                extra = {'materialized': Path(argv[argv.index('--materialized') + 1])} if '--materialized' in argv else {}
                self.project(source, target, **extra)
                if stage.load(target / 'projection.json')['projection'] != 'PASS':
                    raise self.runtime.RuntimeFailure(self.process_receipt('FAIL'))
            elif operation == 'guard':
                result = self.export(source, target)
                if result['evidence_export'] != 'PASS':
                    raise self.runtime.RuntimeFailure(self.process_receipt('FAIL'))
                if self.mode == 'public-worker-cancel':
                    item = self.process_receipt('CANCELLED'); item['cancelled_signals'] = [15]
                    raise self.runtime.RuntimeCancelled(item)
            else:
                target.write_bytes(self.actual_bundle.bundle(source))
            stage.save(stdout, {'status': 'PASS', 'operation': operation})
        else:
            self.assertEqual(phase, 'gpg-cleanup')
        return self.process_receipt()

    def pipeline(self):
        return stage.pipeline(self.root, self.controller, self.controller_sha, self.output, runner=self.fake_run)

    def terminal(self):
        candidates = list((self.output / 'terminal-public').glob('*.json'))
        return [stage.load(p) for p in candidates if p.name != 'export-manifest.json']

    def assert_clean_failure(self, result, cancelled=False):
        self.assertNotEqual(result['status'], 'PASS')
        self.assertTrue(result['private_data_removed'])
        self.assertFalse((self.output / 'private').exists())
        self.assertEqual(stage.load(self.output / 'result.json')['status'], result['status'])
        self.assertTrue(self.cleanup_calls)
        self.assertEqual(result['cancelled'], cancelled)
        for row in self.terminal(): self.assertNotEqual(row['status'], 'PASS')

    def test_success_is_fixture_only_with_real_cleanup_and_guarded_projection(self):
        result = self.pipeline()
        self.assertEqual(result['status'], 'PASS')
        self.assertFalse((self.output / 'private').exists())
        self.assertEqual(self.commands, ['native-daemon', 'materialize', 'freeze', 'native-pair',
                                        'public-projection', 'public-guard', 'public-bundle'])
        self.assertEqual(result['cleanup_status'], 'PASS')
        self.assertEqual(result['publication'], 'NOT ACCEPTED')
        self.assertEqual(result['hardware'], 'NOT RUN')
        self.assertTrue(self.guard_inputs)

    def test_real_bounded_public_worker_cli_with_fake_native_commands(self):
        python = Path(sys.executable).resolve(strict=True)
        self.tool_rows['python'] = {'path': str(python), 'sha256': stage.digest(stage.regular(python, 256 * 1024**2))}
        stage.save(self.controller, self.contract); self.controller_sha = stage.digest(self.controller.read_bytes())
        phases = []
        def public_cli(argv, stdout, stderr, deadline, env, cwd, **kwargs):
            if stdout.stem not in ('public-projection', 'public-guard', 'public-bundle'):
                return self.fake_run(argv, stdout, stderr, deadline, env, cwd, **kwargs)
            phases.append(stdout.stem)
            self.assertEqual(argv[0], str(python)); self.assertIn('-I', argv); self.assertIn('-B', argv)
            self.assertLessEqual(deadline, time.monotonic() + 60)
            return self.runtime.run_process(argv, stdout, stderr, deadline, env, cwd, **kwargs)
        result = stage.pipeline(self.root, self.controller, self.controller_sha, self.output, runner=public_cli)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(phases, ['public-projection', 'public-guard', 'public-bundle'])
        self.assertFalse((self.output / 'private').exists())
        self.assertEqual(stage.load(self.output / 'projected/projection.json')['projection'], 'PASS')
        self.assertEqual(stage.load(self.output / 'guarded/export-manifest.json')['evidence_export'], 'PASS')
        for path in (self.output / 'guarded').rglob('*'):
            if path.is_file():
                self.assertEqual(path.suffix, '.json'); self.assertNotIn(POISON, path.read_bytes())
        self.assertEqual(result['public_bundle_sha256'], stage.digest((self.output / 'public-evidence.tar.gz').read_bytes()))
        for phase in phases:
            item = result['processes'][phase]
            self.assertEqual(item['status'], 'PASS'); self.assertTrue(item['group_absent'])
        owner = stage.load(self.output / 'ownership.json')
        self.assertTrue(all(row['complete'] for row in owner['children']))
        self.assertTrue(owner['private_removed']); self.assertTrue(owner['cleanup_verified'])

    def test_partial_materializer_failure_removes_registered_cache_and_persists_typed_failure(self):
        self.mode = 'materializer-fail'; result = self.pipeline()
        self.assert_clean_failure(result)
        self.assertEqual(result['failure_class'], 'RuntimeFailure')
        self.assertNotIn('native-pair', self.commands)
        projected = stage.load(self.output / 'projected/materializer.json')
        self.assertEqual(projected['status'], 'FAIL')
        self.assertNotIn('raw_env', projected)

    def test_native_failure_removes_registered_raw_inputs_and_keeps_partial_receipt(self):
        self.mode = 'native-fail'; result = self.pipeline()
        self.assert_clean_failure(result)
        self.assertEqual(stage.load(self.output / 'projected/native-result.json')['native_pair'], 'FAIL')

    def test_projection_failure_invalidates_pass_native_pair(self):
        self.project_fail = True; result = self.pipeline()
        self.assert_clean_failure(result)
        self.assertEqual(result['native_compilation'], 'PASS PRIVATE NATIVE PAIR')
        self.assertEqual(result['public_projection'], 'FAIL')
        self.assertNotIn('public-guard', self.commands); self.assertNotIn('public-bundle', self.commands)

    def test_guard_failure_invalidates_pass_native_pair(self):
        self.guard_fail = True; result = self.pipeline()
        self.assert_clean_failure(result)
        self.assertEqual(result['native_compilation'], 'PASS PRIVATE NATIVE PAIR')
        self.assertNotIn('public-bundle', self.commands)

    def test_public_worker_cancellation_preserves_cancel_state_with_attested_cleanup(self):
        self.mode = 'public-worker-cancel'
        self.assert_clean_failure(self.pipeline(), cancelled=True)
        self.assertNotIn('public-bundle', self.commands)

    def test_terminal_guard_failure_cannot_leave_public_pass(self):
        self.guard_fail = 'terminal'; self.assert_clean_failure(self.pipeline())

    def test_runtime_cancelled_process_preserves_cancel_state_after_private_removal(self):
        self.mode = 'process-cancel'; result = self.pipeline()
        self.assert_clean_failure(result, cancelled=True)
        owner = stage.load(self.output / 'ownership.json')
        self.assertTrue(owner['children'])
        self.assertTrue(all(row['complete'] for row in owner['children']))

    def test_partial_constructor_registration_failure_still_removes_owned_tree(self):
        original = self.runtime.owned_create
        def partial(*args, **kwargs):
            with mock.patch.object(self.runtime.os, 'write', side_effect=OSError('fixture marker failure')):
                return original(*args, **kwargs)
        with mock.patch.object(self.runtime, 'owned_create', side_effect=partial):
            result = self.pipeline()
        self.assert_clean_failure(result)
        self.assertFalse(self.commands)

    def test_constructor_cancelled_after_registration_preserves_cancel_and_cleanup(self):
        original = self.runtime.owned_create
        def registered(*args, **kwargs):
            original(*args, **kwargs)
            raise self.runtime.RuntimeCancelled(self.runtime.Receipt(status='CANCELLED', reason_code='cancelled', registered=True))
        with mock.patch.object(self.runtime, 'owned_create', side_effect=registered):
            self.assert_clean_failure(self.pipeline(), cancelled=True)

    def test_cleanup_cancelled_receipt_preserves_cancel_state_and_removal(self):
        original = self.runtime.owned_remove
        def removed(*args, **kwargs):
            result = original(*args, **kwargs); result.update(status='CANCELLED', cancelled_signals=[15]); return result
        with mock.patch.object(self.runtime, 'owned_remove', side_effect=removed):
            self.assert_clean_failure(self.pipeline(), cancelled=True)

    def test_late_terminal_pass_save_cancellation_cannot_leave_public_pass(self):
        original = stage.save; fired = False
        def late(path, value):
            nonlocal fired
            original(path, value)
            if not fired and path.name == 'terminal.json' and value.get('status') == 'PASS':
                fired = True; os.kill(os.getpid(), signal.SIGTERM)
        with mock.patch.object(stage, 'save', side_effect=late):
            result = self.pipeline()
        self.assertTrue(fired)
        self.assert_clean_failure(result, cancelled=True)

    def test_late_final_result_pass_save_cancellation_replaces_already_public_pass(self):
        original = stage.save; fired = False
        def late(path, value):
            nonlocal fired
            original(path, value)
            if (not fired and path == self.output / 'result.json' and value.get('status') == 'PASS'
                    and (self.output / 'terminal-public').is_dir()):
                fired = True; os.kill(os.getpid(), signal.SIGTERM)
        with mock.patch.object(stage, 'save', side_effect=late):
            result = self.pipeline()
        self.assertTrue(fired)
        self.assert_clean_failure(result, cancelled=True)

    def test_late_cancellation_then_republication_guard_failure_revokes_previous_public_pass(self):
        original_save = stage.save; original_export = self.export; fired = False; terminal_seen = False
        def late(path, value):
            nonlocal fired
            original_save(path, value)
            if not fired and path.parent.name == 'terminal-input' and value.get('status') == 'PASS':
                fired = True; os.kill(os.getpid(), signal.SIGTERM)
        def fail_replacement(raw, target):
            nonlocal terminal_seen
            result = original_export(raw, target)
            if raw.name == 'terminal-input':
                if terminal_seen: result['evidence_export'] = 'FAIL'
                terminal_seen = True
            return result
        with mock.patch.object(stage, 'save', side_effect=late), \
                mock.patch.object(self, 'export', side_effect=fail_replacement):
            try: self.pipeline()
            except (ValueError, OSError): pass
        self.assertTrue(fired); self.assertTrue(terminal_seen)
        result = stage.load(self.output / 'result.json')
        self.assertEqual(result['status'], 'FAIL'); self.assertTrue(result['cancelled'])
        self.assertTrue(result['private_data_removed']); self.assertFalse((self.output / 'private').exists())
        self.assertFalse((self.output / 'terminal-public/terminal.json').exists())
        self.assertFalse((self.output / 'terminal-public/export-manifest.json').exists())

    def test_publication_staging_mkdir_failure_revokes_old_pass_before_guard(self):
        self.output.mkdir(mode=0o700)
        receipt = {'schema_version': 1, 'status': 'PASS', 'phase': 'finalized', 'publication': 'NOT ACCEPTED'}
        guard = types.SimpleNamespace(export_evidence=self.export)
        stage.publish_terminal(self.output, receipt, guard, 0)
        self.assertEqual(stage.load(self.output / 'terminal-public/terminal.json')['status'], 'PASS')
        calls = len(self.guard_inputs); original = Path.mkdir
        def fail(path, *args, **kwargs):
            if path == self.output / 'terminal-input': raise OSError('fixture staging mkdir failure')
            return original(path, *args, **kwargs)
        with mock.patch.object(Path, 'mkdir', new=fail), self.assertRaises(OSError):
            stage.publish_terminal(self.output, dict(receipt, status='FAIL'), guard, 1)
        self.assertEqual(len(self.guard_inputs), calls)
        self.assertFalse((self.output / 'terminal-public/terminal.json').exists())
        self.assertFalse((self.output / 'terminal-public/export-manifest.json').exists())

    def test_persistent_result_save_failure_after_public_pass_revokes_pass_and_restores_signals(self):
        original = stage.save; fired = False
        handlers = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM)}
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        def failed_receipt(path, value):
            nonlocal fired
            if fired and path == self.output / 'result.json':
                raise OSError('fixture persistent receipt storage failure')
            original(path, value)
            if path == self.output / 'result.json' and (self.output / 'terminal-public/terminal.json').is_file():
                fired = True; os.kill(os.getpid(), signal.SIGTERM)
        try:
            with mock.patch.object(stage, 'save', side_effect=failed_receipt), self.assertRaises(OSError):
                self.pipeline()
            self.assertTrue(fired); self.assertFalse((self.output / 'private').exists())
            for value in self.terminal(): self.assertNotEqual(value['status'], 'PASS')
            self.assertEqual({s: signal.getsignal(s) for s in handlers}, handlers)
            self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), mask)
        finally:
            for number, handler in handlers.items(): signal.signal(number, handler)
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)

    def test_active_alarm_with_default_prior_handler_is_deferred_and_cancelled(self):
        original = self.fake_run; previous = signal.getsignal(signal.SIGALRM)
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, set()); fired = False
        def alarm(argv, stdout, stderr, deadline, env, cwd, **kwargs):
            nonlocal fired
            if stdout.stem == 'freeze':
                # Do not send a fatal default signal if the regression returns.
                self.assertTrue(callable(signal.getsignal(signal.SIGALRM)))
                fired = True; os.kill(os.getpid(), signal.SIGALRM)
            return original(argv, stdout, stderr, deadline, env, cwd, **kwargs)
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
        try:
            with mock.patch.object(signal, 'getitimer', return_value=(1.0, 0.0)):
                result = stage.pipeline(self.root, self.controller, self.controller_sha, self.output, runner=alarm)
            self.assertTrue(fired); self.assert_clean_failure(result, cancelled=True)
            self.assertEqual(signal.getsignal(signal.SIGALRM), signal.SIG_DFL)
            self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), mask)
        finally:
            signal.signal(signal.SIGALRM, previous)
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)

    def test_controller_and_source_commit_mode_or_self_drift_refused_before_commands(self):
        for drift in ('controller', 'source-commit', 'mode', 'self'):
            with self.subTest(drift=drift):
                controller = self.controller.read_bytes()
                script = (self.own / 'stage.py').read_bytes()
                helper = self.root / 'scripts/ci/log_evidence.py'
                if drift == 'controller': self.controller.write_bytes(controller + b' ')
                if drift == 'source-commit':
                    changed = stage.load(self.controller); changed['source']['source_commit'] = 'c' * 40
                    stage.save(self.controller, changed); self.controller_sha = stage.digest(self.controller.read_bytes())
                if drift == 'mode': helper.chmod(0o755)
                if drift == 'self': (self.own / 'stage.py').write_bytes(script + b'\n# drift\n')
                with self.assertRaises(ValueError): self.pipeline()
                self.assertFalse(self.output.exists()); self.assertFalse(self.commands)
                self.controller.write_bytes(controller); (self.own / 'stage.py').write_bytes(script)
                self.controller_sha = stage.digest(controller)
                helper.chmod(0o644); self.source_drift = False

    def test_unknown_source_code_refused_before_private_registration_or_commands(self):
        path = self.root / (stage.PACKAGE + 'unreviewed.py'); path.write_bytes(b'never executed')
        with self.assertRaisesRegex(ValueError, 'source-package-closure'):
            self.pipeline()
        self.assertFalse(self.output.exists()); self.assertFalse(self.commands)

    def test_snapshot_missing_extra_cache_and_mode_drift_refused(self):
        for drift in ('missing', 'extra', 'cache', 'mode', 'symlink'):
            with self.subTest(drift=drift):
                target = self.base / ('copy-' + drift); stage.snapshot(self.root, target, self.contract['source'])
                file = target / 'scripts/ci/log_evidence.py'
                if drift == 'missing': file.unlink()
                if drift == 'extra': (target / 'unknown.py').write_bytes(b'never execute')
                if drift == 'cache':
                    cache = target / '__pycache__'; cache.mkdir(); (cache / 'evil.pyc').write_bytes(b'never execute')
                if drift == 'mode': file.chmod(0o755)
                if drift == 'symlink': file.unlink(); file.symlink_to(self.root / 'scripts/ci/log_evidence.py')
                with self.assertRaises(ValueError): stage.verify_snapshot(target, self.contract['source'])

    def recovery_fixture(self, private=True, attested=False):
        self.output.mkdir(mode=0o700); nonce = 'd' * 32; record = None
        if private:
            raw = self.runtime.owned_create(self.output, 'private', nonce)
            (raw / 'materialized/private-cache').mkdir(parents=True, mode=0o700)
            (raw / 'materialized/private-cache/partial-archive').write_bytes(POISON)
            record = self.runtime.owned_record(self.output, 'private', nonce)
            # Simulate a new recovery process; adoption must use persisted facts.
            del self.runtime._REGISTERED[(str(self.output), 'private', nonce)]
        info = self.output.stat()
        self.owner = {'schema_version': 1, 'controller_sha256': self.controller_sha,
                      'source_commit': self.contract['source']['source_commit'], 'host': self.host,
                      'nonce': nonce, 'uid': os.getuid(),
                      'output_identity': {'device': info.st_dev, 'inode': info.st_ino},
                      'stage': {'pid': 2147482000, 'start_ticks': 100},
                      'started_monotonic': time.monotonic() - 1,
                      'private_record': record, 'children': [],
                      'cleanup_verified': attested, 'private_removed': attested, 'launch_intents': []}
        stage.save(self.output / 'ownership.json', self.owner)
        self.owner_sha = stage.digest((self.output / 'ownership.json').read_bytes())
        return self.output / 'private/materialized/private-cache/partial-archive'

    def recover(self, absent=True, owner_sha=None):
        patch = mock.patch.object(stage, 'process_identity', side_effect=FileNotFoundError) if absent else \
                mock.patch.object(stage, 'process_identity', return_value=self.owner['stage'])
        with patch:
            return stage.recover(self.root, self.controller, self.controller_sha, self.output,
                                 self.owner_sha if owner_sha is None else owner_sha)

    def recovery_public(self):
        return stage.load(self.output / 'recovery-terminal-public/terminal.json')

    def test_recovery_original_stage_alive_refuses_before_docker_or_delete(self):
        raw = self.recovery_fixture()
        with self.assertRaisesRegex(ValueError, 'original-stage-still-active'):
            self.recover(absent=False)
        self.assertEqual(raw.read_bytes(), POISON); self.assertFalse(self.cleanup_calls)
        self.assertFalse((self.output / 'recovery-result.json').exists())

    def test_recovery_wrong_ownership_hash_preserves_raw_and_unowned_files(self):
        raw = self.recovery_fixture()
        unowned = self.output / 'unowned.txt'; unowned.write_bytes(b'unowned fixture')
        with self.assertRaisesRegex(ValueError, 'ownership-pin'):
            self.recover(owner_sha='0' * 64)
        self.assertEqual(raw.read_bytes(), POISON); self.assertEqual(unowned.read_bytes(), b'unowned fixture')
        self.assertFalse(self.cleanup_calls)

    def test_recovery_forged_private_inode_refuses_adoption_and_preserves_data(self):
        raw = self.recovery_fixture(); self.owner['private_record']['child'][1] += 1
        stage.save(self.output / 'ownership.json', self.owner)
        self.owner_sha = stage.digest((self.output / 'ownership.json').read_bytes())
        result = self.recover()
        self.assertEqual(result['status'], 'FAIL'); self.assertEqual(raw.read_bytes(), POISON)
        self.assertFalse(result['private_data_removed']); self.assertFalse(self.cleanup_calls)
        self.assertEqual(self.recovery_public()['status'], 'FAIL')

    def test_recovery_adopts_exact_persisted_private_identity_and_removes_partial_cache(self):
        raw = self.recovery_fixture()
        result = self.recover()
        self.assertEqual(result['status'], 'PASS'); self.assertFalse(raw.exists())
        self.assertFalse((self.output / 'private').exists()); self.assertTrue(self.cleanup_calls)
        self.assertEqual(result['cleanup_status'], 'PASS')
        self.assertEqual(result['native_compilation'], 'NOT ATTESTED BY RECOVERY')
        self.assertEqual(self.recovery_public()['publication'], 'NOT ACCEPTED')
        self.owner = stage.load(self.output / 'ownership.json')
        self.owner_sha = stage.digest((self.output / 'ownership.json').read_bytes())
        self.assertTrue(self.owner['cleanup_verified']); self.assertTrue(self.owner['private_removed'])
        self.assertEqual(self.recover()['status'], 'PASS')
        self.assertEqual(len(self.cleanup_calls), 1)

    def test_recovery_already_cleaned_attested_owner_is_repeatable_noop(self):
        self.recovery_fixture(private=False, attested=True)
        for _ in range(2):
            result = self.recover()
            self.assertEqual(result['status'], 'PASS'); self.assertTrue(result['private_data_removed'])
            self.assertEqual(self.recovery_public()['status'], 'PASS')
        self.assertFalse(self.cleanup_calls); self.assertFalse((self.output / 'private').exists())

    def test_recovery_missing_private_without_cleanup_attestation_is_refused(self):
        self.recovery_fixture(private=False)
        result = self.recover()
        self.assertEqual(result['status'], 'FAIL'); self.assertFalse(result['private_data_removed'])
        self.assertEqual(self.recovery_public()['status'], 'FAIL'); self.assertFalse(self.cleanup_calls)

    def test_recovery_late_guarded_terminal_pass_cancellation_replaces_public_pass(self):
        self.recovery_fixture(); original = stage.save; fired = False
        def late(path, value):
            nonlocal fired
            original(path, value)
            if (not fired and path.parent.name == 'recovery-terminal-input'
                    and value.get('status') == 'PASS'):
                fired = True; os.kill(os.getpid(), signal.SIGTERM)
        with mock.patch.object(stage, 'save', side_effect=late):
            result = self.recover()
        self.assertTrue(fired); self.assertEqual(result['status'], 'CANCELLED')
        self.assertTrue(result['private_data_removed']); self.assertTrue(result['cancelled'])
        self.assertEqual(self.recovery_public()['status'], 'CANCELLED')

    def test_recovery_late_final_result_pass_cancellation_replaces_existing_public_pass(self):
        self.recovery_fixture(); original = stage.save; fired = False
        def late(path, value):
            nonlocal fired
            original(path, value)
            if (not fired and path == self.output / 'recovery-result.json' and value.get('status') == 'PASS'
                    and (self.output / 'recovery-terminal-public').is_dir()):
                fired = True; os.kill(os.getpid(), signal.SIGTERM)
        with mock.patch.object(stage, 'save', side_effect=late):
            result = self.recover()
        self.assertTrue(fired); self.assertEqual(result['status'], 'CANCELLED')
        self.assertTrue(result['private_data_removed']); self.assertTrue(result['cancelled'])
        self.assertEqual(self.recovery_public()['status'], 'CANCELLED')

    def test_bootstrap_stage_and_source_hash_refused_before_local_helper_execution(self):
        stage_sha = stage.digest((self.own / 'stage.py').read_bytes())
        source_path = self.own / 'source.py'
        source_path.write_bytes(b'raise AssertionError("unverified helper executed")\n')
        for source_sha, script_sha in [(None, None), ('0' * 64, '0' * 64), ('0' * 64, stage_sha)]:
            with self.subTest(source_sha=source_sha, script_sha=script_sha), \
                    mock.patch.object(stage, 'module', side_effect=self.original_module) as imported:
                with self.assertRaises(ValueError):
                    stage.freeze(self.root, 'a' * 40, stage.READY_SHA, self.base / 'freeze.json', source_sha, script_sha)
                self.assertFalse((self.base / 'freeze.json').exists())
                if script_sha != stage_sha: self.assertFalse(imported.called)

    def test_recovery_scoped_gpg_symlink_refused_before_gpgconf_or_foreign_mutation(self):
        raw = self.recovery_fixture()
        private = self.output / 'private'; (private / 'native').mkdir(mode=0o700)
        foreign = self.base / 'foreign-agent'; foreign.mkdir(mode=0o700)
        untouched = foreign / 'agent-state'; untouched.write_bytes(b'foreign fixture state')
        (private / 'native/gpg').symlink_to(foreign, target_is_directory=True)
        with mock.patch.object(self.runtime, 'run_process', side_effect=AssertionError('gpgconf must not execute')) as process:
            result = self.recover()
        self.assertEqual(result['status'], 'FAIL'); self.assertFalse(process.called)
        self.assertEqual(untouched.read_bytes(), b'foreign fixture state'); self.assertEqual(raw.read_bytes(), POISON)
        self.assertFalse(result['private_data_removed'])

    def test_recovery_direct_launch_intent_ambiguity_preserves_private_tree(self):
        raw = self.recovery_fixture()
        self.owner['launch_intents'] = [{'phase': 'materialize', 'status': 'INTENT', 'child_index': None}]
        stage.save(self.output / 'ownership.json', self.owner)
        self.owner_sha = stage.digest((self.output / 'ownership.json').read_bytes())
        result = self.recover()
        self.assertEqual(result['status'], 'FAIL'); self.assertEqual(raw.read_bytes(), POISON)
        self.assertFalse(self.cleanup_calls); self.assertFalse(result['private_data_removed'])

    def test_registration_failure_does_not_rewrite_previous_child_attestation(self):
        self.mode = 'registration-fail'; result = self.pipeline()
        self.assertNotEqual(result['status'], 'PASS')
        owner = stage.load(self.output / 'ownership.json')
        self.assertGreaterEqual(len(owner['children']), 1)
        self.assertTrue(owner['children'][0]['complete'])
        self.assertEqual(owner['launch_intents'][0]['status'], 'ABSENT')
        self.assertEqual(owner['launch_intents'][1]['status'], 'INTENT')
        self.assertIsNone(owner['launch_intents'][1]['child_index'])
        self.assertTrue((self.output / 'private').exists())

    def signal_finish_fault(self, restoration):
        original_save = stage.save; original_query = stage.signal.sigpending; original_signal = stage.signal.signal
        handlers = {s: stage.signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGINT)}
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        active = False; failed = False
        def committed(path, value):
            nonlocal active
            original_save(path, value)
            if path == self.output / 'result.json' and (self.output / 'terminal-public').is_dir(): active = True
        def query():
            nonlocal failed
            if active and not restoration and not failed:
                failed = True; raise OSError('fixture pending query failure')
            return original_query()
        def restore(number, handler):
            nonlocal failed
            if active and restoration and number in handlers and handler == handlers[number] and not failed:
                failed = True; raise OSError('fixture restore failure')
            return original_signal(number, handler)
        try:
            with mock.patch.object(stage, 'save', side_effect=committed), \
                    mock.patch.object(stage.signal, 'sigpending', side_effect=query), \
                    mock.patch.object(stage.signal, 'signal', side_effect=restore):
                result = self.pipeline()
            self.assertTrue(failed); self.assertNotEqual(result['status'], 'PASS')
            self.assertFalse((self.output / 'private').exists())
            self.assertEqual(stage.load(self.output / 'result.json')['status'], result['status'])
            for value in self.terminal(): self.assertNotEqual(value['status'], 'PASS')
            self.assertEqual({s: signal.getsignal(s) for s in handlers}, handlers)
            self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), mask)
        finally:
            for number, handler in handlers.items(): original_signal(number, handler)
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)

    def test_final_pending_query_fault_restores_handlers_and_invalidates_public_pass(self):
        self.signal_finish_fault(False)

    def test_final_handler_restore_fault_restores_remaining_handlers_and_invalidates_public_pass(self):
        self.signal_finish_fault(True)


class SignalHelperTests(unittest.TestCase):
    def state(self):
        return ({number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM)},
                signal.pthread_sigmask(signal.SIG_BLOCK, set()))

    def assert_restored(self, handlers, mask):
        self.assertEqual({number: signal.getsignal(number) for number in handlers}, handlers)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), mask)

    def test_second_handler_install_failure_rolls_back_every_handler_and_mask(self):
        handlers, mask = self.state(); original = signal.signal; failed = False
        def defer(*_args): pass
        def install(number, handler):
            nonlocal failed
            if number == signal.SIGINT and handler is defer and not failed:
                failed = True; raise OSError('fixture second handler install')
            return original(number, handler)
        try:
            with mock.patch.object(signal, 'signal', side_effect=install), self.assertRaises(OSError):
                stage.install_signals(handlers, defer)
            self.assertTrue(failed); self.assert_restored(handlers, mask)
        finally:
            for number, handler in handlers.items(): original(number, handler)
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)

    def test_install_mask_restore_failure_rolls_back_handlers_and_retries_mask(self):
        handlers, mask = self.state(); original = signal.pthread_sigmask; failed = False
        def restore(operation, value):
            nonlocal failed
            if operation == signal.SIG_SETMASK and not failed:
                failed = True; raise OSError('fixture initial mask restore')
            return original(operation, value)
        try:
            with mock.patch.object(signal, 'pthread_sigmask', side_effect=restore), self.assertRaises(OSError):
                stage.install_signals(handlers, lambda *_args: None)
            self.assertTrue(failed); self.assert_restored(handlers, mask)
        finally:
            for number, handler in handlers.items(): signal.signal(number, handler)
            original(signal.SIG_SETMASK, mask)

    def test_finish_initial_block_failure_commits_failure_and_restores_original_state(self):
        handlers, mask = self.state(); original = signal.pthread_sigmask; failed = False; commits = []; cancelled = []
        for number in handlers: signal.signal(number, lambda *_args: None)
        def block(operation, value):
            nonlocal failed
            if operation == signal.SIG_BLOCK and not failed:
                failed = True; raise OSError('fixture initial cleanup block')
            return original(operation, value)
        try:
            with mock.patch.object(signal, 'pthread_sigmask', side_effect=block):
                stage.finish_signals(handlers, cancelled, commits.append, mask)
            self.assertTrue(failed); self.assertTrue(commits); self.assertTrue(all(commits))
            self.assertTrue(cancelled); self.assert_restored(handlers, mask)
        finally:
            for number, handler in handlers.items(): signal.signal(number, handler)
            original(signal.SIG_SETMASK, mask)


if __name__ == '__main__':
    unittest.main()
