"""Finite orchestration fixtures; no native acceptance, Git, Docker or builds.

Authenticated synthetic contracts mock Git/host trust only. Snapshot hashes and
modes, private registration/removal, semantic projection and guards are real.
"""
import copy
import contextlib
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import stat
import sys
import tempfile
import threading
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


def directory_leaf_fixture(root, check='PATH_IDENTITY', scope='ROOT', component='INODE'):
    """Exercise the source predicate using finite stat races; retain no private values."""
    root = Path(root)
    target = root if scope == 'ROOT' else root / 'leaf-child'
    if target != root: target.mkdir(mode=0o700, exist_ok=True)
    real_stat, real_fstat, real_open, real_close = os.stat, os.fstat, os.open, os.close
    inode = real_stat(target).st_ino; seen_stat = seen_fd = 0; acquired = []; closed = []
    def changed(info, component):
        values = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
        field = {'DEVICE': 'st_dev', 'INODE': 'st_ino', 'OWNER': 'st_uid', 'MODE': 'st_mode', 'TYPE': 'st_mode'}[component]
        if component == 'MODE': values[field] = stat.S_IFMT(info.st_mode) | 0o500
        elif component == 'TYPE': values[field] = stat.S_IFREG | stat.S_IMODE(info.st_mode)
        else: values[field] += 1
        return types.SimpleNamespace(**values)
    def observe_stat(path, *args, **kwargs):
        nonlocal seen_stat
        info = real_stat(path, *args, **kwargs)
        if not isinstance(path, int) and Path(os.fsdecode(path)).name == target.name:
            seen_stat += 1
            if seen_stat == 2:
                if check in ('ROOT_PATH_MISSING', 'LINKED_CHILD_PATH_MISSING'):
                    raise FileNotFoundError(errno.ENOENT, 'finite missing fixture')
                if check in ('PATH_IDENTITY', 'PATH_NOT_DIRECTORY'):
                    return changed(info, component)
        return info
    def observe_fd(fd):
        nonlocal seen_fd
        info = real_fstat(fd)
        if info.st_ino == inode:
            seen_fd += 1
            if check == 'OPEN_FD_IDENTITY' and seen_fd == (2 if scope == 'ROOT' else 1):
                return changed(info, component)
        return info
    def opened(path, flags, *args, **kwargs):
        if check == 'CHILD_OPEN_REAPPEARED' and not isinstance(path, int) and Path(os.fsdecode(path)).name == target.name:
            raise FileNotFoundError(errno.ENOENT, 'finite open fixture')
        fd = real_open(path, flags, *args, **kwargs); acquired.append(fd); return fd
    def close(fd): closed.append(fd); return real_close(fd)
    error = None
    with mock.patch.object(stage.os, 'stat', side_effect=observe_stat), \
            mock.patch.object(stage.os, 'fstat', side_effect=observe_fd), \
            mock.patch.object(stage.os, 'open', side_effect=opened), \
            mock.patch.object(stage.os, 'close', side_effect=close):
        try: stage.disk_check(root)
        except ValueError as refused: error = refused
    if error is None: raise AssertionError('original private directory predicate did not refuse')
    return error, acquired, closed


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
        self.create_gpg = False; self.gpg_status = 'PASS'; self.docker_status = 'PASS'
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
        self.actual_broker = self.original_module(HERE / 'broker.py')
        self.broker = types.SimpleNamespace(cleanup=self.broker_cleanup,
                                           BrokerError=self.actual_broker.BrokerError,
                                           load_controller=self.broker_controller)
        for name in ('storage_policy', 'storage_initialize', 'storage_check', 'storage_projection'):
            setattr(self.broker, name, lambda *args, _name=name, **kwargs:
                    getattr(self.actual_broker, _name)(*args, **kwargs))
        sampler = mock.patch.object(self.actual_broker, 'storage_sample',
                                    side_effect=self.storage_sample, create=True)
        sampler.start(); self.addCleanup(sampler.stop)
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
        return {'status': self.docker_status, 'containers_absent': True,
                'images_absent': self.docker_status == 'PASS',
                'failures': [] if self.docker_status == 'PASS' else
                            ['image-cleanup-ambiguous', 'image-id-missing']}

    def storage_sample(self, path):
        info = Path(path).stat()
        return {'path': str(path), 'device': info.st_dev, 'inode': info.st_ino,
                'free_bytes': 64 * 1024**3}

    def broker_controller(self, path, expected, allow_expired=False):
        # Synthetic host authentication only; state binding/projection is real.
        path = Path(path); self.assertEqual(stage.digest(path.read_bytes()), expected)
        self.assertTrue(allow_expired)
        result = stage.load(path); result.update(_path=str(path), _sha256=expected)
        return result

    def process_receipt(self, status='PASS'):
        return self.runtime.Receipt(kind='process-lifecycle', schema_version=1, status=status,
                                    reason_code={'PASS': None, 'FAIL': 'process-failed', 'CANCELLED': 'cancelled'}[status],
                                    returncode={'PASS': 0, 'FAIL': 1, 'CANCELLED': -15}[status],
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
            if self.mode == 'tick-scan-fail':
                with mock.patch.object(stage, 'disk_check', side_effect=ValueError('private-disk-budget')):
                    try: kwargs['on_tick']()
                    except ValueError:
                        item = self.process_receipt('FAIL'); item.update(reason_code='tick-failed', returncode=-15)
                        raise self.runtime.RuntimeFailure(item)
                self.fail('private scan tick must fail')
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
            if self.create_gpg: (root / 'gpg').mkdir(mode=0o700)
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
            return self.process_receipt(self.gpg_status)
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

    def test_pipeline_tick_failure_has_guarded_finite_diagnostics_and_cleanup(self):
        self.mode = 'tick-scan-fail'; result = self.pipeline()
        self.assert_clean_failure(result)
        expected = {'failed_phase': 'native-daemon', 'runtime_reason': 'tick-failed',
                    'runtime_returncode': -15, 'tick_operation': 'private-scan',
                    'tick_reason': 'private-disk-budget'}
        self.assertEqual(stage.diagnostic_projection(result), expected)
        self.assertTrue(self.guard_inputs)
        terminals = self.terminal(); self.assertTrue(terminals)
        for terminal in terminals:
            self.assertEqual(stage.diagnostic_projection(terminal), expected)
            self.assertNotIn(POISON.decode(), json.dumps(terminal))

    def test_failure_diagnostics_requires_exact_authenticated_process_receipt(self):
        class Forged(self.runtime.Receipt): pass
        valid = self.process_receipt('FAIL')
        invalid = [dict(valid), Forged(valid), object(), self.process_receipt('PASS')]
        for key, value in [('kind', 'secret/private-path'), ('schema_version', True),
                           ('schema_version', 2), ('status', 'UNKNOWN'),
                           ('reason_code', POISON.decode()), ('reason_code', 1),
                           ('returncode', True), ('returncode', -65), ('returncode', 256),
                           ('returncode', 'password=secret')]:
            item = self.runtime.Receipt(valid); item[key] = value; invalid.append(item)
        for item in invalid:
            with self.subTest(item_type=type(item).__name__, item=item if isinstance(item, dict) else None):
                target = {'status': 'FAIL'}
                stage.failure_diagnostics(target, 'native-pair', item, self.runtime)
                self.assertEqual(target, {'status': 'FAIL'})
        for phase in (POISON.decode(), 1, None):
            target = {}; stage.failure_diagnostics(target, phase, valid, self.runtime)
            self.assertEqual(target, {})
        item = self.runtime.Receipt(valid); item['reason_code'] = 'tick-failed'
        for tick in ({'operation': POISON.decode(), 'reason': 'missing-path'},
                     {'operation': 'private-scan', 'reason': POISON.decode()},
                     {'operation': 'private-scan'}, {'reason': 'missing-path'}):
            target = {}; stage.failure_diagnostics(target, 'materialize', item, self.runtime, tick)
            self.assertEqual(target, {})

    def test_first_authenticated_failure_is_frozen_with_bounded_returncode(self):
        for code in (None, -64, 255):
            with self.subTest(code=code):
                first = self.process_receipt('FAIL'); first['returncode'] = code
                target = {'status': 'FAIL'}
                stage.failure_diagnostics(target, 'materialize', first, self.runtime)
                expected = {'failed_phase': 'materialize', 'runtime_reason': 'process-failed',
                            'runtime_returncode': code}
                self.assertEqual(stage.diagnostic_projection(target), expected)
                stage.failure_diagnostics(target, 'public-guard', self.process_receipt('CANCELLED'), self.runtime)
                self.assertEqual(stage.diagnostic_projection(target), expected)

    def test_partial_or_secret_public_diagnostics_are_refused(self):
        valid = {'failed_phase': 'native-pair', 'runtime_reason': 'tick-failed', 'runtime_returncode': 1,
                 'tick_operation': 'private-scan', 'tick_reason': 'private-hardlink'}
        invalid = [{key: value for key, value in valid.items() if key != missing} for missing in valid]
        for key, value in [('failed_phase', POISON.decode()), ('runtime_reason', POISON.decode()),
                           ('runtime_returncode', False), ('tick_operation', POISON.decode()),
                           ('tick_reason', POISON.decode()), ('runtime_reason', 'process-failed')]:
            item = dict(valid); item[key] = value; invalid.append(item)
        for item in invalid:
            with self.subTest(item=item), self.assertRaises(ValueError): stage.public_summary(item)
        public = stage.public_summary(dict(valid, raw_env=POISON.decode(), argv=[POISON.decode()]))
        self.assertEqual(public, valid); self.assertNotIn(POISON.decode(), json.dumps(public))
        self.assertEqual(stage.public_summary({'raw_env': POISON.decode()}), {})

    def test_tick_observation_normalizes_io_and_only_known_operation_codes(self):
        cases = [('private-scan', ValueError('private-file-type'), 'private-file-type'),
                 ('socket-identity', ValueError('daemon-socket-changed'), 'daemon-socket-changed'),
                 ('daemon-storage', ValueError('docker-storage-budget'), 'docker-storage-budget'),
                 ('private-scan', ValueError(POISON.decode()), 'validation-error'),
                 ('socket-identity', FileNotFoundError(POISON.decode()), 'missing-path'),
                 ('daemon-storage', PermissionError(POISON.decode()), 'permission-denied'),
                 ('private-scan', OSError(POISON.decode()), 'io-error'),
                 ('private-scan', RuntimeError(POISON.decode()), 'unexpected-error')]
        for operation, error, reason in cases:
            with self.subTest(operation=operation, reason=reason):
                failed = {}
                def action(): raise error
                with self.assertRaises(type(error)) as raised:
                    stage.tick_observation(operation, action, failed)
                self.assertIs(raised.exception, error)
                self.assertEqual(failed, {'operation': operation, 'reason': reason})
                target = {}; item = self.process_receipt('FAIL'); item['reason_code'] = 'tick-failed'
                stage.failure_diagnostics(target, 'freeze', item, self.runtime, failed)
                self.assertEqual(target['tick_operation'], operation); self.assertEqual(target['tick_reason'], reason)
                self.assertNotIn(POISON.decode(), json.dumps(stage.public_summary(target)))
        observed = {}; self.assertEqual(stage.tick_observation('private-scan', lambda: 7, observed), 7)
        self.assertEqual(observed, {})


    def leaf_error(self):
        private = self.base / 'leaf-private'; private.mkdir(mode=0o700, exist_ok=True)
        return directory_leaf_fixture(private)[0]

    def leaf_tick(self, error=None):
        error = self.leaf_error() if error is None else error; failed = {}
        def action(): raise error
        with self.assertRaises(type(error)) as caught:
            stage.tick_observation('private-scan', action, failed)
        self.assertIs(caught.exception, error)
        return failed

    def test_directory_leaf_source_issued_tick_projection_is_finite_and_sticky(self):
        failed = self.leaf_tick(); saved = dict(failed)
        self.assertIn('_directory_leaf_issued', failed)
        def later(): raise ValueError('private-hardlink')
        with self.assertRaises(ValueError): stage.tick_observation('private-scan', later, failed)
        self.assertEqual(failed, saved)
        item = self.process_receipt('FAIL'); item['reason_code'] = 'tick-failed'
        target = {'status': 'FAIL'}; stage.failure_diagnostics(target, 'freeze', item, self.runtime, failed)
        expected = {'availability': 'OBSERVED', 'check': 'PATH_IDENTITY', 'scope': 'ROOT', 'component': 'INODE'}
        self.assertEqual(target['directory_leaf'], expected)
        public = stage.public_summary(dict(target, path=POISON.decode(), inode=123, uid=123, raw_log=POISON.decode()))
        self.assertEqual(public['directory_leaf'], expected)
        self.assertLessEqual(len(json.dumps(expected, separators=(',', ':')).encode()), 256)
        self.assertNotIn(POISON.decode(), json.dumps(public)); self.assertNotIn('_directory_leaf_issued', public)
        stage.failure_diagnostics(target, 'public-guard', self.process_receipt('CANCELLED'), self.runtime)
        self.assertEqual(stage.public_summary(target), public)

    def test_directory_leaf_legacy_caller_and_exception_subclass_are_unknown(self):
        class PrivateError(ValueError):
            @property
            def _directory_leaf_issued(self): raise AssertionError('property must not execute')
        errors = [ValueError('private-directory-identity'), PrivateError('private-directory-identity')]
        for error in errors:
            if type(error) is ValueError:
                error._directory_leaf_issued = {'availability': 'OBSERVED', 'check': 'PATH_IDENTITY', 'scope': 'ROOT', 'component': 'INODE'}
            self.assertIsNone(stage._directory_leaf_issued(error))
        item = self.process_receipt('FAIL'); item['reason_code'] = 'tick-failed'
        for tick in ({'operation': 'private-scan', 'reason': 'private-directory-identity'},
                     {'operation': 'private-scan', 'reason': 'private-directory-identity',
                      'directory_leaf': {'availability': 'OBSERVED', 'check': 'PATH_IDENTITY', 'scope': 'ROOT', 'component': 'INODE'}},
                     {'operation': 'private-scan', 'reason': 'private-directory-identity',
                      '_directory_leaf_issued': (object(), 'PATH_IDENTITY', 'ROOT', 'INODE')}):
            target = {}; stage.failure_diagnostics(target, 'freeze', item, self.runtime, tick)
            self.assertEqual(target['directory_leaf'], stage.directory_leaf_unknown())
        legacy = {'failed_phase': 'freeze', 'runtime_reason': 'tick-failed', 'runtime_returncode': -15,
                  'tick_operation': 'private-scan', 'tick_reason': 'private-directory-identity'}
        self.assertEqual(stage.diagnostic_projection(legacy), legacy)

    def test_directory_leaf_reader_and_storage_faults_preserve_original_error(self):
        for fault in (OSError('finite reader'), KeyboardInterrupt(), SystemExit(1)):
            error = self.leaf_error(); failed = {}
            def action(): raise error
            with mock.patch.object(stage, '_directory_leaf_issued', side_effect=fault), self.assertRaises(ValueError) as caught:
                stage.tick_observation('private-scan', action, failed)
            self.assertIs(caught.exception, error)
            self.assertEqual(failed.get('reason'), 'private-directory-identity')
        class Broken(dict):
            def update(self, *args, **kwargs): raise OSError('finite storage fault')
            def __setitem__(self, *args): raise KeyboardInterrupt()
        error = self.leaf_error()
        def action(): raise error
        with self.assertRaises(ValueError) as caught: stage.tick_observation('private-scan', action, Broken())
        self.assertIs(caught.exception, error)

    def test_directory_leaf_projection_rejects_partial_wrong_extra_and_hostile_groups(self):
        group = {'availability': 'OBSERVED', 'check': 'PATH_IDENTITY', 'scope': 'ROOT', 'component': 'INODE'}
        base = {'failed_phase': 'freeze', 'runtime_reason': 'tick-failed', 'runtime_returncode': -15,
                'tick_operation': 'private-scan', 'tick_reason': 'private-directory-identity', 'directory_leaf': group}
        invalid = [{k: v for k, v in group.items() if k != missing} for missing in group]
        invalid += [dict(group, raw_path=POISON.decode()), dict(group, component=POISON.decode()),
                    dict(group, availability='NOT_OBSERVED'), dict(group, check='ROOT_PATH_MISSING', component='INODE'),
                    dict(group, check='OPEN_FD_IDENTITY', component='OWNER'), dict(group, scope='SECRET'),
                    dict(group, component=True), dict(group, check='x' * 300)]
        class Hostile(dict):
            def __iter__(self): raise AssertionError('subclass access forbidden')
        invalid += [Hostile(group), None, []]
        for row in invalid:
            with self.subTest(row_type=type(row).__name__), self.assertRaises((ValueError, TypeError)):
                stage.directory_leaf_projection(row)
            with self.assertRaises((ValueError, TypeError)): stage.diagnostic_projection(dict(base, directory_leaf=row))
        for changes in ({'tick_reason': 'private-hardlink'}, {'tick_operation': 'socket-identity', 'tick_reason': 'daemon-socket-changed'},
                        {'runtime_reason': 'process-failed'}, {'tick_operation': None}):
            with self.assertRaises(ValueError): stage.diagnostic_projection(dict(base, **changes))
        with self.assertRaises(ValueError): stage.diagnostic_projection({'directory_leaf': group})

    def test_directory_leaf_diagnostics_never_grant_pass_or_bypass_cancellation_cleanup(self):
        tick = self.leaf_tick(); item = self.process_receipt('PASS'); target = {'status': 'FAIL'}
        stage.failure_diagnostics(target, 'native-pair', item, self.runtime, tick)
        self.assertEqual(target, {'status': 'FAIL'})
        error = self.leaf_error(); actual = self.fake_run
        def refused(argv, stdout, stderr, deadline, env, cwd, **kwargs):
            if stdout.stem != 'native-daemon': return actual(argv, stdout, stderr, deadline, env, cwd, **kwargs)
            with mock.patch.object(stage, 'disk_check', side_effect=error):
                try: kwargs['on_tick']()
                except ValueError:
                    item = self.process_receipt('FAIL'); item.update(reason_code='tick-failed', returncode=-15)
                    raise self.runtime.RuntimeFailure(item)
            self.fail('original tick must refuse')
        with mock.patch.object(self, 'fake_run', side_effect=refused): result = self.pipeline()
        self.assert_clean_failure(result)
        self.assertEqual(result['directory_leaf']['availability'], 'OBSERVED')
        self.assertNotIn('native-pair', self.commands)
        for row in self.terminal():
            self.assertNotEqual(row['status'], 'PASS')
            self.assertEqual(row['directory_leaf'], result['directory_leaf'])
        self.output = self.base / 'cancel-evidence'
        self.mode = 'process-cancel'; result = self.pipeline()
        self.assert_clean_failure(result, cancelled=True)
        self.assertNotIn('directory_leaf', result)

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

    def test_docker_ambiguity_does_not_skip_scoped_gpg_or_delete_private_data(self):
        self.create_gpg = True; self.docker_status = 'FAIL'
        result = self.pipeline()
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['process_cleanup_status'], 'PASS')
        self.assertEqual(result['docker_cleanup_status'], 'FAIL')
        self.assertEqual(result['gpg_cleanup_status'], 'PASS')
        self.assertEqual(result['private_cleanup_status'], 'NOT RUN')
        self.assertIn('gpg-cleanup', self.commands)
        self.assertIn('image-cleanup-ambiguous', result['cleanup_reasons'])
        self.assertIn('image-id-missing', result['cleanup_reasons'])
        self.assertIn('private-removal-blocked', result['cleanup_reasons'])
        self.assertFalse(result['private_data_removed'])
        self.assertEqual((self.output / 'private/native/raw-build.log').read_bytes(), POISON)
        self.assertEqual(result['daemon_disposal_status'], 'NOT ATTESTED')
        public = self.terminal()[0]
        self.assertEqual(public['cleanup_reasons'], result['cleanup_reasons'])
        self.assertIn('image-id-missing', public['cleanup_reasons'])
        self.assertNotIn(POISON.decode(), json.dumps(public))

    def test_process_failure_still_attempts_docker_and_scoped_gpg_preserving_private(self):
        self.create_gpg = True
        with mock.patch.object(stage, 'stop_record', return_value={'status': 'FAIL', 'group_absent': False}):
            result = self.pipeline()
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['process_cleanup_status'], 'FAIL')
        self.assertEqual(result['docker_cleanup_status'], 'PASS')
        self.assertEqual(result['gpg_cleanup_status'], 'PASS')
        self.assertTrue(self.cleanup_calls); self.assertIn('gpg-cleanup', self.commands)
        self.assertIn('process-group-unverified', result['cleanup_reasons'])
        self.assertFalse(result['private_data_removed']); self.assertTrue((self.output / 'private').is_dir())

    def test_gpg_failure_aggregates_without_replacing_first_runtime_failure(self):
        self.create_gpg = True; self.gpg_status = 'FAIL'; self.docker_status = 'FAIL'
        original = self.fake_run
        def failed_native(*args, **kwargs):
            result = original(*args, **kwargs)
            if args[1].stem == 'native-pair':
                raise self.runtime.RuntimeFailure(self.process_receipt('FAIL'))
            return result
        result = stage.pipeline(self.root, self.controller, self.controller_sha, self.output, runner=failed_native)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['gpg_cleanup_status'], 'FAIL')
        self.assertEqual(result['failed_phase'], 'native-pair')
        self.assertEqual(result['runtime_reason'], 'process-failed')
        self.assertEqual(result['failure_class'], 'RuntimeFailure')
        self.assertEqual(result['cleanup_reasons'], sorted(set(result['cleanup_reasons'])))
        self.assertIn('gpg-process-unverified', result['cleanup_reasons'])
        self.assertIn('image-cleanup-ambiguous', result['cleanup_reasons'])
        self.assertFalse(result['private_data_removed'])

    def test_gpg_pass_without_group_absence_attestation_blocks_private_removal(self):
        self.create_gpg = True
        def unverified_gpg(*args, **kwargs):
            item = self.fake_run(*args, **kwargs)
            if args[1].stem == 'gpg-cleanup': item['group_absent'] = False
            return item
        result = stage.pipeline(self.root, self.controller, self.controller_sha, self.output, runner=unverified_gpg)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['gpg_cleanup_status'], 'FAIL')
        self.assertIn('gpg-process-unverified', result['cleanup_reasons'])
        self.assertIn('private-removal-blocked', result['cleanup_reasons'])
        self.assertFalse(result['private_data_removed']); self.assertTrue((self.output / 'private').is_dir())

    def test_repeated_real_runtime_cancellation_keeps_ambiguous_private_and_foreign_state(self):
        foreign = self.base / 'foreign-state'; foreign.write_bytes(b'foreign state')
        self.docker_status = 'FAIL'; real_receipts = []; real_groups = []
        def cancelled_worker(argv, stdout, stderr, deadline, env, cwd, **kwargs):
            if stdout.stem != 'materialize':
                return self.fake_run(argv, stdout, stderr, deadline, env, cwd, **kwargs)
            fixture_options = {k: v for k, v in kwargs.items() if k != 'on_spawn'}
            self.fake_run(argv, stdout, stderr, deadline, env, cwd, **fixture_options)
            stdout.unlink(); stderr.unlink(); fired = False
            def cancel_tick():
                nonlocal fired
                if not fired:
                    fired = True; os.kill(os.getpid(), signal.SIGTERM)
            def register(identity):
                real_groups.append(identity['group'])
                if kwargs.get('on_spawn'): kwargs['on_spawn'](identity)
            try:
                return self.runtime.run_process([sys.executable, '-I', '-B', '-c',
                                                 'import time;time.sleep(1)'],
                                                stdout, stderr, min(deadline, time.monotonic() + 3),
                                                env, cwd, on_tick=cancel_tick, on_spawn=register)
            except self.runtime.RuntimeCancelled as error:
                real_receipts.append(error.receipt); raise
        for index in range(2):
            self.output = self.base / ('cancel-evidence-' + str(index))
            result = stage.pipeline(self.root, self.controller, self.controller_sha, self.output,
                                    runner=cancelled_worker)
            self.assertEqual(result['status'], 'FAIL'); self.assertTrue(result['cancelled'])
            self.assertEqual(result['failed_phase'], 'materialize')
            self.assertEqual(result['runtime_reason'], 'cancelled')
            self.assertEqual(result['process_cleanup_status'], 'PASS')
            self.assertEqual(result['docker_cleanup_status'], 'FAIL')
            self.assertFalse(result['private_data_removed'])
            self.assertEqual((self.output / 'private/materialized/private-cache/original.tar.gz').read_bytes(), POISON)
            self.assertEqual(foreign.read_bytes(), b'foreign state')
            self.assertEqual(self.terminal()[0]['status'], 'FAIL')
        self.assertEqual(len(real_receipts), 2)
        self.assertEqual(len(real_groups), 2)
        for group in real_groups:
            with self.assertRaises(ProcessLookupError): os.killpg(group, 0)
        for receipt in real_receipts:
            self.assertEqual(receipt['status'], 'CANCELLED')
            self.assertTrue(receipt['group_absent'])
            self.assertEqual(receipt['cancelled_signals'], [int(signal.SIGTERM)])

    def test_closed_cleanup_projection_refuses_partial_unknown_or_secret_fields(self):
        valid = {'process_cleanup_status': 'PASS', 'docker_cleanup_status': 'FAIL',
                 'gpg_cleanup_status': 'PASS', 'private_cleanup_status': 'NOT RUN',
                 'daemon_disposal_status': 'NOT ATTESTED',
                 'cleanup_reasons': ['image-cleanup-ambiguous', 'private-removal-blocked']}
        self.assertEqual(stage.public_summary(valid), valid)
        invalid = [{k: v for k, v in valid.items() if k != missing} for missing in valid]
        for key, value in [('process_cleanup_status', POISON.decode()),
                           ('docker_cleanup_status', True), ('gpg_cleanup_status', 'UNKNOWN'),
                           ('private_cleanup_status', 'CANCELLED'), ('daemon_disposal_status', 'PASS'),
                           ('cleanup_reasons', [POISON.decode()]),
                           ('cleanup_reasons', ['image-cleanup-ambiguous'] * 2),
                           ('cleanup_reasons', ['private-removal-blocked', 'image-cleanup-ambiguous'])]:
            item = copy.deepcopy(valid); item[key] = value; invalid.append(item)
        for item in invalid:
            with self.subTest(item=item), self.assertRaises(ValueError): stage.public_summary(item)

    def test_public_storage_projection_is_pathless_and_rejects_malformed_scalars(self):
        gib = 1024**3
        row = {'role': 'shared', 'device': 1, 'baseline_free_bytes': 30*gib,
               'current_free_bytes': 21*gib, 'peak_growth_bytes': 9*gib,
               'growth_limit_bytes': 16*gib, 'reserve_bytes': 2*gib}
        valid = {'mode': 'shared', 'latched': False, 'reason': 'none', 'filesystems': [row]}
        self.assertEqual(stage.public_summary({'storage': valid}), {'storage': valid})
        invalid = [{k: v for k, v in valid.items() if k != missing} for missing in valid]
        for key, value in [('mode', POISON.decode()), ('latched', 1), ('reason', POISON.decode()),
                           ('reason', 'growth-limit'), ('filesystems', []), ('filesystems', [row, row])]:
            item = copy.deepcopy(valid); item[key] = value; invalid.append(item)
        for key, value in [('device', True), ('current_free_bytes', -1), ('peak_growth_bytes', 0),
                           ('reserve_bytes', 'secret'), ('growth_limit_bytes', 2**64), ('role', 'daemon')]:
            item = copy.deepcopy(valid); item['filesystems'][0][key] = value; invalid.append(item)
        item = copy.deepcopy(valid); item['filesystems'][0]['path'] = POISON.decode(); invalid.append(item)
        for item in invalid:
            with self.subTest(item=item), self.assertRaises(ValueError): stage.public_summary({'storage': item})

    def test_public_storage_latch_requires_matching_breach_witness(self):
        gib = 1024**3
        valid = {'mode': 'shared', 'latched': False, 'reason': 'none', 'filesystems': [
            {'role': 'shared', 'device': 1, 'baseline_free_bytes': 30*gib,
             'current_free_bytes': 21*gib, 'peak_growth_bytes': 9*gib,
             'growth_limit_bytes': 16*gib, 'reserve_bytes': 2*gib}]}
        invalid = []
        for changes in ({'baseline_free_bytes': 17*gib, 'current_free_bytes': 17*gib, 'peak_growth_bytes': 0},
                        {'peak_growth_bytes': 17*gib},
                        {'current_free_bytes': gib, 'peak_growth_bytes': 29*gib}):
            item = copy.deepcopy(valid); item['filesystems'][0].update(changes); invalid.append(item)
        for reason in ('growth-limit', 'reserve-floor', 'baseline-floor'):
            item = copy.deepcopy(valid); item.update(latched=True, reason=reason); invalid.append(item)
        for item in invalid:
            with self.subTest(item=item), self.assertRaises(ValueError):
                stage.public_summary({'storage': item, 'raw_env': POISON.decode()})
        for reason, peak in (('growth-limit', 17*gib), ('reserve-floor', 29*gib)):
            restored = copy.deepcopy(valid); restored.update(latched=True, reason=reason)
            restored['filesystems'][0].update(current_free_bytes=30*gib, peak_growth_bytes=peak)
            public = stage.public_summary({'storage': restored, 'raw_env': POISON.decode()})
            self.assertEqual(public, {'storage': restored})
            self.assertNotIn(POISON.decode(), json.dumps(public))

    def test_shared_growth_nine_gibibytes_is_admitted_and_publicly_counted_once(self):
        samples = 0; gib = 1024**3
        def observed(path):
            nonlocal samples
            samples += 1; row = self.storage_sample(path)
            row['free_bytes'] = (30 if samples <= 4 else 21)*gib
            return row
        def count_growth(*args, **kwargs):
            result = self.fake_run(*args, **kwargs)
            if args[1].stem == 'native-pair':
                path = self.output / 'private/broker-controller.json'
                contract = stage.load(path)
                contract.update(_path=str(path), _sha256=stage.digest(path.read_bytes()))
                self.actual_broker.storage_check(contract)
            return result
        with mock.patch.object(self.actual_broker, 'storage_sample', side_effect=observed):
            result = stage.pipeline(self.root, self.controller, self.controller_sha, self.output, runner=count_growth)
        self.assertEqual(result['status'], 'PASS')
        observed = result['storage']; self.assertEqual(observed['mode'], 'shared')
        self.assertEqual(len(observed['filesystems']), 1)
        row = observed['filesystems'][0]
        self.assertEqual(row['baseline_free_bytes'], 30*gib)
        self.assertEqual(row['current_free_bytes'], 21*gib)
        self.assertEqual(row['peak_growth_bytes'], 9*gib)
        self.assertEqual(row['growth_limit_bytes'], 16*gib)
        self.assertFalse(observed['latched'])

    def test_insufficient_baseline_durably_refuses_before_materializer_launch(self):
        def insufficient(path):
            row = self.storage_sample(path); row['free_bytes'] = 17*1024**3; return row
        with mock.patch.object(self.actual_broker, 'storage_sample', side_effect=insufficient):
            result = self.pipeline()
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual([phase for phase in self.commands if phase in
                          ('native-daemon', 'materialize', 'freeze', 'native-pair')], ['native-daemon'])
        self.assertTrue(result['storage']['latched']); self.assertEqual(result['storage']['reason'], 'baseline-floor')
        self.assertEqual(result['storage']['filesystems'][0]['baseline_free_bytes'], 17*1024**3)
        self.assertTrue(result['private_data_removed'])
        self.assertEqual(self.terminal()[0]['storage'], result['storage'])

    def test_actual_storage_breach_tick_latches_and_preserves_first_failure_through_cleanup(self):
        available = 64*1024**3; self.create_gpg = True; self.docker_status = 'FAIL'
        def observed(path):
            row = self.storage_sample(path); row['free_bytes'] = available; return row
        original_tick = stage.tick_observation
        def fake_socket(operation, action, failed):
            if operation == 'socket-identity': return None
            return original_tick(operation, action, failed)
        def breach(*args, **kwargs):
            nonlocal available
            if args[1].stem != 'native-pair': return self.fake_run(*args, **kwargs)
            result = self.fake_run(*args, **{k: v for k, v in kwargs.items() if k != 'on_tick'})
            available = 46*1024**3
            try:
                with mock.patch.object(stage, 'tick_observation', side_effect=fake_socket): kwargs['on_tick']()
            except ValueError:
                item = self.process_receipt('FAIL'); item['reason_code'] = 'tick-failed'
                raise self.runtime.RuntimeFailure(item)
            self.fail('18GiB growth must latch and fail the real storage check')
        with mock.patch.object(self.actual_broker, 'storage_sample', side_effect=observed):
            result = stage.pipeline(self.root, self.controller, self.controller_sha, self.output, runner=breach)
            path = self.output / 'private/broker-controller.json'; contract = stage.load(path)
            contract.update(_path=str(path), _sha256=stage.digest(path.read_bytes()))
            available = 64*1024**3
            with self.assertRaisesRegex(ValueError, 'docker-storage-budget'):
                self.actual_broker.storage_check(contract, create=True)
        self.assertEqual(result['status'], 'FAIL'); self.assertFalse(result['cancelled'])
        self.assertEqual(result['failed_phase'], 'native-pair')
        self.assertEqual(result['runtime_reason'], 'tick-failed')
        self.assertEqual(result['tick_operation'], 'daemon-storage')
        self.assertEqual(result['tick_reason'], 'docker-storage-budget')
        self.assertTrue(result['storage']['latched']); self.assertEqual(result['storage']['reason'], 'growth-limit')
        self.assertEqual(result['storage']['filesystems'][0]['peak_growth_bytes'], 18*1024**3)
        self.assertEqual(result['gpg_cleanup_status'], 'PASS'); self.assertIn('gpg-cleanup', self.commands)
        self.assertFalse(result['private_data_removed'])
        self.assertEqual(self.terminal()[0]['storage'], result['storage'])

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

    def recovery_gpg(self, argv, stdout, stderr, deadline, env, cwd, **kwargs):
        self.commands.append('recovery-gpg')
        self.assertLessEqual(deadline, time.monotonic() + 15)
        self.assertEqual(argv[-4:], ['--homedir', str(self.output / 'private/native/gpg'), '--kill', 'all'])
        if kwargs.get('on_spawn'):
            kwargs['on_spawn']({'pid': 2147481000, 'group': 2147481000, 'start_ticks': 2})
        stdout.write_bytes(b''); stderr.write_bytes(POISON)
        return self.process_receipt(self.gpg_status)

    def test_repeated_recovery_docker_ambiguity_attempts_gpg_and_keeps_same_private_identity(self):
        raw = self.recovery_fixture(); private = self.output / 'private'
        (private / 'native/gpg').mkdir(parents=True, mode=0o700)
        (private / 'logs').mkdir(mode=0o700)
        original = private.stat(); self.docker_status = 'FAIL'
        for _ in range(2):
            with mock.patch.object(self.runtime, 'run_process', side_effect=self.recovery_gpg):
                result = self.recover()
            self.assertEqual(result['status'], 'FAIL'); self.assertFalse(result['private_data_removed'])
            self.assertEqual(result['docker_cleanup_status'], 'FAIL')
            self.assertEqual(result['gpg_cleanup_status'], 'PASS')
            self.assertIn('image-cleanup-ambiguous', result['cleanup_reasons'])
            self.assertEqual((private.stat().st_dev, private.stat().st_ino), (original.st_dev, original.st_ino))
            self.assertEqual(raw.read_bytes(), POISON)
            self.owner = stage.load(self.output / 'ownership.json')
            self.owner_sha = stage.digest((self.output / 'ownership.json').read_bytes())
            self.assertFalse(self.owner['cleanup_verified']); self.assertFalse(self.owner['private_removed'])
            self.assertEqual(self.recovery_public()['status'], 'FAIL')
        self.assertEqual(self.commands, ['recovery-gpg', 'recovery-gpg'])
        self.assertEqual(len(self.cleanup_calls), 2)

    def test_recovery_invalid_established_storage_state_stays_fail_after_attested_private_removal(self):
        for fault in ('missing', 'malformed'):
            with self.subTest(fault=fault):
                self.output = self.base / ('invalid-storage-' + fault)
                raw = self.recovery_fixture(); private = self.output / 'private'
                contract = {'root': str(private), 'nonce': self.owner['nonce'],
                            'storage_policy': self.actual_broker.storage_policy(private, self.storage)}
                path = private / 'broker-controller.json'; stage.save(path, contract)
                contract.update(_path=str(path), _sha256=stage.digest(path.read_bytes()))
                self.actual_broker.storage_initialize(contract)
                state = private / 'storage-state.json'
                if fault == 'missing': state.unlink()
                else: stage.save(state, {'secret': POISON.decode()})
                result = self.recover()
                self.assertEqual(result['status'], 'FAIL'); self.assertTrue(result['private_data_removed'])
                self.assertEqual(result['cleanup_status'], 'PASS')
                self.assertIn('storage-observation-unverified', result['cleanup_reasons'])
                self.assertFalse(raw.exists()); self.assertFalse(private.exists())
                public = self.recovery_public(); self.assertEqual(public['status'], 'FAIL')
                self.assertNotIn(POISON.decode(), json.dumps(public))

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
        self.assertTrue(self.cleanup_calls); self.assertFalse(result['private_data_removed'])
        self.assertEqual(result['process_cleanup_status'], 'FAIL')
        self.assertIn('process-ownership-unverified', result['cleanup_reasons'])

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


class DiskCheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='updater-disk-fixture-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.base.chmod(0o700)
        self.root = self.base / 'private'; self.root.mkdir(mode=0o700)

    @contextlib.contextmanager
    def barrier(self, mutate):
        ready = threading.Event(); changed = threading.Event(); errors = []
        def writer():
            try:
                if not ready.wait(2): raise AssertionError('scan barrier not reached')
                mutate()
            except BaseException as error: errors.append(error)
            finally: changed.set()
        thread = threading.Thread(target=writer); thread.start()
        def rendezvous():
            ready.set(); self.assertTrue(changed.wait(2), 'bounded writer handshake')
            if errors: raise errors[0]
        try: yield rendezvous
        finally:
            ready.set(); thread.join(3); self.assertFalse(thread.is_alive())
            if errors: raise errors[0]

    def name(self, path):
        return Path(os.fsdecode(path)).name if not isinstance(path, int) else None

    def stat_race(self, leaf, rendezvous):
        original = os.stat; called = False
        def observe(path, *args, **kwargs):
            nonlocal called
            if self.name(path) == leaf and not called:
                called = True; rendezvous()
            return original(path, *args, **kwargs)
        return observe


    def test_directory_leaf_all_original_sites_and_components_close_every_fd(self):
        proposal = [('OPEN_FD_IDENTITY', ('ROOT', 'DESCENDANT'), ('DEVICE', 'INODE', 'MODE')),
                    ('ROOT_PATH_MISSING', ('ROOT',), ('NONE',)),
                    ('LINKED_CHILD_PATH_MISSING', ('DESCENDANT',), ('NONE',)),
                    ('PATH_IDENTITY', ('ROOT', 'DESCENDANT'), ('DEVICE', 'INODE', 'OWNER', 'MODE')),
                    ('PATH_NOT_DIRECTORY', ('ROOT', 'DESCENDANT'), ('TYPE',)),
                    ('CHILD_OPEN_REAPPEARED', ('DESCENDANT',), ('NONE',))]
        cases = 0
        for check, scopes, components in proposal:
            for scope in scopes:
                for component in components:
                    with self.subTest(check=check, scope=scope, component=component):
                        error, acquired, closed = directory_leaf_fixture(self.root, check, scope, component)
                        self.assertIs(type(error), ValueError)
                        self.assertEqual(str(error), 'private-directory-identity')
                        issued = stage._directory_leaf_issued(error)
                        self.assertIs(type(issued), tuple); self.assertEqual(issued[1:], (check, scope, component))
                        self.assertIs(issued[0], stage._DIRECTORY_LEAF_ISSUER)
                        self.assertCountEqual(acquired, closed)
                        for fd in acquired:
                            with self.assertRaises(OSError): os.fstat(fd)
                        cases += 1
        self.assertEqual(cases, 19)

    def test_directory_leaf_component_selection_preserves_original_identity_order(self):
        real_stat = os.stat
        fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode')
        for first, component in enumerate(('DEVICE', 'INODE', 'OWNER', 'MODE')):
            seen = 0
            def changed(path, *args, **kwargs):
                nonlocal seen
                info = real_stat(path, *args, **kwargs)
                if self.name(path) == self.root.name:
                    seen += 1
                    if seen == 2:
                        values = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
                        for field in fields[first:-1]: values[field] += 1
                        values['st_mode'] = stat.S_IFDIR | 0o500
                        return types.SimpleNamespace(**values)
                return info
            with self.subTest(component=component), mock.patch.object(stage.os, 'stat', side_effect=changed), \
                    self.assertRaises(ValueError) as caught:
                stage.disk_check(self.root)
            self.assertEqual(stage._directory_leaf_issued(caught.exception)[1:], ('PATH_IDENTITY', 'ROOT', component))

    def test_directory_leaf_issue_faults_preserve_original_refusal_and_fd_cleanup(self):
        for fault in (ValueError('finite issuance'), OSError('finite issuance'), KeyboardInterrupt(), SystemExit(1)):
            with self.subTest(fault=type(fault).__name__), \
                    mock.patch.object(stage, 'directory_leaf_projection', side_effect=fault):
                error, acquired, closed = directory_leaf_fixture(self.root)
                self.assertEqual(str(error), 'private-directory-identity')
                self.assertIsNone(stage._directory_leaf_issued(error))
                self.assertCountEqual(acquired, closed)
        for component in ('OWNER', 'TYPE'):
            error, acquired, closed = directory_leaf_fixture(self.root, 'OPEN_FD_IDENTITY', 'ROOT', component)
            self.assertEqual(str(error), 'private-directory-owner')
            self.assertIsNone(stage._directory_leaf_issued(error))
            self.assertCountEqual(acquired, closed)

    def test_directory_leaf_metadata_change_remains_allowed(self):
        real_stat = os.stat; seen = 0
        def metadata(path, *args, **kwargs):
            nonlocal seen
            info = real_stat(path, *args, **kwargs)
            if self.name(path) == self.root.name:
                seen += 1
                if seen == 2:
                    values = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
                    for field in ('st_mtime', 'st_ctime', 'st_atime'): values[field] += 1
                    return types.SimpleNamespace(**values)
            return info
        with mock.patch.object(stage.os, 'stat', side_effect=metadata):
            self.assertEqual(stage.disk_check(self.root), {'members': 0, 'bytes': 0})

    def test_concurrent_atomic_rename_counts_vanished_name_without_abort(self):
        partial = self.root / 'download.partial'; partial.write_bytes(b'finite download')
        target = self.root / 'download.tar.xz'
        with self.barrier(lambda: partial.rename(target)) as reach, \
                mock.patch.object(stage.os, 'stat', side_effect=self.stat_race(partial.name, reach)):
            result = stage.disk_check(self.root)
        self.assertEqual(target.read_bytes(), b'finite download')
        self.assertEqual(result, {'members': 1, 'bytes': 0})

    def test_real_runtime_tick_survives_concurrent_receipt_replace(self):
        partial = self.root / 'acquisition.partial'; partial.write_bytes(b'{}\n')
        target = self.root / 'acquisition.json'; logs = self.base / 'logs'; logs.mkdir(mode=0o700)
        runtime = stage.module(HERE / 'runtime.py')
        with self.barrier(lambda: partial.replace(target)) as reach, \
                mock.patch.object(stage.os, 'stat', side_effect=self.stat_race(partial.name, reach)):
            result = runtime.run_process([str(Path(sys.executable).resolve()), '-I', '-B', '-c', 'print("finite")'],
                                         logs / 'out', logs / 'err', time.monotonic() + 3,
                                         {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8'}, self.base,
                                         on_tick=lambda: stage.disk_check(self.root))
        self.assertEqual(result['status'], 'PASS'); self.assertTrue(result['group_absent'])
        self.assertEqual(target.read_bytes(), b'{}\n')

    def test_vanished_entries_count_before_stat_and_member_budget(self):
        leaf = self.root / 'gone'; leaf.write_bytes(b'x'); observed = False; original = os.stat
        def missing(path, *args, **kwargs):
            nonlocal observed
            if self.name(path) == leaf.name:
                observed = True; raise FileNotFoundError(errno.ENOENT, 'fixture disappearance')
            return original(path, *args, **kwargs)
        with mock.patch.object(stage, 'BUDGET', dict(stage.BUDGET, private_members=0)), \
                mock.patch.object(stage.os, 'stat', side_effect=missing), self.assertRaises(ValueError):
            stage.disk_check(self.root)
        self.assertFalse(observed, 'enumerated member cap must run before descendant stat')
        with mock.patch.object(stage.os, 'stat', side_effect=missing):
            self.assertEqual(stage.disk_check(self.root), {'members': 1, 'bytes': 0})
        self.assertTrue(observed)

    def test_missing_or_nonprivate_root_refused(self):
        with self.assertRaises((OSError, ValueError)): stage.disk_check(self.base / 'missing')
        self.root.chmod(0o755)
        with self.assertRaises((OSError, ValueError)): stage.disk_check(self.root)

    def test_expected_registered_root_identity_binds_later_scans(self):
        info = self.root.stat(); identity = [info.st_dev, info.st_ino]
        self.assertEqual(stage.disk_check(self.root, identity), {'members': 0, 'bytes': 0})
        self.root.rename(self.base / 'old-private'); self.root.mkdir(mode=0o700)
        with self.assertRaises((OSError, ValueError)): stage.disk_check(self.root, identity)

    def test_root_replacement_during_scan_is_fatal(self):
        original = os.scandir; inode = self.root.stat().st_ino; fired = False
        def replace():
            self.root.rename(self.base / 'old-private'); self.root.mkdir(mode=0o700)
        with self.barrier(replace) as reach:
            def scan(path):
                nonlocal fired
                iterator = original(path)
                if isinstance(path, int) and os.fstat(path).st_ino == inode and not fired:
                    fired = True; reach()
                return iterator
            with mock.patch.object(stage.os, 'scandir', side_effect=scan), self.assertRaises((OSError, ValueError)):
                stage.disk_check(self.root)
        self.assertTrue(fired)

    def test_root_unlinked_after_fd_open_is_fatal(self):
        original = os.scandir; inode = self.root.stat().st_ino; fired = False
        with self.barrier(self.root.rmdir) as reach:
            def scan(path):
                nonlocal fired
                iterator = original(path)
                if isinstance(path, int) and os.fstat(path).st_ino == inode and not fired:
                    fired = True; reach()
                return iterator
            with mock.patch.object(stage.os, 'scandir', side_effect=scan), self.assertRaises((OSError, ValueError)):
                stage.disk_check(self.root)
        self.assertTrue(fired)

    def test_child_directory_moved_outside_opened_tree_is_fatal(self):
        child = self.root / 'cache'; child.mkdir(mode=0o700); inode = child.stat().st_ino
        original = os.scandir; fired = False
        with self.barrier(lambda: child.rename(self.base / 'moved-cache')) as reach:
            def scan(path):
                nonlocal fired
                iterator = original(path)
                if isinstance(path, int) and os.fstat(path).st_ino == inode and not fired:
                    fired = True; reach()
                return iterator
            with mock.patch.object(stage.os, 'scandir', side_effect=scan), self.assertRaises((OSError, ValueError)):
                stage.disk_check(self.root)
        self.assertTrue(fired)

    def test_replaced_child_directory_is_fatal(self):
        child = self.root / 'cache'; child.mkdir(mode=0o700); original = os.open; fired = False
        def replace():
            child.rename(self.base / 'old-cache'); child.mkdir(mode=0o700)
        with self.barrier(replace) as reach:
            def opened(path, flags, *args, **kwargs):
                nonlocal fired
                if self.name(path) == child.name and flags & os.O_DIRECTORY and not fired:
                    fired = True; reach()
                return original(path, flags, *args, **kwargs)
            with mock.patch.object(stage.os, 'open', side_effect=opened), self.assertRaises((OSError, ValueError)):
                stage.disk_check(self.root)
        self.assertTrue(fired)

    def test_opened_descendant_unlinked_during_scan_is_allowed(self):
        child = self.root / 'cache'; child.mkdir(mode=0o700); inode = child.stat().st_ino
        original = os.scandir; fired = False
        with self.barrier(child.rmdir) as reach:
            def scan(path):
                nonlocal fired
                iterator = original(path)
                if isinstance(path, int) and os.fstat(path).st_ino == inode and not fired:
                    fired = True; reach()
                return iterator
            with mock.patch.object(stage.os, 'scandir', side_effect=scan): result = stage.disk_check(self.root)
        self.assertTrue(fired); self.assertEqual(result, {'members': 1, 'bytes': 0})

    def test_symlink_hardlink_and_fifo_refused(self):
        external = self.base / 'external'; external.write_bytes(b'untouched')
        link = self.root / 'link'; link.symlink_to(external)
        with self.assertRaises((OSError, ValueError)): stage.disk_check(self.root)
        link.unlink(); os.link(external, link)
        with self.assertRaises((OSError, ValueError)): stage.disk_check(self.root)
        link.unlink(); os.mkfifo(link)
        with self.assertRaises((OSError, ValueError)): stage.disk_check(self.root)
        self.assertEqual(external.read_bytes(), b'untouched')

    def test_foreign_owner_cross_device_and_permission_error_refused(self):
        child = self.root / 'cache'; child.mkdir(mode=0o700); original = os.stat
        for fault in ('uid', 'device', 'permission'):
            def observe(path, *args, **kwargs):
                info = original(path, *args, **kwargs)
                if self.name(path) != child.name: return info
                if fault == 'permission': raise PermissionError(errno.EACCES, 'fixture permission failure')
                values = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
                values['st_uid' if fault == 'uid' else 'st_dev'] += 1
                return types.SimpleNamespace(**values)
            with self.subTest(fault=fault), mock.patch.object(stage.os, 'stat', side_effect=observe), \
                    self.assertRaises((OSError, ValueError)):
                stage.disk_check(self.root)

    def test_byte_budget_is_unchanged(self):
        (self.root / 'large').write_bytes(b'xx')
        with mock.patch.object(stage, 'BUDGET', dict(stage.BUDGET, private_bytes=1)), self.assertRaises(ValueError):
            stage.disk_check(self.root)

    def test_only_exact_owned_gpg_unix_socket_names_are_allowed(self):
        home = self.root / 'native/gpg'; home.mkdir(parents=True, mode=0o700)
        for name in ('S.gpg-agent', 'S.gpg-agent.browser', 'S.gpg-agent.extra', 'S.gpg-agent.ssh', 'S.dirmngr', 'S.keyboxd'):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); self.addCleanup(sock.close)
            sock.bind(str(home / name))
            self.assertTrue(stat.S_ISSOCK((home / name).lstat().st_mode))
        self.assertEqual(stage.disk_check(self.root)['members'], 8)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); self.addCleanup(sock.close)
        sock.bind(str(self.root / 'S.gpg-agent'))
        with self.assertRaises((OSError, ValueError)): stage.disk_check(self.root)

    def test_owned_gpg_dotlock_hardlinks_are_counted_but_outside_links_refused(self):
        home = self.root / 'native/gpg'; home.mkdir(parents=True, mode=0o700)
        original = home / '.#lk-fixture'; original.write_bytes(b'lock')
        os.link(original, home / 'pubring.kbx.lock')
        self.assertEqual(stage.disk_check(self.root), {'members': 4, 'bytes': 8})
        os.link(original, self.root / 'native/outside-lock')
        with self.assertRaises((OSError, ValueError)): stage.disk_check(self.root)

    def test_nonlock_hardlinks_within_gpg_are_refused(self):
        home = self.root / 'native/gpg'; home.mkdir(parents=True, mode=0o700)
        original = home / 'unapproved'; original.write_bytes(b'data')
        os.link(original, home / 'unapproved-peer')
        with self.assertRaises((OSError, ValueError)): stage.disk_check(self.root)

    def test_two_link_gpg_lock_with_external_peer_is_refused(self):
        home = self.root / 'native/gpg'; home.mkdir(parents=True, mode=0o700)
        external = self.base / 'external-lock'; external.write_bytes(b'foreign peer')
        os.link(external, home / '.#lk-fixture')
        self.assertEqual(external.stat().st_nlink, 2)
        descriptors = set(os.listdir('/proc/self/fd'))
        with self.assertRaisesRegex(ValueError, '^private-hardlink$'): stage.disk_check(self.root)
        self.assertEqual(set(os.listdir('/proc/self/fd')), descriptors)
        self.assertEqual(external.read_bytes(), b'foreign peer')

    def test_known_lock_with_nonlock_peer_in_same_gpg_directory_is_refused(self):
        home = self.root / 'native/gpg'; home.mkdir(parents=True, mode=0o700)
        original = home / '.#lk-fixture'; original.write_bytes(b'lock')
        os.link(original, home / 'unapproved-peer')
        with self.assertRaisesRegex(ValueError, '^private-hardlink$'): stage.disk_check(self.root)

    def test_captured_gpg_lock_peer_unlink_and_full_removal_are_allowed(self):
        for remove_all in (False, True):
            with self.subTest(remove_all=remove_all):
                home = self.root / 'native/gpg'; home.mkdir(parents=True, mode=0o700, exist_ok=True)
                original = home / '.#lk-fixture'; original.write_bytes(b'lock')
                peer = home / 'pubring.kbx.lock'; os.link(original, peer)
                inode = home.stat().st_ino; scanned = 0; actual = os.scandir
                def remove():
                    peer.unlink()
                    if remove_all: original.unlink()
                with self.barrier(remove) as reach:
                    def scan(path):
                        nonlocal scanned
                        if isinstance(path, int) and os.fstat(path).st_ino == inode:
                            scanned += 1
                            if scanned == 2: reach()
                        return actual(path)
                    with mock.patch.object(stage.os, 'scandir', side_effect=scan):
                        result = stage.disk_check(self.root)
                self.assertGreaterEqual(scanned, 2)
                self.assertEqual(result, {'members': 4, 'bytes': 8})
                if not remove_all:
                    self.assertEqual(original.stat().st_nlink, 1); original.unlink()
                self.assertFalse(peer.exists()); self.assertFalse(original.exists())

    def test_gpg_lock_peer_created_after_initial_enumeration_is_reobserved(self):
        home = self.root / 'native/gpg'; home.mkdir(parents=True, mode=0o700)
        original = home / '.#lk-fixture'; original.write_bytes(b'lock')
        peer = home / 'pubring.kbx.lock'; inode = home.stat().st_ino
        actual = os.scandir; fired = False; scanned = 0
        with self.barrier(lambda: os.link(original, peer)) as reach:
            def scan(path):
                nonlocal fired, scanned
                if isinstance(path, int) and os.fstat(path).st_ino == inode:
                    scanned += 1
                    if not fired:
                        fired = True
                        with actual(path) as entries: snapshot = list(entries)
                        self.assertEqual([entry.name for entry in snapshot], [original.name])
                        reach()
                        return contextlib.nullcontext(iter(snapshot))
                return actual(path)
            with mock.patch.object(stage.os, 'scandir', side_effect=scan): result = stage.disk_check(self.root)
        self.assertTrue(fired); self.assertGreaterEqual(scanned, 2)
        self.assertEqual(original.stat().st_nlink, 2)
        self.assertEqual(result, {'members': 4, 'bytes': 8})

    def test_gpg_lock_fd_bound_closes_all_captured_descriptors_on_failure(self):
        home = self.root / 'native/gpg'; home.mkdir(parents=True, mode=0o700)
        for number in range(65):
            original = home / f'.#lk-fixture-{number}'; original.write_bytes(b'lock')
            os.link(original, home / f'fixture-{number}.lock')
        descriptors = set(os.listdir('/proc/self/fd'))
        with self.assertRaisesRegex(ValueError, '^private-gpg-lock-bound$'): stage.disk_check(self.root)
        self.assertEqual(set(os.listdir('/proc/self/fd')), descriptors)

    def test_gpg_peer_rescan_validates_every_new_entry(self):
        home = self.root / 'native/gpg'; home.mkdir(parents=True, mode=0o700)
        original = home / '.#lk-fixture'; original.write_bytes(b'lock')
        os.link(original, home / 'pubring.kbx.lock')
        inode = home.stat().st_ino; external = self.base / 'untouched'; external.write_bytes(b'foreign')
        for kind, reason in [('symlink', 'private-file-type'), ('fifo', 'private-file-type'),
                             ('oversized', 'private-disk-budget'), ('foreign-owner', 'private-foreign-owner')]:
            with self.subTest(kind=kind):
                new = home / 'new-entry'; actual_scan = os.scandir; actual_stat = os.stat; scanned = 0
                def create():
                    if kind == 'symlink': new.symlink_to(external)
                    elif kind == 'fifo': os.mkfifo(new)
                    else: new.write_bytes(b'x')
                def observe(path, *args, **kwargs):
                    info = actual_stat(path, *args, **kwargs)
                    if kind == 'foreign-owner' and self.name(path) == new.name:
                        values = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
                        values['st_uid'] += 1
                        return types.SimpleNamespace(**values)
                    return info
                descriptors = set(os.listdir('/proc/self/fd'))
                with self.barrier(create) as reach:
                    def scan(path):
                        nonlocal scanned
                        if isinstance(path, int) and os.fstat(path).st_ino == inode:
                            scanned += 1
                            if scanned == 2: reach()
                        return actual_scan(path)
                    budget = dict(stage.BUDGET, private_bytes=8) if kind == 'oversized' else stage.BUDGET
                    with mock.patch.object(stage.os, 'scandir', side_effect=scan), \
                            mock.patch.object(stage.os, 'stat', side_effect=observe), \
                            mock.patch.object(stage, 'BUDGET', budget), self.assertRaisesRegex(ValueError, '^'+reason+'$'):
                        stage.disk_check(self.root)
                self.assertGreaterEqual(scanned, 2)
                self.assertEqual(set(os.listdir('/proc/self/fd')), descriptors)
                self.assertEqual(external.read_bytes(), b'foreign'); new.unlink()


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
