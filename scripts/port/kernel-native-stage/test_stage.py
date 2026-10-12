# SPDX-License-Identifier: MIT
from contextlib import contextmanager, ExitStack
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import common
import stage
import evidence
from test_evidence import binding


class StageDataTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'public').mkdir(); (self.root / 'private').mkdir()
        self.report = {'status': 'PASS', 'phase': 'complete', 'cancelled': False, 'source_commit': 'a' * 40,
            'native_kernel_compilation': 'PASS', 'kernel_execution': 'NOT RUN', 'hardware_validation': 'NOT RUN',
            'performance': 'NOT MEASURED', 'cleanup': {'status': 'PASS'}}
        diagnostic = evidence.initial(binding())
        diagnostic.update(current_predicate='COMPLETE',
            commands={name: evidence.exit_record(0) for name in evidence.ACTIONS},
            cleanup={'status': 'PASS', 'category': 'NONE'})
        self.report['diagnostics'] = diagnostic

    def test_finish_has_explicit_public_allowlist_no_private_data(self):
        self.report['unaccepted_binary'] = 'private ELF path'
        stage.finish(self.root, self.report)
        public = json.loads((self.root / 'public/status.json').read_text())
        self.assertNotIn('unaccepted_binary', public)
        self.assertEqual(public['hardware_validation'], 'NOT RUN')

    def test_late_cancel_with_failure_export_error_cannot_retain_pass(self):
        @contextmanager
        def deferred(): yield [15]
        actual = common.save; calls = []
        def save(path, value):
            calls.append(path)
            if len(calls) == 3: raise OSError('injected failure rewrite error')
            actual(path, value)
        with patch.object(stage, 'defer_signals', deferred), patch.object(stage, 'save', side_effect=save):
            with self.assertRaises(OSError): stage.finish(self.root, self.report)
        self.assertFalse((self.root / 'public/status.json').exists())
        self.assertFalse((self.root / 'private/result.json').exists())
        self.assertEqual((self.report['status'], self.report['cancelled']), ('FAIL', True))

    def test_late_cancel_retains_authoritative_failure_receipts(self):
        @contextmanager
        def deferred(): yield [15]
        with patch.object(stage, 'defer_signals', deferred):
            with self.assertRaises(stage.Cancelled): stage.finish(self.root, self.report)
        for name in ('public/status.json', 'private/result.json'):
            receipt = json.loads((self.root / name).read_text())
            self.assertEqual((receipt['status'], receipt['cancelled']), ('FAIL', True))

    def test_config_metadata_delta_and_exact_new_lint_probe_only(self):
        policy = {'version_symbols': ['CONFIG_RUSTC_VERSION']}
        result = common.delta_config({'CONFIG_ARM64_16K_PAGES': 'y', 'CONFIG_RUSTC_VERSION': '109301'},
            {'CONFIG_ARM64_16K_PAGES': 'y', 'CONFIG_RUSTC_VERSION': '109900',
             'CONFIG_RUSTC_HAS_SUSPICIOUS_RUNTIME_SYMBOL_DEFINITIONS': 'y'}, policy)
        self.assertEqual(len(result), 2)
        with self.assertRaises(ValueError): common.delta_config({'CONFIG_HZ': '1000'}, {'CONFIG_HZ': '250'}, policy)
        with self.assertRaises(ValueError): common.delta_config({}, {'CONFIG_RUSTC_HAS_SUSPICIOUS_RUNTIME_SYMBOL_DEFINITIONS': 'n'}, policy)

    def test_json_pin_authenticates_captured_bytes(self):
        path = self.root / 'receipt.json'; common.save(path, {'status': 'UNREVIEWED'})
        pin = common.digest(path)
        with patch.object(common, 'digest', side_effect=AssertionError('second-path-read not allowed')):
            self.assertEqual(common.load(path, pin)['status'], 'UNREVIEWED')
        path.write_text('{"status":"REVIEWED"}')
        with self.assertRaises(ValueError): common.load(path, pin)

    def test_non_native_stage_rejected_before_outputs(self):
        with patch.object(stage.platform, 'machine', return_value='x86_64'):
            with self.assertRaises(ValueError): stage.ordinary()

    def test_isolated_cli_can_load_owned_helpers(self):
        result = subprocess.run([sys.executable, '-I', '-B', stage.__file__, '--help'], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'--accepted-result-sha256', result.stdout)

    def test_snapshot_failure_remains_authoritative_fail(self):
        base = self.root / 'artifacts/kernel-native-stage'; base.mkdir(parents=True)
        args = SimpleNamespace(root=self.root, output=base / 'failed-new', source_commit='a' * 40,
                               lock=self.root / 'lock', lock_sha256='b' * 64,
                               accepted_result_sha256='c' * 64, bootstrap_sha256='d' * 64)
        lock = {'purpose': 'KERNEL-NATIVE-C01', 'base_inventory_sha256': stage.BASE_SHA}
        with (patch.object(stage, 'ordinary'), patch.object(stage, 'load', return_value=lock),
              patch.object(stage.shutil, 'disk_usage', return_value=SimpleNamespace(free=8 * 1024**3)),
              patch.dict(stage.os.environ, {'GITHUB_SHA': args.source_commit}),
              patch.object(stage, 'snapshot', side_effect=ValueError('injected source mismatch'))):
            self.assertEqual(stage.execute(args), 1)
        public = json.loads((args.output / 'public/status.json').read_text())
        self.assertEqual((public['status'], public['native_kernel_compilation']), ('FAIL', 'NOT RUN'))
        self.assertEqual(public['cleanup']['status'], 'FAIL')
        private = json.loads((args.output / 'private/result.json').read_text())
        self.assertEqual(private['error_type'], 'ValueError')
        self.assertEqual(public['diagnostics']['first_failed_predicate'], 'SNAPSHOT')
        self.assertEqual(public['diagnostics']['failure_category'], 'INVALID_DATA')
        self.assertEqual(private['diagnostics']['commands']['provision'], {'kind': 'NOT_RUN', 'code': None})


class ChildCheckpointTests(unittest.TestCase):
    """Real owned receipt I/O through execute; native actors are inert fixtures."""
    def run_fixture(self, fault=None):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        args = SimpleNamespace(root=root, output=root / 'artifacts/kernel-native-stage/fixture',
            source_commit='a' * 40, lock=root / 'lock', lock_sha256='b' * 64,
            accepted_result_sha256='c' * 64, bootstrap_sha256='d' * 64,
            bootstrap=root / 'bootstrap', accepted_result=root / 'accepted',
            inputs=root / 'inputs', base_packages=root / 'base', image='fixture-image',
            docker=root / 'docker', docker_sha256='e' * 64, endpoint='fixture-endpoint')
        args.inputs.write_bytes(b'inputs'); args.base_packages.write_bytes(b'base')
        lock = {'purpose': 'KERNEL-NATIVE-C01', 'base_inventory_sha256': stage.BASE_SHA,
            'files': {'scripts/ci/native_arm.py': {'sha256': 'f' * 64}}}
        checkpoints, calls = [], []
        real_finish = stage.finish
        def finish(output, report):
            checkpoints.append(report['diagnostics']['current_predicate'])
            if fault == 'checkpoint-provision' and report['diagnostics']['current_predicate'] == 'PROVISION_COMMAND':
                raise OSError('private checkpoint path')
            real_finish(output, report)
        def load(path, pin=None):
            if path == args.lock: return lock
            if path in (args.bootstrap, args.accepted_result): return {}
            return common.load(path, pin)
        def packet(_args, _code, private, _lock, nonce):
            if fault == 'packet': raise ValueError('private unexported packet path')
            inputs = private / 'inputs'; inputs.mkdir(mode=0o700)
            return inputs, {'inputs': {}, 'dependencies_sha256': '1' * 64}, {'expected_inventory_sha256': '2' * 64}
        class Broker:
            def __init__(self, runner, cleanup, docker, docker_sha, endpoint, image_id,
                         uid, gid, journal, nonce, role='build', observer=None):
                self.role, self.nonce, self.observer = role, nonce, observer
            def initialize(self, **kwargs):
                calls.append(('initialize', self.role))
                if fault == 'initialize-' + self.role: raise OSError('private daemon message')
                return {'fixture': True}
            def launch(self, action, mounts, env, timeout, persist=False):
                calls.append(('launch', action))
                if fault == 'validate-' + action:
                    with self.observer.scope('LAUNCH_VALIDATE'):
                        raise ValueError('docker-kernel-mount-map')
                if fault == 'signal-' + action: os.kill(os.getpid(), signal.SIGTERM)
                if fault == 'io-' + action: raise OSError('private command path')
                if fault == 'timeout-' + action: raise ValueError('command-timeout')
                if fault == 'exit-' + action: return SimpleNamespace(returncode=125)
                out = Path(mounts['/out'])
                receipt = {'status': 'PASS', 'action': action, 'nonce': self.nonce, 'cancelled': False,
                    'tools': {'fixture': '1'}, 'generated_config_delta': [], 'native_kernel_compilation': 'PASS'}
                if fault == 'receipt-' + action: receipt['nonce'] = '0' * 32
                if fault == 'pair' and action == 'candidate': receipt['tools'] = {'fixture': '2'}
                common.save(out / 'result.json', receipt)
                if action in ('baseline', 'candidate'):
                    (out / 'generated-config.txt').write_text('CONFIG_FIXTURE=y\n')
                return SimpleNamespace(returncode=0)
            def cleanup(self):
                calls.append(('cleanup', self.role))
                if fault == 'cleanup-io': raise OSError('private cleanup message')
                if fault == 'cleanup-unknown':
                    return {'status': 'FAIL', 'absence_verified': False, 'uncertain_commit': True}
                return {'status': 'PASS', 'absence_verified': True}
        def commit(*_):
            if fault == 'derive': raise ValueError('private commit uncertainty')
            return {'image_id': 'fixture-derived'}
        with ExitStack() as stack:
            for name, value in (('ordinary', lambda: None), ('load', load),
                ('snapshot', lambda *a: root), ('packet', packet), ('Broker', Broker), ('finish', finish),
                ('module', lambda *a: SimpleNamespace(accepted_base=lambda *a: {}))):
                stack.enter_context(patch.object(stage, name, value))
            stack.enter_context(patch.object(stage.shutil, 'disk_usage', return_value=SimpleNamespace(free=8 * 1024**3)))
            stack.enter_context(patch.object(stage.image, 'commit', commit))
            stack.enter_context(patch.object(stage.image, 'cleanup', return_value={'status': 'PASS', 'absence_verified': True}))
            stack.enter_context(patch.dict(stage.os.environ, {'GITHUB_SHA': args.source_commit}))
            stack.enter_context(stage.cancellation_handlers())
            code = stage.execute(args)
        report = common.load(args.output / 'private/result.json')
        public = common.load(args.output / 'public/status.json')
        self.assertEqual(public['diagnostics'], evidence.project(report['diagnostics']))
        self.assertEqual(code, int(public['status'] != 'PASS'))
        self.assertNotIn('private', json.dumps(public['diagnostics']))
        return report, public['diagnostics'], calls, checkpoints

    def test_full_control_flow_records_all_actual_returns_before_complete(self):
        report, row, calls, checkpoints = self.run_fixture()
        self.assertEqual((report['status'], row['current_predicate']), ('PASS', 'COMPLETE'))
        self.assertEqual(row['first_failed_predicate'], 'NONE')
        self.assertEqual(row['commands'], {name: evidence.exit_record(0) for name in evidence.ACTIONS})
        self.assertEqual(row['cleanup'], {'status': 'PASS', 'category': 'NONE'})
        for action in evidence.ACTIONS:
            self.assertLess(checkpoints.index(action.upper() + '_COMMAND'), checkpoints.index(action.upper() + '_RECEIPT'))
        self.assertEqual([value for kind, value in calls if kind == 'cleanup'], ['build', 'provision'])

    def test_first_failed_predicates_distinguish_precompile_boundaries(self):
        cases = {'packet': ('DEPENDENCY_PACKET', 'INVALID_DATA'),
            'initialize-provision': ('PROVISION_INITIALIZE', 'IO'),
            'derive': ('DERIVED_IMAGE', 'INVALID_DATA'), 'initialize-build': ('BUILD_INITIALIZE', 'IO'),
            'pair': ('PAIR_ACCEPTANCE', 'INVALID_DATA')}
        for fault, expected in cases.items():
            with self.subTest(fault=fault):
                report, row, _, _ = self.run_fixture(fault)
                self.assertEqual((row['first_failed_predicate'], row['failure_category']), expected)
                self.assertEqual(report['native_kernel_compilation'], 'NOT RUN')

    def test_returned_nonzero_and_unobserved_launch_are_not_inferred_equal(self):
        for action in evidence.ACTIONS:
            for kind, category in (('exit', 'COMMAND_NONZERO'), ('io', 'IO'), ('timeout', 'TIMEOUT')):
                with self.subTest(action=action, kind=kind):
                    _, row, _, _ = self.run_fixture(kind + '-' + action)
                    self.assertEqual((row['first_failed_predicate'], row['failure_category']),
                        (action.upper() + '_COMMAND', category))
                    expected = evidence.exit_record(125) if kind == 'exit' else {'kind': 'UNOBSERVED', 'code': None}
                    self.assertEqual(row['commands'][action], expected)

    def test_zero_command_bad_receipt_does_not_claim_accepted_worker(self):
        for action in evidence.ACTIONS:
            with self.subTest(action=action):
                report, row, _, _ = self.run_fixture('receipt-' + action)
                self.assertEqual(row['first_failed_predicate'], action.upper() + '_RECEIPT')
                self.assertEqual(row['commands'][action], evidence.exit_record(0))
                self.assertNotIn(action, report)

    def test_actual_TERM_before_worker_return_keeps_unobserved_and_reaches_cleanup(self):
        report, row, calls, _ = self.run_fixture('signal-provision')
        self.assertTrue(report['cancelled'])
        self.assertEqual((row['first_failed_predicate'], row['failure_category']), ('PROVISION_COMMAND', 'CANCELLED'))
        self.assertEqual(row['commands']['provision'], {'kind': 'UNOBSERVED', 'code': None})
        self.assertIn(('cleanup', 'provision'), calls)

    def test_cleanup_type_is_finite_and_revokes_success_without_rewriting_prior_work(self):
        for fault, category in (('cleanup-io', 'IO'), ('cleanup-unknown', 'UNCERTAIN_MUTATION')):
            with self.subTest(fault=fault):
                report, row, _, _ = self.run_fixture(fault)
                self.assertEqual(report['status'], 'FAIL')
                self.assertEqual(row['first_failed_predicate'], 'CLEANUP')
                self.assertEqual(row['cleanup'], {'status': 'FAIL', 'category': category})
                self.assertEqual(row['commands']['candidate'], evidence.exit_record(0))



class OperationCheckpointTests(unittest.TestCase):
    run_fixture = ChildCheckpointTests.run_fixture

    def test_checkpoint_and_launch_validation_are_causally_separate(self):
        for fault, gate, called in [('checkpoint-provision','CHECKPOINT_WRITE',False),
                                    ('validate-provision','LAUNCH_VALIDATE',True)]:
            report,row,calls,_=self.run_fixture(fault)
            first=row['operation']['first_failure']
            self.assertEqual(report['status'],'FAIL');self.assertEqual(row['schema_version'],2)
            self.assertEqual(row['first_failed_predicate'],'PROVISION_COMMAND')
            self.assertEqual(first['gate'],gate);self.assertEqual(first['action'],'provision')
            self.assertEqual(any(kind=='launch' for kind,_ in calls),called)
            self.assertEqual(row['commands']['provision'],{'kind':'UNOBSERVED','code':None})
            self.assertNotIn('private',json.dumps(first))

    def test_primary_error_stays_fixed_and_cleanup_failure_is_separate(self):
        report,row,_,_=self.run_fixture('cleanup-unknown')
        self.assertEqual(report['status'],'FAIL')
        self.assertEqual(row['operation']['cleanup_failure']['category'],'UNCERTAIN_MUTATION')
        self.assertEqual(row['operation']['cleanup_failure']['action'],'cleanup')
        self.assertEqual(row['commands']['candidate'],evidence.exit_record(0))
        self.assertNotEqual(row['current_predicate'],'COMPLETE')


class OperationFinalizationTests(unittest.TestCase):
    setUp = StageDataTests.setUp

    def test_diagnostic2_late_cancel_revokes_complete_and_records_finite_failure(self):
        trace=evidence.Trace()
        self.report['diagnostics'].update(schema_version=2,operation=trace.snapshot())
        @contextmanager
        def deferred():yield [15]
        with patch.object(stage,'defer_signals',deferred):
            with self.assertRaises(stage.Cancelled):stage.finish(self.root,self.report)
        row=common.load(self.root/'public/status.json')
        self.assertEqual(row['status'],'FAIL')
        self.assertEqual(row['diagnostics']['first_failed_predicate'],'FINALIZATION')
        failure=row['diagnostics']['operation']['first_failure']
        self.assertEqual((failure['gate'],failure['category']),('FINALIZATION','CANCELLED'))
        self.assertNotIn('cancelled',json.dumps(failure))


if __name__ == '__main__':
    unittest.main()
