# SPDX-License-Identifier: MIT
import ast
import copy
from contextlib import contextmanager, ExitStack
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import types
from unittest.mock import MagicMock, patch

import common
import worker
import inner_result
from runtime import Cancelled


class ProvisionFlow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.inputs = self.root / 'inputs'; self.inputs.mkdir()
        self.real_path = Path
        self.packet = b'archive'; self.sig = b'signature'
        (self.inputs / 'tool.pkg').write_bytes(self.packet); (self.inputs / 'tool.pkg.sig').write_bytes(self.sig)
        common.save(self.inputs / 'contract.json', {'base_inventory': 'base 1\n'})
        self.signer = '6' * 40
        self.dependencies = {'packages': [{'name': 'tool', 'filename': 'tool.pkg', 'sha256': hashlib.sha256(self.packet).hexdigest(),
            'signature_sha256': hashlib.sha256(self.sig).hexdigest()}], 'signer_fingerprint': self.signer,
            'expected_inventory': 'base 1\ntool 2\n'}
        self.labels = []; self.installed = False
        self.log_dir = self.root / 'logs'; self.log_dir.mkdir()

    def path(self, value):
        if str(value).startswith('/tmp/'):
            return self.real_path(self.root / str(value).lstrip('/'))
        if str(value).startswith('/usr/share/') or str(value).startswith('/etc/'):
            return self.root / 'nonexistent-hooks'
        return self.real_path(value)

    def command_run(self, argv, timeout=0, log=None):
        self.labels.append(log)
        data = b''
        if '--verify' in argv:
            data = ('[GNUPG:] VALIDSIG ' + self.signer + ' 2026-10-12 1 0 4 0 1 10 00 ' + self.signer + '\n').encode()
        if '-U' in argv: self.installed = True
        if '-Q' in argv: data = b'base 1\ntool 2\n' if self.installed else b'base 1\n'
        (self.log_dir / log).open('xb').close()
        return subprocess.CompletedProcess(argv, 0, data)

    def test_distinct_inventory_logs_allow_complete_provision(self):
        (self.root / 'tmp').mkdir()
        runner = type('Runner', (), {'log_dir': self.log_dir, 'run': self.command_run})()
        report = {'commands': []}
        with patch.object(worker, 'Path', side_effect=self.path), patch.object(worker, 'INPUTS', self.inputs):
            worker.provision(runner, report, self.dependencies)
        self.assertIn('inventory-before.log', self.labels)
        self.assertIn('inventory-after.log', self.labels)
        self.assertEqual(len(self.labels), len(set(self.labels)))
        self.assertEqual(report['base_inventory']['count'], 1)
        self.assertEqual(report['installed_inventory']['count'], 2)
        self.assertTrue(self.installed)

    def test_wrong_crypto_signer_blocks_install(self):
        (self.root / 'tmp').mkdir()
        self.dependencies['signer_fingerprint'] = '7' * 40
        runner = type('Runner', (), {'log_dir': self.log_dir, 'run': self.command_run})()
        with patch.object(worker, 'Path', side_effect=self.path), patch.object(worker, 'INPUTS', self.inputs):
            with self.assertRaises(ValueError): worker.provision(runner, {'commands': []}, self.dependencies)
        self.assertFalse(self.installed)


BINDING = {'nonce': 'a'*32, 'action': 'baseline', 'contract_sha256': 'b'*64, 'worker_sha256': 'c'*64}


class DiagnosticCommands(unittest.TestCase):
    def report(self):
        return {'commands': [], 'inner_diagnostic': inner_result.initial(BINDING)}

    def runner(self, result=None, error=None):
        runner = MagicMock(); runner.log_dir = Path('/inert/logs')
        runner.run.side_effect = error
        runner.run.return_value = result
        return runner

    def test_same_call_and_post_return_digest_failure(self):
        report = self.report(); inner_result.phase(report['inner_diagnostic'], 'KERNEL')
        runner = self.runner(subprocess.CompletedProcess(['fixture'], -15, b'output'))
        with patch.object(worker, 'digest', side_effect=OSError('fixture digest')):
            with self.assertRaises(OSError): worker.command(runner, report, 'kernel', ['fixture'], timeout=7200)
        runner.run.assert_called_once_with(['fixture'], timeout=7200, log='kernel.log')
        self.assertEqual({'kind': 'RETURNED', 'code': -15}, report['inner_diagnostic']['natural_return'])
        self.assertEqual([], report['commands'])

    def test_spawn_timeout_cleanup_and_controls_do_not_invent_return(self):
        for error in (OSError('spawn'), ValueError('command-timeout'), ValueError('deadline-exhausted'),
                      ValueError('output-bound'), ValueError('process-cleanup'), Cancelled(), KeyboardInterrupt(), SystemExit(7)):
            with self.subTest(error=type(error).__name__, args=error.args):
                report = self.report(); runner = self.runner(error=error)
                with self.assertRaises(type(error)):
                    worker.command(runner, report, 'config', ['fixture'], timeout=300)
                row = report['inner_diagnostic']; self.assertEqual('ISSUED', row['attempt'])
                self.assertEqual({'kind': 'UNOBSERVED', 'code': None}, row['natural_return'])
                inner_result.failure(row, error); inner_result.validate(row)

    def test_unexpected_return_invalidates_only_observation(self):
        report = self.report(); runner = self.runner(type('Foreign', (), {'returncode': 0, 'stdout': b'original'})())
        with patch.object(worker, 'digest', return_value='d'*64):
            self.assertEqual(b'original', worker.command(runner, report, 'inventory', ['fixture']))
        row = report['inner_diagnostic']; self.assertTrue(row['write_failed'])
        self.assertEqual('UNOBSERVED', row['natural_return']['kind']); self.assertEqual(0, report['commands'][0]['exit'])

    def test_ordinary_observation_faults_preserve_nonzero_business_error(self):
        for operation in ('issued', 'returned'):
            for error in (OSError('fixture'), ValueError('fixture'), ImportError('fixture')):
                report = self.report(); runner = self.runner(subprocess.CompletedProcess(['fixture'], 7, b'original'))
                with patch.object(inner_result, operation, side_effect=error), patch.object(worker, 'digest', return_value='d'*64):
                    with self.assertRaisesRegex(ValueError, 'command failed: kernel'):
                        worker.command(runner, report, 'kernel', ['fixture'])
                self.assertTrue(report['inner_diagnostic']['write_failed']); self.assertEqual(7, report['commands'][0]['exit'])

    def test_observation_controls_propagate(self):
        for error in (Cancelled(), KeyboardInterrupt(), SystemExit(9)):
            report = self.report(); runner = self.runner(subprocess.CompletedProcess(['fixture'], 0, b''))
            with patch.object(inner_result, 'issued', side_effect=error):
                with self.assertRaises(type(error)): worker.command(runner, report, 'kernel', ['fixture'])
            runner.run.assert_not_called()

    def test_partial_issue_control_invalidates_attempt_claim(self):
        for control in (Cancelled(15), KeyboardInterrupt(), SystemExit(0)):
            report = self.report(); runner = self.runner(subprocess.CompletedProcess(['fixture'], 0, b''))
            original = inner_result.issued
            def interrupted(row, command):
                original(row, command)
                raise control
            with patch.object(inner_result, 'issued', side_effect=interrupted):
                with self.assertRaises(type(control)): worker.command(runner, report, 'kernel', ['fixture'])
            runner.run.assert_not_called()
            self.assertEqual('ISSUED', report['inner_diagnostic']['attempt'])
            self.assertTrue(report['inner_diagnostic']['write_failed'])
            self.assertTrue(report['inner_diagnostic']['cancelled'])

    def test_fixed_tool_mapping(self):
        for i in range(18):
            report = self.report(); runner = self.runner(subprocess.CompletedProcess(['fixture'], 0, b''))
            with patch.object(worker, 'digest', return_value='d'*64):
                worker.command(runner, report, f'tool-{i}', ['fixture'])
            self.assertEqual(f'TOOL_{i}', report['inner_diagnostic']['command'])
        report = self.report(); runner = self.runner(subprocess.CompletedProcess(['fixture'], 0, b''))
        with patch.object(worker, 'digest', return_value='d'*64):
            worker.command(runner, report, 'attacker-label', ['fixture'])
        self.assertTrue(report['inner_diagnostic']['write_failed'])


class DiagnosticExecute(unittest.TestCase):
    def model(self, module=worker, business=None, save_error=None, late_events=False, init_error=None,
              observation_site=None, observation_fault=None, copy_error=None):
        # All Paths, business APIs, Runner calls and signals are inert test doubles.
        contract = {'nonce': BINDING['nonce'], 'files': {module.PREFIX + 'worker.py': {'sha256': BINDING['worker_sha256']}},
                    'dependencies_sha256': 'd'*64, 'inputs': {}}
        trace = []; saves = []; live = []; runner = MagicMock(); runner.log_dir.glob.return_value = []
        calls = []; state = {'after_business': False}
        def run(argv, timeout=0, log=None):
            calls.append({'argv': argv, 'timeout': timeout, 'log': log})
            state['after_business'] = True
            if isinstance(business, BaseException): raise business
            return subprocess.CompletedProcess(argv, 0 if business is None else business, b'original')
        runner.run.side_effect = run
        def compile_one(r, report, *args):
            trace.append('compile')
            if module is worker: module.observe(report, inner_result.phase, 'KERNEL')
            module.command(r, report, 'kernel', ['inert-original'], timeout=7200)
        def save(path, report):
            trace.append('save'); saves.append(copy.deepcopy(report)); live.append(report)
            if save_error is not None: raise save_error
        if observation_site or copy_error:
            runner.log_dir.glob.return_value = [types.SimpleNamespace(name='kernel.log')]
        def copy_log(*args):
            trace.append('copy-log')
            if copy_error: raise copy_error
        original_observe = getattr(module, 'observe', None)
        actual_helper = getattr(module, 'inner_result', inner_result)
        class AcquisitionFault(types.ModuleType):
            def __getattribute__(self, name):
                if name == 'phase' and state['after_business']: raise observation_fault
                return getattr(actual_helper, name)
        def entry(report, operation, *args, **kw):
            if args == ('FINALIZATION',): raise observation_fault
            return original_observe(report, operation, *args, **kw)
        count = [0]
        @contextmanager
        def deferred():
            events = []; count[0] += 1; current = count[0]
            yield events
            if late_events and current == 1: events.append(15)
        with ExitStack() as stack:
            stack.enter_context(patch.dict(module.os.environ, {'KERNEL_STAGE_ACTION': 'baseline'}))
            for name, value in {'Path': MagicMock(), 'load': MagicMock(side_effect=[contract, {'expected_inventory': 'inert'}]),
                'code_contract': MagicMock(), 'regular': MagicMock(), 'digest': MagicMock(return_value='d'*64),
                'Runner': MagicMock(return_value=runner), 'profile': MagicMock(side_effect=lambda *a: trace.append('profile') or {}),
                'package_map': MagicMock(side_effect=lambda *a: trace.append('inventory') or {}),
                'tools': MagicMock(side_effect=lambda *a: trace.append('tools') or {}), 'compile_variant': compile_one,
                'save': save, 'defer_signals': deferred}.items():
                stack.enter_context(patch.object(module, name, value))
            stack.enter_context(patch.object(module.shutil, 'copyfile', side_effect=copy_log))
            if observation_site == 'acquisition': stack.enter_context(patch.object(module, 'inner_result', AcquisitionFault('fault')))
            if observation_site == 'entry': stack.enter_context(patch.object(module, 'observe', entry))
            if init_error is not None: stack.enter_context(patch.object(inner_result, 'initial', side_effect=init_error))
            result = None; caught = None
            try: result = module.execute('baseline', BINDING['nonce'], BINDING['contract_sha256'])
            except BaseException as error: caught = error
        return {'return': result, 'error': caught, 'trace': trace, 'calls': calls, 'saves': saves, 'live': live}

    def test_finalization_acquisition_and_entry_have_inline_caller_guard(self):
        tree = ast.parse(Path(worker.__file__).read_text())
        self.assertFalse(hasattr(worker, 'deferred_observe'))
        final = next(node for node in ast.walk(tree) if isinstance(node, ast.Try) and
            any(isinstance(item, ast.Expr) and isinstance(item.value, ast.Call) and
                isinstance(item.value.func, ast.Name) and item.value.func.id == 'observe' and
                any(isinstance(arg, ast.Constant) and arg.value == 'FINALIZATION' for arg in item.value.args)
                for item in node.body))
        self.assertEqual(2, len(final.handlers))
        self.assertEqual('Exception', final.handlers[1].type.id)
        # Attribute acquisition and original observer call are both inside Try.body.
        self.assertEqual('inner_result', final.body[0].value.args[1].value.id)

    def test_finalization_acquisition_and_entry_regressions(self):
        cases = [('acquisition', AttributeError('phase acquisition')), ('acquisition', OSError('phase acquisition')),
            ('acquisition', KeyboardInterrupt('phase acquisition')), ('acquisition', SystemExit(0)),
            ('entry', Cancelled(15)), ('entry', KeyboardInterrupt('call entry'))]
        for site, fault in cases:
            with self.subTest(site=site, fault=type(fault).__name__):
                result = self.model(business=7, observation_site=site, observation_fault=fault)
                self.assertIsInstance(result['error'], ValueError)
                self.assertEqual(('command failed: kernel',), result['error'].args)
                self.assertEqual(['profile', 'inventory', 'tools', 'compile', 'copy-log', 'save'], result['trace'])
                self.assertEqual(1, len(result['saves']))
                report = result['saves'][0]; row = report['inner_diagnostic']
                self.assertEqual('ValueError', report['error_type'])
                self.assertEqual('DATA_REFUSAL', row['first_failure']['error_kind'])
                self.assertTrue(row['write_failed'])
                self.assertEqual(isinstance(fault, (Cancelled, KeyboardInterrupt, SystemExit)), report['cancelled'])

    def test_acquisition_success_and_original_finalizer_faults(self):
        for site in ('acquisition', 'entry'):
            for fault in (OSError('ordinary'), Cancelled(15), KeyboardInterrupt(), SystemExit(0)):
                with self.subTest(site=site, fault=type(fault).__name__):
                    result = self.model(observation_site=site, observation_fault=fault)
                    control = isinstance(fault, (Cancelled, KeyboardInterrupt, SystemExit))
                    self.assertIs(result['error'], fault if control else None)
                    self.assertEqual(1, len(result['saves']))
                    self.assertEqual('FAIL' if control else 'PASS', result['saves'][0]['status'])
                    self.assertTrue(result['saves'][0]['inner_diagnostic']['write_failed'])
        for location in ('copy', 'save'):
            fault = OSError('original finalizer')
            args = {'copy_error': fault} if location == 'copy' else {'save_error': fault}
            result = self.model(business=7, observation_site='acquisition', observation_fault=KeyboardInterrupt(), **args)
            self.assertIs(result['error'], fault)
            self.assertIn('copy-log', result['trace'])
            self.assertEqual(location == 'save', bool(result['saves']))
            row = result['live'][-1]['inner_diagnostic'] if result['live'] else None
            if row:
                self.assertEqual('DATA_REFUSAL', row['first_failure']['error_kind'])
                self.assertEqual('IO', row['cleanup_failure']['error_kind'])

    def test_business_return_and_failure_projection(self):
        for business in (None, 7, OSError('spawn'), ValueError('command-timeout'),
                         ValueError('deadline-exhausted'), ValueError('output-bound'), ValueError('process-cleanup'),
                         ImportError('private'), Cancelled(15), KeyboardInterrupt(), SystemExit(7)):
            with self.subTest(business=repr(business)):
                result = self.model(business=business); report = result['saves'][-1]; row = report['inner_diagnostic']
                inner_result.validate(row, BINDING)
                self.assertEqual('KERNEL', row['command']); self.assertEqual('ISSUED', row['attempt'])
                self.assertEqual('RETURNED' if business is None or type(business) is int else 'UNOBSERVED', row['natural_return']['kind'])
                group = inner_result.capture(json.dumps(report).encode(), BINDING)
                self.assertEqual('REFUSED' if business is None or isinstance(business, SystemExit) else 'VERIFIED', group['availability'])
                self.assertEqual('PASS' if business is None else 'FAIL', report['status'])
                self.assertEqual(0 if business is None else None, result['return'])
                if business is not None: self.assertIsNotNone(result['error'])

    def test_after_effect_save_healthy_snapshot_is_refused(self):
        # Save captures the actual as-of-write bytes before its mocked publication error.
        result = self.model(save_error=OSError('after-effect-save'))
        self.assertIsInstance(result['error'], OSError)
        saved = result['saves'][-1]
        self.assertEqual('PASS', saved['status'])
        self.assertEqual('COMPLETE', saved['inner_diagnostic']['phase'])
        self.assertIsNone(saved['inner_diagnostic']['cleanup_failure'])
        raw = json.dumps(saved).encode(); group = inner_result.capture(raw, BINDING)
        self.assertEqual('REFUSED', group['availability'])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), group['raw_sha256'])
        self.assertIsNone(group['diagnostic'])
        # The later live row knows IO, but cannot rewrite the captured snapshot.
        self.assertEqual('IO', result['live'][-1]['inner_diagnostic']['cleanup_failure']['error_kind'])

    def test_first_business_failure_survives_cleanup_failure(self):
        result = self.model(business=7, save_error=OSError('publication'))
        row = result['live'][-1]['inner_diagnostic']
        self.assertEqual('KERNEL', row['first_failure']['phase'])
        self.assertEqual('DATA_REFUSAL', row['first_failure']['error_kind'])
        self.assertEqual('IO', row['cleanup_failure']['error_kind'])
        self.assertEqual('RETURNED', row['natural_return']['kind'])
        self.assertIsInstance(result['error'], OSError)  # Original finalizer exception precedence.

    def test_late_deferred_cancel_preserves_original_resave(self):
        result = self.model(late_events=True); report = result['saves'][-1]
        self.assertEqual(2, len(result['saves'])); self.assertEqual(0, result['return'])
        self.assertEqual('FAIL', report['status']); self.assertTrue(report['cancelled'])
        self.assertTrue(report['inner_diagnostic']['cancelled'])
        self.assertIsNone(report['inner_diagnostic']['first_failure'])
        self.assertEqual('CANCELLED', report['inner_diagnostic']['cleanup_failure']['error_kind'])
        self.assertEqual('VERIFIED', inner_result.capture(json.dumps(report).encode(), BINDING)['availability'])

    def test_unavailable_initial_observation_preserves_business(self):
        result = self.model(business=7, init_error=OSError('observation'))
        self.assertIsInstance(result['error'], ValueError)
        self.assertIsNone(result['saves'][-1]['inner_diagnostic'])
        self.assertEqual('REFUSED', inner_result.capture(json.dumps(result['saves'][-1]).encode(), BINDING)['availability'])

    def test_failure_and_finalization_observation_controls_finish_original_cleanup(self):
        for site in ('failure', 'FINALIZATION', 'COMPLETE'):
            for control in (Cancelled(15), KeyboardInterrupt(), SystemExit(0)):
                with self.subTest(site=site, control=type(control).__name__):
                    operation = 'failure' if site == 'failure' else 'phase'
                    original = getattr(inner_result, operation)
                    fired = [False]
                    def injected(row, value, **kw):
                        match = site == 'failure' or value == site
                        if match and not fired[0]:
                            fired[0] = True
                            raise control
                        return original(row, value, **kw)
                    with patch.object(inner_result, operation, side_effect=injected):
                        result = self.model(business=None if site == 'COMPLETE' else 7)
                    self.assertTrue(fired[0]); self.assertTrue(result['saves'])
                    if site == 'COMPLETE': self.assertIs(result['error'], control)
                    else: self.assertIsInstance(result['error'], ValueError)
                    report = result['saves'][-1]; row = report['inner_diagnostic']
                    self.assertEqual('FAIL', report['status']); self.assertTrue(report['cancelled'])
                    self.assertTrue(row['write_failed']); self.assertTrue(row['cancelled'])
                    if site != 'COMPLETE':
                        self.assertEqual('ValueError', report['error_type'])
                        self.assertEqual('KERNEL', row['first_failure']['phase'])
                        self.assertEqual('DATA_REFUSAL', row['first_failure']['error_kind'])
                    self.assertEqual('REFUSED', inner_result.capture(json.dumps(report).encode(), BINDING)['availability'])

    def test_classification_observation_faults_preserve_business_error(self):
        for error in (OSError('observer'), ValueError('observer'), Cancelled(15), KeyboardInterrupt(), SystemExit(0)):
            with self.subTest(error=type(error).__name__):
                with patch.object(inner_result, '_kind', side_effect=error): result = self.model(business=7)
                self.assertIsInstance(result['error'], ValueError)
                self.assertEqual(('command failed: kernel',), result['error'].args)
                self.assertTrue(result['saves'])
                report = result['saves'][-1]; row = report['inner_diagnostic']
                self.assertEqual('DATA_REFUSAL', row['first_failure']['error_kind'])
                self.assertEqual('ValueError', report['error_type']); self.assertTrue(row['write_failed'])
                self.assertEqual(isinstance(error, (Cancelled, KeyboardInterrupt, SystemExit)), report['cancelled'])
                self.assertEqual('REFUSED', inner_result.capture(json.dumps(report).encode(), BINDING)['availability'])



if __name__ == '__main__':
    unittest.main()
