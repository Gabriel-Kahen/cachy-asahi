#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""No compiler/Docker calls: original-module isolation and late cancellation."""
from contextlib import contextmanager
import io
import copy
import json
import os
import signal
from types import SimpleNamespace
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import worker
import worker_evidence as diagnostic
from evidence import load, save
from runtime import Cancelled


def config_fixture(private='/tmp/private-fixture', snapshot=None, action='build-1'):
    return {'snapshot': str(snapshot or HERE.parents[2]), 'private': str(private), 'action': action,
        'image': 'sha256:' + '2' * 64, 'nonce': '3' * 32, 'source_commit': 'a' * 40,
        'stage_lock_sha256': 'b' * 64, 'run_id': '1', 'run_attempt': '2',
        'docker_binary': '/unused/docker', 'docker_sha256': 'c' * 64, 'endpoint': 'unix:///unused/socket',
        'timeout': 60, 'daemon': {'fixture': True}}


def passing_workers():
    rows = {}
    for action in diagnostic.ACTIONS:
        row = diagnostic.initial(config_fixture(action=action), 'd' * 64)
        row['current_predicate'] = 'COMPLETE'
        if action != 'compare':
            row['builder'].update(exit=diagnostic.exit_record(0), status='STATIC_PASS',
                provenance={'sha256': 'e' * 64, 'bytes': 1}, log={'sha256': 'f' * 64, 'bytes': 1})
            row['commands'].update(create=diagnostic.exit_record(0), attach=diagnostic.exit_record(0),
                                   container=diagnostic.no_exit('UNOBSERVED'))
            row['cleanup'] = {'status': 'PASS', 'absence': 'PASS', 'reason': 'NONE'}
        rows[action] = {'availability': 'VERIFIED', 'exit': diagnostic.exit_record(0),
                        'observation': diagnostic.project(row)}
    return rows


class WorkerTests(unittest.TestCase):
    def test_original_builder_patch_is_module_local_and_checker_keeps_real_subprocess(self):
        original_run = subprocess.run
        builder = worker.module('build', HERE.parents[1] / 'build/build.py')
        checker = sys.modules['package_checks']
        original_builder_subprocess = builder.subprocess
        try:
            broker = mock.Mock()
            broker.capture.return_value = 'aarch64'
            broker.build.return_value = subprocess.CompletedProcess(['fixture'], 0, b'owned output\n')
            builder.subprocess = worker.BuilderCommands(broker)
            self.assertEqual(builder.capture(['docker', 'info', '--format', '{{.Architecture}}']), 'aarch64')
            log = io.BytesIO()
            result = builder.subprocess.run(['fixture'], stdout=log, stderr=subprocess.STDOUT, timeout=7)
            self.assertEqual((result.returncode, log.getvalue()), (0, b'owned output\n'))
            broker.build.assert_called_once_with(['fixture'], 7)
            self.assertIs(checker.subprocess, subprocess)
            self.assertIs(checker.subprocess.run, original_run)
        finally:
            builder.subprocess = original_builder_subprocess

    def test_late_cancellation_invalidates_owned_worker_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'build-1-receipt.json'
            @contextmanager
            def late():
                yield
                raise Cancelled(15)
            def executed(config, state, pin):
                receipt = {'status': 'PASS', 'action': 'build-1'}
                state.update(receipt=receipt, path=path)
                save(path, receipt)
                return 0
            with mock.patch.object(sys, 'argv', ['worker.py', '--config', '/unused', '--config-sha256', '0' * 64]), \
                 mock.patch.object(worker, 'load', return_value={}), \
                 mock.patch.object(worker, 'execute', side_effect=executed), \
                 mock.patch.object(worker, 'cancellation_handlers', late), \
                 mock.patch.object(sys, 'stderr', io.StringIO()):
                self.assertEqual(worker.main(), 1)
            self.assertEqual(load(path)['status'], 'FAIL')
            self.assertIs(load(path)['cancelled'], True)

    def test_builder_remove_request_cannot_remove_an_unregistered_name_directly(self):
        broker = mock.Mock()
        broker.cleanup.return_value = {'status': 'FAIL', 'absence_verified': False}
        proxy = worker.BuilderCommands(broker)
        result = proxy.run(['docker', 'rm', '-f', 'fixture-name'])
        self.assertEqual(result.returncode, 1)
        broker.cleanup.assert_called_once_with()
        broker.build.assert_not_called()


class WorkerExecutionTests(unittest.TestCase):
    def fixture(self, fault=None):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        private = Path(temporary.name); config = config_fixture(private)
        observed = {}; calls = []
        class Broker:
            def __init__(self, *args, observation, **kwargs): self.observation = observation; observed['row'] = observation
            def initialize(self, **kwargs):
                if fault == 'initialize': raise OSError('private initialize path')
                return {}
            def cleanup(self):
                calls.append('cleanup')
                if fault == 'cleanup': raise OSError('private cleanup path')
                return {'status': 'PASS', 'absence_verified': True, 'cancelled': False, 'errors': []}
        def build():
            calls.append('builder')
            if fault == 'signal': os.kill(os.getpid(), signal.SIGTERM)
            if fault == 'raise': raise OSError('private build path')
            target = private / 'build-1'; target.mkdir()
            reviewed = load(HERE / 'reviewed-inputs.json')
            code = 1 if fault == 'returned' else 0
            observed['row']['commands'].update(create=diagnostic.exit_record(0), attach=diagnostic.exit_record(code),
                                               container=diagnostic.no_exit('UNOBSERVED'))
            record = {'schema_version': 1, 'status': 'failed' if code else 'built-package-static-pass',
                'mode': 'native', 'network': 'none', 'image': config['image'], 'source_date_epoch': diagnostic.EPOCH,
                'recipe_inputs': reviewed, 'image_id': config['image'], 'exit_code': code,
                'expected_packages_sha256': diagnostic.INVENTORY_SHA, 'builder_host_arch': 'aarch64',
                'entry_script_sha256': diagnostic.ENTRY_SHA,
                'error': 'isolated generated metadata differs from reviewed url' if code else 'private unused text'}
            save(target / 'provenance.json', record); (target / 'build.log').write_bytes(b'private log output')
            return code
        builder = SimpleNamespace(main=build, package=None, recipe=None, bind_artifact=None)
        def verify(*args, **kwargs):
            calls.append('verify')
            self.assertEqual(set(kwargs), {'record', 'log_bytes'})
            self.assertEqual(kwargs['log_bytes'], b'private log output')
            if fault == 'artifact': raise ValueError('private ELF/path failure')
            return {'fixture': True}
        state = {}
        with mock.patch.object(worker, 'ObservedBroker', Broker), mock.patch.object(worker, 'module', return_value=builder), \
             mock.patch.object(worker, 'verify_attempt', side_effect=verify), worker.cancellation_handlers():
            if fault in ('initialize', 'raise', 'returned', 'artifact', 'signal'):
                with self.assertRaises(BaseException): worker.execute(config, state, 'd' * 64)
            else:
                self.assertEqual(worker.execute(config, state, 'd' * 64), int(fault == 'cleanup'))
        receipt = load(private / 'build-1-receipt.json')
        self.assertNotIn('private', json.dumps(diagnostic.project(receipt['diagnostics'])))
        return config, receipt, calls

    def test_actual_returned_builder_failure_retains_finite_provenance_reason(self):
        _, receipt, calls = self.fixture('returned'); row = receipt['diagnostics']
        self.assertEqual(row['first_failed_predicate'], 'BUILDER_CALL')
        self.assertEqual(row['builder']['exit'], diagnostic.exit_record(1))
        self.assertEqual(row['builder']['reason'], 'GENERATED_METADATA')
        self.assertNotIn('verify', calls); self.assertEqual(receipt['cleanup']['status'], 'PASS')

    def test_pre_builder_launch_and_artifact_failures_are_distinct(self):
        for fault, predicate, reason in (('initialize', 'BROKER_INITIALIZE', 'IO'),
            ('raise', 'BUILDER_CALL', 'IO'), ('artifact', 'ARTIFACT_VERIFY', 'INVALID_DATA')):
            with self.subTest(fault=fault):
                _, receipt, _ = self.fixture(fault); row = receipt['diagnostics']
                self.assertEqual((row['first_failed_predicate'], row['failure_reason']), (predicate, reason))
                self.assertEqual(row['builder']['exit']['kind'], 'NOT_RUN' if fault == 'initialize' else
                                 'UNOBSERVED' if fault == 'raise' else 'EXIT_ZERO')

    def test_captured_success_and_cleanup_failure_require_actual_absence(self):
        config, receipt, _ = self.fixture()
        row = diagnostic.worker_row('UNAVAILABLE'); row['exit'] = diagnostic.exit_record(0)
        self.assertEqual(diagnostic.receive(config, 'd' * 64, row), receipt)
        self.assertEqual(row['observation']['current_predicate'], 'COMPLETE')
        _, failed, _ = self.fixture('cleanup')
        self.assertEqual((failed['status'], failed['diagnostics']['first_failed_predicate']), ('FAIL', 'CLEANUP'))
        self.assertEqual(failed['diagnostics']['cleanup'], {'status': 'FAIL', 'absence': 'UNVERIFIED', 'reason': 'IO'})

    def test_real_TERM_before_builder_return_is_unobserved_and_cleanup_still_runs(self):
        _, receipt, calls = self.fixture('signal')
        self.assertTrue(receipt['cancelled']); self.assertIn('cleanup', calls)
        self.assertEqual((receipt['diagnostics']['first_failed_predicate'], receipt['diagnostics']['failure_reason']),
                         ('BUILDER_CALL', 'CANCELLED'))
        self.assertEqual(receipt['diagnostics']['builder']['exit'], diagnostic.no_exit('UNOBSERVED'))

    def test_after_capture_mutation_cannot_be_promoted_or_exported(self):
        config, receipt, _ = self.fixture()
        row = diagnostic.worker_row('UNAVAILABLE'); row['exit'] = diagnostic.exit_record(0)
        received = diagnostic.receive(config, 'd' * 64, row)
        path = Path(config['private']) / 'build-1/provenance.json'
        save(path, {'raw': 'private poison'})
        self.assertEqual(received, receipt)
        self.assertEqual(row['observation']['current_predicate'], 'COMPLETE')
        late = diagnostic.worker_row('UNAVAILABLE'); late['exit'] = diagnostic.exit_record(0)
        self.assertIsNone(diagnostic.receive(config, 'd' * 64, late))
        self.assertEqual(late['availability'], 'UNVERIFIED')


class OperationObservationTests(unittest.TestCase):
    def fixture(self, observed=False, code=0, foreign=False, remove_failure=False):
        import test_broker
        case = test_broker.BrokerTests(); case.setUp(); self.addCleanup(case.doCleanups)
        # Private fake daemon state; original production Broker methods are unchanged.
        source = case.binary.read_text().replace("else:print('build output');raise SystemExit(s.get('build_code',0))",
            "else:\n  item['State']={'Status':'exited','Running':False,'ExitCode':s.get('build_code',0)};save();print('build output');raise SystemExit(s.get('build_code',0))")
        case.binary.write_text(source); case.digest = diagnostic.sha(source.encode())
        case.state['build_code'] = code
        case.state['remove_failure'] = remove_failure
        if foreign: case.state['label'] = 'f' * 32
        case.save()
        config = config_fixture(case.root); config['nonce'] = test_broker.NONCE
        row = diagnostic.initial(config, 'd' * 64)
        if observed:
            value = worker.ObservedBroker(test_broker.Runner(30, case.env, case.root / 'logs'),
                test_broker.Runner(1, case.env, case.root / 'cleanup-logs'), case.binary, case.digest,
                case.endpoint, test_broker.IMAGE, case.uid, case.gid, case.root / 'journal.json',
                test_broker.NONCE, expected_mounts=case.mounts, observation=row)
        else:
            value = case.make()
        value.initialize()
        if foreign or remove_failure:
            with self.assertRaises(ValueError): value.build(case.command(), 2)
        else:
            self.assertEqual(value.build(case.command(), 2).returncode, code)
        calls = [[str(part).replace(str(case.root), '/fixture') for part in command] for command in case.load()['calls']]
        self.last = case, value
        return row, calls

    def test_instance_observer_preserves_exact_existing_operation_sequence(self):
        _, original = self.fixture()
        row, observed = self.fixture(observed=True)
        self.assertEqual(observed, original)
        self.assertEqual(row['commands']['create'], diagnostic.exit_record(0))
        self.assertEqual(row['commands']['attach'], diagnostic.exit_record(0))
        self.assertEqual(row['commands']['container'], diagnostic.exit_record(0))

    def test_actual_attached_and_owned_container_exits_are_separate_observations(self):
        row, _ = self.fixture(observed=True, code=1)
        self.assertEqual(row['commands']['create'], diagnostic.exit_record(0))
        self.assertEqual(row['commands']['attach'], diagnostic.exit_record(1))
        self.assertEqual(row['commands']['container'], diagnostic.exit_record(1))
        self.assertEqual((row['first_failed_predicate'], row['failure_reason']), ('CONTAINER_ATTACH', 'COMMAND_NONZERO'))

    def test_foreign_nonce_cannot_authorize_container_state_observation(self):
        row, _ = self.fixture(observed=True, foreign=True)
        self.assertEqual(row['commands']['container'], diagnostic.no_exit('UNOBSERVED'))
        self.assertEqual(row['commands']['attach'], diagnostic.no_exit())

    def test_later_owned_state_drift_cannot_overwrite_first_actual_container_exit(self):
        row, _ = self.fixture(observed=True, code=1, remove_failure=True)
        case, value = self.last
        registered = value._journal()['containers'][0]
        self.assertEqual(row['commands']['container'], diagnostic.exit_record(1))
        state = case.load()
        state['containers'][registered['name']]['State']['ExitCode'] = 0
        case.save()
        with self.assertRaisesRegex(ValueError, 'worker-container-state-drift'):
            value._inspect(registered['id'], registered, cleanup=True)
        self.assertEqual(row['commands']['container'], diagnostic.exit_record(1))


class WorkerDiagnosticTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.config = config_fixture(self.root)
        self.row = diagnostic.initial(self.config, 'd' * 64)
        self.work = self.root / 'build-1'; self.work.mkdir(mode=0o700)
        self.reviewed = {'PKGBUILD': 'e' * 64}
        self.provenance = {'schema_version': 1, 'status': 'failed', 'error': 'private token /secret',
            'mode': 'native', 'network': 'none', 'image': self.config['image'], 'source_date_epoch': diagnostic.EPOCH,
            'recipe_inputs': self.reviewed, 'expected_packages_sha256': diagnostic.INVENTORY_SHA}

    def test_closed_projection_binds_hash_only_and_never_raw_details(self):
        result = diagnostic.project(self.row)
        self.assertNotIn('binding', result); self.assertNotIn('nonce', json.dumps(result))
        self.assertLessEqual(len(diagnostic.encoded(result)), 4096)
        self.assertEqual(result['commands']['container'], diagnostic.no_exit())

    def test_public_vector_complete_roles_distinct_bindings_and_finite_fallback(self):
        good = passing_workers(); snapshot = diagnostic.validate_workers(good, require_complete=True)
        self.assertEqual(snapshot, good)
        good['build-1']['observation']['builder']['reason'] = 'private poison'
        self.assertNotIn('private', json.dumps(snapshot))
        fallback = {name: diagnostic.worker_row() for name in diagnostic.ACTIONS}
        self.assertEqual(diagnostic.validate_workers(fallback), fallback)
        with self.assertRaises(ValueError): diagnostic.validate_workers(fallback, require_complete=True)
        for change in (lambda r: r.update(unknown=diagnostic.worker_row()),
            lambda r: r['build-2']['observation'].update(binding_sha256=r['build-1']['observation']['binding_sha256']),
            lambda r: r.update(compare=copy.deepcopy(r['build-1']))):
            altered = passing_workers(); change(altered)
            with self.subTest(change=change), self.assertRaises(ValueError): diagnostic.validate_workers(altered)
        with self.assertRaises(ValueError): diagnostic.validate_workers(passing_workers(), require_complete='true')
        with self.assertRaises(ValueError): diagnostic.validate_public(snapshot['build-1']['observation'], 'unknown')

    def test_failed_builder_classifies_known_messages_and_unknown_raw_error_without_export(self):
        self.row['builder']['exit'] = diagnostic.exit_record(1)
        self.provenance['error'] = 'container build exited 1; see build.log'
        save(self.work / 'provenance.json', self.provenance); (self.work / 'build.log').write_bytes(b'private raw output')
        raw, log = diagnostic.observe_builder(self.row, self.work, self.config, self.reviewed)
        self.assertEqual(raw, self.provenance); self.assertEqual(log, b'private raw output')
        self.assertEqual(self.row['builder']['reason'], 'CONTAINER_EXIT')
        self.provenance['error'] += ' private token'
        save(self.work / 'provenance.json', self.provenance)
        diagnostic.observe_builder(self.row, self.work, self.config, self.reviewed)
        self.assertEqual(self.row['builder']['reason'], 'UNKNOWN')
        self.assertNotIn('private', json.dumps(diagnostic.project(self.row)))

    def test_provenance_wrong_bindings_types_and_status_are_unverified(self):
        for key, value in (('schema_version', True), ('mode', 'emulated'), ('network', 'bridge'),
            ('image', 'sha256:' + '4' * 64), ('recipe_inputs', {}), ('source_date_epoch', 1),
            ('expected_packages_sha256', 'f' * 64), ('status', 'made-up')):
            with self.subTest(key=key):
                current = copy.deepcopy(self.provenance); current[key] = value
                save(self.work / 'provenance.json', current)
                diagnostic.observe_builder(self.row, self.work, self.config, self.reviewed)
                self.assertEqual(self.row['builder']['status'], 'UNVERIFIED')

    def test_claimed_static_pass_requires_complete_native_builder_binding(self):
        self.provenance.update(status='built-package-static-pass', exit_code=0, image_id=self.config['image'],
            builder_host_arch='aarch64', entry_script_sha256=diagnostic.ENTRY_SHA)
        self.row['builder']['exit'] = diagnostic.exit_record(0)
        (self.work / 'build.log').write_bytes(b'private fixture log')
        save(self.work / 'provenance.json', self.provenance)
        diagnostic.observe_builder(self.row, self.work, self.config, self.reviewed)
        self.assertEqual(self.row['builder']['status'], 'STATIC_PASS')
        for key in ('recipe_inputs', 'image_id', 'expected_packages_sha256', 'builder_host_arch', 'entry_script_sha256'):
            changed = copy.deepcopy(self.provenance); changed.pop(key)
            save(self.work / 'provenance.json', changed)
            with self.subTest(key=key):
                diagnostic.observe_builder(self.row, self.work, self.config, self.reviewed)
                self.assertEqual(self.row['builder']['status'], 'UNVERIFIED')

    def test_capture_mutation_owner_links_and_bounds_cannot_supply_provenance(self):
        path = self.work / 'provenance.json'; save(path, self.provenance)
        original = diagnostic.read
        def mutation(path, limit):
            raw = original(path, limit); path.write_bytes(raw + b' '); return raw
        with mock.patch.object(diagnostic, 'read', mutation), self.assertRaises(ValueError):
            diagnostic.capture(path, diagnostic.PROVENANCE_LIMIT)
        with mock.patch.object(diagnostic.os, 'getuid', return_value=os.getuid() + 1), self.assertRaises(ValueError):
            diagnostic.capture(path, diagnostic.PROVENANCE_LIMIT)
        other = path.with_name('link'); os.link(path, other)
        with self.assertRaises(ValueError): diagnostic.capture(path, diagnostic.PROVENANCE_LIMIT)
        other.unlink()
        with self.assertRaises(ValueError): diagnostic.capture(path, 1)

    def test_first_failure_survives_cleanup_and_late_cancellation(self):
        self.row['current_predicate'] = 'CONTAINER_ATTACH'
        self.row['commands']['attach'] = diagnostic.exit_record(1)
        diagnostic.failure(self.row, 'COMMAND_NONZERO')
        diagnostic.failure(self.row, 'CANCELLED', 'FINALIZATION')
        self.assertEqual((self.row['first_failed_predicate'], self.row['failure_reason']), ('CONTAINER_ATTACH', 'COMMAND_NONZERO'))
        self.assertTrue(self.row['cancelled'])

    def test_finite_fields_refuse_poison_and_contradictory_completion(self):
        for change in (lambda r: r.update(raw_error='secret'), lambda r: r.update(schema_version=True),
            lambda r: r.update(first_failed_predicate='path'), lambda r: r['binding'].update(nonce='unknown'),
            lambda r: r['binding'].update(recipe_sha256='0' * 64), lambda r: r['builder']['exit'].update(code=True),
            lambda r: r['commands'].update(container=diagnostic.exit_record(-9)),
            lambda r: r.update(current_predicate='COMPLETE'), lambda r: r['cleanup'].update(status='PASS'),
            lambda r: r['builder'].update(log={'sha256': 'a' * 64, 'bytes': 8 * 1024**2 + 1})):
            with self.subTest(change=change):
                row = copy.deepcopy(self.row); change(row)
                with self.assertRaises(ValueError): diagnostic.project(row)
        good = passing_workers()['build-1']['observation']; diagnostic.validate_public(good, 'build-1')
        good['commands']['container'] = diagnostic.exit_record(1)
        with self.assertRaises(ValueError): diagnostic.validate_public(good, 'build-1')

    def test_missing_and_early_receipt_are_truthful_without_builder_invocation_claim(self):
        row = diagnostic.worker_row('UNAVAILABLE'); row['exit'] = diagnostic.exit_record(1)
        self.assertIsNone(diagnostic.receive(self.config, 'd' * 64, row)); self.assertEqual(row['availability'], 'UNAVAILABLE')
        diagnostic.failure(self.row, 'IO', 'REVIEWED_INPUTS')
        receipt = {'status': 'FAIL', 'action': 'build-1', 'hardware': 'NOT RUN', 'cancelled': False, 'diagnostics': self.row}
        save(self.root / 'build-1-receipt.json', receipt)
        self.assertEqual(diagnostic.receive(self.config, 'd' * 64, row), receipt)
        self.assertEqual(row['availability'], 'VERIFIED')
        self.assertEqual(row['observation']['builder']['exit'], diagnostic.no_exit())
        diagnostic.validate_worker_row(row, 'build-1')

    def test_wrong_nonce_config_run_and_source_bindings_are_not_accepted(self):
        diagnostic.failure(self.row, 'IO', 'REVIEWED_INPUTS')
        for key, value in (('nonce', 'f' * 32), ('config_sha256', 'f' * 64), ('run_id', '99'),
            ('run_attempt', '99'), ('source_commit', 'f' * 40), ('stage_lock_sha256', 'f' * 64)):
            changed = copy.deepcopy(self.row); changed['binding'][key] = value
            save(self.root / 'build-1-receipt.json', {'status': 'FAIL', 'action': 'build-1', 'hardware': 'NOT RUN',
                'cancelled': False, 'diagnostics': changed})
            row = diagnostic.worker_row('UNAVAILABLE'); row['exit'] = diagnostic.exit_record(1)
            with self.subTest(key=key):
                self.assertIsNone(diagnostic.receive(self.config, 'd' * 64, row))
                self.assertEqual(row['availability'], 'UNVERIFIED')


if __name__ == '__main__':
    unittest.main()
