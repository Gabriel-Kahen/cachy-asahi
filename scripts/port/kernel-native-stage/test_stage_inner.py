# SPDX-License-Identifier: MIT
"""Owned regular fixture I/O and fully mocked stage actors; no native actors."""
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import common
import stage
import inner_result
import evidence
import test_stage


class InnerCaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        private = Path(self.tmp.name) / 'private'; private.mkdir(mode=0o700)
        self.out = private / 'output-baseline'; self.out.mkdir(mode=0o700)
        self.path = self.out / 'result.json'
        self.expected = {'nonce': 'a' * 32, 'action': 'baseline',
                         'contract_sha256': 'b' * 64, 'worker_sha256': 'c' * 64}

    def write(self):
        row = inner_result.initial(self.expected)
        inner_result.phase(row, 'KERNEL')
        inner_result.issued(row, 'KERNEL')
        inner_result.returned(row, 2)
        inner_result.failure(row, ValueError('private path text'))
        raw = (json.dumps({'status': 'FAIL', 'action': 'baseline', 'nonce': self.expected['nonce'], 'cancelled': False, 'inner_diagnostic': row}) + '\n').encode()
        self.path.write_bytes(raw); self.path.chmod(0o600)
        return raw

    def capture(self): return stage.capture_inner_failure(self.out, self.expected)

    def test_one_read_raw_hash_and_no_private_binding(self):
        raw = self.write(); calls = []
        original = inner_result.capture
        def capture(data, expected):
            calls.append(data)
            self.path.write_bytes(b'poison after capture')
            return original(data, expected)
        with patch.object(inner_result, 'capture', capture): group = self.capture()
        self.assertEqual(calls, [raw])
        self.assertEqual(group['availability'], 'VERIFIED')
        self.assertEqual(group['raw_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertNotIn('private path text', json.dumps(group))
        self.assertNotIn('nonce', json.dumps(group))

    def test_missing_wrong_mode_link_symlink_fifo_and_oversize_refuse(self):
        self.assertEqual(self.capture()['availability'], 'UNAVAILABLE')
        cases = ('mode', 'hardlink', 'symlink', 'fifo', 'oversize', 'directory', 'parent-mode')
        for case in cases:
            with self.subTest(case=case):
                self.write()
                other = self.out / 'other'
                if case == 'mode': self.path.chmod(0o644)
                elif case == 'hardlink': os.link(self.path, other)
                elif case == 'symlink': self.path.rename(other); self.path.symlink_to(other)
                elif case == 'fifo': self.path.unlink(); os.mkfifo(self.path, 0o600)
                elif case == 'oversize': self.path.write_bytes(b'x' * (4 * 1024**2 + 1))
                elif case == 'directory': self.path.unlink(); self.path.mkdir(mode=0o600)
                elif case == 'parent-mode': self.out.parent.chmod(0o755)
                self.assertEqual(self.capture()['availability'], 'REFUSED')
                if self.path.is_dir(): self.path.rmdir()
                else: self.path.unlink()
                other.unlink(missing_ok=True); self.out.parent.chmod(0o700)

    def test_stale_binding_and_malformed_bytes_refuse(self):
        self.write()
        for key in self.expected:
            old = self.expected[key]; self.expected[key] = '0' * len(old)
            with self.subTest(key=key): self.assertEqual(self.capture()['availability'], 'REFUSED')
            self.expected[key] = old
        self.path.write_bytes(b'{broken')
        self.assertEqual(self.capture()['availability'], 'REFUSED')

    def test_transient_identity_and_control_faults_close_actual_descriptor(self):
        self.write(); original = os.fstat
        for error in (OSError('once'), KeyboardInterrupt(), stage.Cancelled()):
            seen = []
            def fault(fd):
                seen.append(fd)
                raise error
            with self.subTest(error=type(error).__name__), patch.object(stage.os, 'fstat', fault):
                if isinstance(error, Exception): self.assertEqual(self.capture()['availability'], 'REFUSED')
                else:
                    with self.assertRaises(type(error)): self.capture()
            self.assertEqual(len(seen), 1)
            with self.assertRaises(OSError) as caught: original(seen[0])
            self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_drift_after_single_read_refuses(self):
        self.write(); original = os.fstat; calls = []
        def mutate(fd):
            calls.append(fd)
            if len(calls) == 2: self.path.write_bytes(b'changed')
            return original(fd)
        with patch.object(stage.os, 'fstat', mutate):
            self.assertEqual(self.capture()['availability'], 'REFUSED')
        self.assertEqual(len(calls), 2)


class FailureCaptureFlowTests(unittest.TestCase):
    run_fixture = test_stage.ChildCheckpointTests.run_fixture

    def test_nonzero_capture_after_first_latch_preserves_original_failure_and_cleanup(self):
        for action in ('probe', 'baseline', 'candidate'):
            seen = []
            original = evidence.inner_failure
            def attach(row, name, group):
                self.assertEqual(row['first_failed_predicate'], action.upper() + '_COMMAND')
                self.assertEqual(row['failure_category'], 'COMMAND_NONZERO')
                self.assertEqual(row['operation']['first_failure']['gate'], 'QUERY_RETURN')
                seen.append((name, group)); return original(row, name, group)
            with self.subTest(action=action), patch.object(evidence, 'inner_failure', attach):
                report, row, calls, _ = self.run_fixture('exit-' + action)
            self.assertEqual(len(seen), 1)
            self.assertEqual(seen[0][0], action)
            self.assertEqual(seen[0][1]['availability'], 'UNAVAILABLE')
            self.assertEqual(row['schema_version'], 4)
            self.assertEqual(row['commands'][action], evidence.exit_record(125))
            self.assertEqual(report['status'], 'FAIL')
            self.assertNotIn(action, report)
            self.assertIn(('cleanup', 'build'), calls)
            self.assertIn(('cleanup', 'provision'), calls)

    def test_success_and_provision_never_capture(self):
        for fault in (None, 'exit-provision'):
            with patch.object(stage, 'capture_inner_failure', side_effect=AssertionError('unexpected capture')):
                report, row, _, _ = self.run_fixture(fault)
            self.assertEqual(row['schema_version'], 3)
            self.assertNotIn('inner', row)

    def test_valid_failed_receipt_uses_original_launch_binding_before_refusal(self):
        original = stage.capture_inner_failure
        captures = []
        def capture(out, expected):
            captures.append(dict(expected))
            contract = common.digest(out.parent / 'inputs/contract.json')
            self.assertEqual(expected['contract_sha256'], contract)
            self.assertEqual(expected['worker_sha256'], '3' * 64)
            self.assertEqual(expected['action'], 'baseline')
            row = inner_result.initial(expected)
            inner_result.phase(row, 'KERNEL'); inner_result.issued(row, 'KERNEL')
            inner_result.returned(row, 2); inner_result.failure(row, ValueError('private compiler message'))
            common.save(out / 'result.json', {'status': 'FAIL', 'action': expected['action'],
                'nonce': expected['nonce'], 'cancelled': False, 'inner_diagnostic': row})
            return original(out, expected)
        with patch.object(stage, 'capture_inner_failure', capture):
            report, row, calls, _ = self.run_fixture('exit-baseline')
        self.assertEqual(len(captures), 1)
        self.assertEqual(report['status'], 'FAIL')
        self.assertEqual(report['error_type'], 'ValueError')
        self.assertEqual(row['commands']['baseline'], evidence.exit_record(125))
        self.assertEqual(row['inner']['baseline']['availability'], 'VERIFIED')
        self.assertEqual(row['inner']['baseline']['diagnostic']['natural_return'], {'kind': 'RETURNED', 'code': 2})
        self.assertNotIn('baseline', report)
        self.assertNotIn('private compiler message', json.dumps(row))
        self.assertIn(('cleanup', 'build'), calls)

    def test_ordinary_capture_and_projection_faults_keep_original_refusal(self):
        for target in ('capture_inner_failure', 'inner_failure'):
            owner = stage if target == 'capture_inner_failure' else evidence
            with self.subTest(target=target), patch.object(owner, target, side_effect=OSError('observation only')):
                report, row, calls, _ = self.run_fixture('exit-baseline')
            self.assertEqual(report['error_type'], 'ValueError')
            self.assertEqual(row['first_failed_predicate'], 'BASELINE_COMMAND')
            self.assertEqual(row['failure_category'], 'COMMAND_NONZERO')
            self.assertEqual(row['commands']['baseline'], evidence.exit_record(125))
            self.assertNotIn('inner', row)
            self.assertIn(('cleanup', 'build'), calls)

    def test_capture_control_keeps_original_business_failure_and_latches_cancel(self):
        for error in (KeyboardInterrupt(), stage.Cancelled()):
            with self.subTest(error=type(error).__name__), patch.object(
                    stage, 'capture_inner_failure', side_effect=error):
                report, row, calls, _ = self.run_fixture('exit-baseline')
            self.assertTrue(report['cancelled'])
            self.assertEqual(row['first_failed_predicate'], 'BASELINE_COMMAND')
            self.assertEqual(row['failure_category'], 'COMMAND_NONZERO')
            self.assertEqual(row['operation']['first_failure']['category'], 'COMMAND_NONZERO')
            self.assertIn(('cleanup', 'build'), calls)

    def test_systemexit_keeps_original_propagation_and_finally_without_invented_cancel(self):
        actual = stage.finish; snapshots = []
        def finish(out, report):
            actual(out, report); snapshots.append(copy.deepcopy(report))
        with patch.object(stage, 'finish', finish), patch.object(stage, 'capture_inner_failure',
                side_effect=SystemExit(9)):
            with self.assertRaises(SystemExit) as caught: self.run_fixture('exit-baseline')
        self.assertEqual(caught.exception.code, 9)
        final = snapshots[-1]; row = final['diagnostics']
        self.assertEqual(final['status'], 'FAIL')
        self.assertFalse(final['cancelled'])
        self.assertEqual(row['first_failed_predicate'], 'BASELINE_COMMAND')
        self.assertEqual(row['failure_category'], 'COMMAND_NONZERO')
        self.assertEqual(row['operation']['first_failure']['category'], 'COMMAND_NONZERO')
        self.assertEqual(row['commands']['baseline'], evidence.exit_record(125))
        self.assertEqual(final['cleanup']['status'], 'PASS')
        self.assertEqual(len(final['cleanup']['records']), 3)
        self.assertNotIn('inner', row)


if __name__ == '__main__': unittest.main()
