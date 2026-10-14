# SPDX-License-Identifier: MIT
import copy
import hashlib
import json
import unittest

import inner_result as diag
from runtime import Cancelled

BINDING = {'nonce': 'a' * 32, 'action': 'baseline', 'contract_sha256': 'b' * 64, 'worker_sha256': 'c' * 64}


class InnerResult(unittest.TestCase):
    def row(self): return diag.initial(BINDING)
    def report(self, row=None, **extra):
        value = {'action': 'baseline', 'nonce': BINDING['nonce'], 'status': 'FAIL', 'cancelled': False,
                 'inner_diagnostic': self.row() if row is None else row}
        value.update(extra)
        return json.dumps(value).encode()

    def test_check001_closed_conjuncts_preserve_capture_and_privacy(self):
        import evidence
        labels = ('ALIGN_MIN', 'ALIGN_POWER_TWO', 'VA_ALIGN', 'PA_ALIGN', 'VA_16K', 'PA_16K', 'PERMISSIONS', 'MEMORY_SIZE')
        prefix = '16K ELF load geometry/permissions required; WX refused'
        for label in labels:
            row = self.row(); diag.phase(row, 'KERNEL'); diag.issued(row, 'KERNEL'); diag.returned(row, 0)
            diag.phase(row, 'OUTPUTS'); error = ValueError(prefix + ' [' + label + ']')
            diag.failure(row, error); first = copy.deepcopy(row['first_failure'])
            diag.output_failure(row, error)
            fact = {'call_boundary': 'VERIFY_OUTPUTS', 'predicate': 'CHECK_001_' + label}
            self.assertEqual(row['output_failure'], fact); evidence.validate_output_fact(fact)
            group = diag.capture(self.report(row), BINDING); diag.validate_group(group)
            self.assertEqual(group['availability'], 'VERIFIED')
            self.assertEqual(group['diagnostic']['output_failure'], fact)
            diag.failure(row, OSError('/private'), cleanup=True)
            self.assertEqual(row['first_failure'], first)
            self.assertEqual(row['natural_return'], {'kind': 'RETURNED', 'code': 0})
            self.assertNotIn('/private', json.dumps(diag.capture(self.report(row), BINDING)))
        for code in ('CHECK_001_PRIVATE', 'CHECK_001_VA_16K /private', '/private', True):
            with self.assertRaises(ValueError):
                evidence.validate_output_fact({'call_boundary': 'VERIFY_OUTPUTS', 'predicate': code})
        for text, code in ((prefix, 'CHECK_001'), (prefix + ' [PRIVATE]', 'OTHER')):
            row = self.row(); diag.phase(row, 'KERNEL'); diag.issued(row, 'KERNEL'); diag.returned(row, 0)
            diag.phase(row, 'OUTPUTS'); error = ValueError(text); diag.failure(row, error); diag.output_failure(row, error)
            self.assertEqual(row['output_failure']['predicate'], code)

    def test_frozen_business_and_independent_cleanup(self):
        row = self.row(); diag.phase(row, 'KERNEL'); diag.issued(row, 'KERNEL')
        diag.returned(row, -15); diag.failure(row, ValueError('command failed: kernel'))
        first = copy.deepcopy(row['first_failure'])
        diag.phase(row, 'FINALIZATION'); diag.failure(row, OSError('/private'), cleanup=True)
        diag.failure(row, KeyboardInterrupt(), cleanup=True); diag.failure(row, ValueError('later'))
        self.assertEqual(first, row['first_failure'])
        self.assertEqual('IO', row['cleanup_failure']['error_kind'])
        self.assertTrue(row['cancelled']); self.assertEqual(-15, row['natural_return']['code'])
        diag.invalidate(row); diag.returned(row, 0); self.assertTrue(row['write_failed'])
        diag.validate(row)

    def test_issued_is_not_natural(self):
        row = self.row(); diag.issued(row, 'TOOL_0'); diag.failure(row, OSError('spawn'))
        self.assertEqual({'kind': 'UNOBSERVED', 'code': None}, row['natural_return'])
        diag.validate(row)

    def test_fixed_error_classification(self):
        cases = [(ValueError('command-timeout'), 'TIMEOUT'), (ValueError('deadline-exhausted'), 'DEADLINE'),
            (ValueError('output-bound'), 'OUTPUT_BOUND'), (ValueError('process-cleanup'), 'PROCESS_CLEANUP'),
            (ValueError('private path command-timeout'), 'DATA_REFUSAL'), (ValueError({'private': 'data'}), 'DATA_REFUSAL'),
            (OSError('private'), 'IO'), (ImportError('private'), 'IMPORT'), (RuntimeError('command-timeout'), 'OTHER'),
            (Cancelled(15), 'CANCELLED'), (KeyboardInterrupt(), 'CANCELLED'), (SystemExit(7), 'CANCELLED')]
        for error, expected in cases:
            with self.subTest(expected=expected, cls=type(error).__name__):
                row = self.row(); diag.failure(row, error); self.assertEqual(expected, row['first_failure']['error_kind'])
                self.assertEqual(expected == 'CANCELLED', row['cancelled']); diag.validate(row)

    def test_capture_authenticates_and_redacts(self):
        row = self.row(); diag.phase(row, 'TOOLS'); diag.issued(row, 'TOOL_17'); diag.returned(row, 1)
        diag.failure(row, ValueError('private attacker text'))
        raw = self.report(row); group = diag.capture(raw, BINDING)
        diag.validate_group(group)
        self.assertEqual('VERIFIED', group['availability'])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), group['raw_sha256'])
        self.assertNotIn('binding', group['diagnostic'])
        self.assertNotIn('private attacker text', json.dumps(group))
        self.assertNotIn(BINDING['nonce'], json.dumps(group))
        expected = hashlib.sha256(json.dumps(BINDING, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        self.assertEqual(expected, group['diagnostic']['binding_sha256'])

    def test_missing_and_invalid_full_report(self):
        self.assertEqual('UNAVAILABLE', diag.capture(None, BINDING)['availability'])
        raws = [b'', b'{', b'null', b'[]', b'{"nonce":1,"nonce":2}', self.report(action='probe'),
                self.report(nonce='d'*32), self.report(status=1), self.report(cancelled=1),
                self.report(cancelled=True), b' ' * (diag.REPORT_LIMIT + 1), self.report().replace(b'"FAIL"', b'NaN'),
                self.report()[:-1] + b',"extra":Infinity}']
        for raw in raws:
            with self.subTest(bytes=len(raw)):
                group = diag.capture(raw, BINDING); diag.validate_group(group)
                self.assertEqual('REFUSED', group['availability']); self.assertIsNone(group['diagnostic'])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), group['raw_sha256'])

    def test_unused_numeric_values_are_finite_throughout_captured_report(self):
        for token in (b'1e999', b'-1e999', b'1.0e999', b'NaN', b'Infinity', b'-Infinity'):
            for value in (token, b'{"nested":[' + token + b']}', b'[' + token + b']'):
                raw = self.report()[:-1] + b',"unused":' + value + b'}'
                with self.subTest(value=value):
                    group = diag.capture(raw, BINDING)
                    self.assertEqual('REFUSED', group['availability'])
                    self.assertIsNone(group['diagnostic'])
                    self.assertEqual(hashlib.sha256(raw).hexdigest(), group['raw_sha256'])
        for token in (b'1e308', b'-1e308', b'1e-999', b'1.25', b'0'):
            raw = self.report()[:-1] + b',"unused":{"nested":[' + token + b']}}'
            with self.subTest(finite=token):
                self.assertEqual('VERIFIED', diag.capture(raw, BINDING)['availability'])

    def test_strict_private_poison(self):
        poisons = [('schema_version', True), ('schema_version', 2), ('phase', 'private'), ('phase', []),
            ('command', 'TOOL_18'), ('command', '/usr/bin/gcc'), ('attempt', True), ('attempt', 'STARTED'),
            ('natural_return', {'kind': 'RETURNED', 'code': True}), ('natural_return', {'kind': 'RETURNED', 'code': 256}),
            ('natural_return', {'kind': 'UNOBSERVED', 'code': 0}), ('natural_return', {'kind': 'RETURNED', 'code': 0}),
            ('cancelled', 0), ('write_failed', 1), ('binding', dict(BINDING, action='provision')),
            ('binding', dict(BINDING, nonce='g'*32)), ('binding', dict(BINDING, worker_sha256='C'*64)),
            ('first_failure', {'phase': 'PROFILE', 'command': 'NONE', 'error_kind': 'NONE'}),
            ('cleanup_failure', {'phase': 'PROFILE', 'command': 'NONE', 'error_kind': 'CANCELLED'})]
        for key, value in poisons:
            with self.subTest(key=key, value=value):
                row = self.row(); row[key] = value
                with self.assertRaises(ValueError): diag.validate(row)
                self.assertEqual('REFUSED', diag.capture(self.report(row), BINDING)['availability'])
        for key in self.row():
            row = self.row(); del row[key]
            with self.assertRaises(ValueError): diag.validate(row)
        row = self.row(); row['raw_message'] = 'private'
        with self.assertRaises(ValueError): diag.validate(row)

    def test_stale_binding_and_write_fault_refuse(self):
        for key, value in BINDING.items():
            row = self.row(); row['binding'][key] = ('probe' if key == 'action' else 'd' * len(value))
            self.assertEqual('REFUSED', diag.capture(self.report(row), BINDING)['availability'])
        row = self.row(); diag.invalidate(row)
        self.assertEqual('REFUSED', diag.capture(self.report(row), BINDING)['availability'])

    def test_failure_only_capture_refuses_saved_success(self):
        row = self.row()
        self.assertEqual('REFUSED', diag.capture(self.report(row, status='PASS'), BINDING)['availability'])
        diag.phase(row, 'COMPLETE')
        self.assertEqual('REFUSED', diag.capture(self.report(row, status='PASS'), BINDING)['availability'])
        self.assertEqual('VERIFIED', diag.capture(self.report(row, status='FAIL'), BINDING)['availability'])
        self.assertIsNone(row['cleanup_failure'])
        diag.failure(row, OSError('private'), cleanup=True)
        self.assertEqual('VERIFIED', diag.capture(self.report(row, status='FAIL'), BINDING)['availability'])
        self.assertEqual('REFUSED', diag.capture(self.report(row, status='PASS'), BINDING)['availability'])

    def test_group_poison(self):
        group = diag.capture(self.report(), BINDING)
        for key, value in [('availability', 'PASS'), ('reason', 'private'), ('raw_sha256', None), ('diagnostic', None)]:
            bad = copy.deepcopy(group); bad[key] = value
            with self.assertRaises(ValueError): diag.validate_group(bad)
        for key in group['diagnostic']:
            bad = copy.deepcopy(group); del bad['diagnostic'][key]
            with self.assertRaises(ValueError): diag.validate_group(bad)
        diag.validate_group({'availability': 'REFUSED', 'reason': 'INVALID', 'raw_sha256': None, 'diagnostic': None})
        bad = copy.deepcopy(group); bad['diagnostic']['binding'] = BINDING
        with self.assertRaises(ValueError): diag.validate_group(bad)

    def test_all_finite_values_fit(self):
        for phase in diag.PHASES:
            for command in diag.COMMANDS - {'NONE'}:
                row = self.row(); diag.phase(row, phase); diag.issued(row, command); diag.returned(row, -64)
                diag.failure(row, Cancelled()); diag.failure(row, OSError('private'), cleanup=True)
                diag.invalidate(row); diag.validate(row)
                self.assertLessEqual(len(json.dumps(row).encode()), diag.LIMIT)


if __name__ == '__main__': unittest.main()
