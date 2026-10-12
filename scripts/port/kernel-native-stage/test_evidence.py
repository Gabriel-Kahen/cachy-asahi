# SPDX-License-Identifier: MIT
import copy
import importlib.util
import json
from pathlib import Path
import unittest

import evidence


def binding():
    return {'source_commit': 'a' * 40, 'stage_lock_sha256': 'b' * 64,
        'output_name_sha256': 'c' * 64, 'run_id': '1', 'run_attempt': '2', 'nonce': 'd' * 32,
        'accepted_result_sha256': 'e' * 64, 'bootstrap_sha256': 'f' * 64,
        'inputs_sha256': '1' * 64, 'base_inventory_sha256': '2' * 64}


class ChildEvidenceTests(unittest.TestCase):
    def receiver(self):
        path = Path(__file__).resolve().parents[1] / 'kernel-native-job/public.py'
        spec = importlib.util.spec_from_file_location('kernel_child_public_fixture', path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module

    def test_pending_projection_binds_only_digest_not_private_inputs(self):
        row = evidence.initial(binding()); projected = evidence.project(row)
        self.assertNotIn('binding', projected)
        self.assertNotIn('source_commit', projected)
        self.assertNotIn('nonce', projected)
        self.assertEqual(projected['commands']['provision'], {'kind': 'NOT_RUN', 'code': None})
        self.assertLessEqual(len(evidence.encoded(row)), 4096)
        self.assertEqual(self.receiver().child_project(row), projected)

    def test_completed_diagnostic_requires_observed_zero_each_command_and_cleanup(self):
        row = evidence.initial(binding())
        row['current_predicate'] = 'COMPLETE'
        with self.assertRaises(ValueError): evidence.project(row)
        row['commands'] = {name: evidence.exit_record(0) for name in evidence.ACTIONS}
        with self.assertRaises(ValueError): evidence.project(row)
        row['cleanup'] = {'status': 'PASS', 'category': 'NONE'}
        self.assertEqual(evidence.project(row)['current_predicate'], 'COMPLETE')
        for name in evidence.ACTIONS:
            altered = copy.deepcopy(row); altered['commands'][name] = evidence.exit_record(125)
            with self.subTest(command=name), self.assertRaises(ValueError): evidence.project(altered)

    def test_first_predicate_stays_fixed_across_cleanup_and_finalization_cancellation(self):
        row = evidence.initial(binding()); row['current_predicate'] = 'PROVISION_COMMAND'
        row['commands']['provision'] = evidence.exit_record(125)
        evidence.failure(row, 'COMMAND_NONZERO')
        row['cleanup'] = {'status': 'FAIL', 'category': 'UNCERTAIN_MUTATION'}
        evidence.failure(row, 'CANCELLED', 'FINALIZATION')
        self.assertEqual((row['first_failed_predicate'], row['failure_category']),
                         ('PROVISION_COMMAND', 'COMMAND_NONZERO'))
        self.assertEqual(self.receiver().child_project(row), evidence.project(row))

    def test_complete_late_cancel_preserves_completed_commands_without_claiming_pass(self):
        row = evidence.initial(binding())
        row.update(current_predicate='COMPLETE', commands={name: evidence.exit_record(0) for name in evidence.ACTIONS},
                   cleanup={'status': 'PASS', 'category': 'NONE'})
        evidence.failure(row, 'CANCELLED', 'FINALIZATION')
        self.assertEqual(evidence.project(row)['failure_category'], 'CANCELLED')
        self.assertEqual(row['commands']['candidate'], evidence.exit_record(0))

    def test_exit_codes_are_actual_integers_and_unobserved_is_not_zero(self):
        for code in (True, False, None, 256, -65, '0'):
            with self.subTest(code=code), self.assertRaises(ValueError): evidence.exit_record(code)
        for row in ({'kind': 'EXIT_ZERO', 'code': None}, {'kind': 'UNOBSERVED', 'code': 0},
                    {'kind': 'EXIT_SIGNAL', 'code': 1}, {'kind': 'EXIT_ZERO', 'code': True}):
            with self.subTest(row=row), self.assertRaises(ValueError): evidence.validate_exit(row)
        for code in (-15, 0, 125): self.assertEqual(evidence.validate_exit(evidence.exit_record(code)), evidence.exit_record(code))

    def test_closed_error_categories_never_export_arbitrary_exception_data(self):
        self.assertEqual(evidence.error_category(ValueError('private/secret/path')), 'INVALID_DATA')
        self.assertEqual(evidence.error_category(OSError('token data')), 'IO')
        self.assertEqual(evidence.error_category(ValueError('command-timeout')), 'TIMEOUT')
        self.assertEqual(evidence.error_category(ValueError('deadline-exhausted')), 'DEADLINE')
        self.assertEqual(evidence.error_category(ValueError('output-bound')), 'OUTPUT_BOUND')
        self.assertEqual(evidence.error_category(RuntimeError('secret')), 'UNCLASSIFIED')
        self.assertEqual(evidence.error_category(KeyboardInterrupt()), 'CANCELLED')

    def test_cleanup_categories_preserve_cancel_unknown_mutation_without_raw_errors(self):
        self.assertEqual(evidence.cleanup_category([{'uncertain_commit': True}]), 'UNCERTAIN_MUTATION')
        self.assertEqual(evidence.cleanup_category([{'cancelled': True, 'errors': ['secret']}]), 'CANCELLED')
        self.assertEqual(evidence.cleanup_category([{'status': 'FAIL', 'errors': ['secret/path']}]), 'ABSENCE_UNVERIFIED')

    def test_child_receiver_schema_agreement_on_meaningful_poison_matrix(self):
        receiver = self.receiver()
        changes = [lambda r: r.update(schema_version=True), lambda r: r.update(extra='secret'),
            lambda r: r.update(current_predicate='private/path'), lambda r: r.update(failure_category='secret'),
            lambda r: r['commands']['provision'].update(code=True), lambda r: r['commands'].pop('candidate'),
            lambda r: r['cleanup'].update(status='PASS', category='IO'),
            lambda r: r['cleanup'].update(status='FAIL', category='NONE'),
            lambda r: r['binding'].update(nonce='private nonce'), lambda r: r['binding'].update(run_id='../secret'),
            lambda r: r['binding'].update(run_attempt=True), lambda r: r['binding'].update(source_commit='b' * 64),
            lambda r: r['binding'].update(extra='secret'), lambda r: r.update(commands=[])]
        for change in changes:
            row = evidence.initial(binding()); change(row)
            with self.subTest(change=change):
                with self.assertRaises(ValueError): evidence.project(row)
                with self.assertRaises(ValueError): receiver.child_project(row)
        row = evidence.initial(binding()); row['binding']['source_commit'] = 'x' * 5000
        with self.assertRaises(ValueError): evidence.project(row)
        with self.assertRaises(ValueError): receiver.child_project(row)


if __name__ == '__main__': unittest.main()
