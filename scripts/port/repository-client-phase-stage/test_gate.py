#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""MODELED native lineage, real TEST signing and independent GPG gate rechecks."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_fixture import PhaseFixture, aliases, digest, encoded, ROOT


class GateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='MODELED-native-real-phase-gate-template-')
        try:
            cls.template = PhaseFixture(Path(cls.temporary.name) / 'inputs')
        except BaseException:
            cls.temporary.cleanup()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.template.close()
        cls.temporary.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='MODELED-native-phase-gate-case-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fixture = self.template.clone(self.root)

    def poison_command(self, label, raw, stderr=False):
        module = self.fixture.old_tests
        previous, module.g = module.g, self.fixture.gate
        try:
            module.GateTests.poison_command(self, label, raw, stderr)
        finally:
            module.g = previous

    def test_complete15_real_crypto_preserves_explicit_current_revocation(self):
        result = self.fixture.accept()
        self.assertEqual(result['status'], 'PASS-input-acceptance')
        self.assertEqual(result['crypto_verification'], 'independent-public-key-phase-verification')
        self.assertEqual(result['current_A_authorization'], 'REVOKED')
        self.assertEqual(len(result['lineage']), 15)
        self.assertEqual(result['phase_receipt_sha256'], self.fixture.authority['crypto']['receipt']['sha256'])
        self.assertEqual(result['phase_request_sha256'], self.fixture.authority['crypto']['request']['sha256'])
        self.assertEqual(len(result['archives']), 4)
        self.assertTrue(all(row['snapshot_integrity'] == 'VALID' for row in result['lineage']))
        self.assertEqual(sum(row['terminal_authorization'] == 'REVOKED' for row in result['lineage']), 7)
        self.assertTrue(all(row['certificate_sha256'] in {value['certificate_sha256']
                        for value in result['signer_roles'].values()} for row in result['lineage']))

    def test_frozen_v1_external_flags_acceptance_cannot_enter_successor(self):
        # The v1 gate's data-only authority is demonstrated on its original
        # complete modeled fixture, then refused by schema2 before phase tools.
        with tempfile.TemporaryDirectory(prefix='MODELED-v1-causal-refusal-') as name:
            old = self.fixture.old_tests.Fixture(Path(name))
            self.assertEqual(old.accept()['crypto_verification'], 'external-attestation-only')
            raw = encoded(old.authority)
            with mock.patch.object(self.fixture.phases, 'validate', side_effect=AssertionError('unexpected phase execution')) as verify:
                with self.assertRaises(self.fixture.gate.Refused):
                    self.fixture.gate.accept(old.root, raw, digest(raw), repo_root=ROOT)
            verify.assert_not_called()

    def test_schema2_refuses_v1_crypto_envelope_and_reference_substitution(self):
        original = copy.deepcopy(self.fixture.authority['crypto'])
        for value in ({'purpose': 'external-repository-cryptographic-acceptance', 'status': 'PASS', 'boundary': 'external-attestation-only'},
                      {**original, 'schema_version': 1}, {**original, 'status': 'NOT RUN'},
                      {**original, 'request': {**original['request'], 'sha256': '0' * 64}},
                      {**original, 'receipt': {**original['receipt'], 'bytes': True}}):
            self.fixture.authority['crypto'] = value
            with self.subTest(value=value), self.assertRaises(self.fixture.gate.Refused):
                self.fixture.accept()
        self.fixture.authority['crypto'] = original

    def test_coherent_request_nonce_order_and_map_poison_refused(self):
        original_raw = self.fixture.data[self.fixture.authority['crypto']['request']['path']]
        original_ref = copy.deepcopy(self.fixture.authority['crypto']['request'])
        for mutate in (lambda value: value.update(nonce='0' * 32),
                       lambda value: value['signed_objects'].reverse(),
                       lambda value: value['files'].pop(next(iter(value['files']))),
                       lambda value: value['native_verifications'][0].update(native_phase='unrevoked-B')):
            name = self.fixture.authority['crypto']['request']['path']
            self.fixture.put(name, original_raw)
            self.fixture.authority['crypto']['request'] = copy.deepcopy(original_ref)
            self.fixture.rebind_phase('request', mutate)
            with self.subTest(mutate=mutate), self.assertRaises(self.fixture.gate.Refused):
                self.fixture.accept()

    def test_coherent_phase_receipt_authorization_status_and_source_poison_refused(self):
        original_raw = self.fixture.data[self.fixture.authority['crypto']['receipt']['path']]
        original_ref = copy.deepcopy(self.fixture.authority['crypto']['receipt'])
        for mutate in (lambda value: value.update(current_A_authorization='VALID_AT_OBSERVATION'),
                       lambda value: value['terminal_authorization'][0].update(authorization='VALID_AT_OBSERVATION'),
                       lambda value: value['snapshot_integrity'][0].update(status_sha256='0' * 64),
                       lambda value: value['source_sha256'].update(**{'crypto.py': '0' * 64}),
                       lambda value: value.update(public_only_agent_sockets_absent=False)):
            self.fixture.put(original_ref['path'], original_raw)
            self.fixture.authority['crypto']['receipt'] = copy.deepcopy(original_ref)
            self.fixture.rebind_phase('receipt', mutate)
            with self.subTest(mutate=mutate), self.assertRaises(self.fixture.gate.Refused):
                self.fixture.accept()

    def test_exact_native_gpg_subject_and_command_index_binding(self):
        raw = self.fixture.data[self.fixture.refs['repository']]
        for mutate in (lambda repository: repository['commands'][0]['argv'].__setitem__(-1, '/scratch/repos/unrelated/same-name.pkg.tar.xz'),
                       lambda repository: repository['commands'][0].update(label='unrelated-verify'),
                       lambda repository: repository['commands'][0].update(expected=False)):
            self.fixture.put(self.fixture.refs['repository'], raw)
            self.fixture.change('repository', mutate)
            self.fixture.bind_native()
            self.fixture.project()
            self.fixture.refresh()
            with self.subTest(mutate=mutate), self.assertRaises(self.fixture.gate.Refused):
                self.fixture.accept()

    def test_original_signed_archive_bytes_and_synthetic_metadata_identity(self):
        result = self.fixture.accept()
        metadata = self.fixture.metadata()
        self.assertEqual(metadata['policy']['supported_models'], [])
        self.assertEqual(len(metadata['base']['packages']), 341)
        self.assertEqual(metadata['base']['fixture_scope'], 'FABRICATED-METADATA-NOT-NATIVE')
        self.assertEqual(metadata['acceptance_sha256'], digest(encoded(self.fixture.authority)))
        self.assertTrue(all(row['version'] == '0.1.1-1' for row in result['archives']))
        self.assertEqual({row['name'] for row in result['archives']}, set(self.fixture.old_gate.ORIGINALS))


# Reuse the frozen predecessor's semantic counterexamples against the new gate.
# Index/hardcoded-fingerprint/obsolete-v1-crypto tests are replaced above; all
# included tests exercise preserved native/public predicates without fabrication
# of cryptographic PASS rows or changes to frozen production/test files.
PRESERVED = (
    'test_authority_must_be_externally_pinned', 'test_aggregate_fail_rejects_before_archive_reads',
    'test_actual_initial_purpose_and_all_stages_required', 'test_cancelled_uncertain_or_unobserved_cleanup_aggregate_refused',
    'test_native_guard_exact_caps_privileges_and_scalar_types', 'test_exact_eleven_case_set', 'test_input_drift_refused',
    'test_map_size_boolean_unknown_fields_or_paths_refused', 'test_extra_file_symlink_fifo_and_hardlink_refused',
    'test_parent_symlink_refused', 'test_run_source_and_bootstrap_identity_mismatch',
    'test_projection_cannot_change_an_unknown_field', 'test_raw_projection_hash_binding',
    'test_negative_snapshot_or_transaction_drift', 'test_positive_before_snapshot_must_continue_previous_case',
    'test_initial_payload_absence_and_missing_parent_semantics', 'test_reset_snapshots_must_match_actual_revoked_case',
    'test_reset_command_label_must_be_unique', 'test_raw_command_logs_and_paired_stderr_binding',
    'test_current_ci_operation_protocol_is_accepted_with_identical_copies',
    'test_operation_index_requires_exact_fields_map_and_scalar_types', 'test_operation_public_copies_must_preserve_raw_bytes',
    'test_projection_refs_and_unknown_fields_cannot_be_whitelisted', 'test_operations_require_native_source_pins_and_order',
    'test_positive_inventory_stderr_and_relation_diagnostics_are_exact',
    'test_positive_raw_errors_reject_after_all_hashes_and_projection_rebound',
    'test_negative_raw_diagnostics_require_signature_or_trust_rejection', 'test_missing_database_diagnostic_rejects_generic_near_miss',
    'test_missing_operation_index_is_refused_even_with_projected_fields', 'test_finite_payload_lock_and_base_versions_identity',
    'test_fixture_source_pin_cannot_be_changed_without_lock_binding', 'test_tree_does_not_follow_directory_swap_after_stat',
    'test_tree_scan_stops_at_first_excess_entry', 'test_incomplete_public_export_even_if_resigned_authority',
    'test_probe_cannot_be_returned_as_original', 'test_complete_base_and_owned_absence_required',
    'test_duplicate_and_nonfinite_json_authority_refused', 'test_file_change_after_validation_refused',
)


def preserved(name):
    def test(self):
        module = self.fixture.old_tests
        previous, module.g = module.g, self.fixture.gate
        try:
            getattr(module.GateTests, name)(self)
        finally:
            module.g = previous
    test.__name__ = name
    return test


for name in PRESERVED:
    setattr(GateTests, name, preserved(name))


if __name__ == '__main__':
    unittest.main()
