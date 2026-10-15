# SPDX-License-Identifier: MIT
"""Public projection and inline-bootstrap fixtures; no native execution."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import importlib._bootstrap_external
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location('kernel_job_public', HERE / 'public.py')
public = importlib.util.module_from_spec(spec)
spec.loader.exec_module(public)
WORKFLOW = ROOT / '.github/workflows/native-arm-kernel.yml'
COMMIT, PIN = 'a' * 40, 'b' * 64


def receipt():
    return {'schema_version': 3, 'stage': 'kernel-native-development-job', 'status': 'PASS',
            'phase': 'complete', 'cancelled': False, 'source_commit': COMMIT, 'packet_sha256': PIN,
            'producer': 'PASS', 'kernel_probe': 'PASS', 'baseline': 'PASS', 'candidate': 'PASS',
            'cleanup': 'PASS', 'native_compilation': 'PASS', 'kernel_runtime': 'NOT RUN',
            'hardware': 'NOT RUN', 'installation': 'NOT RUN', 'performance': 'NOT MEASURED',
            'binary_publication': 'NOT RUN', 'selected_for_release': False,
            'first_failed_phase': 'NONE', 'failure_reason': 'NONE',
            'producer_exit': public.exit_record(0), 'acquisition_exit': public.exit_record(0),
            'resources': {name: None for name in public.RESOURCE_KEYS},
            'daemon_baseline': {'initial_container_count': 0, 'initial_image_id_count': 3,
                                'pre_identity_sha256': 'c' * 64, 'post_identity_sha256': 'c' * 64,
                                'preservation': 'PASS', 'owned_absence': 'PASS',
                                'producer_mutation': 'COMPLETE_ACCEPTED',
                                'legacy_build_cache': 'NOT_ESTABLISHED'}}


def initial_baseline():
    return {'initial_container_count': None, 'initial_image_id_count': None,
            'pre_identity_sha256': None, 'post_identity_sha256': None,
            'preservation': 'NOT_RUN', 'owned_absence': 'NOT_RUN',
            'producer_mutation': 'NOT_STARTED', 'legacy_build_cache': 'NOT_ESTABLISHED'}


def encoded(value):
    return json.dumps(value).encode()


def bootstrap():
    workflow = WORKFLOW.read_text()
    code = workflow.split("          /usr/bin/python3 -I -B - <<'PY'\n", 1)[1].split('\n          PY', 1)[0]
    namespace = {'__name__': 'bootstrap_fixture'}
    exec(compile(textwrap.dedent(code), str(WORKFLOW), 'exec'), namespace)
    return namespace


class ProjectionTests(unittest.TestCase):
    def test_complete_success_is_only_pass(self):
        self.assertEqual(public.project(encoded(receipt()), COMMIT, PIN, 'success'), receipt())

    def test_failed_cancelled_skipped_outcome_downgrades_stale_pass(self):
        for outcome in ('failure', 'cancelled', 'skipped', ''):
            with self.subTest(outcome=outcome):
                value = public.project(encoded(receipt()), COMMIT, PIN, outcome)
                self.assertEqual(value['status'], 'FAIL')
                self.assertEqual(value['native_compilation'], 'NOT ACCEPTED')
                self.assertEqual(value['cancelled'], outcome == 'cancelled')
                self.assertEqual(value['first_failed_phase'], 'outcome')
                self.assertEqual(value['failure_reason'], {'failure': 'NATIVE_FAILURE',
                                 'cancelled': 'NATIVE_CANCELLED', 'skipped': 'NATIVE_SKIPPED',
                                 '': 'NATIVE_UNAVAILABLE'}[outcome])
                self.assertEqual(value['producer_exit'], public.exit_record(0))

    def test_each_acceptance_condition_is_required(self):
        changes = {'phase': 'kernel', 'cancelled': True, 'producer': 'FAIL', 'kernel_probe': 'NOT RUN',
                   'baseline': 'FAIL', 'candidate': 'NOT RUN', 'cleanup': 'FAIL', 'native_compilation': 'NOT ACCEPTED'}
        for key, value in changes.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                record = receipt(); record[key] = value
                public.project(encoded(record), COMMIT, PIN, 'success')

    def test_initial_fail_has_no_fabricated_execution(self):
        value = receipt(); value.update(status='FAIL', phase='preflight', cleanup='FAIL', native_compilation='NOT RUN')
        value.update({key: 'NOT RUN' for key in public.CHILDREN})
        value.update({key: {'kind': 'NOT_RUN', 'code': None} for key in ('producer_exit', 'acquisition_exit')})
        value['daemon_baseline'] = initial_baseline()
        result = public.project(encoded(value), COMMIT, PIN, 'failure')
        public.record_failure(value, 'outcome', 'NATIVE_FAILURE')
        self.assertEqual(result, value)

    def test_failed_receipt_keeps_recorded_children_but_revokes_compilation(self):
        value = receipt(); value.update(status='FAIL', phase='cleanup', cleanup='FAIL')
        result = public.project(encoded(value), COMMIT, PIN, 'success')
        self.assertEqual(result['baseline'], 'PASS')
        self.assertEqual(result['native_compilation'], 'NOT ACCEPTED')

    def test_wrong_identity_unknown_keys_and_nonfinite_values_refused(self):
        changes = {'source_commit': 'c' * 40, 'packet_sha256': 'c' * 64, 'error': 'SECRET', 'status': 'SECRET',
                   'hardware': 'PASS', 'installation': 'PASS', 'kernel_runtime': 'PASS',
                   'performance': 'PASS', 'binary_publication': 'PASS', 'selected_for_release': 0,
                   'schema_version': True, 'cancelled': 0, 'stage': 'SECRET', 'producer': 'SECRET'}
        for key, value in changes.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                record = receipt(); record[key] = value
                public.project(encoded(record), COMMIT, PIN, 'success')

    def test_duplicate_json_and_constants_refused(self):
        data = encoded(receipt())
        for bad in (data[:-1] + b',"status":"PASS"}', b'{"x": NaN}', b'[]'):
            with self.subTest(data=bad), self.assertRaises(ValueError):
                public.project(bad, COMMIT, PIN, 'success')

    def test_size_bound(self):
        with self.assertRaises(ValueError):
            public.project(b' ' * (public.MAX_BYTES + 1), COMMIT, PIN, 'success')

    def test_decode_uses_only_supplied_captured_bytes(self):
        data = encoded(receipt())
        with patch.object(public, 'read', side_effect=AssertionError('second read')):
            self.assertEqual(public.project(data, COMMIT, PIN, 'success')['status'], 'PASS')


class DiagnosticTests(unittest.TestCase):
    def failed(self):
        value = receipt()
        public.record_failure(value, 'parallel', 'PRODUCER_EXIT')
        value.update(phase='cleanup', producer='FAIL', cleanup='FAIL')
        value['producer_exit'] = public.exit_record(1)
        value['daemon_baseline']['producer_mutation'] = 'UNCERTAIN'
        return value

    def refuse(self, value):
        with self.assertRaises(ValueError):
            public.project(encoded(value), COMMIT, PIN, 'success')

    def test_exact_schema_requires_every_diagnostic_field(self):
        for key in ('first_failed_phase', 'failure_reason', 'producer_exit', 'acquisition_exit', 'resources',
                    'daemon_baseline'):
            with self.subTest(key=key):
                value = receipt(); del value[key]; self.refuse(value)
        value = receipt(); value['schema_version'] = 1; self.refuse(value)
        value = receipt(); value['schema_version'] = 2; self.refuse(value)

    def test_failure_phase_and_reason_are_closed_related_enums(self):
        for phase, reason in (('PRIVATE PATH', 'CANCELLED'), ('parallel', 'SECRET ERROR'),
                              ('parallel', 'CLEANUP_FAILED'), ('NONE', 'CANCELLED'),
                              ('cleanup', 'NONE'), ([], 'CANCELLED'), ('parallel', {})):
            with self.subTest(phase=phase, reason=reason):
                value = self.failed()
                value.update(first_failed_phase=phase, failure_reason=reason)
                self.refuse(value)

    def test_all_declared_failure_pairs_are_valid(self):
        for phase, reasons in public.REASONS.items():
            for reason in reasons:
                with self.subTest(phase=phase, reason=reason):
                    value = receipt(); value.update(status='FAIL', first_failed_phase=phase, failure_reason=reason)
                    if phase == 'parallel':
                        if reason in {'PRODUCER_EXIT', 'BOTH_CHILDREN_EXIT'}:
                            value['producer_exit'] = public.exit_record(1)
                            value.update(cleanup='FAIL', producer='FAIL')
                            value['daemon_baseline']['producer_mutation'] = 'UNCERTAIN'
                        if reason in {'ACQUISITION_EXIT', 'BOTH_CHILDREN_EXIT'}:
                            value['acquisition_exit'] = public.exit_record(-15)
                    if phase == 'source' and reason in {'DAEMON_CONTAINERS_PRESENT', 'DAEMON_BASELINE_UNVERIFIED'}:
                        value.update(cleanup='FAIL', producer='NOT RUN',
                                     producer_exit={'kind': 'NOT_RUN', 'code': None}, daemon_baseline=initial_baseline())
                        value['daemon_baseline']['preservation'] = 'UNVERIFIED'
                        if reason == 'DAEMON_CONTAINERS_PRESENT': value['daemon_baseline']['initial_container_count'] = 1
                    if phase == 'producer' and reason == 'PRODUCER_BASELINE_ID_COLLISION':
                        value.update(cleanup='FAIL', producer='FAIL')
                        value['daemon_baseline']['producer_mutation'] = 'COMPLETE_REJECTED'
                    projected = public.project(encoded(value), COMMIT, PIN, 'success')
                    self.assertEqual((projected['first_failed_phase'], projected['failure_reason']), (phase, reason))

    def test_record_failure_preserves_first_cause_across_cleanup_and_cancel(self):
        value = self.failed()
        public.record_failure(value, 'cleanup', 'CLEANUP_FAILED')
        public.record_failure(value, 'finalization', 'CANCELLED')
        self.assertEqual(value['status'], 'FAIL')
        self.assertEqual((value['first_failed_phase'], value['failure_reason']), ('parallel', 'PRODUCER_EXIT'))
        before = copy.deepcopy(value)
        with self.assertRaises(ValueError): public.record_failure(value, 'cleanup', 'PRODUCER_EXIT')
        self.assertEqual(value, before)

    def test_outcome_keeps_first_cause_and_observed_children(self):
        original = self.failed()
        original['failure_reason'] = 'PARALLEL_RUN_FAILED'
        original['acquisition_exit'] = {'kind': 'UNOBSERVED', 'code': None}
        for outcome in ('success', 'failure', 'cancelled', 'skipped', ''):
            with self.subTest(outcome=outcome):
                value = public.project(encoded(original), COMMIT, PIN, outcome)
                self.assertEqual((value['first_failed_phase'], value['failure_reason']), ('parallel', 'PARALLEL_RUN_FAILED'))
                self.assertEqual(value['producer_exit'], original['producer_exit'])
                self.assertEqual(value['acquisition_exit'], original['acquisition_exit'])
                self.assertEqual(value['cancelled'], outcome == 'cancelled')

    def test_pending_receipt_outcome_never_invents_child_codes(self):
        value = receipt(); value.update(status='FAIL', phase='preflight', native_compilation='NOT RUN')
        value['cleanup'] = 'FAIL'; value['daemon_baseline'] = initial_baseline()
        value.update({key: 'NOT RUN' for key in public.CHILDREN})
        value.update({key: {'kind': 'NOT_RUN', 'code': None} for key in ('producer_exit', 'acquisition_exit')})
        projected = public.project(encoded(value), COMMIT, PIN, 'cancelled')
        self.assertTrue(projected['cancelled'])
        self.assertEqual(projected['failure_reason'], 'NATIVE_CANCELLED')
        self.assertEqual(projected['producer_exit'], value['producer_exit'])

    def test_cancelled_receipt_requires_an_observed_primary_cause(self):
        value = receipt(); value.update(status='FAIL', cancelled=True)
        self.refuse(value)
        public.record_failure(value, 'kernel', 'CANCELLED')
        self.assertTrue(public.project(encoded(value), COMMIT, PIN, 'success')['cancelled'])

    def test_stale_pass_with_diagnostic_failure_is_refused(self):
        for field, replacement in (('first_failed_phase', 'parallel'), ('producer_exit', public.exit_record(1)),
                                   ('acquisition_exit', {'kind': 'UNOBSERVED', 'code': None})):
            with self.subTest(field=field):
                value = receipt(); value[field] = replacement
                if field == 'first_failed_phase': value['failure_reason'] = 'PRODUCER_EXIT'
                self.refuse(value)

    def test_exit_record_exact_numeric_boundaries_and_classification(self):
        for code, kind in ((-64, 'EXIT_SIGNAL'), (-1, 'EXIT_SIGNAL'), (0, 'EXIT_ZERO'),
                           (1, 'EXIT_NONZERO'), (255, 'EXIT_NONZERO')):
            with self.subTest(code=code):
                self.assertEqual(public.exit_record(code), {'kind': kind, 'code': code})
        for code in (-65, 256, True, False, 1.0, '1', None, [], {}):
            with self.subTest(code=code), self.assertRaises(ValueError): public.exit_record(code)

    def test_exit_records_refuse_unknown_shape_and_kind_code_mismatch(self):
        rows = [{'kind': 'NOT_RUN', 'code': 0}, {'kind': 'UNOBSERVED', 'code': 1},
                {'kind': 'EXIT_ZERO', 'code': -1}, {'kind': 'EXIT_ZERO', 'code': False},
                {'kind': 'EXIT_NONZERO', 'code': 0}, {'kind': 'EXIT_SIGNAL', 'code': 143},
                {'kind': 'EXIT_SIGNAL', 'code': -65}, {'kind': 'EXIT_NONZERO', 'code': 256},
                {'kind': 'EXIT_NONZERO', 'code': 1.0}, {'kind': 'EXIT_NONZERO', 'code': '1'},
                {'kind': 'SECRET', 'code': 1}, {'kind': [], 'code': 1},
                {'kind': 'EXIT_ZERO'}, {'kind': 'EXIT_ZERO', 'code': 0, 'stderr': 'SECRET'}, []]
        for name in ('producer_exit', 'acquisition_exit'):
            for row in rows:
                with self.subTest(name=name, row=row):
                    value = self.failed(); value[name] = row; self.refuse(value)

    def test_parallel_exit_reasons_require_matching_observed_children(self):
        choices = (public.exit_record(0), public.exit_record(1), public.exit_record(-15),
                   {'kind': 'NOT_RUN', 'code': None}, {'kind': 'UNOBSERVED', 'code': None})
        expected = {'PRODUCER_EXIT': (True, False), 'ACQUISITION_EXIT': (False, True),
                    'BOTH_CHILDREN_EXIT': (True, True)}
        for reason, pair in expected.items():
            for producer in choices:
                for acquisition in choices:
                    with self.subTest(reason=reason, producer=producer, acquisition=acquisition):
                        value = self.failed(); value['failure_reason'] = reason
                        value['producer_exit'], value['acquisition_exit'] = producer, acquisition
                        observed = (producer['code'], acquisition['code'])
                        valid = all(type(code) is int and (code != 0) == failed
                                    for code, failed in zip(observed, pair))
                        if valid:
                            self.assertEqual(public.project(encoded(value), COMMIT, PIN, 'success')['failure_reason'], reason)
                        else:
                            self.refuse(value)

    def test_observed_failed_child_requires_first_cause(self):
        for name in ('producer_exit', 'acquisition_exit'):
            for code in (1, -15):
                value = receipt(); value['status'] = 'FAIL'; value[name] = public.exit_record(code)
                with self.subTest(name=name, code=code): self.refuse(value)

    def test_cancelled_cause_allows_already_observed_child_results(self):
        value = receipt(); public.record_failure(value, 'parallel', 'CANCELLED')
        value['cancelled'] = True; value['producer_exit'] = public.exit_record(-15)
        value.update(cleanup='FAIL', producer='FAIL'); value['daemon_baseline']['producer_mutation'] = 'UNCERTAIN'
        result = public.project(encoded(value), COMMIT, PIN, 'cancelled')
        self.assertEqual(result['producer_exit'], public.exit_record(-15))
        self.assertEqual(result['failure_reason'], 'CANCELLED')

    def test_resources_require_exact_keys_and_bounded_integers(self):
        for number in (None, 0, 2**60):
            value = receipt(); value['resources'] = dict.fromkeys(public.RESOURCE_KEYS, number)
            self.assertEqual(public.project(encoded(value), COMMIT, PIN, 'success')['resources'], value['resources'])
        for number in (-1, 2**60 + 1, True, False, 0.0, '0', [], {}):
            value = receipt(); value['resources']['mem_total_bytes'] = number
            with self.subTest(number=number): self.refuse(value)
        for resources in ({}, [], {**receipt()['resources'], 'path': 'SECRET'}):
            value = receipt(); value['resources'] = resources; self.refuse(value)

    def test_nested_duplicate_diagnostics_are_refused(self):
        raw = encoded(receipt())
        for needle, replacement in ((b'"kind": "EXIT_ZERO"', b'"kind": "EXIT_ZERO", "kind": "SECRET"'),
                                    (b'"mem_total_bytes": null', b'"mem_total_bytes": null, "mem_total_bytes": 0')):
            with self.subTest(needle=needle), self.assertRaises(ValueError):
                public.project(raw.replace(needle, replacement, 1), COMMIT, PIN, 'success')


class DaemonBaselineTests(unittest.TestCase):
    def project(self, row, outcome='success', **changes):
        value = receipt(); value.update(changes); value['daemon_baseline'] = row
        return public.project(encoded(value), COMMIT, PIN, outcome)

    def refuse(self, row, **changes):
        with self.assertRaises(ValueError): self.project(row, **changes)

    def test_exact_summary_shape_and_no_raw_metadata(self):
        row = receipt()['daemon_baseline']
        for key in public.DAEMON_BASELINE_KEYS:
            poisoned = row.copy(); del poisoned[key]
            with self.subTest(missing=key): self.refuse(poisoned)
        for key in ('Config', 'RepoTags', 'path', 'images', 'daemon_id', 'error'):
            poisoned = row.copy(); poisoned[key] = 'PRIVATE TOKEN'
            with self.subTest(extra=key): self.refuse(poisoned)
        for row in (None, [], 'PRIVATE TOKEN'):
            self.refuse(row)

    def test_initial_unobserved_summary_preserves_nulls(self):
        value = receipt(); value.update(status='FAIL', phase='preflight', cleanup='FAIL',
                                         native_compilation='NOT RUN', daemon_baseline=initial_baseline())
        value.update({key: 'NOT RUN' for key in public.CHILDREN})
        value.update({key: {'kind': 'NOT_RUN', 'code': None} for key in ('producer_exit', 'acquisition_exit')})
        result = public.project(encoded(value), COMMIT, PIN, 'failure')
        self.assertEqual(result['daemon_baseline'], initial_baseline())
        self.assertIsNone(result['daemon_baseline']['initial_container_count'])
        self.assertIsNone(result['daemon_baseline']['initial_image_id_count'])

    def test_positive_empty_baseline_is_distinct_from_unobserved(self):
        row = receipt()['daemon_baseline']; row['initial_image_id_count'] = 0
        value = self.project(row)
        self.assertEqual(value['status'], 'PASS')
        self.assertEqual(value['daemon_baseline']['initial_image_id_count'], 0)
        self.assertIsNotNone(value['daemon_baseline']['pre_identity_sha256'])

    def test_image_count_accepts_exact_boundary_and_refuses_numeric_poison(self):
        for count in (0, 256):
            row = receipt()['daemon_baseline']; row['initial_image_id_count'] = count
            self.assertEqual(self.project(row)['status'], 'PASS')
        for key in ('initial_container_count', 'initial_image_id_count'):
            for count in (-1, 257, False, True, 0.0, '0', [], {}):
                row = receipt()['daemon_baseline']; row[key] = count
                with self.subTest(key=key, count=count): self.refuse(row)

    def test_initial_presence_never_accepts_preservation_or_cleanup_pass(self):
        for count in (1, 256, None):
            row = receipt()['daemon_baseline']; row['initial_container_count'] = count
            with self.subTest(count=count): self.refuse(row)
        row = initial_baseline(); row.update(initial_container_count=1, initial_image_id_count=4,
                                              preservation='UNVERIFIED')
        value = self.project(row, 'failure', status='FAIL', cleanup='FAIL', producer='NOT RUN',
                             producer_exit={'kind': 'NOT_RUN', 'code': None},
                             first_failed_phase='source', failure_reason='DAEMON_CONTAINERS_PRESENT')
        self.assertEqual(value['daemon_baseline']['initial_container_count'], 1)
        self.assertIsNone(value['daemon_baseline']['pre_identity_sha256'])

    def test_query_failure_never_synthesizes_zero_or_digest(self):
        row = initial_baseline(); row['preservation'] = 'UNVERIFIED'
        value = self.project(row, 'failure', status='FAIL', cleanup='FAIL', producer='NOT RUN',
                             producer_exit={'kind': 'NOT_RUN', 'code': None},
                             first_failed_phase='source', failure_reason='DAEMON_BASELINE_UNVERIFIED')
        self.assertEqual(value['daemon_baseline'], row)
        for key in ('initial_container_count', 'initial_image_id_count'):
            poisoned = receipt()['daemon_baseline']; poisoned[key] = None
            self.refuse(poisoned)

    def test_initial_presence_reason_requires_positive_observation(self):
        for count in (None, 0):
            row = initial_baseline(); row.update(initial_container_count=count, preservation='UNVERIFIED')
            with self.subTest(count=count):
                self.refuse(row, status='FAIL', cleanup='FAIL', producer='NOT RUN',
                            producer_exit={'kind': 'NOT_RUN', 'code': None},
                            first_failed_phase='source', failure_reason='DAEMON_CONTAINERS_PRESENT')

    def test_initial_query_failure_reason_cannot_claim_preservation_pass(self):
        self.refuse(receipt()['daemon_baseline'], status='FAIL', cleanup='FAIL',
                    first_failed_phase='source', failure_reason='DAEMON_BASELINE_UNVERIFIED')

    def test_borrowed_iid_collision_cannot_claim_accepted_or_unknown_mutation(self):
        for mutation in ('COMPLETE_ACCEPTED', 'UNCERTAIN', 'NOT_STARTED'):
            row = receipt()['daemon_baseline']; row['producer_mutation'] = mutation
            with self.subTest(mutation=mutation):
                self.refuse(row, status='FAIL', cleanup='FAIL', first_failed_phase='producer',
                            failure_reason='PRODUCER_BASELINE_ID_COLLISION')
        row = receipt()['daemon_baseline']; row['producer_mutation'] = 'COMPLETE_REJECTED'
        value = self.project(row, 'failure', status='FAIL', cleanup='FAIL', producer='FAIL',
                             first_failed_phase='producer', failure_reason='PRODUCER_BASELINE_ID_COLLISION')
        self.assertEqual(value['daemon_baseline']['producer_mutation'], 'COMPLETE_REJECTED')
        self.refuse(row, status='FAIL', cleanup='FAIL', producer_exit={'kind': 'UNOBSERVED', 'code': None},
                    first_failed_phase='producer', failure_reason='PRODUCER_BASELINE_ID_COLLISION')

    def test_digest_grammar_and_missing_observation_are_refused(self):
        for key in ('pre_identity_sha256', 'post_identity_sha256'):
            for digest in (None, '', 'c' * 63, 'c' * 65, 'C' * 64, 'g' * 64,
                           'sha256:' + 'c' * 64, True, 0, [], {}):
                row = receipt()['daemon_baseline']; row[key] = digest
                with self.subTest(key=key, digest=digest): self.refuse(row)

    def test_positive_changed_projection_is_fail_not_unverified(self):
        row = receipt()['daemon_baseline']; row['post_identity_sha256'] = 'd' * 64
        self.refuse(row)
        row['preservation'] = 'FAIL'
        value = self.project(row, 'failure', status='FAIL', cleanup='FAIL',
                             first_failed_phase='cleanup', failure_reason='DAEMON_BASELINE_CHANGED')
        self.assertEqual(value['daemon_baseline']['preservation'], 'FAIL')
        for state in ('NOT_RUN', 'UNVERIFIED'):
            row['preservation'] = state
            with self.subTest(state=state): self.refuse(row, status='FAIL', cleanup='FAIL')

    def test_equal_projection_cannot_claim_positive_changed_failure(self):
        row = receipt()['daemon_baseline']; row['preservation'] = 'FAIL'
        self.refuse(row, status='FAIL', cleanup='FAIL')

    def test_unknown_final_observation_is_not_a_pre_kernel_digest(self):
        row = receipt()['daemon_baseline']; row.update(post_identity_sha256=None, preservation='UNVERIFIED')
        value = self.project(row, 'failure', status='FAIL', cleanup='FAIL',
                             first_failed_phase='cleanup', failure_reason='DAEMON_BASELINE_UNVERIFIED')
        self.assertIsNone(value['daemon_baseline']['post_identity_sha256'])
        self.assertIsNotNone(value['daemon_baseline']['pre_identity_sha256'])
        self.refuse(row)

    def test_closed_summary_enums_and_cache_claim(self):
        for key in ('preservation', 'owned_absence', 'producer_mutation', 'legacy_build_cache'):
            for item in ('SECRET', '', True, 0, [], {}):
                row = receipt()['daemon_baseline']; row[key] = item
                with self.subTest(key=key, item=item): self.refuse(row)
        row = receipt()['daemon_baseline']; row['legacy_build_cache'] = 'PASS'; self.refuse(row)

    def test_uncertain_or_rejected_producer_never_cleanup_pass(self):
        for mutation in ('UNCERTAIN', 'COMPLETE_REJECTED', 'NOT_STARTED'):
            row = receipt()['daemon_baseline']; row['producer_mutation'] = mutation
            changes = ({'producer': 'NOT RUN', 'producer_exit': {'kind': 'NOT_RUN', 'code': None}}
                       if mutation == 'NOT_STARTED' else {'producer': 'FAIL'})
            with self.subTest(mutation=mutation):
                self.refuse(row, status='FAIL', **changes)
                value = self.project(row, 'failure', status='FAIL', cleanup='FAIL',
                                     first_failed_phase='cleanup', failure_reason='CLEANUP_FAILED', **changes)
                self.assertEqual(value['daemon_baseline']['producer_mutation'], mutation)

    def test_not_started_mutation_cannot_hide_observed_producer(self):
        row = receipt()['daemon_baseline']; row['producer_mutation'] = 'NOT_STARTED'
        self.refuse(row, status='FAIL', cleanup='FAIL')
        self.refuse(row, status='FAIL', cleanup='FAIL', producer='NOT RUN')

    def test_complete_rejected_requires_zero_exit_and_failed_acceptance(self):
        row = receipt()['daemon_baseline']; row['producer_mutation'] = 'COMPLETE_REJECTED'
        for producer in ('PASS', 'NOT RUN'):
            with self.subTest(producer=producer):
                self.refuse(row, status='FAIL', cleanup='FAIL', producer=producer)
        for result in ({'kind': 'NOT_RUN', 'code': None}, {'kind': 'UNOBSERVED', 'code': None},
                       public.exit_record(1), public.exit_record(-15)):
            with self.subTest(result=result):
                self.refuse(row, status='FAIL', cleanup='FAIL', producer='FAIL', producer_exit=result,
                            first_failed_phase='producer', failure_reason='PRODUCER_RECEIPT_REJECTED')
        value = self.project(row, 'failure', status='FAIL', cleanup='FAIL', producer='FAIL',
                             first_failed_phase='producer', failure_reason='PRODUCER_RECEIPT_REJECTED')
        self.assertEqual(value['producer_exit'], public.exit_record(0))
        self.assertEqual(value['daemon_baseline']['producer_mutation'], 'COMPLETE_REJECTED')

    def test_uncertain_mutation_rejects_fabricated_producer_pass(self):
        row = receipt()['daemon_baseline']; row['producer_mutation'] = 'UNCERTAIN'
        self.refuse(row, status='FAIL', cleanup='FAIL', first_failed_phase='parallel',
                    failure_reason='PARALLEL_RUN_FAILED')
        for producer in ('FAIL', 'NOT RUN'):
            result = self.project(row, 'failure', status='FAIL', cleanup='FAIL', producer=producer,
                                  first_failed_phase='parallel', failure_reason='PARALLEL_RUN_FAILED')
            self.assertEqual(result['daemon_baseline']['producer_mutation'], 'UNCERTAIN')

    def test_owned_absence_required_separately_from_preservation(self):
        for absence in ('FAIL', 'UNVERIFIED', 'NOT_RUN'):
            row = receipt()['daemon_baseline']; row['owned_absence'] = absence
            with self.subTest(absence=absence):
                self.refuse(row, status='FAIL')
                self.assertEqual(self.project(row, 'failure', status='FAIL', cleanup='FAIL',
                                 first_failed_phase='cleanup', failure_reason='OWNED_ABSENCE_UNVERIFIED')
                                 ['daemon_baseline']['owned_absence'], absence)

    def test_complete_accepted_producer_needs_receipt_and_zero_exit(self):
        row = receipt()['daemon_baseline']
        self.refuse(row, status='FAIL', cleanup='FAIL', producer='FAIL')
        self.refuse(row, status='FAIL', cleanup='FAIL', producer_exit={'kind': 'UNOBSERVED', 'code': None})
        self.refuse(row, status='FAIL', cleanup='FAIL', producer_exit=public.exit_record(-15),
                    first_failed_phase='parallel', failure_reason='CANCELLED')

    def test_outcome_downgrade_preserves_positive_baseline_without_cache_claim(self):
        row = receipt()['daemon_baseline']
        for outcome in ('failure', 'cancelled', 'skipped', ''):
            value = self.project(row, outcome)
            self.assertEqual(value['status'], 'FAIL')
            self.assertEqual(value['daemon_baseline'], row)
            self.assertEqual(value['daemon_baseline']['legacy_build_cache'], 'NOT_ESTABLISHED')

    def test_baseline_failure_does_not_replace_earlier_parallel_cause(self):
        value = receipt(); value.update(status='FAIL', cleanup='FAIL', producer='FAIL')
        public.record_failure(value, 'parallel', 'PARALLEL_TIMEOUT')
        value['daemon_baseline'].update(producer_mutation='UNCERTAIN', preservation='UNVERIFIED',
                                         owned_absence='UNVERIFIED', post_identity_sha256=None)
        public.record_failure(value, 'cleanup', 'DAEMON_BASELINE_UNVERIFIED')
        projected = public.project(encoded(value), COMMIT, PIN, 'cancelled')
        self.assertEqual(projected['first_failed_phase'], 'parallel')
        self.assertEqual(projected['failure_reason'], 'PARALLEL_TIMEOUT')
        self.assertEqual(projected['daemon_baseline']['producer_mutation'], 'UNCERTAIN')

    def test_nested_baseline_duplicate_refused(self):
        raw = encoded(receipt()).replace(b'"preservation": "PASS"',
                                         b'"preservation": "PASS", "preservation": "UNVERIFIED"', 1)
        with self.assertRaises(ValueError): public.project(raw, COMMIT, PIN, 'success')


class FileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.path = self.base / 'status.json'

    def call(self, outcome='success'):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = public.main(['--status', str(self.path), '--source-commit', COMMIT,
                                '--packet-sha256', PIN, '--native-outcome', outcome])
        return code, output.getvalue()

    def test_missing_receipt_fixed_marker(self):
        self.assertEqual(self.call(), (1, 'KERNEL_PUBLIC_RECEIPT_MISSING\n'))

    def test_valid_receipt_emits_one_bounded_record(self):
        self.path.write_bytes(encoded(receipt()))
        code, data = self.call()
        self.assertEqual(code, 0); self.assertEqual(json.loads(data), receipt())
        self.assertEqual(data.count('\n'), 1); self.assertLess(len(data), public.MAX_BYTES)

    def test_successful_process_with_failed_receipt_returns_failure(self):
        value = receipt(); value['status'] = 'FAIL'
        self.path.write_bytes(encoded(value))
        code, data = self.call(); self.assertEqual(code, 1)
        self.assertEqual(json.loads(data)['status'], 'FAIL')

    def test_unknown_data_never_reaches_output(self):
        self.path.write_text('{"secret":"PRIVATE TOKEN"}')
        self.assertEqual(self.call(), (1, 'KERNEL_PUBLIC_EVIDENCE_REFUSED\n'))

    def test_diagnostic_poison_never_reaches_output(self):
        value = receipt(); value['failure_reason'] = 'PRIVATE PATH TOKEN STDERR'
        self.path.write_bytes(encoded(value))
        self.assertEqual(self.call(), (1, 'KERNEL_PUBLIC_EVIDENCE_REFUSED\n'))

    def test_failed_diagnostic_emits_one_bounded_record(self):
        value = receipt(); public.record_failure(value, 'parallel', 'BOTH_CHILDREN_EXIT')
        value.update(phase='cleanup', producer='FAIL', cleanup='FAIL')
        value['daemon_baseline']['producer_mutation'] = 'UNCERTAIN'
        value['producer_exit'], value['acquisition_exit'] = public.exit_record(255), public.exit_record(-64)
        value['resources'] = dict.fromkeys(public.RESOURCE_KEYS, 2**60)
        self.path.write_bytes(encoded(value))
        code, data = self.call('failure')
        self.assertEqual(code, 0); self.assertEqual(data.count('\n'), 1)
        self.assertLess(len(data), public.MAX_BYTES)
        projected = json.loads(data)
        self.assertEqual(projected['failure_reason'], 'BOTH_CHILDREN_EXIT')
        self.assertEqual(projected['producer_exit'], value['producer_exit'])

    def test_symlink_hardlink_fifo_and_directory_refused(self):
        target = self.base / 'target'; target.write_bytes(encoded(receipt()))
        for shape in ('symlink', 'hardlink', 'fifo', 'directory'):
            with self.subTest(shape=shape):
                if shape == 'symlink': self.path.symlink_to(target)
                elif shape == 'hardlink': os.link(target, self.path)
                elif shape == 'fifo': os.mkfifo(self.path)
                else: self.path.mkdir()
                self.assertEqual(self.call(), (1, 'KERNEL_PUBLIC_EVIDENCE_REFUSED\n'))
                if self.path.is_dir(): self.path.rmdir()
                else: self.path.unlink()

    def test_parent_symlink_refused(self):
        self.path.write_bytes(encoded(receipt()))
        linked = self.base / 'link'; linked.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(ValueError): public.read(linked / self.path.name)

    def test_file_replacement_after_fd_capture_refused(self):
        self.path.write_bytes(encoded(receipt()))
        original = os.fstat; calls = 0
        def swapped(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.path.unlink(); self.path.write_text('SECRET')
            return original(fd)
        with patch.object(public.os, 'fstat', side_effect=swapped), self.assertRaises(ValueError):
            public.read(self.path)


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'source'; self.root.mkdir()
        self.ns = bootstrap()
        fixture_files = self.ns['REQUIRED'] | {'scripts/port/kernel-native-job/current_cache.py'}
        for name in fixture_files:
            path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / name).read_bytes() if name in
                            {self.ns['PUBLIC'], self.ns['JOB'], 'scripts/port/kernel-native-job/packet.py',
                             'scripts/port/kernel-native-job/runtime.py',
                             'scripts/port/kernel-native-job/current_cache.py'} else
                             (name + '\n').encode())
            path.chmod(0o755 if name == self.ns['JOB'] else 0o644)
        self.rows = {name: {'bytes': len((self.root / name).read_bytes()),
                    'sha256': hashlib.sha256((self.root / name).read_bytes()).hexdigest(),
                    'mode': stat.S_IMODE((self.root / name).stat().st_mode)} for name in fixture_files}
        self.packet = self.root / self.ns['PACKET']
        self.write_packet()
        self.git('init', '-q'); self.git('add', '.')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-q', '-m', 'fixture')
        self.commit = self.git('rev-parse', 'HEAD').strip()
        self.environment = patch.dict(os.environ, {'RUNNER_TEMP': self.temp.name, 'GITHUB_WORKFLOW_SHA': self.commit})
        self.environment.start(); self.addCleanup(self.environment.stop)

    def git(self, *args):
        env = {'PATH': '/usr/bin:/bin', 'HOME': self.temp.name, 'GIT_CONFIG_NOSYSTEM': '1',
               'GIT_CONFIG_GLOBAL': '/dev/null', 'LANG': 'C.UTF-8'}
        return subprocess.run(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-C', str(self.root), *args],
                              env=env, capture_output=True, timeout=10, check=True).stdout.decode()

    def write_packet(self, raw=None):
        self.packet.write_bytes(raw if raw is not None else encoded({'schema_version': 1, 'files': self.rows}))
        self.packet.chmod(0o644)
        self.pin = hashlib.sha256(self.packet.read_bytes()).hexdigest()

    def source(self):
        return self.ns['source'](self.root, self.commit, self.pin)

    def test_real_git_blob_mode_and_full_capture_pass(self):
        captured = self.source()
        self.assertEqual(set(captured), set(self.rows))
        self.assertEqual(captured[self.ns['PUBLIC']], (self.root / self.ns['PUBLIC']).read_bytes())

    def test_live_source_byte_and_mode_changes_refused(self):
        path = self.root / self.ns['PUBLIC']; data = path.read_bytes()
        path.write_text('changed')
        with self.assertRaises(ValueError): self.source()
        path.write_bytes(data); path.chmod(0o755)
        with self.assertRaises(ValueError): self.source()

    def test_packet_external_pin_and_committed_blob_required(self):
        pin = self.pin; self.pin = '0' * 64
        with self.assertRaises(ValueError): self.source()
        self.pin = pin; self.write_packet(self.packet.read_bytes() + b'\n')
        with self.assertRaises(ValueError): self.source()

    def test_head_and_workflow_commit_are_required(self):
        self.commit = '0' * 40
        with self.assertRaises(ValueError): self.source()
        self.commit = self.git('rev-parse', 'HEAD').strip()
        with patch.dict(os.environ, {'GITHUB_WORKFLOW_SHA': '0' * 40}), self.assertRaises(ValueError): self.source()

    def test_symlink_and_hardlink_rows_refused(self):
        path = self.root / self.ns['PUBLIC']; data = path.read_bytes()
        other = self.root / 'other'; other.write_bytes(data)
        path.unlink(); path.symlink_to(other)
        with self.assertRaises(ValueError): self.source()
        path.unlink(); os.link(other, path)
        with self.assertRaises(ValueError): self.source()

    def test_packet_schema_path_budget_and_required_rows_refused(self):
        original = self.ns['committed']
        self.ns['committed'] = lambda *args: None
        variants = []
        rows = copy.deepcopy(self.rows); rows.pop(self.ns['JOB']); variants.append(rows)
        for bad in ('../escape', '/absolute', 'a//b', 'a/./b', 'a\\b', 'a\nb'):
            rows = copy.deepcopy(self.rows); rows[bad] = next(iter(rows.values())); variants.append(rows)
        for changes in ({'mode': True}, {'mode': 0o777}, {'bytes': True}, {'bytes': 8 * 1024**2 + 1}, {'sha256': 'invalid'}):
            rows = copy.deepcopy(self.rows); rows[self.ns['PUBLIC']].update(changes); variants.append(rows)
        rows = copy.deepcopy(self.rows); rows.update({f'extra/{n}': next(iter(rows.values())) for n in range(257)}); variants.append(rows)
        try:
            for rows in variants:
                with self.subTest(rows=len(rows)), self.assertRaises(ValueError):
                    self.rows = rows; self.write_packet(); self.source()
        finally:
            self.ns['committed'] = original

    def test_duplicate_packet_json_refused(self):
        self.ns['committed'] = lambda *args: None
        raw = encoded({'schema_version': 1, 'files': self.rows})
        self.write_packet(raw[:-1] + b',"schema_version":1}')
        with self.assertRaises(ValueError): self.source()

    def test_captured_public_bytes_survive_later_path_replacement(self):
        captured = self.source(); path = self.root / self.ns['PUBLIC']
        path.write_text('UNTRUSTED REPLACEMENT')
        self.assertNotIn(b'UNTRUSTED', captured[self.ns['PUBLIC']])

    def test_inline_public_executes_authenticated_capture_end_to_end(self):
        target = self.root / 'artifacts/kernel-native-job/job-123-1/public/status.json'
        target.parent.mkdir(parents=True)
        value = receipt(); value.update(source_commit=self.commit, packet_sha256=self.pin)
        target.write_bytes(encoded(value))
        environment = {'KERNEL_BOOTSTRAP_MODE': 'public', 'GITHUB_WORKSPACE': str(self.root),
                       'GITHUB_SHA': self.commit, 'KERNEL_JOB_PACKET_SHA256': self.pin,
                       'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1', 'KERNEL_NATIVE_OUTCOME': 'success'}
        output = io.StringIO()
        with patch.dict(os.environ, environment), contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as stop:
            self.ns['main']()
        self.assertEqual(stop.exception.code, 0)
        self.assertEqual(json.loads(output.getvalue()), value)

    def snapshot(self):
        modes = {}
        captured = self.ns['source'](self.root, self.commit, self.pin, modes)
        return self.ns['clean_snapshot'](self.root, '123', '1', captured, modes)

    def test_timestamp_valid_root_caches_cannot_execute_in_clean_bootstrap(self):
        marker = self.root / 'malicious-cache-executed'
        cache_bytes = {}
        for name in ('packet', 'runtime', 'public'):
            source = self.root / f'scripts/port/kernel-native-job/{name}.py'
            info = source.stat()
            code = compile(f'from pathlib import Path\nPath({str(marker)!r}).write_text("EXECUTED")\nraise SystemExit(97)\n', str(source), 'exec')
            data = bytes(importlib._bootstrap_external._code_to_timestamp_pyc(code, int(info.st_mtime), info.st_size))
            cache = Path(importlib.util.cache_from_source(str(source)))
            cache.parent.mkdir(exist_ok=True); cache.write_bytes(data); cache_bytes[cache] = data
        # This proves -I/-B alone would still execute the timestamp-valid root cache.
        poisoned = subprocess.run(['/usr/bin/python3', '-I', '-B', str(self.root / self.ns['JOB']), '--help'],
                                  capture_output=True, timeout=10)
        self.assertEqual(poisoned.returncode, 97); self.assertTrue(marker.exists()); marker.unlink()
        extension = self.root / 'scripts/port/kernel-native-job' / ('packet' + importlib.machinery.EXTENSION_SUFFIXES[0])
        extension.write_bytes(b'UNLISTED EXTENSION')
        target = self.snapshot()
        clean = subprocess.run(['/usr/bin/python3', '-I', '-B', str(target / self.ns['JOB']), '--help'],
                               capture_output=True, timeout=10)
        self.assertEqual(clean.returncode, 0, clean.stderr.decode())
        self.assertIn(b'--execute-native', clean.stdout)
        self.assertFalse(marker.exists())
        self.assertEqual({str(path.relative_to(target)) for path in target.rglob('*') if path.is_file()}, set(self.rows))
        self.assertFalse(any(path.name == '__pycache__' for path in target.rglob('*')))
        self.assertEqual(extension.read_bytes(), b'UNLISTED EXTENSION')
        for cache, data in cache_bytes.items(): self.assertEqual(cache.read_bytes(), data)
        for name, row in self.rows.items():
            self.assertEqual(hashlib.sha256((target / name).read_bytes()).hexdigest(), row['sha256'])
            self.assertEqual(stat.S_IMODE((target / name).stat().st_mode), row['mode'])

    def test_clean_snapshot_refuses_existing_or_linked_destination(self):
        parent = self.root / 'artifacts/kernel-native-job'
        parent.mkdir(parents=True)
        path = parent / 'bootstrap-123-1'; path.mkdir()
        with self.assertRaises(FileExistsError): self.snapshot()
        path.rmdir(); path.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(FileExistsError): self.snapshot()

    def test_clean_snapshot_refuses_linked_parent(self):
        (self.root / 'artifacts').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError): self.snapshot()

    def test_aggregate_packet_bytes_are_bounded(self):
        payload = b'x' * (8 * 1024**2)
        rows = copy.deepcopy(self.rows)
        row = {'bytes': len(payload), 'mode': 0o644, 'sha256': hashlib.sha256(payload).hexdigest()}
        rows.update({f'large/{n}': row for n in range(5)})
        packet = encoded({'schema_version': 1, 'files': rows})
        self.pin = hashlib.sha256(packet).hexdigest()
        original = self.ns['read']
        def read(path, *args):
            if path == self.packet: return packet
            if path.parent.name == 'large': return payload
            return original(path, *args)
        with patch.dict(self.ns, {'read': read, 'committed': lambda *args: None}), self.assertRaises(ValueError):
            self.source()

    def test_workflow_finite_manual_shape_and_reserves(self):
        text = WORKFLOW.read_text()
        for expected in ('workflow_dispatch:', "github.repository == 'Gabriel-Kahen/cachy-asahi'", 'github.event.repository.private == false',
                         'runs-on: ubuntu-24.04-arm', 'contents: read', 'group: native-arm-kernel', 'cancel-in-progress: false',
                         'persist-credentials: false', '--deadline 20760', 'if: always()', 'run: *trusted-bootstrap',
                         'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'):
            self.assertIn(expected, text)
        for forbidden in ('upload-artifact', 'actions/cache', 'sudo', 'apt-get', 'docker system prune', 'schedule:', 'pull_request:', 'push:'):
            self.assertNotIn(forbidden, text)
        self.assertEqual(5 + 5 + 346 + 3 + 1, 360)
        self.assertNotIn('default:', text)
        self.assertIn("exec(compile(captured[PUBLIC]", text)
        self.assertIn('"$KERNEL_JOB_BOOTSTRAP_SOURCE/scripts/port/kernel-native-job/job.py"', text)
        self.assertIn("stream.write('KERNEL_JOB_BOOTSTRAP_SOURCE='", text)



class Schema4ChildTests(unittest.TestCase):
    def current(self):
        value = receipt(); value['schema_version'] = 4
        diagnostic = {'schema_version': 3, 'operation': {'current': dict(action='NONE',gate='NONE',predicate='NONE',category='NONE',query='NONE', query_return={'kind':'NOT_RUN','code':None},daemon_return={'kind':'NOT_RUN','code':None},create='NOT_ATTEMPTED',start='NOT_ATTEMPTED',resource_mismatch=None), 'first_failure':None,'cleanup_failure':None}, 'binding_sha256': 'f' * 64, 'current_predicate': 'COMPLETE',
            'first_failed_predicate': 'NONE', 'failure_category': 'NONE',
            'commands': {name: public.exit_record(0) for name in public.CHILD_ACTIONS},
            'cleanup': {'status': 'PASS', 'category': 'NONE'}}
        value['kernel_child'] = {'availability': 'VERIFIED', 'exit': public.exit_record(0), 'diagnostics': diagnostic}
        return value

    def test_schema3_historical_semantics_and_new_schema4_bound_success_are_separate(self):
        self.assertEqual(public.project(encoded(receipt()), COMMIT, PIN, 'success'), receipt())
        value = self.current(); self.assertEqual(public.project(encoded(value), COMMIT, PIN, 'success'), value)
        for outcome in ('failure', 'cancelled', 'skipped', ''):
            row = public.project(encoded(value), COMMIT, PIN, outcome)
            self.assertEqual(row['status'], 'FAIL')
            self.assertEqual(row['native_compilation'], 'NOT ACCEPTED')
            self.assertEqual(row['kernel_child'], value['kernel_child'])

    def test_current_pass_requires_actual_zero_exit_verified_complete_diagnostic(self):
        changes = (lambda r: r.pop('kernel_child'), lambda r: r['kernel_child'].update(exit=public.exit_record(1)),
            lambda r: r['kernel_child'].update(exit={'kind': 'UNOBSERVED', 'code': None}),
            lambda r: r['kernel_child'].update(availability='UNVERIFIED', diagnostics=None),
            lambda r: r['kernel_child']['diagnostics'].update(current_predicate='PROVISION_COMMAND'),
            lambda r: r['kernel_child']['diagnostics']['commands'].update(candidate=public.exit_record(125)),
            lambda r: r['kernel_child']['diagnostics']['cleanup'].update(status='FAIL', category='UNCERTAIN_MUTATION'))
        for change in changes:
            value = self.current(); change(value)
            with self.subTest(change=change), self.assertRaises(ValueError): public.project(encoded(value), COMMIT, PIN, 'success')

    def test_truthful_missing_child_keeps_observed_outer_first_cause(self):
        for availability in ('UNAVAILABLE', 'UNVERIFIED'):
            value = self.current(); value.update(status='FAIL', phase='cleanup', native_compilation='NOT RUN',
                kernel_probe='NOT RUN', baseline='NOT RUN', candidate='NOT RUN', cleanup='FAIL',
                first_failed_phase='kernel', failure_reason='KERNEL_EXIT')
            value['kernel_child'] = {'availability': availability, 'exit': public.exit_record(1), 'diagnostics': None}
            result = public.project(encoded(value), COMMIT, PIN, 'failure')
            self.assertEqual((result['first_failed_phase'], result['failure_reason']), ('kernel', 'KERNEL_EXIT'))
            self.assertEqual(result['kernel_child'], value['kernel_child'])
            self.assertEqual(result['native_compilation'], 'NOT RUN')

    def test_diagnostic_unknown_keys_raw_text_types_and_partial_groups_refused(self):
        changes = (lambda r: r['kernel_child'].update(raw='secret/path'),
            lambda r: r['kernel_child'].update(exit={'kind': 'EXIT_ZERO', 'code': True}),
            lambda r: r['kernel_child']['diagnostics'].update(raw='secret/path'),
            lambda r: r['kernel_child']['diagnostics'].update(binding_sha256='secret'),
            lambda r: r['kernel_child']['diagnostics'].update(failure_category='private error'),
            lambda r: r['kernel_child']['diagnostics']['commands'].pop('baseline'),
            lambda r: r['kernel_child']['diagnostics'].update(schema_version=True),
            lambda r: r['kernel_child'].update(availability='UNAVAILABLE'))
        for change in changes:
            value = self.current(); change(value)
            with self.subTest(change=change), self.assertRaises(ValueError): public.project(encoded(value), COMMIT, PIN, 'success')


class Schema4OperationTests(unittest.TestCase):
    current = Schema4ChildTests.current

    def operation(self):
        return {'current':dict(action='NONE',gate='NONE',predicate='NONE',category='NONE',query='NONE',
            query_return={'kind':'NOT_RUN','code':None},daemon_return={'kind':'NOT_RUN','code':None},
            create='NOT_ATTEMPTED',start='NOT_ATTEMPTED',resource_mismatch=None),'first_failure':None,'cleanup_failure':None}

    def test_closed_diagnostic3_does_not_replace_native_outcome_or_actual_exit_gate(self):
        value=self.current();row=value['kernel_child']['diagnostics']
        row.update(schema_version=3,operation=self.operation())
        self.assertEqual(public.project(encoded(value),COMMIT,PIN,'success'),value)
        for outcome in ('failure','cancelled','skipped',''):
            result=public.project(encoded(value),COMMIT,PIN,outcome)
            self.assertEqual(result['status'],'FAIL');self.assertEqual(result['kernel_child'],value['kernel_child'])
        for change in (lambda r:r['kernel_child'].update(exit=public.exit_record(1)),
            lambda r:r['kernel_child']['diagnostics']['operation']['current'].update(raw='secret'),
            lambda r:r['kernel_child']['diagnostics']['operation']['current'].update(gate='private/path')):
            bad=copy.deepcopy(value);change(bad)
            with self.assertRaises(ValueError):public.project(encoded(bad),COMMIT,PIN,'success')

    def test_schema1_and2_are_exact_shapes_not_optional_field_waivers(self):
        value=self.current();d=value['kernel_child']['diagnostics'];d['schema_version']=1;d['operation']=self.operation()
        with self.assertRaises(ValueError):public.project(encoded(value),COMMIT,PIN,'success')
        d.pop('operation');d['schema_version']=2
        with self.assertRaises(ValueError):public.project(encoded(value),COMMIT,PIN,'success')



class ModernResourcePublicTests(unittest.TestCase):
    current = Schema4ChildTests.current
    def test_legacy_complete_cannot_grant_modern_pass_but_exact_historical_failure_remains(self):
        for version in (1,2):
            value=self.current();d=value['kernel_child']['diagnostics'];d['schema_version']=version
            if version==1:d.pop('operation')
            else:
                for row in d['operation'].values():
                    if row is not None:row.pop('resource_mismatch')
            with self.assertRaises(ValueError):public.project(encoded(value),COMMIT,PIN,'success')
            value.update(status='FAIL',first_failed_phase='kernel',failure_reason='KERNEL_EXIT',cleanup='FAIL')
            value['kernel_child']['exit']=public.exit_record(1)
            self.assertEqual(public.project(encoded(value),COMMIT,PIN,'failure')['status'],'FAIL')

    def test_all_three_resource_slots_are_required_and_raw_poison_never_projects(self):
        stale=self.current()
        stale['kernel_child']['diagnostics']['operation']['current'].update(gate='INSPECT_RESOURCES',
            predicate='docker-container-resources',category='INVALID_DATA',resource_mismatch={'field':'Memory','kind':'TYPE'})
        with self.assertRaises(ValueError):public.project(encoded(stale),COMMIT,PIN,'success')
        value=self.current();d=value['kernel_child']['diagnostics'];op=d['operation']
        failed=copy.deepcopy(op['current']);failed.update(action='provision',gate='INSPECT_RESOURCES',
            predicate='docker-container-resources',category='INVALID_DATA',resource_mismatch={'field':'Memory','kind':'TYPE'})
        op.update(current=copy.deepcopy(failed),first_failure=copy.deepcopy(failed),cleanup_failure=dict(failed,action='cleanup'))
        value.update(status='FAIL',first_failed_phase='kernel',failure_reason='KERNEL_EXIT',cleanup='FAIL')
        d.update(current_predicate='CLEANUP',first_failed_predicate='PROVISION_COMMAND',failure_category='INVALID_DATA',cleanup={'status':'FAIL','category':'ABSENCE_UNVERIFIED'})
        value['kernel_child']['exit']=public.exit_record(1)
        self.assertEqual(public.project(encoded(value),COMMIT,PIN,'failure')['kernel_child']['diagnostics'],d)
        for slot in ('current','first_failure','cleanup_failure'):
            bad=copy.deepcopy(value);bad['kernel_child']['diagnostics']['operation'][slot].pop('resource_mismatch')
            with self.assertRaises(ValueError):public.project(encoded(bad),COMMIT,PIN,'failure')
            bad=copy.deepcopy(value);bad['kernel_child']['diagnostics']['operation'][slot]['resource_mismatch']['actual']='private-secret'
            with self.assertRaises(ValueError):public.project(encoded(bad),COMMIT,PIN,'failure')


class InnerFailurePublicTests(unittest.TestCase):
    def value(self):
        source = HERE.parent / 'kernel-native-stage/evidence.py'
        spec = importlib.util.spec_from_file_location('inner_child_evidence_fixture', source)
        evidence = importlib.util.module_from_spec(spec); spec.loader.exec_module(evidence)
        trace = evidence.Trace(); trace.action('baseline')
        binding = {'source_commit': COMMIT, 'stage_lock_sha256': 'c'*64,
            'output_name_sha256': 'd'*64, 'run_id': '1', 'run_attempt': '1', 'nonce': 'e'*32,
            'accepted_result_sha256': 'f'*64, 'bootstrap_sha256': '1'*64,
            'inputs_sha256': '2'*64, 'base_inventory_sha256': '3'*64}
        row = evidence.initial(binding, trace); row['commands']['baseline'] = evidence.exit_record(1)
        evidence.failure(row, 'COMMAND_NONZERO', 'BASELINE_COMMAND')
        row['cleanup'] = {'status': 'PASS', 'category': 'NONE'}
        evidence.inner_failure(row, 'baseline', {'availability': 'REFUSED', 'reason': 'INVALID',
                                                'raw_sha256': None, 'diagnostic': None})
        value = receipt(); value.update(schema_version=4, status='FAIL', phase='cleanup',
            first_failed_phase='kernel', failure_reason='KERNEL_EXIT', baseline='FAIL',
            candidate='NOT RUN', native_compilation='NOT ACCEPTED')
        value['kernel_child'] = {'availability': 'VERIFIED', 'exit': public.exit_record(1),
                                 'diagnostics': evidence.project(row)}
        return value

    def test_refused_permission_subclass_is_a_closed_public_value(self):
        for code in ('CHECK_001_PERMISSIONS_RWX', 'CHECK_001_PERMISSIONS_OTHER'):
            fact = {'call_boundary': 'VERIFY_OUTPUTS', 'predicate': code}
            self.assertEqual(public.validate_output_fact(fact), fact)
            with self.assertRaises(ValueError):
                public.validate_output_fact(dict(fact, flags=7))
        with self.assertRaises(ValueError):
            public.validate_output_fact({'call_boundary': 'VERIFY_OUTPUTS', 'predicate': 'CHECK_001_PERMISSIONS_7'})

    def test_check001_conjuncts_are_closed_public_values(self):
        labels = ('ALIGN_MIN', 'ALIGN_POWER_TWO', 'VA_ALIGN', 'PA_ALIGN', 'VA_16K', 'PA_16K', 'PERMISSIONS', 'MEMORY_SIZE')
        for label in labels:
            fact = {'call_boundary': 'VERIFY_OUTPUTS', 'predicate': 'CHECK_001_' + label}
            self.assertEqual(public.validate_output_fact(fact), fact)
        for code in ('CHECK_001_PRIVATE', 'CHECK_001_PERMISSIONS /private', True, None):
            with self.assertRaises(ValueError):
                public.validate_output_fact({'call_boundary': 'VERIFY_OUTPUTS', 'predicate': code})
        with self.assertRaises(ValueError):
            public.validate_output_fact({'call_boundary': 'VERIFY_OUTPUTS', 'predicate': 'CHECK_001_VA_16K', 'address': 1})

    def test_new_failure_diagnostic_preserves_all_outcome_failures(self):
        value = self.value(); original = copy.deepcopy(value['kernel_child'])
        for outcome in ('success', 'failure', 'cancelled', 'skipped', ''):
            row = public.project(encoded(value), COMMIT, PIN, outcome)
            self.assertEqual((row['status'], row['baseline'], row['candidate']), ('FAIL', 'FAIL', 'NOT RUN'))
            self.assertEqual(row['kernel_child'], original)
            self.assertEqual((row['first_failed_phase'], row['failure_reason']), ('kernel', 'KERNEL_EXIT'))
            self.assertEqual(row['cancelled'], outcome == 'cancelled')

    def test_inner_version_cannot_relax_original_pass_gate(self):
        value = self.value(); value.update(status='PASS', phase='complete',
            first_failed_phase='NONE', failure_reason='NONE', baseline='PASS', candidate='PASS',
            native_compilation='PASS')
        value['kernel_child']['exit'] = public.exit_record(0)
        with self.assertRaises(ValueError): public.project(encoded(value), COMMIT, PIN, 'success')

    def test_unknown_inner_fields_remain_private_and_refused(self):
        value = self.value(); value['kernel_child']['diagnostics']['inner']['baseline']['raw_stderr'] = 'private-secret'
        with self.assertRaises(ValueError): public.project(encoded(value), COMMIT, PIN, 'failure')



def relocation_fixture():
    return {'role': 'arm64-image-reference', 'elf_type': 3, 'branch': 'NULL_LINK_RELATIVE',
        'failed_check': 'INFO_RELATIVE', 'section': {'index': 3, 'type': 4, 'flags': 2,
        'link': 0, 'info': 0, 'entry_index': 0}, 'offset': 4097, 'info': 1028,
        'symbol_count': None, 'target_size': None,
        'allocated': {'start_count': 1, 'full_count': 1, 'first_start': {'index': 1, 'address': 4096, 'size': 32}},
        'load': {'start_count': 1, 'full_count': 1, 'first_start': {'index': 0, 'address': 4096, 'size': 32}}}


class RelocationPublicTests(unittest.TestCase):
    value = InnerFailurePublicTests.value
    def test_schema5_survives_full_public_projection_without_outcome_upgrade(self):
        import importlib.util
        path=HERE.parent/'kernel-native-stage/inner_result.py'
        spec=importlib.util.spec_from_file_location('relocation_inner_fixture',path)
        diag=importlib.util.module_from_spec(spec)
        # Inner runtime is a separate module namespace from this job runtime.
        import sys,types
        saved=sys.modules.get('runtime');stub=types.ModuleType('runtime')
        stub.Cancelled=type('Cancelled',(Exception,),{})
        try:
            sys.modules['runtime']=stub;spec.loader.exec_module(diag)
        finally:
            if saved is None:sys.modules.pop('runtime',None)
            else:sys.modules['runtime']=saved
        binding={'nonce':'a'*32,'action':'baseline','contract_sha256':'b'*64,'worker_sha256':'c'*64}
        row=diag.initial(binding);diag.phase(row,'KERNEL');diag.issued(row,'KERNEL');diag.returned(row,0)
        diag.phase(row,'OUTPUTS');error=ValueError('ELF relocation index/offset invalid')
        error.relocation_failure=relocation_fixture();diag.failure(row,error);diag.output_failure(row,error)
        report={'action':'baseline','nonce':binding['nonce'],'status':'FAIL','cancelled':False,'inner_diagnostic':row}
        group=diag.capture(json.dumps(report).encode(),binding);value=self.value()
        value['kernel_child']['diagnostics']['inner']['baseline']=group
        for outcome in ('success','failure','cancelled'):
            result=public.project(encoded(value),COMMIT,PIN,outcome)
            self.assertEqual(result['kernel_child']['diagnostics']['inner']['baseline'],group)
            self.assertEqual((result['status'],result['baseline'],result['candidate']),('FAIL','FAIL','NOT RUN'))
        bad=copy.deepcopy(value);bad['kernel_child']['diagnostics']['inner']['baseline']['diagnostic']['schema_version']=4
        with self.assertRaises(ValueError):public.project(encoded(bad),COMMIT,PIN,'failure')


if __name__ == '__main__':
    unittest.main()
