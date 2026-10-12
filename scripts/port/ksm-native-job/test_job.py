# SPDX-License-Identifier: MIT
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location('ksm_job_tested', HERE / 'job.py')
j = importlib.util.module_from_spec(spec)
exec(compile((HERE / 'job.py').read_bytes(), str(HERE / 'job.py'), 'exec'), j.__dict__)


def captures():
    names = set(j.PINS) | {'scripts/port/ksm-lifecycle/source-test-results.json'}
    names |= {'packages/tools/cachy-asahi-ksmctl/' + name for name in j.KSM_INPUTS}
    for directory, rows in json.loads((ROOT / 'scripts/ci/recipes.lock.json').read_bytes()).items():
        names |= {directory + '/' + name for name in rows}
    return {name: (ROOT / name).read_bytes() for name in names}


class JobTests(unittest.TestCase):
    def setUp(self):
        self.files = captures()
        self.env = {'GITHUB_REPOSITORY': 'Gabriel-Kahen/cachy-asahi', 'GITHUB_SHA': 'a' * 40,
                    'GITHUB_WORKFLOW_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123', 'PACKET_SHA256': 'b' * 64}
        self.provenance = {'kind': 'reviewed-committed-source-packet-capture', 'commit': 'a' * 40,
                           'packet_sha256': 'b' * 64, 'workflow': '.github/workflows/native-arm-ksm.yml'}
        self.identity = (1000, 1000, 1000, 1000, 'Linux', 'aarch64')

    def assess(self, **kwargs):
        return j.assess(SimpleNamespace(files=self.files, provenance=self.provenance), self.env,
                        identity=self.identity, **kwargs)

    def test_current_held_sources_have_explicit_owned_interface_blocker(self):
        result = self.assess()
        self.assertEqual(result['status'], 'BLOCKED')
        self.assertEqual(result['source_acceptance'], 'PASS')
        self.assertEqual(result['blockers'], list(j.BLOCKERS))
        self.assertEqual(result['owned_resources'], [])
        self.assertEqual(result['producer'], 'NOT RUN')
        self.assertEqual(result['public_export'], 'NOT RUN')
        self.assertFalse(result['published'])

    def test_single_source_drift_cannot_reach_producer(self):
        self.files['scripts/ci/native_arm.py'] += b'\n'
        result = self.assess()
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['source_acceptance'], 'FAIL')

    def test_gpl_notice_drift_refused(self):
        self.files['packages/tools/cachy-asahi-ksmctl/NOTICE'] += b'\n'
        self.assertEqual(self.assess()['status'], 'FAIL')

    def test_original_recipe_payload_drift_refused(self):
        self.files['packages/shells/cachy-asahi-fish-config/config.fish'] += b'\n'
        self.assertEqual(self.assess()['status'], 'FAIL')

    def test_source147_receipt_drift_refused(self):
        self.files['scripts/port/ksm-lifecycle/source-test-results.json'] += b'\n'
        self.assertEqual(self.assess()['status'], 'FAIL')

    def test_cancellation_before_and_after_source_checks(self):
        for cut in range(3):
            calls = iter(range(3))
            result = self.assess(cancelled=lambda: next(calls, cut) >= cut)
            self.assertEqual(result['status'], 'FAIL')
            self.assertEqual(result['owned_resources'], [])

    def test_source_deadline_cannot_be_extended(self):
        ticks = iter([0, 181])
        self.assertEqual(self.assess(clock=lambda: next(ticks))['status'], 'FAIL')

    def test_initial_workflow_source_time_is_in_same_deadline(self):
        self.assertEqual(self.assess(clock=lambda: 181, started_at=0)['status'], 'FAIL')

    def test_snapshot_from_other_run_packet_or_workflow_refused(self):
        for key in self.provenance:
            old = self.provenance[key]
            self.provenance[key] = 'wrong'
            self.assertEqual(self.assess()['status'], 'FAIL')
            self.provenance[key] = old

    def test_wrong_repository_run_or_workflow_commit_refused(self):
        for key in self.env:
            previous = self.env[key]
            self.env[key] = 'wrong'
            self.assertEqual(self.assess()['status'], 'FAIL', key)
            self.env[key] = previous

    def test_privilege_gid_and_emulation_refused(self):
        for identity in [(0, 0, 1000, 1000, 'Linux', 'aarch64'),
                         (1000, 1000, 0, 0, 'Linux', 'aarch64'),
                         (1000, 1001, 1000, 1000, 'Linux', 'aarch64'),
                         (1000, 1000, 1000, 1001, 'Linux', 'aarch64'),
                         (1000, 1000, 1000, 1000, 'Linux', 'x86_64')]:
            self.identity = identity
            self.assertEqual(self.assess()['status'], 'FAIL')

    def test_finite_total_reserves_cover_phase_maxima(self):
        b = j.BUDGETS
        self.assertLessEqual(b['source_seconds'] + b['producer_seconds'] + b['build_count'] *
                             b['build_seconds_each'] + b['compare_seconds'] + b['lifecycle_seconds'] +
                             b['cleanup_seconds'] + b['public_seconds'], b['aggregate_seconds'])


if __name__ == '__main__':
    unittest.main()
