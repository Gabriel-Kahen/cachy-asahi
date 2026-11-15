"""Provenance and zero-credit fences for a finite unsuccessful notice screen."""
import copy
import importlib.util
import json
from pathlib import Path
import resource
import signal
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('notice_g', HERE / 'reevaluate.py')
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)
DATA = json.loads((HERE / 'cases.json').read_text())
LEDGER = json.loads((HERE / 'requests.json').read_text())
PACKET = Path('/tmp/cachy-checksum-successor-20261115-03/private-license-candidates.json')


def read(name):
    return (HERE / name).read_bytes()


class Controls(unittest.TestCase):
    def test_each_root_has_exact_metadata_receipt_and_source_blobs(self):
        for snapshot in DATA['snapshots']:
            with self.subTest(snapshot=snapshot['id']):
                entries = review.root_entries(snapshot, read)
                review.source_body(snapshot, snapshot['readme_file'], 'README.md', entries, read, LEDGER['requests'])
                if snapshot['grant_file']:
                    body, _ = review.source_body(snapshot, snapshot['grant_file'], snapshot['grant_path'], entries, read, LEDGER['requests'])
                    review.compiler.grant_review('MIT', body)

    def test_wasi_alias_requires_exact_official_redirect(self):
        snapshot = copy.deepcopy(next(s for s in DATA['snapshots'] if s['id'] == 'wasip1'))
        review.root_entries(snapshot, read)
        snapshot['official_api_repository_id'] += 1
        with self.assertRaisesRegex(ValueError, 'redirect missing'):
            review.root_entries(snapshot, read)
        snapshot['official_api_repository_id'] -= 1
        def no_redirect(name):
            if name == 'requests.json':
                ledger = copy.deepcopy(LEDGER)
                ledger['requests'] = [r for r in ledger['requests'] if r.get('HTTP') != 301]
                return json.dumps(ledger).encode()
            return read(name)
        with self.assertRaisesRegex(ValueError, 'redirect missing'):
            review.root_entries(snapshot, no_redirect)

    def test_equal_grants_and_readmes_do_not_substitute_commit_scope(self):
        left, right = DATA['snapshots'][:2]
        self.assertEqual(read(left['grant_file']), read(right['grant_file']))
        self.assertEqual(read(left['readme_file']), read(right['readme_file']))
        changed = {**right, 'root_file': left['root_file']}
        with self.assertRaisesRegex(ValueError, 'HTTP receipt'):
            review.root_entries(changed, read)

    def test_wrong_repository_and_changed_body_rejected(self):
        snapshot = DATA['snapshots'][0]
        entries = review.root_entries(snapshot, read)
        with self.assertRaisesRegex(ValueError, 'HTTP receipt'):
            review.root_entries({**snapshot, 'repository': 'wrong/repository'}, read)
        def tamper(name):
            return read(name) + b'changed' if name == snapshot['readme_file'] else read(name)
        with self.assertRaisesRegex(ValueError, 'Git blob'):
            review.source_body(snapshot, snapshot['readme_file'], 'README.md', entries, tamper, LEDGER['requests'])

    def test_no_positive_credit_without_separate_package_scope_join(self):
        snapshot = DATA['snapshots'][0]
        readme, grant = read(snapshot['readme_file']), read(snapshot['grant_file'])
        self.assertEqual(review.retain_hold(snapshot, readme, grant)['closure_credit'], 0)
        for change in [{'manual_named_notice': 'Copyright An Author'}, {'package_manifest_to_Git_binding': 'PASS'}]:
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'separate reviewed join'):
                review.retain_hold({**snapshot, **change}, readme, grant)

    def test_changed_notice_context_requires_review_instead_of_silent_credit(self):
        snapshot = DATA['snapshots'][0]
        readme, grant = read(snapshot['readme_file']), read(snapshot['grant_file'])
        with self.assertRaisesRegex(ValueError, 'manual review'):
            review.retain_hold(snapshot, readme + b'Copyright 2026 Actual Project\n', grant)
        with self.assertRaisesRegex(ValueError, 'manual review'):
            review.retain_hold(snapshot, readme, b'Copyright 2026 Actual Project\n' + grant)

    def test_50request_2mib_15minute_perbody_and_error_accounting(self):
        result = review.network_summary(LEDGER)
        self.assertEqual((result['new_actual_HTTP_requests'], result['new_response_body_bytes']), (26, 82053))
        self.assertEqual((result['redirect_requests'], result['error_or_incomplete_requests']), ([4, 6], [3]))
        for change in [{'stopped_epoch': LEDGER['started_epoch'] + 901}, {'body_bytes': 0}, {'acquisition_closed': False},
                       {'requests': [{'ordinal': i, 'bytes': 0} for i in range(1, 52)], 'body_bytes': 0},
                       {'requests': [{'ordinal': 1, 'bytes': 128 * 1024 + 1}], 'body_bytes': 128 * 1024 + 1},
                       {'requests': [{'ordinal': i, 'bytes': 128 * 1024} for i in range(1, 18)], 'body_bytes': 17 * 128 * 1024}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                review.network_summary({**LEDGER, **change})

    def test_acquisition_closed_without_another_request(self):
        spec = importlib.util.spec_from_file_location('finite_g_fetch', HERE / 'fetch.py')
        fetch = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fetch)
        with self.assertRaisesRegex(ValueError, 'acquisition closed'):
            fetch.acquire('https://api.github.com/repos/unused/unused', 'unused.json')

    @unittest.skipUnless(PACKET.exists(), 'private source packet deliberately not distributed')
    def test_real_zero_credit_replay_preserves_every_remaining_case(self):
        result = review.evaluate(PACKET)
        self.assertEqual(result, json.loads((HERE / 'report.json').read_text()))
        self.assertEqual((result['baseline_unresolved'], result['new_scoped_package_notice_cases_closed'], result['remaining_unresolved']), (90, 0, 90))
        self.assertEqual(result['screened_component_count'], 12)
        self.assertEqual(result['remaining_components'], json.loads(read('../successor-f/report.json'))['remaining_components'])
        for root in result['root_snapshots']:
            self.assertEqual(root['closure_credit'], 0)
            self.assertEqual(root['package_manifest_to_Git_binding'], 'NOT_PERFORMED_NO_ELIGIBLE_NOTICE_FOUND')
            for component in root['selected_components']:
                self.assertEqual(component['closure_credit'], 0)
                self.assertEqual(component['package_manifest_scope_and_inherited_values'], 'NOT_PROMOTED')
                self.assertIn(component['component'], result['remaining_components'])


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    signal.alarm(30)
    unittest.main()
