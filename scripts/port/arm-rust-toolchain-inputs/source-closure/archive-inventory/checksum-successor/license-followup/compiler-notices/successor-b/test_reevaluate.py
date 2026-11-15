"""Finite negative provenance, scope and accounting controls; zero HTTP."""
import copy
import importlib.util
import json
from pathlib import Path
import resource
import signal
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('notice_successor', HERE / 'reevaluate.py')
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)
PACKET = Path('/tmp/cachy-checksum-successor-20261115-03/private-license-candidates.json')
DATA = json.loads((HERE / 'cases.json').read_text())
RECEIPTS = json.loads((HERE / 'requests.json').read_text())['requests']


def read(name):
    return (HERE / name).read_bytes()


class Controls(unittest.TestCase):
    def test_official_redirect_needs_exact_repository_id_and_revision(self):
        case = copy.deepcopy(DATA['cases'][0])
        review.exact_tree(case, read, RECEIPTS)
        for key, value in [('repository', 'wrong/repository'), ('commit', 'b' * 40),
                           ('tree_request_repository', 'another/alias')]:
            changed = {**case, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                review.exact_tree(changed, read, RECEIPTS)
        receipts = copy.deepcopy(RECEIPTS)
        receipts[0]['location'] = receipts[0]['location'].replace('60375943', '60375944')
        with self.assertRaisesRegex(ValueError, 'redirect'):
            review.exact_tree(case, read, receipts)

    def test_canonical_repository_cannot_use_an_unrelated_tree_receipt(self):
        case = copy.deepcopy(DATA['cases'][-1])
        review.exact_tree(case, read, RECEIPTS)
        case['tree_file'] = DATA['cases'][1]['tree_file']
        with self.assertRaisesRegex(ValueError, 'tree receipt'):
            review.exact_tree(case, read, RECEIPTS)

    def test_inherited_license_and_repository_need_pinned_workspace(self):
        case = DATA['cases'][0]
        captures = [{'path': 'vendor/libffi/Cargo.toml.orig', 'text': '[package]\nlicense.workspace=true\nrepository.workspace=true\n'}]
        entries = review.exact_tree(case, read, RECEIPTS)
        self.assertTrue(review.inherited_license_repository(case, captures, entries, read)['inherited_license_repository_resolved'])
        with self.assertRaisesRegex(ValueError, 'workspace Git blob'):
            review.inherited_license_repository(case, captures, entries, lambda _: read(case['workspace_manifest']) + b'#changed')
        changed = {**case, 'repository': 'wrong/repository'}
        with self.assertRaisesRegex(ValueError, 'inherited repository'):
            review.inherited_license_repository(changed, captures, entries, read)

    def test_named_notice_cannot_come_from_another_revision(self):
        case = DATA['cases'][-1]
        review.scope_notice(case, read(case['grant_file']))
        with self.assertRaisesRegex(ValueError, 'named notice'):
            review.scope_notice(case, read(DATA['cases'][1]['grant_file']))

    def test_sibling_grant_template_and_incomplete_body_refused(self):
        case = copy.deepcopy(DATA['cases'][1])
        grant = read(case['grant_file'])
        case['grant_upstream_path'] = 'phf_macros/LICENSE'
        with self.assertRaisesRegex(ValueError, 'ancestor'):
            review.scope_notice(case, grant)
        case['grant_upstream_path'] = 'LICENSE'
        case['manual_named_notice'] = 'Copyright [yyyy] [name of copyright owner]'
        with self.assertRaisesRegex(ValueError, 'template'):
            review.scope_notice(case, grant + b'Copyright [yyyy] [name of copyright owner]\n')
        with self.assertRaisesRegex(ValueError, 'complete grant'):
            review.scope_notice(case, b'Permission is hereby granted')

    def test_error_redirect_request_byte_and_time_caps(self):
        ledger = json.loads((HERE / 'requests.json').read_text())
        result = review.network_summary(ledger)
        self.assertEqual((result['new_actual_HTTP_requests'], result['new_response_body_bytes']), (20, 336941))
        self.assertEqual((result['redirect_requests'], result['failed_requests']), ([1, 4, 10, 12], [8]))
        for patch in [{'requests': ledger['requests'] + [{'ordinal': 21, 'bytes': 0, 'HTTP': 422}]},
                      {'body_bytes': ledger['body_bytes'] - 1}, {'acquisition_closed': False},
                      {'stopped_epoch': ledger['started_epoch'] + 901},
                      {'requests': [{'ordinal': 1, 'bytes': 16 * 1024**2 + 1}], 'body_bytes': 16 * 1024**2 + 1}]:
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                review.network_summary({**ledger, **patch})

    def test_acquisition_is_closed_without_new_requests(self):
        spec = importlib.util.spec_from_file_location('finite_fetch', HERE / 'fetch.py')
        fetch = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fetch)
        with self.assertRaisesRegex(ValueError, 'acquisition is closed'):
            fetch.acquire('https://api.github.com/repos/unused/unused', 'unused.json')

    @unittest.skipUnless(PACKET.exists(), 'private source packet deliberately not distributed')
    def test_real_offline_replay_preserves_100_remaining_and_selection_holds(self):
        result = review.evaluate(PACKET)
        self.assertEqual(result, json.loads((HERE / 'report.json').read_text()))
        self.assertEqual((result['baseline_unresolved'], result['new_scoped_notice_cases_closed'], result['remaining_unresolved']), (106, 6, 100))
        ffi = next(c for c in result['cases'] if c['component'] == 'libffi-5.1.0')
        self.assertTrue(ffi['inherited_license_repository_resolved'])
        self.assertEqual(ffi['static_root_lock_path'][0][:2], ['miri', '0.1.0'])
        for case in result['cases']:
            self.assertFalse(case['Linux_aarch64_cfg_features_resolved'])
            self.assertEqual(case['all_file_license_and_legal_acceptance'], 'HELD')
            if case['component'].startswith('phf'):
                self.assertEqual(case['lock_membership'], {'Cargo.lock': False, 'src/tools/cargo/Cargo.lock': False})
                self.assertIsNone(case['static_root_lock_path'])
        for component in ['intl_pluralrules-7.0.2', 'polonius-engine-0.13.0', 'perf-event-open-sys-3.0.0',
                          'spanned-0.4.1', 'rsqlite-vfs-0.1.1', 'anes-0.1.6', 'ui_test-0.30.7', 'line-index-0.1.2']:
            self.assertIn(component, result['remaining_components'])


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    signal.alarm(30)
    unittest.main()
