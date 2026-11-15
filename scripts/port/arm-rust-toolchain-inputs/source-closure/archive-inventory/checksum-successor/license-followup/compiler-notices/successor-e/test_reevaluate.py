"""Exact per-revision grants, distinct project notices and tight budget fences."""
import copy
import importlib.util
import json
from pathlib import Path
import resource
import signal
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('notice_e', HERE / 'reevaluate.py')
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)
DATA = json.loads((HERE / 'cases.json').read_text())
LEDGER = json.loads((HERE / 'requests.json').read_text())
PACKET = Path('/tmp/cachy-checksum-successor-20261115-03/private-license-candidates.json')


def read(name):
    return (HERE / name).read_bytes()


class Controls(unittest.TestCase):
    def test_every_selected_grant_is_complete_actual_mit(self):
        for case in DATA['cases']:
            with self.subTest(component=case['component']):
                review.compiler.grant_review('MIT', read(case['grant_file']))
        with self.assertRaisesRegex(ValueError, 'complete grant'):
            review.compiler.grant_review('MIT', b'Permission is hereby granted')

    def test_identical_jni_grant_bytes_cannot_substitute_commit_scope(self):
        left, right = DATA['cases'][:2]
        self.assertEqual(read(left['grant_file']), read(right['grant_file']))
        review.compiler.tree_entries(left, read, LEDGER['requests'])
        review.compiler.tree_entries(right, read, LEDGER['requests'])
        changed = {**right, 'tree_file': left['tree_file']}
        with self.assertRaisesRegex(ValueError, 'repository receipt'):
            review.compiler.tree_entries(changed, read, LEDGER['requests'])

    def test_jni_sys_notice_cannot_be_replaced_with_prevoty_notice(self):
        case = DATA['cases'][2]
        body = read(case['notice_file'])
        review.compiler.notice_review(body, case['manual_named_notice'])
        with self.assertRaisesRegex(ValueError, 'named notice'):
            review.compiler.notice_review(body, DATA['cases'][0]['manual_named_notice'])

    def test_inherited_jni_license_requires_member_and_mit_alternative(self):
        case = DATA['cases'][0]
        entries = review.compiler.tree_entries(case, read, LEDGER['requests'])
        package = {'license': {'workspace': True}}
        self.assertTrue(review.jni_license(case, package, entries, read, LEDGER['requests'])['inherited_license_resolved'])
        bodies = [b'[workspace]\nmembers=["crates/*"]\nexclude=["crates/jni"]\n[workspace.package]\nlicense="MIT OR Apache-2.0"\n',
                  b'[workspace]\nmembers=["other/*"]\n[workspace.package]\nlicense="MIT"\n',
                  b'[workspace]\nmembers=["crates/*"]\n[workspace.package]\nlicense="Apache-2.0"\n']
        for body in bodies:
            with self.subTest(body=body), patch.object(review.preceding, 'primary_body', return_value=(body, 'test')), self.assertRaises(ValueError):
                review.jni_license(case, package, entries, read, LEDGER['requests'])

    def test_wasite_separate_named_notice_needs_exact_root_readme_and_vendor_pin(self):
        case = DATA['cases'][-1]
        body = read(case['notice_file'])
        record = {'path': 'vendor/wasite-1.0.2/README.md', 'complete_text': True, 'utf8_replacement_used': False, **review.pin(body)}
        entries = review.compiler.tree_entries(case, read, LEDGER['requests'])
        result = review.named_notice(case, {'readme': 'README.md'}, [record], entries, read, LEDGER['requests'])
        self.assertTrue(result['vendor_README_correspondence'])
        with self.assertRaisesRegex(ValueError, 'package README'):
            review.named_notice(case, {'readme': 'OTHER.md'}, [record], entries, read, LEDGER['requests'])
        wrong = {**record, 'sha256': '0' * 64}
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            review.named_notice(case, {'readme': 'README.md'}, [wrong], entries, read, LEDGER['requests'])
        changed = {**case, 'manifest_path': 'sibling/Cargo.toml'}
        with self.assertRaisesRegex(ValueError, 'root package scope'):
            review.named_notice(changed, {'readme': 'README.md'}, [record], entries, read, LEDGER['requests'])

    def test_wrong_repository_and_wrong_directory_shard_are_rejected(self):
        case = copy.deepcopy(DATA['cases'][0])
        changed = {**case, 'repository': 'wrong/repository'}
        with self.assertRaisesRegex(ValueError, 'repository receipt'):
            review.compiler.tree_entries(changed, read, LEDGER['requests'])
        case['tree_shards'][1]['file'] = DATA['cases'][1]['tree_shards'][1]['file']
        with self.assertRaisesRegex(ValueError, 'ancestor Git ID'):
            review.compiler.tree_entries(case, read, LEDGER['requests'])

    def test_template_notices_error_redirect_byte_request_time_fences(self):
        literal = 'Copyright [yyyy] [name of copyright owner]'
        with self.assertRaisesRegex(ValueError, 'template'):
            review.compiler.notice_review((literal + '\n').encode(), literal)
        result = review.network_summary(LEDGER)
        self.assertEqual((result['new_actual_HTTP_requests'], result['new_response_body_bytes']), (29, 76018))
        self.assertEqual((result['redirect_requests'], result['error_or_incomplete_requests']), ([16], [13]))
        ledger = {'requests': [{'ordinal': i, 'bytes': 1, 'HTTP': s, 'complete_body': True} for i, s in enumerate([301, 200, 404], 1)],
                  'body_bytes': 3, 'started_epoch': 0, 'stopped_epoch': 899, 'acquisition_closed': True}
        self.assertEqual(review.network_summary(ledger)['error_or_incomplete_requests'], [3])
        for change in [{'stopped_epoch': 901}, {'body_bytes': 4}, {'acquisition_closed': False},
                       {'requests': [{'ordinal': i, 'bytes': 0} for i in range(1, 52)], 'body_bytes': 0},
                       {'requests': [{'ordinal': 1, 'bytes': 128 * 1024 + 1}], 'body_bytes': 128 * 1024 + 1},
                       {'requests': [{'ordinal': i, 'bytes': 128 * 1024} for i in range(1, 18)], 'body_bytes': 17 * 128 * 1024}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                review.network_summary({**ledger, **change})

    def test_acquisition_closed_before_new_request(self):
        spec = importlib.util.spec_from_file_location('finite_e_fetch', HERE / 'fetch.py')
        fetch = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fetch)
        with self.assertRaisesRegex(ValueError, 'acquisition closed'):
            fetch.acquire('https://api.github.com/repos/unused/unused', 'unused.json')

    @unittest.skipUnless(PACKET.exists(), 'private source packet deliberately not distributed')
    def test_real_replay_five_closures_91_remaining_all_weak_attempts_held(self):
        result = review.evaluate(PACKET)
        self.assertEqual(result, json.loads((HERE / 'report.json').read_text()))
        self.assertEqual((result['baseline_unresolved'], result['new_scoped_package_notice_cases_closed'], result['remaining_unresolved']), (96, 5, 91))
        self.assertEqual(result['closed_components'], ['defmt-parser-1.0.0', 'jni-0.22.4', 'jni-macros-0.22.4', 'jni-sys-macros-0.4.1', 'wasite-1.0.2'])
        for case in result['cases']:
            self.assertEqual(case['actual_target_activation'], 'NOT_PROVED')
            self.assertEqual(case['all_file_full_projection_legal_native_M2_release_acceptance'], 'HELD')
        for attempt in result['unresolved_attempts']:
            self.assertEqual(attempt['closure_credit'], 0)
            self.assertIn(attempt['component'], result['remaining_components'])
        for component in ['spanned-0.4.1', 'wasmparser-0.243.0', 'intl_pluralrules-7.0.2', 'polonius-engine-0.13.0', 'perf-event-open-sys-3.0.0']:
            self.assertIn(component, result['remaining_components'])


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    signal.alarm(30)
    unittest.main()
