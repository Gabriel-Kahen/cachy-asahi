"""Manifest restoration and separate wrapper/PostgreSQL obligation fences."""
import copy
import importlib.util
import json
from pathlib import Path
import resource
import signal
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('notice_f', HERE / 'reevaluate.py')
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)
DATA = json.loads((HERE / 'cases.json').read_text())
LEDGER = json.loads((HERE / 'requests.json').read_text())
PACKET = Path('/tmp/cachy-checksum-successor-20261115-03/private-license-candidates.json')


def read(name):
    return (HERE / name).read_bytes()


class Controls(unittest.TestCase):
    def test_restore_requires_full_hash_and_exact_original_prefix(self):
        body = b'[package]\nname="one"\nversion="1.0"\n'
        prefix = body[:12]
        record = {'text': prefix.decode(), 'captured_bytes': len(prefix), 'captured_prefix_sha256': review.pin(prefix)['sha256'],
                  'complete_text': False, 'utf8_replacement_used': False, **review.pin(body)}
        self.assertTrue(review.restore_manifest(record, body)['complete_text'])
        self.assertFalse(record['complete_text'])
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            review.restore_manifest(record, body + b'#changed')
        changed = {**record, 'text': 'WRONG PREFIX'}
        with self.assertRaisesRegex(ValueError, 'prefix mismatch'):
            review.restore_manifest(changed, body)

    def test_published_html_extracts_exact_complete_manifest(self):
        body = review.source_text.extract(read(DATA['case']['manifest_source_html']))
        self.assertEqual(body, read(DATA['case']['restored_manifest']))
        self.assertEqual(review.pin(body), {'bytes': 8758, 'sha256': 'b515af637371396c35e5203e2da3fa28c70a96dc3c14baf8909e1789f4b195ad'})
        with self.assertRaises(ValueError):
            review.source_text.extract(b'<div id="source-code">one</div><div id="source-code">two</div>')

    def test_exact_submodule_mode_commit_repository_and_path(self):
        case = DATA['case']
        entries = review.compiler.tree_entries(case, read, LEDGER['requests'])
        modules = read('evidence/pq-gitmodules')
        review.submodule_identity(case, entries, modules)
        for field, value in [('mode', '040000'), ('type', 'tree'), ('sha', '0' * 40)]:
            changed = copy.deepcopy(entries)
            changed[case['submodule_path']][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'Gitlink'):
                review.submodule_identity(case, changed, modules)
        for replacement in [modules.replace(b'postgres/postgres', b'wrong/repository'), modules.replace(b'path = pq-src/source', b'path = another/source')]:
            with self.subTest(replacement=replacement), self.assertRaisesRegex(ValueError, 'path/repository'):
                review.submodule_identity(case, entries, replacement)

    def test_postgres_requires_both_notices_permission_and_two_disclaimers(self):
        notices = DATA['case']['postgres_notices']
        body = read('evidence/postgres-COPYRIGHT')
        review.postgres_grant(body, notices)
        for literal in [notices[0].encode(), notices[1].encode(), b'provided that the above copyright notice',
                        b'IN NO EVENT SHALL THE UNIVERSITY', b'SPECIFICALLY DISCLAIMS ANY WARRANTIES',
                        b'NO OBLIGATIONS TO']:
            with self.subTest(literal=literal), self.assertRaises(ValueError):
                review.postgres_grant(body.replace(literal, b'REMOVED', 1), notices)
        with self.assertRaisesRegex(ValueError, 'both distinct'):
            review.postgres_grant(body, [notices[0], notices[0]])

    def test_wrapper_mit_notice_is_not_transferred_to_postgres(self):
        wrapper = read('evidence/pq-wrapper-LICENSE-MIT')
        postgres = read('evidence/postgres-COPYRIGHT')
        review.compiler.grant_review('MIT', wrapper)
        review.compiler.notice_review(wrapper, DATA['case']['wrapper_notice'])
        with self.assertRaisesRegex(ValueError, 'named notice'):
            review.compiler.notice_review(postgres, DATA['case']['wrapper_notice'])
        with self.assertRaises(ValueError):
            review.postgres_grant(wrapper, DATA['case']['postgres_notices'])

    def test_child_tree_cannot_substitute_parent_or_wrong_revision(self):
        child = {'repository': DATA['case']['submodule_repository'], 'commit': DATA['case']['submodule_commit'], 'tree_file': 'evidence/postgres-root-tree.json'}
        review.compiler.tree_entries(child, read, LEDGER['requests'])
        child['commit'] = DATA['case']['commit']
        with self.assertRaisesRegex(ValueError, 'repository receipt'):
            review.compiler.tree_entries(child, read, LEDGER['requests'])

    def test_strict_50request_2mib_15minute_and_perbody_caps(self):
        result = review.network_summary(LEDGER)
        self.assertEqual((result['new_actual_HTTP_requests'], result['new_response_body_bytes']), (13, 223877))
        ledger = {'requests': [{'ordinal': i, 'bytes': 1, 'HTTP': s, 'complete_body': True} for i, s in enumerate([301, 200, 404], 1)],
                  'body_bytes': 3, 'started_epoch': 0, 'stopped_epoch': 899, 'acquisition_closed': True}
        self.assertEqual(review.network_summary(ledger)['redirect_or_error_requests'], [1, 3])
        for change in [{'stopped_epoch': 901}, {'body_bytes': 4}, {'acquisition_closed': False},
                       {'requests': [{'ordinal': i, 'bytes': 0} for i in range(1, 52)], 'body_bytes': 0},
                       {'requests': [{'ordinal': 1, 'bytes': 256 * 1024 + 1}], 'body_bytes': 256 * 1024 + 1},
                       {'requests': [{'ordinal': i, 'bytes': 256 * 1024} for i in range(1, 10)], 'body_bytes': 9 * 256 * 1024}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                review.network_summary({**ledger, **change})

    def test_closed_acquisition_prevents_new_request(self):
        spec = importlib.util.spec_from_file_location('finite_f_fetch', HERE / 'fetch.py')
        fetch = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fetch)
        with self.assertRaisesRegex(ValueError, 'acquisition closed'):
            fetch.acquire('https://api.github.com/repos/unused/unused', 'unused.json')

    @unittest.skipUnless(PACKET.exists(), 'private source packet deliberately not distributed')
    def test_real_composite_closure_preserves_all_boundary_holds(self):
        result = review.evaluate(PACKET)
        self.assertEqual(result, json.loads((HERE / 'report.json').read_text()))
        self.assertEqual((result['baseline_unresolved'], result['new_scoped_package_notice_cases_closed'], result['remaining_unresolved']), (91, 1, 90))
        self.assertEqual(result['closed_components'], ['pq-src-0.3.6+libpq-17.4'])
        self.assertEqual(result['package_declared_license'], 'PostgreSQL')
        self.assertFalse(result['wrapper_scope']['ownership_transferred_to_bundled_C'])
        self.assertEqual(result['declared_bundled_source_scope']['child_source_version_metadata'], '17.4')
        self.assertFalse(result['restored_manifest']['original_capture_complete_text'])
        self.assertFalse(result['restored_manifest']['private_capture_changed'])
        self.assertEqual(result['actual_target_activation_all_file_legal_native_M2_release_acceptance'], 'HELD')
        self.assertIn('HELD', result['vendor_C_to_declared_submodule_full_projection_and_third_party_notices'])
        generated = result['generated_package_attempt']
        self.assertEqual((len(generated['components']), generated['closure_credit']), (11, 0))
        self.assertEqual(generated['publisher_revision_and_generated_manifest_transformation'], 'UNPROVED')
        self.assertEqual(result['core_objc_attempt']['closure_credit'], 0)
        for component in generated['components'] + result['core_objc_attempt']['components']:
            self.assertIn(component, result['remaining_components'])


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    signal.alarm(30)
    unittest.main()
