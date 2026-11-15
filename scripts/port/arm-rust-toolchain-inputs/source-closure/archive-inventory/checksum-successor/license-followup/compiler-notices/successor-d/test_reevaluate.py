"""Finite grant completeness, project-scope and provenance controls."""
import copy
import importlib.util
import json
from pathlib import Path
import resource
import signal
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('notice_d', HERE / 'reevaluate.py')
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)
DATA = json.loads((HERE / 'cases.json').read_text())
LEDGER = json.loads((HERE / 'requests.json').read_text())
PACKET = Path('/tmp/cachy-checksum-successor-20261115-03/private-license-candidates.json')


def read(file):
    return (HERE / file).read_bytes()


class Controls(unittest.TestCase):
    def test_all_four_complete_named_grants(self):
        for case in DATA['cases']:
            with self.subTest(component=case['component']):
                review.complete_grant(case, read(case['grant_file']))

    def test_bsd_requires_source_binary_endorsement_and_disclaimer(self):
        case = next(c for c in DATA['cases'] if c['grant_kind'] == 'BSD-3-Clause')
        body = read(case['grant_file'])
        for literal in [b'1. Redistributions', b'2. Redistributions', b'3. Neither',
                        b'THIS SOFTWARE IS PROVIDED', b'EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.']:
            with self.subTest(literal=literal), self.assertRaisesRegex(ValueError, 'complete BSD'):
                review.complete_grant(case, body.replace(literal, b'REMOVED', 1))

    def test_named_notice_is_literal_and_not_an_author_inference(self):
        case = copy.deepcopy(DATA['cases'][0])
        case['manual_named_notice'] = 'Copyright (c) 2021 A Different Person'
        with self.assertRaisesRegex(ValueError, 'named notice'):
            review.complete_grant(case, read(case['grant_file']))
        case['manual_named_notice'] = 'Copyright [yyyy] [name of copyright owner]'
        with self.assertRaisesRegex(ValueError, 'template'):
            review.complete_grant(case, read(case['grant_file']) + b'Copyright [yyyy] [name of copyright owner]\n')

    def test_root_tree_and_raw_grant_need_exact_repository_revision_origin(self):
        case = copy.deepcopy(DATA['cases'][0])
        entries = review.compiler.tree_entries(case, read, LEDGER['requests'])
        review.primary_body(case, case['grant_file'], case['grant_upstream_path'], entries, read, LEDGER['requests'])
        case['repository'] = 'wrong/repository'
        with self.assertRaisesRegex(ValueError, 'repository receipt'):
            review.compiler.tree_entries(case, read, LEDGER['requests'])
        with self.assertRaisesRegex(ValueError, 'HTTP receipt'):
            review.primary_body(case, case['grant_file'], case['grant_upstream_path'], entries, read, LEDGER['requests'])

    def test_nonancestor_license_cannot_gain_scope_without_both_declarations(self):
        case = copy.deepcopy(next(c for c in DATA['cases'] if c['component'] == 'tenthash-1.1.0'))
        entries = review.compiler.tree_entries(case, read, LEDGER['requests'])
        for patch in [{'scope_readmes': case['scope_readmes'][:1]}, {'grant_upstream_path': 'licenses/OTHER.txt'},
                      {'component': 'another-1.1.0'}, {'manifest_path': 'reference/rust/Cargo.toml'}]:
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                review.grant_scope({**case, **patch}, [], entries, read, LEDGER['requests'])

    def test_sibling_grant_not_allowed_for_other_packages(self):
        case = copy.deepcopy(DATA['cases'][0])
        case['grant_upstream_path'] = 'another/LICENSE'
        with self.assertRaisesRegex(ValueError, 'outside proved package scope'):
            review.grant_scope(case, [], {}, read, LEDGER['requests'])

    def test_http_errors_redirects_budget_and_deadline_count(self):
        result = review.network_summary(LEDGER)
        self.assertEqual((result['new_actual_HTTP_requests'], result['new_response_body_bytes']), (13, 269861))
        ledger = {'requests': [{'ordinal': i, 'bytes': 1, 'HTTP': code} for i, code in enumerate([301, 200, 422], 1)],
                  'body_bytes': 3, 'started_epoch': 0, 'stopped_epoch': 1199, 'acquisition_closed': True}
        self.assertEqual(review.network_summary(ledger)['redirect_or_error_requests'], [1, 3])
        for patch in [{'stopped_epoch': 1201}, {'body_bytes': 4}, {'acquisition_closed': False},
                      {'requests': [{'ordinal': i, 'bytes': 0} for i in range(1, 22)], 'body_bytes': 0},
                      {'requests': [{'ordinal': 1, 'bytes': 16 * 1024**2 + 1}], 'body_bytes': 16 * 1024**2 + 1}]:
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                review.network_summary({**ledger, **patch})

    def test_acquisition_closed_before_a_new_request(self):
        fetch = review.preceding.module('finite_d_fetch', HERE / 'fetch.py')
        with self.assertRaisesRegex(ValueError, 'acquisition is closed'):
            fetch.acquire('https://api.github.com/repos/unused/unused', 'unused.json')

    @unittest.skipUnless(PACKET.exists(), 'private source packet deliberately not distributed')
    def test_real_replay_four_package_joins_96_remaining_all_broader_holds(self):
        result = review.evaluate(PACKET)
        self.assertEqual(result, json.loads((HERE / 'report.json').read_text()))
        self.assertEqual((result['baseline_unresolved'], result['new_scoped_package_notice_cases_closed'], result['remaining_unresolved']), (100, 4, 96))
        self.assertEqual(result['closed_components'], ['alloc-stdlib-0.2.4', 'dateparser-0.2.1', 'tenthash-1.1.0', 'tera-2.0.0'])
        self.assertEqual(result['framework_attempt']['closure_credit'], 0)
        for case in result['cases']:
            self.assertEqual(case['actual_target_activation'], 'NOT_PROVED')
            self.assertEqual(case['full_vendor_projection_all_file_legal_native_release_acceptance'], 'HELD')
            self.assertEqual(case['lock_membership'], {'Cargo.lock': False, 'src/tools/cargo/Cargo.lock': False})
        tenthash = next(c for c in result['cases'] if c['component'] == 'tenthash-1.1.0')
        self.assertTrue(tenthash['scope_evidence']['package_README_matches_authenticated_vendor_capture'])
        self.assertEqual(len(tenthash['scope_evidence']['readme_evidence']), 2)
        for component in ['spanned-0.4.1', 'objc2-core-foundation-0.3.2', 'wasmparser-0.243.0',
                          'intl_pluralrules-7.0.2', 'polonius-engine-0.13.0', 'perf-event-open-sys-3.0.0']:
            self.assertIn(component, result['remaining_components'])


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    signal.alarm(30)
    unittest.main()
