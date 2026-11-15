"""Fenced file correspondence and feature-declaration controls; zero HTTP."""
import copy
import importlib.util
import json
from pathlib import Path
import resource
import signal
import tomllib
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('notice_c', HERE / 'reevaluate.py')
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)
DATA = json.loads((HERE / 'cases.json').read_text())
LEDGER = json.loads((HERE / 'requests.json').read_text())
PACKET = Path('/tmp/cachy-checksum-successor-20261115-03/private-license-candidates.json')


def read(name):
    return (HERE / name).read_bytes()


class Controls(unittest.TestCase):
    def test_source_html_extracts_data_without_page_or_script_text(self):
        self.assertEqual(review.source_text.extract(b'<script>ignore()</script><div id="source-code"><pre><code>A &lt; B\n</code></pre></div>tail'), b'A < B\n')
        for body in [b'no source', b'<div id="source-code">open',
                     b'<div id="source-code">one</div><div id="source-code">two</div>']:
            with self.subTest(body=body), self.assertRaises(ValueError):
                review.source_text.extract(body)

    def test_vendor_full_hash_and_captured_prefix_both_required(self):
        body = b'Copyright Actual Holder\nfull retained source\n'
        prefix = body[:12]
        record = {**review.pin(body), 'text': prefix.decode(), 'captured_bytes': len(prefix),
                  'captured_prefix_sha256': review.pin(prefix)['sha256'], 'complete_text': False, 'utf8_replacement_used': False}
        review.vendor_source_match(record, body)
        for replacement in [body + b'changed', b'X' + body[1:]]:
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                review.vendor_source_match(record, replacement)
        changed = {**record, 'text': 'wrong prefix', 'captured_bytes': 12}
        with self.assertRaisesRegex(ValueError, 'prefix'):
            review.vendor_source_match(changed, body)

    def test_docs_original_manifest_has_exact_published_vcs_git_join(self):
        document = tomllib.loads(read('../../primary-b/rustc_codegen_ssa-Cargo.toml').decode())
        review.object_declarations(read, LEDGER['requests'], DATA, document)
        changed = copy.deepcopy(DATA)
        changed['object_source']['commit'] = 'a' * 40
        with self.assertRaisesRegex(ValueError, 'VCS identity'):
            review.object_declarations(read, LEDGER['requests'], changed, document)
        def tampered(name):
            if name == 'evidence/object-Cargo.toml.orig':
                return read(name) + b'#changed\n'
            return read(name)
        with self.assertRaisesRegex(ValueError, 'extraction changed'):
            review.object_declarations(tampered, LEDGER['requests'], DATA, document)

    def test_compiler_optional_or_unselected_object_wasm_edge_refused(self):
        document = tomllib.loads(read('../../primary-b/rustc_codegen_ssa-Cargo.toml').decode())
        for field, value in [('optional', True), ('features', ['read_core']), ('version', '0.38.0')]:
            changed = copy.deepcopy(document)
            changed['dependencies']['object'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'compiler object/wasm'):
                review.object_declarations(read, LEDGER['requests'], DATA, changed)

    def test_wrong_repository_or_source_origin_cannot_reuse_matching_bytes(self):
        case = copy.deepcopy(DATA['case'])
        review.compiler.tree_entries(case, read, LEDGER['requests'])
        case['repository'] = 'wrong/repository'
        with self.assertRaisesRegex(ValueError, 'repository receipt'):
            review.compiler.tree_entries(case, read, LEDGER['requests'])
        with self.assertRaisesRegex(ValueError, 'HTTP receipt'):
            review.receipt(LEDGER['requests'], 'https://raw.githubusercontent.com/wrong/repo/commit/src/lib.rs', read('evidence/wasm243-lib.rs'))

    def test_notice_is_file_only_and_sibling_grants_are_refused(self):
        case = DATA['case']
        body = read(case['source_file'])
        review.compiler.notice_review(body, case['manual_named_notice'])
        review.compiler.file_notice_scope(case['manifest_path'], case['source_path'], case['grant_upstream_path'])
        with self.assertRaisesRegex(ValueError, 'sibling package'):
            review.compiler.file_notice_scope(case['manifest_path'], 'crates/wasm-encoder/src/lib.rs', 'LICENSE-APACHE')
        with self.assertRaisesRegex(ValueError, 'ancestor scope'):
            review.compiler.file_notice_scope(case['manifest_path'], case['source_path'], 'crates/wasm-encoder/LICENSE-APACHE')

    def test_network_errors_redirects_and_time_still_count(self):
        result = review.network_summary(LEDGER)
        self.assertEqual((result['new_actual_HTTP_requests'], result['new_response_body_bytes']), (11, 392546))
        ledger = {'requests': [{'ordinal': i, 'bytes': 1, 'HTTP': s} for i, s in enumerate([301, 200, 422], 1)],
                  'body_bytes': 3, 'started_epoch': 0, 'stopped_epoch': 1199, 'acquisition_closed': True}
        self.assertEqual(review.network_summary(ledger)['redirect_or_error_requests'], [1, 3])
        for patch in [{'stopped_epoch': 1201}, {'body_bytes': 4}, {'acquisition_closed': False},
                      {'requests': [{'ordinal': i, 'bytes': 0} for i in range(1, 22)], 'body_bytes': 0},
                      {'requests': [{'ordinal': 1, 'bytes': 16 * 1024**2 + 1}], 'body_bytes': 16 * 1024**2 + 1}]:
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                review.network_summary({**ledger, **patch})

    def test_closed_acquisition_refuses_without_a_request(self):
        fetch = review.module('finite_c_fetch', HERE / 'fetch.py')
        with self.assertRaisesRegex(ValueError, 'acquisition closed'):
            fetch.fetch('https://docs.rs/crate/object/0.38.1/source/Cargo.toml', HERE / 'evidence/unused', HERE / 'requests.json')

    @unittest.skipUnless(PACKET.exists(), 'private source packet deliberately not distributed')
    def test_real_replay_has_zero_package_credit_and_preserves_object_mismatch(self):
        result = review.evaluate(PACKET)
        self.assertEqual(result, json.loads((HERE / 'report.json').read_text()))
        self.assertEqual((result['new_package_root_notice_cases_closed'], result['remaining_unresolved']), (0, 100))
        self.assertEqual(result['new_exact_vendor_source_file_notice_joins'], 1)
        self.assertEqual(result['workspace_version_holds_resolved'], 1)
        self.assertIn('UNRESOLVED_DIFFERENT_BYTES', result['object_source_declarations']['normalized_vendor_byte_correspondence'])
        self.assertIn('NOT_PROVED', result['object_source_declarations']['object_vendor_original_manifest_and_VCS_correspondence'])
        self.assertEqual(result['Linux_aarch64_Cargo_cfg_feature_resolution'], 'NOT_EXECUTED_OR_PROVED')
        self.assertEqual(result['package_all_file_legal_native_M2_release_acceptance'], 'HELD')
        self.assertIn('ONLY', result['file_notice']['scope'])
        for component in ['wasmparser-0.243.0', 'spanned-0.4.1', 'intl_pluralrules-7.0.2', 'polonius-engine-0.13.0', 'perf-event-open-sys-3.0.0']:
            self.assertIn(component, result['remaining_components'])


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    signal.alarm(30)
    unittest.main()
