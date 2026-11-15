"""Negative controls for scope, provenance, version inheritance and budgets."""
import copy
import importlib.util
import json
from pathlib import Path
import resource
import signal
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('notices', HERE / 'reevaluate.py')
review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(review)
PACKET = Path('/tmp/cachy-checksum-successor-20261115-03/private-license-candidates.json')


def fixture():
    orig = b'[package]\nname="one"\nversion.workspace=true\nlicense.workspace=true\n'
    workspace = b'[workspace.package]\nversion="1.2.3"\nlicense="MIT OR Apache-2.0"\n'
    vcs = json.dumps({'git': {'sha1': 'a' * 40}, 'path_in_vcs': 'crates/one'}).encode()
    captures = [{'path': 'vendor/one/' + name, 'text': body.decode(), 'complete_text': True, **review.prior.pin(body)}
                for name, body in [('Cargo.toml.orig', orig), ('.cargo_vcs_info.json', vcs)]]
    case = {'component': 'one-1.2.3', 'commit': 'a' * 40, 'repository': 'example/one',
            'manifest_path': 'crates/one/Cargo.toml', 'workspace_manifest': 'workspace'}
    entries = {'crates/one/Cargo.toml': {'sha': review.prior.blob(orig)},
               'Cargo.toml': {'sha': review.prior.blob(workspace)}}
    return case, captures, entries, lambda _: workspace


class Controls(unittest.TestCase):
    def test_workspace_version_comes_from_workspace_not_root_package(self):
        case, captures, entries, read = fixture()
        self.assertTrue(review.binding(case, captures, entries, read)['workspace_version_resolved'])
        case['component'] = 'one-9.9.9'
        with self.assertRaisesRegex(ValueError, 'exact package version'):
            review.binding(case, captures, entries, read)
        case['component'] = 'one-1.2.3'
        with self.assertRaisesRegex(ValueError, 'workspace manifest Git blob'):
            review.binding(case, captures, entries, lambda _: read('') + b'#changed')

    def test_dirty_commit_version_and_path_holds(self):
        for patch in [{'git': {'sha1': 'a' * 40, 'dirty': True}},
                      {'git': {'sha1': 'b' * 40}},
                      {'git': {'sha1': 'a' * 40}, 'path_in_vcs': 'sibling'}]:
            case, captures, entries, read = fixture()
            captures[1]['text'] = json.dumps(patch)
            captures[1].update(review.prior.pin(captures[1]['text'].encode()))
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                review.binding(case, captures, entries, read)

    def test_wrong_repository_root_receipt_rejected(self):
        data = json.loads((HERE / 'cases.json').read_text())
        case = copy.deepcopy(next(c for c in data['cases'] if c['component'] == 'valuable-0.1.1'))
        receipts = json.loads((HERE / 'requests.json').read_text())['requests']
        read = lambda name: (HERE / name).read_bytes()
        self.assertIn('valuable/Cargo.toml', review.tree_entries(case, read, receipts))
        case['repository'] = 'wrong/repository'
        with self.assertRaisesRegex(ValueError, 'repository receipt'):
            review.tree_entries(case, read, receipts)

    def test_tree_shard_cannot_move_between_package_ancestors(self):
        data = json.loads((HERE / 'cases.json').read_text())
        case = copy.deepcopy(next(c for c in data['cases'] if c['component'] == 'wasmparser-0.219.2'))
        receipts = json.loads((HERE / 'requests.json').read_text())['requests']
        read = lambda name: (HERE / name).read_bytes()
        review.tree_entries(case, read, receipts)
        case['tree_shards'][1]['file'] = 'evidence/wasm219-wasm-encoder-tree.json'
        with self.assertRaisesRegex(ValueError, 'ancestor Git ID'):
            review.tree_entries(case, read, receipts)

    def test_file_notice_does_not_cover_sibling_or_accept_sibling_grant(self):
        review.file_notice_scope('crates/one/Cargo.toml', 'crates/one/src/lib.rs', 'LICENSE')
        for source, grant in [('crates/two/src/lib.rs', 'LICENSE'), ('crates/one/src/lib.rs', 'crates/two/LICENSE')]:
            with self.subTest(source=source, grant=grant), self.assertRaises(ValueError):
                review.file_notice_scope('crates/one/Cargo.toml', source, grant)

    def test_template_notice_and_incomplete_grant_rejected(self):
        with self.assertRaisesRegex(ValueError, 'template'):
            review.notice_review(b'Copyright [yyyy] [name of copyright owner]\n', 'Copyright [yyyy] [name of copyright owner]')
        with self.assertRaisesRegex(ValueError, 'complete grant'):
            review.grant_review('Apache-2.0', b'Apache License Version 2.0, January 2004')

    def test_errors_redirects_capped_bodies_and_elapsed_budget_count(self):
        ledger = {'requests': [{'ordinal': n, 'HTTP': s, 'bytes': 1} for n, s in enumerate([301, 200, 422, None], 1)],
                  'body_bytes': 4, 'started_epoch': 0, 'stopped_epoch': 1199, 'acquisition_closed': True}
        self.assertEqual(review.network_summary(ledger)['new_actual_HTTP_requests'], 4)
        for patch in [{'stopped_epoch': 1201}, {'body_bytes': 3}, {'acquisition_closed': False},
                      {'requests': [{'ordinal': n, 'bytes': 0} for n in range(1, 42)], 'body_bytes': 0},
                      {'requests': [{'ordinal': 1, 'bytes': 16 * 1024**2 + 1}], 'body_bytes': 16 * 1024**2 + 1}]:
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                review.network_summary({**ledger, **patch})

    @unittest.skipUnless(PACKET.exists(), 'private packet intentionally not distributed')
    def test_actual_replay_retains_partial_and_all_remaining_holds(self):
        result = review.evaluate(PACKET)
        self.assertEqual(result, json.loads((HERE / 'report.json').read_text()))
        self.assertEqual(result['closed_components'], ['levenshtein-1.0.5', 'valuable-0.1.1'])
        self.assertEqual((result['remaining_unresolved'], result['exact_version_commit_bindings']), (106, 12))
        self.assertEqual(result['workspace_version_holds_resolved'], 2)
        for component in ['intl_pluralrules-7.0.2', 'polonius-engine-0.13.0', 'perf-event-open-sys-3.0.0',
                          'spanned-0.4.1', 'difflib-0.4.0', 'quine-mc_cluskey-0.2.4', 'wasmparser-0.219.2']:
            self.assertIn(component, result['remaining_components'])
        parser = next(c for c in result['cases'] if c['component'] == 'wasmparser-0.219.2')
        self.assertEqual(parser['status'], 'UNRESOLVED_ATTRIBUTION')
        self.assertIn('ONLY', parser['file_scoped_notice']['scope'])


if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
    signal.alarm(30)
    unittest.main()
