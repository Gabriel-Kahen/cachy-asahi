"""Meaningful regression cases for scope, recipe parsing and evidence corruption."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('source_plan', Path(__file__).with_name('check.py'))
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.config = plan.recipe_config()
        self.rows = plan.read_json(plan.HERE.parent / 'submodule-closure/report.json')['submodules']

    def classify(self):
        return {r['path']: r['classification'] for r in plan.classify(self.config, self.rows)}

    def test_optional_gcc_gap_does_not_block_exact_recipe(self):
        self.assertEqual(self.classify()['src/gcc'], 'NOT_SELECTED_LLVM_BACKEND')
        self.config['rust']['codegen-backends'] = ['llvm', 'gcc']
        self.assertEqual(self.classify()['src/gcc'], 'MISSING_PAYLOAD_IF_GCC_BACKEND_SELECTED')

    def test_docs_and_enzyme_flags_change_source_selection(self):
        result = self.classify()
        self.assertTrue(all(v == 'NOT_SELECTED_DOCS_DISABLED' for k, v in result.items() if k.startswith('src/doc/')))
        self.assertEqual(result['src/tools/enzyme'], 'NOT_SELECTED_ENZYME_DISABLED')
        self.config['build']['docs'] = True
        self.config['llvm']['enzyme'] = True
        result = self.classify()
        self.assertEqual(result['src/doc/book'], 'REQUIRED_IF_DOCS_ENABLED')
        self.assertEqual(result['src/tools/enzyme'], 'REQUIRED_IF_ENZYME_ENABLED')

    def test_external_llvm_does_not_erase_source_need(self):
        self.assertEqual(self.classify()['src/llvm-project'], 'REPLACED_EXTERNAL_LLVM_SOURCE_STILL_REQUIRED')
        del self.config['target']['aarch64-unknown-linux-gnu']['llvm-config']
        self.assertEqual(self.classify()['src/llvm-project'], 'RUST_LLVM_SOURCE_REQUIRED')

    def test_dist_defaults_and_explicit_overrides(self):
        self.assertEqual(self.config['build']['build-stage'], 2)
        self.assertTrue(self.config['build']['extended'])
        self.assertFalse(self.config['rust']['download-rustc'])
        self.assertFalse(self.config['rust']['llvm-bitcode-linker'])
        self.assertEqual(self.config['rust']['channel'], 'stable')
        self.assertEqual(self.config['dist']['compression-profile'], 'fast')

    def test_unknown_source_identity_fails_closed(self):
        rows = copy.deepcopy(self.rows)
        rows[0]['path'] = 'src/unreviewed'
        with self.assertRaisesRegex(ValueError, 'unreviewed'):
            plan.classify(self.config, rows)

    def test_changed_evidence_manifest_rejected(self):
        original = plan.HERE
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'records').mkdir()
            (root / 'records/pins.json').write_text('{}\n')
            plan.HERE = root
            try:
                with self.assertRaisesRegex(ValueError, 'manifest changed'):
                    plan.verify_inputs()
            finally:
                plan.HERE = original

    def test_deterministic_report_and_unresolved_correspondence(self):
        report = plan.make_plan()
        self.assertEqual(report, plan.read_json(plan.HERE / 'report.json'))
        self.assertEqual(len(report['original_binary_recipe_correspondence']), 4)
        self.assertTrue(all(r['status'] == 'UNRESOLVED' and len(r['original_sha256']) == 64 for r in report['original_binary_recipe_correspondence'].values()))
        self.assertEqual(report['limits_and_actual_work']['metadata_requests'], 8)
        self.assertEqual(report['limits_and_actual_work']['response_bytes'], 1015552)


if __name__ == '__main__':
    unittest.main()
