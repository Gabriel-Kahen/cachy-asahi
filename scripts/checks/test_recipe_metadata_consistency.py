#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite declared-metadata controls. No shell sourcing, package or native actors."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('literal_consistency', HERE / 'recipe_metadata_consistency.py')
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
ROOT = HERE.parents[1]
SHA = 'a' * 64
RECIPE = f"""pkgname=example
pkgver=1.2
pkgrel=1
arch=('aarch64')
depends=('python>=3.12')
provides=('example-api=1')
source=('one.tar.gz')
sha256sums=('{SHA}')

package() {{
    printf 'body not executed'
}}
"""
INFO = f"""pkgbase = example
pkgver = 1.2
pkgrel = 1
arch = aarch64
depends = python>=3.12
provides = example-api=1
source = one.tar.gz
sha256sums = {SHA}
pkgname = example
"""


class ConsistencyTests(unittest.TestCase):
    def result(self, recipe=RECIPE, info=INFO):
        return C.compare(recipe, info)

    def mismatch(self, recipe, info, field):
        result = self.result(recipe, info)
        self.assertEqual(result['status'], 'MISMATCH', result)
        self.assertIn(field, [x['field'] for x in result['mismatches']])

    def unsupported(self, recipe=RECIPE, info=INFO):
        result = self.result(recipe, info)
        self.assertEqual(result['status'], 'UNSUPPORTED', result)
        self.assertTrue(result['unsupported'])
        self.assertFalse(result['shell_evaluation'])

    def test_matching_declared_subset_and_explicit_limits(self):
        result = self.result(RECIPE.replace('pkgver=1.2', "pkgdesc='description'\npkgver=1.2"))
        self.assertEqual(result['status'], 'MATCH_MODELED_LITERAL_DECLARATIONS')
        self.assertEqual(result['ignored_fields']['PKGBUILD'], ['pkgdesc'])
        self.assertEqual(result['opaque_stage_functions'], ['package'])
        self.assertIn('NOT_RECIPE_SAFETY', result['qualification'])

    def test_stale_version(self):
        self.mismatch(RECIPE, INFO.replace('pkgver = 1.2', 'pkgver = 1.1'), 'pkgver')

    def test_default_and_numeric_epoch(self):
        self.assertEqual(self.result(info=INFO.replace('pkgver =', 'epoch = 00\npkgver ='))['status'],
                         'MATCH_MODELED_LITERAL_DECLARATIONS')

    def test_stale_epoch(self):
        self.mismatch(RECIPE, INFO.replace('pkgver =', 'epoch = 2\npkgver ='), 'epoch')

    def test_excessive_epoch_is_unsupported_without_integer_conversion(self):
        self.unsupported(RECIPE + 'epoch=' + '1' * 5000 + '\n')

    def test_stale_release(self):
        self.mismatch(RECIPE, INFO.replace('pkgrel = 1', 'pkgrel = 1.1'), 'pkgrel')

    def test_stale_dependency(self):
        self.mismatch(RECIPE, INFO.replace('python>=3.12', 'python>=3.11'), 'depends')

    def test_stale_provides(self):
        self.mismatch(RECIPE, INFO.replace('example-api=1', 'example-api=2'), 'provides')

    def test_stale_source_checksum(self):
        self.mismatch(RECIPE, INFO.replace(SHA, 'b' * 64), 'sha256sums')

    def test_source_and_checksum_order_are_preserved(self):
        recipe = RECIPE.replace("'one.tar.gz'", "'one.tar.gz' 'two.tar.gz'").replace(f"'{SHA}'", f"'{SHA}' '{'b' * 64}'")
        info = INFO.replace('source = one.tar.gz', 'source = two.tar.gz\nsource = one.tar.gz').replace(
            'sha256sums = ' + SHA, 'sha256sums = ' + 'b' * 64 + '\nsha256sums = ' + SHA)
        self.mismatch(recipe, info, 'source')
        self.mismatch(recipe, info, 'sha256sums')

    def test_stale_architecture(self):
        self.mismatch(RECIPE, INFO.replace('arch = aarch64', 'arch = x86_64'), 'arch')

    def test_architecture_qualified_groups_compare(self):
        recipe = RECIPE.replace('depends=', "depends_aarch64=('extra>=2')\ndepends=")
        info = INFO.replace('depends =', 'depends_aarch64 = extra>=2\ndepends =')
        self.assertEqual(self.result(recipe, info)['status'], 'MATCH_MODELED_LITERAL_DECLARATIONS')
        self.mismatch(recipe, info.replace('extra>=2', 'extra>=3'), 'depends_aarch64')

    def test_qualified_group_outside_declared_arch_is_unsupported(self):
        self.unsupported(RECIPE + "depends_x86_64=('extra')\n")

    def test_split_packages_are_unsupported(self):
        self.unsupported(RECIPE.replace('pkgname=example', "pkgname=('one' 'two')"))
        self.unsupported(info=INFO + 'pkgname = another\n')

    def test_expansion_command_substitution_and_redirection_are_unsupported(self):
        for value in ('"$version"', '$(touch sentinel)', '1.2; touch sentinel', '`id`', '1.2 > sentinel'):
            with self.subTest(value=value):
                self.unsupported(RECIPE.replace('pkgver=1.2', 'pkgver=' + value))

    def test_dynamic_pkgver_function_and_conditionals_are_unsupported(self):
        self.unsupported(RECIPE + 'pkgver() {\n    echo 2\n}\n')
        self.unsupported('if true; then\n' + RECIPE + 'fi\n')

    def test_duplicate_amended_compound_and_tail_assignments_are_unsupported(self):
        for text in (RECIPE + 'pkgver=2\n', RECIPE + "depends+=('extra')\n",
                     RECIPE.replace("'python>=3.12'", "'python'\"${version}\""),
                     RECIPE.replace("depends=('python>=3.12')", "depends=('python>=3.12'); echo bad")):
            with self.subTest(text=text):
                self.unsupported(text)

    def test_relation_order_duplicates_and_optional_reasons(self):
        recipe = RECIPE.replace("'python>=3.12'", "'b' 'python>=3.12' 'b'") + "optdepends=('editor: optional editor')\n"
        info = INFO.replace('depends = python>=3.12', 'depends = python>=3.12\ndepends = b') + 'optdepends = editor: optional editor\n'
        self.assertEqual(self.result(recipe, info)['status'], 'MATCH_MODELED_LITERAL_DECLARATIONS')

    def test_checksum_algorithms_and_skip_compare_as_declarations(self):
        recipe = RECIPE.replace('sha256sums=', 'sha512sums=').replace(SHA, 'a' * 128)
        info = INFO.replace('sha256sums =', 'sha512sums =').replace(SHA, 'a' * 128)
        self.assertEqual(self.result(recipe, info)['status'], 'MATCH_MODELED_LITERAL_DECLARATIONS')
        self.assertEqual(self.result(RECIPE.replace(SHA, 'SKIP'), INFO.replace(SHA, 'SKIP'))['status'],
                         'MATCH_MODELED_LITERAL_DECLARATIONS')

    def test_unpaired_sources_and_bad_checksum_are_unsupported(self):
        self.unsupported(RECIPE.replace(SHA, 'not-a-checksum'))
        self.unsupported(RECIPE.replace("sha256sums=('" + SHA + "')", 'sha256sums=()'))

    def test_comments_multiline_arrays_and_quoted_literal_dollar(self):
        recipe = RECIPE.replace("source=('one.tar.gz')", "source=(\n  # explicit source\n  'one.tar.gz'\n)")
        self.assertEqual(self.result(recipe)['status'], 'MATCH_MODELED_LITERAL_DECLARATIONS')
        self.assertEqual(self.result(RECIPE.replace('one.tar.gz', '$literal'), INFO.replace('one.tar.gz', '$literal'))['status'],
                         'MATCH_MODELED_LITERAL_DECLARATIONS')

    def cli(self, root, recipe=RECIPE, info=INFO):
        (root / 'PKGBUILD').write_text(recipe)
        (root / '.SRCINFO').write_text(info)
        return subprocess.run([sys.executable, '-I', '-B', str(HERE / 'recipe_metadata_consistency.py'), str(root / 'PKGBUILD')],
                              capture_output=True, text=True, timeout=10, check=False)

    def test_actual_cli_status_pins_and_no_recipe_execution(self):
        with tempfile.TemporaryDirectory(prefix='metadata-consistency-') as temporary:
            root = Path(temporary)
            sentinel = root / 'must-not-exist'
            recipe = RECIPE.replace("printf 'body not executed'", 'touch ' + str(sentinel))
            result = self.cli(root, recipe)
            value = json.loads(result.stdout)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(value['inputs']['PKGBUILD']['sha256'], hashlib.sha256(recipe.encode()).hexdigest())
            self.assertFalse(sentinel.exists())
            mismatch = self.cli(root, recipe, INFO.replace('pkgver = 1.2', 'pkgver = 2'))
            self.assertEqual(mismatch.returncode, 1)
            unsupported = self.cli(root, recipe + 'touch ' + str(sentinel) + '\n')
            self.assertEqual(unsupported.returncode, 2)
            self.assertEqual(json.loads(unsupported.stdout)['status'], 'UNSUPPORTED')
            self.assertFalse(sentinel.exists())

    def test_symlink_hardlink_and_oversized_inputs_are_refused(self):
        with tempfile.TemporaryDirectory(prefix='metadata-inputs-') as temporary:
            root = Path(temporary)
            original = root / 'original'
            original.write_text(RECIPE)
            alias = root / 'alias'
            alias.symlink_to(original)
            with self.assertRaises(C.Unsupported):
                C.read(alias)
            alias.unlink()
            os.link(original, alias)
            with self.assertRaises(C.Unsupported):
                C.read(original)
            alias.unlink()
            original.write_bytes(b'x' * (C.MAX_BYTES + 1))
            with self.assertRaises(C.Unsupported):
                C.read(original)

    def test_read_only_current_real_build_tools_recipe(self):
        directory = ROOT / 'packages/tools/cachy-asahi-build-tools'
        paths = [directory / 'PKGBUILD', directory / '.SRCINFO']
        before = [(p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns) for p in paths]
        recipe, rp = C.read(paths[0])
        info, ip = C.read(paths[1])
        result = self.result(recipe, info)
        self.assertEqual(result['status'], 'MATCH_MODELED_LITERAL_DECLARATIONS', result)
        self.assertTrue(rp['sha256'] and ip['sha256'])
        self.assertEqual([(p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns) for p in paths], before)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', type=Path, default=ROOT)
    args, remaining = parser.parse_known_args()
    ROOT = args.root.resolve()
    unittest.main(argv=[sys.argv[0], *remaining])
