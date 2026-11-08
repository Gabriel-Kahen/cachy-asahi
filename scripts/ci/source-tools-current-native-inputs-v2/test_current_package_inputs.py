#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source/recipe binding controls only; no native or recipe actor is run."""
import argparse
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('current_package_inputs', HERE / 'current_package_inputs.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fixture(root):
    files = {path.name: path.read_bytes() for path in root.iterdir() if path.is_file()}
    pins = {name: m.pin(raw, 0o755 if name == m.NAME else 0o644) for name, raw in files.items()}
    mapping = json.loads(files['payload-map.json'])
    payload = dict(mapping['files'])
    payload[mapping['self']] = m.pin(files['payload-map.json'])
    return dict(schema=2, purpose='source-tools-current-recipe-selection',
        package=dict(name=m.NAME, version=m.VERSION, arch='any', license='MIT'),
        recipe=dict(sources=list(m.SOURCES), files=pins, payload_files=payload),
        checks=dict(m.CHECKS), dependencies=copy.deepcopy(m.DEPENDENCIES),
        frozen_private_runtime=dict(archive=pins['private-source.tar.gz'],
            provenance=pins['source-provenance.json'], files=json.loads(files['source-provenance.json'])['files']),
        provenance=dict(Main='f15f487113ae14586b3b206bd2c0240483b82f28', PR=362,
            head='cebc57effd170aacf145aaf3c3de9b5a3ee48360', fixture='LOCAL_CURRENT_PACKAGE_SNAPSHOT_NOT_NATIVE'))


class RecipeBinding(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='current-recipe-data-')
        self.root = Path(self.temp.name) / 'recipe'
        shutil.copytree(RECIPE, self.root)
        self.choice = fixture(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def change(self, name, transform, repin=False):
        path = self.root / name
        path.write_bytes(transform(path.read_bytes()))
        if repin:
            self.choice['recipe']['files'][name] = m.pin(path.read_bytes(), 0o755 if name == m.NAME else 0o644)

    def refuse(self):
        with self.assertRaises((ValueError, OSError, KeyError, tarfile.TarError)):
            m.validate_recipe(self.root, self.choice)

    def test_current_sixteen_files_eighteen_payload_and_frozen_eleven(self):
        data = m.validate_recipe(self.root, self.choice)
        self.assertEqual(set(data), m.FILES)
        self.assertEqual(len(self.choice['recipe']['sources']), 14)
        self.assertEqual(len(self.choice['recipe']['payload_files']), 18)
        self.assertEqual(len(self.choice['frozen_private_runtime']['files']), 11)

    def test_changed_catalog_helper_refuses(self):
        self.change('source_mirror_catalog.py', lambda body: body + b'\n# changed\n')
        self.refuse()

    def test_private_checkout_modes_normalize_to_canonical_delivery_modes(self):
        for path in self.root.iterdir():
            path.chmod(0o700 if path.name == m.NAME else 0o600)
        files = m.validate_recipe(self.root, self.choice)
        raw = m.recipe_bundle(files, self.choice)
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            self.assertTrue(all(node.mode == (0o755 if node.name == 'recipe/' + m.NAME else 0o644)
                                for node in archive))

    def test_changed_current_test_refuses(self):
        self.change('test_source_mirror_catalog.py', lambda body: body.replace(b'catalog', b'changed', 1))
        self.refuse()

    def test_missing_or_extra_source_refuses(self):
        path = self.root / 'test_source_mirror_catalog.py'
        raw = path.read_bytes()
        path.unlink()
        self.refuse()
        path.write_bytes(raw)
        (self.root / 'unlisted.py').write_bytes(b'not executed\n')
        self.refuse()

    def test_empty_directory_not_part_of_closed_recipe(self):
        (self.root / 'empty').mkdir()
        self.refuse()

    def test_symlink_leaf_and_ancestor_refuse(self):
        path = self.root / 'source_mirror_catalog.py'
        retained = Path(self.temp.name) / 'retained.py'
        path.rename(retained)
        path.symlink_to(retained)
        self.refuse()
        path.unlink()
        retained.rename(path)
        alias = Path(self.temp.name) / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            m.validate_recipe(alias, self.choice)

    def test_hardlink_and_executable_helper_refuse(self):
        path = self.root / 'source_mirror_catalog.py'
        link = Path(self.temp.name) / 'hardlink.py'
        os.link(path, link)
        self.refuse()
        link.unlink()
        path.chmod(0o755)
        self.refuse()

    def test_stale_old_version_and_old_thirteen_file_selection_refuse(self):
        self.change('PKGBUILD', lambda body: body.replace(b'pkgver=0.2.0', b'pkgver=0.1.0'), repin=True)
        self.refuse()
        choice = copy.deepcopy(self.choice)
        for name in ('source_mirror_catalog.py', 'test_source_mirror_catalog.py', 'test_cli_input_refusal.py'):
            choice['recipe']['files'].pop(name)
            choice['recipe']['sources'].remove(name)
        with self.assertRaises(ValueError):
            m.selection(choice)

    def test_srcinfo_recipe_identity_mismatch_refuses_even_when_repinning(self):
        self.change('.SRCINFO', lambda body: body.replace(b'\tpkgrel = 1', b'\tpkgrel = 2'), repin=True)
        self.refuse()

    def test_repeated_source_and_recipe_checksum_mismatch_refuse(self):
        self.change('PKGBUILD', lambda body: body.replace(b'source=(private-source.tar.gz ',
            b'source=(private-source.tar.gz private-source.tar.gz '), repin=True)
        self.refuse()
        self.change('PKGBUILD', lambda body: body.replace(b'private-source.tar.gz private-source.tar.gz ',
            b'private-source.tar.gz '), repin=True)
        self.change('.SRCINFO', lambda body: body.replace(m.PRIVATE_SHA.encode(), b'0' * 64), repin=True)
        self.refuse()

    def test_legacy_payload_and_bool_counts_refuse(self):
        choice = copy.deepcopy(self.choice)
        choice['recipe']['payload_files'].pop('usr/lib/cachy-asahi/source-tools/scripts/release/source_mirror_catalog.py')
        with self.assertRaises(ValueError):
            m.selection(choice)
        for field, value in (('schema', True), ('checks', dict(m.CHECKS, private_helpers=True))):
            choice = copy.deepcopy(self.choice)
            choice[field] = value
            with self.assertRaises(ValueError):
                m.selection(choice)

    def test_frozen_private_runtime_cannot_be_rebound(self):
        self.change('private-source.tar.gz', lambda body: body + b'changed', repin=True)
        self.choice['frozen_private_runtime']['archive'] = self.choice['recipe']['files']['private-source.tar.gz']
        self.refuse()

    def test_canonical_package_tar_roundtrip_and_determinism(self):
        files = m.validate_recipe(self.root, self.choice)
        raw = m.recipe_bundle(files, self.choice)
        self.assertEqual(m.verify_bundle(raw, self.choice), files)
        self.assertEqual(raw, m.recipe_bundle(dict(reversed(list(files.items()))), self.choice))
        with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
            self.assertEqual(len(archive.getmembers()), 16)
        self.assertEqual(files['private-source.tar.gz'], (RECIPE / 'private-source.tar.gz').read_bytes())

    def test_tar_extra_member_mode_and_trailing_bytes_refuse(self):
        files = m.validate_recipe(self.root, self.choice)
        raw = m.recipe_bundle(files, self.choice)
        for bad in (raw + b'extra', raw[:-1024], b'not a tar'):
            with self.assertRaises((ValueError, tarfile.TarError)):
                m.verify_bundle(bad, self.choice)
        for mode, extra in ((0o755, False), (0o644, True)):
            output = io.BytesIO()
            with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                for name, body in sorted(files.items()):
                    node = tarfile.TarInfo('recipe/' + name)
                    node.size = len(body)
                    node.mode = mode if name == 'source_mirror_catalog.py' else self.choice['recipe']['files'][name]['mode']
                    archive.addfile(node, io.BytesIO(body))
                if extra:
                    node = tarfile.TarInfo('recipe/extra')
                    node.size, node.mode = 1, 0o644
                    archive.addfile(node, io.BytesIO(b'x'))
            with self.assertRaises(ValueError):
                m.verify_bundle(output.getvalue(), self.choice)

    def test_unknown_selection_fields_and_missing_current_check_refuse(self):
        choice = copy.deepcopy(self.choice)
        choice['fallback'] = True
        with self.assertRaises(ValueError):
            m.selection(choice)
        choice = copy.deepcopy(self.choice)
        choice['recipe']['files'] = list(m.FILES)
        with self.assertRaises(ValueError):
            m.selection(choice)
        self.change('PKGBUILD', lambda body: body.replace(b'$srcdir/test_source_mirror_catalog.py',
            b'$srcdir/other_test.py'), repin=True)
        self.refuse()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe-root', type=Path, required=True)
    args = parser.parse_args()
    RECIPE = args.recipe_root.resolve()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RecipeBinding)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = dict(status='PASS' if result.wasSuccessful() and not result.skipped else 'FAIL',
        tests=result.testsRun, failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped),
        package=m.NAME, version=m.VERSION, source_files=14, recipe_files=16,
        payload_files=18, frozen_private_helpers=11, evidence='PURE_PACKAGE_DATA_BINDING_NOT_NATIVE',
        native='NOT_RUN', Source_constructor='NOT_RUN', installation='NOT_RUN')
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(report['status'] != 'PASS')
