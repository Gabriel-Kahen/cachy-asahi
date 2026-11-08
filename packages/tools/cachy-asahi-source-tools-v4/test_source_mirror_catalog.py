#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real offline mirror catalogs; synthetic package archives stay inert DATA."""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='source-catalog-tests-')
        cls.root = Path(cls.temporary.name)
        cls.m = load('catalog_test_mirror', RUNTIME / 'release/release_source_mirror.py')
        cls.helper = load('catalog_under_test', HERE / 'source_mirror_catalog.py')
        cls.deps = cls.m.dependencies(RUNTIME / 'release')
        cls.fixtures = json.loads((FIXTURES / 'fixtures.json').read_bytes())['fixtures']
        cls.old, cls.current = cls.fixtures
        cls.single, _, _ = cls.m.build(FIXTURES / cls.old['label'], cls.old['release_sha256'],
            cls.deps, directory=RUNTIME / 'release')
        cls.history, _, _ = cls.m.update(cls.single, cls.m.digest(cls.single), cls.old['release_sha256'],
            FIXTURES / cls.current['label'], cls.current['release_sha256'], cls.deps, directory=RUNTIME / 'release')
        cls.consumer = load('catalog_context_consumer', RUNTIME / 'build/mirror_consumer.py')
        cls.consumer_deps = cls.consumer.dependencies(RUNTIME / 'build')

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def listing(self, raw=None, fixture=None):
        raw = self.history if raw is None else raw
        fixture = self.current if fixture is None else fixture
        return self.helper.catalog(raw, self.m.digest(raw), fixture['release_sha256'], self.m)

    def expected_packages(self, fixture):
        return [dict(package=p['name'], **{key: p[key] for key in
            ('version', 'arch', 'package_sha256', 'recipe_sha256', 'srcinfo_sha256')},
            source_profile='REVIEWED_ORIGINAL_RECIPE_PROFILE') for p in fixture['packages']]

    def test_single_release_exact_pins_and_boundaries(self):
        result = self.listing(self.single, self.old)
        self.assertEqual(result['packages'], self.expected_packages(self.old))
        self.assertEqual(result['retained_releases'], [dict(release_id='source-tools-two-package-legacy',
            release_sha256=self.old['release_sha256'])])
        self.assertEqual(result['head_release_sha256'], self.old['release_sha256'])
        self.assertFalse(result['legal_acceptance'])
        self.assertTrue(result['synthetic'])
        self.assertEqual(result['corresponding_source_completeness'], 'NOT_ASSERTED')
        self.assertEqual(result['native_build_validation'], 'NOT_PERFORMED')
        self.assertEqual(result['hardware_validation'], 'NOT_RUN')
        self.assertEqual(result['release_acceptance'], 'NOT_ADMITTED')

    def test_history_selects_exact_old_or_current_without_mixing(self):
        retained = [dict(release_id='source-tools-two-package-' + f['label'],
            release_sha256=f['release_sha256']) for f in self.fixtures]
        for fixture in self.fixtures:
            with self.subTest(release=fixture['label']):
                result = self.listing(fixture=fixture)
                self.assertEqual(result['packages'], self.expected_packages(fixture))
                self.assertEqual(result['release_sha256'], fixture['release_sha256'])
                self.assertEqual(result['head_release_sha256'], self.current['release_sha256'])
                self.assertEqual(result['retained_releases'], retained)
                self.assertEqual(result, self.listing(fixture=fixture))
        self.assertNotEqual(self.old['packages'][0]['version'], self.current['packages'][0]['version'])

    def test_listed_pins_materialize_and_verify_four_exact_contexts(self):
        for fixture in self.fixtures:
            for package in self.listing(fixture=fixture)['packages']:
                with self.subTest(release=fixture['label'], package=package['package']):
                    prepared = self.consumer.prepare(self.history, self.m.digest(self.history), fixture['release_sha256'],
                        *(package[key] for key in ('package', 'version', 'arch', 'package_sha256', 'recipe_sha256', 'srcinfo_sha256')),
                        self.consumer_deps)
                    output = self.root / (fixture['label'] + '-' + package['package'])
                    result = self.consumer.materialize(prepared, output, self.consumer_deps)
                    checked = self.consumer.verify_context(output, result['selection_sha256'], self.consumer_deps)
                    self.assertEqual(checked['package']['sha256'], package['package_sha256'])
                    self.assertTrue(all(value is None for value in prepared['native_request']['actual_selectors'].values()))
                    self.assertEqual(prepared['native_request']['native_build'], 'NOT_RUN')

    def test_wrong_mirror_pin_release_and_incomplete_mirrors_refuse(self):
        for raw, checksum, release in ((self.history, '0' * 64, self.current['release_sha256']),
                (self.history, self.m.digest(self.history), '0' * 64),
                (self.history + b'tamper', self.m.digest(self.history), self.current['release_sha256'])):
            with self.subTest(checksum=checksum, release=release), self.assertRaises(ValueError):
                self.helper.catalog(raw, checksum, release, self.m)
        files = self.m.canonical_files(self.history, self.m.digest(self.history))
        del files[next(key for key in files if key.startswith('objects/'))]
        raw = self.m.tar_bytes(files)
        with self.assertRaises(ValueError):
            self.helper.catalog(raw, self.m.digest(raw), self.current['release_sha256'], self.m)

    def test_corrupt_recovery_release_refuses_selected_current(self):
        files = self.m.canonical_files(self.history, self.m.digest(self.history))
        history = self.m.decode(files['history.json'])
        old_manifest = 'objects/' + history['releases'][0]['manifest']['sha256']
        files[old_manifest] += b' '
        raw = self.m.tar_bytes(files)
        with self.assertRaises(ValueError):
            self.helper.catalog(raw, self.m.digest(raw), self.current['release_sha256'], self.m)

    def test_archived_python_never_executes_and_catalog_has_no_side_effects(self):
        files = self.m.canonical_files(self.single, self.m.digest(self.single))
        files['verify.py'] = b"raise RuntimeError('ARCHIVED_VERIFIER_EXECUTED')\n"
        manifest = self.m.decode(files['mirror.json'])
        manifest['verifier_sha256'] = self.m.digest(files['verify.py'])
        files['mirror.json'] = self.m.encoded(manifest)
        raw = self.m.tar_bytes(files)
        forbidden = AssertionError('catalog must not execute, download, extract or write')
        with patch.object(socket, 'socket', side_effect=forbidden), \
             patch.object(socket, 'getaddrinfo', side_effect=forbidden), \
             patch.object(subprocess, 'Popen', side_effect=forbidden), \
             patch.object(os, 'open', side_effect=forbidden), \
             patch.object(Path, 'write_bytes', side_effect=forbidden):
            self.assertEqual(self.listing(raw, self.old)['packages'], self.expected_packages(self.old))

    def test_refusal_emits_no_partial_catalog(self):
        output = io.StringIO()
        with patch.object(self.helper, 'mirror_helper', return_value=self.m), \
             patch.object(self.m, 'read_file', return_value=self.history), contextlib.redirect_stdout(output):
            status = self.helper.main(['list', '--bundle', 'inert.tar', '--sha256', '0' * 64,
                '--release-sha256', self.current['release_sha256']])
        self.assertEqual(status, 1)
        self.assertEqual(set(json.loads(output.getvalue())), {'status', 'reason'})
        self.assertEqual(json.loads(output.getvalue())['status'], 'REFUSED')

    def test_duplicate_abbreviated_unknown_and_missing_flags_refuse_before_import(self):
        base = ['list', '--bundle', 'inert.tar', '--sha256', 'a' * 64, '--release-sha256', 'b' * 64]
        cases = [base + [flag + '=different'] for flag in ('--bundle', '--sha256', '--release-sha256')]
        cases += [['list', '--bund=inert.tar', '--sha256=' + 'a' * 64, '--release-sha256=' + 'b' * 64],
                  base + ['--unknown=value'], ['list']]
        for argv in cases:
            with self.subTest(argv=argv), patch.object(self.helper, 'mirror_helper', side_effect=AssertionError('import before refusal')), \
                 contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                self.helper.main(argv)
            self.assertEqual(caught.exception.code, 2)

    def test_moved_standalone_helper_uses_only_adjacent_trusted_runtime(self):
        prefix = self.root / 'moved-runtime'
        shutil.copytree(RUNTIME, prefix)
        entry = prefix / 'release/source_mirror_catalog.py'
        shutil.copyfile(HERE / 'source_mirror_catalog.py', entry)
        bundle = self.root / 'history.tar'; bundle.write_bytes(self.history)
        run = subprocess.run([sys.executable, '-I', '-B', str(entry), 'list', '--bundle', str(bundle),
            '--sha256', self.m.digest(self.history), '--release-sha256', self.old['release_sha256']],
            cwd=self.root, env={'PATH': '/usr/bin:/bin', 'PYTHONPATH': '/unavailable'}, capture_output=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual(json.loads(run.stdout)['packages'], self.expected_packages(self.old))
        self.assertFalse(list(prefix.rglob('__pycache__')))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime-root', type=Path, required=True, help='Trusted scripts root containing release/ and build/')
    parser.add_argument('--fixture-root', type=Path, required=True, help='Extracted package fixtures directory')
    args = parser.parse_args()
    RUNTIME, FIXTURES = args.runtime_root.resolve(), args.fixture_root.resolve()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CatalogTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = dict(status='PASS' if result.wasSuccessful() else 'FAIL', tests=result.testsRun,
        failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped),
        fixtures='TWO_PACKAGES_LEGACY_CURRENT_SYNTHETIC_ARCHIVES_REAL_ORIGINAL_RECIPE_BYTES',
        exact_materialized_contexts=4 if result.wasSuccessful() else None,
        helper_sha256=hashlib.sha256((HERE / 'source_mirror_catalog.py').read_bytes()).hexdigest(),
        native='NOT_RUN', installation='NOT_RUN', hardware='NOT_RUN', release='NOT_ADMITTED')
    print(json.dumps(report, sort_keys=True))
    raise SystemExit(not result.wasSuccessful() or bool(result.skipped))
