# SPDX-License-Identifier: MIT
"""Focused package-resume checks; no Docker, signing, account or package mutation."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import integration_resume as resume


class ResumeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.image = 'sha256:' + 'a' * 64
        self.recipe_pin = 'b' * 64
        self.inputs = b'{"source_date_epoch": 1}\n'
        (self.root / 'inputs.lock.json').write_bytes(self.inputs)
        (self.root / 'packages.lock').write_text('base 1-1\n')
        self.inventory_pin = resume.native.sha(self.root / 'packages.lock')
        self.input_pin = resume.native.sha(self.root / 'inputs.lock.json')
        (self.root / 'image-id').write_text(self.image + '\n')
        self.write('result.json', dict(status='native-builds-and-byte-comparison-pass', native_build='PASS',
                                      reviewed_recipes_sha256=self.recipe_pin, reviewed_inputs_sha256=self.input_pin))
        self.write('bootstrap.json', dict(status='image-provisioned', image_id=self.image,
                                         inputs_sha256=self.input_pin, packages_lock_sha256=self.inventory_pin))
        self.reviews = {'packages/' + name: {'PKGBUILD': 'c' * 64} for name in resume.native.RECIPES}
        for name in resume.native.RECIPES:
            for attempt in (1, 2):
                directory = self.root / f'{name}-{attempt}'
                directory.mkdir()
                self.write(f'{name}-{attempt}/provenance.json', dict(mode='native', image_id=self.image,
                    expected_packages_sha256=self.inventory_pin, recipe_inputs={'PKGBUILD': 'c' * 64}))

    def write(self, name, value):
        (self.root / name).write_text(json.dumps(value))

    def prepared(self, row=None):
        with patch.object(resume.integration, 'artifact', side_effect=lambda path, name:
                          (path / 'archive', row(path, name) if row else dict(name=name, sha256='d' * 64))), \
             patch.object(resume.native, 'load_pinned', return_value=self.reviews):
            return resume.prepared_build(self.root, self.recipe_pin)

    def test_reuses_native_build_without_audit_or_build(self):
        with patch.object(resume.native, 'audit', side_effect=AssertionError('must not reacquire inputs')), \
             patch.object(resume.native, 'build', side_effect=AssertionError('must not rebuild originals')):
            self.assertEqual(self.prepared(), self.image)

    def test_later_integration_failure_does_not_discard_successful_build(self):
        result = json.loads((self.root / 'result.json').read_text())
        result.update(status='failed', mode='integration', error='native virtual integration failed')
        self.write('result.json', result)
        self.assertEqual(self.prepared(), self.image)
        result['native_build'] = 'NOT RUN'
        self.write('result.json', result)
        with self.assertRaisesRegex(ValueError, 'successful native build'):
            self.prepared()

    def test_refuses_inventory_recipe_and_archive_pair_drift(self):
        (self.root / 'packages.lock').write_text('base 2-1\n')
        with self.assertRaisesRegex(ValueError, 'input/inventory drift'):
            self.prepared()
        (self.root / 'packages.lock').write_text('base 1-1\n')
        self.reviews['packages/' + resume.native.RECIPES[0]] = {'PKGBUILD': 'e' * 64}
        with self.assertRaisesRegex(ValueError, 'archive recipe differs'):
            self.prepared()
        self.reviews['packages/' + resume.native.RECIPES[0]] = {'PKGBUILD': 'c' * 64}
        with self.assertRaisesRegex(ValueError, 'package pair differs'):
            self.prepared(lambda path, name: dict(name=name, sha256=path.name))

    def test_x86_host_refused_before_docker_or_output(self):
        with patch.object(resume.platform, 'system', return_value='Linux'), \
             patch.object(resume.platform, 'machine', return_value='x86_64'), \
             patch.object(resume.native, 'run', side_effect=AssertionError('Docker must not run')):
            with self.assertRaisesRegex(ValueError, 'native ARM'):
                resume.main(['--native-output', str(self.root), '--integration-lock', 'unused',
                             '--integration-sha256', 'a'*64, '--recipes-sha256', self.recipe_pin,
                             '--source-commit', 'c'*40, '--output', str(self.root/'new')])
        self.assertFalse((self.root / 'new').exists())

    def test_main_checks_live_image_then_runs_package_only_controller(self):
        output = self.root / 'integration'
        build = self.root / 'build'
        build.mkdir()
        (build / 'inputs.lock.json').write_bytes(self.inputs)
        (build / 'packages.lock').write_text('base 1-1\n')
        lock = {'fixture': 'frozen'}
        with patch.object(resume.platform, 'system', return_value='Linux'), \
             patch.object(resume.platform, 'machine', return_value='aarch64'), \
             patch.object(resume.os, 'getuid', return_value=1000), \
             patch.object(resume, 'prepared_build', return_value=self.image) as prepared, \
             patch.object(resume.integration, 'preflight', return_value=lock), \
             patch.object(resume.native, 'probe') as probe, \
             patch.object(resume.native, 'run', side_effect=[json.dumps([dict(
                 Id=self.image, Architecture='arm64', Os='linux')]), 'base 1-1']) as run, \
             patch.object(resume.native, 'audit', side_effect=AssertionError('must not reacquire inputs')), \
             patch.object(resume.native, 'build', side_effect=AssertionError('must not rebuild originals')), \
             patch.object(resume.integration, 'Controller') as controller:
            controller.return_value.run.return_value = True
            self.assertEqual(resume.main(['--native-output', str(build), '--integration-lock', 'unused',
                '--integration-sha256', 'a'*64, '--recipes-sha256', self.recipe_pin,
                '--source-commit', 'c'*40, '--output', str(output)]), 0)
        prepared.assert_called_once_with(build, self.recipe_pin)
        probe.assert_called_once_with(self.root / 'integration-probe')
        self.assertEqual(run.call_count, 2)
        self.assertIn('--read-only', run.call_args.args[0])
        self.assertIn('--network=none', run.call_args.args[0])
        controller.assert_called_once_with(self.image, build, output, lock, 'c'*40, package_only=True)
        controller.return_value.run.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
