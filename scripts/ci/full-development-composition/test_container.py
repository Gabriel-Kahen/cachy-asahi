#!/usr/bin/env python3
"""Safety boundaries only: no Docker, pacman, GPG, network, or installation."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('composition_container', Path(__file__).with_name('container.py'))
trial = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trial)


class Boundaries(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.base = {'base-' + str(i): '1-1' for i in range(573)} | {'libfdk-aac': '2-1'}
        self.plan = {'packages': [], 'projects': []}
        for name in sorted(trial.PROJECTS | trial.EXTRAS):
            filename = name + '-1-1-any.pkg.tar.xz'
            row = {'name': name, 'version': '1-1', 'filename': filename}
            for suffix, prefix in (('', ''), ('.sig', 'signature_')):
                data = (name + suffix).encode()
                (self.directory / (filename + suffix)).write_bytes(data)
                row[prefix + 'sha256'] = hashlib.sha256(data).hexdigest()
                row[prefix + 'size'] = len(data)
            self.plan['packages'].append(row)
            if name in trial.PROJECTS:
                self.plan['projects'].append({'name': name, 'version': '1-1', 'archive': filename,
                    'sha256': row['sha256'], 'payload': [{'path': '/usr/bin/' + name, 'type': 'file'}]})
        self.expected = {k: v for k, v in self.base.items() if k != 'libfdk-aac'}
        self.expected.update({r['name']: r['version'] for r in self.plan['packages']})

    def validate(self):
        return trial.inputs(self.plan, self.base, self.expected, self.directory)

    def test_byte_drift_blocks_input_acceptance(self):
        self.validate()
        path = self.directory / self.plan['packages'][-1]['filename']
        original = path.read_bytes()
        path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        with self.assertRaisesRegex(ValueError, 'byte pin'):
            self.validate()

    def test_duplicate_package_cannot_replace_missing_project(self):
        self.plan['packages'][-1] = copy.deepcopy(self.plan['packages'][0])
        with self.assertRaisesRegex(ValueError, 'exact ten'):
            self.validate()

    def test_explicit_container_and_payload_namespace_required(self):
        with patch.dict(trial.os.environ, {}, clear=True), patch.object(trial.platform, 'machine', return_value='aarch64'):
            with self.assertRaisesRegex(ValueError, 'disposable'):
                trial.guard()
        self.plan['projects'][0]['payload'][0]['path'] = '/usr/../etc/pacman.conf'
        with self.assertRaisesRegex(ValueError, 'namespace'):
            self.validate()

    def test_unrelated_base_version_change_is_rejected(self):
        self.expected['base-0'] = '2-1'
        with self.assertRaisesRegex(ValueError, 'changes more'):
            self.validate()
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            trial.lock('base 1\nbase 2\n')

    def test_pacman_refusal_cannot_reach_installed_checks(self):
        failure = subprocess.CalledProcessError(1, ['pacman', '-U'])
        with patch.object(trial, 'run', side_effect=failure), patch.object(trial, 'inventory') as inventory:
            with self.assertRaises(subprocess.CalledProcessError):
                trial.install(['pacman'], ['candidate.pkg.tar.xz'], self.expected)
            inventory.assert_not_called()


if __name__ == '__main__':
    unittest.main()
