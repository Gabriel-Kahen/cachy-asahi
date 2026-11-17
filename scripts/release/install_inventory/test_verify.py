#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verify = load('install_inventory', HERE / 'verify.py')
fixtures = load('kit_fixture', HERE.parent / 'test_offline_kit.py')
LOCK_607 = HERE.parent / 'package_set_verify_v2/testdata/current607.lock'
PIN_607 = 'be35402204ba5c03d78279722afa83047c9575d2da70fb5c4064f46ed15954c5'


class InstallInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.KitTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.KitTests.tearDownClass()

    def setUp(self):
        self.fixture = fixtures.KitTests(methodName='runTest')
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.fixture.assemble()
        self.lock = self.fixture.f.base / 'target.lock'
        self.args = argparse.Namespace(**vars(self.fixture.inspect_args), target_lock=str(self.lock))

    def set_lock(self, raw):
        self.lock.write_bytes(raw)
        self.args.target_lock_sha256 = verify.client.digest(raw)

    def test_real_signatures_and_exact_inventory_via_isolated_cli(self):
        self.set_lock(b'fixture 1.0-1\nlinux-asahi 1\nruntime 2\n')
        command = [sys.executable, '-I', '-B', str(HERE / 'verify.py')]
        for name, value in vars(self.args).items():
            command.extend(['--' + name.replace('_', '-'), str(value)])
        before = verify.kit.inventory(self.fixture.output)
        run = subprocess.run(command, capture_output=True, timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr.decode())
        result = json.loads(run.stdout)
        self.assertEqual(result['status'], 'matched-development-install-inventory')
        self.assertEqual(result['target_package_count'], 3)
        self.assertEqual(result['base_package_count'], 2)
        self.assertEqual(result['overlay_package_count'], 1)
        self.assertEqual(result['target_lock_sha256'], self.args.target_lock_sha256)
        self.assertTrue(result['synthetic'])
        for field in ('base_archives_authenticated', 'state_changed', 'packages_installed',
                      'supported_asahi_installation', 'm2_validated', 'stable_accepted'):
            self.assertIs(result[field], False)
        self.assertEqual(verify.kit.inventory(self.fixture.output), before)
        self.assertEqual(list(self.fixture.state.iterdir()), [])

        self.set_lock(b'fixture 9.0-1\nlinux-asahi 1\nforeign 2\n')
        command[-1] = self.args.target_lock_sha256
        run = subprocess.run(command, capture_output=True, timeout=60)
        self.assertEqual(run.returncode, 1)
        self.assertEqual(run.stdout, b'')
        self.assertIn(b'{"missing":["foreign"],"extra":["runtime"],"version_mismatches":["fixture"]}', run.stderr)

    def test_real_retained_607_lock_cannot_authorize_another_signed_kit(self):
        expected = verify.target_lock(str(LOCK_607), PIN_607)
        self.assertEqual(len(expected), 607)
        self.assertEqual(expected['alsa-card-profiles'], '1:1.6.9-1')
        self.assertEqual(expected['alsa-ucm-conf-asahi'], '10-2')
        self.args.target_lock = str(LOCK_607)
        self.args.target_lock_sha256 = PIN_607
        with self.assertRaisesRegex(verify.client.Error, 'target lock differs from signed declared transaction'):
            verify.verify(self.args)

    def test_lock_pin_and_closed_line_format_are_enforced(self):
        for raw in (b'fixture 1\nfixture 2\n', b'fixture 1', b'fixture  1\n', b'fixture 1\n\n'):
            with self.subTest(raw=raw):
                self.set_lock(raw)
                with self.assertRaises(verify.client.Error):
                    verify.target_lock(str(self.lock), self.args.target_lock_sha256)
        self.set_lock(b'fixture 1\n')
        with self.assertRaisesRegex(verify.client.Error, 'target lock SHA-256 mismatch'):
            verify.target_lock(str(self.lock), '0' * 64)
        alias = self.lock.parent / 'alias.lock'
        alias.symlink_to(self.lock)
        with self.assertRaises(OSError):
            verify.target_lock(str(alias), self.args.target_lock_sha256)

    def test_overlay_replacement_uses_successor_version(self):
        inputs = self.fixture.f.inputs
        base_path = inputs / 'base.json'
        base = json.loads(base_path.read_bytes())
        base['packages'].append({'name': 'fixture', 'version': '0.8-1', 'arch': 'any',
                                 'depend': [], 'provides': [], 'conflict': [], 'files': []})
        self.fixture.f.put('base.json', base)
        self.fixture.f.release_spec['base']['sha256'] = self.fixture.f.ref('base.json')['sha256']
        self.fixture.f.release_spec['release_id'] = 'fixture-2'
        self.fixture.bundle = Path(self.fixture.f.stage()['path'])
        self.fixture.make_metadata()
        self.fixture.output = self.fixture.f.base / 'replacement-kit'
        self.fixture.args.bundle = str(self.fixture.bundle)
        self.fixture.args.output = str(self.fixture.output)
        self.fixture.assemble()
        self.args = argparse.Namespace(**vars(self.fixture.inspect_args), target_lock=str(self.lock))
        self.set_lock(b'linux-asahi 1\nruntime 2\nfixture 1.0-1\n')
        result = verify.verify(self.args)
        self.assertEqual(result['target_package_count'], 3)
        self.assertEqual(result['base_package_count'], 3)
        self.set_lock(b'linux-asahi 1\nruntime 2\nfixture 0.8-1\n')
        with self.assertRaisesRegex(verify.client.Error, 'version_mismatches.*fixture'):
            verify.verify(self.args)

    def test_genuinely_signed_protected_overlay_is_refused(self):
        f = self.fixture.f
        release_path = self.fixture.bundle / 'release.json'
        spec_path = self.fixture.bundle / 'spec.json'
        spec = json.loads(spec_path.read_bytes())
        spec['policy']['protected_packages'].append('fixture')
        fixtures.t.r.write(spec_path, spec)
        release = json.loads(release_path.read_bytes())
        release['files']['spec.json'] = fixtures.t.r.sha(spec_path)
        fixtures.t.r.write(release_path, release)
        release_path.with_suffix('.json.sig').unlink()
        fixtures.t.r.sign(release_path, f.key, f.env)
        self.fixture.make_metadata()
        self.fixture.output = f.base / 'malformed-policy-kit'
        self.fixture.args.output = str(self.fixture.output)
        self.fixture.assemble()
        self.args = argparse.Namespace(**vars(self.fixture.inspect_args), target_lock=str(self.lock))
        self.set_lock(b'fixture 1.0-1\nlinux-asahi 1\nruntime 2\n')
        with self.assertRaisesRegex(verify.client.Error, 'preserve all declared protected base packages'):
            verify.verify(self.args)

    def test_post_verification_base_replacement_refuses(self):
        self.set_lock(b'fixture 1.0-1\nlinux-asahi 1\nruntime 2\n')
        inspect = verify.kit.inspect

        def change_base(args):
            result = inspect(args)
            base = self.fixture.output / 'release/base.json'
            base.chmod(0o600)
            base.write_bytes(base.read_bytes() + b' ')
            return result

        with patch.object(verify.kit, 'inspect', side_effect=change_base):
            with self.assertRaisesRegex(verify.client.Error, 'base.json changed after authentication'):
                verify.verify(self.args)


if __name__ == '__main__':
    unittest.main()
