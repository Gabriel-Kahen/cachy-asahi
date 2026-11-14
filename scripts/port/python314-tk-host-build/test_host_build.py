# SPDX-License-Identifier: MIT
"""Input binding, confinement and result refusal controls; no Docker required."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('host_build', HERE / 'run.py')
host = importlib.util.module_from_spec(spec); spec.loader.exec_module(host)


class Controls(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)

    def fixture(self):
        recipe = self.root / 'recipe'; recipe.mkdir()
        (recipe / 'PKGBUILD').write_text('exact frozen recipe')
        archive = self.root / 'source'; archive.write_bytes(b'exact source')
        pins = {'files': {'PKGBUILD': host.identity(recipe / 'PKGBUILD')},
                'source': {'name': 'source', **host.identity(archive)}}
        (self.root / 'inputs.json').write_text(json.dumps(pins))
        return recipe, archive

    def test_exact_inputs(self):
        recipe, archive = self.fixture()
        with patch.object(host, 'HERE', self.root):
            self.assertEqual(host.verify_inputs(recipe, archive)['source']['bytes'], 12)

    def test_changed_recipe(self):
        recipe, archive = self.fixture(); (recipe / 'PKGBUILD').write_text('changed')
        with patch.object(host, 'HERE', self.root), self.assertRaisesRegex(ValueError, 'input changed'):
            host.verify_inputs(recipe, archive)

    def test_omitted_recipe(self):
        recipe, archive = self.fixture(); (recipe / 'PKGBUILD').unlink()
        with patch.object(host, 'HERE', self.root), self.assertRaisesRegex(ValueError, 'namespace'):
            host.verify_inputs(recipe, archive)

    def test_extra_recipe(self):
        recipe, archive = self.fixture(); (recipe / 'unbound').write_text('extra')
        with patch.object(host, 'HERE', self.root), self.assertRaisesRegex(ValueError, 'namespace'):
            host.verify_inputs(recipe, archive)

    def test_changed_source(self):
        recipe, archive = self.fixture(); archive.write_bytes(b'changed')
        with patch.object(host, 'HERE', self.root), self.assertRaisesRegex(ValueError, 'archive changed'):
            host.verify_inputs(recipe, archive)

    def test_symlink_source(self):
        recipe, archive = self.fixture(); link = self.root / 'link'; link.symlink_to(archive)
        with patch.object(host, 'HERE', self.root), self.assertRaisesRegex(ValueError, 'ordinary'):
            host.verify_inputs(recipe, link)

    def actor(self):
        return {'HostConfig': {'NanoCpus': 2000000000, 'Memory': 4 * 1024**3,
                'MemorySwap': 4 * 1024**3, 'PidsLimit': 256, 'NetworkMode': 'none',
                'ReadonlyRootfs': True, 'Init': True, 'CapDrop': ['ALL'],
                'SecurityOpt': ['no-new-privileges'], 'Privileged': False, 'Devices': []},
                'Config': {'User': '1000:1000'}, 'Mounts': [
                    {'Destination': '/inputs', 'Type': 'bind', 'RW': False},
                    {'Destination': '/work', 'Type': 'volume', 'RW': True}]}

    def test_exact_actor(self):
        host.validate_actor(self.actor())

    def test_actor_refuses_each_resource_escape(self):
        for key, value in {'NanoCpus': 0, 'Memory': 0, 'MemorySwap': -1, 'PidsLimit': 0,
                           'NetworkMode': 'bridge', 'ReadonlyRootfs': False, 'Init': False,
                           'CapDrop': [], 'SecurityOpt': [], 'Privileged': True,
                           'Devices': ['/dev/snd']}.items():
            actor = self.actor(); actor['HostConfig'][key] = value
            with self.subTest(key=key), self.assertRaises(AssertionError):
                host.validate_actor(actor)

    def test_root_actor_refused(self):
        actor = self.actor(); actor['Config']['User'] = '0'
        with self.assertRaises(AssertionError): host.validate_actor(actor)

    def test_writable_source_refused(self):
        actor = self.actor(); actor['Mounts'][0]['RW'] = True
        with self.assertRaises(AssertionError): host.validate_actor(actor)

    def test_unbound_host_mount_refused(self):
        actor = self.actor(); actor['Mounts'].append({'Destination': '/host', 'Type': 'bind', 'RW': True})
        with self.assertRaises(AssertionError): host.validate_actor(actor)

    def exported(self):
        pins = {'files': {'PKGBUILD': {'sha256': 'a' * 64}}}
        (self.root / 'makepkg-exit.txt').write_text('0\n')
        (self.root / 'PKGINFO').write_text('pkgname = python\npkgver = 3.14.8-1.1\narch = x86_64\n')
        (self.root / 'BUILDINFO').write_text('pkgbuild_sha256sum = ' + 'a' * 64 + '\n')
        (self.root / 'tk-headless.json').write_text(json.dumps({'status': 'PASS headless Tcl only', 'Tk_loaded': False}))
        (self.root / 'python-3.14.8-1.1-x86_64.pkg.tar.zst').write_bytes(b'x' * 2048)
        return pins

    def test_full_result_binding(self):
        self.assertEqual(host.check_export(self.root, self.exported())['archive']['bytes'], 2048)

    def test_failed_makepkg_refused(self):
        pins = self.exported(); (self.root / 'makepkg-exit.txt').write_text('8')
        with self.assertRaisesRegex(ValueError, 'makepkg failed'): host.check_export(self.root, pins)

    def test_wrong_arch_refused(self):
        pins = self.exported(); (self.root / 'PKGINFO').write_text('pkgname = python\npkgver = 3.14.8-1.1\narch = aarch64\n')
        with self.assertRaisesRegex(ValueError, 'archive identity'): host.check_export(self.root, pins)

    def test_wrong_build_binding_refused(self):
        pins = self.exported(); (self.root / 'BUILDINFO').write_text('pkgbuild_sha256sum = ' + 'b' * 64)
        with self.assertRaisesRegex(ValueError, 'recipe binding'): host.check_export(self.root, pins)

    def test_missing_tk_result_refused(self):
        pins = self.exported(); (self.root / 'tk-headless.json').unlink()
        with self.assertRaises(FileNotFoundError): host.check_export(self.root, pins)

    def test_window_profile_refused(self):
        pins = self.exported(); (self.root / 'tk-headless.json').write_text(json.dumps({'status': 'PASS headless Tcl only', 'Tk_loaded': True}))
        with self.assertRaisesRegex(ValueError, 'headless'): host.check_export(self.root, pins)

    def test_missing_archive_refused(self):
        pins = self.exported(); (self.root / 'python-3.14.8-1.1-x86_64.pkg.tar.zst').unlink()
        with self.assertRaises(FileNotFoundError): host.check_export(self.root, pins)

    def test_shell_syntax(self):
        for name in ('build.sh', 'provision.sh'):
            subprocess.run(['/usr/bin/bash', '-n', str(HERE / name)], check=True)

    def test_cleanup_precise_owned_absence(self):
        cases = [(['docker', 'rm', '-f', 'owned'], 'No such container: owned'),
                 (['docker', 'volume', 'rm', 'owned'], 'get owned: no such volume'),
                 (['docker', 'image', 'rm', 'owned:tag'], 'No such image: owned:tag')]
        for argv, message in cases:
            with self.subTest(argv=argv):
                self.assertTrue(host.cleanup_absent(argv, 'Error response from daemon: ' + message + '\n'))

    def test_cleanup_unknown_or_wrong_name_not_hidden(self):
        argv = ['docker', 'rm', '-f', 'owned']
        for text in ('Error response from daemon: No such container: other',
                     'daemon unavailable', 'Error response from daemon: No such container: owned\nextra error'):
            with self.subTest(text=text):
                self.assertFalse(host.cleanup_absent(argv, text))

    def test_direct_nonisolated_invocation_refused(self):
        result = subprocess.run([sys.executable, str(HERE / 'run.py'), '--help'], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'run with python3 -I', result.stderr)

    def test_optimized_invocation_refused(self):
        result = subprocess.run([sys.executable, '-I', '-O', str(HERE / 'run.py'), '--help'], capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'without optimization', result.stderr)


if __name__ == '__main__':
    unittest.main()
