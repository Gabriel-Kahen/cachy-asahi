#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stage and move the real payload; inspect disposable public trust without applying it."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent


def run(argv, **kwargs):
    return subprocess.run(list(map(str, argv)), capture_output=True, timeout=45, **kwargs)


class PackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.space = tempfile.TemporaryDirectory(prefix='caa-enrollment-package-')
        cls.base = Path(cls.space.name)
        staged = cls.base / 'staged'
        staged.mkdir()
        env = dict(os.environ, srcdir=str(ROOT), pkgdir=str(staged))
        result = run(['/bin/bash', '-c', 'source "$1"; package', 'stage', ROOT / 'PKGBUILD'], env=env)
        if result.returncode:
            cls.space.cleanup()
            raise RuntimeError(result.stderr.decode())
        cls.payload = cls.base / 'moved'
        staged.rename(cls.payload)
        cls.cli = cls.payload / 'usr/bin/cachy-asahi-repository-enrollment'
        cls.signer = cls.base / 'test-signer'
        cls.signer.mkdir(mode=0o700)
        cls.addClassCleanup(cls.space.cleanup)
        cls.addClassCleanup(lambda: run(['/usr/bin/gpgconf', '--homedir', cls.signer, '--kill', 'all']))
        result = cls.gpg(cls.signer, '--pinentry-mode', 'loopback', '--passphrase', '',
                         '--quick-generate-key', 'DISPOSABLE ENROLLMENT TEST <test@example.invalid>',
                         'ed25519', 'sign', '1d')
        if result.returncode:
            raise RuntimeError(result.stderr.decode())
        listing = cls.gpg(cls.signer, '--with-colons', '--fingerprint', '--list-keys').stdout.decode()
        cls.fingerprint = next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
        cls.public = cls.gpg(cls.signer, '--export', cls.fingerprint).stdout

    @staticmethod
    def gpg(home, *args, **kwargs):
        return run(['/usr/bin/gpg', '--no-options', '--homedir', home, '--batch', *args], **kwargs)

    def target(self):
        space = tempfile.TemporaryDirectory(prefix='root-', dir=self.base)
        self.addCleanup(space.cleanup)
        target = Path(space.name)
        (target / 'etc/pacman.d/gnupg').mkdir(parents=True, mode=0o700)
        (target / 'var/lib/pacman').mkdir(parents=True)
        main = target / 'etc/pacman.conf'
        main.write_text('[options]\nArchitecture = auto\nSigLevel = Required DatabaseOptional\n'
                        '[core]\nServer = https://base.example.invalid/$repo/os/$arch\n')
        key = target / 'etc/pacman.d/public.gpg'
        key.write_bytes(self.public)
        key.chmod(0o600)
        result = self.gpg(target / 'etc/pacman.d/gnupg', '--import', key)
        self.assertEqual(result.returncode, 0, result.stderr)
        return target, key

    @staticmethod
    def tree(root):
        return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}

    def test_exact_payload_and_pinned_original_sources(self):
        provenance = json.loads((ROOT / 'source-provenance.json').read_text())
        expected = {'usr/bin/cachy-asahi-repository-enrollment',
                    'usr/lib/cachy-asahi/repository-enrollment/enroll.py',
                    'usr/lib/cachy-asahi/repository-enrollment/rotate.py',
                    'usr/share/doc/cachy-asahi-repository-enrollment/README.md',
                    'usr/share/doc/cachy-asahi-repository-enrollment/source-provenance.json',
                    'usr/share/licenses/cachy-asahi-repository-enrollment/LICENSE',
                    'usr/share/licenses/cachy-asahi-repository-enrollment/NOTICE'}
        self.assertEqual(set(self.tree(self.payload)), expected)
        for name, row in provenance['sources'].items():
            body = (self.payload / 'usr/lib/cachy-asahi/repository-enrollment' / name).read_bytes()
            self.assertEqual(hashlib.sha256(body).hexdigest(), row['sha256'])
            self.assertEqual(body, (ROOT / name).read_bytes())
        self.assertEqual(self.cli.stat().st_mode & 0o777, 0o755)

    def test_moved_help_version_and_dispatch(self):
        for args in (['--help'], ['--version'], ['configure', '--help'], ['rotate', '--help']):
            result = run([self.cli, *args])
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(result.stdout)
        self.assertEqual(run([self.cli, 'unknown']).returncode, 2)

    def test_real_public_key_preview_preserves_configuration_and_ring(self):
        target, key = self.target()
        before = self.tree(target)
        url = 'https://repo.example.invalid/generations/' + 'a' * 64 + '/release/repo'
        result = run([self.cli, 'configure', '--root', target, 'enroll', '--snapshot-url', url,
                      '--public-key', key, '--fingerprint', self.fingerprint])
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['status'], 'preview')
        self.assertIn('PackageRequired DatabaseRequired TrustedOnly', report['managed_include'])
        self.assertFalse(report['keyring_may_have_changed'])
        self.assertFalse(report['network_used'])
        self.assertEqual(before, self.tree(target))

    def test_bad_fingerprint_and_unenrolled_rotation_refuse_without_changes(self):
        target, key = self.target()
        before = self.tree(target)
        url = 'https://repo.example.invalid/generations/' + 'a' * 64 + '/release/repo'
        commands = [
            ['configure', '--root', target, 'enroll', '--snapshot-url', url,
             '--public-key', key, '--fingerprint', '0' * 40],
            ['rotate', '--root', target, '--expected-current-fingerprint', self.fingerprint,
             '--public-key', key, '--fingerprint', self.fingerprint]]
        for args in commands:
            result = run([self.cli, *args])
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(json.loads(result.stdout)['status'], 'failed')
            self.assertEqual(before, self.tree(target))

    def test_environment_and_working_directory_do_not_select_python_code(self):
        hostile = self.base / 'hostile'
        hostile.mkdir(exist_ok=True)
        (hostile / 'sitecustomize.py').write_text('raise RuntimeError("untrusted startup")\n')
        (hostile / 'json.py').write_text('raise RuntimeError("untrusted json")\n')
        env = dict(os.environ, PYTHONPATH=str(hostile), PYTHONHOME=str(hostile))
        target, _ = self.target()
        before = self.tree(target)
        result = run([self.cli, 'configure', '--root', target, 'disable'], cwd=hostile, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'preview')
        self.assertEqual(before, self.tree(target))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--recipe-root', type=Path, default=ROOT)
    args, remaining = parser.parse_known_args()
    ROOT = args.recipe_root.resolve()
    unittest.main(argv=[__file__, *remaining])
