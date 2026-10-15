#!/usr/bin/env python3
"""Pure fixture/argv tests; never execute package tools or Docker locally."""
import importlib.util
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('real_check', Path(__file__).with_name('real-check.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class FixtureTests(unittest.TestCase):
    def test_package_has_only_metadata_and_inert_versioned_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            for version in ('0.1.0-1', '0.1.1-1'):
                path = Path(temporary) / 'fixture.pkg.tar.gz'
                fixture.write_package(path, version)
                with tarfile.open(path) as archive:
                    self.assertEqual(archive.getnames(), ['.PKGINFO', str(fixture.PAYLOAD).lstrip('/')])
                    self.assertTrue(all(row.isfile() and row.mode == 0o644
                                        and row.uid == row.gid == 0 for row in archive))
                    info = archive.extractfile('.PKGINFO').read().decode()
                    self.assertIn('pkgver = ' + version + '\n', info)
                    self.assertFalse(any(key + ' =' in info for key in
                                         ('depend', 'provides', 'replaces', 'conflict', 'install')))
                    self.assertEqual(archive.extractfile(str(fixture.PAYLOAD).lstrip('/')).read(),
                                     ('inert Check fixture ' + version + '\n').encode())

    def test_real_command_uses_empty_environment_and_installed_binary(self):
        argv = fixture.user_command(Path('/tmp/fixture/user'), ['/usr/bin/arch-update', '--check'])
        self.assertEqual(argv[:7], ['/usr/bin/runuser', '-u', 'alarm', '--', '/usr/bin/env', '-i',
                                   'PATH=/usr/bin:/bin'])
        self.assertEqual(argv[-2:], ['/usr/bin/arch-update', '--check'])
        self.assertFalse(any('PACMAN_CONF=' in item or 'ARCH_UPDATE_LIBDIR=' in item
                             or 'CACHY_ASAHI_POLICY' in item for item in argv))
        self.assertIn('NoAUR\n', fixture.OPTIONS)
        self.assertIn('NoNotification\n', fixture.OPTIONS)

    def test_config_requires_signatures_and_only_local_fixture_repository(self):
        config = fixture.configuration(Path('/tmp/fixture/repo'), Path('/tmp/fixture/public'))
        self.assertEqual(config.count('Server ='), 1)
        self.assertIn('Server = file:///tmp/fixture/repo\n', config)
        self.assertEqual(config.count('SigLevel = Required\n'), 3)
        self.assertNotIn('Optional', config)
        self.assertNotIn('Include', config)
        with self.assertRaises(ValueError):
            fixture.configuration(Path('/tmp/bad\n[evil]'), Path('/tmp/public'))

    def test_container_guard_precedes_any_command_or_filesystem_mutation(self):
        with patch.object(fixture.platform, 'machine', return_value='x86_64'), \
             patch.object(fixture.subprocess, 'run', side_effect=AssertionError('must not execute')):
            result = fixture.exercise(Path('/missing'), Path('/missing/key'), 'A' * 40)
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['phase'], 'container-guard')
        self.assertEqual(result['error_type'], 'ValueError')
        self.assertEqual(result['cases'], {})


if __name__ == '__main__':
    unittest.main()
