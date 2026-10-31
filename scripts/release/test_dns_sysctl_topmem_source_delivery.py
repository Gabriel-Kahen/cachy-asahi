#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reuse the prior finite-source controls for three exact local tool recipes."""
import importlib.util
import json
from pathlib import Path
import re
import shlex
import unittest
from unittest.mock import patch

HERE = Path(__file__).absolute().parent
SPEC = importlib.util.spec_from_file_location('prior_management_controls', HERE / 'test_management_tools_source_delivery.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
d = m.d
PROFILES = {
    'cachy-asahi-dns': ('0.1.0-1', 9, 5),
    'cachy-asahi-sysctl': ('0.1.0-1', 8, 5),
    'cachy-asahi-topmem': ('0.1.0-1', 7, 4),
}


class SourceCoverage(m.ManagementDelivery):
    # These prior-specific cases are replaced by the three cases below.
    test_cache_and_orphans_payload_match_pinned_literal_install_statements = None
    test_runtime_helper_pins_provenance_and_loop_defined_payload = None
    test_literal_recipe_srcinfo_and_exact_host_command_policy = None

    def setUp(self):
        super().setUp()
        profiles = patch.object(m, 'PROFILES', PROFILES)
        profiles.start()
        self.addCleanup(profiles.stop)

    def test_literal_recipe_srcinfo_and_bounded_pure_check_policy(self):
        checks = {
            'cachy-asahi-dns': [['python', '-I', '-B', 'check_source.py', '--recipe-root', '.'],
                                ['python', '-I', '-B', 'cachy-asahi-dns', '--help']],
            'cachy-asahi-sysctl': [['python', '-I', '-B', 'cachy-asahi-sysctl', '--help']],
            'cachy-asahi-topmem': [['python', '-I', '-B', '-Werror::ResourceWarning', 'test_topmem.py']],
        }
        for name in PROFILES:
            bodies, info = self.contents(name)
            literal = {}
            for match in re.finditer(r'^([a-z][a-z0-9_]*)=(\([^)]*\)|[^\n]+)', bodies['PKGBUILD'].decode(), re.M):
                key, value = match.groups()
                self.assertNotIn('$', value)
                self.assertNotIn('`', value)
                literal[key] = shlex.split(value[1:-1] if value.startswith('(') else value, comments=True)
            for key in ('pkgname', 'pkgver', 'pkgrel', 'arch', 'license', 'depends', 'source', 'sha256sums',
                        'epoch', 'makedepends', 'checkdepends', 'optdepends', 'provides', 'conflicts',
                        'replaces', 'backup', 'install'):
                self.assertEqual(info.get(key, []), literal.get(key, []), (name, key))
            self.assertEqual(info['pkgbase'], [name])
            saved = d.manifest(name, bodies, info, m.REVISION, None)
            self.assertEqual(saved['host_check_commands'], checks[name])

    def test_payload_maps_match_every_literal_install_and_dns_loop(self):
        for name in PROFILES:
            bodies, _ = self.contents(name)
            recipe = bodies['PKGBUILD'].decode()
            actual = {}
            for line in recipe.splitlines():
                if not line.strip().startswith('install -Dm'):
                    continue
                parts = shlex.split(line)
                self.assertIn(len(parts), (4, 6))
                if len(parts) == 6:
                    self.assertEqual(parts[4:], ['||', 'return'])
                _, mode, source, dest = parts[:4]
                self.assertTrue(source.startswith('$srcdir/'))
                self.assertTrue(dest.startswith('$pkgdir/'))
                if '$file' in source:
                    self.assertEqual(name, 'cachy-asahi-dns')
                    folder = 'doc' if '/doc/' in dest else 'licenses'
                    leaves = ('README.md', 'source-provenance.json') if folder == 'doc' else ('NOTICE', 'LICENSE')
                    self.assertIn('for file in ' + ' '.join(leaves) + '; do', recipe)
                    for leaf in leaves:
                        path = dest.removeprefix('$pkgdir/').replace('$pkgname', name).replace('$file', leaf)
                        self.assertNotIn(path, actual)
                        actual[path] = (leaf, int(mode.removeprefix('-Dm'), 8))
                else:
                    path = dest.removeprefix('$pkgdir/').replace('$pkgname', name)
                    self.assertNotIn(path, actual)
                    actual[path] = (source.removeprefix('$srcdir/'), int(mode.removeprefix('-Dm'), 8))
            self.assertEqual(actual, d.payload(name))
            self.assertEqual(len(actual), PROFILES[name][2])
            self.assertEqual(set(source for source, mode in actual.values()),
                {name, 'README.md', 'NOTICE', 'LICENSE'} | ({'source-provenance.json'} if not name.endswith('topmem') else set()))

    def test_actual_notice_license_provenance_and_system_dependency_boundaries(self):
        for name in PROFILES:
            bodies, info = self.contents(name)
            self.assertEqual(d.s.digest(bodies['LICENSE']), '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7')
            self.assertIn(b'MIT', bodies['NOTICE'])
            self.assertEqual(info['license'], ['MIT'])
            self.assertTrue(all('://' not in key for key in info['source']))
            if name.endswith('dns'):
                provenance = json.loads(bodies['source-provenance.json'])
                raw = bodies[name]
                self.assertEqual(provenance['installed_program'], dict(bytes=len(raw), sha256=d.s.digest(raw)))
                self.assertFalse(provenance['nmcli']['bundled'])
                self.assertEqual(provenance['nmcli']['dependency'], 'networkmanager>=1.44')
                self.assertEqual(info['depends'], ['python>=3.11', 'networkmanager>=1.44'])
            elif name.endswith('sysctl'):
                provenance = json.loads(bodies['source-provenance.json'])
                self.assertEqual(set(provenance['files']), {name, 'LICENSE'})
                for leaf, row in provenance['files'].items():
                    raw = bodies[leaf]
                    self.assertEqual(row, dict(bytes=len(raw), sha256=d.s.digest(raw)))
                self.assertEqual(info['depends'], ['python>=3.11'])
            else:
                self.assertNotIn('source-provenance.json', bodies)
                self.assertEqual(info['depends'], ['python>=3.11'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
