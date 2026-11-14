# SPDX-License-Identifier: MIT
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('support', HERE / 'test_support.py')
support = importlib.util.module_from_spec(spec); spec.loader.exec_module(support)


def sandbox(root, argv):
    hidden = next((p for p in (HERE, *HERE.parents) if (p / 'AGENTS.md').is_file()), HERE)
    return ['bwrap', '--unshare-all', '--die-with-parent', '--new-session', '--ro-bind', '/', '/',
            '--dev', '/dev', '--proc', '/proc', '--tmpfs', str(hidden),
            '--tmpfs', '/tmp', '--bind', str(root), str(root), '--chdir', '/', *argv]


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.f = support.Fixture(); self.addCleanup(self.f.close)
        self.entry = self.f.usr / 'bin/cachy-asahi-first-login-ui'

    def test_eight_owned_files_and_no_hooks_or_autostart(self):
        dependencies = {'usr/bin/cachy-asahi-first-login', 'usr/bin/cachy-asahi-setup',
                        'usr/lib/cachy-asahi/first-login/first_login.py'}
        paths = {str(p.relative_to(self.f.prefix)): p.stat().st_mode & 0o777 for p in self.f.prefix.rglob('*') if p.is_file()}
        owned = set(paths) - dependencies
        expected = {'usr/bin/cachy-asahi-first-login-ui',
            'usr/lib/cachy-asahi/first-login-ui/bridge.py', 'usr/lib/cachy-asahi/first-login-ui/gui.py',
            'usr/share/applications/io.github.GabrielKahen.CachyAsahiFirstLogin.desktop',
            'usr/share/doc/cachy-asahi-first-login-ui/README.md',
            'usr/share/doc/cachy-asahi-first-login-ui/source-provenance.json',
            'usr/share/licenses/cachy-asahi-first-login-ui/LICENSE',
            'usr/share/licenses/cachy-asahi-first-login-ui/NOTICE'}
        self.assertEqual(owned, expected)
        self.assertEqual(paths['usr/bin/cachy-asahi-first-login-ui'], 0o755)
        self.assertEqual(self.f.files(), {})

    def test_isolated_moved_help_ignores_ambient_python(self):
        poison = self.f.root / 'poison'; poison.mkdir()
        for name in ('pathlib.py', 'argparse.py', 'runpy.py', 'json.py', 'gi.py'):
            (poison / name).write_text("raise RuntimeError('ambient import')\n")
        env = dict(os.environ, PYTHONPATH=str(poison), PYTHONHOME=str(poison))
        result = subprocess.run([str(self.entry), '--help'], cwd=poison, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--state-dir', result.stdout)

    def test_missing_runtime_has_no_checkout_fallback(self):
        (self.f.usr / 'lib/cachy-asahi/first-login-ui/bridge.py').unlink()
        result = subprocess.run([str(self.entry), '--help'], capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_backend_absence_preserves_home(self):
        (self.f.usr / 'bin/cachy-asahi-first-login').unlink()
        with self.assertRaises(support.bridge.Error): self.f.client.run('inspect')
        self.assertEqual(self.f.files(), {})

    @unittest.skipUnless(shutil.which('bwrap'), 'source-hidden runtime NOT RUN: bwrap unavailable')
    def test_source_hidden_moved_runtime_and_real_backend(self):
        probe_argv = sandbox(self.f.root, ['/usr/bin/true'])
        probe = subprocess.run(probe_argv, cwd='/', env={'PATH': '/usr/bin:/bin'},
                               capture_output=True, text=True, timeout=10)
        if probe.returncode:
            print('optional namespace probe: ' + json.dumps({'argv': probe_argv,
                'returncode': probe.returncode, 'stdout': probe.stdout, 'stderr': probe.stderr}), file=sys.stderr)
            denied = ('bwrap: No permissions to create a new namespace' in probe.stderr
                or 'bwrap: Creating new namespace failed: Operation not permitted' in probe.stderr
                or 'bwrap: Creating new namespace failed: Operation not supported' in probe.stderr
                or 'bwrap: setting up uid map: Permission denied' in probe.stderr)
            if denied:
                self.skipTest('NOT RUN optional source-hidden sandbox: namespace permission/support denied; exact probe above')
        self.assertEqual(probe.returncode, 0, probe.stderr)
        script = self.f.root / 'private-run.py'
        module = self.f.usr / 'lib/cachy-asahi/first-login-ui/bridge.py'
        script.write_text('import importlib.util,json\nfrom pathlib import Path\n'
            + f's=importlib.util.spec_from_file_location("bridge",{str(module)!r})\n'
            + 'm=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n'
            + f'c=m.Bridge(Path({str(self.f.usr)!r}),home=Path({str(self.f.home)!r}),template_root=Path({str(self.f.templates)!r}))\n'
            + 'assert c.run("inspect")[0]["status"]=="ready-to-select"\n'
            + 'assert c.run("preview",("fish",))[0]["status"]=="activation-preview"\n'
            + 'assert c.run("apply")[0]["status"]=="activation-applied"\n'
            + 'print("PASS source-hidden moved bridge+real helpers")\n')
        result = subprocess.run(sandbox(self.f.root, ['/usr/bin/python3', '-I', str(script)]),
            cwd='/', env={'PATH': '/usr/bin:/bin'}, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('PASS source-hidden', result.stdout)
        self.assertIn('.config/fish/config.fish', self.f.files())


if __name__ == '__main__':
    unittest.main()
