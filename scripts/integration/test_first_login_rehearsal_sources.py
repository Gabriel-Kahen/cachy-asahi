# SPDX-License-Identifier: MIT
"""Source-selection controls; no build, shell journey or installation."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('retained_first_login_sources', HERE / 'first_login_rehearsal.py')
rehearsal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rehearsal)


class SourceControls(unittest.TestCase):
    def test_retained02_local_pins_and_setup_canonical_roots_are_distinct(self):
        self.assertEqual(rehearsal.RECIPES['first_login'],
                         ('packages/tools/cachy-asahi-first-login', '0.1.0-2'))
        with tempfile.TemporaryDirectory(prefix='first-login-source-controls-') as temporary:
            root = Path(temporary) / 'root'
            workspace = Path(temporary) / 'workspace'
            root.mkdir()
            workspace.mkdir()
            calls = []
            for relative, _ in rehearsal.RECIPES.values():
                source = root / relative
                source.mkdir(parents=True)
                (source / 'PKGBUILD').write_text('# inert source fixture\n')
                (source / 'check-sync.py').write_text('# never executed fixture\n')

            class Runner:
                cwd = None

                def run(self, label, argv):
                    calls.append((label, argv))
                    if not label.endswith('-srcinfo'):
                        return ''
                    name = self.cwd.name
                    relative, version = rehearsal.RECIPES[name]
                    body = (root / relative / 'check-sync.py').read_bytes()
                    return '\n'.join((
                        'pkgname = ' + rehearsal.journey.PACKAGE_NAMES[name],
                        'arch = any', 'pkgver = ' + version.rsplit('-', 1)[0],
                        'pkgrel = ' + version.rsplit('-', 1)[1], 'source = check-sync.py',
                        'sha256sums = ' + hashlib.sha256(body).hexdigest())) + '\n'

            rows = rehearsal.prepare_sources(root, workspace, Runner())
            self.assertEqual(len(rows), 4)
            commands = {label: argv for label, argv in calls if label.endswith('-canonical-source')}
            self.assertEqual(commands['first_login-canonical-source'],
                             ['/usr/bin/python3', '-I', '-B', workspace / 'first_login/check-sync.py'])
            self.assertEqual(commands['setup-canonical-source'],
                             ['/usr/bin/python3', '-I', '-B', workspace / 'setup/check-sync.py', '--root', root])


if __name__ == '__main__':
    unittest.main(verbosity=2)
