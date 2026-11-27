# SPDX-License-Identifier: MIT
"""Verify that CI stages the checker bytes held by each source profile."""

import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / 'scripts/ci'
CHECKER = Path('scripts/checks/package_checks.py')
RUNTIME_CHECKER = 'runtime/' + CHECKER.as_posix()
SOURCE95_CHECKER = (
    Path('scripts/ci/llhttp-minimal-native-source-data/fixtures/Source95/held-source')
    / 'scripts/ci/llhttp-reference-native-source/base' / RUNTIME_CHECKER
)
LIVE = b'# Unpinned live checker\n'


def write(path, body=b''):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)


class HeldPackageCheckerSources(unittest.TestCase):
    def test_apps_action_stages_pinned_checkout_checker(self):
        action = (ROOT / '.github/actions/apps-package-source/action.yml').read_text()
        self.assertIn('        ref: 565e10bfe7ef00b0528881dfba08e0f0fe50721c\n', action)
        self.assertIn('          /scripts/checks/package_checks.py\n', action)
        stage = action.split('    - name: Stage the package check inputs\n', 1)[1]
        stage = textwrap.dedent(stage.split('      run: |\n', 1)[1].split('\n    - ', 1)[0])
        frozen = (ROOT / SOURCE95_CHECKER).read_bytes()
        pin = {'bytes': len(frozen), 'sha256': hashlib.sha256(frozen).hexdigest()}

        with tempfile.TemporaryDirectory() as name:
            temp = Path(name)
            workspace = temp / 'workspace'
            held = workspace / '.ci-inputs/apps-package-release'
            output = temp / 'output'
            for relative in ('LICENSE', 'scripts/client/client.py', 'scripts/release/source_delivery.py'):
                write(workspace / relative)
            for relative in ('scripts/release/release.py', 'scripts/release/test_release.py'):
                write(held / relative)
            write(held / CHECKER, frozen)
            write(workspace / CHECKER, LIVE)
            packages = workspace / 'packages/tools'
            for package in ('cachy-asahi-repository-client-v2', 'cachy-asahi-repository-runtime', 'cachy-asahi-apps7'):
                (packages / package).mkdir(parents=True)

            for revision in range(8, 17):
                with self.subTest(revision=revision):
                    (packages / f'cachy-asahi-apps{revision}').mkdir()
                    profile = json.loads((CI / f'apps{revision}-package/profile.json').read_bytes())
                    self.assertEqual(profile['held'][CHECKER.as_posix()], pin)
                    output.write_text('')
                    env = dict(os.environ, APPS_REVISION=str(revision), GITHUB_WORKSPACE=str(workspace),
                               RUNNER_TEMP=str(temp), GITHUB_OUTPUT=str(output))
                    subprocess.run(['bash', '--noprofile', '--norc', '-e', '-o', 'pipefail'],
                                   input=stage, text=True, env=env, check=True)
                    staged = Path(output.read_text().strip().removeprefix('path='))
                    self.assertEqual((staged / CHECKER).read_bytes(), frozen)
                    self.assertEqual((workspace / CHECKER).read_bytes(), LIVE)

    def test_libgit2_uses_source95_checker_and_rejects_tampering(self):
        libgit2 = CI / 'libgit2-reference-native-source'
        select = runpy.run_path(str(libgit2 / 'prepare.py'))['held_framework_body']
        profile = json.loads((libgit2 / 'base/profile.json').read_bytes())
        row = profile['held_inputs'][RUNTIME_CHECKER]
        frozen = (ROOT / SOURCE95_CHECKER).read_bytes()

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            write(root / CHECKER, LIVE)
            write(root / SOURCE95_CHECKER, frozen)
            self.assertEqual(select(root, RUNTIME_CHECKER, row), frozen)

            write(root / CHECKER, frozen)
            write(root / SOURCE95_CHECKER, LIVE)
            with self.assertRaisesRegex(ValueError, 'exact held framework dependency'):
                select(root, RUNTIME_CHECKER, row)


if __name__ == '__main__':
    unittest.main()
