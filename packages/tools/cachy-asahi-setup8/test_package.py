# SPDX-License-Identifier: MIT
"""Meaningful isolated delivery checks; no package installation or host configuration."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def stage(root):
    for name, row in json.loads((HERE / 'payload-map.json').read_text()).items():
        path = root / name;path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(HERE / row['source'], path);path.chmod(row['mode'])


class PackageTests(unittest.TestCase):
    def test_staged_real_launcher_ignores_poisoned_pythonpath(self):
        with tempfile.TemporaryDirectory(prefix='setup8-stage-help-') as td:
            root = Path(td);stage(root)
            poison = root / 'poison';poison.mkdir();(poison / 'setup.py').write_text("raise RuntimeError('PYTHONPATH injection')")
            result = subprocess.run([str(root / 'usr/bin/cachy-asahi-config-migrate'), '--help'],
                                    env=dict(os.environ, PYTHONPATH=str(poison)), capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('preview', result.stdout)
            self.assertFalse(list(root.rglob('__pycache__')))

    def test_staged_delivered_clis_execute_all_private_fixture_controls(self):
        with tempfile.TemporaryDirectory(prefix='setup8-stage-controls-') as td:
            root = Path(td) / 'root';root.mkdir();stage(root)
            result = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'test_delivery.py'), '--root', str(root)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            value = json.loads(result.stdout)
            self.assertEqual(value['status'], 'PASS_SETUP8_DELIVERED_CLI_PRIVATE_FIXTURES')
            self.assertEqual(value['actual_sigkill_returncode'], -9)
            self.assertTrue(value['private_fixtures_retired'])
            self.assertTrue(all(v == 'PASS' for v in value['cases'].values()))
            self.assertGreaterEqual(len(value['cases']), 12)
            self.assertFalse(list(root.rglob('__pycache__')))

    def test_reinstall_verifier_uses_persistent_user_snapshot_and_installed_cli(self):
        with tempfile.TemporaryDirectory(prefix='setup8-stage-reinstall-') as td:
            root = Path(td) / 'root';root.mkdir();stage(root);work = Path(td) / 'explicit-fixtures'
            argv = [sys.executable, '-I', '-B', str(HERE / 'test_delivery.py'), '--root', str(root), '--work', str(work)]
            first = subprocess.run([*argv, '--keep-fixtures'], capture_output=True, text=True, timeout=30)
            self.assertEqual(first.returncode, 0, first.stderr)
            # This is a host staging disappearance/reappearance control, not ALPM.
            shutil.rmtree(root);root.mkdir();stage(root)
            second = subprocess.run([*argv, '--verify-reinstall'], capture_output=True, text=True, timeout=15)
            self.assertEqual(second.returncode, 0, second.stderr)
            self.assertEqual(json.loads(second.stdout)['cases'], {'post-package-reinstall-user-version-preserved':'PASS'})
            path = work / 'existing/.zshrc';path.write_bytes(path.read_bytes() + b'changed\n')
            refused = subprocess.run([*argv, '--verify-reinstall'], capture_output=True, text=True, timeout=15)
            self.assertEqual(refused.returncode, 1)
            self.assertIn('changed private user homes', refused.stderr)

    def test_snapshot_checker_rejects_drift_without_rewriting_it(self):
        with tempfile.TemporaryDirectory(prefix='setup8-source-drift-') as td:
            root = Path(td) / 'inputs';root.mkdir()
            names = set(json.loads((HERE / 'source-provenance.json').read_text())['input_sha256'])
            names |= {'source-provenance.json', 'PKGBUILD', '.SRCINFO'}
            self.assertEqual(len(names), 20)
            self.assertTrue(all(type(name) is str and name not in ('', '.', '..')
                                and Path(name).name == name and '\\' not in name
                                and all(32 <= ord(c) != 127 for c in name) for name in names))
            for name in sorted(names):shutil.copyfile(HERE / name, root / name)
            result = subprocess.run([sys.executable, '-B', str(root / 'check-sync.py'), '--snapshot'], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            path = root / 'config_migrate.py';path.write_bytes(path.read_bytes() + b'# changed\n');before = path.read_bytes()
            result = subprocess.run([sys.executable, '-B', str(root / 'check-sync.py'), '--snapshot'], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(path.read_bytes(), before)


if __name__ == '__main__':unittest.main(verbosity=2)
