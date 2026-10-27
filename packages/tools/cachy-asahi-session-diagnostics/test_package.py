#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Package staging and corruption controls; no diagnostic collection or install."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('package_check', HERE / 'check_package.py')
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)


class Package(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=HERE)
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)

    def stage(self):
        stage = self.work / 'stage'
        stage.mkdir(mode=0o755)
        result = subprocess.run(['/usr/bin/bash', '--noprofile', '--norc', '-c',
            'umask 022; source "$1/PKGBUILD"; srcdir=$1; pkgdir=$2; package', 'stage', str(HERE), str(stage)],
            cwd=self.work, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        return stage

    def cli(self, stage, *args):
        other = self.work / 'unrelated'
        other.mkdir(exist_ok=True)
        return subprocess.run([str(stage / 'usr/bin' / C.NAME), *args], cwd=other,
                              env={'PATH': '/nonexistent', 'PYTHONPATH': '/PRIVATE', 'PYTHONHOME': '/PRIVATE', 'LC_ALL': 'C'},
                              capture_output=True, timeout=5)

    def test_source_pins_and_exact_frozen_identity(self):
        C.check_source(HERE)

    def test_actual_unprivileged_package_function_exact_payload_and_modes(self):
        stage = self.stage()
        C.check_stage(HERE, stage)
        self.assertEqual(len(C.PAYLOAD), 7)
        self.assertFalse(list(stage.rglob('__pycache__')))

    def test_staged_help_from_unrelated_cwd_with_hostile_python_path(self):
        stage = self.stage()
        result = self.cli(stage, '--help')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'--baseline-sha256', result.stdout)
        self.assertNotIn(b'PRIVATE', result.stdout + result.stderr)
        C.check_stage(HERE, stage)

    def test_changed_missing_oversized_or_symlink_runtime_refused_before_probe(self):
        stage = self.stage()
        runtime = stage / 'usr/lib' / C.NAME / 'session_probe.py'
        original = runtime.read_bytes()
        for change in ('changed', 'missing', 'oversized', 'symlink'):
            with self.subTest(change=change):
                runtime.unlink()
                if change == 'changed':
                    runtime.write_bytes(original + b'\n# corrupted\n')
                elif change == 'oversized':
                    runtime.write_bytes(b'x' * 65537)
                elif change == 'symlink':
                    runtime.symlink_to(HERE / 'session_probe.py')
                result = self.cli(stage, '--help')
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b'')
                self.assertIn(b'runtime missing or changed', result.stderr)
                if runtime.is_symlink() or runtime.exists():
                    runtime.unlink()
                runtime.write_bytes(original)

    def test_extra_payload_wrong_mode_and_symlink_rejected(self):
        stage = self.stage()
        program = stage / 'usr/bin' / C.NAME
        program.chmod(0o777)
        with self.assertRaises(ValueError):
            C.check_stage(HERE, stage)
        program.chmod(0o755)
        extra = stage / 'usr/bin/extra'
        extra.write_text('unexpected')
        with self.assertRaises(ValueError):
            C.check_stage(HERE, stage)
        extra.unlink()
        runtime = stage / 'usr/lib' / C.NAME / 'session_probe.py'
        runtime.unlink()
        runtime.symlink_to(HERE / 'session_probe.py')
        with self.assertRaises(ValueError):
            C.check_stage(HERE, stage)

    def source_copy(self):
        root = self.work / 'recipe'
        root.mkdir()
        for name in (*C.SOURCES, 'PKGBUILD', '.SRCINFO'):
            shutil.copyfile(HERE / name, root / name)
        return root

    def test_local_source_tamper_rejected(self):
        root = self.source_copy()
        (root / 'session_probe.py').write_text('print("PRIVATE")')
        with self.assertRaises(ValueError):
            C.check_source(root)

    def test_srcinfo_drift_or_install_hook_rejected(self):
        root = self.source_copy()
        info = root / '.SRCINFO'
        original = info.read_text()
        for change in (original.replace('arch = any', 'arch = aarch64'), original + '\tinstall = surprise.install\n'):
            info.write_text(change)
            with self.assertRaises(ValueError):
                C.check_source(root)


if __name__ == '__main__':
    unittest.main(verbosity=2)
