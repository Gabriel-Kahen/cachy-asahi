#!/usr/bin/env python3
"""Checkpoint selection and drift refusal without builds or package actors."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


inputs = load('setup4_host_inputs', 'setup4_inputs.py')
host = load('setup4_host', 'run.py')


class Setup4Inputs(unittest.TestCase):
    def test_only_setup_release_may_change_for_both_checkpoints(self):
        for v2 in (False, True):
            with self.subTest(v2=v2):
                before = (inputs.HERE / ('expected-updater-v2.lock' if v2 else 'expected-installed.lock')).read_bytes()
                target = (inputs.HERE / ('expected-setup4-v2.lock' if v2 else 'expected-setup4-v1.lock')).read_bytes()
                rows = inputs.expected_lock(before, target)
                self.assertEqual(rows['cachy-asahi-update'], '4.4.2-2' if v2 else '4.4.2-1')
                self.assertEqual(rows['cachy-asahi-setup'], '0.1.0-4')
                changed = target.replace(b'bash 5.', b'bash 9.', 1)
                self.assertNotEqual(changed, target)
                with self.assertRaisesRegex(AssertionError, 'changes more'):
                    inputs.expected_lock(before, changed)
                with self.assertRaises(AssertionError):
                    inputs.expected_lock(before, target + b'bash 1-1\n')

    def test_setup4_v2_selection_replaces_only_initial_updater_and_lock(self):
        rows = [{'name': 'cachy-asahi-update', 'version': '4.4.2-1'},
                {'name': 'cachy-asahi-setup', 'version': '0.1.0-3'}, {'name': 'other', 'version': '1'}]
        projects = [dict(row, archive='old.pkg.tar.xz') for row in rows]
        successor = {'package': {'name': 'cachy-asahi-update', 'version': '4.4.2-2',
                                 'filename': 'v2.pkg.tar.xz', 'signature_sha256': 'a' * 64},
                     'expected_inventory_sha256': host.sha(host.HERE / 'expected-updater-v2.lock')}
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            untouched = host.setup4_checkpoint(None, rows, projects, root)
            self.assertIs(untouched[0], rows); self.assertIs(untouched[1], projects)
            self.assertFalse(list(root.iterdir()))
            selected, metadata, digest = host.setup4_checkpoint(successor, rows, projects, root)
            self.assertEqual(selected[0], successor['package'])
            self.assertEqual(metadata[0]['archive'], 'v2.pkg.tar.xz')
            self.assertEqual(metadata[0]['signature_sha256'], 'a' * 64)
            self.assertEqual(selected[1:], rows[1:]); self.assertEqual(metadata[1:], projects[1:])
            self.assertEqual(rows[0]['version'], '4.4.2-1')
            self.assertEqual(digest, successor['expected_inventory_sha256'])
            self.assertEqual((root / 'expected-installed.lock').read_bytes(),
                             (host.HERE / 'expected-updater-v2.lock').read_bytes())

    def test_setup4_and_historical_lifecycle_refused_before_platform_or_actors(self):
        argv = [sys.executable, '-B', str(host.HERE / 'run.py')]
        for name in ('product', 'updater', 'desktop', 'native', 'fdk', 'cache', 'output'):
            argv += ['--' + name, '/inert']
        result = subprocess.run(argv + ['--lifecycle', '--setup4-pair', '/inert'],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn('--setup4-pair is incompatible with --lifecycle', result.stderr)


if __name__ == '__main__':
    unittest.main()
