#!/usr/bin/env python3
"""Causal successor selection/ordering tests with inert in-memory transactions."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


trial = load('updater_v2_trial', 'updater_v2.py')
inputs = load('updater_v2_preparation', 'updater_v2_inputs.py')


def need(condition, message):
    if not condition: raise ValueError(message)


class Successor(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        data = Path(__file__).with_name('expected-updater-v2.lock').read_bytes()
        self.v2 = dict(line.split() for line in data.decode().splitlines())
        self.v1 = self.v2 | {trial.NAME: '4.4.2-1'}
        (self.root / 'expected-updater-v2.lock').write_bytes(data)

    def test_only_updater_release_may_change(self):
        encode = lambda rows: ''.join(f'{k} {v}\n' for k, v in sorted(rows.items())).encode()
        self.assertEqual(inputs.expected_lock(encode(self.v1), encode(self.v2)), self.v2)
        changed = dict(self.v2); changed['bash'] = '99-1'
        with self.assertRaisesRegex(AssertionError, 'changes more'):
            inputs.expected_lock(encode(self.v1), encode(changed))
        with self.assertRaises(AssertionError):
            inputs.expected_lock(encode(self.v1), encode(self.v2) + b'bash 1-1\n')
        composition = SimpleNamespace(lock=lambda text: dict(line.split() for line in text.splitlines()), need=need)
        self.assertEqual(trial.expected_inventory(self.root, self.v1, composition), self.v2)
        path = self.root / 'expected-updater-v2.lock'; path.write_bytes(encode(changed))
        with self.assertRaisesRegex(ValueError, 'inventory pin'):
            trial.expected_inventory(self.root, self.v1, composition)

    def simulate(self, *, drift=None):
        state = dict(self.v1); events = []
        old = {'name': trial.NAME, 'filename': 'v1.pkg.tar.xz', 'depends': ['python'], 'payload': []}
        new = {**old, 'filename': 'v2.pkg.tar.xz', 'sha256': 'a' * 64}
        plan = {'projects': [old], 'packages': [old]}
        inert = SimpleNamespace(NAME='inert-check', PAYLOAD=self.root / 'absent-payload')

        def command(argv):
            if '-U' in argv:
                version = '4.4.2-2' if argv[-1].endswith('v2.pkg.tar.xz') else '4.4.2-1'
                state[trial.NAME] = version; events.append(version)
                if drift == 'upgrade' and version == '4.4.2-2': state['bash'] = '99-1'
            if '-R' in argv:
                del state[inert.NAME]; events.append('remove-fixture')
                if drift == 'remove': state['bash'] = '99-1'
            return ''

        def check(*args):
            self.assertEqual(state, self.v2); events.append('check')
            if drift == 'check': raise ValueError('injected Check refusal')
            state[inert.NAME] = '0.1.0-1'
            return inert, {'status': 'PASS', 'installed_packages': 588, 'cases': {}}

        composition = SimpleNamespace(guard=lambda: None, need=need, inventory=lambda: dict(state), run=command)
        payloads = Mock()
        with patch.object(trial, 'expected_inventory', return_value=self.v2), \
             patch.object(trial, 'successor', return_value=new), patch.object(trial, 'check', side_effect=check):
            try:
                result = trial.run(['pacman'], plan, self.v1, self.root, self.root, composition,
                                   SimpleNamespace(payloads=payloads))
            except RuntimeError:
                if drift is None: raise
                result = None
        return result, events, state, payloads

    def test_upgrade_check_remove_and_rollback_select_correct_versions(self):
        result, events, state, payloads = self.simulate()
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(events, ['4.4.2-2', 'check', 'remove-fixture', '4.4.2-1'])
        self.assertEqual(state, self.v1)
        self.assertEqual(payloads.call_count, 2)

    def test_upgrade_drift_stops_before_check(self):
        result, events, _, payloads = self.simulate(drift='upgrade')
        self.assertIsNone(result); self.assertEqual(events, ['4.4.2-2'])
        payloads.assert_not_called()

    def test_check_or_removal_failure_cannot_reach_rollback_pass(self):
        for drift in ('check', 'remove'):
            with self.subTest(drift=drift):
                result, events, state, _ = self.simulate(drift=drift)
                self.assertIsNone(result)
                self.assertNotIn('4.4.2-1', events)
                self.assertEqual(state[trial.NAME], '4.4.2-2')

    def test_lifecycle_and_updater_successor_modes_are_exclusive_before_actors(self):
        argv = [sys.executable, '-B', str(Path(__file__).with_name('run.py'))]
        for name in ('product', 'updater', 'desktop', 'native', 'fdk', 'cache', 'output'):
            argv += ['--' + name, '/inert']
        argv += ['--lifecycle', '--updater-v2-source', '/inert']
        result = subprocess.run(argv, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn('not allowed with argument', result.stderr)


if __name__ == '__main__':
    unittest.main()
