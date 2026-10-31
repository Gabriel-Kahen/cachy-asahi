#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Original package checks: real CLI, private prefixes, no session/sensor access."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

RECIPE = None
EVIDENCE = None


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text())


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


class Package(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('bwrap'):
            raise RuntimeError('bubblewrap is required; no unsandboxed fallback')
        cls.temporary = None if EVIDENCE else tempfile.TemporaryDirectory(prefix='measurement-package-')
        cls.root = EVIDENCE or Path(cls.temporary.name)
        cls.root.mkdir(parents=True, exist_ok=True)
        cls.prefixes = []
        cls.commands = []
        cls.journeys = []
        cls.sandbox = ['bwrap', '--die-with-parent', '--ro-bind', '/', '/', '--bind', str(cls.root), str(cls.root),
            '--dev', '/dev', '--tmpfs', '/sys', '--unshare-net', '--unshare-pid', '--proc', '/proc', '--']
        cls.env = os.environ | {'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': str(cls.root / 'poison')}
        (cls.root / 'poison').mkdir()
        for name in ('json', 'platform', 'benchmark', 'platform_metrics'):
            (cls.root / 'poison' / (name + '.py')).write_text('raise RuntimeError("cwd/PYTHONPATH injected")\n')
        for name in ('one', 'two'):
            stage = cls.root / ('staging-' + name)
            (stage / 'source').mkdir(parents=True)
            for line in (RECIPE / '.SRCINFO').read_text().splitlines():
                if line.strip().startswith('source = '):
                    filename = line.strip().split(' = ', 1)[1]
                    (stage / 'source' / filename).symlink_to(RECIPE / filename)
            result = subprocess.run(['bash', '-euc', 'source "$1/PKGBUILD"; srcdir=$2/source; pkgdir=$2/payload; prepare; package',
                'package-stage', str(RECIPE), str(stage)], capture_output=True, text=True, timeout=15)
            if result.returncode:
                raise RuntimeError(result.stdout + result.stderr)
            moved = cls.root / ('moved prefix ' + name)
            (stage / 'payload/usr').rename(moved)
            cls.prefixes.append(moved)

    @classmethod
    def tearDownClass(cls):
        write(cls.root / 'commands.json', cls.commands)
        if cls.temporary:
            cls.temporary.cleanup()

    def cli(self, prefix, *args, expected=0):
        command = [*self.sandbox, str(prefix / 'bin/cachy-asahi-measurement-tools'), *map(str, args)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=15,
                                cwd=self.root / 'poison', env=self.env)
        self.commands.append({'argv': command, 'returncode': result.returncode,
                              'stdout': result.stdout[:2000], 'stderr': result.stderr[:2000]})
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def compare(self, journey, output, directories=None, expected=2):
        prefix, work, runs = journey
        return self.cli(prefix, 'benchmark', 'compare', '--plan', work / 'plan.json',
            '--runs', *(directories or runs), '--output', work / output, expected=expected)

    def test_01_original_source_and_exact_payload(self):
        provenance = read(RECIPE / 'source-provenance.json')
        self.assertEqual(provenance['base_commit'], '852d1b7324e4ad840fa94ea7c9fc994b1aa07280')
        for row in provenance['sources']:
            self.assertEqual(sha(RECIPE / row['file']), row['sha256'])
            self.assertEqual((RECIPE / row['file']).stat().st_size, row['bytes'])
            self.assertEqual(row['transformation'], 'none; byte-identical')
        mapping = read(RECIPE / 'payload-map.json')
        expected = {row['installed'] for row in mapping['files']} | {mapping['self_path']}
        for prefix in self.prefixes:
            actual = {str(p.relative_to(prefix)) for p in prefix.rglob('*') if p.is_file()}
            self.assertEqual(actual, expected)
            self.assertFalse(any(p.is_symlink() for p in prefix.rglob('*')))
            for row in mapping['files']:
                target = prefix / row['installed']
                self.assertEqual(sha(target), row['sha256'])
                self.assertEqual(target.stat().st_mode & 0o777, int(row['mode'], 8))
            self.assertEqual(sha(prefix / mapping['self_path']), sha(RECIPE / 'payload-map.json'))

    def test_02_relocated_isolated_cli(self):
        for prefix in self.prefixes:
            self.assertIn('0.1.0', self.cli(prefix, '--version').stdout)
            self.cli(prefix, 'benchmark', 'run', '--help')
            self.cli(prefix, 'metrics', 'capture', '--help')
            self.assertIn('requires --platform-metrics', self.cli(prefix, 'benchmark', 'run', expected=2).stderr)
        self.assertEqual(sha(self.prefixes[0] / 'bin/cachy-asahi-measurement-tools'),
                         sha(self.prefixes[1] / 'bin/cachy-asahi-measurement-tools'))

    def test_03_complete_host_journeys(self):
        for index, prefix in enumerate(self.prefixes):
            work = self.root / ('journey-' + str(index))
            work.mkdir()
            self.cli(prefix, 'state', '--execution-context', 'unknown', '--output', work / 'base.json')
            shutil.copyfile(work / 'base.json', work / 'candidate.json')
            shutil.copyfile(RECIPE / 'smoke_workload.py', work / 'workload.py')
            config = read(RECIPE / 'experiment.example.json')
            config['argv'] = ['/usr/bin/python3', str(work / 'workload.py')]
            config['inputs'] = config['argv'].copy()
            config['thresholds']['minimum_elapsed_improvement_pct'] = 0 if index == 0 else 100
            write(work / 'config.json', config)
            shutil.copyfile(RECIPE / 'conditions.example.json', work / 'conditions.json')
            self.cli(prefix, 'benchmark', 'prepare-plan', '--config', work / 'config.json', '--baseline',
                     work / 'base.json', '--candidate-state', work / 'candidate.json', '--output', work / 'plan.json')
            self.assertEqual(read(work / 'plan.json')['optimization_acceptance'], 'NOT RUN')
            runs = []
            for slot, variant in enumerate(config['order']):
                run = work / ('trial-' + str(slot))
                self.cli(prefix, 'benchmark', 'run', '--plan', work / 'plan.json', '--slot', slot,
                    '--state', work / ('base.json' if variant == 'baseline' else 'candidate.json'),
                    '--conditions', work / 'conditions.json', '--cwd', work, '--output', run, '--platform-metrics')
                trial = read(run / 'trial.json')
                self.assertTrue(trial['valid'])
                self.assertEqual(trial['optimization_acceptance'], 'NOT RUN')
                self.assertIsNone(trial['metrics']['root_rss_kib'])
                self.assertEqual(trial['execution_label'].split('/')[-1], 'unknown nonacceptance smoke')
                inventory = read(run / 'platform-metrics/inventory.json')
                self.assertEqual(inventory['sensors'], [])
                self.assertTrue(all(c['status'] == 'absent' for c in inventory['classes'].values()))
                capture = read(run / 'platform-metrics/capture.json')
                self.assertTrue(capture['completed'])
                self.assertTrue(capture['supervision']['reaped'])
                self.assertEqual(capture['supervision']['ownership'], 'REAPED')
                runs.append(run)
            journey = (prefix, work, runs)
            self.journeys.append(journey)
            self.compare(journey, 'comparison.json')
            report = read(work / 'comparison.json')
            self.assertEqual(report['preliminary_result'], 'INCOMPLETE' if index == 0 else 'FAIL')
            self.assertEqual(report['optimization_acceptance'], 'NOT RUN')
            self.assertTrue(report['missing_guardrail_telemetry'])
            self.assertEqual(len(report['trial_bindings']), 12)
            self.cli(prefix, 'metrics', 'capture', '--machine-label', 'inert host only', '--duration', '.2',
                     '--interval', '.1', '--output', work / 'capture')
            self.cli(prefix, 'metrics', 'summarize', '--capture', work / 'capture', '--output', work / 'replay.json')
            self.assertEqual(read(work / 'replay.json')['sensors'], [])
            self.assertEqual(read(work / 'replay.json')['sensor_count'], 0)

    def test_04_missing_duplicate_and_mixed_plan_trials(self):
        first, second = self.journeys
        for label, runs in [('missing', first[2][:-1]), ('duplicate', first[2] + first[2][:1]),
                            ('mixed', second[2][:1] + first[2][1:])]:
            self.compare(first, label + '.json', runs)
            self.assertFalse((first[1] / (label + '.json')).exists())

    def test_05_state_and_source_drift_refused(self):
        prefix, work, runs = self.journeys[0]
        for name in ('base.json', 'workload.py'):
            path = work / name
            original = path.read_bytes()
            path.write_bytes(original + b' ')
            try:
                result = self.compare(self.journeys[0], name + '-drift.json')
                self.assertIn('changed after declaration', result.stderr)
            finally:
                path.write_bytes(original)

    def test_06_raw_and_capture_tamper_refused(self):
        _, work, runs = self.journeys[0]
        for name in ('stdout.txt', 'platform-metrics/samples.jsonl', 'platform-metrics/summary.json'):
            path = runs[0] / name
            original = path.read_bytes()
            path.write_bytes(original + b' ')
            try:
                self.compare(self.journeys[0], 'tamper-' + path.name)
                self.assertFalse((work / ('tamper-' + path.name)).exists())
            finally:
                path.write_bytes(original)

    def test_07_mismatched_baseline_invalid_budgets_and_flag(self):
        prefix, work, runs = self.journeys[0]
        config = read(work / 'config.json')
        baseline = read(work / 'base.json')
        write(work / 'mismatched.json', baseline | {'page_size_bytes': baseline['page_size_bytes'] * 2})
        result = self.cli(prefix, 'benchmark', 'prepare-plan', '--config', work / 'config.json',
            '--baseline', work / 'base.json', '--candidate-state', work / 'mismatched.json',
            '--output', work / 'bad-state-plan.json', expected=2)
        self.assertIn('state differences', result.stderr)
        for label, delta in [('few', {'order': ['baseline', 'candidate'] * 4}),
                             ('grouped', {'order': ['baseline'] * 6 + ['candidate'] * 6}),
                             ('unbounded', {'platform_metrics': {'interval_seconds': 0.01}})]:
            write(work / (label + '-config.json'), config | delta)
            self.cli(prefix, 'benchmark', 'prepare-plan', '--config', work / (label + '-config.json'),
                '--baseline', work / 'base.json', '--candidate-state', work / 'candidate.json',
                '--output', work / (label + '-plan.json'), expected=2)
            self.assertFalse((work / (label + '-plan.json')).exists())
        legacy = copy.deepcopy(config)
        legacy.pop('platform_metrics')
        write(work / 'legacy-config.json', legacy)
        self.cli(prefix, 'benchmark', 'prepare-plan', '--config', work / 'legacy-config.json',
            '--baseline', work / 'base.json', '--candidate-state', work / 'candidate.json',
            '--output', work / 'legacy-plan.json')
        result = self.cli(prefix, 'benchmark', 'run', '--plan', work / 'legacy-plan.json', '--slot', 0,
            '--state', work / 'base.json', '--conditions', work / 'conditions.json', '--cwd', work,
            '--output', work / 'must-not-run', '--platform-metrics', expected=2)
        self.assertIn('flag must match', result.stderr)
        self.assertFalse((work / 'must-not-run').exists())

    def test_08_freshness_move_and_private_removal(self):
        prefix, work, runs = self.journeys[0]
        self.compare(self.journeys[0], 'comparison.json')
        self.cli(prefix, 'state', '--execution-context', 'unknown', '--output', work / 'base.json', expected=2)
        moved = self.root / 'moved-again'
        prefix.rename(moved)
        try:
            self.cli(moved, '--version')
            result = self.cli(moved, 'benchmark', 'compare', '--plan', work / 'plan.json',
                '--runs', *runs, '--output', work / 'old-location.json', expected=2)
            self.assertFalse((work / 'old-location.json').exists())
            self.assertTrue('No such file' in result.stderr or 'changed' in result.stderr)
        finally:
            moved.rename(prefix)
        disposable = self.root / 'removal-prefix'
        shutil.copytree(prefix, disposable)
        for file in disposable.rglob('*'):
            if file.is_file():
                file.unlink()
        for directory in sorted(disposable.rglob('*'), key=lambda p: len(p.parts), reverse=True):
            directory.rmdir()
        disposable.rmdir()
        self.assertTrue((work / 'comparison.json').is_file())
        self.assertFalse(any(self.root.rglob('*.pyc')))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--recipe-root', type=Path, required=True)
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    RECIPE = args.recipe_root.resolve(strict=True)
    EVIDENCE = args.evidence.absolute() if args.evidence else None
    if EVIDENCE and EVIDENCE.exists():
        raise SystemExit('evidence directory must be fresh')
    unittest.main(argv=[sys.argv[0]], verbosity=2, failfast=True)
