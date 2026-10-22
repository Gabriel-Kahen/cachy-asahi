"""Exact two-profile source generation and the emitted source's real controls."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('native4k_factory', HERE / 'prepare.py')
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)
parser = argparse.ArgumentParser()
for name in ('held', 'normal', 'recovery', 'decisions'):
    parser.add_argument('--' + name, type=Path, required=True)
ARGS, rest = parser.parse_known_args()
ARGS = argparse.Namespace(**{k: v.absolute() for k, v in vars(ARGS).items()})


def load(path):
    spec = importlib.util.spec_from_file_location('_changed_factory_control', path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class Controls(unittest.TestCase):
    def test_01_both_exact_emissions_real_isolated_CLI_and_NULLs(self):
        profile = F.profile()
        with tempfile.TemporaryDirectory() as td:
            for selected in ('normal', 'recovery'):
                output = Path(td) / selected
                run = subprocess.run([sys.executable, '-I', '-B', '-Werror',
                    str(HERE / 'prepare.py'), '--held', str(ARGS.held),
                    '--profile', selected, '--output', str(output)],
                    capture_output=True, timeout=30)
                self.assertEqual(run.returncode, 0, run.stderr)
                result = json.loads(run.stdout)
                self.assertEqual(result['native_result'], 'UNQUALIFIED')
                self.assertIsNone(result['actual'])
                expected = F.pins(F.tree(getattr(ARGS, selected), checkout=True))
                self.assertEqual(F.pins(F.tree(output)), expected)
                self.assertEqual(expected, profile['variants'][selected]['files'])
                emitted = json.loads(F.read(output / 'profile.json'))
                self.assertTrue(all(emitted[k] is None for k in (
                    'wrapper_source', 'wrapper_ref', 'wrapper_run')))
                with self.assertRaisesRegex(ValueError, 'fresh output'):
                    F.emit(ARGS.held, output, selected)
                for path in output.glob('*.py'):
                    compile(F.read(path), str(path), 'exec')
                self.assertFalse(list(output.rglob('__pycache__')))

    def test_02_input_drift_missing_extra_and_alias_refuse_before_output(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            held = root / 'held'
            shutil.copytree(ARGS.held, held, ignore=shutil.ignore_patterns('.git'))
            name = next(iter(json.loads(F.read(HERE / 'input-profile.json'))['held_files']))
            path = held / name
            raw = F.read(path)
            path.write_bytes(raw + b'\n')
            output = root / 'never'
            with self.assertRaises(ValueError):
                F.emit(held, output, 'normal')
            self.assertFalse(output.exists())
            path.unlink()
            with self.assertRaises(ValueError):
                F.emit(held, output, 'recovery')
            self.assertFalse(output.exists())
            path.write_bytes(raw)
            (held / 'foreign.json').write_text('{}')
            with self.assertRaises(ValueError):
                F.emit(held, output, 'normal')
            self.assertFalse(output.exists())
            (held / 'foreign.json').unlink()
            alias = root / 'alias'
            alias.symlink_to(held, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'no-alias'):
                F.emit(alias, output, 'recovery')
            with self.assertRaisesRegex(ValueError, 'disjoint'):
                F.emit(ARGS.held, ARGS.held / 'must-not-create', 'normal')
            self.assertFalse((ARGS.held / 'must-not-create').exists())

    def test_03_readable_payload_profile_drift_and_symlinks_refuse(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            factory = root / 'factory'
            shutil.copytree(HERE, factory)
            module = load(factory / 'prepare.py')
            payload = factory / 'payload/recovery/runtime.py'
            raw = F.read(payload)
            payload.write_bytes(raw + b'\n')
            with self.assertRaises(ValueError):
                module.emit(ARGS.held, root / 'never1', 'recovery')
            self.assertFalse((root / 'never1').exists())
            payload.unlink()
            payload.symlink_to(HERE / 'payload/recovery/runtime.py')
            with self.assertRaises(ValueError):
                module.emit(ARGS.held, root / 'never2', 'normal')
            self.assertFalse((root / 'never2').exists())
            payload.unlink()
            payload.write_bytes(raw)
            profile = factory / 'profile.json'
            profile.write_bytes(F.read(profile) + b'\n')
            with self.assertRaisesRegex(ValueError, 'fixed wrapper profile'):
                module.emit(ARGS.held, root / 'never3', 'normal')
            self.assertFalse((root / 'never3').exists())

    def test_04_explicit_profile_and_unchanged_55_step_runtime_envelopes(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td) / 'never'
            for selected in (None, '16k', 'automatic'):
                with self.assertRaisesRegex(ValueError, 'explicit'):
                    F.emit(ARGS.held, output, selected)
            run = subprocess.run([sys.executable, '-I', '-B', '-Werror',
                str(HERE / 'prepare.py'), '--held', str(ARGS.held),
                '--output', str(output)], capture_output=True, timeout=10)
            self.assertNotEqual(run.returncode, 0)
            self.assertFalse(output.exists())
        for selected in ('normal', 'recovery'):
            source = getattr(ARGS, selected)
            profile = json.loads(F.read(source / 'profile.json'))
            self.assertEqual(profile['limits'], dict(owner=3900, stage=1200, copy=1200,
                driver=1860 if selected == 'normal' else 2400, verify=600,
                lifetime_cleanup=60, job_owner=15600, job=21000))
            workflow = F.read(source / F.WF)
            named = '.github/workflows/native-arm-updater604-' + (
                'copy4k' if selected == 'normal' else 'recovery4k') + '.yml'
            self.assertEqual(F.read(source / named), workflow)
            job = json.loads(workflow)['jobs']['native']
            self.assertEqual((job['runs-on'], job['timeout-minutes']), ('ubuntu-24.04-arm', 350))
            self.assertEqual(len(job['steps']), 55)

    def test_05_all_actual_emitted_source_controls_11_normal_and10_recovery(self):
        with tempfile.TemporaryDirectory() as td:
            for selected, count in (('normal', 11), ('recovery', 10)):
                output = Path(td) / selected
                F.emit(ARGS.held, output, selected)
                argv = [sys.executable, '-I', '-B', '-Werror',
                        str(output / 'test_source.py'), '--held', str(ARGS.held)]
                if selected == 'recovery':
                    argv += ['--decisions', str(ARGS.decisions)]
                run = subprocess.run(argv, capture_output=True, timeout=120)
                self.assertEqual(run.returncode, 0, run.stderr.decode())
                self.assertIn(f'Ran {count} tests'.encode(), run.stderr)
                self.assertTrue(run.stderr.endswith(b'\nOK\n'), run.stderr)
                self.assertEqual(F.pins(F.tree(output)), F.profile()['variants'][selected]['files'])


    def test_06_actual_retainer_shell_output_matches_every_upload_alias(self):
        checker = load(HERE / 'retention_path_test.py')
        with tempfile.TemporaryDirectory() as td:
            for selected in ('normal', 'recovery'):
                source = Path(td) / selected
                F.emit(ARGS.held, source, selected)
                named = '.github/workflows/native-arm-updater604-' + (
                    'copy4k' if selected == 'normal' else 'recovery4k') + '.yml'
                for name, case in ((F.WF, 'normal' if selected == 'normal' else 'precommit-exit86'),
                                   (named, 'normal' if selected == 'normal' else 'postcommit-exit87')):
                    result = checker.check(source, name, case)
                    self.assertEqual(result['files'], 11)
                    self.assertFalse(result['actual_acceptance'])
                if selected == 'recovery':
                    workflow = source / F.WF
                    workflow.write_bytes(F.read(workflow).replace(
                        b'${{ runner.temp }}/updater604-recovery4k-evidence/evidence.zip',
                        b'${{ runner.temp }}/updater604-copy4k-evidence/evidence.zip'))
                    with self.assertRaisesRegex(ValueError, 'output and upload path differ'):
                        checker.check(source, F.WF, 'precommit-exit86')


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *rest], verbosity=2)
