"""Small source-only controls. No GPG, VM, build, updater or reader actor."""
import ast
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('_updater_factory', HERE / 'prepare.py')
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)
PARENT = Path(os.environ['UPDATER_COPY_PARENT']).resolve()
EXPECTED = Path(os.environ['UPDATER_COPY_EXPECTED']).resolve()
LANE = 'scripts/ci/current604-public-pair-updater16k'


class Controls(unittest.TestCase):
    def test_exact_emission_and_real_isolated_cli(self):
        profile = F.profile()
        self.assertEqual(F.pins(F.tree(EXPECTED, checkout=True)), profile['after'])
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / 'source'
            row = subprocess.run([sys.executable, '-I', '-B', '-Werror', str(HERE / 'prepare.py'),
                                  '--parent', str(PARENT), '--output', str(output)],
                                 capture_output=True, text=True, timeout=30, check=True)
            result = json.loads(row.stdout)
            self.assertEqual(result['status'], 'SOURCE_ONLY')
            self.assertFalse(result['acceptance'])
            self.assertEqual(result['native_fit'], 'UNQUALIFIED')
            self.assertEqual(row.stderr, '')
            self.assertEqual(F.pins(F.tree(output)), profile['after'])
            for name in profile['after']:
                self.assertEqual((output / name).read_bytes(), (EXPECTED / name).read_bytes())
            for name in (LANE + '/adapter.py', LANE + '/test_lane.py'):
                ast.parse((output / name).read_bytes())
        help_row = subprocess.run([sys.executable, '-I', '-B', '-Werror', str(HERE / 'prepare.py'),
                                   '--help'], capture_output=True, text=True, timeout=10, check=True)
        self.assertIn('--parent', help_row.stdout)
        self.assertEqual(help_row.stderr, '')

    def test_drift_missing_extra_refuse_before_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            parent = root / 'parent'
            shutil.copytree(PARENT, parent, ignore=shutil.ignore_patterns('.git'))
            name = 'LICENSE'
            original = (parent / name).read_bytes()
            for mode in ('drift', 'missing', 'extra'):
                if mode == 'drift':
                    (parent / name).write_bytes(original + b'changed')
                elif mode == 'missing':
                    (parent / name).unlink()
                else:
                    (parent / name).write_bytes(original)
                    (parent / 'foreign').write_bytes(b'extra')
                output = root / mode
                with self.assertRaisesRegex(ValueError, 'whole pinned parent489'):
                    F.emit(parent, output)
                self.assertFalse(output.exists())
                if mode == 'drift':
                    (parent / name).write_bytes(original)

    def test_payload_and_profile_drift_refuse_before_output(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            factory = root / 'factory'
            shutil.copytree(HERE, factory)
            with patch.object(F, 'HERE', factory):
                path = next(p for p in (factory / 'payload').rglob('*') if p.is_file())
                original = path.read_bytes()
                path.write_bytes(original + b'changed')
                with self.assertRaisesRegex(ValueError, 'whole six replacement payloads'):
                    F.emit(PARENT, root / 'payload-output')
                self.assertFalse((root / 'payload-output').exists())
                path.write_bytes(original)
                (factory / 'profile.json').write_bytes(b'{}')
                with self.assertRaisesRegex(ValueError, 'whole fixed source profile'):
                    F.emit(PARENT, root / 'profile-output')
                self.assertFalse((root / 'profile-output').exists())

    def test_output_ownership_and_file_alias_refusals(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaisesRegex(ValueError, 'fresh output'):
                F.emit(PARENT, root)
            with self.assertRaisesRegex(ValueError, 'disjoint output'):
                F.emit(PARENT, PARENT / 'never-created')
            file = root / 'file'
            file.write_bytes(b'exact')
            before = file.stat()
            os.utime(file, ns=(1, before.st_mtime_ns))
            self.assertEqual(F.read(file), b'exact')
            link = root / 'link'
            link.symlink_to(file)
            with self.assertRaisesRegex(ValueError, 'ordinary single-link'):
                F.read(link)
            link.unlink()
            os.link(file, link)
            with self.assertRaisesRegex(ValueError, 'ordinary single-link'):
                F.read(file)

    def test_actual_generated_cost_hook_preserves_original_body_and_clocks(self):
        # Import only the exact source adapter/contract. No lane execution.
        source = EXPECTED / LANE
        old_path = list(sys.path)
        old_contract = sys.modules.pop('contract', None)
        try:
            sys.path.insert(0, str(source))
            spec = importlib.util.spec_from_file_location('_copy_cost_adapter', source / 'adapter.py')
            adapter = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(adapter)
            original = (PARENT / 'scripts/ci/full-root-upgrade-caller/upgrade_hook.py').read_bytes()
            changed = adapter.driver_cost_hook(original)
            setup = adapter.COST_FORWARD_SETUP.encode()
            self.assertTrue(changed.startswith(setup))
            self.assertEqual(changed[len(setup):].replace(
                b'        _updater_cost_forward.forward(row)\n', b'', 1), original)
            with tempfile.TemporaryDirectory() as temp:
                target = Path(temp)
                name = 'scripts/ci/full-root-upgrade-caller/upgrade_hook.py'
                path = target / name
                path.parent.mkdir(parents=True)
                path.write_bytes(original)
                value = dict(code_pins={name: adapter.C.sha(original)}, copy_seconds=1200,
                             driver_seconds=1860, verify_seconds=600)
                row = adapter.driver_cost_profile(value, target)
                self.assertEqual(path.read_bytes(), changed)
                self.assertEqual(row['clocks'], 'UNCHANGED')
                self.assertEqual([value[k] for k in ('copy_seconds', 'driver_seconds', 'verify_seconds')],
                                 [1200, 1860, 600])
                self.assertEqual((row['scalar_bytes'], row['scalar_records']), (3072, 12))
        finally:
            sys.path[:] = old_path
            sys.modules.pop('contract', None)
            if old_contract is not None:
                sys.modules['contract'] = old_contract


if __name__ == '__main__':
    unittest.main(verbosity=2)
