# SPDX-License-Identifier: MIT
"""All four exact public source modes and real isolated entries; never native actors."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import prepare as F

RUNTIME = os.environ.get('CORE_LIFECYCLE_RUNTIME')
EXPECTED = os.environ.get('CORE_LIFECYCLE_EXPECTED')
AUTH_EXPECTED = os.environ.get('CORE_LIFECYCLE_AUTH_EXPECTED')
BASELINE_EXPECTED = os.environ.get('CORE_LIFECYCLE_BASELINE_EXPECTED')
TRANSPORT_EXPECTED = os.environ.get('CORE_LIFECYCLE_TRANSPORT_EXPECTED')
LAUNCH_EXPECTED = os.environ.get('CORE_LIFECYCLE_LAUNCH_EXPECTED')
if not RUNTIME or not EXPECTED or not LAUNCH_EXPECTED or not TRANSPORT_EXPECTED or not AUTH_EXPECTED or not BASELINE_EXPECTED:
    raise SystemExit('Set CORE_LIFECYCLE_RUNTIME to complete public d268745, '
                     'CORE_LIFECYCLE_EXPECTED to complete public 7be796 and '
                     'CORE_LIFECYCLE_LAUNCH_EXPECTED to public4ae796 and '
                     'CORE_LIFECYCLE_TRANSPORT_EXPECTED to public1450796 and '
                     'CORE_LIFECYCLE_AUTH_EXPECTED to public070797; no test is skipped.')


class Controls(unittest.TestCase):
    def check_mode(self, mode, expected_path):
        runtime, expected = Path(RUNTIME).absolute(), Path(expected_path).absolute()
        profile = F.profile()
        target = {'original796': profile['expected'], 'workflow-launch': profile['workflow_launch'],
                  'evidence-transport': profile['evidence_transport'], 'auth-import': profile['auth_import'], 'baseline-scriptlet': profile['baseline_scriptlet']}[mode]
        self.assertEqual(F.files(expected, checkout=True), target['files'])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            generated = root / 'generated'
            sentinel = types.ModuleType('contract')
            with patch.dict(sys.modules, {'contract': sentinel}), \
                 patch.object(subprocess, 'run', side_effect=AssertionError('NO_ACTORS')), \
                 patch.object(subprocess, 'Popen', side_effect=AssertionError('NO_ACTORS')):
                receipt = F.assemble(runtime, generated, mode)
                self.assertIs(sys.modules['contract'], sentinel)
            self.assertEqual(receipt['files'], len(target['files']))
            self.assertEqual(receipt['source_mode'], mode)
            self.assertEqual(receipt['native_lifecycle'], 'NOT_RUN_BY_FACTORY')
            if mode == 'baseline-scriptlet':
                self.assertEqual(receipt['dispatch'], 'SEPARATE_ROOT_NATIVE_DISPATCH_AND_ACCEPTANCE_REQUIRED')
            else:
                self.assertTrue(receipt['dispatch'].endswith('DO_NOT_DISPATCH'))
            self.assertEqual(F.files(generated), F.files(expected, checkout=True))
            lane = generated / 'scripts/ci/core-native-lifecycle'
            with F.modules(lane):
                factory = F.load(lane / 'prepare.py', '_emitted_core796_self_factory')
                with patch.object(subprocess, 'run', side_effect=AssertionError('NO_ACTORS')), \
                     patch.object(subprocess, 'Popen', side_effect=AssertionError('NO_ACTORS')):
                    factory.emit(runtime, root / 'self-reproduced')
            self.assertEqual(F.files(root / 'self-reproduced'), target['files'])

            # Real Python source/help/portable checks only, with no inherited workspace variable.
            environment = {'PATH': os.defpath, 'LANG': 'C', 'LC_ALL': 'C',
                           'PYTHONDONTWRITEBYTECODE': '1'}
            def python(arguments):
                result = subprocess.run([sys.executable, '-I', '-B', '-Werror', *arguments],
                                        cwd=root, env=environment, capture_output=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr.decode(errors='replace'))
                return result.stdout

            for entry in (HERE / 'prepare.py', *(lane / name for name in
                          ('entry.py', 'prepare.py', 'owner.py', 'assemble.py', 'container.py',
                           'run.py', 'test_signer.py', 'capability_snapshot.py'))):
                self.assertIn(b'usage:', python([str(entry), '--help']))
            source = json.loads(python([str(lane / 'entry.py'), 'source', '--source', str(generated)]))
            self.assertEqual(source['files'], len(target['files']))
            self.assertEqual(source['status'], 'PASS_CLOSED_CORE7_SOURCE_ONLY')
            imported = json.loads(python([str(lane / 'assemble.py'), '--source-only']))
            self.assertEqual(imported['signing'], 'NOT_RUN')
            if mode == 'baseline-scriptlet':
                python([str(lane / 'test_fixture.py')])
            python([str(lane / 'test_contract.py')])  # All six existing meaningful controls.
            arguments = [str(HERE / 'prepare.py'), '--runtime', str(runtime),
                         '--output', str(root / 'cli-emitted')]
            if mode != 'baseline-scriptlet':
                arguments += ['--mode', mode]  # Auth-import mode also verifies the exact default CLI.
            emitted = json.loads(python(arguments))
            self.assertEqual(emitted['files'], len(target['files']))
            self.assertEqual(emitted['source_mode'], mode)
            self.assertEqual(F.files(root / 'cli-emitted'), target['files'])

    def test_whole_historical796_explicit_and_self_reproduction(self):
        self.check_mode('original796', EXPECTED)

    def test_whole_historical_workflow_launch_explicit_and_self_reproduction(self):
        self.check_mode('workflow-launch', LAUNCH_EXPECTED)

    def test_whole_historical_transport_explicit_and_self_reproduction(self):
        self.check_mode('evidence-transport', TRANSPORT_EXPECTED)

    def test_whole_auth_import797_default_and_self_reproduction(self):
        self.check_mode('auth-import', AUTH_EXPECTED)

    def test_whole_baseline800_default_and_self_reproduction(self):
        self.check_mode('baseline-scriptlet', BASELINE_EXPECTED)

    def test_real_parent_drift_refuses_before_output(self):
        runtime = Path(RUNTIME).absolute()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'must-not-exist'
            original = F.files
            def drift(root, **kwargs):
                rows = original(root, **kwargs)
                if Path(root) == runtime:
                    rows[next(iter(rows))] = {'bytes': 1, 'sha256': '0' * 64}
                return rows
            with patch.object(F, 'files', side_effect=drift), \
                 patch.object(F, 'load', side_effect=AssertionError('EMITTER_MUST_NOT_START')):
                with self.assertRaisesRegex(ValueError, 'predecessor'):
                    F.assemble(runtime, output)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
