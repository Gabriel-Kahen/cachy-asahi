# SPDX-License-Identifier: MIT
"""Custody/refusal controls; real packaging evidence comes from the separate CLI."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('python_development', ROOT / 'scripts/workflows/python_development.py')
P = importlib.util.module_from_spec(spec); spec.loader.exec_module(P)


class Commands:
    """Explicit no-launch unit stub, never a frontend or wheel implementation."""
    def __init__(self, output):
        self.output, self.records, self.env = output, [], {}

    def run(self, *args):
        self.records.append(args)
        raise AssertionError('unit refusal control attempted a launch')


class PythonDevelopmentTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='python-workflow-controls-')
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.commands = Commands(self.base)
        self.python = self.base / 'selected python'; self.python.write_bytes(b'unit-interpreter')
        self.uv = self.base / 'selected uv'; self.uv.write_bytes(b'unit-frontend')
        self.project = P.Project(self.commands, str(self.python), str(self.uv), self.base)
        self.project.venv.mkdir()
        (self.project.venv / 'bin').mkdir()
        (self.project.venv / 'bin/python').symlink_to(self.python)
        (self.project.venv / 'pyvenv.cfg').write_text('include-system-site-packages = false\n')

    def authorize_unit_receipts(self):
        # Arbitrary bytes test gates only. They are never passed to a package tool.
        wheel = self.base / 'unit-gate-product'; wheel.write_bytes(b'unit-product')
        self.project.built = dict(inputs=self.project.inputs(), wheel=str(wheel), wheel_pin=P.file_pin(wheel))
        module = self.project.venv / 'unit-installed-module.py'; module.write_bytes(b'unit-installed')
        self.project.installed = dict(files={module.name: P.ordinary_pin(module)})
        self.project.tested = True

    def test_original_dependency_free_fixture(self):
        import tomllib
        files = P.fixture_files()
        config = tomllib.loads(files['pyproject.toml'].decode())
        self.assertEqual(config['project']['dependencies'], [])
        self.assertEqual(config['build-system']['requires'], ['uv_build==' + P.UV_VERSION])
        self.assertIn(b'MIT License', files['LICENSE'])

    def test_explicit_executable_required(self):
        for path in ('python3', str(self.base / 'absent'), str(self.python)):
            with self.subTest(path=path), self.assertRaises(ValueError):
                P.executable(path)
        self.python.chmod(0o700)
        alias = self.base / 'alias'; alias.symlink_to(self.python)
        self.assertEqual(P.executable(alias), str(self.python))

    def test_venv_invocation_path_preserved(self):
        self.assertNotEqual(self.project.env_python, str(self.python))
        self.assertEqual(Path(self.project.env_python).resolve(), self.python)

    def test_offline_argv_uses_private_cache(self):
        argv = self.project.uv_argv('build', '--wheel')
        for flag in ('--offline', '--no-config', '--no-python-downloads'):
            self.assertIn(flag, argv)
        self.assertEqual(argv[argv.index('--cache-dir') + 1], str(self.base / 'cache'))
        self.assertEqual(argv[0], str(self.uv))

    def test_unbuilt_run_refused_without_launch(self):
        self.project.refuse_stale('unbuilt')
        self.assertEqual(self.commands.records, [])

    def test_source_edit_same_mtime_revokes(self):
        self.authorize_unit_receipts()
        path = self.project.source / P.NAMES[3]; stamp = path.stat().st_mtime_ns
        path.write_bytes(path.read_bytes() + b'# changed\n'); os.utime(path, ns=(stamp, stamp))
        self.project.refuse_stale('edited')
        self.assertFalse(self.project.tested)

    def test_frontend_tamper_revokes(self):
        self.authorize_unit_receipts(); self.uv.write_bytes(b'changed frontend')
        self.project.refuse_stale('frontend-tamper')

    def test_interpreter_tamper_revokes(self):
        self.authorize_unit_receipts(); self.python.write_bytes(b'changed interpreter')
        self.project.refuse_stale('interpreter-tamper')

    def test_environment_config_tamper_revokes(self):
        self.authorize_unit_receipts()
        (self.project.venv / 'pyvenv.cfg').write_text('include-system-site-packages = true\n')
        self.project.refuse_stale('environment-tamper')

    def test_venv_interpreter_rebinding_revokes(self):
        self.authorize_unit_receipts()
        other = self.base / 'other-python'; other.write_bytes(b'other interpreter')
        path = Path(self.project.env_python); path.unlink(); path.symlink_to(other)
        self.project.refuse_stale('environment-rebind')

    def test_wheel_tamper_revokes(self):
        self.authorize_unit_receipts()
        Path(self.project.built['wheel']).write_bytes(b'changed wheel')
        self.project.refuse_stale('wheel-tamper')

    def test_installed_module_tamper_revokes(self):
        self.authorize_unit_receipts()
        (self.project.venv / 'unit-installed-module.py').write_bytes(b'changed module')
        self.project.refuse_stale('install-tamper')

    def test_installed_symlink_refused(self):
        self.authorize_unit_receipts()
        path = self.project.venv / 'unit-installed-module.py'; path.unlink(); path.symlink_to(self.python)
        self.project.refuse_stale('install-symlink')

    def test_untested_installation_refused(self):
        self.authorize_unit_receipts(); self.project.tested = False
        self.project.refuse_stale('untested')

    def test_unchanged_build_launches_nothing(self):
        self.authorize_unit_receipts(); before = dict(self.project.built)
        self.project.build('unchanged')
        self.assertEqual(self.project.built, before)
        self.assertEqual(self.commands.records, [])

    def test_expected_build_failure_revokes_stale_install(self):
        self.authorize_unit_receipts()
        with mock.patch.object(self.project, 'command', return_value=b'INTENTIONAL_BUILD_FAILURE'):
            self.project.build('failed', expected='nonzero')
        self.assertIsNone(self.project.built)
        self.assertIsNone(self.project.installed)
        self.project.refuse_stale('failed-stale')

    def test_unrelated_build_failure_is_not_accepted(self):
        self.authorize_unit_receipts()
        with mock.patch.object(self.project, 'command', return_value=b'unrelated frontend error'):
            with self.assertRaises(P.Failure):
                self.project.build('wrong-failure', expected='nonzero')
        self.assertFalse(self.project.tested)

    def test_expected_test_failure_revokes_run(self):
        self.authorize_unit_receipts()
        with mock.patch.object(self.project, 'command', return_value=b'INTENTIONAL_TEST_MISMATCH\nRan 1 test\nFAILED (failures=1)\n'):
            self.project.test('failed-test', P.ORIGINAL, expected='nonzero')
        self.project.refuse_stale('failed-test-stale')

    def test_zero_tests_never_qualify(self):
        self.authorize_unit_receipts()
        with mock.patch.object(self.project, 'command', return_value=b'Ran 0 tests\nOK\n'):
            with self.assertRaises(P.Failure):
                self.project.test('empty-test', P.ORIGINAL)
        self.assertFalse(self.project.tested)

    def test_run_output_mismatch_revokes_run(self):
        self.authorize_unit_receipts()
        with mock.patch.object(self.project, 'command', return_value=b'wrong output\n'):
            with self.assertRaises(P.Failure):
                self.project.run('wrong-output', P.ORIGINAL)
        self.assertFalse(self.project.tested)

    def test_invalid_budgets_refused_before_workspace_creation(self):
        for timeout, total in ((float('nan'), 180), (2, float('inf')), (1, 180), (20, 19), (61, 180)):
            output = self.base / 'not-created'
            with self.subTest(timeout=timeout, total=total), self.assertRaises(ValueError):
                P.run(output, '/usr/bin/python3', timeout=timeout, total=total)
            self.assertFalse(output.exists())

    def test_existing_output_refused_before_commands(self):
        with self.assertRaises(FileExistsError):
            P.run(self.base, '/usr/bin/python3')

    def test_output_symlink_refused(self):
        alias = self.base / 'alias-dir'; alias.symlink_to(self.project.source, target_is_directory=True)
        with self.assertRaises(ValueError):
            P.run(alias / 'new', '/usr/bin/python3')

    def test_missing_uv_is_explicit_not_run(self):
        output = self.base / 'missing-uv'
        with mock.patch.object(P.Project, 'create_environment'), mock.patch.object(P.W, 'Commands') as commands:
            commands.return_value.run.return_value = b'{}'
            commands.return_value.records = []
            report = P.run(output, '/usr/bin/python3')
        self.assertEqual(report['status'], 'NOT_RUN_MISSING_EXPLICIT_UV')
        self.assertEqual(report['project']['build'], 'NOT_RUN')
        self.assertEqual(report['project']['install'], 'NOT_RUN')

    def test_incompatible_uv_is_explicit_not_run(self):
        self.uv.chmod(0o700)
        with mock.patch.object(P.Project, 'create_environment'), mock.patch.object(P.Project, 'journey') as journey:
            with mock.patch.object(P.W, 'Commands') as commands:
                commands.return_value.run.side_effect = [b'{}', b'uv 0.0.0\n']
                commands.return_value.records = []
                report = P.run(self.base / 'wrong-uv', '/usr/bin/python3', str(self.uv))
        journey.assert_not_called()
        self.assertEqual(report['status'], 'NOT_RUN_INCOMPATIBLE_OFFLINE_BACKEND')
        self.assertNotIn('inputs', report['uv'])
        self.assertEqual(report['project']['build'], 'NOT_RUN')


if __name__ == '__main__':
    unittest.main()
