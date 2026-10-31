# SPDX-License-Identifier: MIT
"""Focused adapter/gate controls. Real build evidence is the separate CLI run."""
import importlib.util
import os
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('build_systems', ROOT / 'scripts/workflows/developer_build_systems.py')
B = importlib.util.module_from_spec(spec); spec.loader.exec_module(B)


class Commands:
    """Explicit unit stub; never evidence of a real CMake/Meson journey."""
    def __init__(self, output):
        self.output, self.records = output, []

    def run(self, *args):
        self.records.append(args)
        raise AssertionError('unit control must not launch a tool')


class BuildSystemsTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='build-system-controls-')
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.commands = Commands(self.base)
        self.frontend = self.base / 'compiler with spaces'
        self.frontend.write_bytes(b'unit-control-not-a-real-compiler')
        self.tools = {n: str(self.frontend) for n in {'cmake', 'ctest', 'ninja', 'meson', 'cc', 'c++'}}

    def project(self, backend='cmake'):
        return B.Project(backend, self.commands, self.tools, self.base)

    def authorize_unit_products(self, project):
        project.build_dir.mkdir()
        for name in ('developer-demo', 'libgreeting.so', 'main.c.o', 'greeting.cpp.o'):
            (project.build_dir / name).write_bytes(('unit-product:' + name).encode())
        project.verified = dict(inputs=project.inputs(), products=project.artifacts())
        project.usable = True

    def test_original_mit_c_and_cpp_sources(self):
        files = B.fixture_files()
        self.assertEqual(files['expected.txt'], B.ORIGINAL)
        self.assertIn(b'MIT License', files['LICENSE'])
        self.assertIn(b'extern "C"', files['greeting.h'])
        self.assertIn(b'INTENTIONAL_TEST_MISMATCH', files['main.c'])

    def test_unknown_backend_refused(self):
        with self.assertRaises(ValueError):
            self.project('unknown')

    def test_cmake_argv_preserves_compiler_as_one_argument(self):
        project = self.project()
        argv = project.argv('configure')
        self.assertIn('-DCMAKE_C_COMPILER=' + str(self.frontend), argv)
        self.assertIn('-DCMAKE_CXX_COMPILER=' + str(self.frontend), argv)
        self.assertIn('-DCMAKE_INSTALL_PREFIX=' + str(project.prefix), argv)
        self.assertEqual(project.argv('build')[-2:], ['--parallel', '1'])

    def test_meson_argv_no_downloads_or_implicit_test_install_build(self):
        project = self.project('meson')
        self.assertIn('--wrap-mode=nodownload', project.argv('configure'))
        self.assertIn('--libdir=lib', project.argv('configure'))
        for action in ('test', 'install'):
            self.assertIn('--no-rebuild', project.argv(action))
        self.assertEqual(project.argv('build')[-2:], ['-j', '1'])

    def test_meson_compiler_environment_quotes_literal_paths(self):
        path = str(self.base / "compiler space '$;$(literal)")
        env = B.compiler_environment({'cc': path, 'c++': path})
        self.assertEqual(shlex.split(env['CC']), [path])
        self.assertEqual(shlex.split(env['CXX']), [path])

    def test_absent_tools_are_not_run(self):
        reports = {}
        B.project_workflows(self.commands, {}, self.base, reports)
        self.assertEqual({n: r['status'] for n, r in reports.items()}, {'cmake': 'NOT_RUN', 'meson': 'NOT_RUN'})
        self.assertEqual(self.commands.records, [])

    def test_missing_meson_does_not_run_mock_journey(self):
        reports = {}
        with mock.patch.object(B.Project, 'journey') as journey:
            B.project_workflows(self.commands, {'cc': 'x', 'c++': 'x', 'ninja': 'x'}, self.base, reports)
        journey.assert_not_called()
        self.assertEqual(reports['meson']['missing'], ['meson'])

    def test_unbuilt_executable_refused_without_launch(self):
        project = self.project()
        project.refuse_stale('unbuilt-control')
        self.assertEqual(self.commands.records, [])
        self.assertEqual(project.value['records'][-1]['attempted_launches'], 0)

    def test_source_change_revokes_even_with_same_mtime(self):
        project = self.project(); self.authorize_unit_products(project)
        source = project.source / 'greeting.cpp'; stamp = source.stat().st_mtime_ns
        source.write_bytes(source.read_bytes() + b'// changed\n')
        os.utime(source, ns=(stamp, stamp))
        with self.assertRaises(B.Failure):
            project.run('source-control', B.ORIGINAL)
        self.assertEqual(self.commands.records, [])
        self.assertFalse(project.usable)

    def test_shared_library_tamper_revokes(self):
        project = self.project(); self.authorize_unit_products(project)
        project.library.write_bytes(b'altered')
        with self.assertRaises(B.Failure):
            project.run('library-control', B.ORIGINAL)
        self.assertEqual(self.commands.records, [])

    def test_tool_tamper_revokes(self):
        project = self.project(); self.authorize_unit_products(project)
        self.frontend.write_bytes(b'changed tool')
        with self.assertRaises(B.Failure):
            project.require_usable()

    def test_symlink_source_refused(self):
        project = self.project()
        path = project.source / 'greeting.cpp'; path.unlink(); path.symlink_to(self.frontend)
        with self.assertRaises(B.Failure):
            project.inputs()

    def test_expected_compile_failure_revokes_old_products(self):
        project = self.project(); self.authorize_unit_products(project)
        before = project.artifacts()
        with mock.patch.object(project, 'command', return_value=b'INTENTIONAL_COMPILE_FAILURE'):
            project.build('unit-compile-failure', 'nonzero')
        self.assertEqual(project.artifacts(), before)
        self.assertFalse(project.usable)
        with self.assertRaises(B.Failure):
            project.require_usable()

    def test_unrelated_compile_failure_is_not_expected_success(self):
        project = self.project(); self.authorize_unit_products(project)
        with mock.patch.object(project, 'command', return_value=b'unrelated missing compiler'):
            with self.assertRaises(B.Failure):
                project.build('unit-wrong-failure', 'nonzero')
        self.assertFalse(project.usable)

    def test_expected_test_failure_revokes_run_and_installed_receipt(self):
        project = self.project(); self.authorize_unit_products(project)
        project.installed = {'unit': 'old receipt'}
        with mock.patch.object(project, 'command', return_value=b'INTENTIONAL_TEST_MISMATCH'):
            project.test('unit-expected-test-failure', 'nonzero')
        self.assertFalse(project.usable)
        self.assertIsNone(project.installed)
        with self.assertRaises(B.Failure):
            project.require_usable()

    def test_unexpected_test_failure_revokes_run(self):
        project = self.project(); self.authorize_unit_products(project)
        with mock.patch.object(project, 'command', side_effect=B.Failure('unit failure')):
            with self.assertRaises(B.Failure):
                project.test('unit-failed-test')
        self.assertFalse(project.usable)

    def test_success_exit_without_test_marker_is_failure(self):
        project = self.project(); self.authorize_unit_products(project)
        with mock.patch.object(project, 'command', return_value=b'zero tests'):
            with self.assertRaises(B.Failure):
                project.test('unit-empty-test')
        self.assertFalse(project.usable)

    def test_test_product_mutation_revokes_run(self):
        project = self.project(); self.authorize_unit_products(project)
        def mutate(*args):
            project.library.write_bytes(b'changed during unit test')
            return b'DEVELOPER_TEST_OK'
        with mock.patch.object(project, 'command', side_effect=mutate):
            with self.assertRaises(B.Failure):
                project.test('unit-changing-test')
        self.assertFalse(project.usable)

    def test_existing_install_prefix_refused_before_command(self):
        project = self.project(); self.authorize_unit_products(project)
        project.prefix.mkdir()
        with self.assertRaises(B.Failure):
            project.install()
        self.assertEqual(self.commands.records, [])

    def test_installed_tree_tamper_refused(self):
        project = self.project()
        project.prefix.mkdir(); (project.prefix / 'demo').write_bytes(b'unit installed product')
        project.installed = dict(inputs=project.inputs(), tree=project.installed_tree())
        (project.prefix / 'demo').write_bytes(b'changed installed bytes')
        with self.assertRaises(B.Failure):
            project.installed_runtime()
        self.assertIsNone(project.installed)
        self.assertEqual(self.commands.records, [])

    def test_input_budgets_and_search_path_fail_before_output_creation(self):
        for kwargs in ({'timeout': float('nan')}, {'total': 601}, {'timeout': 1},
                       {'tool_path': '/usr/bin:'}, {'tool_path': 'relative'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                B.run(self.base / 'new-output', **kwargs)
            self.assertFalse((self.base / 'new-output').exists())

    def test_output_alias_refused_before_mkdir(self):
        alias = self.base / 'alias'; alias.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(ValueError):
            B.run(alias / 'new-output')
        self.assertFalse((self.base / 'new-output').exists())

    def test_helper_pin_mismatch_refused(self):
        fake = self.base / 'scripts/workflows'; fake.mkdir(parents=True)
        (fake / 'developer_workflow.py').write_bytes(b'raise RuntimeError("must never execute")')
        with mock.patch.object(B, 'ROOT', self.base), self.assertRaises(ValueError):
            B.load_workflow()


if __name__ == '__main__':
    unittest.main(verbosity=2)
