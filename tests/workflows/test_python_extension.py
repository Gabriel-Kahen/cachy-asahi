# SPDX-License-Identifier: MIT
"""Custody/refusal controls. Product bytes below are unit-only gate data.

No fake compiler, build frontend, extension or loader is used. The separate
retained CLI demonstration provides actual compile/load evidence.
"""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('python_extension', ROOT / 'scripts/workflows/python_extension.py')
P = importlib.util.module_from_spec(spec); spec.loader.exec_module(P)


class NoLaunchCommands:
    def __init__(self, output):
        self.output, self.records, self.env = output, [], {}

    def run(self, *args):
        self.records.append(args)
        raise AssertionError('unit refusal control attempted a launch')


class PythonExtensionTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='python-extension-controls-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.commands = NoLaunchCommands(self.base)
        self.tools = {}
        for name in ('python', 'cmake', 'ctest', 'ninja', 'cc'):
            path = self.base / ('unit ' + name)
            path.write_bytes(('unit identity only: ' + name).encode()); path.chmod(0o700)
            self.tools[name] = str(path)
        self.host_headers = self.base / 'host-headers'; self.host_headers.mkdir()
        self.headers = {n: ('unit header: ' + n).encode() for n in ('Python.h', 'pyconfig.h')}
        for name, raw in self.headers.items():
            (self.host_headers / name).write_bytes(raw)
        self.identity = dict(implementation='cpython', machine='x86_64', executable=self.tools['python'],
            include=str(self.host_headers), platinclude=str(self.host_headers),
            config=dict(EXT_SUFFIX='.cpython-unit-x86_64-linux-gnu.so', SOABI='cpython-unit-x86_64-linux-gnu'))
        self.project = P.ExtensionProject(self.commands, self.tools, self.identity, self.headers, self.base)

    def authorize_unit_receipts(self):
        # Arbitrary bytes test gates only; they are never passed to a loader.
        self.project.extension.parent.mkdir(parents=True)
        self.project.extension.write_bytes(b'unit extension custody data, not ELF')
        (self.project.build_dir / 'extension.c.o').write_bytes(b'unit object custody data')
        for name in ('CMakeCache.txt', 'build.ninja', 'compile_commands.json'):
            (self.project.build_dir / name).write_bytes(('unit graph: ' + name).encode())
        self.project.verified = dict(inputs=self.project.inputs(), products=self.project.artifacts())
        self.project.usable = True

    def authorize_unit_install(self):
        self.project.prefix.mkdir()
        path = self.project.prefix / 'unit-installed.so'; path.write_bytes(b'unit installed custody data')
        self.project.installed = dict(inputs=self.project.inputs(), tree=self.project.installed_tree())
        return path

    def assert_import_refused(self):
        with self.assertRaises((OSError, ValueError)):
            self.project.run('unit-forbidden-import', P.ORIGINAL)
        self.assertEqual(self.commands.records, [])

    def test_original_mit_fixture(self):
        files = P.fixture_files()
        self.assertEqual(files['expected.txt'], P.ORIGINAL)
        self.assertIn(b'MIT License', files['LICENSE'])
        self.assertIn(b'#include <Python.h>', files['extension.c'])
        self.assertIn(b'PyInit_cachy_extension', files['extension.c'])

    def test_explicit_executable_selection(self):
        self.assertIsNone(P.selected_executable(None))
        self.assertIsNone(P.selected_executable(str(self.base / 'missing')))
        with self.assertRaises(ValueError):
            P.selected_executable('python3')
        alias = self.base / 'compiler alias'; alias.symlink_to(self.tools['cc'])
        self.assertEqual(P.selected_executable(alias), self.tools['cc'])

    def test_cmake_argv_selects_exact_tools_without_cpp_dependency(self):
        self.assertNotIn('c++', self.tools)
        argv = self.project.argv('configure')
        self.assertIn('-DPython3_EXECUTABLE=' + self.tools['python'], argv)
        self.assertIn('-DCMAKE_C_COMPILER=' + self.tools['cc'], argv)
        self.assertIn('-DCMAKE_MAKE_PROGRAM=' + self.tools['ninja'], argv)
        self.assertIn('-DPython3_INCLUDE_DIR=' + str(self.project.include), argv)
        self.assertNotIn('-DPython3_INCLUDE_DIR=' + str(self.host_headers), argv)
        self.assertEqual(self.project.argv('build')[-2:], ['--parallel', '1'])
        self.assertEqual(self.project.argv('test')[0], self.tools['ctest'])
        self.assertIn('--no-tests=error', self.project.argv('test'))

    def test_header_snapshot_matches_original_bytes(self):
        report, files = P.header_inputs(self.identity)
        self.assertEqual(report['status'], 'PRESENT')
        self.assertEqual(files, self.headers)
        self.assertEqual(report['files'], {n: P.pin(raw) for n, raw in files.items()})

    def test_missing_headers_are_explicit_not_run(self):
        (self.host_headers / 'pyconfig.h').unlink()
        report, files = P.header_inputs(self.identity)
        self.assertEqual(report['status'], 'NOT_RUN_MISSING_HEADERS')
        self.assertEqual(files, {})
        self.assertEqual(report['missing'], [str(self.host_headers / 'pyconfig.h')])

    def test_split_header_layout_is_explicit_not_run(self):
        other = self.base / 'other-headers'; other.mkdir()
        report, files = P.header_inputs(dict(self.identity, platinclude=str(other)))
        self.assertEqual(report['status'], 'NOT_RUN_UNSUPPORTED_SPLIT_HEADERS')
        self.assertEqual(files, {})

    def test_unsupported_interpreter_or_abi_is_not_run(self):
        cases = [(dict(self.identity, implementation='pypy'), 'NOT_RUN_UNSUPPORTED_INTERPRETER_PROFILE'),
            (dict(self.identity, machine='unknown'), 'NOT_RUN_UNSUPPORTED_INTERPRETER_PROFILE'),
            (dict(self.identity, config=dict(EXT_SUFFIX='../outside.so', SOABI='unit')), 'NOT_RUN_UNSUPPORTED_EXTENSION_ABI'),
            (dict(self.identity, config=dict(EXT_SUFFIX=None, SOABI='unit')), 'NOT_RUN_UNSUPPORTED_EXTENSION_ABI')]
        for identity, status in cases:
            with self.subTest(identity=identity):
                report, files = P.header_inputs(identity)
                self.assertEqual(report['status'], status)
                self.assertEqual(files, {})

    def test_header_symlink_or_nonabsolute_directory_is_refused(self):
        path = self.host_headers / 'Python.h'; path.unlink(); path.symlink_to(self.host_headers / 'pyconfig.h')
        with self.assertRaises(P.Failure):
            P.header_inputs(self.identity)
        with self.assertRaises(P.Failure):
            P.header_inputs(dict(self.identity, include='relative'))

    def test_unbuilt_import_refused_without_launch(self):
        self.project.refuse_stale('unit-unbuilt')
        self.assertEqual(self.commands.records, [])
        self.assertEqual(self.project.value['records'][-1]['attempted_launches'], 0)

    def test_source_change_same_timestamp_revokes_import(self):
        self.authorize_unit_receipts()
        path = self.project.source / 'extension.c'; timestamp = path.stat().st_mtime_ns
        path.write_bytes(path.read_bytes() + b'\n/* unit change */\n'); os.utime(path, ns=(timestamp, timestamp))
        self.assert_import_refused()

    def test_private_header_change_revokes_import(self):
        self.authorize_unit_receipts()
        (self.project.include / 'Python.h').write_bytes(b'changed unit header')
        self.assert_import_refused()

    def test_missing_or_extra_private_header_is_refused(self):
        self.authorize_unit_receipts()
        (self.project.include / 'Python.h').unlink()
        with self.assertRaises(P.Failure):
            self.project.inputs()
        (self.project.include / 'Python.h').write_bytes(self.headers['Python.h'])
        (self.project.include / 'extra.h').write_bytes(b'unexpected unit header')
        with self.assertRaises(P.Failure):
            self.project.inputs()
        self.assertEqual(self.commands.records, [])

    def test_sysconfig_receipt_change_revokes_import(self):
        self.authorize_unit_receipts()
        self.project.identity_file.write_text('{"config":"changed sysconfig"}\n')
        self.assert_import_refused()

    def test_interpreter_change_revokes_import(self):
        self.authorize_unit_receipts()
        Path(self.tools['python']).write_bytes(b'changed unit interpreter')
        self.assert_import_refused()

    def test_compiler_change_revokes_import(self):
        self.authorize_unit_receipts()
        Path(self.tools['cc']).write_bytes(b'changed unit compiler')
        self.assert_import_refused()

    def test_import_checker_change_revokes_import(self):
        self.authorize_unit_receipts()
        self.project.checker.write_bytes(b'changed checker')
        self.assert_import_refused()

    def test_extension_tamper_revokes_import(self):
        self.authorize_unit_receipts()
        self.project.extension.write_bytes(b'changed unit extension custody data')
        self.assert_import_refused()

    def test_build_graph_tamper_revokes_import(self):
        self.authorize_unit_receipts()
        (self.project.build_dir / 'build.ninja').write_bytes(b'changed unit graph')
        self.assert_import_refused()

    def test_source_symlink_and_missing_file_refused_before_launch(self):
        self.authorize_unit_receipts()
        path = self.project.source / 'extension.c'; path.unlink(); path.symlink_to(self.host_headers / 'Python.h')
        self.assert_import_refused()
        path.unlink(); self.assert_import_refused()

    def test_installed_tree_tamper_revokes_receipt(self):
        self.authorize_unit_receipts(); installed = self.authorize_unit_install()
        installed.write_bytes(b'changed unit installed extension')
        with self.assertRaises(P.Failure):
            self.project.require_installed()
        self.assertIsNone(self.project.installed)
        self.assertEqual(self.commands.records, [])

    def test_existing_install_prefix_refused_before_launch(self):
        self.authorize_unit_receipts()
        (self.project.root / 'prefixes' / 'unit-existing').mkdir(parents=True)
        with self.assertRaises(P.Failure):
            self.project.install_and_import('unit-existing', P.ORIGINAL)
        self.assertEqual(self.commands.records, [])

    def test_expected_compile_failure_revokes_old_import(self):
        self.authorize_unit_receipts(); before = self.project.artifacts()
        with mock.patch.object(self.project, 'command', return_value=b'INTENTIONAL_COMPILE_FAILURE'):
            self.project.build('unit-compile-failure', expected='nonzero')
        self.assertEqual(self.project.artifacts(), before)
        self.assertFalse(self.project.usable)
        self.project.refuse_stale('unit-stale-after-failure')
        self.assertEqual(self.commands.records, [])

    def test_unrelated_compile_error_never_passes_expected_failure(self):
        self.authorize_unit_receipts()
        with mock.patch.object(self.project, 'command', return_value=b'unrelated missing compiler'):
            with self.assertRaises(P.Failure):
                self.project.build('unit-unrelated-compile-failure', expected='nonzero')
        self.assertFalse(self.project.usable)

    def test_expected_unit_failure_revokes_old_import(self):
        self.authorize_unit_receipts(); self.authorize_unit_install()
        with mock.patch.object(self.project, 'command', return_value=b'INTENTIONAL_TEST_MISMATCH'):
            self.project.test('unit-test-failure', expected='nonzero')
        self.assertFalse(self.project.usable)
        self.assertIsNone(self.project.installed)
        self.project.refuse_stale('unit-stale-after-test')
        self.assertEqual(self.commands.records, [])

    def test_unrelated_test_error_never_passes_expected_failure(self):
        self.authorize_unit_receipts()
        with mock.patch.object(self.project, 'command', return_value=b'unrelated import error'):
            with self.assertRaises(P.Failure):
                self.project.test('unit-unrelated-test-failure', expected='nonzero')
        self.assertFalse(self.project.usable)

    def test_raw_target_elf_profile_retained_without_hardware_credit(self):
        self.authorize_unit_receipts()
        assessment = dict(machine=62, load_segments=4,
            errors=['ELF machine 62, expected AArch64 (183)', 'PT_LOAD fails structural 16K alignment check'],
            hardware_status='NOT RUN')
        with mock.patch.object(P.PC, 'elf_check', return_value=assessment):
            result = self.project.inspect_elf(self.project.extension)
        self.assertEqual(result['package_check'], assessment)
        self.assertEqual(result['aarch64_16k_structure'], 'FAIL_TARGET_PROFILE')
        self.assertEqual(result['native_16K'], 'NOT_QUALIFIED')
        self.assertEqual(result['physical_M2'], 'NOT_RUN')

    def test_malformed_or_wrong_machine_elf_is_refused(self):
        self.authorize_unit_receipts()
        assessments = [None, dict(errors=['truncated/invalid ELF program headers']),
            dict(machine=183, load_segments=4, errors=[]), dict(machine=62, load_segments=0, errors=[]),
            dict(machine=62, load_segments=4, errors=['invalid PT_LOAD file/memory size'])]
        for assessment in assessments:
            with self.subTest(assessment=assessment), mock.patch.object(P.PC, 'elf_check', return_value=assessment):
                with self.assertRaises(P.Failure):
                    self.project.inspect_elf(self.project.extension)

    def test_import_identity_requires_exact_loader_builtin_and_path(self):
        identity = dict(module=str(self.project.extension), greeting=P.ORIGINAL.decode().rstrip('\n'),
            builtin=True, loader='ExtensionFileLoader', isolated=1, executable=self.tools['python'])
        self.project.check_import(identity, self.project.extension, P.ORIGINAL)
        for key, wrong in [('module', str(self.base / 'other.so')), ('greeting', 'wrong'), ('builtin', False),
                           ('loader', 'SourceFileLoader'), ('isolated', 0), ('executable', self.tools['cc'])]:
            with self.subTest(key=key), self.assertRaises(P.Failure):
                self.project.check_import(dict(identity, **{key: wrong}), self.project.extension, P.ORIGINAL)

    def test_missing_selected_interpreter_is_explicit_not_run(self):
        with mock.patch.object(P.W, 'Commands') as commands:
            commands.return_value.records = []
            report = P.run(self.base / 'missing-python', str(self.base / 'absent-python'))
        self.assertEqual(report['status'], 'NOT_RUN_MISSING_INTERPRETER')
        self.assertIsNone(report['project'])
        commands.return_value.run.assert_not_called()

    def test_missing_selected_tools_never_construct_project(self):
        with mock.patch.object(P.W, 'Commands') as commands, mock.patch.object(P, 'ExtensionProject') as project:
            commands.return_value.records = []
            commands.return_value.run.return_value = json.dumps(self.identity).encode()
            report = P.run(self.base / 'missing-tools', self.tools['python'])
        self.assertEqual(report['status'], 'NOT_RUN_MISSING_EXPLICIT_TOOLS')
        self.assertGreaterEqual(set(report['missing']), {'cmake', 'ctest', 'ninja', 'cc'})
        self.assertIsNone(report['project'])
        project.assert_not_called()

    def test_invalid_budgets_and_output_alias_refused(self):
        for timeout, total in [(float('nan'), 240), (30, float('inf')), (1, 240), (30, 29), (61, 240)]:
            output = self.base / 'must-not-exist'
            with self.subTest(timeout=timeout, total=total), self.assertRaises(ValueError):
                P.run(output, self.tools['python'], timeout=timeout, total=total)
            self.assertFalse(output.exists())
        alias = self.base / 'output-alias'; alias.symlink_to(self.project.source, target_is_directory=True)
        with self.assertRaises(ValueError):
            P.run(alias / 'new', self.tools['python'])


if __name__ == '__main__':
    unittest.main()
