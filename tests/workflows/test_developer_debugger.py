#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Focused controls; synthetic transcripts here are not host debugger evidence."""
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('debugger', ROOT / 'scripts/workflows/developer_debugger.py')
D = importlib.util.module_from_spec(spec); spec.loader.exec_module(D)


class Commands:
    def __init__(self, output):
        self.output, self.records = output, []

    def run(self, *args):
        self.records.append(args)
        raise AssertionError('unit refusal must not launch a tool')


class DebuggerTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='debugger-controls-')
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.commands = Commands(self.base)
        self.compiler = self.base / 'compiler with spaces'
        self.compiler.write_bytes(b'unit-only-compiler')
        self.debugger = self.base / 'debugger'
        self.debugger.write_bytes(b'unit-only-debugger')
        self.tools = {'cc': str(self.compiler), 'c++': str(self.compiler), 'gdb': str(self.debugger)}

    def project(self, language='c'):
        return D.Project(language, self.commands, self.tools, self.base)

    def authorize_unit_product(self, project):
        project.binary.write_bytes(b'unit-only-binary')
        project.verified = dict(inputs=project.inputs(), binary=project.products())

    def transcript(self, source, line=8):
        return ('Breakpoint 1, workflow_step (seed=10) at %s:%d\n'
                'DEBUGGER_LOCAL:17\n'
                '#0  workflow_step (seed=10) at %s:%d\n'
                '#1  0x00001234 in main () at %s:13\n'
                'Debugger version one: 17\n'
                '[Inferior 1 (process 42) exited normally]\n'
                'DEBUGGER_EXIT:0\nDEBUGGER_DONE\n' % (source, line, source, line, source)).encode()

    def test_original_fixtures_have_mit_notice_and_fixed_breakpoint(self):
        files = D.fixture_files()
        self.assertIn(b'MIT License', files['LICENSE'])
        for name in ('hello.c', 'hello.cpp'):
            self.assertEqual(files[name].count(b'/* WORKFLOW_BREAKPOINT */'), 1)
            self.assertIn(b'volatile int known_local = seed + 7', files[name])

    def test_unknown_language_refused(self):
        with self.assertRaises(ValueError):
            self.project('python')

    def test_unbuilt_refused_without_launch(self):
        project = self.project()
        project.refuse_stale('unbuilt-unit')
        self.assertEqual(self.commands.records, [])
        self.assertEqual(project.value['records'][-1]['attempted_launches'], 0)

    def test_source_edit_with_preserved_mtime_revokes(self):
        project = self.project(); self.authorize_unit_product(project)
        stamp = project.source.stat().st_mtime_ns
        project.source.write_bytes(project.source.read_bytes() + b'// changed\n')
        os.utime(project.source, ns=(stamp, stamp))
        with self.assertRaises(D.Failure):
            project.debug('unit', 17, 'one')
        self.assertIsNone(project.verified)
        self.assertEqual(self.commands.records, [])

    def test_binary_tamper_revokes(self):
        project = self.project(); self.authorize_unit_product(project)
        project.binary.write_bytes(b'changed')
        with self.assertRaises(D.Failure):
            project.debug('unit', 17, 'one')
        self.assertEqual(self.commands.records, [])

    def test_compiler_and_debugger_tamper_revoke(self):
        for tool in (self.compiler, self.debugger):
            with self.subTest(tool=tool):
                project = self.project(); self.authorize_unit_product(project)
                tool.write_bytes(tool.read_bytes() + b'changed')
                with self.assertRaises(D.Failure):
                    project.debug('unit', 17, 'one')
                self.assertEqual(self.commands.records, [])
                shutil.rmtree(project.root)

    def test_symlink_source_refused(self):
        project = self.project()
        project.source.unlink(); project.source.symlink_to(self.compiler)
        with self.assertRaises(D.Failure):
            project.inputs()

    def test_stale_binary_retained_but_revoked_after_expected_compile_failure(self):
        project = self.project(); self.authorize_unit_product(project)
        old_source = project.source.read_bytes(); old_binary = project.products()
        project.source.write_bytes(old_source + b'\n#error INTENTIONAL_DEBUGGER_COMPILE_FAILURE\n')
        with mock.patch.object(self.commands, 'run', return_value=b'INTENTIONAL_DEBUGGER_COMPILE_FAILURE'):
            project.build('unit-failure', 'nonzero')
        self.assertEqual(project.products(), old_binary)
        self.assertIsNone(project.verified)
        project.refuse_stale('unit-failed-source')
        project.source.write_bytes(old_source)
        project.refuse_stale('unit-restored-source')
        self.assertEqual(self.commands.records, [])

    def test_unrelated_nonzero_compile_cannot_pass(self):
        project = self.project(); self.authorize_unit_product(project)
        with mock.patch.object(self.commands, 'run', return_value=b'unrelated failure'):
            with self.assertRaises(D.Failure):
                project.build('unit-failure', 'nonzero')
        self.assertIsNone(project.verified)

    def test_unexpected_compile_failure_revokes(self):
        project = self.project(); self.authorize_unit_product(project)
        with mock.patch.object(self.commands, 'run', side_effect=D.Failure('unit exit failure')):
            with self.assertRaises(D.Failure):
                project.build('unit-failure')
        self.assertIsNone(project.verified)

    def test_compile_input_change_during_command_cannot_pass(self):
        project = self.project(); self.authorize_unit_product(project)
        def mutate(*args):
            project.source.write_bytes(project.source.read_bytes() + b'// changed\n')
            return b''
        with mock.patch.object(self.commands, 'run', side_effect=mutate):
            with self.assertRaises(D.Failure):
                project.build('unit-changing-source')
        self.assertIsNone(project.verified)

    def test_compile_zero_without_product_cannot_pass(self):
        project = self.project()
        with mock.patch.object(self.commands, 'run', return_value=b''):
            with self.assertRaises(D.Failure):
                project.build('unit-no-product')
        self.assertIsNone(project.verified)

    def test_compile_zero_cannot_reuse_preexisting_binary(self):
        project = self.project(); self.authorize_unit_product(project)
        with mock.patch.object(self.commands, 'run', return_value=b''):
            with self.assertRaises(D.Failure):
                project.build('unit-noop-compiler')
        self.assertFalse(project.binary.exists())
        self.assertIsNone(project.verified)

    def test_valid_transcript_observes_source_local_stack_continue_exit(self):
        source = self.base / 'source with spaces.cpp'
        observed = D.validate_debugger(self.transcript(source), source, 8, 17, 'one')
        self.assertEqual(observed['known_local'], 17)
        self.assertEqual(observed['normal_exit'], 0)
        self.assertEqual(observed['stack'], ['workflow_step(seed=10)', 'main()'])

    def test_missing_wrong_or_duplicate_observation_rejected(self):
        source = self.base / 'hello.c'; raw = self.transcript(source)
        broken = [b'', raw.replace(b'DEBUGGER_LOCAL:17', b'DEBUGGER_LOCAL:21'),
                  raw.replace(b'DEBUGGER_LOCAL:17\n', b''), raw + b'DEBUGGER_LOCAL:17\n',
                  raw.replace(b'#1 ', b'#2 '), raw.replace(b'seed=10', b'seed=11'),
                  raw.replace(b'exited normally', b'exited with code 01'),
                  raw.replace(b'DEBUGGER_EXIT:0', b'DEBUGGER_EXIT:1'),
                  raw.replace(b'DEBUGGER_DONE\n', b''),
                  raw.replace(b'hello.c:8', b'hello.c:9'),
                  raw.replace(b'Debugger version one: 17', b'Debugger version one: 21')]
        for transcript in broken:
            with self.subTest(transcript=transcript), self.assertRaises(D.Failure):
                D.validate_debugger(transcript, source, 8, 17, 'one')

    def test_observations_must_be_in_execution_order(self):
        source = self.base / 'hello.c'
        raw = self.transcript(source).replace(b'DEBUGGER_LOCAL:17\n', b'') + b'DEBUGGER_LOCAL:17\n'
        with self.assertRaises(D.Failure):
            D.validate_debugger(raw, source, 8, 17, 'one')

    def test_debugger_exit_failure_revokes(self):
        project = self.project(); self.authorize_unit_product(project)
        with mock.patch.object(self.commands, 'run', side_effect=D.Failure('unit debugger failure')):
            with self.assertRaises(D.Failure):
                project.debug('unit-failure', 17, 'one')
        self.assertIsNone(project.verified)
        project.refuse_stale('unit-after-failure')
        self.assertEqual(self.commands.records, [])

    def test_debugger_zero_with_empty_transcript_revokes(self):
        project = self.project(); self.authorize_unit_product(project)
        with mock.patch.object(self.commands, 'run', return_value=b''):
            with self.assertRaises(D.Failure):
                project.debug('unit-empty', 17, 'one')
        self.assertIsNone(project.verified)

    def test_mutation_during_debugger_revokes(self):
        project = self.project(); self.authorize_unit_product(project)
        def mutate(*args):
            project.binary.write_bytes(b'unit tampered during debugging')
            return self.transcript(project.source)
        with mock.patch.object(self.commands, 'run', side_effect=mutate):
            with self.assertRaises(D.Failure):
                project.debug('unit-mutated', 17, 'one')
        self.assertIsNone(project.verified)

    def test_command_file_mutation_during_debugger_revokes(self):
        project = self.project(); self.authorize_unit_product(project)
        def mutate(*args):
            (self.base / 'c-unit-script.gdb').write_bytes(b'changed')
            return self.transcript(project.source)
        with mock.patch.object(self.commands, 'run', side_effect=mutate):
            with self.assertRaises(D.Failure):
                project.debug('unit-script', 17, 'one')
        self.assertIsNone(project.verified)

    def test_debugger_commands_isolate_and_only_run_fixture(self):
        project = self.project(); self.authorize_unit_product(project)
        with mock.patch.object(self.commands, 'run', return_value=self.transcript(project.source)) as launch:
            project.debug('unit-argv', 17, 'one')
        argv = launch.call_args.args[1]
        self.assertEqual(argv[0], str(self.debugger))
        for option in ('-nx', '-nh', '--batch', 'set auto-load off', 'set debuginfod enabled off'):
            self.assertIn(option, argv)
        script = (self.base / 'c-unit-argv.gdb').read_text()
        self.assertIn('set startup-with-shell off', script)
        self.assertIn('file ' + D.gdb_quote(project.binary), script)
        self.assertNotIn('attach', script)
        self.assertFalse(any(line.startswith(('shell ', '!')) for line in script.splitlines()))

    def test_gdb_path_quoting_and_line_injection_refusal(self):
        self.assertEqual(D.gdb_quote('/path/space \\"quoted'), '"/path/space \\\\\\"quoted"')
        for path in ('line\nbreak', 'line\rbreak', 'nul\0'):
            with self.assertRaises(ValueError):
                D.gdb_quote(path)

    def test_missing_or_duplicate_breakpoint_refused(self):
        project = self.project()
        raw = project.source.read_bytes()
        for broken in (raw.replace(b'/* WORKFLOW_BREAKPOINT */', b''), raw + b'/* WORKFLOW_BREAKPOINT */\n'):
            project.source.write_bytes(broken)
            with self.assertRaises(D.Failure):
                D.debugger_script(project.source, project.binary)

    def test_missing_tools_explicit_and_no_launch(self):
        empty = self.base / 'empty-tools'; empty.mkdir()
        with mock.patch.object(D.W.Commands, 'run', side_effect=AssertionError('no tools to launch')):
            report = D.run(self.base / 'missing-output', tool_path=str(empty))
        self.assertEqual(report['status'], 'MISSING_TOOLS')
        self.assertIn('gdb', report['missing'])
        self.assertEqual({v['status'] for v in report['projects'].values()}, {'NOT_RUN'})
        self.assertEqual(report['commands'], [])

    def test_missing_gdb_alone_does_not_launch_projects(self):
        def which(name, path):
            return None if name == 'gdb' else str(self.compiler)
        with mock.patch.object(D.shutil, 'which', side_effect=which), \
             mock.patch.object(D.W.Commands, 'run', return_value=b'unit-version\n'), \
             mock.patch.object(D.Project, 'journey') as journey:
            report = D.run(self.base / 'no-gdb')
        journey.assert_not_called()
        self.assertEqual(report['missing'], ['gdb'])
        self.assertEqual(report['tools']['gdb'], dict(status='MISSING', workflow='NOT_RUN'))

    def test_invalid_budgets_or_search_path_refused_before_output(self):
        for kwargs in ({'timeout': float('nan')}, {'total': 601}, {'timeout': 1}, {'timeout': True},
                       {'tool_path': '/usr/bin:'}, {'tool_path': 'relative'}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                D.run(self.base / 'output', **kwargs)
            self.assertFalse((self.base / 'output').exists())

    def test_existing_output_or_alias_refused(self):
        with self.assertRaises(FileExistsError):
            D.run(self.base)
        alias = self.base / 'alias'; alias.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(ValueError):
            D.run(alias / 'output')
        self.assertFalse((self.base / 'output').exists())

    def test_helper_pin_mismatch_does_not_execute(self):
        fake = self.base / 'scripts/workflows'; fake.mkdir(parents=True)
        (fake / 'developer_workflow.py').write_bytes(b'raise RuntimeError("must not execute")')
        with mock.patch.object(D, 'ROOT', self.base), self.assertRaises(ValueError):
            D.load_workflow()


if __name__ == '__main__':
    unittest.main(verbosity=2)
