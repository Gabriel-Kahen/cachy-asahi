# SPDX-License-Identifier: MIT
"""Focused real-child and failure controls; source-only checkout invocation."""
import importlib.util
import os
from pathlib import Path
import shutil
import signal
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('developer_workflow', ROOT / 'scripts/workflows/developer_workflow.py')
W = importlib.util.module_from_spec(spec)
spec.loader.exec_module(W)


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='developer-workflow-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.logs = self.base / 'logs'; self.logs.mkdir()
        self.home = self.base / 'home'; self.home.mkdir()
        self.commands = W.Commands(self.logs, self.home, os.defpath, timeout=3, total=30, max_output=4096)

    def python(self, code, expected=0):
        return self.commands.run('control', [sys.executable, '-I', '-B', '-c', code], self.base, expected)

    def test_real_raw_output_and_retirement(self):
        self.assertEqual(self.python('import os;os.write(1,b"raw\\x00\\xff")'), b'raw\x00\xff')
        row = self.commands.records[0]
        self.assertTrue(row['success'])
        self.assertEqual(row['supervision']['group_census'], 'EMPTY_TWICE')
        self.assertEqual((self.logs / row['log']).read_bytes(), b'raw\x00\xff')

    def test_expected_failure_requires_real_nonzero(self):
        self.python('raise SystemExit(7)', 'nonzero')
        self.assertEqual(self.commands.records[0]['supervision']['exit'], 7)
        with self.assertRaises(W.Failure):
            self.python('pass', 'nonzero')

    def test_timeout_fails_and_reaps(self):
        with self.assertRaises(W.Failure):
            self.python('import time;time.sleep(30)')
        row = self.commands.records[0]['supervision']
        self.assertTrue(row['reaped'])
        self.assertTrue(row['timeout'])
        self.assertIn('SIGTERM', row['signals'])

    def test_overflow_fails_and_caps_raw_log(self):
        with self.assertRaises(W.Failure):
            self.python('import os;os.write(1,b"x"*100000)')
        row = self.commands.records[0]
        self.assertEqual((self.logs / row['log']).stat().st_size, 4096)
        self.assertIn('output cap exceeded', row['supervision']['error'])
        self.assertTrue(row['supervision']['reaped'])

    def test_missing_executable_is_not_success(self):
        with self.assertRaises(W.Failure):
            self.commands.run('missing', [str(self.base / 'absent')], self.base)
        self.assertIn('launch_error', self.commands.records[0])
        self.assertIsNone(self.commands.records[0]['supervision'])

    def test_late_log_failure_has_no_signal_authority(self):
        original = Path.write_bytes
        signals = []
        real_killpg = os.killpg
        def note(pid, sig):
            signals.append((pid, sig)); return real_killpg(pid, sig)
        def refuse(path, raw):
            if path.suffix == '.log':
                raise OSError('intentional late log failure')
            return original(path, raw)
        with mock.patch.object(os, 'killpg', side_effect=note), mock.patch.object(Path, 'write_bytes', refuse):
            with self.assertRaisesRegex(OSError, 'late log failure'):
                self.python('print("finished")')
        self.assertEqual(signals, [])

    def test_echild_never_becomes_success_or_signals(self):
        real = self.commands.core.supervise
        def stolen(child, **kwargs):
            os.waitpid(child.pid, 0)
            with mock.patch.object(self.commands.core, '_stat', side_effect=AssertionError('post-ECHILD probe')), \
                    mock.patch.object(os, 'killpg', side_effect=AssertionError('post-ECHILD signal')):
                return real(child, **kwargs)
        with mock.patch.object(self.commands.core, 'supervise', side_effect=stolen):
            with self.assertRaises(W.Failure):
                self.python('pass')
        result = self.commands.records[0]['supervision']
        self.assertEqual(result['ownership'], 'UNKNOWN')
        self.assertIsNone(result['exit'])
        self.assertFalse(result['reaped'])

    def test_core_pin_refuses_changed_dependency(self):
        with mock.patch.object(W, 'CORE_PIN', '0'*64):
            with self.assertRaisesRegex(ValueError, 'pin differs'):
                W.load_core()

    def test_missing_required_and_optional_are_explicit(self):
        tools = self.base / 'empty-tools'; tools.mkdir()
        report = W.run(self.base / 'missing', str(tools), timeout=2, total=5)
        self.assertEqual(report['status'], 'MISSING_TOOLS')
        self.assertEqual(report['missing_required'], list(W.REQUIRED))
        self.assertEqual(report['commands'], [])
        self.assertTrue(all(report['tools'][n]['status'] == 'MISSING_OPTIONAL' for n in W.OPTIONAL))
        self.assertEqual(report['physical_M2'], 'NOT_RUN')

    def test_present_tool_probe_is_not_a_completed_workflow(self):
        git = shutil.which('git', path=os.defpath)
        if git is None:
            self.skipTest('Git unavailable; partial inventory control NOT RUN')
        tools = self.base / 'partial-tools'; tools.mkdir()
        (tools / 'git').symlink_to(git)
        report = W.run(self.base / 'partial', str(tools), timeout=3, total=10)
        self.assertEqual(report['status'], 'MISSING_TOOLS')
        self.assertEqual(report['tools']['git']['workflow'], 'VERSION_ONLY_WORKFLOW_NOT_RUN')

    def test_elapsed_cap_is_required_even_after_reap(self):
        real = self.commands.core.supervise
        def delayed(child, **kwargs):
            result = real(child, **kwargs)
            result['seconds'] = kwargs['cap']
            return result
        with mock.patch.object(self.commands.core, 'supervise', side_effect=delayed):
            with self.assertRaises(W.Failure):
                self.python('pass')
        self.assertFalse(self.commands.records[0]['success'])

    def test_cancellation_defers_until_owned_child_retires(self):
        before = signal.getsignal(signal.SIGTERM)
        with self.assertRaises(W.Failure):
            self.python('import os,signal;os.kill(os.getppid(),signal.SIGTERM);print("retired")')
        result = self.commands.records[0]['supervision']
        self.assertTrue(result['reaped'])
        self.assertEqual(result['group_census'], 'EMPTY_TWICE')
        self.assertEqual(signal.getsignal(signal.SIGTERM), before)

    def test_output_reuse_and_alias_refused(self):
        with self.assertRaises(FileExistsError):
            W.run(self.logs)
        alias = self.base / 'alias'; alias.symlink_to(self.logs, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'aliases'):
            W.run(alias / 'new')

    def test_invalid_bounds_and_shell_strings_refused_before_launch(self):
        for timeout, total in ((float('nan'), 30), (1, 30), (61, 90), (15, 601), (20, 10)):
            with self.assertRaises(ValueError):
                W.run(self.base / 'not-created', timeout=timeout, total=total)
        with self.assertRaises(ValueError):
            self.commands.run('string', 'echo unsafe', self.base)
        with self.assertRaises(ValueError):
            self.commands.run('relative', ['python3', '--version'], self.base)
        self.assertFalse((self.base / 'not-created').exists())

    def test_real_incremental_compile_changed_source_and_failure(self):
        compiler = shutil.which('cc', path=os.defpath)
        if compiler is None:
            self.skipTest('cc unavailable; native compile controls NOT RUN')
        source = self.base / 'tiny.c'
        source.write_text('#include <stdio.h>\nint main(void){puts("first");}\n')
        target = self.base / 'tiny'
        builder = W.IncrementalBuild(self.commands)
        builder.build('first', compiler, source, target)
        self.assertEqual(self.commands.run('run-first', [str(target)], self.base), b'first\n')
        count = len(self.commands.records)
        builder.build('unchanged', compiler, source, target)
        self.assertEqual(len(self.commands.records), count)
        self.assertEqual(builder.records[-1]['outcome'], 'UNCHANGED')
        before = source.stat()
        source.write_text(source.read_text().replace('first', 'later'))
        os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
        builder.build('changed', compiler, source, target)
        self.assertEqual(self.commands.run('run-later', [str(target)], self.base), b'later\n')
        target.write_bytes(b'corrupt executable')
        builder.build('binary-tamper-rebuild', compiler, source, target)
        self.assertEqual(self.commands.run('run-restored', [str(target)], self.base), b'later\n')
        source.write_text('#error INTENTIONAL_TEST_FAILURE\n')
        builder.build('failure', compiler, source, target, expected='nonzero')
        self.assertFalse(target.exists())
        self.assertFalse(target.with_suffix('.state.json').exists())
        self.assertEqual(builder.records[-1]['outcome'], 'EXPECTED_COMPILE_FAILURE')


class ProjectWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='developer-project-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.logs = self.base / 'logs'; self.logs.mkdir()
        self.home = self.base / 'home'; self.home.mkdir()
        self.commands = W.Commands(self.logs, self.home, os.defpath, timeout=5, total=60)
        self.tools = {n: str(Path(p).resolve()) for n in ('cc', 'python3', 'vim', 'make', 'ninja')
                      if (p := shutil.which(n, path=os.defpath)) is not None}

    def project(self, backend):
        if any(n not in self.tools for n in ('cc', 'python3', 'vim', backend)):
            self.skipTest(backend + ' project prerequisites unavailable; workflow NOT RUN')
        return W.BuildProject(backend, self.commands, self.tools, self.base)

    def check_full(self, backend):
        project = self.project(backend)
        result = project.journey()
        self.assertEqual(result['status'], 'PASS_REAL_PROJECT_WORKFLOW')
        self.assertEqual(len(self.commands.records), 15)
        self.assertTrue(all(r['success'] for r in self.commands.records))
        self.assertTrue(all(r['supervision']['group_census'] == 'EMPTY_TWICE' for r in self.commands.records))
        unchanged = next(r for r in result['records'] if r['step'] == 'unchanged-build')
        self.assertEqual(unchanged['before'], unchanged['after'])
        rejected = next(r for r in result['records'] if r['step'] == 'broken-test')
        self.assertEqual(rejected['stale_run_attempts'], 0)
        self.assertEqual(rejected['outcome'], 'GRAPH_AND_GATE_REJECT_STALE_EXECUTABLE')
        self.assertEqual(rejected['stale_binary'], rejected['before']['hello']['file'])
        for row in result['records']:
            for path, wanted in row['source_snapshots'].items():
                self.assertEqual(W.file_pin(self.logs / path), wanted)
        broken = next(r for r in result['records'] if r['step'] == 'broken-build')
        source = next(p for p in broken['source_snapshots'] if p.endswith('/hello.c'))
        self.assertIn(b'#error INTENTIONAL_PROJECT_COMPILE_FAILURE', (self.logs / source).read_bytes())

    def test_real_make_configure_build_test_edit_failure_recovery(self):
        self.check_full('make')

    def test_real_ninja_configure_build_test_edit_failure_recovery(self):
        self.check_full('ninja')

    def test_gate_rejects_source_and_binary_tamper_before_launch(self):
        for backend in ('make', 'ninja'):
            with self.subTest(backend=backend):
                project = self.project(backend)
                project.configure(); project.build('initial')
                raw = project.source.read_bytes()
                count = len(self.commands.records)
                project.source.write_bytes(raw + b'// unbuilt source change\n')
                with self.assertRaises(W.Failure):
                    project.run('forbidden', b'Project version one\n')
                with self.assertRaises(W.Failure):
                    project.test('forbidden-test', b'Project version one\n')
                self.assertEqual(len(self.commands.records), count)
                project.source.write_bytes(raw)
                project.binary.write_bytes(b'wrong executable')
                with self.assertRaises(W.Failure):
                    project.run('forbidden-tampered', b'Project version one\n')
                self.assertEqual(len(self.commands.records), count)

    def test_fixed_graphs_quote_compiler_alias_with_shell_metacharacters(self):
        if 'cc' not in self.tools:
            self.skipTest('compiler unavailable; escaping control NOT RUN')
        alias = self.base / "compiler space $value ' quote; $(not-a-command)"
        alias.symlink_to(self.tools['cc'])
        self.tools['cc'] = str(alias)
        for backend in ('make', 'ninja'):
            with self.subTest(backend=backend):
                project = self.project(backend)
                project.configure(); project.build('quoted-build')
                project.run('quoted-run', b'Project version one\n')
                project.test('quoted-test', b'Project version one\n')
        self.assertFalse((self.base / 'not-a-command').exists())

    def test_missing_backends_are_explicit_and_launch_nothing(self):
        results = {}
        W.project_workflows(self.commands, {}, self.base, results)
        self.assertEqual(results, {n: dict(status='MISSING_OPTIONAL', workflow='NOT_RUN')
                                  for n in ('make', 'ninja')})
        self.assertEqual(self.commands.records, [])

    def test_failed_graph_test_revokes_execution_until_successful_build(self):
        false = shutil.which('false', path=os.defpath)
        if false is None:
            self.skipTest('false unavailable; failed-test control NOT RUN')
        for backend in ('make', 'ninja'):
            with self.subTest(backend=backend):
                project = self.project(backend)
                project.configure(); project.build('initial')
                with self.assertRaises(W.Failure):
                    project.test('wrong-output', b'not the expected message\n')
                self.assertFalse(project.usable)
                count = len(self.commands.records)
                with self.assertRaises(W.Failure):
                    project.run('forbidden-after-mismatch', b'Project version one\n')
                self.assertEqual(len(self.commands.records), count)
                project.build('after-output-failure')
                with mock.patch.object(project, 'argv', return_value=[false]):
                    with self.assertRaises(W.Failure):
                        project.test('nonzero-test', b'Project version one\n')
                self.assertFalse(project.usable)
                count = len(self.commands.records)
                with self.assertRaises(W.Failure):
                    project.run('forbidden-after-test-failure', b'Project version one\n')
                self.assertEqual(len(self.commands.records), count)
                project.build('after-command-failure')
                project.test('recovered-test', b'Project version one\n')

    def test_unexpected_build_failure_does_not_become_project_pass(self):
        tools = dict(self.tools)
        false = shutil.which('false', path=os.defpath)
        if false is None or any(n not in tools for n in ('cc', 'python3')):
            self.skipTest('failure prerequisites unavailable; control NOT RUN')
        tools['make'] = false
        results = {}
        with self.assertRaises(W.Failure):
            W.project_workflows(self.commands, tools, self.base, results)
        self.assertEqual(results['make']['status'], 'FAIL')
        self.assertEqual(results['make']['records'][-1]['outcome'], 'UNEXPECTED_FAILURE')
        self.assertFalse(self.commands.records[-1]['success'])
        self.assertNotIn('ninja', results)

    def test_original_v1_workflow_bodies_held(self):
        import ast
        import hashlib
        source = (ROOT / 'scripts/workflows/developer_workflow.py').read_text()
        nodes = {n.name: ast.get_source_segment(source, n) for n in ast.parse(source).body
                 if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        wanted = {'load_core': 'd757ca96b9dd992e81d9151c87a1751314fac00b8eef80a146a773d9a8fe4391', 'Commands': '7d2d520e99efe072791deddccddbf68c6dc8d66e3eabc3376425a2b40e9eb24b', 'OnboardingAdapter': '5042050c3bff0c383e501a5a48bd7cce8fbe7e6e875a457db9c0949e0fcaba6f', 'IncrementalBuild': '3392355967138126c9c0104e60e858f8089ac00be9561ea68a8206cdc09be3fe', 'fixture_files': '0c787a8e74ead8232794af2482dc3d09991c5a36f47fa680b0d6552ee6dcd93d', 'journey': '1587efa37e4c6327adc8de6249709618978cb6555a806b92a75c95c87dfd5321'}
        for name, digest in wanted.items():
            self.assertEqual(hashlib.sha256(nodes[name].encode()).hexdigest(), digest, name)


if __name__ == '__main__':
    unittest.main(verbosity=2)
