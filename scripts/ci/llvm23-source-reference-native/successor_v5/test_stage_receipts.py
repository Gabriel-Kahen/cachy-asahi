#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Trusted repo AST and modeled receipts only; no artifact actor code executes."""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('llvm_stage_receipt_constructor', HERE / 'prepare.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec', 'os.spawn', 'os.posix_spawn')) or event in (
            'os.system', 'os.fork', 'os.forkpty', 'fcntl.flock', 'fcntl.lockf', 'os.unshare', 'os.setns'):
        raise RuntimeError('stage receipt DATA-only fence: ' + event)


sys.addaudithook(fence)


def selected(raw):
    functions = {'command', 'need', 'encode', 'natural', 'digest'}
    constants = {'MIB', 'LOG_LIMIT', 'STAGES'}
    nodes, found = [], set()
    for node in ast.parse(raw, filename='<maintained repo actor DATA>').body:
        if isinstance(node, ast.FunctionDef) and node.name in functions:
            nodes.append(node); found.add(node.name)
        elif (isinstance(node, ast.Assign) and len(node.targets) == 1 and
              isinstance(node.targets[0], ast.Name) and node.targets[0].id in constants):
            nodes.append(node); found.add(node.targets[0].id)
    if found != functions | constants:
        raise AssertionError('exact finite maintained-definition surface')
    namespace = dict(__builtins__=__builtins__, hashlib=hashlib, json=json,
                     Path=Path, re=re, stat=stat, subprocess=SimpleNamespace(STDOUT='MODELED_STDOUT'))
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<trusted receipt definitions>', 'exec'), namespace)
    return namespace


def natural(exit_code=0, forced=False):
    return dict(natural_exit=not forced, forced_cleanup=forced, group_absent=True,
                retirement='REAPED', ownership_lost=False, leader_held_until_group_inspection=True,
                exit_observed_via_waitpid=True, exit=exit_code, cleanup_error=None)


class ReceiptControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # This is maintained repo payload, not B/source-tree or a TAR member.
        cls.repo = HERE.parent / 'payload/actor/container_mode.py'
        raw, mode = P.fs.read(cls.repo)
        if P.descriptor((raw, mode)) != P.OLD_ACTOR:
            raise AssertionError('maintained actor payload must equal exact parent descriptor')
        cls.original = raw
        cls.fixed = P.corrected(raw)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='llvm-stage-receipts-DATA-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.out, self.work = self.root / 'output', self.root / 'work'
        self.out.mkdir(mode=0o700); self.work.mkdir(mode=0o700)
        self.calls, self.mode = [], 'pass'
        self.facts = {}
        for name in ('probe', 'tools', 'runtime', 'runtimes', 'check'):
            path = self.out / (name + '.json')
            path.write_bytes(('MODEL_INITIAL_FACT ' + name + '\n\n').encode())
            path.chmod(0o640)
            self.facts[path.name] = (path.read_bytes(), P.fs.identity(path.lstat()))
        self.old, self.new = selected(self.original), selected(self.fixed)
        for namespace in (self.old, self.new):
            namespace.update(OUT=self.out, WORK=self.work, INPUTS=self.root / 'MODEL-inputs',
                             remaining=lambda: 600.0, environment=lambda: {'MODEL_ONLY': '1'},
                             module=self.module)

    def module(self, name, path):
        self.assertEqual(name, 'llvm23_owned_child')
        self.assertEqual(path, self.root / 'MODEL-inputs/helpers/owned_child.py')
        return SimpleNamespace(run=self.run_owned)

    def run_owned(self, argv, **options):
        self.calls.append((list(argv), options))
        self.assertEqual(options['cwd'], self.work / 'recipe')
        self.assertEqual(options['allowed_uids'], {1001})
        self.assertEqual(options['env'], {'MODEL_ONLY': '1'})
        self.assertEqual(options['stdout_limit'], self.new['LOG_LIMIT'])
        options['stdout'].write(b'MODELED_STAGE_OUTPUT\n')
        options['stdout'].flush()
        code = 7 if self.mode == 'nonzero' else 0
        options['lifecycle'].update(natural(code, forced=self.mode in ('forced', 'cancel')))
        if self.mode == 'cancel':
            (self.work / 'cancelled').write_bytes(b'MODELED cancellation\n')
            options['on_tick']()
        return SimpleNamespace(returncode=code)

    def invoke(self, name, namespace=None):
        namespace = self.new if namespace is None else namespace
        seconds = namespace['STAGES'].get(name, 60)
        return namespace['command'](['/usr/bin/bash', '/MODEL/build.sh', name], name, seconds)

    def assert_facts(self):
        for name, before in self.facts.items():
            path = self.out / name
            self.assertEqual((path.read_bytes(), P.fs.identity(path.lstat())), before, name)

    def receipt(self, name):
        return json.loads((self.out / (name + '.json')).read_bytes())

    def test_original_reproduces_tools_json_collision_and_preserves_fact(self):
        with self.assertRaisesRegex(ValueError, 'command receipt collision'):
            self.invoke('tools', self.old)
        self.assertEqual(len(self.calls), 1)
        self.assertTrue((self.out / 'tools.log').is_file())
        self.assert_facts()

    def test_all_four_stages_coexist_with_all_initial_fact_bytes_and_metadata(self):
        for name in self.new['STAGES']:
            row = self.invoke(name)
            self.assertEqual(row, self.receipt('stage-' + name))
            self.assertTrue(row['success'])
            self.assertEqual(row['log'], 'stage-' + name + '.log')
            self.assertEqual(row['requested_seconds'], self.new['STAGES'][name])
            self.assertEqual(row['log_pin']['sha256'], hashlib.sha256(b'MODELED_STAGE_OUTPUT\n').hexdigest())
        self.assertEqual(len(self.calls), 4)
        self.assert_facts()

    def test_only_singleton_insertion_and_original_buildloop_is_unchanged(self):
        self.assertEqual(self.fixed.replace(P.NEW.encode(), P.OLD.encode()), self.original)
        def action(raw):
            return ast.dump(next(n for n in ast.parse(raw).body if isinstance(n, ast.FunctionDef) and n.name == 'action'))
        self.assertEqual(action(self.fixed), action(self.original))
        self.assertEqual(self.new['STAGES'], self.old['STAGES'])
        self.assertEqual(self.new['LOG_LIMIT'], self.old['LOG_LIMIT'])

    def test_nonstage_command_names_are_not_rewritten(self):
        for name in ('makepkg', 'pkginfo', 'buildinfo', 'tool-owners', 'packages-unsorted'):
            row = self.invoke(name)
            self.assertEqual(row['log'], name + '.log')
            self.assertTrue((self.out / (name + '.json')).is_file())
            self.assertFalse((self.out / ('stage-' + name + '.json')).exists())
        self.assert_facts()

    def test_stage_prefix_is_not_added_twice(self):
        self.invoke('stage-tools')
        self.assertTrue((self.out / 'stage-tools.json').is_file())
        self.assertFalse((self.out / 'stage-stage-tools.json').exists())
        self.assert_facts()

    def test_nonzero_stage_preserves_failed_receipt_lifecycle_and_log_pin(self):
        self.mode = 'nonzero'
        with self.assertRaisesRegex(ValueError, 'command failed'):
            self.invoke('tools')
        row = self.receipt('stage-tools')
        self.assertFalse(row['success']); self.assertEqual(row['returncode'], 7)
        self.assertEqual(row['lifecycle'], natural(7))
        self.assertIsNotNone(row['log_pin']); self.assert_facts()

    def test_forced_retirement_never_becomes_success(self):
        self.mode = 'forced'
        with self.assertRaisesRegex(ValueError, 'natural retirement unproven'):
            self.invoke('runtimes')
        row = self.receipt('stage-runtimes')
        self.assertFalse(row['success']); self.assertTrue(row['lifecycle']['forced_cleanup'])
        self.assertIsNotNone(row['log_pin']); self.assert_facts()

    def test_cancellation_before_launch_keeps_stage_failure_receipt_without_child(self):
        (self.work / 'cancelled').write_bytes(b'MODELED cancellation\n')
        with self.assertRaisesRegex(ValueError, 'actor cancelled'):
            self.invoke('probe')
        row = self.receipt('stage-probe')
        self.assertEqual(self.calls, [])
        self.assertFalse(row['success']); self.assertIsNone(row['returncode']); self.assertIsNone(row['log_pin'])
        self.assert_facts()

    def test_cancellation_during_child_keeps_stage_log_and_lifecycle(self):
        self.mode = 'cancel'
        with self.assertRaisesRegex(ValueError, 'actor cancelled'):
            self.invoke('check')
        row = self.receipt('stage-check')
        self.assertFalse(row['success']); self.assertIsNone(row['returncode'])
        self.assertTrue(row['lifecycle']['forced_cleanup'])
        self.assertIsNotNone(row['log_pin']); self.assert_facts()

    def test_preexisting_stage_receipt_and_log_are_not_overwritten(self):
        files = {name: self.out / ('stage-tools.' + name) for name in ('log', 'json')}
        for path in files.values(): path.write_bytes(b'MODELED previous attempt\n')
        before = {name: (path.read_bytes(), P.fs.identity(path.lstat())) for name, path in files.items()}
        with self.assertRaisesRegex(ValueError, 'receipt collision'):
            self.invoke('tools')
        self.assertEqual(self.calls, [])
        for name, path in files.items(): self.assertEqual((path.read_bytes(), P.fs.identity(path.lstat())), before[name])
        self.assert_facts()

    def test_json_only_collision_refuses_and_keeps_original_receipt(self):
        path = self.out / 'stage-tools.json'; path.write_bytes(b'MODELED prior receipt\n')
        before = (path.read_bytes(), P.fs.identity(path.lstat()))
        with self.assertRaisesRegex(ValueError, 'receipt collision'):
            self.invoke('tools')
        self.assertEqual(len(self.calls), 1)  # Existing command semantics are unchanged.
        self.assertEqual((path.read_bytes(), P.fs.identity(path.lstat())), before)
        self.assertTrue((self.out / 'stage-tools.log').is_file()); self.assert_facts()

    def test_invalid_command_name_refuses_before_any_output(self):
        before = {p.name for p in self.out.iterdir()}
        for name in ('../tools', '', 'TOOLS', 'stage/tools'):
            with self.subTest(name=name), self.assertRaises(ValueError): self.invoke(name)
        self.assertEqual(self.calls, []); self.assertEqual({p.name for p in self.out.iterdir()}, before)


if __name__ == '__main__':
    unittest.main(verbosity=2)
