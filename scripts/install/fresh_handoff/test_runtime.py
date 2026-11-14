#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite runtime delivery controls; no package/native/hardware operations.

The source-hidden smoke runs the actual relocated CLI with network isolated,
original checkout hidden and a poisoned Python environment. Full TEST signature
journey coverage belongs to the signed handoff integration suite.
"""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


D = module('fresh_handoff_runtime', Path(__file__).with_name('runtime.py'))
H = module('fresh_handoff_runtime_composer', Path(__file__).with_name('handoff.py'))


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fresh-handoff-runtime-TEST-')
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.work.chmod(0o700)
        self.commit = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
        self.refs = H.source_refs(self.commit)
        self.staged = self.work/'staged'
        self.moved = self.work/'moved operator'

    def stage(self):
        result = D.stage(ROOT, self.staged, self.commit, self.refs)
        self.staged.rename(self.moved)
        self.pin = result['runtime_sha256']
        return result

    def cli(self, *arguments, prefix=(), pin=None):
        return subprocess.run([*map(str, prefix), sys.executable, '-I', '-B',
            str(self.moved/'scripts/install/fresh_handoff/runtime.py'), '--runtime-sha256',
            self.pin if pin is None else pin, '--', *map(str, arguments)],
            capture_output=True, timeout=30, cwd=self.work)

    def test_exact_finite_payload_and_relocated_help(self):
        self.assertEqual(set(H.SOURCES), set(D.INTERFACES))
        result = self.stage()
        self.assertEqual(result['runtime_files'], 17)
        self.assertEqual(result['payload_files'], len(D.FILES)+1)
        lock = D.verify(self.moved, self.pin)
        self.assertEqual(lock['source_commit'], self.commit)
        self.assertEqual(lock['source_refs'], self.refs)
        self.assertEqual(set(D.inventory(self.moved)), D.FILES | {D.MANIFEST})
        process = self.cli('--help')
        self.assertEqual(process.returncode, 0, process.stderr.decode())
        self.assertIn(b'{prepare,verify}', process.stdout)
        self.assertFalse((self.moved/'.git').exists())
        self.assertFalse(list(self.moved.rglob('__pycache__')))

    def test_wrong_external_runtime_pin_refused_before_helper_import(self):
        self.stage()
        process = self.cli('--help', pin='0'*64)
        self.assertEqual(process.returncode, 1)
        self.assertIn(b'external runtime inventory pin differs', process.stderr)
        self.assertNotIn(b'{prepare,verify}', process.stdout)

    def test_changed_deleted_foreign_and_symlinked_runtime_members_refused(self):
        self.stage()
        path = self.moved/'scripts/platform/recovery_inputs.py'
        raw = path.read_bytes()
        path.chmod(0o600)
        path.write_bytes(raw+b'\nraise RuntimeError("TEST must never execute")\n')
        process = self.cli('--help')
        self.assertEqual(process.returncode, 1)
        self.assertIn(b'runtime closure incomplete or changed', process.stderr)
        self.assertNotIn(b'TEST must never execute', process.stderr)
        path.unlink()
        with self.assertRaisesRegex(D.Error, 'closure incomplete'):
            D.verify(self.moved, self.pin)
        path.symlink_to(ROOT/'scripts/platform/recovery_inputs.py')
        with self.assertRaises(OSError):
            D.verify(self.moved, self.pin)
        path.unlink()
        path.write_bytes(raw)
        foreign = self.moved/'unexpected.py'
        foreign.write_text('raise RuntimeError("foreign")')
        with self.assertRaisesRegex(D.Error, 'foreign runtime member'):
            D.verify(self.moved, self.pin)

    def test_source_witness_drift_existing_output_and_unsafe_parent_refused(self):
        refs = dict(self.refs)
        refs[D.INTERFACES[0]] = dict(refs[D.INTERFACES[0]], sha256='0'*64)
        with self.assertRaisesRegex(D.Error, 'source witness changed'):
            D.stage(ROOT, self.staged, self.commit, refs)
        self.assertFalse(self.staged.exists())
        self.assertFalse(list(self.work.glob('.fresh-handoff-runtime-*')))
        self.stage()
        with self.assertRaisesRegex(D.Error, 'fresh runtime output'):
            D.stage(ROOT, self.moved, self.commit, self.refs)
        alias = self.work/'alias'
        alias.symlink_to(self.work, target_is_directory=True)
        with self.assertRaisesRegex(D.Error, 'directory/symlink'):
            D.stage(ROOT, alias/'out', self.commit, self.refs)

    def test_source_hidden_network_isolated_actual_CLI(self):
        if not shutil.which('bwrap'):
            self.skipTest('bwrap unavailable; no dependencies installed')
        self.stage()
        prefix = ['bwrap', '--unshare-net', '--ro-bind', '/', '/', '--proc', '/proc', '--dev', '/dev',
                  '--tmpfs', str(ROOT), '--chdir', str(self.work)]
        environment = dict(os.environ, PYTHONPATH='/TEST-poison', PYTHONHOME='/TEST-poison',
                           HOME='/TEST-no-home', PYTHONDONTWRITEBYTECODE='1')
        proof = subprocess.run([*prefix, '/usr/bin/python3', '-I', '-B', '-c',
            'import pathlib,socket,sys; assert not list(pathlib.Path(sys.argv[1]).iterdir()); '
            'assert [name for _,name in socket.if_nameindex()]==["lo"]', str(ROOT)],
            capture_output=True, timeout=30, env=environment)
        self.assertEqual(proof.returncode, 0, proof.stderr.decode())
        process = subprocess.run([*prefix, sys.executable, '-I', '-B',
            str(self.moved/'scripts/install/fresh_handoff/runtime.py'), '--runtime-sha256', self.pin,
            '--', '--help'], capture_output=True, timeout=30, env=environment)
        self.assertEqual(process.returncode, 0, process.stderr.decode())
        self.assertIn(b'{prepare,verify}', process.stdout)
        # No Git or source discovery even when ordinary handoff arguments fail.
        process = subprocess.run([*prefix, sys.executable, '-I', '-B',
            str(self.moved/'scripts/install/fresh_handoff/runtime.py'), '--runtime-sha256', self.pin,
            '--', 'verify', '--workspace', str(self.work/'not-a-handoff'), '--state-dir',
            str(self.work/'external-state'), '--selection-sha256', '0'*64, '--receipt-sha256', '0'*64],
            capture_output=True, timeout=30, env=environment)
        self.assertEqual(process.returncode, 1)
        self.assertNotIn(b'git', process.stderr.lower())
        self.assertFalse(list(self.moved.rglob('__pycache__')))


if __name__ == '__main__':
    unittest.main()
