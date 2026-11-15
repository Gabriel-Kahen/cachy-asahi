# SPDX-License-Identifier: MIT
"""Fenced host-CLI binding controls; modeled ELF DATA is never executed."""
import ast
from contextlib import contextmanager
import copy
import ctypes
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('llvm_cli_controls', HERE/'runtime.py')
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
K = R.module('contracts')
# Bind only this DATA-allocation API before the permanent operational fence.
# On Python builds without os.memfd_create the tested lazy loader receives this
# prebound libc handle; no quota/daemon/process API is available through it.
MEMFD_LIB = ctypes.CDLL(None, use_errno=True)
MEMFD_FN = MEMFD_LIB.memfd_create
MEMFD_ADDRESS = ctypes.cast(MEMFD_FN, ctypes.c_void_p).value


def fence(event, args):
    if event == 'ctypes.call_function' and args == (MEMFD_ADDRESS, (b'Root-reviewed-Docker-CLI', 0x13)):
        return  # Only this bounded DATA allocation, never execution or quota.
    if event.startswith(('subprocess.', 'socket.', 'ctypes.')) or event in ('os.system', 'os.fork', 'os.posix_spawn', 'os.exec', 'fcntl.flock'):
        raise RuntimeError('CLI control operational fence: '+event)


sys.addaudithook(fence)


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.cli = self.root/'reviewed-cli'
        data = bytearray(64); data[:7] = b'\x7fELF\x02\x01\x01'
        data[16:18] = (2).to_bytes(2, 'little')
        data[18:20] = {'x86_64': 62, 'aarch64': 183}[os.uname().machine].to_bytes(2, 'little')
        self.cli.write_bytes(data+b'MODELED_HOST_CLI_NEVER_EXECUTED'); self.cli.chmod(0o755)
        self.authority = dict(docker_cli=dict(path=str(self.cli), **K.pin(self.cli)), daemon={'MODEL_ONLY': True})
        self.endpoint = 'unix:///run/user/'+str(os.getuid())+'/docker.sock'
        self.addCleanup(patch.stopall)
        original = R.module
        patch.object(R, 'module', side_effect=lambda name: K if name == 'contracts' else original(name)).start()
        patch.object(K, 'endpoint', return_value=self.endpoint).start()
        patch.object(K.ctypes, 'CDLL', return_value=MEMFD_LIB).start()

    def test_positive_whole_pin_and_open_fd_close(self):
        self.assertEqual(K.docker_cli(self.authority), self.authority['docker_cli'])
        with K.open_docker_cli(self.authority) as fd:
            self.assertEqual(os.pread(fd, self.cli.stat().st_size, 0), self.cli.read_bytes())
        with self.assertRaises(OSError): os.fstat(fd)

    def test_missing_null_and_extra_descriptor_fields_refuse(self):
        for row in (None, {}, dict(path=None, bytes=None, sha256=None), dict(self.authority['docker_cli'], extra=True)):
            with self.subTest(row=row), self.assertRaises(ValueError): K.docker_cli(dict(docker_cli=row))
        with self.assertRaises(ValueError): K.docker_cli({})

    def test_tampered_hash_length_and_absent_path_refuse(self):
        for key, value in [('sha256', '0'*64), ('bytes', self.cli.stat().st_size+1), ('path', str(self.root/'absent'))]:
            bad = copy.deepcopy(self.authority); bad['docker_cli'][key] = value
            with self.subTest(key=key), self.assertRaises((ValueError, OSError)): K.docker_cli(bad)

    def test_symlink_operand_and_symlink_ancestor_refuse(self):
        alias = self.root/'docker'; alias.symlink_to(self.cli)
        parent = self.root/'alias'; parent.symlink_to(self.root, target_is_directory=True)
        for path in (alias, parent/self.cli.name):
            bad = copy.deepcopy(self.authority); bad['docker_cli']['path'] = str(path)
            with self.subTest(path=path), self.assertRaises(ValueError): K.docker_cli(bad)

    def test_noncanonical_relative_dot_and_dotdot_refuse(self):
        for path in ('reviewed-cli', str(self.root)+'/./reviewed-cli', str(self.root)+'/../'+self.root.name+'/reviewed-cli', str(self.root)+'//reviewed-cli'):
            bad = copy.deepcopy(self.authority); bad['docker_cli']['path'] = path
            with self.subTest(path=path), self.assertRaises(ValueError): K.docker_cli(bad)

    def test_unsafe_mode_and_hardlink_refuse(self):
        for mode in (0o644, 0o775, 0o777, 0o4755, 0o2755):
            self.cli.chmod(mode)
            with self.subTest(mode=oct(mode)), self.assertRaises(ValueError): K.docker_cli(self.authority)
        self.cli.chmod(0o755); os.link(self.cli, self.root/'hardlink')
        with self.assertRaises(ValueError): K.docker_cli(self.authority)

    def test_script_and_wrong_host_elf_refuse_even_with_updated_pin(self):
        for data in (b'#!/bin/sh\n'+b'x'*80, b'\x7fELF'+b'x'*80):
            self.cli.write_bytes(data); self.authority['docker_cli'].update(K.pin(self.cli))
            with self.assertRaises(ValueError): K.docker_cli(self.authority)

    def test_no_active_authority_refuses_before_output_or_launch(self):
        out = self.root/'absent-output'
        with self.assertRaises(ValueError): R.command(['docker', 'info'], out, 'no-authority')
        self.assertFalse(out.exists())

    def test_held_fd_launch_ignores_hostile_path_and_records_canonical_argv(self):
        out = self.root/'out'; out.mkdir(); seen = []
        class NoLaunch(Exception): pass
        def capture(argv, **kwargs):
            fd, = kwargs['pass_fds']
            self.assertEqual(kwargs['executable'], '/proc/self/fd/'+str(fd))
            self.assertEqual(os.pread(fd, self.cli.stat().st_size, 0), self.cli.read_bytes())
            self.assertEqual(argv, [str(self.cli), 'info'])
            self.assertEqual(kwargs['env']['PATH'], '/usr/bin:/bin')
            self.assertEqual(kwargs['env']['DOCKER_HOST'], self.endpoint)
            self.assertNotIn('DOCKER_CONTEXT', kwargs['env']); seen.append(fd)
            raise NoLaunch()
        with patch.dict(os.environ, PATH=str(self.root), DOCKER_CONTEXT='hostile'), R.transport(self.authority), patch.object(R.subprocess, 'Popen', side_effect=capture):
            with self.assertRaises(NoLaunch): R.command(['docker', 'info'], out, 'fenced')
        self.assertEqual(len(seen), 1)
        with self.assertRaises(OSError): os.fstat(seen[0])
        import json
        self.assertEqual(json.loads((out/'fenced.json').read_bytes())['argv'][0], str(self.cli))

    def test_unreviewed_absolute_cli_aliases_refuse(self):
        with R.transport(self.authority):
            for operand in ('/usr/bin/docker', str(self.root/'docker')):
                self.assertTrue(R.docker_operand([operand]))
                with self.subTest(operand=operand), self.assertRaises(ValueError):
                    with R.docker_launch([operand, 'info']): self.fail('alias launched')

    def test_transport_restores_environment_and_nested_authority_on_exception(self):
        previous = dict(os.environ); self.assertIsNone(R._DOCKER_AUTHORITY)
        with self.assertRaisesRegex(ValueError, 'MODELED'):
            with R.transport(self.authority):
                outer = R._DOCKER_AUTHORITY
                with R.transport(self.authority): self.assertIsNot(outer, R._DOCKER_AUTHORITY)
                self.assertIs(outer, R._DOCKER_AUTHORITY); raise ValueError('MODELED')
        self.assertEqual(dict(os.environ), previous); self.assertIsNone(R._DOCKER_AUTHORITY)

    def test_each_dispatch_rechecks_tamper_and_endpoint(self):
        with R.transport(self.authority):
            self.cli.write_bytes(b'changed')
            with self.assertRaises(ValueError):
                with R.docker_launch(['docker', 'wait', 'MODELED']): self.fail('tamper launched')
            with patch.dict(os.environ, DOCKER_HOST='unix:///wrong.sock'), self.assertRaises(ValueError):
                R.docker_selection(['docker', 'info'])

    def test_launch_holds_original_inode_if_path_replaced_after_validation(self):
        with R.transport(self.authority), R.docker_launch(['docker', 'info']) as (_, kwargs):
            fd, = kwargs['pass_fds']; original = os.fstat(fd).st_ino
            self.cli.rename(self.root/'original'); self.cli.write_bytes(b'replacement')
            self.assertEqual(os.fstat(fd).st_ino, original)
            self.assertNotEqual(self.cli.stat().st_ino, original)
        with self.assertRaises(OSError): os.fstat(fd)

    def test_launch_snapshot_is_sealed_against_inplace_rewrite(self):
        expected = self.cli.read_bytes()
        with R.transport(self.authority), R.docker_launch(['docker', 'info']) as (_, kwargs):
            fd, = kwargs['pass_fds']; self.cli.write_bytes(b'rewritten in place')
            self.assertEqual(os.pread(fd, len(expected), 0), expected)
            self.assertEqual(os.fstat(fd).st_size, len(expected))
            for mutate in (lambda: os.pwrite(fd, b'X', 0), lambda: os.ftruncate(fd, 0), lambda: os.ftruncate(fd, len(expected)+1)):
                with self.assertRaises(PermissionError): mutate()

    def test_recovery_dispatch_uses_same_descriptor_and_original_deadline(self):
        seen = []
        def command(argv, out, label, **kwargs):
            with R.docker_launch(argv) as (selected, launch):
                self.assertTrue(launch['pass_fds']); seen.append((selected, kwargs))
        deadline = time.monotonic()+10
        with R.transport(self.authority), patch.object(R, 'command', side_effect=command):
            for args in (['container', 'ls', '-a'], ['container', 'inspect', 'MODELED'], ['wait', 'MODELED'], ['container', 'rm', '--force', 'MODELED']):
                R.docker_call(['docker', *args], self.root, deadline, shared_deadline=deadline-1)
        self.assertEqual(len(seen), 4)
        for argv, kwargs in seen:
            self.assertEqual(argv[0], str(self.cli)); self.assertEqual(kwargs['deadline'], deadline-1)
            self.assertTrue(kwargs['completed']); self.assertFalse(kwargs['check'])

    def test_original_deadline_expiring_during_pin_refuses_launch_and_closes_fd(self):
        out = self.root/'out'; out.mkdir(); clock = [100.0]; held = []
        original = K.open_docker_cli
        @contextmanager
        def delayed(authority, **kwargs):
            with original(authority, **kwargs) as fd:
                held.append(fd); clock[0] = 150.0; yield fd
        with R.transport(self.authority), patch.object(R.time, 'monotonic', side_effect=lambda: clock[0]), patch.object(K, 'open_docker_cli', side_effect=delayed), patch.object(R.subprocess, 'Popen', side_effect=AssertionError('expired launch')):
            # The first pin is the pre-output check; delay only the held spawn pin.
            with patch.object(K, 'docker_cli', return_value=self.authority['docker_cli']), self.assertRaisesRegex(ValueError, 'work budget exhausted while pinning'):
                R.command(['docker', 'info'], out, 'expired')
        self.assertEqual(len(held), 1)
        with self.assertRaises(OSError): os.fstat(held[0])

    def test_cancellation_arriving_during_pin_refuses_launch(self):
        out = self.root/'out'; out.mkdir(); calls = []
        def pending():
            calls.append(True); return {R.signal.SIGINT} if len(calls) == 2 else set()
        with R.transport(self.authority), patch.object(R.signal, 'sigpending', side_effect=pending), patch.object(R.subprocess, 'Popen', side_effect=AssertionError('cancelled launch')):
            with self.assertRaisesRegex(KeyboardInterrupt, 'cancelled while pinning'):
                R.command(['docker', 'info'], out, 'cancelled')

    def test_deadline_and_cooperative_checks_run_during_hash_reads(self):
        self.cli.write_bytes(self.cli.read_bytes()+b'x'*200000)
        self.authority['docker_cli'].update(K.pin(self.cli)); ticks = []
        def clock():
            ticks.append(True); return float(len(ticks))
        with patch.object(K.time, 'monotonic', side_effect=clock), self.assertRaisesRegex(ValueError, 'work budget exhausted while pinning'):
            K.docker_cli(self.authority, deadline=3.0)
        self.assertEqual(len(ticks), 3)
        checks = []
        K.docker_cli(self.authority, check=lambda: checks.append(True))
        self.assertGreaterEqual(len(checks), 5)

    def test_lazy_libc_memfd_fallback_and_refusal(self):
        with patch.object(K.os, 'memfd_create', create=True) as wrapper:
            wrapper.return_value = 123; self.assertEqual(K.executable_memfd(), 123)
            self.assertEqual(wrapper.call_args.args[1], 0x13)
        with patch.object(K, 'hasattr', side_effect=lambda obj, name: False if obj is K.os else hasattr(obj, name), create=True):
            fd = K.executable_memfd()
            try: self.assertGreaterEqual(fd, 0)
            finally: os.close(fd)
            with patch.object(K.ctypes, 'CDLL', return_value=object()), self.assertRaises(ValueError): K.executable_memfd()

    def test_ops_preflight_and_retained_recheck_gate_cli(self):
        tree = ast.parse((HERE/'ops.py').read_bytes())
        for name in ('preflight', 'recheck'):
            node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
            self.assertTrue(any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == 'docker_cli' for n in ast.walk(node)))
        self.assertEqual(K.load(HERE/'authority.TEMPLATE.json')['docker_cli'], dict(path=None, bytes=None, sha256=None))
        for event in ('subprocess.Popen', 'socket.__new__', 'ctypes.dlopen'):
            with self.assertRaises(RuntimeError): sys.audit(event)


if __name__ == '__main__': unittest.main(verbosity=2)
