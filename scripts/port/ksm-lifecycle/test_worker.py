#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Portable safety/contracts and real private GPG checks; no native acceptance."""
import copy
import importlib.util
import io
import json
import marshal
import os
from pathlib import Path
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from contextlib import nullcontext, redirect_stdout
from types import SimpleNamespace
from importlib.machinery import SourceFileLoader

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ksm_worker_tests_subject', HERE / 'worker.py')
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)
gspec = importlib.util.spec_from_file_location('ksm_worker_tests_guard', HERE.parents[1] / 'ci/source_suites.py')
g = importlib.util.module_from_spec(gspec)
gspec.loader.exec_module(g)


def guarded_record(uid=0):
    mounts = {p: {'fs': sorted(kinds)[0], 'options': set(flags)} for p, (kinds, flags) in g.STANDARD_TYPES.items()}
    mounts.update({p: {'fs': 'proc', 'options': {'ro', 'nosuid', 'nodev', 'noexec'}} for p in g.READONLY_PROC})
    mounts.update({p: {'fs': 'tmpfs', 'options': {'ro'}} for p in g.EMPTY_MASKS | g.NULL_MASKS})
    mounts.update({p: {'fs': 'ext4', 'options': {'rw'}} for p in g.RUNTIME_FILES})
    mounts.update({'/': {'fs': 'overlay', 'options': {'rw'}}, '/source': {'fs': 'ext4', 'options': {'ro'}},
                   '/out': {'fs': 'ext4', 'options': {'rw'}}, '/tmp': {'fs': 'tmpfs', 'options': {'rw', 'nosuid', 'nodev'}}})
    return {'arch': 'aarch64', 'uid': uid, 'docker_marker': True, 'interfaces': ['lo'], 'sockets': [],
            'unexpected_devices': [], 'capabilities': {k: w.SAFE_CAPS if k == 'CapBnd' or (not uid and k in {'CapEff', 'CapPrm'}) else 0 for k in g.CAPS},
            'no_new_privs': 1, 'source': '/source', 'output': '/out', 'paths_safe': True, 'home_safe': True,
            'home': '/tmp/ksm-stage', 'mounts': mounts, 'null_masks': {p: True for p in g.NULL_MASKS},
            'runtime_files': {p: {'regular': True, 'uid': 0, 'mode': 0o644} for p in g.RUNTIME_FILES}}


class PortableTests(unittest.TestCase):
    def test_root_guard_accepts_only_actual_writable_native_contract(self):
        w.native_guard(guarded_record(), g)
        for field, wrong in (('arch', 'x86_64'), ('uid', 1000), ('docker_marker', False), ('interfaces', ['eth0', 'lo']),
                             ('sockets', ['/run/sock']), ('unexpected_devices', ['/dev/dri']), ('no_new_privs', 0),
                             ('home', '/root'), ('paths_safe', False), ('home_safe', False)):
            with self.subTest(field=field):
                record = guarded_record(); record[field] = wrong
                with self.assertRaises(ValueError):
                    w.native_guard(record, g)

    def test_probe_has_no_effective_permitted_or_ambient_capabilities(self):
        w.native_guard(guarded_record(1000), g, 1000)
        for key in ('CapEff', 'CapPrm', 'CapInh', 'CapAmb'):
            record = guarded_record(1000); record['capabilities'][key] = 1
            with self.assertRaises(ValueError):
                w.native_guard(record, g, 1000)

    def test_root_guard_refuses_broader_or_missing_capabilities(self):
        for key in g.CAPS:
            record = guarded_record(); record['capabilities'][key] |= 1 << 8
            with self.assertRaises(ValueError):
                w.native_guard(record, g)
        record = guarded_record(); record['capabilities']['CapBnd'] = 0
        with self.assertRaises(ValueError):
            w.native_guard(record, g)

    def test_all_protected_proc_mounts_are_required(self):
        for point in g.READONLY_PROC:
            record = guarded_record(); del record['mounts'][point]
            with self.assertRaises(ValueError):
                w.native_guard(record, g)

    def test_root_source_sysfs_and_tmp_mounts_cannot_change_mode(self):
        for point in ('/', '/source', '/sys', '/sys/fs/cgroup', '/tmp'):
            record = guarded_record(); record['mounts'][point]['options'] = {'ro', 'rw'}
            with self.assertRaises(ValueError):
                w.native_guard(record, g)
        record = guarded_record(); record['mounts']['/host'] = {'fs': 'ext4', 'options': {'rw'}}
        with self.assertRaises(ValueError):
            w.native_guard(record, g)

    def test_runtime_masks_and_files_must_be_real(self):
        for point in g.NULL_MASKS:
            record = guarded_record(); record['null_masks'][point] = False
            with self.assertRaises(ValueError):
                w.native_guard(record, g)
        for changed in ({'mode': 0o666}, {'uid': 1000}, {'regular': False}):
            record = guarded_record(); record['runtime_files']['/etc/hosts'].update(changed)
            with self.assertRaises(ValueError):
                w.native_guard(record, g)

    def test_guard_refuses_host_before_private_output_or_package_commands(self):
        with patch.object(w, 'checked') as check, patch.object(w, 'success') as command:
            with self.assertRaises(ValueError):
                w.guard_entry('lifecycle')
            check.assert_not_called(); command.assert_not_called()

    def test_read_refuses_symlinks_hardlinks_and_special_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); source = root / 'data'; source.write_bytes(b'finite')
            self.assertEqual(w.read(source), b'finite')
            alias = root / 'alias'; alias.symlink_to(source)
            with self.assertRaises(ValueError): w.read(alias)
            os.link(source, root / 'hard')
            with self.assertRaises(ValueError): w.read(source)
            os.mkfifo(root / 'fifo')
            with self.assertRaises(ValueError): w.read(root / 'fifo')

    def test_changed_hash_and_oversize_files_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'data'; path.write_bytes(b'123')
            with self.assertRaises(ValueError): w.checked(path, '0' * 64)
            with self.assertRaises(ValueError): w.read(path, 2)

    def test_duplicate_nonfinite_and_nonobject_json_fail(self):
        for data in (b'{"a":1,"a":2}', b'{"a":NaN}', b'[]'):
            with self.assertRaises(ValueError): w.decode(data)

    def test_inventory_is_schema_and_map_exact_without_diagnostic_filtering(self):
        expected = {'a': '1-1', 'b': '2:3-4'}
        self.assertEqual(w.inventory(b'b 2:3-4\na 1-1\n', expected), expected)
        for data in (b'a 1-1\na 1-1\nb 2:3-4\n', b'a 1-1\n', b'a 1-1\nb 2:3-4\n:: Import PGP key?\n',
                     b'a 1-1\nb 2:3-4', b'a 2-1\nb 2:3-4\n'):
            with self.assertRaises(ValueError): w.inventory(data, expected)

    def test_command_retains_stdout_and_stderr_separately(self):
        code, stdout, stderr = w.run([sys.executable, '-I', '-c', "import sys;print('a 1-1');print('warning',file=sys.stderr)"], {'PATH': '/usr/bin:/bin'})
        self.assertEqual((code, stdout, stderr), (0, b'a 1-1\n', b'warning\n'))
        w.inventory(stdout, {'a': '1-1'})

    def test_command_timeout_and_output_bound(self):
        for code, timeout in (("import time;time.sleep(4)", .05), ("print('x'*1048577)", 5)):
            with self.assertRaises(ValueError):
                w.run([sys.executable, '-I', '-c', code], {'PATH': '/usr/bin:/bin'}, timeout=timeout)

    def test_user_fixture_checks_bytes_mode_owner_and_mtime(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'user'; path.write_bytes(b'keep'); path.chmod(0o600)
            initial = w.file_state(path)
            path.chmod(0o644)
            self.assertNotEqual(w.file_state(path), initial)
            path.chmod(0o600); path.write_bytes(b'changed')
            self.assertNotEqual(w.file_state(path), initial)

    def test_signature_status_requires_one_pinned_ed25519_sha256_primary(self):
        fp = 'A' * 40
        valid = f'[GNUPG:] GOODSIG {fp[-16:]} TEST\n[GNUPG:] VALIDSIG {fp} 2026-10-12 {int(time.time())} 0 4 0 22 8 00 {fp}\n'.encode()
        w.signature_status(valid, fp)
        for data in (valid + valid, valid + b'[GNUPG:] REVKEYSIG X\n', valid.replace(b'22 8 00', b'22 2 00'),
                     valid.replace(fp.encode(), b'B' * 40), b'[GNUPG:] GOODSIG X TEST\n'):
            with self.assertRaises(ValueError): w.signature_status(data, fp)

    def test_public_identity_requires_bounded_single_signing_primary(self):
        now = int(time.time()); fp = 'A' * 40
        row = f'pub:-:255:22:X:{now-1}:{now+100}:::::scSC:::::ed25519:\nfpr:::::::::{fp}:\nuid:::::::::{w.TEST_ID}:\n'.encode()
        self.assertEqual(w.public_identity(row), fp)
        for data in (row + row, row + b'sub:::::::::::::\n', row.replace(str(now+100).encode(), b'0'),
                     row.replace(b'255:22', b'255:1'), row.replace(b':scSC:', b':cC:')):
            with self.assertRaises(ValueError): w.public_identity(data)
        with self.assertRaises(ValueError): w.public_identity(row, 'B' * 40)

    def test_installed_payload_checks_full_regular_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'payload'; path.write_bytes(b'checked'); path.chmod(0o644)
            package = {'payload': {str(path)[1:]: {'sha256': w.sha(b'checked'), 'mode': 0o644,
                                                 'uid': os.getuid(), 'gid': os.getgid()}}}
            w.installed_payload(package)
            path.chmod(0o755)
            with self.assertRaises(ValueError): w.installed_payload(package)

    def test_absent_payload_refuses_dangling_links_and_symlink_ancestors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); path = root / 'payload'
            package = {'payload': {str(path)[1:]: {}}}
            w.absent_payload(package)
            path.symlink_to(root / 'missing')
            with self.assertRaises(ValueError): w.absent_payload(package)
            path.unlink(); alias = root / 'parent'; alias.symlink_to(root / 'missing-parent')
            with self.assertRaises(ValueError):
                w.absent_payload({'payload': {str(alias / 'file')[1:]: {}}})

    def test_owned_payload_refuses_extra_missing_duplicates_and_unknown_dirs(self):
        package = {'payload': {'usr/bin/tool': {}, 'usr/share/doc/tool/README.md': {}}}
        valid = b'/usr/\n/usr/bin/\n/usr/bin/tool\n/usr/share/\n/usr/share/doc/\n/usr/share/doc/tool/\n/usr/share/doc/tool/README.md\n'
        w.owned_payload(valid, package)
        for data in (valid + b'/etc/passwd\n', valid + b'/usr/bin/tool\n', valid.replace(b'/usr/bin/tool\n', b''),
                     valid + b'/usr/share/libalpm/hooks/\n', valid.rstrip(b'\n')):
            with self.assertRaises(ValueError): w.owned_payload(data, package)


    def test_bounded_exposure_refuses_symlink_socket_and_node_flood(self):
        import socket
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            w.bounded_nodes([root])
            alias = root / 'alias'; alias.symlink_to('/dev/null')
            with self.assertRaises(ValueError): w.bounded_nodes([root])
            alias.unlink()
            sock = socket.socket(socket.AF_UNIX)
            try:
                sock.bind(str(root / 'socket'))
                with self.assertRaises(ValueError): w.bounded_nodes([root])
            finally:
                sock.close(); (root / 'socket').unlink()
            names = ['same'] * 4097
            (root / 'same').write_bytes(b'finite')
            with patch.object(w.os, 'walk', return_value=[(str(root), [], names)]):
                with self.assertRaisesRegex(ValueError, 'runtime-node-bound'):
                    w.bounded_nodes([root])


    def test_pacman_zero_exit_with_ancillary_error_is_rejected_on_either_stream(self):
        command = ['/usr/bin/pacman', '-U', '--noscriptlet', '/private/test.pkg.tar.xz']
        progress = b'checking package integrity...\ninstalling cachy-asahi-ksmctl...\n'
        failures = (b'error: could not execute command\n',
                    b'could not change root directory (Operation not permitted)\n',
                    b'could not change the root directory (Operation not permitted)\n',
                    b'could not change directory (Operation not permitted)\n')
        for diagnostic in failures:
            for stdout, stderr in ((progress, diagnostic), (progress + diagnostic, b'')):
                with self.subTest(diagnostic=diagnostic, stderr=bool(stderr)), \
                     patch.object(w, 'run', return_value=(0, stdout, stderr)):
                    # The old generic success primitive accepts this actual producer shape.
                    self.assertEqual(w.success(command, {}), stdout)
                    with self.assertRaisesRegex(ValueError, '^pacman-positive-diagnostic-error$'):
                        w.pacman_success(command, {})

    def test_pacman_clean_result_returns_unmodified_stdout_and_forwards_bounds(self):
        command = ['/usr/bin/pacman', '--config', '/private/pacman.conf', '-Q']
        stdout = b'base 1-1\n'
        with patch.object(w, 'run', return_value=(0, stdout, b'warning: fixture warning\n')) as run:
            self.assertEqual(w.pacman_success(command, {}, timeout=90), stdout)
            run.assert_called_once_with(command, {}, timeout=90)
        with patch.object(w, 'run', return_value=(0, stdout, b'error: ancillary inventory error\n')):
            with self.assertRaises(ValueError): w.pacman_success(command, {})
        with patch.object(w, 'run', return_value=(1, stdout, b'')):
            with self.assertRaises(ValueError): w.pacman_success(command, {})
        with self.assertRaises(ValueError): w.pacman_success(['/usr/bin/gpg'], {})


    def test_check_sets_are_fixed_finite_and_distinct(self):
        self.assertEqual(len(w.CHECKS['sign']), 6)
        self.assertEqual(len(w.CHECKS['lifecycle']), 12)
        for names in w.CHECKS.values():
            self.assertEqual(len(names), len(set(names)))
        self.assertNotIn('activation', w.CHECKS['lifecycle'])


    def test_denied_cross_uid_kill_cannot_escape_cleanup_or_claim_reaped(self):
        original = subprocess.Popen
        def spawn(*args, **options):
            process = original(*args, **options)
            original_wait = process.wait
            waits = 0
            def wait(*a, **kw):
                nonlocal waits
                waits += 1
                if waits == 1:
                    return original_wait(*a, **kw)
                raise subprocess.TimeoutExpired('fixed-private-command', 5)
            process.wait = wait
            return process
        with patch.object(w.subprocess, 'Popen', side_effect=spawn), \
             patch.object(w.os, 'killpg', side_effect=PermissionError('cross UID')):
            with self.assertRaisesRegex(ValueError, 'private-command-not-reaped'):
                w.run([sys.executable, '-I', '-c', 'print("bounded")'], {'PATH': '/usr/bin:/bin'})

    def test_different_uid_process_failure_still_attempts_tmpfs_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp); home = sandbox / 'private'; home.mkdir()
            (home / 'private-key-placeholder').write_bytes(b'private')
            def process_cleanup(): raise ValueError('unexpected-process-owner')
            base = SimpleNamespace(defer_signals=nullcontext, cleanup_processes=process_cleanup)
            def mapped(path): return sandbox if str(path) == '/tmp' else Path(path)
            with patch.object(w, 'Path', side_effect=mapped), patch.object(w.os, 'chdir'):
                self.assertEqual(w.cleanup_private(home, base), {'processes': 'FAIL', 'tmpfs': 'PASS'})
            self.assertFalse(home.exists())

    def test_failed_tmpfs_removal_remains_failure(self):
        base = SimpleNamespace(defer_signals=nullcontext, cleanup_processes=lambda: True)
        with patch.object(w.os, 'chdir'), patch.object(w.shutil, 'rmtree', side_effect=OSError('denied')):
            self.assertEqual(w.cleanup_private(Path('/unused-test-private'), base), {'processes': 'PASS', 'tmpfs': 'FAIL'})

    def test_cancellation_is_retained_while_both_cleanups_are_attempted(self):
        with tempfile.TemporaryDirectory() as tmp:
            sandbox = Path(tmp); home = sandbox / 'private'; home.mkdir()
            base = SimpleNamespace(CANCELLED=True, defer_signals=nullcontext, cleanup_processes=lambda: True)
            with patch.object(w, 'Path', side_effect=lambda p: sandbox if str(p) == '/tmp' else Path(p)), \
                 patch.object(w.os, 'chdir'):
                result = w.cleanup_private(home, base)
            self.assertEqual(result, {'processes': 'PASS', 'tmpfs': 'PASS'})
            self.assertTrue(base.CANCELLED)


def forged_pyc(path, source):
    """Produce a genuinely timestamp/size-valid foreign bytecode fixture."""
    info = path.stat()
    cache = Path(importlib.util.cache_from_source(str(path)))
    cache.parent.mkdir(exist_ok=True)
    cache.write_bytes(importlib.util.MAGIC_NUMBER + struct.pack('<III', 0, int(info.st_mtime), info.st_size)
                      + marshal.dumps(compile(source, str(path), 'exec')))
    return SourceFileLoader('foreign_cache_control', str(path)).get_code('foreign_cache_control')


class CapturedLoaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'module.py'
        self.data = b"MARKER = 'TRUSTED'\n"
        self.path.write_bytes(self.data)
        self.pin = w.sha(self.data)
        self.enterContext(patch.dict(w._MODULES, clear=True))

    def test_same_size_replacement_after_capture_executes_only_reviewed_bytes(self):
        captured = w.checked(self.path, self.pin)
        foreign = self.data.replace(b'TRUSTED', b'UNSAFE!')
        self.assertEqual(len(foreign), len(captured))
        self.path.write_bytes(foreign)
        module = w.load('captured_fixture', self.path, self.pin, data=captured)
        self.assertEqual(module.MARKER, 'TRUSTED')
        self.assertEqual(module.__file__, str(self.path))
        with self.assertRaisesRegex(ValueError, 'changed-input'):
            w.load('cached_alias', self.path, self.pin)

    def test_valid_forged_pyc_is_ignored_even_when_bytecode_writes_disabled(self):
        code = forged_pyc(self.path, self.data.replace(b'TRUSTED', b'UNSAFE!'))
        self.assertIn('UNSAFE!', code.co_consts)
        self.assertTrue(sys.dont_write_bytecode)
        self.assertEqual(w.load('no_pyc_fixture', self.path, self.pin).MARKER, 'TRUSTED')

    def test_aliases_share_exact_module_and_wrong_pin_cannot_hit_cache(self):
        first = w.load('first_alias', self.path, self.pin)
        first.CANCELLED = True
        second = w.load('second_alias', self.path, self.pin)
        self.assertIs(first, second); self.assertTrue(second.CANCELLED)
        with self.assertRaisesRegex(ValueError, 'changed-input'):
            w.load('wrong_pin', self.path, '0' * 64)
        with self.assertRaisesRegex(ValueError, 'captured-source-pin'):
            w.load('wrong_capture', self.path, self.pin, data=b'foreign source')
        replacement = self.data.replace(b'TRUSTED', b'UNSAFE!')
        self.path.write_bytes(replacement)
        changed = w.load('changed_pin', self.path, w.sha(replacement))
        self.assertIsNot(first, changed); self.assertEqual(changed.MARKER, 'UNSAFE!')

    def test_same_descriptor_capture_enforces_mode_uid_gid_and_link_count(self):
        info = self.path.stat()
        expected = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
        self.assertEqual(w.checked(self.path, self.pin, metadata=expected), self.data)
        for field, value in (('mode', 0o755), ('uid', info.st_uid + 1), ('gid', info.st_gid + 1)):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'captured-file-metadata'):
                w.checked(self.path, self.pin, metadata=expected | {field: value})
        os.link(self.path, self.path.with_name('hardlink'))
        with self.assertRaisesRegex(ValueError, 'unsafe-file'):
            w.checked(self.path, self.pin, metadata=expected)

    def test_real_base_aliases_share_cancellation_state(self):
        first = w.load('base_entry', HERE.parents[2] / w.BASE, w.BASE_SHA)
        second = w.load('base_guard', HERE.parents[2] / w.BASE, w.BASE_SHA)
        self.assertIs(first, second)
        first.CANCELLED = True
        self.assertTrue(second.CANCELLED)

    def test_sign_guard_uses_captured_guard_and_preserves_proc_and_identity_checks(self):
        base = SimpleNamespace(worker_guard=lambda _: self.fail('unsafe base loader called'))
        record = {'mounts': {'protected-proc': {}}}
        calls = []
        guard = SimpleNamespace(READONLY_PROC={'protected-proc'}, environment=lambda *_: record,
                                guard=lambda value: calls.append(value))
        def mapped(value):
            return SimpleNamespace(iterdir=lambda: iter(())) if str(value) in {'/tmp', '/out'} else Path(value)
        with patch.object(w, '__file__', str(w.ROOT / w.HERE)), patch.object(w, 'Path', side_effect=mapped), \
             patch.object(w, 'load', side_effect=lambda name, path, pin: base if path == w.ROOT / w.BASE else guard), \
             patch.object(w.os, 'geteuid', return_value=1234), patch.object(w.os, 'getegid', return_value=1234), \
             patch.object(w.os, 'getpid', return_value=1), patch.object(w, 'bounded_nodes'), \
             patch.dict(w.os.environ, {'CACHY_ASAHI_CLIENT_UID': '1234', 'HOME': '/tmp/ksm-stage'}):
            self.assertIs(w.guard_entry('sign'), base)
            self.assertEqual(calls, [record])
            record['mounts'] = {}
            with self.assertRaisesRegex(ValueError, 'missing-protected-proc-mount'): w.guard_entry('sign')
            record['mounts'] = {'protected-proc': {}}
            for uid, gid in ((0, 1234), (1234, 0), (1235, 1235)):
                with self.subTest(uid=uid, gid=gid), patch.object(w.os, 'geteuid', return_value=uid), \
                     patch.object(w.os, 'getegid', return_value=gid), self.assertRaisesRegex(ValueError, 'uid-gid-mismatch'):
                    w.guard_entry('sign')


class CapturedProbeTests(unittest.TestCase):
    """Benign Python fixture only; no Docker, package or host sysfs operation."""
    SOURCE = b'''import json,sys
MARKER = 'TRUSTED'
def main(argv=None,root=None):
    args = sys.argv[1:] if argv is None else argv
    if '--enable' in args or '--disable' in args: return 2
    print(json.dumps({'state':{'run':1},'management_available':False,'marker':MARKER,
                      'file':__file__,'argv0':sys.argv[0],'name':__name__}))
    return 0
def report(root,page_size):
    return {'page_size_bytes':page_size,'management_available':False,
            'counters':{'pages_sharing':{'mib':'0.01171875' if page_size==4096 else '0.046875'}}}
if __name__ == '__main__': sys.exit(main())
'''

    def scenario(self, mutation):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); executable = root / 'installed'; executable.write_bytes(self.SOURCE); executable.chmod(0o755)
            home = root / 'home'; fixture = home / 'ksm-fixture'; fixture.mkdir(parents=True)
            (fixture / 'run').write_text('1\n')
            item = {'sha256': w.sha(self.SOURCE), 'mode': 0o755, 'uid': os.getuid(), 'gid': os.getgid()}
            record = {'package': {'payload': {'usr/bin/cachy-asahi-ksmctl': item}}}
            base = SimpleNamespace(defer_signals=nullcontext)
            original_check, original_run = w.checked, w.run
            descriptor, outputs = None, []
            def checked(path, pin, *args, **kwargs):
                captured = original_check(path, pin, *args, **kwargs)
                if mutation == 'replacement': executable.write_bytes(self.SOURCE.replace(b'TRUSTED', b'UNSAFE!'))
                return captured
            def command(argv, env, **kwargs):
                nonlocal descriptor
                descriptor = kwargs['pass_fds'][0]
                self.assertEqual(Path(f'/proc/self/fd/{descriptor}').read_bytes(), self.SOURCE)
                with self.assertRaises(OSError): os.write(descriptor, b'foreign')
                result = original_run(argv, env, **kwargs)
                if result[1]:
                    observation = json.loads(result[1])
                    self.assertEqual(observation['marker'], 'TRUSTED')
                    self.assertEqual(observation['file'], '/usr/bin/cachy-asahi-ksmctl')
                    self.assertEqual(observation['argv0'], '/usr/bin/cachy-asahi-ksmctl')
                    self.assertEqual(observation['name'], '__main__')
                outputs.append(result)
                return result
            if mutation == 'pyc':
                code = forged_pyc(executable, self.SOURCE.replace(b'TRUSTED', b'UNSAFE!'))
                self.assertIn('UNSAFE!', code.co_consts)
            def mapped(path):
                return home if str(path) == '/tmp/ksm-stage' else executable if str(path) == '/usr/bin/cachy-asahi-ksmctl' else Path(path)
            with patch.dict(w._MODULES, clear=True), patch.object(w, 'Path', side_effect=mapped), \
                 patch.object(w, 'guard_entry', return_value=base), patch.object(w, 'bindings', return_value=(record, None, None)), \
                 patch.object(w, 'installed_payload', side_effect=lambda _: executable.chmod(0o644) if mutation == 'wrong-mode' else None), \
                 patch.object(w, 'checked', side_effect=checked), \
                 patch.object(w, 'run', side_effect=command), redirect_stdout(io.StringIO()):
                if mutation == 'wrong-mode':
                    with self.assertRaisesRegex(ValueError, 'captured-file-metadata'): w.probe('a' * 64)
                    self.assertEqual(outputs, [])
                    return
                self.assertEqual(w.probe('a' * 64), 0)
                self.assertEqual(next(iter(w._MODULES.values())).MARKER, 'TRUSTED')
            self.assertEqual(len(outputs), 5)
            with self.assertRaises(OSError): os.fstat(descriptor)

    def test_installed_cli_and_fixture_ignore_same_size_path_replacement(self):
        self.scenario('replacement')

    def test_installed_cli_and_fixture_ignore_valid_forged_pyc(self):
        self.scenario('pyc')

    def test_changed_mode_between_payload_observation_and_capture_refused(self):
        self.scenario('wrong-mode')


class BindingTests(unittest.TestCase):
    """Synthetic binding fixtures; actual archive validation is contract's scope."""
    def scenario(self, mutation=None, phase='sign', *, source_race=False):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)
            names = {w.BASE: w.BASE_SHA, w.GUARD: w.GUARD_SHA, w.HERE: None, w.CONTRACT: None, w.STAGE: None}
            for name in names:
                target = source / name; target.parent.mkdir(parents=True, exist_ok=True)
                original = HERE.parents[2] / name
                value = original.read_bytes() if original.exists() else b'# fixture source'
                target.write_bytes(value); names[name] = w.sha(value)
            lock, current, approved = b'fixture 1-1\n', b'{"fixture":"current"}', b'{}'
            (source / 'packages.lock').write_bytes(lock)
            (source / 'current-inputs.json').write_bytes(current)
            (source / 'approved-inputs.json').write_bytes(approved)
            package_bytes = b'archive fixture validated by mock'
            (source / 'fixture.pkg.tar.xz').write_bytes(package_bytes)
            image = 'sha256:' + 'a' * 64
            bootstrap = {'status': 'image-provisioned', 'image_id': image, 'inputs_sha256': w.sha(current),
                         'packages_lock_sha256': w.sha(lock)}
            bootstrap_bytes = json.dumps(bootstrap).encode(); (source / 'bootstrap.json').write_bytes(bootstrap_bytes)
            package = {'status': 'PASS-build-pair-contract', 'filename': 'fixture.pkg.tar.xz', 'sha256': w.sha(package_bytes),
                       'source_date_epoch': 1700000000, 'image_id': image,
                       'expected_packages_sha256': w.sha(lock), 'approved_inputs_sha256': w.sha(approved),
                       'comparisons': {k: True for k in ('bytes_equal', 'payload_equal', 'pkginfo_equal', 'buildinfo_equal')}}
            record = {'schema_version': 1, 'purpose': w.PURPOSE, 'scope': w.SCOPE, 'phase': phase,
                      'nonce': 'b' * 32, 'source_commit': 'c' * 40, 'run_id': '12345', 'daemon_id': 'native-daemon',
                      'image_id': image, 'uid': 1000, 'package': package, 'approved_inputs_sha256': w.sha(approved),
                      'bootstrap_sha256': w.sha(bootstrap_bytes), 'packages_sha256': w.sha(lock),
                      'current_inputs_sha256': w.sha(current), 'source_sha256': names, 'signing': None}
            if phase == 'lifecycle':
                (source / 'package.sig').write_bytes(b'signature'); (source / 'public.gpg').write_bytes(b'public')
                record['signing'] = {'fingerprint': 'A' * 40, 'signature_sha256': w.sha(b'signature'), 'public_key_sha256': w.sha(b'public')}
            if mutation: mutation(record)
            data = json.dumps(record).encode(); (source / 'inputs.json').write_bytes(data)
            checked = w.checked
            original_contract = (source / w.CONTRACT).read_bytes()
            def capture(path, pin, *args, **kwargs):
                result = checked(path, pin, *args, **kwargs)
                if source_race and path == source / w.CONTRACT:
                    path.write_bytes(b'#' + b'x' * (len(result) - 1))
                return result
            def read(path, limit=w.LIMIT):
                return lock if str(path) == '/builder-packages.lock' else original_read(path, limit)
            original_read = w.read
            contract = SimpleNamespace(MAX_FILE=1024, validate_archive=lambda *_: {
                'filename': 'fixture.pkg.tar.xz', 'sha256': w.sha(package_bytes)})
            def captured_contract(name, path, pin, *, data):
                self.assertEqual(name, 'ksm_archive_contract')
                self.assertEqual(pin, names[w.CONTRACT])
                self.assertEqual(data, original_contract)
                if source_race: self.assertNotEqual(path.read_bytes(), data)
                return contract
            with patch.object(w, 'ROOT', source), patch.object(w, 'read', side_effect=read), \
                 patch.object(w, 'checked', side_effect=capture), patch.object(w, 'load', side_effect=captured_contract), \
                 patch.object(w, 'LOCK_SHA', w.sha(lock)), \
                 patch.object(w, 'INPUT_SHA', w.sha(current)), patch.object(w, 'APPROVED_SHA', w.sha(approved)), \
                 patch.dict(os.environ, {'CACHY_ASAHI_CLIENT_UID': '1000', 'CACHY_ASAHI_IMAGE_ID': image}):
                return w.bindings(phase, w.sha(data))[0]

    def test_complete_sign_and_lifecycle_bindings(self):
        self.assertIsNone(self.scenario()['signing'])
        self.assertEqual(self.scenario(phase='lifecycle')['signing']['fingerprint'], 'A' * 40)

    def test_contract_consumer_uses_verified_capture_after_same_size_replacement(self):
        self.assertIsNone(self.scenario(source_race=True)['signing'])

    def test_unknown_bool_wrong_phase_uid_or_image_fail(self):
        for mutation in (lambda r: r.update(unknown='x'), lambda r: r.update(schema_version=True),
                         lambda r: r.update(phase='lifecycle'), lambda r: r.update(uid=True),
                         lambda r: r.update(image_id='sha256:' + '0' * 64), lambda r: r.update(scope='stable')):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.scenario(mutation)

    def test_job_source_bootstrap_and_archive_drift_fail(self):
        for mutation in (lambda r: r.update(source_commit='bad'), lambda r: r.update(nonce='x'),
                         lambda r: r.update(run_id='0'), lambda r: r['source_sha256'].update({w.HERE: '0' * 64}),
                         lambda r: r.update(bootstrap_sha256='0' * 64), lambda r: r['package'].update(sha256='0' * 64),
                         lambda r: r['package'].update(filename='../escape'),
                         lambda r: r['package']['comparisons'].update(bytes_equal=1)):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): self.scenario(mutation)

    def test_sign_phase_cannot_accept_external_signer_and_lifecycle_requires_exact_sig_pins(self):
        with self.assertRaises(ValueError): self.scenario(lambda r: r.update(signing={}))
        with self.assertRaises(ValueError): self.scenario(lambda r: r['signing'].update(signature_sha256='0' * 64), phase='lifecycle')


class LifecycleSequenceTests(unittest.TestCase):
    def scenario(self, fail=None):
        with tempfile.TemporaryDirectory(prefix='ksm-worker-sequence-') as tmp:
            sandbox = Path(tmp)
            source = sandbox / 'source'; source.mkdir()
            home = sandbox / 'tmp/ksm-stage'; home.mkdir(parents=True)
            archive = b'bounded test archive'; signature = b'private signature placeholder'
            (source / 'test.pkg.tar.xz').write_bytes(archive)
            (source / 'package.sig').write_bytes(signature)
            (source / 'public.gpg').write_bytes(b'public placeholder')
            package = {'filename': 'test.pkg.tar.xz', 'sha256': w.sha(archive), 'payload': {
                'usr/bin/cachy-asahi-ksmctl': {'sha256': w.sha(b'executable'), 'mode': 0o755,
                                             'uid': os.getuid(), 'gid': os.getgid()}}}
            record = {'uid': os.getuid(), 'package': package,
                      'signing': {'fingerprint': 'A' * 40, 'signature_sha256': w.sha(signature)}}
            class Contract:
                NAME = 'cachy-asahi-ksmctl'
                VERSION = '0.1.0-1'
                MAX_FILE = 1024
                @staticmethod
                def _inventory(_): return {'base': '1-1'}
            for directory in ('usr/share/libalpm/hooks', 'etc/pacman.d/hooks'):
                hooks = sandbox / directory; hooks.mkdir(parents=True)
                (hooks / 'base.hook').write_bytes(b'Image-owned hook stays intact')
            installed = False
            commands, marks = [], []
            def mapped(value):
                value = str(value)
                if value.startswith('/') and not value.startswith(str(sandbox)):
                    return sandbox / value.lstrip('/')
                return Path(value)
            def generated(keys, _):
                keys.mkdir(mode=0o700)
                return 'B' * 40
            def command(argv, env, **_):
                nonlocal installed
                argv = [str(v) for v in argv]
                commands.append(argv)
                if argv[0] == '/usr/bin/pacman':
                    self.assertIn('Required TrustedOnly', (home / 'pacman.conf').read_text())
                    self.assertNotIn('--nodeps', argv); self.assertNotIn('--overwrite', argv)
                    if '-Q' in argv:
                        return b'base 1-1\n' + (b'cachy-asahi-ksmctl 0.1.0-1\n' if installed else b'')
                    if '-Qql' in argv:
                        return b'/usr/\n/usr/bin/\n/usr/bin/cachy-asahi-ksmctl\n'
                    self.assertIn('--noscriptlet', argv)
                    for directory in ('usr/share/libalpm/hooks', 'etc/pacman.d/hooks'):
                        self.assertEqual((sandbox / directory / 'base.hook').read_bytes(), b'Image-owned hook stays intact')
                    self.assertEqual(os.readlink(home / 'empty-hooks/base.hook'), '/dev/null')
                    executable = sandbox / 'usr/bin/cachy-asahi-ksmctl'
                    if '-U' in argv:
                        self.assertFalse(installed)
                        selected = Path(argv[-1])
                        self.assertEqual(selected.read_bytes(), archive)
                        self.assertEqual(Path(str(selected) + '.sig').read_bytes(), signature)
                        self.assertEqual(stat.S_IMODE(selected.parent.stat().st_mode), 0o700)
                        executable.parent.mkdir(parents=True, exist_ok=True)
                        executable.write_bytes(b'executable'); executable.chmod(0o755)
                        installed = True
                        if fail == 'inventory': return b''
                    elif '-R' in argv:
                        self.assertTrue(installed); executable.unlink(); installed = False
                if argv[0] == '/usr/bin/setpriv':
                    self.assertTrue(installed)
                    self.assertIn('--clear-groups', argv); self.assertIn('--no-new-privs', argv)
                    self.assertNotIn('--bounding-set=-all', argv)
                    if fail == 'probe': raise ValueError('fixed-probe-failure')
                    if fail == 'fixture': (home / 'user-owned.conf').write_bytes(b'changed')
                    return b'{"status":"PASS","actual_status_exit":3,"fixture_4k":"PASS","fixture_16k":"PASS"}'
                return b''
            with patch.object(w, 'Path', side_effect=mapped), patch.object(w, 'ROOT', source), \
                 patch.object(w, 'create_key', side_effect=generated), patch.object(w, 'public_identity'), \
                 patch.object(w, 'verify_signature'), patch.object(w, 'success', side_effect=command), \
                 patch.object(w, 'pacman_success', side_effect=command):
                if fail:
                    with self.assertRaises(ValueError):
                        w.lifecycle(record, Contract, b'lock', home, {}, marks.append, '0' * 64)
                else:
                    w.lifecycle(record, Contract, b'lock', home, {}, marks.append, '0' * 64)
                    self.assertFalse(installed)
                    self.assertEqual(marks, ['signature', 'install', 'installed-payload', 'probes', 'remove',
                                             'reinstall', 'final-remove', 'user-fixture'])
                    self.assertEqual(sum('-U' in c for c in commands), 2)
                    self.assertEqual(sum('-R' in c for c in commands), 2)
                    self.assertEqual((home / 'user-owned.conf').read_bytes(), b'KSM DEVELOPMENT TEST user fixture\n')
            return commands, marks

    def test_full_mocked_sequence_preserves_fixture_and_strict_signed_install(self):
        self.scenario()

    def test_probe_failure_prevents_reinstall_and_success_claim(self):
        commands, marks = self.scenario('probe')
        self.assertNotIn('probes', marks)
        self.assertEqual(sum('-U' in c for c in commands), 1)

    def test_user_fixture_mutation_prevents_remove_acceptance(self):
        _, marks = self.scenario('fixture')
        self.assertNotIn('remove', marks)
        self.assertNotIn('user-fixture', marks)


class ReceiptCancellationTests(unittest.TestCase):
    """Real worker receipt files/chmod/fsync; native/package phases are fixtures."""
    def setUp(self):
        self.base = w.load('ksm_actual_frozen_receipt_base', HERE.parents[2] / w.BASE, w.BASE_SHA)
        self.base.CANCELLED = False
        self.addCleanup(setattr, self.base, 'CANCELLED', False)

    def run_lifecycle_fixture(self, injection):
        with tempfile.TemporaryDirectory(prefix='ksm-receipt-cancellation-') as tmp:
            root = Path(tmp); home = root / 'home'; receipt = root / 'worker-receipt.json'
            record = {'uid': os.getuid(), 'nonce': 'a' * 32, 'image_id': 'sha256:' + 'b' * 64,
                      'source_commit': 'c' * 40, 'source_sha256': {}, 'packages_sha256': 'd' * 64,
                      'package': {'sha256': 'e' * 64, 'payload': {}},
                      'signing': {'fingerprint': 'A' * 40, 'signature_sha256': 'f' * 64, 'public_key_sha256': '0' * 64}}
            contract = SimpleNamespace(_inventory=lambda _: {})
            def mapped(value):
                return home if str(value) == '/tmp/ksm-stage' else receipt if str(value) == '/out/worker-receipt.json' else Path(value)
            def lifecycle(record, contract, lock, home, env, mark, pin):
                for name in w.CHECKS['lifecycle'][4:]: mark(name)
            def cleanup(home, base):
                w.shutil.rmtree(home)
                return {'processes': 'PASS', 'tmpfs': 'PASS'}
            original_chmod = Path.chmod
            original_persist = w.persist_receipt
            original_fsync = os.fsync
            original_signal = signal.signal
            calls = []
            armed, injected = False, False
            def chmod(path, *args, **kwargs):
                original_chmod(path, *args, **kwargs)
                if path == receipt:
                    self.assertEqual(path.read_bytes(), b'')  # no authoritative PASS precedes permission change
                    calls.append('chmod')
                    if injection == 'chmod': self.base.CANCELLED = True
            def fsync(fd):
                original_fsync(fd)
                calls.append('fsync')
                if injection == 'fsync': self.base.CANCELLED = True
            def persist(path, report, phase, base, **kwargs):
                nonlocal armed
                original_persist(path, report, phase, base, **kwargs)
                calls.append('persist')
                armed = report['status'] == 'PASS'
                if injection == 'post-receipt':
                    # A deferred cancellation after real fsync/chmod, before the worker returns.
                    self.base.CANCELLED = True
            def restore(signum, handler):
                nonlocal injected
                previous = original_signal(signum, handler)
                selected = getattr(signal, injection.removeprefix('restore-'), None) if injection else None
                boundary = signum == selected and handler is self.base.interrupt
                if injection == 'caller-SIGINT':
                    boundary = signum == signal.SIGINT and handler is signal.default_int_handler
                if armed and not injected and boundary:
                    injected = True
                    calls.append('actual-' + injection)
                    os.kill(os.getpid(), signum)
                return previous
            with patch.object(w, 'Path', side_effect=mapped), patch.object(w, 'guard_entry', return_value=self.base), \
                 patch.object(w, 'bindings', return_value=(record, contract, b'')), patch.object(w.os, 'chown'), \
                 patch.object(w, 'inventory'), patch.object(w, 'absent_payload'), patch.object(w, 'pacman_success', return_value=b''), \
                 patch.object(w, 'lifecycle', side_effect=lifecycle), patch.object(w, 'cleanup_private', side_effect=cleanup), \
                 patch.object(w, 'persist_receipt', side_effect=persist), patch.object(Path, 'chmod', autospec=True, side_effect=chmod), \
                 patch.object(w.os, 'fsync', side_effect=fsync), patch.dict(w.os.environ, dict(w.os.environ)):
                if injection == 'caller-SIGINT':
                    prior = {sig: signal.getsignal(sig) for sig in self.base.SIGNALS}
                    original_signal(signal.SIGINT, signal.default_int_handler)
                    try:
                        with patch.object(signal, 'signal', side_effect=restore), patch.object(w, 'checked'), \
                             patch.object(w, 'load', return_value=self.base), \
                             patch.object(sys, 'argv', ['worker', '--phase', 'lifecycle', '--contract-sha256', 'a' * 64]):
                            result = w.main()
                    finally:
                        for sig, handler in prior.items(): original_signal(sig, handler)
                    self.assertTrue(injected)
                elif injection and injection.startswith('restore-'):
                    with self.base.cancellation_handlers(), patch.object(signal, 'signal', side_effect=restore):
                        result = w.main_worker('lifecycle', 'a' * 64)
                    self.assertTrue(injected)
                else:
                    result = w.main_worker('lifecycle', 'a' * 64)
            self.assertFalse(home.exists())
            self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o644)
            self.assertIn('chmod', calls); self.assertIn('fsync', calls)
            return result, json.loads(receipt.read_bytes()), calls

    def test_real_chmod_cancellation_precedes_authoritative_write(self):
        result, report, calls = self.run_lifecycle_fixture('chmod')
        self.assertEqual(result, 1)
        self.assertEqual(report['status'], 'FAIL'); self.assertIs(report['cancelled'], True)
        self.assertLess(calls.index('chmod'), calls.index('fsync'))

    def test_real_fsync_cancellation_is_persisted_as_failure(self):
        result, report, _ = self.run_lifecycle_fixture('fsync')
        self.assertEqual(result, 1)
        self.assertEqual(report['status'], 'FAIL'); self.assertIs(report['cancelled'], True)

    def test_post_receipt_boundary_cancellation_rewrites_durable_pass(self):
        result, report, calls = self.run_lifecycle_fixture('post-receipt')
        self.assertEqual(result, 1)
        self.assertEqual(report['status'], 'FAIL'); self.assertIs(report['cancelled'], True)
        self.assertEqual(calls.count('persist'), 2)

    def test_clean_lifecycle_receipt_is_durable_readable_pass(self):
        result, report, calls = self.run_lifecycle_fixture(None)
        self.assertEqual(result, 0)
        self.assertEqual(report['status'], 'PASS'); self.assertNotIn('cancelled', report)
        self.assertEqual(calls.count('persist'), 1)

    def test_actual_sigterm_during_final_handler_restoration_rewrites_pass(self):
        result, report, calls = self.run_lifecycle_fixture('restore-SIGTERM')
        self.assertEqual(result, 1)
        self.assertEqual(report['status'], 'FAIL'); self.assertIs(report['cancelled'], True)
        self.assertIn('actual-restore-SIGTERM', calls)
        self.assertEqual(calls.count('persist'), 2)

    def test_actual_sigint_during_final_handler_restoration_rewrites_pass(self):
        result, report, calls = self.run_lifecycle_fixture('restore-SIGINT')
        self.assertEqual(result, 1)
        self.assertEqual(report['status'], 'FAIL'); self.assertIs(report['cancelled'], True)
        self.assertIn('actual-restore-SIGINT', calls)
        self.assertEqual(calls.count('persist'), 2)

    def test_actual_sigint_during_caller_handler_restoration_rewrites_pass(self):
        result, report, calls = self.run_lifecycle_fixture('caller-SIGINT')
        self.assertEqual(result, 1)
        self.assertEqual(report['status'], 'FAIL'); self.assertIs(report['cancelled'], True)
        self.assertIn('actual-caller-SIGINT', calls)
        self.assertEqual(calls.count('persist'), 2)



class GPGTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ksm-worker-gpg-')
        self.root = Path(self.tmp.name)
        self.env = {'PATH': '/usr/bin:/bin', 'HOME': str(self.root), 'TMPDIR': str(self.root), 'LC_ALL': 'C'}
        self.keys = self.root / 'private'
        self.fp = w.create_key(self.keys, self.env)
        self.package = self.root / 'package'; self.package.write_bytes(b'finite DEVELOPMENT TEST package bytes')
        self.signature = self.root / 'package.sig'; self.public = self.root / 'public.gpg'
        w.success(w.gpg(self.keys) + ['--local-user', self.fp, '--digest-algo', 'SHA256', '--output', self.signature,
                                    '--detach-sign', self.package], self.env)
        w.success(w.gpg(self.keys) + ['--output', self.public, '--export', self.fp], self.env)

    def tearDown(self):
        subprocess.run(['/usr/bin/gpgconf', '--homedir', str(self.keys), '--kill', 'all'], env=self.env,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=True)
        self.tmp.cleanup()

    def test_real_temporary_ed25519_sha256_detached_signature(self):
        w.verify_signature(self.keys, self.package, self.signature, self.public, self.fp, self.env)
        self.assertEqual(stat.S_IMODE(self.keys.stat().st_mode), 0o700)
        self.assertNotIn(b'PRIVATE KEY', self.public.read_bytes())
        self.assertEqual(len(self.fp), 40)

    def test_real_tampered_package_is_rejected(self):
        self.package.write_bytes(b'changed package')
        with self.assertRaises(ValueError):
            w.verify_signature(self.keys, self.package, self.signature, self.public, self.fp, self.env)

    def test_real_wrong_pinned_primary_is_rejected(self):
        with self.assertRaises(ValueError):
            w.verify_signature(self.keys, self.package, self.signature, self.public, 'B' * 40, self.env)

    def test_real_private_certifier_trusts_only_imported_test_signer(self):
        verifier = self.root / 'verifier'
        certifier = w.create_key(verifier, self.env)
        try:
            w.success(w.gpg(verifier) + ['--import', self.public], self.env)
            w.success(w.gpg(verifier) + ['--local-user', certifier, '--quick-lsign-key', self.fp], self.env)
            w.success(w.gpg(verifier) + ['--check-trustdb'], self.env)
            w.verify_signature(verifier, self.package, self.signature, self.public, self.fp, self.env)
            _, status, _ = w.run(w.gpg(verifier) + ['--status-fd', '1', '--verify', self.signature, self.package], self.env)
            self.assertIn(b'[GNUPG:] TRUST_FULLY', status)
        finally:
            subprocess.run(['/usr/bin/gpgconf', '--homedir', str(verifier), '--kill', 'all'], env=self.env,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=True)


if __name__ == '__main__':
    unittest.main()
