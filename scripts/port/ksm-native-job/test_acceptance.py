# SPDX-License-Identifier: MIT
"""Temporary Git fixtures only; no Docker, network or package execution."""
import hashlib
import importlib.util
import json
import marshal
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from types import ModuleType

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('ksm_acceptance_tests_subject', HERE / 'acceptance.py')
acceptance = importlib.util.module_from_spec(spec)
exec(compile((HERE / 'acceptance.py').read_bytes(), str(HERE / 'acceptance.py'), 'exec'), acceptance.__dict__)


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / 'repo'; self.root.mkdir()
        self.workflow = '.github/workflows/native-ksm.yml'
        self.helper = 'scripts/helper.py'
        self.required = {self.workflow, self.helper}
        self.sources = {self.workflow: b'name: reviewed finite fixture\n', self.helper: b"MARKER = 'TRUSTED'\n"}
        self.env = {'PATH': '/usr/bin:/bin', 'XDG_CONFIG_HOME': str(self.base), 'GIT_CONFIG_NOSYSTEM': '1',
                    'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
                    'GIT_AUTHOR_NAME': 'Fixture', 'GIT_AUTHOR_EMAIL': 'fixture@invalid.invalid',
                    'GIT_COMMITTER_NAME': 'Fixture', 'GIT_COMMITTER_EMAIL': 'fixture@invalid.invalid'}
        self.fixture_git('init', '-q')
        for name, data in self.sources.items():
            path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data); path.chmod(0o644)
        self.fixture_git('add', '--', *sorted(self.required))
        self.fixture_git('-c', 'core.hooksPath=/dev/null', 'commit', '-q', '-m', 'fixture')
        self.commit = self.fixture_git('rev-parse', 'HEAD').strip().decode()
        self.job = {'GITHUB_SHA': self.commit, 'GITHUB_WORKFLOW_SHA': self.commit}
        self.packet_relative = 'packet.json'
        self.packet = self.root / self.packet_relative
        self.packet_data = {'schema_version': 1, 'files': {name: {'sha256': acceptance.digest(data),
                            'size_bytes': len(data), 'mode': '0644'} for name, data in self.sources.items()}}
        self.pin = self.write_packet()
        self.commit_packet()

    def fixture_git(self, *args):
        return subprocess.run(['/usr/bin/git', '-C', str(self.root), *args], env=self.env,
                              check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10).stdout

    def write_packet(self):
        self.packet.write_text(json.dumps(self.packet_data))
        return acceptance.digest(self.packet.read_bytes())

    def commit_packet(self):
        self.fixture_git('add', '--', self.packet_relative)
        self.fixture_git('commit', '-q', '-m', 'reviewed packet fixture')
        self.commit = self.fixture_git('rev-parse', 'HEAD').strip().decode()
        self.job = {'GITHUB_SHA': self.commit, 'GITHUB_WORKFLOW_SHA': self.commit}

    def capture(self, **changes):
        args = {'root': self.root, 'packet_path': self.packet, 'packet_sha256': self.pin,
                'expected_paths': self.required, 'workflow_path': self.workflow,
                'expected_commit': self.commit, 'environ': self.job, 'packet_relative_path': self.packet_relative}
        return acceptance.capture(**(args | changes))

    def test_exact_packet_checkout_and_committed_blobs_are_captured(self):
        snapshot = self.capture()
        self.assertEqual(dict(snapshot.files), self.sources)
        self.assertFalse(snapshot.provenance['hardware_accepted'])
        self.assertFalse(snapshot.provenance['native_lifecycle_accepted'])
        with self.assertRaises(TypeError): snapshot.files[self.helper] = b'foreign'
        self.assertEqual(self.fixture_git('status', '--porcelain'), b'')

    def test_executable_mode_is_bound_to_checkout_and_commit(self):
        path = self.root / self.helper; path.chmod(0o755)
        self.fixture_git('add', '--', self.helper); self.fixture_git('commit', '-q', '-m', 'executable fixture')
        self.commit = self.fixture_git('rev-parse', 'HEAD').strip().decode()
        self.job = {'GITHUB_SHA': self.commit, 'GITHUB_WORKFLOW_SHA': self.commit}
        self.packet_data['files'][self.helper]['mode'] = '0755'; self.pin = self.write_packet()
        self.commit_packet()
        self.assertEqual(self.capture().files[self.helper], self.sources[self.helper])

    def test_external_packet_checksum_required_before_git(self):
        with patch.object(acceptance, 'git') as git, self.assertRaisesRegex(ValueError, 'packet checksum/mode mismatch'):
            self.capture(packet_sha256='0' * 64)
        git.assert_not_called()

    def test_unknown_missing_and_bool_schema_refused(self):
        for mutation in (lambda p: p.update(schema_version=True), lambda p: p.update(unknown=1),
                         lambda p: p['files'].pop(self.helper), lambda p: p['files'].update({'extra': p['files'][self.helper]})):
            original = json.loads(json.dumps(self.packet_data)); mutation(self.packet_data)
            self.pin = self.write_packet()
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, 'exact packet schema/source set'):
                self.capture()
            self.packet_data = original

    def test_duplicate_json_fields_and_wrong_pin_types_refused(self):
        data = b'{"schema_version":1,"schema_version":1,"files":{}}'; self.packet.write_bytes(data)
        with self.assertRaisesRegex(ValueError, 'duplicate packet field'): self.capture(packet_sha256=acceptance.digest(data))
        for field, value in (('size_bytes', True), ('mode', ['0644']), ('sha256', 'bad')):
            self.packet_data['files'][self.helper][field] = value; self.pin = self.write_packet()
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'source pin schema'):
                self.capture()
            self.packet_data['files'][self.helper] = {'size_bytes': len(self.sources[self.helper]), 'mode': '0644', 'sha256': acceptance.digest(self.sources[self.helper])}

    def test_path_escape_absolute_empty_and_workflow_not_in_packet_refused(self):
        for name in ('../escape', '/absolute', 'scripts//helper.py', './helper.py', 'scripts/../helper.py', 'bad\nname'):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'unsafe packet path'):
                self.capture(expected_paths={name, self.workflow})
        with self.assertRaisesRegex(ValueError, 'reviewed workflow'): self.capture(workflow_path='.github/workflows/other.yml')

    def test_symlink_leaf_ancestor_hardlink_and_fifo_refused(self):
        original = self.root / self.helper
        saved = self.base / 'saved.py'; original.rename(saved); original.symlink_to(saved)
        with self.assertRaises(OSError): self.capture()
        original.unlink(); os.link(saved, original)
        with self.assertRaisesRegex(ValueError, 'unsafe or oversized'): self.capture()
        original.unlink(); os.mkfifo(original)
        with self.assertRaisesRegex(ValueError, 'unsafe or oversized'): self.capture()
        original.unlink(); saved.rename(original)
        directory = self.root / 'scripts'; directory.rename(self.base / 'saved-scripts'); directory.symlink_to(self.base / 'saved-scripts')
        with self.assertRaises(OSError): self.capture()

    def test_actual_size_hash_and_mode_drift_refused(self):
        path = self.root / self.helper
        for data, mode in ((b'longer foreign data', 0o644), (b"MARKER = 'UNSAFE!'\n", 0o644), (self.sources[self.helper], 0o755)):
            path.write_bytes(data); path.chmod(mode)
            with self.subTest(data=data, mode=mode), self.assertRaises(ValueError): self.capture()

    def test_repinning_uncommitted_source_cannot_pass_git_binding(self):
        data = b"MARKER = 'UNSAFE!'\n"; (self.root / self.helper).write_bytes(data)
        self.packet_data['files'][self.helper].update(sha256=acceptance.digest(data), size_bytes=len(data)); self.pin = self.write_packet()
        self.commit_packet()
        with self.assertRaisesRegex(ValueError, 'committed source bytes mismatch'): self.capture()

    def test_repinning_uncommitted_mode_cannot_pass_git_binding(self):
        (self.root / self.helper).chmod(0o755)
        self.packet_data['files'][self.helper]['mode'] = '0755'; self.pin = self.write_packet()
        self.commit_packet()
        with self.assertRaisesRegex(ValueError, 'committed source mode mismatch'): self.capture()

    def test_head_job_and_workflow_commit_must_all_match(self):
        with self.assertRaisesRegex(ValueError, 'job/workflow commit'): self.capture(environ=self.job | {'GITHUB_WORKFLOW_SHA': '0' * 40})
        with self.assertRaisesRegex(ValueError, 'checkout HEAD mismatch'):
            self.capture(expected_commit='0' * 40, environ={'GITHUB_SHA': '0' * 40, 'GITHUB_WORKFLOW_SHA': '0' * 40})

    def test_packet_outside_checkout_or_wrong_mode_refused(self):
        other = self.base / 'outside-packet.json'; other.write_bytes(self.packet.read_bytes())
        with self.assertRaisesRegex(ValueError, 'reviewed checkout path'): self.capture(packet_path=other)
        self.packet.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'packet checksum/mode mismatch'): self.capture()

    def test_uncommitted_packet_cannot_pass_updated_external_digest(self):
        self.packet.write_bytes(self.packet.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'committed source bytes mismatch: packet.json'):
            self.capture(packet_sha256=acceptance.digest(self.packet.read_bytes()))

    def test_per_file_and_aggregate_budgets_refuse_before_source_read(self):
        with patch.object(acceptance, 'TOTAL_LIMIT', self.packet.stat().st_size), self.assertRaisesRegex(ValueError, 'aggregate source bound'):
            self.capture()
        path = self.base / 'oversized'; path.write_bytes(b'12345')
        with patch.object(acceptance, 'FILE_LIMIT', 4), self.assertRaisesRegex(ValueError, 'unsafe or oversized'):
            acceptance.captured_file(path)

    def test_capture_detects_mutation_of_same_open_file(self):
        original_read = os.read; changed = False
        def mutate(fd, size):
            nonlocal changed
            block = original_read(fd, size)
            if not changed:
                changed = True
                with (self.root / self.helper).open('ab') as stream: stream.write(b'foreign')
            return block
        with patch.object(acceptance.os, 'read', side_effect=mutate), self.assertRaisesRegex(ValueError, 'source read bound'):
            acceptance.captured_file(self.root / self.helper)

    def test_compiled_snapshot_ignores_replaced_source_and_valid_foreign_pyc(self):
        snapshot = self.capture(); path = self.root / self.helper; foreign = b"MARKER = 'UNSAFE!'\n"
        info = path.stat(); cache = Path(importlib.util.cache_from_source(str(path))); cache.parent.mkdir()
        cache.write_bytes(importlib.util.MAGIC_NUMBER + struct.pack('<III', 0, int(info.st_mtime), info.st_size)
                          + marshal.dumps(compile(foreign, str(path), 'exec')))
        self.assertEqual(snapshot.module(self.helper, 'captured_helper').MARKER, 'TRUSTED')
        path.write_bytes(foreign)
        self.assertEqual(snapshot.module(self.helper, 'captured_helper').MARKER, 'TRUSTED')

    def test_module_imports_need_explicit_bound_modules_without_path_search(self):
        data = b'import json\nVALUE = json.loads("1")\n'
        snapshot = acceptance.Snapshot(self.root, {self.helper: data}, {})
        with self.assertRaisesRegex(ValueError, 'unbound transitive import'): snapshot.module(self.helper, 'importing')
        self.assertEqual(snapshot.module(self.helper, 'importing', imports={'json': json}).VALUE, 1)
        relative = acceptance.Snapshot(self.root, {self.helper: b'from . import other\n'}, {})
        with self.assertRaisesRegex(ValueError, 'unbound transitive import'): relative.module(self.helper, 'relative')
        dynamic = acceptance.Snapshot(self.root, {self.helper: b'def later(): return __import__("foreign_local")\n'}, {})
        with self.assertRaisesRegex(ValueError, 'unbound transitive import'): dynamic.module(self.helper, 'dynamic').later()

    def test_transitive_submodule_identity_is_bound_and_wildcards_refused(self):
        parent, child, foreign = ModuleType('parent'), ModuleType('parent.child'), ModuleType('foreign')
        child.VALUE = 7; parent.child = child
        snapshot = acceptance.Snapshot(self.root, {self.helper: b'import parent.child\nVALUE = parent.child.VALUE\n'}, {})
        imports = {'parent': parent, 'parent.child': child}
        self.assertEqual(snapshot.module(self.helper, 'child_consumer', imports=imports).VALUE, 7)
        parent.child = foreign
        with self.assertRaisesRegex(ValueError, 'unbound transitive submodule'):
            snapshot.module(self.helper, 'child_consumer', imports=imports)
        snapshot = acceptance.Snapshot(self.root, {self.helper: b'from parent import child\n'}, {})
        with self.assertRaisesRegex(ValueError, 'unbound transitive submodule'):
            snapshot.module(self.helper, 'child_consumer', imports={'parent': parent})
        snapshot = acceptance.Snapshot(self.root, {self.helper: b'from json import *\n'}, {})
        with self.assertRaisesRegex(ValueError, 'wildcard imports refused'):
            snapshot.module(self.helper, 'wildcard', imports={'json': json})

    def test_git_environment_is_private_and_hooks_fsmonitor_locks_disabled(self):
        original = subprocess.Popen; calls = []
        defaults = self.base / 'git'; defaults.mkdir()
        (defaults / 'config').write_text('[user]\n name = default-config-marker\n')
        def spawn(command, **kwargs):
            calls.append((command, kwargs['env']))
            return original(command, **kwargs)
        with patch.object(acceptance.subprocess, 'Popen', side_effect=spawn), patch.dict(os.environ, {
                'GIT_DIR': '/wrong', 'HOME': '/wrong', 'XDG_CONFIG_HOME': str(self.base),
                'GIT_CONFIG_GLOBAL': str(defaults / 'config'), 'GIT_CONFIG_SYSTEM': str(defaults / 'config')}):
            self.capture()
            observed = acceptance.git(self.root, self.base, ['config', '--list', '--show-origin'])
        self.assertNotIn(b'default-config-marker', observed)
        self.assertEqual(self.fixture_git('status', '--porcelain'), b'')
        self.assertTrue(calls)
        for command, env in calls:
            self.assertIn('core.hooksPath=/dev/null', command); self.assertIn('core.fsmonitor=false', command)
            self.assertIn('--no-optional-locks', command); self.assertEqual(env['GIT_CONFIG_GLOBAL'], '/dev/null')
            self.assertNotIn('GIT_DIR', env); self.assertNotIn('HOME', env)
            self.assertEqual(env['GIT_CONFIG_SYSTEM'], '/dev/null')
            self.assertNotEqual(env['XDG_CONFIG_HOME'], '/wrong')

    def test_git_output_and_timeout_are_enforced_during_capture(self):
        original = subprocess.Popen; children = []
        def spawn(code):
            def run(command, **kwargs):
                child = original([sys.executable, '-I', '-B', '-c', code], **kwargs); children.append(child); return child
            return run
        with patch.object(acceptance, 'GIT_LIMIT', 10), patch.object(acceptance.subprocess, 'Popen', side_effect=spawn('print("x"*100)')):
            with self.assertRaisesRegex(ValueError, 'Git output bound'): acceptance.git(self.root, self.base, ['rev-parse', 'HEAD'])
        with patch.object(acceptance, 'GIT_SECONDS', .05), patch.object(acceptance.subprocess, 'Popen', side_effect=spawn('import time;time.sleep(1)')):
            with self.assertRaisesRegex(ValueError, 'Git deadline'): acceptance.git(self.root, self.base, ['rev-parse', 'HEAD'])
        self.assertTrue(all(p.poll() is not None for p in children))

    def test_aggregate_deadline_rejects_late_source_and_git_completion(self):
        current = [0.0]
        original_capture, original_git = acceptance.captured_file, acceptance.git
        def late_source(path, **kwargs):
            result = original_capture(path, **kwargs)
            current[0] = 181
            return result
        with patch.object(acceptance.time, 'monotonic', side_effect=lambda: current[0]), \
             patch.object(acceptance, 'captured_file', side_effect=late_source), patch.object(acceptance, 'git') as git:
            with self.assertRaisesRegex(ValueError, 'aggregate deadline'): self.capture()
            git.assert_not_called()
        current[0] = 0
        def late_git(root, home, args, **kwargs):
            self.assertEqual(kwargs['deadline'], 180)
            result = original_git(root, home, args, **kwargs)
            current[0] = 181
            return result
        with patch.object(acceptance.time, 'monotonic', side_effect=lambda: current[0]), \
             patch.object(acceptance, 'git', side_effect=late_git) as git:
            with self.assertRaisesRegex(ValueError, 'aggregate deadline'): self.capture()
            self.assertEqual(git.call_count, 1)

    def test_caller_cutoff_is_not_renewed_for_late_source_or_git(self):
        current = [179.0]
        read, git = acceptance.captured_file, acceptance.git
        observed = []
        def late_read(path, **kwargs):
            observed.append(kwargs['deadline'])
            value = read(path, **kwargs)
            current[0] = 181.0
            return value
        with patch.object(acceptance.time, 'monotonic', side_effect=lambda: current[0]), \
             patch.object(acceptance, 'captured_file', side_effect=late_read), patch.object(acceptance, 'git') as query:
            with self.assertRaisesRegex(ValueError, 'aggregate deadline'): self.capture(deadline=180.0)
            query.assert_not_called()
        self.assertEqual(observed, [180.0])
        current[0] = 179.0
        def late_git(root, home, arguments, **kwargs):
            self.assertEqual(kwargs['deadline'], 180.0)
            value = git(root, home, arguments, **kwargs)
            current[0] = 181.0
            return value
        with patch.object(acceptance.time, 'monotonic', side_effect=lambda: current[0]), \
             patch.object(acceptance, 'git', side_effect=late_git) as query:
            with self.assertRaisesRegex(ValueError, 'aggregate deadline'): self.capture(deadline=180.0)
            self.assertEqual(query.call_count, 1)

    def test_finite_caller_cutoff_and_expired_preflight_do_not_read_or_launch(self):
        for cutoff in (True, False, '180', float('nan'), float('inf'), -float('inf'), [], {}):
            with self.subTest(cutoff=cutoff), patch.object(acceptance, 'captured_file') as read, \
                 patch.object(acceptance, 'git') as query:
                with self.assertRaisesRegex(ValueError, 'finite acceptance deadline'): self.capture(deadline=cutoff)
                read.assert_not_called(); query.assert_not_called()
        with patch.object(acceptance.time, 'monotonic', return_value=180.0), \
             patch.object(acceptance, 'captured_file') as read, patch.object(acceptance, 'git') as query:
            with self.assertRaisesRegex(ValueError, 'aggregate deadline'): self.capture(deadline=180.0)
            read.assert_not_called(); query.assert_not_called()
        with patch.object(acceptance.time, 'monotonic', return_value=179.0):
            self.assertEqual(dict(self.capture(deadline=180.0).files), self.sources)

    def cancelled_child(self, signum, *, before_assignment=False, second_signals=False):
        original_spawn, original_kill = subprocess.Popen, os.killpg
        prior = {sig: signal.getsignal(sig) for sig in acceptance.SIGNALS}
        prior_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        children, timers = [], []
        marker = self.base / ('mask-' + str(signum))
        code = ('import json,signal,time\n'
                f'open({str(marker)!r},"w").write(json.dumps([int(s) for s in signal.pthread_sigmask(signal.SIG_BLOCK,[])]))\n'
                'time.sleep(5)\n')
        def spawn(command, **kwargs):
            child = original_spawn([sys.executable, '-I', '-B', '-c', code], **kwargs)
            children.append(child)
            deadline = time.monotonic() + 1
            while not marker.exists() and time.monotonic() < deadline: time.sleep(.005)
            self.assertTrue(marker.exists(), 'private child failed to start')
            self.assertFalse(set(json.loads(marker.read_text())) & {int(s) for s in acceptance.SIGNALS})
            if before_assignment:
                os.kill(os.getpid(), signum)
                self.assertIn(signum, signal.sigpending())  # parent still blocks through PID assignment
            else:
                timer = threading.Timer(.02, lambda: os.kill(os.getpid(), signum))
                timer.start(); timers.append(timer)
            return child
        def dispose(pid, requested):
            self.assertIn(pid, {p.pid for p in children})
            if second_signals:
                for sig in acceptance.SIGNALS: os.kill(os.getpid(), sig)
            return original_kill(pid, requested)
        result = None
        try:
            with patch.object(acceptance.subprocess, 'Popen', side_effect=spawn), \
                 patch.object(acceptance.os, 'killpg', side_effect=dispose):
                with self.assertRaises(acceptance.Cancelled): result = self.capture()
            self.assertIsNone(result)
            for child in children:
                self.assertIsNotNone(child.poll())
                with self.assertRaises(ProcessLookupError): os.kill(child.pid, 0)
            self.assertEqual({sig: signal.getsignal(sig) for sig in acceptance.SIGNALS}, prior)
            self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), prior_mask)
            self.assertIsNone(acceptance._ACTIVE)
        finally:
            for timer in timers: timer.join(timeout=1)
            for child in children:
                if child.poll() is None: original_kill(child.pid, signal.SIGKILL); child.wait(timeout=1)
            for sig, handler in prior.items(): signal.signal(sig, handler)
            signal.pthread_sigmask(signal.SIG_SETMASK, prior_mask)

    def test_actual_sigint_and_sigterm_cancel_blocking_git_and_restore_caller(self):
        for sig in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=sig): self.cancelled_child(sig)

    def test_actual_signals_between_spawn_and_pid_assignment_cannot_lose_child(self):
        for sig in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=sig): self.cancelled_child(sig, before_assignment=True)

    def test_second_signals_during_owned_disposal_are_deferred(self):
        self.cancelled_child(signal.SIGTERM, second_signals=True)

    def test_cancellation_remembered_during_capture_cleanup_prevents_git_spawn(self):
        original_close = os.close; injected = False
        prior = {sig: signal.getsignal(sig) for sig in acceptance.SIGNALS}
        def close(fd):
            nonlocal injected
            original_close(fd)
            state = acceptance._ACTIVE
            if not injected and state is not None and state.deferrals:
                injected = True; os.kill(os.getpid(), signal.SIGTERM)
        with patch.object(acceptance.os, 'close', side_effect=close), patch.object(acceptance, 'git') as git:
            with self.assertRaises(acceptance.Cancelled): self.capture()
            git.assert_not_called()
        self.assertTrue(injected)
        self.assertEqual({sig: signal.getsignal(sig) for sig in acceptance.SIGNALS}, prior)


if __name__ == '__main__':
    unittest.main()
