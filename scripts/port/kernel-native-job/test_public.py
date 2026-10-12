# SPDX-License-Identifier: MIT
"""Public projection and inline-bootstrap fixtures; no native execution."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import importlib._bootstrap_external
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import textwrap
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
spec = importlib.util.spec_from_file_location('kernel_job_public', HERE / 'public.py')
public = importlib.util.module_from_spec(spec)
spec.loader.exec_module(public)
WORKFLOW = ROOT / '.github/workflows/native-arm-kernel.yml'
COMMIT, PIN = 'a' * 40, 'b' * 64


def receipt():
    return {'schema_version': 1, 'stage': 'kernel-native-development-job', 'status': 'PASS',
            'phase': 'complete', 'cancelled': False, 'source_commit': COMMIT, 'packet_sha256': PIN,
            'producer': 'PASS', 'kernel_probe': 'PASS', 'baseline': 'PASS', 'candidate': 'PASS',
            'cleanup': 'PASS', 'native_compilation': 'PASS', 'kernel_runtime': 'NOT RUN',
            'hardware': 'NOT RUN', 'installation': 'NOT RUN', 'performance': 'NOT MEASURED',
            'binary_publication': 'NOT RUN', 'selected_for_release': False}


def encoded(value):
    return json.dumps(value).encode()


def bootstrap():
    workflow = WORKFLOW.read_text()
    code = workflow.split("          /usr/bin/python3 -I -B - <<'PY'\n", 1)[1].split('\n          PY', 1)[0]
    namespace = {'__name__': 'bootstrap_fixture'}
    exec(compile(textwrap.dedent(code), str(WORKFLOW), 'exec'), namespace)
    return namespace


class ProjectionTests(unittest.TestCase):
    def test_complete_success_is_only_pass(self):
        self.assertEqual(public.project(encoded(receipt()), COMMIT, PIN, 'success'), receipt())

    def test_failed_cancelled_skipped_outcome_downgrades_stale_pass(self):
        for outcome in ('failure', 'cancelled', 'skipped', ''):
            with self.subTest(outcome=outcome):
                value = public.project(encoded(receipt()), COMMIT, PIN, outcome)
                self.assertEqual(value['status'], 'FAIL')
                self.assertEqual(value['native_compilation'], 'NOT ACCEPTED')
                self.assertEqual(value['cancelled'], outcome == 'cancelled')

    def test_each_acceptance_condition_is_required(self):
        changes = {'phase': 'kernel', 'cancelled': True, 'producer': 'FAIL', 'kernel_probe': 'NOT RUN',
                   'baseline': 'FAIL', 'candidate': 'NOT RUN', 'cleanup': 'FAIL', 'native_compilation': 'NOT ACCEPTED'}
        for key, value in changes.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                record = receipt(); record[key] = value
                public.project(encoded(record), COMMIT, PIN, 'success')

    def test_initial_fail_has_no_fabricated_execution(self):
        value = receipt(); value.update(status='FAIL', phase='preflight', cleanup='FAIL', native_compilation='NOT RUN')
        value.update({key: 'NOT RUN' for key in public.CHILDREN})
        result = public.project(encoded(value), COMMIT, PIN, 'failure')
        self.assertEqual(result, value)

    def test_failed_receipt_keeps_recorded_children_but_revokes_compilation(self):
        value = receipt(); value.update(status='FAIL', phase='cleanup', cleanup='FAIL')
        result = public.project(encoded(value), COMMIT, PIN, 'success')
        self.assertEqual(result['baseline'], 'PASS')
        self.assertEqual(result['native_compilation'], 'NOT ACCEPTED')

    def test_wrong_identity_unknown_keys_and_nonfinite_values_refused(self):
        changes = {'source_commit': 'c' * 40, 'packet_sha256': 'c' * 64, 'error': 'SECRET', 'status': 'SECRET',
                   'hardware': 'PASS', 'installation': 'PASS', 'kernel_runtime': 'PASS',
                   'performance': 'PASS', 'binary_publication': 'PASS', 'selected_for_release': 0,
                   'schema_version': True, 'cancelled': 0, 'stage': 'SECRET', 'producer': 'SECRET'}
        for key, value in changes.items():
            with self.subTest(key=key), self.assertRaises(ValueError):
                record = receipt(); record[key] = value
                public.project(encoded(record), COMMIT, PIN, 'success')

    def test_duplicate_json_and_constants_refused(self):
        data = encoded(receipt())
        for bad in (data[:-1] + b',"status":"PASS"}', b'{"x": NaN}', b'[]'):
            with self.subTest(data=bad), self.assertRaises(ValueError):
                public.project(bad, COMMIT, PIN, 'success')

    def test_size_bound(self):
        with self.assertRaises(ValueError):
            public.project(b' ' * (public.MAX_BYTES + 1), COMMIT, PIN, 'success')

    def test_decode_uses_only_supplied_captured_bytes(self):
        data = encoded(receipt())
        with patch.object(public, 'read', side_effect=AssertionError('second read')):
            self.assertEqual(public.project(data, COMMIT, PIN, 'success')['status'], 'PASS')


class FileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.path = self.base / 'status.json'

    def call(self, outcome='success'):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = public.main(['--status', str(self.path), '--source-commit', COMMIT,
                                '--packet-sha256', PIN, '--native-outcome', outcome])
        return code, output.getvalue()

    def test_missing_receipt_fixed_marker(self):
        self.assertEqual(self.call(), (1, 'KERNEL_PUBLIC_RECEIPT_MISSING\n'))

    def test_valid_receipt_emits_one_bounded_record(self):
        self.path.write_bytes(encoded(receipt()))
        code, data = self.call()
        self.assertEqual(code, 0); self.assertEqual(json.loads(data), receipt())
        self.assertEqual(data.count('\n'), 1); self.assertLess(len(data), public.MAX_BYTES)

    def test_successful_process_with_failed_receipt_returns_failure(self):
        value = receipt(); value['status'] = 'FAIL'
        self.path.write_bytes(encoded(value))
        code, data = self.call(); self.assertEqual(code, 1)
        self.assertEqual(json.loads(data)['status'], 'FAIL')

    def test_unknown_data_never_reaches_output(self):
        self.path.write_text('{"secret":"PRIVATE TOKEN"}')
        self.assertEqual(self.call(), (1, 'KERNEL_PUBLIC_EVIDENCE_REFUSED\n'))

    def test_symlink_hardlink_fifo_and_directory_refused(self):
        target = self.base / 'target'; target.write_bytes(encoded(receipt()))
        for shape in ('symlink', 'hardlink', 'fifo', 'directory'):
            with self.subTest(shape=shape):
                if shape == 'symlink': self.path.symlink_to(target)
                elif shape == 'hardlink': os.link(target, self.path)
                elif shape == 'fifo': os.mkfifo(self.path)
                else: self.path.mkdir()
                self.assertEqual(self.call(), (1, 'KERNEL_PUBLIC_EVIDENCE_REFUSED\n'))
                if self.path.is_dir(): self.path.rmdir()
                else: self.path.unlink()

    def test_parent_symlink_refused(self):
        self.path.write_bytes(encoded(receipt()))
        linked = self.base / 'link'; linked.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(ValueError): public.read(linked / self.path.name)

    def test_file_replacement_after_fd_capture_refused(self):
        self.path.write_bytes(encoded(receipt()))
        original = os.fstat; calls = 0
        def swapped(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.path.unlink(); self.path.write_text('SECRET')
            return original(fd)
        with patch.object(public.os, 'fstat', side_effect=swapped), self.assertRaises(ValueError):
            public.read(self.path)


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'source'; self.root.mkdir()
        self.ns = bootstrap()
        for name in self.ns['REQUIRED']:
            path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / name).read_bytes() if name in
                            {self.ns['PUBLIC'], self.ns['JOB'], 'scripts/port/kernel-native-job/packet.py',
                             'scripts/port/kernel-native-job/runtime.py'} else
                             (name + '\n').encode())
            path.chmod(0o755 if name == self.ns['JOB'] else 0o644)
        self.rows = {name: {'bytes': len((self.root / name).read_bytes()),
                    'sha256': hashlib.sha256((self.root / name).read_bytes()).hexdigest(),
                    'mode': stat.S_IMODE((self.root / name).stat().st_mode)} for name in self.ns['REQUIRED']}
        self.packet = self.root / self.ns['PACKET']
        self.write_packet()
        self.git('init', '-q'); self.git('add', '.')
        self.git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-q', '-m', 'fixture')
        self.commit = self.git('rev-parse', 'HEAD').strip()
        self.environment = patch.dict(os.environ, {'RUNNER_TEMP': self.temp.name, 'GITHUB_WORKFLOW_SHA': self.commit})
        self.environment.start(); self.addCleanup(self.environment.stop)

    def git(self, *args):
        env = {'PATH': '/usr/bin:/bin', 'HOME': self.temp.name, 'GIT_CONFIG_NOSYSTEM': '1',
               'GIT_CONFIG_GLOBAL': '/dev/null', 'LANG': 'C.UTF-8'}
        return subprocess.run(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-C', str(self.root), *args],
                              env=env, capture_output=True, timeout=10, check=True).stdout.decode()

    def write_packet(self, raw=None):
        self.packet.write_bytes(raw if raw is not None else encoded({'schema_version': 1, 'files': self.rows}))
        self.packet.chmod(0o644)
        self.pin = hashlib.sha256(self.packet.read_bytes()).hexdigest()

    def source(self):
        return self.ns['source'](self.root, self.commit, self.pin)

    def test_real_git_blob_mode_and_full_capture_pass(self):
        captured = self.source()
        self.assertEqual(set(captured), self.ns['REQUIRED'])
        self.assertEqual(captured[self.ns['PUBLIC']], (self.root / self.ns['PUBLIC']).read_bytes())

    def test_live_source_byte_and_mode_changes_refused(self):
        path = self.root / self.ns['PUBLIC']; data = path.read_bytes()
        path.write_text('changed')
        with self.assertRaises(ValueError): self.source()
        path.write_bytes(data); path.chmod(0o755)
        with self.assertRaises(ValueError): self.source()

    def test_packet_external_pin_and_committed_blob_required(self):
        pin = self.pin; self.pin = '0' * 64
        with self.assertRaises(ValueError): self.source()
        self.pin = pin; self.write_packet(self.packet.read_bytes() + b'\n')
        with self.assertRaises(ValueError): self.source()

    def test_head_and_workflow_commit_are_required(self):
        self.commit = '0' * 40
        with self.assertRaises(ValueError): self.source()
        self.commit = self.git('rev-parse', 'HEAD').strip()
        with patch.dict(os.environ, {'GITHUB_WORKFLOW_SHA': '0' * 40}), self.assertRaises(ValueError): self.source()

    def test_symlink_and_hardlink_rows_refused(self):
        path = self.root / self.ns['PUBLIC']; data = path.read_bytes()
        other = self.root / 'other'; other.write_bytes(data)
        path.unlink(); path.symlink_to(other)
        with self.assertRaises(ValueError): self.source()
        path.unlink(); os.link(other, path)
        with self.assertRaises(ValueError): self.source()

    def test_packet_schema_path_budget_and_required_rows_refused(self):
        original = self.ns['committed']
        self.ns['committed'] = lambda *args: None
        variants = []
        rows = copy.deepcopy(self.rows); rows.pop(self.ns['JOB']); variants.append(rows)
        for bad in ('../escape', '/absolute', 'a//b', 'a/./b', 'a\\b', 'a\nb'):
            rows = copy.deepcopy(self.rows); rows[bad] = next(iter(rows.values())); variants.append(rows)
        for changes in ({'mode': True}, {'mode': 0o777}, {'bytes': True}, {'bytes': 8 * 1024**2 + 1}, {'sha256': 'invalid'}):
            rows = copy.deepcopy(self.rows); rows[self.ns['PUBLIC']].update(changes); variants.append(rows)
        rows = copy.deepcopy(self.rows); rows.update({f'extra/{n}': next(iter(rows.values())) for n in range(257)}); variants.append(rows)
        try:
            for rows in variants:
                with self.subTest(rows=len(rows)), self.assertRaises(ValueError):
                    self.rows = rows; self.write_packet(); self.source()
        finally:
            self.ns['committed'] = original

    def test_duplicate_packet_json_refused(self):
        self.ns['committed'] = lambda *args: None
        raw = encoded({'schema_version': 1, 'files': self.rows})
        self.write_packet(raw[:-1] + b',"schema_version":1}')
        with self.assertRaises(ValueError): self.source()

    def test_captured_public_bytes_survive_later_path_replacement(self):
        captured = self.source(); path = self.root / self.ns['PUBLIC']
        path.write_text('UNTRUSTED REPLACEMENT')
        self.assertNotIn(b'UNTRUSTED', captured[self.ns['PUBLIC']])

    def test_inline_public_executes_authenticated_capture_end_to_end(self):
        target = self.root / 'artifacts/kernel-native-job/job-123-1/public/status.json'
        target.parent.mkdir(parents=True)
        value = receipt(); value.update(source_commit=self.commit, packet_sha256=self.pin)
        target.write_bytes(encoded(value))
        environment = {'KERNEL_BOOTSTRAP_MODE': 'public', 'GITHUB_WORKSPACE': str(self.root),
                       'GITHUB_SHA': self.commit, 'KERNEL_JOB_PACKET_SHA256': self.pin,
                       'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1', 'KERNEL_NATIVE_OUTCOME': 'success'}
        output = io.StringIO()
        with patch.dict(os.environ, environment), contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as stop:
            self.ns['main']()
        self.assertEqual(stop.exception.code, 0)
        self.assertEqual(json.loads(output.getvalue()), value)

    def snapshot(self):
        modes = {}
        captured = self.ns['source'](self.root, self.commit, self.pin, modes)
        return self.ns['clean_snapshot'](self.root, '123', '1', captured, modes)

    def test_timestamp_valid_root_caches_cannot_execute_in_clean_bootstrap(self):
        marker = self.root / 'malicious-cache-executed'
        cache_bytes = {}
        for name in ('packet', 'runtime', 'public'):
            source = self.root / f'scripts/port/kernel-native-job/{name}.py'
            info = source.stat()
            code = compile(f'from pathlib import Path\nPath({str(marker)!r}).write_text("EXECUTED")\nraise SystemExit(97)\n', str(source), 'exec')
            data = bytes(importlib._bootstrap_external._code_to_timestamp_pyc(code, int(info.st_mtime), info.st_size))
            cache = Path(importlib.util.cache_from_source(str(source)))
            cache.parent.mkdir(exist_ok=True); cache.write_bytes(data); cache_bytes[cache] = data
        # This proves -I/-B alone would still execute the timestamp-valid root cache.
        poisoned = subprocess.run(['/usr/bin/python3', '-I', '-B', str(self.root / self.ns['JOB']), '--help'],
                                  capture_output=True, timeout=10)
        self.assertEqual(poisoned.returncode, 97); self.assertTrue(marker.exists()); marker.unlink()
        extension = self.root / 'scripts/port/kernel-native-job' / ('packet' + importlib.machinery.EXTENSION_SUFFIXES[0])
        extension.write_bytes(b'UNLISTED EXTENSION')
        target = self.snapshot()
        clean = subprocess.run(['/usr/bin/python3', '-I', '-B', str(target / self.ns['JOB']), '--help'],
                               capture_output=True, timeout=10)
        self.assertEqual(clean.returncode, 0, clean.stderr.decode())
        self.assertIn(b'--execute-native', clean.stdout)
        self.assertFalse(marker.exists())
        self.assertEqual({str(path.relative_to(target)) for path in target.rglob('*') if path.is_file()}, set(self.rows))
        self.assertFalse(any(path.name == '__pycache__' for path in target.rglob('*')))
        self.assertEqual(extension.read_bytes(), b'UNLISTED EXTENSION')
        for cache, data in cache_bytes.items(): self.assertEqual(cache.read_bytes(), data)
        for name, row in self.rows.items():
            self.assertEqual(hashlib.sha256((target / name).read_bytes()).hexdigest(), row['sha256'])
            self.assertEqual(stat.S_IMODE((target / name).stat().st_mode), row['mode'])

    def test_clean_snapshot_refuses_existing_or_linked_destination(self):
        parent = self.root / 'artifacts/kernel-native-job'
        parent.mkdir(parents=True)
        path = parent / 'bootstrap-123-1'; path.mkdir()
        with self.assertRaises(FileExistsError): self.snapshot()
        path.rmdir(); path.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(FileExistsError): self.snapshot()

    def test_clean_snapshot_refuses_linked_parent(self):
        (self.root / 'artifacts').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError): self.snapshot()

    def test_aggregate_packet_bytes_are_bounded(self):
        payload = b'x' * (8 * 1024**2)
        rows = copy.deepcopy(self.rows)
        row = {'bytes': len(payload), 'mode': 0o644, 'sha256': hashlib.sha256(payload).hexdigest()}
        rows.update({f'large/{n}': row for n in range(5)})
        packet = encoded({'schema_version': 1, 'files': rows})
        self.pin = hashlib.sha256(packet).hexdigest()
        original = self.ns['read']
        def read(path, *args):
            if path == self.packet: return packet
            if path.parent.name == 'large': return payload
            return original(path, *args)
        with patch.dict(self.ns, {'read': read, 'committed': lambda *args: None}), self.assertRaises(ValueError):
            self.source()

    def test_workflow_finite_manual_shape_and_reserves(self):
        text = WORKFLOW.read_text()
        for expected in ('workflow_dispatch:', "github.repository == 'Gabriel-Kahen/cachy-asahi'", 'github.event.repository.private == false',
                         'runs-on: ubuntu-24.04-arm', 'contents: read', 'group: native-arm-build', 'cancel-in-progress: false',
                         'persist-credentials: false', '--deadline 20760', 'if: always()', 'run: *trusted-bootstrap',
                         'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1'):
            self.assertIn(expected, text)
        for forbidden in ('upload-artifact', 'actions/cache', 'sudo', 'apt-get', 'docker system prune', 'schedule:', 'pull_request:', 'push:'):
            self.assertNotIn(forbidden, text)
        self.assertEqual(5 + 5 + 346 + 3 + 1, 360)
        self.assertNotIn('default:', text)
        self.assertIn("exec(compile(captured[PUBLIC]", text)
        self.assertIn('"$KERNEL_JOB_BOOTSTRAP_SOURCE/scripts/port/kernel-native-job/job.py"', text)
        self.assertIn("stream.write('KERNEL_JOB_BOOTSTRAP_SOURCE='", text)


if __name__ == '__main__':
    unittest.main()
