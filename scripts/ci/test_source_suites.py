"""Mocked runner tests: never invoke Docker, GPG, package tools or source suites."""
import importlib.util
import hashlib
import json
import os
import signal
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('source_suites', Path(__file__).with_name('source_suites.py'))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


def observed():
    record = {'arch': 'aarch64', 'uid': 1000, 'docker_marker': True, 'interfaces': ['lo'],
            'sockets': [], 'capabilities': {name: 0 for name in runner.CAPS}, 'no_new_privs': 1,
            'unexpected_devices': [], 'null_masks': {},
            'runtime_files': {path: {'regular': True, 'uid': 0, 'mode': 0o644} for path in runner.RUNTIME_FILES},
            'source': '/source', 'output': '/out', 'paths_safe': True,
            'home': '/tmp/home', 'home_safe': True,
            'mounts': {'/': {'fs': 'overlay', 'options': ['ro']},
                       '/source': {'fs': 'ext4', 'options': ['ro']},
                       '/out': {'fs': 'ext4', 'options': ['rw']},
                       '/tmp': {'fs': 'tmpfs', 'options': ['rw', 'nosuid', 'nodev']}}}
    for path, (kinds, flags) in runner.STANDARD_TYPES.items():
        record['mounts'][path] = {'fs': sorted(kinds)[0], 'options': sorted(flags)}
    for path in runner.RUNTIME_FILES:
        record['mounts'][path] = {'fs': 'ext4', 'options': ['rw']}
    return record


class GuardTests(unittest.TestCase):
    def test_supported_disposable_native_boundary(self):
        runner.guard(observed())

    def test_host_root_privilege_network_socket_or_home_drift_rejected(self):
        for key, value in [('arch', 'x86_64'), ('uid', 0), ('docker_marker', False),
                           ('interfaces', ['eth0', 'lo']), ('sockets', ['/run/docker.sock']),
                           ('no_new_privs', 0), ('source', '/home/gabe/project'),
                           ('output', '/tmp/output'), ('paths_safe', False),
                           ('home', '/home/alarm'), ('home', '/tmp/../root'), ('home_safe', False)]:
            record = observed()
            record[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                runner.guard(record)

    def test_all_capability_sets_must_be_zero(self):
        for name in runner.CAPS:
            record = observed()
            record['capabilities'][name] = 1
            with self.subTest(name=name), self.assertRaises(ValueError):
                runner.guard(record)

    def test_rw_source_ro_output_rw_root_or_nonprivate_tmp_rejected(self):
        for point, field, value in [('/', 'options', ['rw']), ('/source', 'options', ['rw']),
                                    ('/out', 'options', ['ro']), ('/tmp', 'fs', 'ext4')]:
            record = observed()
            record['mounts'][point][field] = value
            with self.subTest(point=point), self.assertRaises(ValueError):
                runner.guard(record)

    def test_extra_home_socket_or_unrecognized_device_mount_rejected(self):
        for point in ('/home/gabe', '/root', '/run/docker.sock', '/dev/custom-host-home'):
            record = observed()
            record['mounts'][point] = {'fs': 'ext4', 'options': ['ro']}
            with self.subTest(point=point), self.assertRaises(ValueError):
                runner.guard(record)

    def test_mount_escape_decoding_and_duplicates(self):
        row = '31 20 8:1 / /source\\040space ro,relatime - ext4 /dev/a rw\n'
        self.assertEqual(runner.mount_table(row)['/source space']['options'], ['ro', 'relatime'])
        with self.assertRaises(ValueError):
            runner.mount_table(row + row)

    def test_writable_ext4_at_standard_kernel_targets_refused(self):
        for path in ('/proc', '/sys', '/dev', '/dev/pts', '/dev/shm', '/sys/fs/cgroup'):
            record = observed()
            record['mounts'][path] = {'fs': 'ext4', 'options': ['rw', 'nosuid', 'nodev', 'noexec']}
            with self.subTest(path=path), self.assertRaises(ValueError):
                runner.guard(record)

    def test_standard_mount_security_flags_required(self):
        for path, (_, flags) in runner.STANDARD_TYPES.items():
            for flag in flags:
                record = observed()
                record['mounts'][path]['options'].remove(flag)
                with self.subTest(path=path, flag=flag), self.assertRaises(ValueError):
                    runner.guard(record)

    def test_renamed_or_nonnull_kernel_masks_refused(self):
        for point in ('/proc/private-home', '/sys/private-home', '/dev/private-home'):
            record = observed()
            record['mounts'][point] = {'fs': 'tmpfs', 'options': ['ro']}
            with self.subTest(point=point), self.assertRaises(ValueError):
                runner.guard(record)
        record = observed()
        record['mounts']['/proc/kcore'] = {'fs': 'tmpfs', 'options': ['rw']}
        with self.assertRaises(ValueError):
            runner.guard(record)
        record['null_masks']['/proc/kcore'] = True
        runner.guard(record)

    def test_device_and_socket_exposure_refused_before_commands(self):
        for key, value in [('unexpected_devices', ['/dev/dri/card0']), ('sockets', ['/run/private.sock'])]:
            record = observed()
            record[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                runner.guard(record)

    def test_untrusted_runtime_files_refused(self):
        for field, value in [('regular', False), ('uid', 1000), ('mode', 0o666)]:
            record = observed()
            record['runtime_files']['/etc/hosts'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                runner.guard(record)

    def test_runtime_scan_distinguishes_null_from_gpu_and_socket(self):
        records = {'/dev/null': SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=os.makedev(1, 3)),
                   '/dev/gpu': SimpleNamespace(st_mode=stat.S_IFCHR, st_rdev=os.makedev(226, 0)),
                   '/run/private.sock': SimpleNamespace(st_mode=stat.S_IFSOCK)}
        def walk(root, **options):
            self.assertFalse(options['followlinks'])
            return [('/dev', [], ['null', 'gpu'])] if root == '/dev' else ([('/run', [], ['private.sock'])] if root == '/run' else [])
        with patch.object(runner.os, 'walk', side_effect=walk), patch.object(runner.Path, 'lstat', lambda path: records[str(path)]), patch.object(runner.Path, 'exists', return_value=False):
            devices, sockets = runner.runtime_exposure()
        self.assertEqual(devices, ['/dev/gpu'])
        self.assertEqual(sockets, ['/run/private.sock'])


class SummaryTests(unittest.TestCase):
    def test_counts_and_skips_reported_separately(self):
        report = runner.unittest_counts('test_a ... skipped\nRan 12 tests in 0.01s\n\nOK (skipped=2)\n')
        self.assertEqual(report, {'tests': 12, 'skipped': 2, 'unittest_status': 'OK'})

    def test_last_outer_summary_used(self):
        text = 'Ran 2 tests in 0.01s\nOK\nRan 7 tests in 0.3s\nFAILED (failures=1, skipped=3)\n'
        self.assertEqual(runner.unittest_counts(text), {'tests': 7, 'skipped': 3, 'unittest_status': 'FAILED'})

    def test_incomplete_summary_rejected(self):
        for text in ('PASS', 'OK\n', 'Ran 5 tests in 0.1s\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                runner.unittest_counts(text)


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / 'source-check-5.txt'
        self.output = self.root / 'out'; self.output.mkdir()

    def exporter(self):
        spec = importlib.util.spec_from_file_location('projection_exporter', Path(__file__).with_name('integration_export.py'))
        value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
        return value

    def test_control_invalid_utf8_and_abort_diagnostics_preserved_with_raw_receipt(self):
        data = b'\x1b[31mERROR: abort(-6)\x1b[0m\nNUL:\0 bad:\xff\xc3( del:\x7f c1:\xc2\x85\r\\x00\tend\n'
        self.log.write_bytes(data)
        runner.desktop_projection(self.log, self.output)
        text = (self.output / 'desktop-source-check-5.txt').read_text()
        self.assertEqual(text, '\\x1b[31mERROR: abort(-6)\\x1b[0m\nNUL:\\x00 bad:\\xff\\xc3( del:\\x7f c1:\\u0085\\x0d\\\\x00\tend\n')
        self.assertFalse(any(ord(char) < 32 and char not in '\n\t' for char in text))
        metadata = json.loads((self.output / 'desktop-source-check-5.projection.json').read_text())
        self.assertEqual(metadata['raw_sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(metadata['raw_bytes'], len(data))
        self.assertEqual(metadata['projected_sha256'], hashlib.sha256(text.encode()).hexdigest())
        self.assertFalse(metadata['raw_bytes_exported'])
        public = self.root / 'public'
        result = self.exporter().export_evidence(self.output, public)
        self.assertEqual(result['evidence_export'], 'PASS')
        self.assertEqual((public / 'desktop-source-check-5.txt').read_text(), text)
        self.assertFalse(any(path.read_bytes() == data for path in public.iterdir()))

    def test_private_markers_refused_before_public_projection_or_raw_hash(self):
        for data in (b'-----BEGIN PGP PRIVATE KEY BLOCK-----\nPRIVATE_FIXTURE',
                     b'-----BEGIN PGP PRI\x1b[31mVATE KEY BLOCK-----',
                     b'password=PRIVATE_FIXTURE', b'-----BEGIN RSA PRI\0VATE KEY-----',
                     '-----BEGIN RSA PRI\u200bVATE KEY-----'.encode()):
            self.log.write_bytes(data)
            with self.subTest(data=data), self.assertRaises(ValueError):
                runner.desktop_projection(self.log, self.output)
            self.assertEqual(list(self.output.iterdir()), [])
        self.log.write_bytes(b'-----BEGIN PGP PRIVATE KEY BLOCK-----')
        # Generic exporter is independently unchanged and continues to refuse
        # private markers even if a caller attempts an ordinary text copy.
        copied = self.output / 'desktop-source-check-5.txt'; copied.write_bytes(self.log.read_bytes())
        result = self.exporter().export_evidence(self.output, self.root / 'private-public')
        self.assertEqual(result['evidence_export'], 'FAIL')
        self.assertFalse((self.root / 'private-public/desktop-source-check-5.txt').exists())

    def test_only_named_terminal_files_with_no_symlinks_or_hardlinks(self):
        self.log.write_bytes(b'error diagnostic')
        other = self.root / 'arbitrary.txt'; other.write_bytes(b'unreviewed')
        with self.assertRaises(ValueError):
            runner.desktop_projection(other, self.output)
        other.unlink(); other.symlink_to(self.log)
        self.log.unlink(); self.log.symlink_to(other)
        with self.assertRaises(ValueError):
            runner.desktop_projection(self.log, self.output)

    def test_projection_expansion_fails_explicitly_without_truncation(self):
        self.log.write_bytes(b'\x00' * 32)
        with patch.object(runner, 'LOG_LIMIT', 64), self.assertRaisesRegex(ValueError, 'no truncation'):
            runner.desktop_projection(self.log, self.output)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_runtime_home_is_owned_private_and_not_reused_or_symlinked(self):
        home = self.root / 'home'; home.mkdir()
        runtime = runner.private_runtime(home)
        self.assertEqual(runtime, home / 'runtime')
        self.assertEqual(stat.S_IMODE(runtime.stat().st_mode), 0o700)
        self.assertEqual(runtime.stat().st_uid, os.geteuid())
        with self.assertRaises(FileExistsError):
            runner.private_runtime(home)
        link = self.root / 'linked-home'; link.symlink_to(home, target_is_directory=True)
        with self.assertRaises(ValueError):
            runner.private_runtime(link)


class SuiteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for patcher in (patch.dict(runner.ACTIVE, {}, clear=True), patch.object(runner.os, 'killpg')):
            patcher.start()
            self.addCleanup(patcher.stop)

    def suite(self, text, code=0, **kwargs):
        def spawn(command, **options):
            options['stdout'].write(text.encode())
            return SimpleNamespace(pid=987654321, wait=Mock(return_value=code))
        with patch.object(runner.subprocess, 'Popen', side_effect=spawn) as child:
            result = runner.run_suite('fixture', ['python3', 'fake-unittest'], self.root, self.root,
                                      {'HOME': '/tmp/home'}, unit=True, **kwargs)
        self.assertTrue(child.call_args.kwargs['start_new_session'])
        self.assertEqual(result, json.loads((self.root / 'fixture.json').read_text()))
        self.assertEqual((self.root / 'fixture.log').read_text(), text)
        return result

    def test_complete_unittest_success(self):
        result = self.suite('Ran 3 tests in 0.1s\nOK\n')
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['tests'], 3)
        self.assertEqual(result['skipped'], 0)

    def test_skips_never_become_complete_pass(self):
        result = self.suite('Ran 3 tests in 0.1s\nOK (skipped=1)\n')
        self.assertEqual(result['status'], 'INCOMPLETE')
        self.assertEqual(result['skipped'], 1)

    def test_failure_and_zero_test_discovery_preserve_diagnostics(self):
        self.assertEqual(self.suite('Ran 3 tests in 0.1s\nFAILED (errors=1)\n', 1)['status'], 'FAIL')
        (self.root / 'fixture.log').unlink()
        self.assertEqual(self.suite('Ran 0 tests in 0.1s\nOK\n')['status'], 'FAIL')

    def test_missing_summary_preserves_failure_json(self):
        result = self.suite('failed before discovering any tests\n', 1)
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('summary missing', result['error'])

    def test_timeout_terminates_process_group_without_host_processes(self):
        process = SimpleNamespace(pid=987654321, wait=Mock(side_effect=[
            subprocess.TimeoutExpired('fixture', 1), subprocess.TimeoutExpired('fixture', 5), 137]))
        with patch.object(runner.subprocess, 'Popen', return_value=process), patch.object(runner.os, 'killpg') as kill:
            result = runner.run_suite('timeout', ['fake'], self.root, self.root, {}, timeout=1)
        self.assertEqual(kill.call_count, 2)
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('timeout', result['error'])

    def test_no_host_suites_or_evidence_writes_before_guard(self):
        record = observed()
        record['arch'] = 'x86_64'
        args = ['source_suites.py', '--source', '/source', '--output', str(self.root)]
        with patch.object(runner.sys, 'argv', args), patch.object(runner, 'environment', return_value=record), patch.object(runner, 'suites') as suites:
            self.assertEqual(runner.main(), 1)
            suites.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_complete_plan_and_only_named_desktop_logs_exported(self):
        source, output = self.root / 'source', self.root / 'out'
        desktop = source / 'packages/desktop'
        desktop.mkdir(parents=True)
        (desktop / 'check-local.py').write_text('fixture; never executed')
        output.mkdir()
        home = self.root / 'home'; home.mkdir()
        calls = []

        def check(name, command, cwd, out, env, **options):
            calls.append((name, command, env, options))
            if name == 'desktop-local':
                files = cwd / 'evidence'
                files.mkdir()
                (files / 'host-packaging.json').write_text('{"clean_arm_build":"NOT RUN"}')
                (files / 'private-key.json').write_text('synthetic private fixture; do not copy')
                (files / 'host-package-1.pkg.tar.zst').write_bytes(b'not public logs')
                (files / 'source-check-1.txt').write_text('public source-check log')
            return {'name': name, 'status': 'PASS', 'tests': 1, 'skipped': 0}

        with patch.object(runner, 'run_suite', side_effect=check):
            results = runner.suites(source, output, home)
        self.assertEqual(len(results), len(runner.UNIT_DIRS) + len(runner.CHECKS) + 1)
        self.assertEqual([call[1][5] for call in calls[:len(runner.UNIT_DIRS)]], list(runner.UNIT_DIRS))
        self.assertTrue(all(call[3]['unit'] for call in calls[:len(runner.UNIT_DIRS)]))
        self.assertTrue(all(set(call[2]) == {'PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'PYTHONDONTWRITEBYTECODE',
                        'TERM', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME', 'XDG_DATA_HOME', 'XDG_RUNTIME_DIR'} for call in calls))
        self.assertTrue(all(call[2]['XDG_RUNTIME_DIR'] == str(home / 'runtime') for call in calls))
        self.assertEqual(stat.S_IMODE((home / 'runtime').stat().st_mode), 0o700)
        self.assertEqual(sorted(path.name for path in output.iterdir()),
                         ['desktop-host-packaging.json', 'desktop-source-check-1.projection.json', 'desktop-source-check-1.txt'])

    def test_failed_desktop_terminal_log_is_projected_without_changing_suite_fail(self):
        source, output, home = (self.root / p for p in ('source', 'out', 'home'))
        (source / 'packages/desktop').mkdir(parents=True)
        output.mkdir(); home.mkdir()
        payload = b'\x1b[31mverification error; child exit -6\x1b[0m\0\xff\n'

        def failed(name, command, cwd, out, env, **options):
            if name == 'desktop-local':
                directory = cwd / 'evidence'; directory.mkdir()
                (directory / 'source-check-5.txt').write_bytes(payload)
                return {'name': name, 'status': 'FAIL', 'exit_code': 1, 'tests': None, 'skipped': None}
            return {'name': name, 'status': 'PASS', 'tests': 1, 'skipped': 0}

        with patch.object(runner, 'run_suite', side_effect=failed):
            results = runner.suites(source, output, home)
        self.assertEqual(results[-1]['status'], 'FAIL')
        self.assertIn('verification error; child exit -6', (output / 'desktop-source-check-5.txt').read_text())
        record = json.loads((output / 'desktop-source-check-5.projection.json').read_text())
        self.assertEqual(record['raw_sha256'], hashlib.sha256(payload).hexdigest())

    def test_desktop_projection_finally_preserves_diagnostics_on_cancel(self):
        source, output, home = (self.root / p for p in ('source', 'out', 'home'))
        (source / 'packages/desktop').mkdir(parents=True)
        output.mkdir(); home.mkdir()

        def cancelled(name, command, cwd, out, env, **options):
            if name == 'desktop-local':
                directory = cwd / 'evidence'; directory.mkdir()
                (directory / 'source-check-5.txt').write_bytes(b'\x1b[31merror before cancellation\n')
                raise runner.Cancelled()
            return {'name': name, 'status': 'PASS', 'tests': 1, 'skipped': 0}

        with patch.object(runner, 'run_suite', side_effect=cancelled), self.assertRaises(runner.Cancelled):
            runner.suites(source, output, home)
        self.assertIn('error before cancellation', (output / 'desktop-source-check-5.txt').read_text())

    def test_signal_or_keyboard_cancellation_kills_tracked_group_and_retains_fail(self):
        for error in (runner.Cancelled(), KeyboardInterrupt()):
            process = SimpleNamespace(pid=987654321, wait=Mock(side_effect=[error, 0, 0]))
            with patch.object(runner.subprocess, 'Popen', return_value=process), self.assertRaises(runner.Cancelled):
                runner.run_suite('cancelled', ['fake'], self.root, self.root, {})
            result = json.loads((self.root / 'cancelled.json').read_text())
            self.assertEqual(result['status'], 'FAIL')
            self.assertEqual(result['cleanup']['status'], 'PASS')
            self.assertFalse(runner.ACTIVE)
            (self.root / 'cancelled.log').unlink()

    def test_pending_signal_after_spawn_cannot_hide_child_handle(self):
        process = SimpleNamespace(pid=987654321, wait=Mock(return_value=0))
        with patch.object(runner.subprocess, 'Popen', return_value=process), patch.object(runner.signal, 'pthread_sigmask', side_effect=[set(), runner.Cancelled()]), self.assertRaises(runner.Cancelled):
            runner.run_suite('spawn-cancelled', ['fake'], self.root, self.root, {})
        result = json.loads((self.root / 'spawn-cancelled.json').read_text())
        self.assertEqual(result['cleanup']['groups'][0]['pid'], process.pid)
        self.assertFalse(runner.ACTIVE)

    def test_cleanup_error_retains_sanitized_fail_and_stops_new_suites(self):
        process = SimpleNamespace(pid=987654321, wait=Mock(return_value=0))
        with patch.object(runner.subprocess, 'Popen', return_value=process), patch.object(runner.os, 'killpg', side_effect=OSError('TOKEN=private-secret')), self.assertRaises(runner.StopSuites):
            runner.run_suite('cleanup-error', ['fake'], self.root, self.root, {})
        data = (self.root / 'cleanup-error.json').read_text()
        self.assertNotIn('private-secret', data)
        self.assertEqual(json.loads(data)['cleanup']['status'], 'FAIL')
        self.assertEqual(json.loads(data)['status'], 'FAIL')

    def test_main_cancellation_finalizes_failure_even_when_cleanup_fails(self):
        output = self.root / 'out'
        output.mkdir()
        record = observed()
        record['home'] = str(self.root / 'home')
        process = SimpleNamespace(pid=987654321, wait=Mock(return_value=0))
        def cancel(*args):
            runner.ACTIVE[process.pid] = process
            raise KeyboardInterrupt('TOKEN=private-secret')
        args = ['source_suites.py', '--source', '/source', '--output', str(output)]
        with patch.object(runner.sys, 'argv', args), patch.object(runner, 'environment', return_value=record), patch.object(runner, 'suites', side_effect=cancel), patch.object(runner.os, 'killpg', side_effect=OSError('TOKEN=private-secret')):
            self.assertEqual(runner.main(), 1)
        data = (output / 'result.json').read_text()
        self.assertNotIn('private-secret', data)
        self.assertEqual(json.loads(data)['source_suites'], 'FAIL')
        self.assertEqual(json.loads(data)['cleanup']['status'], 'FAIL')

    def test_sigterm_handler_and_deferred_finalization(self):
        with self.assertRaises(runner.Cancelled):
            runner.interrupt(signal.SIGTERM, None)
        previous = signal.getsignal(signal.SIGTERM)
        with runner.defer_cancellation() as events:
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            self.assertTrue(events)
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)

    def test_signal_during_suite_receipt_write_rewrites_fail(self):
        original_save = runner.save
        injected = False
        def signal_during_write(path, data):
            nonlocal injected
            original_save(path, data)
            if not injected:
                injected = True
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        process = SimpleNamespace(pid=987654321, wait=Mock(return_value=0))
        with patch.object(runner.subprocess, 'Popen', return_value=process), patch.object(runner, 'save', side_effect=signal_during_write), self.assertRaises(runner.Cancelled):
            runner.run_suite('late-cancel', ['fake'], self.root, self.root, {})
        self.assertEqual(json.loads((self.root / 'late-cancel.json').read_text())['status'], 'FAIL')

    def test_signal_during_final_result_write_cannot_leave_pass(self):
        output = self.root / 'out'
        output.mkdir()
        record = observed()
        record['home'] = str(self.root / 'home')
        original_save = runner.save
        injected = False
        def signal_during_write(path, data):
            nonlocal injected
            original_save(path, data)
            if path.name == 'result.json' and not injected:
                injected = True
                signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
        def success(_source, _output, _home, results):
            results.append({'status': 'PASS', 'tests': 3, 'skipped': 0})
        args = ['source_suites.py', '--source', '/source', '--output', str(output)]
        with patch.object(runner.sys, 'argv', args), patch.object(runner, 'environment', return_value=record), patch.object(runner, 'suites', side_effect=success), patch.object(runner, 'save', side_effect=signal_during_write):
            self.assertEqual(runner.main(), 1)
        self.assertEqual(json.loads((output / 'result.json').read_text())['source_suites'], 'FAIL')

    def test_runtime_exception_content_never_enters_receipt(self):
        with patch.object(runner.subprocess, 'Popen', side_effect=OSError('TOKEN=private-secret')):
            result = runner.run_suite('spawn-error', ['fake'], self.root, self.root, {})
        self.assertEqual(result['status'], 'FAIL')
        self.assertNotIn('private-secret', (self.root / 'spawn-error.json').read_text())


if __name__ == '__main__':
    unittest.main()
