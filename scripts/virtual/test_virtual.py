# SPDX-License-Identifier: MIT
"""Guard/output/metadata tests; no Docker, kernel, DRM or ARM execution."""
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import audit_tooling
import common
import guest
import run


class Capabilities(unittest.TestCase):
    def results(self):
        return [{'returncode': 0, 'error': None, 'stdout': expected, 'stderr': ''}
                for _, _, expected in run.CAPABILITIES]

    def checks(self, results):
        with tempfile.TemporaryDirectory(prefix='virtual-capability-test-') as temporary:
            root = Path(temporary); report = {}; writes = []
            original = common.save
            def observe(path, value):
                writes.append(copy.deepcopy(value)); original(path, value)
            with patch('run.bounded', side_effect=results) as process, patch('run.save', side_effect=observe):
                try: run.check_capabilities(report, root)
                except BaseException as error: failure = error
                else: failure = None
            self.assertEqual(common.json_load(root / 'capabilities.json'), report['capabilities'])
            for call in process.call_args_list:
                self.assertEqual(call.kwargs, {'timeout': 15, 'limit': 128 * 1024})
            return report, writes, process.call_args_list, failure

    def test_all_four_checks_record_before_and_after_without_raw_help(self):
        report, writes, calls, failure = self.checks(self.results())
        self.assertIsNone(failure)
        self.assertEqual([r['status'] for rows in writes for r in rows[-1:]],
                         ['STARTING', 'PASS'] * 4)
        self.assertEqual([c.args[0] for c in calls],
                         [['/usr/bin/qemu-system-aarch64', *args] for _, args, _ in run.CAPABILITIES])
        self.assertEqual(len(run.capability_projection(report['capabilities'])), 4)
        self.assertNotIn('stdout', report['capabilities'][0])

    def test_each_missing_capability_stops_at_exact_check_and_has_finite_hashes(self):
        for index, (name, _, _) in enumerate(run.CAPABILITIES):
            with self.subTest(check=name):
                rows = self.results(); rows[index]['stdout'] = 'password=PRIVATE_HELP'
                report, writes, calls, failure = self.checks(rows)
                self.assertIsInstance(failure, common.Refused)
                self.assertEqual(len(calls), index + 1)
                self.assertEqual(report['capabilities'][-1]['check'], name)
                self.assertEqual(report['capabilities'][-1]['reason'], 'capability-missing')
                self.assertEqual(writes[-2][-1]['status'], 'STARTING')
                self.assertNotIn('PRIVATE_HELP', json.dumps(report))

    def test_process_bounds_errors_and_cancel_never_publish_exception_text(self):
        for error, reason in [('timeout', 'timeout'), ('output overflow', 'output-limit'),
                              ('password=PRIVATE_HELP', 'launch-failed'), (None, 'process-failed')]:
            report, _, _, failure = self.checks([{'returncode': -9, 'error': error,
                                                 'stdout': '', 'stderr': 'PRIVATE_HELP'}])
            self.assertIsInstance(failure, common.Refused)
            self.assertEqual(report['capabilities'][-1]['reason'], reason)
            self.assertNotIn('PRIVATE_HELP', json.dumps(report))
        for error, reason in [(OSError('PRIVATE_PATH'), 'launch-failed'),
                              (run.ProofInterrupted('PRIVATE_PATH'), 'cancelled'),
                              (KeyboardInterrupt(), 'cancelled')]:
            report, _, _, failure = self.checks([error])
            self.assertIs(failure, error)
            self.assertEqual(report['capabilities'][-1]['reason'], reason)
            self.assertNotIn('PRIVATE_PATH', json.dumps(report))
            self.assertTrue(all(report['capabilities'][-1][key] is None for key in
                                ('returncode', 'stdout_sha256', 'stdout_bytes', 'stderr_sha256', 'stderr_bytes')))
            changed = copy.deepcopy(report['capabilities'])
            changed[-1].update(stdout_bytes=0, stdout_sha256=hashlib.sha256(b'').hexdigest())
            with self.assertRaises(common.Refused): run.capability_projection(changed)

    def test_projection_rejects_secret_types_order_and_partial_records(self):
        report, _, _, _ = self.checks(self.results()); rows = report['capabilities']
        changes = [('check', 'PRIVATE_PATH'), ('status', True), ('returncode', True),
                   ('reason', 'PRIVATE_PATH'), ('stdout_sha256', 'bad'),
                   ('stdout_bytes', False), ('stdout_bytes', 128 * 1024 * 3 + 1),
                   ('stderr_bytes', -1)]
        for key, value in changes:
            changed = copy.deepcopy(rows); changed[0][key] = value
            with self.subTest(field=key), self.assertRaises(common.Refused):
                run.capability_projection(changed)
        for changed in [rows[::-1], rows + [rows[-1]], [dict(rows[0], private='PRIVATE_PATH')],
                        [{key: value for key, value in rows[0].items() if key != 'stdout_bytes'}]]:
            with self.assertRaises(common.Refused): run.capability_projection(changed)

    def test_actual_bounded_process_output_flood_is_refused_and_reaped(self):
        def flood(_argv, **kwargs):
            return common.bounded([sys.executable, '-I', '-B', '-c',
                                   'import os;os.write(1,b"x"*1048576)'], **kwargs)
        with tempfile.TemporaryDirectory(prefix='virtual-capability-flood-') as temporary:
            report = {}
            with patch('run.bounded', side_effect=flood), self.assertRaises(common.Refused):
                run.check_capabilities(report, Path(temporary))
            row = report['capabilities'][0]
            self.assertEqual(row['reason'], 'output-limit')
            self.assertEqual(row['stdout_bytes'], run.CAPABILITY_LIMIT)

    def test_historical_audit_and_corrected_module_shape_stay_distinct(self):
        old = common.json_load(Path(__file__).with_name('tooling.lock.json'))
        old['packages'] = [row for row in old['packages'] if row['name'] not in
                           ('qemu-hw-display-virtio-gpu', 'qemu-hw-display-virtio-gpu-pci')]
        old['expected_package_count'] = 360
        audit_tooling.validate_lock(old)
        candidate = copy.deepcopy(old)
        candidate['packages'] += [{'name': 'qemu-hw-display-virtio-gpu'},
                                  {'name': 'qemu-hw-display-virtio-gpu-pci'}]
        candidate['expected_package_count'] = 362
        audit_tooling.validate_lock(candidate)
        for change in [dict(expected_package_count=360), dict(base_package_count=345),
                       dict(packages=candidate['packages'][:-1] + [{'name': 'unrelated-module'}])]:
            with self.assertRaises(common.Refused): audit_tooling.validate_lock(candidate | change)

    def test_runtime_requires_corrected_extension_and_exact_inventory(self):
        # Data/interface fixture only: no host pacman, kernel or baseline payload access.
        old = common.json_load(Path(__file__).with_name('tooling.lock.json'))
        old['packages'] = [row for row in old['packages'] if row['name'] not in
                           ('qemu-hw-display-virtio-gpu', 'qemu-hw-display-virtio-gpu-pci')]
        old['expected_package_count'] = 360
        candidate = copy.deepcopy(old)
        candidate['packages'] += [{'name': name, 'version': '11.1.2-1'} for name in
                                  ('qemu-hw-display-virtio-gpu', 'qemu-hw-display-virtio-gpu-pci')]
        candidate['expected_package_count'] = 362
        with tempfile.TemporaryDirectory(prefix='virtual-runtime-extension-') as temporary:
            root = Path(temporary); base = {f'base-package-{i:03d}': '1-1' for i in range(341)}
            (root / 'base.lock').write_text(''.join(name + ' ' + version + '\n' for name, version in base.items()))
            contract = {'base_runtime_lock': 'base.lock', 'base_runtime_lock_sha256': common.digest(root / 'base.lock'),
                        'tooling_lock': 'tooling.json', 'tooling_audit': 'audit.json', 'tooling_audit_sha256': 'a' * 64,
                        'baseline': []}
            def attempt(lock, observed=None):
                common.save(root / 'tooling.json', lock)
                contract['tooling_lock_sha256'] = common.digest(root / 'tooling.json')
                common.save(root / 'audit.json', {'status': 'PASS', 'tooling_lock_sha256': contract['tooling_lock_sha256'],
                                                'packages': {row['name']: {} for row in lock['packages']}})
                expected = base | {row['name']: row['version'] for row in lock['packages']}
                text = ''.join(name + ' ' + version + '\n' for name, version in (observed or expected).items())
                with patch('common.pinned', side_effect=lambda _root, name, _sha: root / name), \
                        patch('common.subprocess.check_output', return_value=text) as process, \
                        patch('common.digest', return_value=common.IMAGE_SHA):
                    result = common.check_runtime(contract)
                    process.assert_called_once_with(['/usr/bin/pacman', '-Q'], text=True, timeout=30)
                return result
            self.assertEqual(len(attempt(candidate)), 362)
            with self.assertRaises(common.Refused): attempt(old)
            with self.assertRaises(common.Refused): attempt(candidate | {'expected_package_count': 360})
            expected = base | {row['name']: row['version'] for row in candidate['packages']}
            expected.pop('qemu-hw-display-virtio-gpu-pci'); expected['unrelated-module'] = '11.1.2-1'
            with self.assertRaises(common.Refused): attempt(candidate, expected)


class Guards(unittest.TestCase):
    def fixture(self, prep=False):
        return {'uid': 0 if prep else 1001, 'arch': 'aarch64', 'docker': True,
                'caps': {k: common.SAFE_CAPS if prep else 0 for k in ('CapEff', 'CapPrm', 'CapBnd')},
                'nnp': '1', 'interfaces': ['lo'], 'devices': False, 'docker_socket': False,
                'nonce': 'a' * 32, 'image_id': 'sha256:' + 'b' * 64, 'marker': '1',
                'runner': '/runner/virtual', 'mounts': {
                    '/': {'flags': ['ro'], 'type': 'overlay'}, '/inputs': {'flags': ['ro'], 'type': 'ext4'},
                    '/runner': {'flags': ['ro'], 'type': 'ext4'}, '/out': {'flags': ['rw'], 'type': 'ext4'},
                    '/tmp': {'flags': ['rw'], 'type': 'tmpfs'}}}

    def test_guards_accept_only_reviewed_root_preparation_and_unprivileged_run(self):
        common.validate_environment(self.fixture())
        common.validate_environment(self.fixture(True), preparation=True)
        for prep in (False, True):
            cases = [dict(uid=1001 if prep else 0), dict(arch='x86_64'), dict(docker=False), dict(marker=''),
                     dict(devices=True), dict(interfaces=['lo', 'eth0']), dict(docker_socket=True), dict(nnp='0'),
                     dict(nonce='a'), dict(image_id='latest'), dict(runner='/home/runner')]
            for changes in cases:
                with self.subTest(preparation=prep, changes=changes), self.assertRaises(common.Refused):
                    common.validate_environment(dict(self.fixture(prep), **changes), preparation=prep)

    def test_caps_ro_root_and_nested_mounts(self):
        for prep in (False, True):
            for bit in (12, 16, 21):  # NET_ADMIN/SYS_MODULE/SYS_ADMIN
                f = self.fixture(prep)
                f['caps']['CapBnd'] |= 1 << bit
                with self.assertRaises(common.Refused):
                    common.validate_environment(f, preparation=prep)
        for point in ('/out/secret', '/inputs/socket', '/usr/local', '/home'):
            f = self.fixture()
            f['mounts'][point] = {'flags': ['rw'], 'type': 'ext4'}
            with self.assertRaises(common.Refused):
                common.validate_environment(f)
        f = self.fixture()
        f['mounts']['/']['flags'] = ['rw']
        with self.assertRaises(common.Refused):
            common.validate_environment(f)

    def test_guest_refuses_host_before_cmdline_or_drivers(self):
        with patch.dict(os.environ, {}, clear=True), patch('guest.platform.machine', return_value='x86_64'):
            with self.assertRaises(ValueError):
                guest.guest_guard()

    def test_paths_and_json_data_rejected(self):
        for value in ('/usr/foo', '../x', 'a/../x', 'a//x', 'a\\x', 'a\nx'):
            with self.assertRaises(common.Refused):
                common.relative(value)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input'
            path.write_text('{"a":1,"a":2}')
            with self.assertRaises(common.Refused):
                common.json_load(path)
            path.write_text('{"a":NaN}')
            with self.assertRaises(common.Refused):
                common.json_load(path)
            path.write_bytes(b'fixture')
            linked = Path(directory) / 'link'
            linked.symlink_to(path)
            with self.assertRaises(common.Refused):
                common.pinned(directory, 'link', common.digest(path))
            with self.assertRaises(common.Refused):
                common.pinned(directory, 'input', '0' * 64)


class Bounds(unittest.TestCase):
    def test_cancellation_between_popen_and_registration_reaps_real_child(self):
        original = subprocess.Popen
        for kind in ('bounded', 'logged'):
            for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM):
                children = []
                def interrupt(*_):
                    raise KeyboardInterrupt('spawn cancellation')
                def spawn(*args, **kwargs):
                    child = original(*args, **kwargs)
                    children.append(child)
                    os.kill(os.getpid(), sig)
                    return child
                previous = signal.signal(sig, interrupt)
                try:
                    with self.subTest(kind=kind, signal=sig), tempfile.TemporaryDirectory() as directory, \
                            patch('common.subprocess.Popen', side_effect=spawn), self.assertRaises(KeyboardInterrupt):
                        path = Path(directory) / 'cancel.log'
                        argv = [sys.executable, '-c', 'import time; time.sleep(30)']
                        if kind == 'bounded':
                            common.bounded(argv, log=path, timeout=2)
                        else:
                            common.LoggedProcess(argv, path)
                    self.assertEqual(len(children), 1)
                    self.assertIsNotNone(children[0].poll())
                    self.assertIs(signal.getsignal(sig), interrupt)
                    self.assertTrue(children[0].stdout.closed)
                finally:
                    signal.signal(sig, previous)
                    for child in children:
                        if child.poll() is None:
                            run.kill(child)

    def test_spawn_preserves_child_term_and_default_parent_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'term.log'
            item = common.LoggedProcess([sys.executable, '-c', 'import time; print("ready",flush=True); time.sleep(30)'], path)
            deadline = time.monotonic() + 2
            try:
                while not path.read_bytes() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertIn(b'ready', path.read_bytes())
                item.process.send_signal(signal.SIGTERM)
                self.assertEqual(item.process.wait(timeout=2), -signal.SIGTERM)
                item.finish()
            finally:
                if item.process.poll() is None:
                    run.kill(item.process)
            previous = signal.signal(signal.SIGTERM, signal.SIG_DFL)
            original, children = subprocess.Popen, []
            def spawn(*args, **kwargs):
                child = original(*args, **kwargs); children.append(child)
                os.kill(os.getpid(), signal.SIGTERM)
                return child
            try:
                with patch('common.subprocess.Popen', side_effect=spawn), self.assertRaises(InterruptedError):
                    common.bounded([sys.executable, '-c', 'import time; time.sleep(30)'], timeout=2)
                self.assertIsNotNone(children[0].poll())
                self.assertEqual(signal.getsignal(signal.SIGTERM), signal.SIG_DFL)
            finally:
                signal.signal(signal.SIGTERM, previous)
                for child in children:
                    if child.poll() is None:
                        run.kill(child)

    def test_streaming_combined_output_cap(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bounded.log'
            result = common.bounded([sys.executable, '-c', 'import os; os.write(1,b"x"*100000); os.write(2,b"y"*100000)'], log=path, limit=1024)
            self.assertEqual(result['error'], 'output overflow')
            self.assertEqual(path.stat().st_size, 1024)
            self.assertLessEqual(len(result['stdout']) + len(result['stderr']), 1024)
            self.assertNotEqual(result['returncode'], 0)

    def test_deadline_kills_process_group_and_retains_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'timeout.log'
            result = common.bounded([sys.executable, '-c', 'import os,time; print("before deadline",flush=True); os.fork(); time.sleep(30)'], log=path, timeout=.15)
            self.assertEqual(result['error'], 'timeout')
            self.assertIn('before deadline', path.read_text())
            self.assertNotEqual(result['returncode'], 0)

    def test_long_lived_log_is_capped_while_process_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'session.log'
            item = common.LoggedProcess([sys.executable, '-c', 'import os,time; os.write(1,b"x"*1000000); time.sleep(30)'], path, limit=2048)
            item.process.wait(timeout=5)
            with self.assertRaises(common.Refused):
                item.finish()
            self.assertEqual(item.error, 'output overflow')
            self.assertEqual(path.stat().st_size, 2048)

    def test_short_log_is_durable_before_process_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'short.log'
            item = common.LoggedProcess([sys.executable, '-c', 'import time; print("retained now",flush=True); time.sleep(30)'], path)
            deadline = time.monotonic() + 2
            while not path.read_bytes() and time.monotonic() < deadline:
                time.sleep(.01)
            try:
                self.assertIn(b'retained now', path.read_bytes())
                self.assertIsNone(item.process.poll())
            finally:
                run.kill(item.process)
                item.finish()

    def test_qmp_dribbling_has_absolute_deadline(self):
        left, right = socket.socketpair()
        qmp = run.QMP.__new__(run.QMP)
        qmp.socket, qmp.buffer = left, b''
        stop = threading.Event()
        def bytes_slowly():
            while not stop.wait(.01):
                try:
                    right.send(b'x')
                except OSError:
                    break
        thread = threading.Thread(target=bytes_slowly)
        thread.start()
        start = time.monotonic()
        try:
            with self.assertRaises(common.Refused):
                qmp.read(start + .12)
            self.assertLess(time.monotonic() - start, .5)
        finally:
            stop.set()
            left.close()
            right.close()
            thread.join()


class Evidence(unittest.TestCase):
    def test_colorful_console_is_never_a_visual_review_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'frame.ppm'
            path.write_bytes(b'P6\n8 1\n255\n' + b''.join(bytes([i, i, i]) for i in range(8)))
            result = run.inspect_ppm(path)
            self.assertEqual(result['visual_review'], 'NOT RUN')
            self.assertNotIn('status', result)
            path.write_bytes(b'P6\n8 1\n255\n' + b'\x00' * 24)
            with self.assertRaises(common.Refused):
                run.inspect_ppm(path)
            path.write_bytes(b'P6\n8 1\n255\n' + b'\x00' * 25)
            with self.assertRaises(common.Refused):
                run.inspect_ppm(path)

    def test_tooling_receipt_exactly_binds_all_resolved_inputs(self):
        root = Path(__file__).parent
        lock = common.json_load(root / 'tooling.lock.json')
        audit = common.json_load(root / 'tooling-audit.json')
        self.assertEqual(audit['status'], 'PASS')
        self.assertEqual(audit['tooling_lock_sha256'], common.digest(root / 'tooling.lock.json'))
        self.assertEqual(lock['resolver']['exit_code'], 0)
        audit_tooling.validate_lock(lock)
        self.assertEqual({p['name'] for p in lock['packages']}, set(audit['packages']))
        for p in lock['packages']:
            with self.subTest(package=p['name']):
                result = audit['packages'][p['name']]
                self.assertEqual(result['archive_sha256'], p['sha256'])
                self.assertFalse(result['hooks'])
                audit_tooling.verify(result['signature_status'], lock['signer_fingerprint'])

    def test_signature_cannot_be_accepted_with_wrong_signer_or_failure(self):
        lock = common.json_load(Path(__file__).parent / 'tooling.lock.json')
        audit = common.json_load(Path(__file__).parent / 'tooling-audit.json')
        status = next(iter(audit['packages'].values()))['signature_status']
        with self.assertRaises(common.Refused):
            audit_tooling.verify(status, 'A' * 40)
        with self.assertRaises(common.Refused):
            audit_tooling.verify(status + '\n[GNUPG:] REVKEYSIG key\n', lock['signer_fingerprint'])


if __name__ == '__main__':
    unittest.main()
