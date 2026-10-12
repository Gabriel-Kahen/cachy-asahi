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
        self.assertEqual(lock['expected_package_count'], 360)
        self.assertEqual(len(lock['packages']), 19)
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
