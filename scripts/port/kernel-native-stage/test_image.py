# SPDX-License-Identifier: MIT
import json
from pathlib import Path
import socket
from types import SimpleNamespace
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import image
import common


class ImageCleanupTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.journal = Path(tmp.name) / 'derived-image.json'
        self.base, self.derived = ('sha256:' + value * 64 for value in ('b', 'c'))
        self.nonce = 'a' * 32; self.tag = 'cachy-asahi-kernel-private:' + self.nonce
        self.config = {'Env': ['PATH=/usr/bin:/bin'], 'User': 'alarm'}
        self.state = {'tag_present': False, 'id_present': False}; self.calls = []
        self.broker = SimpleNamespace(role='provision', nonce=self.nonce, image=self.base,
            image_config=self.config, _operation=self.operation,
            _journal=lambda: {'containers': [{'id': 'd' * 64, 'name': 'owned-provision'}]},
            _inspect=lambda *args: 'd' * 64)

    def operation(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[:2] == ['image', 'ls']:
            return SimpleNamespace(returncode=0, stdout=(self.derived + '\n').encode() if self.state['tag_present'] else b'')
        reference = argv[2]
        if argv[:2] == ['image', 'inspect']:
            exists = reference == self.base or (self.state['tag_present'] if reference == self.tag else self.state['id_present'])
            if not exists: return SimpleNamespace(returncode=1, stdout=b'Error: No such image')
            base = reference == self.base
            row = {'Id': self.base if base else self.derived, 'Architecture': 'arm64', 'Os': 'linux',
                   'Config': self.config, 'RootFS': {'Layers': ['base'] if base else ['base', 'extension']},
                   'Size': 100 if base else 200}
            return SimpleNamespace(returncode=0, stdout=json.dumps([row]).encode())
        if argv[:2] == ['image', 'rm']:
            persisted = common.load(self.journal)
            self.assertEqual(persisted['image_id'], self.derived)
            if reference == self.tag: self.state['tag_present'] = False
            else: self.state['id_present'] = False
            return SimpleNamespace(returncode=0, stdout=b'')
        self.fail('unexpected image command')

    def attempt_unknown_commit(self):
        def request(*args):
            if args[1] == 'GET': return 404, {}
            raise TimeoutError('injected uncertain POST; daemon work remains pending')
        with patch.object(image, 'request', side_effect=request), patch.object(image, 'module', return_value=SimpleNamespace(commit_config=lambda config: {})):
            with self.assertRaises(TimeoutError): image.commit(self.broker, Path('/owned/code'), self.journal)
        self.assertEqual(common.load(self.journal)['status'], 'COMMIT_ATTEMPTED')

    def test_uncertain_post_empty_tag_cannot_claim_absence_before_late_arrival(self):
        self.attempt_unknown_commit()
        result = image.cleanup(self.broker, self.journal)
        self.assertEqual((result['status'], result['absence_verified'], result['uncertain_commit']), ('FAIL', False, True))
        self.assertIsNone(common.load(self.journal)['image_id'])
        # The asynchronous commit completes only after the first cleanup ended.
        self.state.update(tag_present=True, id_present=True)
        recovered = image.cleanup(self.broker, self.journal)
        self.assertEqual((recovered['status'], recovered['absence_verified']), ('PASS', True))
        self.assertEqual(common.load(self.journal)['image_id'], self.derived)
        self.assertFalse(any(self.state.values()))
        self.assertNotIn(['image', 'rm', self.base], self.calls)

    def test_failed_unknown_image_recovery_cannot_remove_unverified_tag(self):
        self.attempt_unknown_commit(); self.state.update(tag_present=True, id_present=True)
        with patch.object(image, 'verify', side_effect=ValueError('image ownership differs')):
            with self.assertRaises(ValueError): image.cleanup(self.broker, self.journal)
        self.assertFalse(any(argv[:2] == ['image', 'rm'] for argv in self.calls))
        self.assertIsNone(common.load(self.journal)['image_id'])

    def test_recovered_id_survives_removal_failure_and_retry(self):
        self.attempt_unknown_commit(); self.state.update(tag_present=True, id_present=True)
        original = self.operation
        def fail_removal(argv, **kwargs):
            if argv[:2] == ['image', 'rm']: return SimpleNamespace(returncode=1, stdout=b'removal failed')
            return original(argv, **kwargs)
        self.broker._operation = fail_removal
        with self.assertRaises(ValueError): image.cleanup(self.broker, self.journal)
        self.assertEqual(common.load(self.journal)['image_id'], self.derived)
        self.broker._operation = original
        self.assertEqual(image.cleanup(self.broker, self.journal)['status'], 'PASS')

    def test_private_tag_absence_cannot_hide_id_retained_under_another_tag(self):
        self.attempt_unknown_commit(); self.state.update(tag_present=True, id_present=True)
        original = self.operation
        def other_tag_conflict(argv, **kwargs):
            if argv == ['image', 'rm', self.derived]:
                self.calls.append(argv)
                return SimpleNamespace(returncode=1, stdout=b'image remains referenced by another tag')
            return original(argv, **kwargs)
        self.broker._operation = other_tag_conflict
        for _ in range(2):
            with self.assertRaisesRegex(ValueError, 'owned image ID removal failed'):
                image.cleanup(self.broker, self.journal)
            self.assertFalse(self.state['tag_present'])
            self.assertTrue(self.state['id_present'])
            self.assertEqual(common.load(self.journal)['image_id'], self.derived)
        self.assertFalse(any('--force' in argv or 'prune' in argv for argv in self.calls))


class ImageWireTests(unittest.TestCase):
    def server(self, response, trickle=False):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        path = str(Path(tmp.name) / 'owned-api.sock')
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); server.bind(path); server.listen(1)
        self.addCleanup(server.close)
        def respond():
            try:
                channel, _ = server.accept()
                with channel:
                    channel.recv(65536)
                    if trickle:
                        for item in response:
                            channel.send(bytes([item])); time.sleep(0.005)
                    else: channel.sendall(response)
            except (OSError, BrokenPipeError): pass
        thread = threading.Thread(target=respond); thread.start()
        self.addCleanup(lambda: thread.join(timeout=1))
        return path

    def test_exact_bounded_json_response(self):
        data = b'{"Id":"image"}'
        response = b'HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(data)).encode() + b'\r\n\r\n' + data
        path = self.server(response)
        status, result = image.wire(path, 'POST', '/commit', b'{}', time.monotonic() + 1)
        self.assertEqual((status, result), (201, {'Id': 'image'}))

    def test_trickling_response_cannot_extend_aggregate_deadline(self):
        path = self.server(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}', trickle=True)
        start = time.monotonic()
        with self.assertRaises(ValueError): image.wire(path, 'GET', '/image', None, start + 0.03)
        self.assertLess(time.monotonic() - start, 0.3)

    def test_duplicate_json_and_conflicting_framing_refused(self):
        for header, data in ((b'Content-Length: 13\r\n', b'{"a":1,"a":2}'),
                             (b'Content-Length: 2\r\nTransfer-Encoding: chunked\r\n', b'{}')):
            path = self.server(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n' + header + b'\r\n' + data)
            with self.assertRaises(ValueError): image.wire(path, 'GET', '/image', None, time.monotonic() + 1)


if __name__ == '__main__':
    unittest.main()
