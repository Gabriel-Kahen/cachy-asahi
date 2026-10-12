# SPDX-License-Identifier: MIT
import json
import os
from pathlib import Path
import socket
import stat
import sys
from types import SimpleNamespace
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import image
import common
from runtime import Cancelled, Runner, cancellation_handlers


class ImageCleanupTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.journal = Path(tmp.name) / 'derived-image.json'
        self.base, self.derived = ('sha256:' + value * 64 for value in ('b', 'c'))
        self.nonce = 'a' * 32; self.tag = 'cachy-asahi-kernel-private:' + self.nonce
        self.config = {'Env': ['PATH=/usr/bin:/bin'], 'User': 'alarm'}
        self.state = {'tag_present': False, 'id_present': False}; self.calls = []
        self.inventory_rows = [self.base]
        self.broker = SimpleNamespace(role='provision', nonce=self.nonce, image=self.base,
            image_config=self.config, _operation=self.operation,
            runner=SimpleNamespace(run=self.inventory_run), _info=lambda runner: None,
            _raw=lambda argv, runner, timeout: runner.run(argv, timeout=timeout),
            _journal=lambda: {'containers': [{'id': 'd' * 64, 'name': 'owned-provision'}]},
            _inspect=lambda *args: 'd' * 64)

    def inventory_run(self, argv, **kwargs):
        self.calls.append(argv)
        self.assertEqual(kwargs, {'limit': 128 * 1024, 'timeout': 30})
        return SimpleNamespace(returncode=0, stdout=('\n'.join(self.inventory_rows) + '\n').encode())

    def operation(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[:2] == ['image', 'ls']:
            return SimpleNamespace(returncode=0, stdout=(self.derived + '\n').encode() if self.state['tag_present'] else b'')
        reference = argv[-1]
        if argv[:2] == ['image', 'inspect']:
            exists = reference == self.base or (self.state['tag_present'] if reference == self.tag else self.state['id_present'])
            if not exists: return SimpleNamespace(returncode=1, stdout=b'Error: No such image')
            base = reference == self.base
            row = {'Id': self.base if base else self.derived, 'Architecture': 'arm64', 'Os': 'linux',
                   'Config': self.config, 'RootFS': {'Layers': ['base'] if base else ['base', 'extension']},
                   'Size': 100 if base else 200}
            return SimpleNamespace(returncode=0, stdout=json.dumps([row]).encode())
        if argv[:2] == ['image', 'rm']:
            self.assertEqual(argv[2], '--no-prune')
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

    def commit_result(self, identifier):
        def request(*args):
            return (404, {}) if args[1] == 'GET' else (201, {'Id': identifier})
        with patch.object(image, 'request', side_effect=request), \
                patch.object(image, 'module', return_value=SimpleNamespace(commit_config=lambda config: {})):
            return image.commit(self.broker, Path('/owned/code'), self.journal)

    def test_precommit_protects_baseline_base_and_intermediates(self):
        self.inventory_rows = ['sha256:' + 'f' * 64, self.base, 'sha256:' + 'e' * 64, self.base]
        self.attempt_unknown_commit()
        self.assertEqual(common.load(self.journal)['protected_image_ids'], sorted(set(self.inventory_rows)))

    def test_returned_existing_id_is_retained_but_never_removed(self):
        for identifier in (self.base, self.derived):
            with self.subTest(identifier=identifier):
                self.journal.unlink(missing_ok=True)
                self.inventory_rows = [self.base, self.derived]
                with self.assertRaisesRegex(ValueError, 'already protected'):
                    self.commit_result(identifier)
                self.assertEqual(common.load(self.journal)['image_id'], identifier)
                with self.assertRaisesRegex(ValueError, 'already protected'):
                    image.cleanup(self.broker, self.journal)
        self.assertFalse(any(argv[:2] == ['image', 'rm'] for argv in self.calls))

    def test_recovered_existing_id_cannot_remove_its_new_private_tag(self):
        self.inventory_rows = [self.base, self.derived]
        self.attempt_unknown_commit(); self.state.update(tag_present=True, id_present=True)
        with self.assertRaisesRegex(ValueError, 'already protected'):
            image.cleanup(self.broker, self.journal)
        self.assertTrue(self.state['tag_present'])
        self.assertIsNone(common.load(self.journal)['image_id'])
        self.assertFalse(any(argv[:2] == ['image', 'rm'] for argv in self.calls))

    def test_inventory_churn_refuses_post_without_mutation_journal(self):
        first = (self.base + '\n').encode()
        second = (self.base + '\nsha256:' + 'e' * 64 + '\n').encode()
        responses = [SimpleNamespace(returncode=0, stdout=data) for data in (first, second)]
        with patch.object(self.broker.runner, 'run', side_effect=responses), \
                patch.object(image, 'request', return_value=(404, {})) as request, \
                patch.object(image, 'module', return_value=SimpleNamespace(commit_config=lambda config: {})):
            with self.assertRaisesRegex(ValueError, 'changed before commit'):
                image.commit(self.broker, Path('/owned/code'), self.journal)
        self.assertEqual(request.call_count, 1)
        self.assertFalse(self.journal.exists())

    def test_inventory_failure_malformed_and_overflow_refuse_post(self):
        cases = [(1, b''), (0, b'x' * (128 * 1024 + 1)),
                 (0, ((self.base + '\n') * 257).encode()), (0, b'mutable-tag\n'),
                 (0, self.base.encode()), (0, (self.base + '\r\n').encode()),
                 (0, b'\xff\n'), (0, b''), (0, ('sha256:' + 'e' * 64 + '\n').encode())]
        for code, data in cases:
            with self.subTest(code=code, bytes=len(data)), \
                    patch.object(self.broker.runner, 'run', return_value=SimpleNamespace(returncode=code, stdout=data)), \
                    patch.object(image, 'request') as request:
                with self.assertRaises(ValueError): image.commit(self.broker, Path('/owned/code'), self.journal)
                request.assert_not_called()
                self.assertFalse(self.journal.exists())

    def test_existing_nonce_tag_cannot_start_commit(self):
        with patch.object(image, 'request', return_value=(200, {})) as request:
            with self.assertRaisesRegex(ValueError, 'new private image tag'):
                image.commit(self.broker, Path('/owned/code'), self.journal)
        self.assertEqual(request.call_count, 1)
        self.assertFalse(self.journal.exists())

    def test_protection_journal_file_and_directory_are_synced_before_post(self):
        synced = []; original = os.fsync
        def fsync(descriptor):
            synced.append(stat.S_IFMT(os.fstat(descriptor).st_mode)); original(descriptor)
        def request(*args):
            if args[1] == 'GET': return 404, {}
            self.assertIn(stat.S_IFREG, synced); self.assertIn(stat.S_IFDIR, synced)
            self.assertEqual(common.load(self.journal)['protected_image_ids'], [self.base])
            self.assertEqual(stat.S_IMODE(self.journal.stat().st_mode), 0o600)
            raise TimeoutError('unknown POST')
        with patch.object(image.os, 'fsync', side_effect=fsync), \
                patch.object(image, 'request', side_effect=request), \
                patch.object(image, 'module', return_value=SimpleNamespace(commit_config=lambda config: {})):
            with self.assertRaises(TimeoutError): image.commit(self.broker, Path('/owned/code'), self.journal)

    def test_malformed_protection_journal_never_authorizes_removal(self):
        self.attempt_unknown_commit()
        original = common.load(self.journal)
        cases = [None, [], [self.base, self.base], ['mutable-tag'], ['sha256:' + 'e' * 64],
                 [self.base] * 257, ['sha256:' + 'f' * 64, self.base]]
        for ids in cases:
            with self.subTest(ids=ids):
                record = dict(original); record['protected_image_ids'] = ids; common.save(self.journal, record)
                with self.assertRaises(ValueError): image.cleanup(self.broker, self.journal)
        record = dict(original); del record['protected_image_ids']; common.save(self.journal, record)
        with self.assertRaises(ValueError): image.cleanup(self.broker, self.journal)
        self.assertFalse(any(argv[:2] == ['image', 'rm'] for argv in self.calls))

    def test_journal_owner_mode_links_and_byte_bound_refuse(self):
        self.attempt_unknown_commit()
        self.journal.chmod(0o644)
        with self.assertRaises(ValueError): image.cleanup(self.broker, self.journal)
        self.journal.chmod(0o600)
        link = self.journal.with_name('second-link'); os.link(self.journal, link)
        with self.assertRaises(ValueError): image.cleanup(self.broker, self.journal)
        link.unlink(); self.journal.write_bytes(b'x' * (128 * 1024 + 1))
        with self.assertRaises(ValueError): image.cleanup(self.broker, self.journal)
        self.journal.unlink(); self.journal.symlink_to(self.journal.with_name('missing'))
        with self.assertRaises(ValueError): image.cleanup(self.broker, self.journal)

    def test_all_removal_paths_preserve_untagged_ancestors(self):
        self.attempt_unknown_commit(); self.state.update(tag_present=True, id_present=True)
        ancestors = {self.base, 'sha256:' + 'e' * 64}; original = self.operation
        def daemon(argv, **kwargs):
            if argv[:2] == ['image', 'rm'] and '--no-prune' not in argv:
                ancestors.clear()  # Simulate Moby's default parent pruning.
            return original(argv, **kwargs)
        self.broker._operation = daemon
        self.assertEqual(image.cleanup(self.broker, self.journal)['status'], 'PASS')
        self.assertEqual(ancestors, {self.base, 'sha256:' + 'e' * 64})
        removals = [argv for argv in self.calls if argv[:2] == ['image', 'rm']]
        self.assertEqual(removals, [['image', 'rm', '--no-prune', self.tag],
                                   ['image', 'rm', '--no-prune', self.derived]])

    def test_inventory_cancellation_leaves_no_commit_journal_or_post(self):
        with patch.object(self.broker.runner, 'run', side_effect=Cancelled()), patch.object(image, 'request') as request:
            with self.assertRaises(Cancelled): image.commit(self.broker, Path('/owned/code'), self.journal)
            request.assert_not_called()
        self.assertFalse(self.journal.exists())

    def test_post_cancellation_retains_protection_and_unknown_fail(self):
        def request(*args):
            if args[1] == 'GET': return 404, {}
            raise Cancelled()
        with patch.object(image, 'request', side_effect=request), \
                patch.object(image, 'module', return_value=SimpleNamespace(commit_config=lambda config: {})):
            with self.assertRaises(Cancelled): image.commit(self.broker, Path('/owned/code'), self.journal)
        self.assertEqual(common.load(self.journal)['protected_image_ids'], [self.base])
        self.assertEqual(image.cleanup(self.broker, self.journal)['status'], 'FAIL')

    def test_inventory_actual_process_output_and_aggregate_deadline_bounds(self):
        for code, seconds, message in (("import sys;sys.stdout.write('x'*131073)", 2, 'output-bound'),
                                       ('import time;time.sleep(10)', .06, 'command-timeout')):
            with self.subTest(code=code):
                self.broker.runner = Runner(seconds, {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'},
                                            self.journal.parent / ('logs-' + str(seconds)))
                self.broker._raw = lambda argv, runner, timeout: runner.run(
                    [sys.executable, '-I', '-B', '-c', code], timeout=timeout)
                began = time.monotonic()
                with self.assertRaisesRegex(ValueError, message): image.inventory(self.broker)
                self.assertLess(time.monotonic() - began, 1)

    def test_actual_term_during_inventory_cleans_child_without_commit(self):
        self.broker.runner = Runner(2, {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, self.journal.parent / 'term-logs')
        self.broker._raw = lambda argv, runner, timeout: runner.run([sys.executable, '-I', '-B', '-c',
            'import os,signal,time;os.kill(os.getppid(),signal.SIGTERM);time.sleep(10)'], timeout=timeout)
        began = time.monotonic()
        with cancellation_handlers(), patch.object(image, 'request') as request:
            with self.assertRaises(Cancelled): image.commit(self.broker, Path('/owned/code'), self.journal)
            request.assert_not_called()
        self.assertFalse(self.journal.exists())
        self.assertLess(time.monotonic() - began, 1)

    def test_cancelled_recovered_tag_removal_retains_id_for_safe_retry(self):
        self.attempt_unknown_commit(); self.state.update(tag_present=True, id_present=True)
        original = self.operation
        def remove_then_cancel(argv, **kwargs):
            result = original(argv, **kwargs)
            if argv == ['image', 'rm', '--no-prune', self.tag]: raise Cancelled()
            return result
        self.broker._operation = remove_then_cancel
        with self.assertRaises(Cancelled): image.cleanup(self.broker, self.journal)
        self.assertEqual(common.load(self.journal)['image_id'], self.derived)
        self.assertEqual(common.load(self.journal)['protected_image_ids'], [self.base])
        self.assertFalse(self.state['tag_present']); self.assertTrue(self.state['id_present'])
        self.broker._operation = original
        self.assertEqual(image.cleanup(self.broker, self.journal)['status'], 'PASS')

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
            if argv == ['image', 'rm', '--no-prune', self.derived]:
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

    def api_commit(self, result, status=201):
        """Exercise the actual wire client and held config helper, without Docker."""
        self.journal.unlink(missing_ok=True)
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / 'owned-api.sock'
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(str(path)); server.listen(2); server.settimeout(2)
        self.addCleanup(server.close)
        requests, errors, guards = [], [], []
        def respond():
            try:
                for code, value in ((404, {'message': 'No such image'}), (status, result)):
                    channel, _ = server.accept()
                    with channel:
                        channel.settimeout(2); data = bytearray()
                        while b'\r\n\r\n' not in data:
                            chunk = channel.recv(65536)
                            if not chunk: raise EOFError('incomplete fixture request headers')
                            data.extend(chunk)
                        header, body = bytes(data).split(b'\r\n\r\n', 1)
                        lines = header.decode().split('\r\n')
                        headers = dict(line.split(': ', 1) for line in lines[1:])
                        length = int(headers['Content-Length'])
                        while len(body) < length:
                            chunk = channel.recv(length - len(body))
                            if not chunk: raise EOFError('incomplete fixture request body')
                            body += chunk
                        requests.append((lines[0], headers, body))
                        encoded = json.dumps(value).encode()
                        channel.sendall(b'HTTP/1.1 ' + str(code).encode() + b' Fixture\r\nContent-Type: application/json\r\nContent-Length: ' +
                                        str(len(encoded)).encode() + b'\r\n\r\n' + encoded)
            except BaseException as error: errors.append(error)
        thread = threading.Thread(target=respond); thread.start()
        self.addCleanup(lambda: thread.join(timeout=3))
        self.broker.socket = path
        self.broker.runner = SimpleNamespace(deadline=time.monotonic() + 5, run=self.inventory_run)
        self.broker._local = lambda runner: guards.append('local')
        self.broker._info = lambda runner: guards.append('info')
        self.state.update(tag_present=True, id_present=True)
        try:
            return image.commit(self.broker, Path(__file__).resolve().parents[3], self.journal)
        finally:
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive()); self.assertEqual(errors, [])
            self.assertEqual(guards, ['info', 'info'] + ['local', 'info'] * 2 +
                             ['info', 'info'] + ['local', 'info'] * 2)
            self.assertEqual(len(requests), 2)
            self.assertEqual(requests[0][0], 'GET /v1.48/images/cachy-asahi-kernel-private%3A' + self.nonce + '/json HTTP/1.1')
            self.assertEqual(requests[0][2], b'')
            self.assertEqual(requests[1][0], 'POST /v1.48/commit?container=' + 'd' * 64 +
                             '&pause=true&repo=cachy-asahi-kernel-private&tag=' + self.nonce + ' HTTP/1.1')
            payload = json.loads(requests[1][2])
            expected = {key: self.config.get(key) for key in image.FIELDS}
            if expected['Entrypoint'] in (None, [], ['']):
                expected['Entrypoint'] = ['']
                if expected['Cmd'] is None: expected['Cmd'] = []
            self.assertEqual(payload, expected); self.assertEqual(len(payload), 12)
            self.assertEqual(requests[1][1]['Content-Type'], 'application/json')
            self.assertEqual(int(requests[1][1]['Content-Length']), len(requests[1][2]))

    def test_api148_exact_requests_config_and_immutable_response(self):
        self.config.update(Entrypoint=['/entry'], Cmd=['argument'], WorkingDir='/work',
            Labels={'owned': 'yes'}, Volumes={'/data': {}}, ExposedPorts={'8080/tcp': {}},
            StopSignal='SIGTERM', Shell=['/bin/sh', '-c'], Healthcheck={'Test': ['NONE'], 'Retries': 1},
            ArgsEscaped=False, Unsupported='not projected')
        record = self.api_commit({'Id': self.derived})
        self.assertEqual((record['status'], record['image_id']), ('DERIVED_CONFIG_VERIFIED', self.derived))
        self.assertEqual(common.load(self.journal), record)
        self.assertEqual(image.cleanup(self.broker, self.journal)['status'], 'PASS')

    def test_api148_empty_entrypoint_uses_held_helper_sentinel(self):
        record = self.api_commit({'Id': self.derived})
        self.assertEqual(record['accepted_config']['Entrypoint'], None)
        self.assertEqual(record['accepted_config']['Cmd'], None)

    def test_api148_unexpected_commit_response_retains_uncertain_journal(self):
        for status, result in ((200, {'Id': self.derived}), (201, {'Id': self.derived, 'extra': True}),
                               (201, {'Id': 'mutable-tag'})):
            with self.subTest(status=status, result=result):
                with self.assertRaisesRegex(ValueError, 'immutable derived image response required'):
                    self.api_commit(result, status)
                self.assertEqual(common.load(self.journal)['status'], 'COMMIT_ATTEMPTED')
                self.assertIsNone(common.load(self.journal)['image_id'])


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



class OperationImageTests(unittest.TestCase):
    server = ImageWireTests.server

    def test_actual_http_status_is_observed_before_body_refusal(self):
        from evidence import Trace
        trace=Trace();trace.current['action']='derive';trace.begin('IMAGE_COMMIT')
        path=self.server(b'HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 3\r\n\r\n{}')
        with self.assertRaises(ValueError):
            image.wire(path,'POST','/commit',b'{}',time.monotonic()+1,trace)
        first=trace.snapshot()['first_failure']
        self.assertEqual(first['gate'],'QUERY_RETURN')
        self.assertEqual(first['query_return'],{'kind':'HTTP_STATUS','code':201})
        self.assertEqual(first['predicate'],'bounded API JSON response required')

    def test_actual_info_status_is_observed_before_non200_refusal(self):
        import broker
        trace=broker.Trace();trace.current['action']='provision';trace.begin('CREATE')
        path=self.server(b'HTTP/1.1 503 Unavailable\r\nContent-Length: 2\r\n\r\n{}')
        with self.assertRaises(ValueError):broker.daemon_http(path,time.monotonic()+1,trace)
        first=trace.snapshot()['first_failure']
        self.assertEqual(first['gate'],'DAEMON_RESPONSE')
        self.assertEqual(first['daemon_return'],{'kind':'HTTP_STATUS','code':503})
        self.assertEqual(first['query_return'],{'kind':'UNOBSERVED','code':None})
        self.assertEqual(first['predicate'],'docker-daemon-http-status')

    def test_api_postcheck_cannot_erase_returned_commit_status(self):
        from evidence import Trace
        trace=Trace();trace.current['action']='derive'
        value=SimpleNamespace(observer=trace,socket='/private/socket',runner=SimpleNamespace(deadline=time.monotonic()+1),
                              _local=lambda runner:None)
        infos=iter((None,ValueError('docker-daemon-drift')))
        def info(runner):
            error=next(infos)
            if error:raise error
        value._info=info
        def wire(*args,observer):observer.returned(201,http=True);return 201,{'Id':'privateID'}
        with patch.object(image,'wire',side_effect=wire):
            with self.assertRaises(ValueError):image.request(value,'POST','/commit')
        first=trace.snapshot()['first_failure']
        self.assertEqual((first['gate'],first['query']),('DAEMON_POST','IMAGE_COMMIT'))
        self.assertEqual(first['query_return'],{'kind':'HTTP_STATUS','code':201})
        self.assertNotIn('private',json.dumps(first))


if __name__ == '__main__':
    unittest.main()
