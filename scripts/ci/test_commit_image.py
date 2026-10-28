"""Exact Docker commit wire tests; all subprocesses and sockets are mocked."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

SPEC = importlib.util.spec_from_file_location('commit_image_tested', Path(__file__).with_name('commit_image.py'))
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)
NAME = 'cachy-asahi-handoff-' + 'a' * 32
IMAGE = 'sha256:' + 'b' * 64


def base_config():
    return {'User': 'alarm', 'Env': ['PATH=/usr/bin', 'HOME=/home/alarm', 'VALUE=private test value', 'UNICODE=café'],
            'Entrypoint': None, 'Cmd': None, 'WorkingDir': '/', 'Labels': {'purpose': 'test'},
            'Volumes': None, 'ExposedPorts': None, 'StopSignal': 'SIGTERM', 'Shell': None,
            'Healthcheck': None, 'ArgsEscaped': False}


class Base(unittest.TestCase):
    def setUp(self):
        self.no_command = patch.object(module.subprocess, 'run', side_effect=AssertionError('host command forbidden'))
        self.no_socket = patch.object(module.socket, 'socket', side_effect=AssertionError('host socket forbidden'))
        self.no_command.start(); self.no_socket.start()
        self.addCleanup(self.no_command.stop); self.addCleanup(self.no_socket.stop)


class ConfigTests(Base):
    def test_empty_entry_and_command_have_explicit_merge_blocking_wire_values(self):
        for entry in (None, [], ['']):
            for cmd in (None, []):
                base = base_config(); base.update(Entrypoint=entry, Cmd=cmd)
                wire = json.loads(json.dumps(module.commit_config(base)))
                with self.subTest(entry=entry, cmd=cmd):
                    self.assertEqual(wire['Entrypoint'], [''])
                    self.assertEqual(wire['Cmd'], [])
                    self.assertEqual(wire['Env'], base['Env'])

    def test_nonempty_entry_and_command_retained_exactly(self):
        for entry in (['/usr/bin/tool'], ['/usr/bin/env', 'python3']):
            for cmd in (None, [], ['--example', 'a b']):
                base = base_config(); base.update(Entrypoint=entry, Cmd=cmd)
                self.assertEqual(module.commit_config(base), base)
        base = base_config(); base['Cmd'] = ['/bin/bash']
        result = module.commit_config(base)
        self.assertEqual(result['Cmd'], ['/bin/bash'])
        self.assertEqual(result['Entrypoint'], [''])

    def test_only_known_portable_fields_and_full_env_are_copied(self):
        base = base_config()
        base.update(Env=['A=one', 'A=two', 'MULTILINE=one\ntwo', 'EMPTY='],
                    Hostname='runtime-only', Tty=True, Image='runtime-only', OnBuild=['runtime-only'])
        result = module.commit_config(base)
        self.assertEqual(set(result), set(module.FIELDS))
        self.assertEqual(result['Env'], base['Env'])
        result['Env'].append('CHANGED=1'); result['Labels']['purpose'] = 'changed'
        self.assertEqual(base['Env'][-1], 'EMPTY=')
        self.assertEqual(base['Labels'], {'purpose': 'test'})

    def test_maps_shell_and_healthcheck_preserved(self):
        base = base_config()
        base.update(Volumes={'/data': {}}, ExposedPorts={'8080/tcp': {}}, Shell=['/bin/sh', '-c'],
                    Healthcheck={'Test': ['CMD', '/bin/true'], 'Interval': 1000, 'Timeout': 1000,
                                 'StartPeriod': 0, 'StartInterval': 0, 'Retries': 1})
        result = module.commit_config(base)
        for field in ('Volumes', 'ExposedPorts', 'Shell', 'Healthcheck'):
            self.assertEqual(result[field], base[field])

    def test_invalid_config_types_and_host_config_refused(self):
        for key, value in (('User', 0), ('User', 'bad\0value'), ('Env', 'A=1'), ('Env', [1]),
                           ('Cmd', '/bin/sh'), ('Entrypoint', [None]), ('WorkingDir', {}),
                           ('Labels', {'x': 1}), ('Volumes', {'/data': {'host': '/home'}}),
                           ('ExposedPorts', []), ('StopSignal', 15), ('Shell', {}), ('ArgsEscaped', 0),
                           ('Healthcheck', {'HostConfig': {}}), ('Healthcheck', {'Test': 'CMD'}),
                           ('Healthcheck', {'Retries': True}), ('HostConfig', None)):
            base = base_config(); base[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(module.CommitError):
                module.commit_config(base)
        for value in (None, [], 'config'):
            with self.subTest(value=value), self.assertRaises(module.CommitError):
                module.commit_config(value)

    def test_oversized_request_and_unencodable_unicode_refused(self):
        for value in ('A=' + 'x' * module.LIMIT, 'A=\ud800'):
            base = base_config(); base['Env'] = [value]
            with self.subTest(size=len(value)), self.assertRaises(module.CommitError):
                module.commit_config(base)

    def test_sentinel_blocks_the_pinned_merge_fallback(self):
        runtime = {'Entrypoint': ['/usr/bin/env'], 'Cmd': ['TEST_ID=nonce', '/runner/installed_handoff.py']}
        # Minimal exact branch from v28.0.4 commit.go, not a daemon execution claim.
        user = module.commit_config(base_config())
        if len(user['Entrypoint'] or []) == 0:
            if len(user['Cmd'] or []) == 0:
                user['Cmd'] = runtime['Cmd']
            if user['Entrypoint'] is None:
                user['Entrypoint'] = runtime['Entrypoint']
        self.assertEqual(user['Cmd'], [])
        self.assertEqual(user['Entrypoint'], [''])


class EndpointTests(Base):
    def query(self, endpoint, mode=stat.S_IFSOCK, uid=0, code=0, body=None):
        data = body if body is not None else json.dumps([{'Endpoints': {'docker': {'Host': endpoint}}}]).encode()
        def run(command, **kwargs):
            self.assertEqual(command, ['docker', 'context', 'inspect'])
            self.assertEqual(kwargs['timeout'], 30)
            kwargs['stdout'].write(data)
            kwargs['stderr'].write(b'private diagnostics must not escape')
            return SimpleNamespace(returncode=code)
        with patch.dict(os.environ, {}, clear=True), patch.object(module.subprocess, 'run', side_effect=run), \
                patch.object(module.os, 'lstat', return_value=SimpleNamespace(st_mode=mode, st_uid=uid)):
            return module.local_endpoint()

    def test_only_two_rootful_local_context_sockets_accepted(self):
        for endpoint, path in module.SOCKETS.items():
            with self.subTest(endpoint=endpoint):
                self.assertEqual(self.query(endpoint), path)

    def test_remote_rootless_and_alias_endpoints_refused(self):
        for endpoint in ('tcp://localhost:2375', 'ssh://example', 'unix:///run/user/1000/docker.sock',
                         'unix:///tmp/docker.sock', 'unix:///var/run/../run/docker.sock', 'http://localhost', None):
            with self.subTest(endpoint=endpoint), self.assertRaises(module.CommitError):
                self.query(endpoint)
        for mode, uid in ((stat.S_IFREG, 0), (stat.S_IFLNK, 0), (stat.S_IFSOCK, 1000)):
            with self.subTest(mode=mode, uid=uid), self.assertRaises(module.CommitError):
                self.query('unix:///run/docker.sock', mode, uid)

    def test_any_docker_environment_override_refused_before_query(self):
        for key in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH',
                    'DOCKER_API_VERSION', 'DOCKER_CONFIG', 'DOCKER_CUSTOM_HEADERS'):
            with patch.dict(os.environ, {key: 'private override'}, clear=True), \
                    self.subTest(key=key), self.assertRaises(module.CommitError):
                module.local_endpoint()

    def test_failed_nonjson_duplicate_oversized_or_missing_context_refused_safely(self):
        for data in (b'private invalid JSON', b'[]', b'{}', b'[{}]', b'[' + b' ' * module.LIMIT + b']',
                     b'[{"Endpoints":{},"Endpoints":{}}]', b'[NaN]'):
            with self.subTest(data=data[:30]), self.assertRaises(module.CommitError) as failure:
                self.query('unix:///run/docker.sock', body=data)
            self.assertNotIn('private', str(failure.exception))
        with self.assertRaises(module.CommitError):
            self.query('unix:///run/docker.sock', code=1)

    def test_context_timeout_is_sanitized(self):
        with patch.dict(os.environ, {}, clear=True), \
                patch.object(module.subprocess, 'run', side_effect=subprocess.TimeoutExpired('PRIVATE VALUE', 30)), \
                self.assertRaises(module.CommitError) as failure:
            module.local_endpoint()
        self.assertNotIn('PRIVATE', str(failure.exception))


class WireTests(Base):
    def response(self, data=None, status=201, content_type='application/json', length=None):
        body = data if data is not None else json.dumps({'Id': IMAGE}).encode()
        result = Mock(status=status)
        result.getheader.side_effect = lambda key: content_type if key == 'Content-Type' else length
        result.read.return_value = body
        return result

    def absence(self):
        return self.response(data=b'{"message":"No such image"}', status=404)

    def call(self, response, base=None):
        connection = Mock()
        connection.getresponse.side_effect = [self.absence(), response]
        with patch.object(module, 'local_endpoint', return_value='/run/docker.sock') as endpoint, \
                patch.object(module, 'UnixHTTPConnection', return_value=connection) as factory:
            result = module.commit_image(NAME, base if base is not None else base_config())
        return result, connection, endpoint, factory

    def test_exact_post_api_version_empty_arrays_sentinel_full_env_and_private_tag(self):
        response = self.response()
        result, connection, endpoint, factory = self.call(response)
        self.assertEqual(result, IMAGE)
        endpoint.assert_called_once_with(); factory.assert_called_once_with('/run/docker.sock')
        method, target = connection.request.call_args.args
        self.assertEqual(method, 'POST')
        self.assertEqual(urlsplit(target).path, '/v1.48/commit')
        self.assertEqual(parse_qs(urlsplit(target).query), {'container': [NAME], 'pause': ['true'],
                         'repo': ['cachy-asahi-private-installed'], 'tag': ['a' * 32]})
        precheck = connection.request.call_args_list[0]
        self.assertEqual(precheck.args, ('GET', '/v1.48/images/cachy-asahi-private-installed%3A' + 'a' * 32 + '/json'))
        self.assertEqual(precheck.kwargs, {'headers': {'Accept': 'application/json'}})
        kwargs = connection.request.call_args.kwargs
        body = json.loads(kwargs['body'])
        self.assertEqual(body['Entrypoint'], ['']); self.assertEqual(body['Cmd'], [])
        self.assertEqual(body['Env'], base_config()['Env'])
        self.assertEqual(set(body), set(module.FIELDS)); self.assertNotIn('HostConfig', body)
        self.assertEqual(kwargs['headers'], {'Content-Type': 'application/json', 'Content-Length': str(len(kwargs['body']))})
        response.read.assert_called_once_with(module.LIMIT + 1)
        connection.close.assert_called_once_with()

    def test_nonempty_command_and_entry_preserved_on_wire(self):
        base = base_config(); base.update(Entrypoint=['/bin/sh', '-c'], Cmd=['printf test'])
        result, connection, unused, ignored = self.call(self.response(), base)
        self.assertEqual(json.loads(connection.request.call_args.kwargs['body']), base)

    def test_invalid_names_and_config_refused_before_endpoint_or_mutation(self):
        with patch.object(module, 'local_endpoint') as endpoint, patch.object(module, 'UnixHTTPConnection') as factory:
            for name in (None, NAME + '?repo=test', 'other-' + 'a' * 32, 'cachy-asahi-handoff-' + 'A' * 32, NAME + '\n'):
                with self.subTest(name=name), self.assertRaises(module.CommitError):
                    module.commit_image(name, base_config())
            with self.assertRaises(module.CommitError):
                module.commit_image(NAME, {'Env': 'private invalid config'})
            endpoint.assert_not_called(); factory.assert_not_called()

    def test_response_status_json_schema_identity_and_bounds_refused(self):
        responses = [self.response(status=code) for code in (200, 301, 400, 500)]
        responses += [self.response(data=data) for data in (b'PRIVATE RAW RESPONSE', b'[]', b'{"Id":NaN}',
                      b'{"Id":"x","Id":"y"}', json.dumps({'ID': IMAGE}).encode(),
                      json.dumps({'Id': IMAGE, 'message': 'PRIVATE'}).encode(), b'x' * (module.LIMIT + 1))]
        responses += [self.response(data=json.dumps({'Id': value}).encode()) for value in
                      ('latest', 'sha256:' + 'b' * 63, 'sha256:' + 'B' * 64, None, 1)]
        responses += [self.response(content_type=value) for value in (None, 'text/plain')]
        responses += [self.response(length=value) for value in ('-1', 'unknown', str(module.LIMIT + 1), '1', '9' * 5000)]
        for response in responses:
            with self.subTest(response=response), self.assertRaises(module.CommitError) as failure:
                self.call(response)
            self.assertNotIn('PRIVATE', str(failure.exception))

    def test_http_transport_failure_suppresses_raw_diagnostics_and_closes(self):
        for error in (OSError('PRIVATE VALUE'), module.http.client.HTTPException('PRIVATE RAW RESPONSE')):
            connection = Mock(); connection.request.side_effect = error
            with patch.object(module, 'local_endpoint', return_value='/run/docker.sock'), \
                    patch.object(module, 'UnixHTTPConnection', return_value=connection), \
                    self.subTest(error=error), self.assertRaises(module.CommitError) as failure:
                module.commit_image(NAME, base_config())
            self.assertNotIn('PRIVATE', str(failure.exception))
            connection.close.assert_called_once_with()

    def test_unix_transport_uses_only_af_unix_with_120_second_timeout(self):
        channel = Mock()
        with patch.object(module.socket, 'socket', return_value=channel) as create:
            connection = module.UnixHTTPConnection('/run/docker.sock')
            connection.connect()
        create.assert_called_once_with(socket.AF_UNIX, socket.SOCK_STREAM)
        channel.settimeout.assert_called_once_with(120)
        channel.connect.assert_called_once_with('/run/docker.sock')
        self.assertIs(connection.sock, channel)
        connection.close()

    def test_failed_unix_connect_closes_and_has_safe_error(self):
        channel = Mock(); channel.connect.side_effect = OSError('PRIVATE SOCKET ERROR')
        with patch.object(module.socket, 'socket', return_value=channel), self.assertRaises(module.CommitError) as failure:
            module.UnixHTTPConnection('/run/docker.sock').connect()
        self.assertNotIn('PRIVATE', str(failure.exception)); channel.close.assert_called_once_with()

    def test_valid_content_length_and_json_charset_accepted(self):
        data = json.dumps({'Id': IMAGE}).encode()
        result, unused, ignored, factory = self.call(self.response(data=data, length=str(len(data)), content_type='application/json; charset=utf-8'))
        self.assertEqual(result, IMAGE)

    def test_interruption_closes_transport_and_propagates_to_controller(self):
        connection = Mock(); connection.getresponse.side_effect = KeyboardInterrupt()
        with patch.object(module, 'local_endpoint', return_value='/run/docker.sock'), \
                patch.object(module, 'UnixHTTPConnection', return_value=connection), self.assertRaises(KeyboardInterrupt):
            module.commit_image(NAME, base_config())
        connection.close.assert_called_once_with()

    def test_cleanup_exception_suppresses_private_transport_diagnostic(self):
        connection = Mock(); connection.getresponse.side_effect = [self.absence(), self.response()]
        connection.close.side_effect = OSError('PRIVATE TRANSPORT DETAILS')
        with patch.object(module, 'local_endpoint', return_value='/run/docker.sock'), \
                patch.object(module, 'UnixHTTPConnection', return_value=connection), self.assertRaises(module.CommitError) as failure:
            module.commit_image(NAME, base_config())
        self.assertNotIn('PRIVATE', str(failure.exception))

    def test_recovery_tag_is_pure_and_bound_to_exact_owned_nonce(self):
        self.assertEqual(module.recovery_tag(NAME), 'cachy-asahi-private-installed:' + 'a' * 32)
        with self.assertRaises(module.CommitError):
            module.recovery_tag(NAME + '/foreign')

    def test_ownership_callback_after_404_before_post_exact_operation_order(self):
        events, connection = [], Mock()
        def request(method, path, **kwargs):
            events.append(method)
        def response():
            if events[-1] == 'GET':
                events.append('404')
                return self.absence()
            events.append('201')
            return self.response()
        def owned(tag):
            self.assertEqual(tag, module.recovery_tag(NAME))
            events.append('owned')
            self.assertEqual(connection.request.call_count, 1)
        connection.request.side_effect = request; connection.getresponse.side_effect = response
        with patch.object(module, 'local_endpoint', return_value='/run/docker.sock'), \
                patch.object(module, 'UnixHTTPConnection', return_value=connection):
            self.assertEqual(module.commit_image(NAME, base_config(), on_submit=owned), IMAGE)
        self.assertEqual(events, ['GET', '404', 'owned', 'POST', '201'])

    def test_occupied_or_failed_precheck_never_claims_ownership_or_posts(self):
        for status in (200, 301, 401, 403, 409, 500):
            connection, owned = Mock(), Mock()
            connection.getresponse.return_value = self.response(status=status)
            with self.subTest(status=status), patch.object(module, 'local_endpoint', return_value='/run/docker.sock'), \
                    patch.object(module, 'UnixHTTPConnection', return_value=connection), self.assertRaises(module.CommitError):
                module.commit_image(NAME, base_config(), on_submit=owned)
            owned.assert_not_called()
            self.assertEqual(connection.request.call_count, 1)
            self.assertEqual(connection.request.call_args.args[0], 'GET')
            connection.close.assert_called_once_with()

    def test_precheck_transport_or_invalid_404_body_never_claims_ownership(self):
        replies = [OSError('PRIVATE'), self.response(status=404, data=b'PRIVATE invalid'),
                   self.response(status=404, data=b'{"Id":"foreign"}'),
                   self.response(status=404, data=b'x' * (module.LIMIT + 1))]
        for reply in replies:
            connection, owned = Mock(), Mock()
            connection.getresponse.side_effect = [reply]
            with self.subTest(reply=reply), patch.object(module, 'local_endpoint', return_value='/run/docker.sock'), \
                    patch.object(module, 'UnixHTTPConnection', return_value=connection), self.assertRaises(module.CommitError) as failure:
                module.commit_image(NAME, base_config(), on_submit=owned)
            self.assertNotIn('PRIVATE', str(failure.exception))
            owned.assert_not_called(); self.assertEqual(connection.request.call_count, 1)

    def test_uncertain_post_reply_retains_callback_ownership(self):
        for reply in (self.response(data=b'PRIVATE malformed'), OSError('PRIVATE timeout'), KeyboardInterrupt()):
            connection, owned = Mock(), []
            connection.getresponse.side_effect = [self.absence(), reply]
            expected = KeyboardInterrupt if isinstance(reply, KeyboardInterrupt) else module.CommitError
            with self.subTest(reply=reply), patch.object(module, 'local_endpoint', return_value='/run/docker.sock'), \
                    patch.object(module, 'UnixHTTPConnection', return_value=connection), self.assertRaises(expected):
                module.commit_image(NAME, base_config(), on_submit=owned.append)
            self.assertEqual(owned, [module.recovery_tag(NAME)])
            self.assertEqual([call.args[0] for call in connection.request.call_args_list], ['GET', 'POST'])
            connection.close.assert_called_once_with()

    def test_race_after_absence_check_fails_without_releasing_claim(self):
        connection, owned = Mock(), []
        # A separate writer can act in the GET/POST gap: no atomic reservation
        # is claimed. The coordinator must keep the unique tag for failure cleanup.
        connection.getresponse.side_effect = [self.absence(), self.response(status=409)]
        with patch.object(module, 'local_endpoint', return_value='/run/docker.sock'), \
                patch.object(module, 'UnixHTTPConnection', return_value=connection), self.assertRaises(module.CommitError):
            module.commit_image(NAME, base_config(), on_submit=owned.append)
        self.assertEqual(owned, [module.recovery_tag(NAME)])
        self.assertEqual([call.args[0] for call in connection.request.call_args_list], ['GET', 'POST'])
        self.assertFalse(any(call.args[0] == 'DELETE' for call in connection.request.call_args_list))

    def test_close_failure_after_submission_retains_callback_ownership(self):
        connection, owned = Mock(), []
        connection.getresponse.side_effect = [self.absence(), self.response()]
        connection.close.side_effect = OSError('PRIVATE close failure')
        with patch.object(module, 'local_endpoint', return_value='/run/docker.sock'), \
                patch.object(module, 'UnixHTTPConnection', return_value=connection), self.assertRaises(module.CommitError):
            module.commit_image(NAME, base_config(), on_submit=owned.append)
        self.assertEqual(owned, [module.recovery_tag(NAME)])

    def test_callback_failure_blocks_post_without_removing_existing_ownership(self):
        connection, owned = Mock(), []
        connection.getresponse.return_value = self.absence()
        def callback(tag):
            owned.append(tag)
            raise KeyboardInterrupt()
        with patch.object(module, 'local_endpoint', return_value='/run/docker.sock'), \
                patch.object(module, 'UnixHTTPConnection', return_value=connection), self.assertRaises(KeyboardInterrupt):
            module.commit_image(NAME, base_config(), on_submit=callback)
        self.assertEqual(owned, [module.recovery_tag(NAME)])
        self.assertEqual(connection.request.call_count, 1)
        connection.close.assert_called_once_with()

    def test_noncallable_callback_refused_before_endpoint_or_precheck(self):
        with patch.object(module, 'local_endpoint') as endpoint, self.assertRaises(module.CommitError):
            module.commit_image(NAME, base_config(), on_submit='foreign tag')
        endpoint.assert_not_called()

    def test_unassigned_socket_closed_on_interrupt_and_other_exceptions(self):
        class Cancelled(BaseException):
            pass
        for method in ('settimeout', 'connect'):
            for error in (KeyboardInterrupt(), Cancelled(), ValueError('configuration failure')):
                channel = Mock(); getattr(channel, method).side_effect = error
                with self.subTest(method=method, error=type(error).__name__), \
                        patch.object(module.socket, 'socket', return_value=channel), self.assertRaises(type(error)) as failure:
                    module.UnixHTTPConnection('/run/docker.sock').connect()
                self.assertIs(failure.exception, error)
                channel.close.assert_called_once_with()

    def test_socket_cleanup_error_does_not_mask_connect_cancellation(self):
        channel = Mock(); interruption = KeyboardInterrupt()
        channel.connect.side_effect = interruption; channel.close.side_effect = OSError('PRIVATE cleanup')
        with patch.object(module.socket, 'socket', return_value=channel), self.assertRaises(KeyboardInterrupt) as failure:
            module.UnixHTTPConnection('/run/docker.sock').connect()
        self.assertIs(failure.exception, interruption)


if __name__ == '__main__':
    unittest.main()
