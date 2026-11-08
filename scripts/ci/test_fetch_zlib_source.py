"""Mocked transport behavior; no network, compiler, build or native actor."""
import contextlib
from email.message import Message
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

SPEC = importlib.util.spec_from_file_location('fixed_zlib_fetch', Path(__file__).with_name('fetch_zlib_source.py'))
F = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(F)
PAYLOAD = gzip.compress(b'controlled fixture archive', mtime=0)
FIXTURE_SHA = hashlib.sha256(PAYLOAD).hexdigest()


class Response:
    def __init__(self, body=PAYLOAD, code=200, headers=None, error_after=None, on_read=None):
        self.code = code
        self.headers = Message()
        for name, value in (headers or {'Content-Type': 'application/octet-stream'}).items():
            self.headers[name] = value
        self.body = io.BytesIO(body)
        self.closed = False
        self.error_after = error_after
        self.reads = 0
        self.on_read = on_read

    def read(self, amount):
        if self.on_read:
            self.on_read()
        if self.error_after is not None and self.reads >= self.error_after:
            raise URLError('https://release-assets.githubusercontent.com/SECRET?sig=PRIVATE')
        self.reads += 1
        return self.body.read(amount)

    def close(self):
        self.closed = True


class Transport:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append((request, timeout))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class FetchTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.output = self.directory / F.FILENAME

    def fetch(self, *responses, expected=FIXTURE_SHA, clock=None):
        transport = Transport(*responses)
        kwargs = dict(expected_sha256=expected, transport=transport)
        if clock is not None:
            kwargs['clock'] = clock
        return F._fetch(self.output, **kwargs), transport

    def refused(self, reason, *responses, **kwargs):
        with self.assertRaisesRegex(F.Refused, '^' + reason + '$'):
            self.fetch(*responses, **kwargs)
        self.assertFalse(os.path.lexists(self.output))
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_valid_payload_is_exclusive_mode600_and_receipt_has_no_signed_query(self):
        redirect = Response(code=302, headers={'Location': 'https://release-assets.githubusercontent.com/file?sig=PRIVATE'})
        response = Response(headers={'Content-Type': 'application/octet-stream', 'Content-Length': str(len(PAYLOAD))})
        result, transport = self.fetch(redirect, response)
        self.assertEqual(self.output.read_bytes(), PAYLOAD)
        info = self.output.stat()
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        self.assertEqual(info.st_nlink, 1)
        self.assertEqual(result['bytes'], len(PAYLOAD))
        self.assertEqual(result['sha256'], FIXTURE_SHA)
        self.assertEqual(result['redirects'], 1)
        self.assertNotIn('PRIVATE', json.dumps(result))
        self.assertEqual(list(self.directory.iterdir()), [self.output])
        self.assertTrue(redirect.closed and response.closed)
        for request, timeout in transport.requests:
            self.assertEqual(request.get_method(), 'GET')
            self.assertEqual({k.lower() for k, _ in request.header_items()}, {'accept', 'accept-encoding'})
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 10)

    def test_http_error_refused_without_body_or_fallback(self):
        headers = Message()
        headers['Content-Type'] = 'text/html'
        error = HTTPError(F.URL, 404, 'not found', headers, io.BytesIO(b'page'))
        transport = Transport(error)
        with self.assertRaisesRegex(F.Refused, '^http-status$'):
            F._fetch(self.output, expected_sha256=FIXTURE_SHA, transport=transport)
        self.assertEqual(len(transport.requests), 1)
        self.assertFalse(self.output.exists())

    def test_http200_html_and_octet_stream_page_refused(self):
        self.refused('content-type', Response(body=b'<html>page</html>', headers={'Content-Type': 'text/html'}))
        self.refused('gzip-magic', Response(body=b'<html>page</html>'), expected=hashlib.sha256(b'<html>page</html>').hexdigest())

    def test_wrong_hash_never_publishes(self):
        self.refused('sha256', Response(), expected='0' * 64)

    def test_encoded_response_refused(self):
        self.refused('content-encoding', Response(headers={'Content-Type': 'application/gzip', 'Content-Encoding': 'gzip'}))

    def test_advertised_oversize_and_stream_oversize_refused(self):
        self.refused('advertised-size', Response(headers={'Content-Type': 'application/gzip', 'Content-Length': str(F.MAX_BYTES + 1)}))
        self.refused('stream-size', Response(body=b'\x1f\x8b' + b'x' * F.MAX_BYTES))

    def test_declared_size_short_body_refused(self):
        self.refused('body-size', Response(headers={'Content-Type': 'application/gzip', 'Content-Length': str(len(PAYLOAD) + 1)}))

    def test_duplicate_security_header_refused(self):
        response = Response()
        response.headers['Content-Type'] = 'application/gzip'
        self.refused('duplicate-header', response)

    def test_redirect_bad_host_http_userinfo_and_fragment_refused(self):
        for target in ('https://evil.example/archive', 'http://release-assets.githubusercontent.com/file',
                       'https://user@release-assets.githubusercontent.com/file',
                       'https://release-assets.githubusercontent.com/file#fragment',
                       'https://release-assets.githubusercontent.com.evil.example/file'):
            with self.subTest(target=target):
                self.refused('redirect-origin', Response(code=302, headers={'Location': target}))

    def test_redirect_hop_cap_and_allowed_chain(self):
        redirects = [Response(code=302, headers={'Location': 'https://release-assets.githubusercontent.com/file?sig=PRIVATE'}) for _ in range(4)]
        self.refused('redirect-cap', *redirects)
        result, transport = self.fetch(*redirects[:3], Response())
        self.assertEqual(result['redirects'], 3)
        self.assertEqual(len(transport.requests), 4)

    def test_existing_output_and_symlink_refuse_before_transport(self):
        self.output.write_bytes(b'caller-owned')
        transport = Transport()
        with self.assertRaisesRegex(F.Refused, '^destination-exists$'):
            F._fetch(self.output, expected_sha256=FIXTURE_SHA, transport=transport)
        self.assertEqual(self.output.read_bytes(), b'caller-owned')
        self.assertEqual(transport.requests, [])
        self.output.unlink()
        target = self.directory / 'target'
        target.write_bytes(b'keep')
        self.output.symlink_to(target)
        with self.assertRaisesRegex(F.Refused, '^destination-exists$'):
            F._fetch(self.output, expected_sha256=FIXTURE_SHA, transport=transport)
        self.assertTrue(self.output.is_symlink())
        self.assertEqual(target.read_bytes(), b'keep')

    def test_parent_symlink_refused(self):
        parent = self.directory / 'actual'
        parent.mkdir()
        link = self.directory / 'link'
        link.symlink_to(parent, target_is_directory=True)
        with self.assertRaisesRegex(F.Refused, '^parent-symlink$'):
            F._fetch(link / F.FILENAME, expected_sha256=FIXTURE_SHA, transport=Transport())
        self.assertEqual(list(parent.iterdir()), [])

    def test_publication_collision_preserves_new_caller_file(self):
        def collide():
            if not self.output.exists():
                self.output.write_bytes(b'new-caller-file')
        with self.assertRaisesRegex(F.Refused, '^destination-exists$'):
            self.fetch(Response(on_read=collide))
        self.assertEqual(self.output.read_bytes(), b'new-caller-file')
        self.assertEqual(list(self.directory.iterdir()), [self.output])

    def test_partial_transport_failure_cleans_temporary_not_final(self):
        self.refused('transport', Response(body=b'\x1f\x8b' + b'x' * 100000, error_after=1))

    def test_deadline_checked_each_chunk(self):
        ticks = iter((0, 0, 0, F.SECONDS + 1))
        self.refused('deadline', Response(), clock=lambda: next(ticks))

    def test_fixed_filename_and_cli_pin_cannot_be_overridden(self):
        with self.assertRaisesRegex(F.Refused, '^fixed-filename$'):
            F._fetch(self.directory / 'other.gz', expected_sha256=FIXTURE_SHA, transport=Transport())
        fake = Transport(Response())
        with patch.object(F, 'build_opener', return_value=fake):
            with self.assertRaisesRegex(F.Refused, '^sha256$'):
                F.fetch_source(self.output)
        self.assertEqual(fake.requests[0][0].full_url, F.URL)
        self.assertFalse(self.output.exists())

    def test_existing_temporary_collision_is_not_removed(self):
        temporary = self.directory / ('.' + F.FILENAME + '.fixed.part')
        temporary.write_bytes(b'caller-temporary')
        with patch.object(F.secrets, 'token_hex', return_value='fixed'):
            with self.assertRaisesRegex(F.Refused, '^filesystem$'):
                self.fetch(Response())
        self.assertEqual(temporary.read_bytes(), b'caller-temporary')
        self.assertFalse(self.output.exists())

    def test_cli_receipt_is_safe_exclusive_mode600(self):
        receipt = self.directory / 'zlib-source-retrieval.json'
        output = io.StringIO()
        with patch.object(F, 'build_opener', return_value=Transport(Response())), contextlib.redirect_stdout(output):
            self.assertEqual(F.main(['--output', str(self.output), '--receipt', str(receipt)]), 1)
        result = json.loads(receipt.read_bytes())
        self.assertEqual(result['status'], 'REFUSED')
        self.assertEqual(result['reason'], 'sha256')
        self.assertEqual(json.loads(output.getvalue()), result)
        self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
        self.assertFalse(self.output.exists())
        original = receipt.read_bytes()
        with patch.object(F, 'fetch_source') as fetch, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(F.main(['--output', str(self.output), '--receipt', str(receipt)]), 1)
        fetch.assert_not_called()
        self.assertEqual(receipt.read_bytes(), original)

    def test_cli_safe_refusal_receipt_and_alarm_cleanup(self):
        output = io.StringIO()
        with patch.object(F, 'fetch_source', side_effect=F.Refused('sha256')), contextlib.redirect_stdout(output):
            self.assertEqual(F.main(['--output', str(self.output)]), 1)
        result = json.loads(output.getvalue())
        self.assertEqual(result['status'], 'REFUSED')
        self.assertEqual(result['reason'], 'sha256')
        self.assertEqual(result['source_url'], F.URL)

    def sources(self, *responses, clock=None):
        transport = Transport(*responses)
        kwargs = {} if clock is None else {'clock': clock}
        return F._fetch_sources(self.output, expected_sha256=FIXTURE_SHA,
                                transport=transport, **kwargs), transport

    def test_primary_direct_success_never_calls_fallback(self):
        result, transport = self.sources(Response())
        self.assertEqual([r.full_url for r, _ in transport.requests], [F.URL])
        self.assertEqual(result['source_url'], F.URL)
        self.assertEqual(len(result['attempts']), 1)

    def test_open_failure_uses_only_fixed_fallback_and_safe_receipt(self):
        error = URLError('https://example.invalid/SECRET?sig=PRIVATE')
        result, transport = self.sources(error, Response(code=302, headers={
            'Location': 'https://release-assets.githubusercontent.com/file?sig=PRIVATE'}), Response())
        self.assertEqual([r.full_url for r, _ in transport.requests][:2], [F.URL, F.FALLBACK_URL])
        self.assertEqual(result['source_url'], F.FALLBACK_URL)
        self.assertEqual(result['attempts'][0]['phase'], 'open')
        self.assertNotIn('PRIVATE', json.dumps(result))

    def test_primary_availability_status_uses_fallback_without_reading_page(self):
        primary = Response(body=b'not an archive', code=503)
        result, transport = self.sources(primary, Response())
        self.assertEqual(primary.reads, 0)
        self.assertTrue(primary.closed)
        self.assertEqual(result['attempts'][0]['http_status'], 503)
        self.assertEqual(len(transport.requests), 2)

    def test_primary_415_http_error_uses_exact_fixed_fallback_without_body_read(self):
        headers = Message()
        headers['Content-Type'] = 'text/html'
        body = io.BytesIO(b'PRIVATE error page')
        error = HTTPError(F.URL, 415, 'unsupported media type', headers, body)
        with patch.object(body, 'read', side_effect=AssertionError('error body must not be read')):
            result, transport = self.sources(error, Response())
        self.assertTrue(body.closed)
        self.assertEqual([r.full_url for r, _ in transport.requests], [F.URL, F.FALLBACK_URL])
        self.assertEqual(result['sha256'], FIXTURE_SHA)
        self.assertEqual(result['total_received_bytes'], len(PAYLOAD))
        self.assertEqual(result['attempts'][0]['http_status'], 415)
        self.assertEqual(result['attempts'][0]['bytes'], 0)
        self.assertNotIn('PRIVATE', json.dumps(result))
        for request, _ in transport.requests:
            self.assertEqual(request.get_method(), 'GET')
            self.assertIsNone(request.data)
            self.assertFalse(request.has_header('Content-Type'))
            self.assertFalse(request.has_header('Content-Encoding'))
            self.assertEqual(request.get_header('Accept-encoding'), 'identity')

    def test_415_fallback_still_enforces_integrity_and_never_tries_a_third_endpoint(self):
        for fallback, reason in ((Response(code=415), 'http-status'),
                                 (Response(body=PAYLOAD + b'x'), 'sha256'),
                                 (Response(headers={'Content-Type': 'text/html'}), 'content-type'),
                                 (Response(code=302, headers={'Location': 'https://evil.example/archive'}), 'redirect-origin')):
            with self.subTest(reason=reason):
                primary = Response(code=415)
                transport = Transport(primary, fallback)
                with self.assertRaisesRegex(F.Refused, '^' + reason + '$'):
                    F._fetch_sources(self.output, expected_sha256=FIXTURE_SHA, transport=transport)
                self.assertEqual(len(transport.requests), 2)
                self.assertEqual(primary.reads, 0)
                self.assertTrue(primary.closed and fallback.closed)
                self.assertEqual(list(self.directory.iterdir()), [])

    def test_primary_partial_read_failure_cleans_and_shares_bytes(self):
        primary = Response(body=PAYLOAD, error_after=1)
        result, transport = self.sources(primary, Response())
        self.assertEqual(result['total_received_bytes'], 2 * len(PAYLOAD))
        self.assertEqual(result['attempts'][0]['phase'], 'read')
        self.assertEqual(list(self.directory.iterdir()), [self.output])

    def test_integrity_and_policy_failures_do_not_fallback(self):
        cases = [('sha256', Response(body=PAYLOAD + b'x')),
                 ('content-type', Response(headers={'Content-Type': 'text/html'})),
                 ('primary-redirect', Response(code=302, headers={'Location': F.FALLBACK_URL})),
                 ('http-status', Response(code=403))]
        for reason, response in cases:
            with self.subTest(reason=reason):
                transport = Transport(response)
                with self.assertRaisesRegex(F.Refused, '^' + reason + '$'):
                    F._fetch_sources(self.output, expected_sha256=FIXTURE_SHA, transport=transport)
                self.assertEqual(len(transport.requests), 1)
                self.assertEqual(list(self.directory.iterdir()), [])

    def test_filesystem_failure_does_not_fallback(self):
        transport = Transport(Response())
        with patch.object(F.secrets, 'token_hex', return_value='fixed'):
            partial = self.directory / ('.' + F.FILENAME + '.fixed.part')
            partial.write_bytes(b'caller')
            with self.assertRaisesRegex(F.Refused, '^filesystem$'):
                F._fetch_sources(self.output, expected_sha256=FIXTURE_SHA, transport=transport)
        self.assertEqual(len(transport.requests), 1)
        self.assertEqual(partial.read_bytes(), b'caller')

    def test_both_unavailable_have_no_third_request_and_safe_receipt(self):
        transport = Transport(URLError('PRIVATE'), URLError('PRIVATE'))
        with self.assertRaises(F.Refused) as caught:
            F._fetch_sources(self.output, expected_sha256=FIXTURE_SHA, transport=transport)
        self.assertEqual(len(transport.requests), 2)
        self.assertEqual(len(caught.exception.facts['attempts']), 2)
        self.assertNotIn('PRIVATE', json.dumps(caught.exception.facts))
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_shared_deadline_expires_before_fallback_request(self):
        ticks = iter((0, 0, F.SECONDS + 1))
        transport = Transport(URLError('unavailable'))
        with self.assertRaisesRegex(F.Refused, '^deadline$'):
            F._fetch_sources(self.output, expected_sha256=FIXTURE_SHA,
                             transport=transport, clock=lambda: next(ticks))
        self.assertEqual(len(transport.requests), 1)

    def test_shared_stream_budget_refuses_second_body_and_cleans(self):
        primary = Response(body=b'\x1f\x8b' + b'x' * 1100000, error_after=17)
        transport = Transport(primary, Response(body=b'\x1f\x8b' + b'x' * 1100000))
        with self.assertRaisesRegex(F.Refused, '^stream-size$') as caught:
            F._fetch_sources(self.output, expected_sha256=FIXTURE_SHA, transport=transport)
        self.assertEqual(caught.exception.facts['total_received_bytes'], F.MAX_BYTES + 1)
        self.assertEqual(len(transport.requests), 2)
        self.assertEqual(list(self.directory.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
