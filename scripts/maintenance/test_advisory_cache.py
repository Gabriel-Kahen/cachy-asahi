#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Private-tree controls with mocked public HTTPS and real child custody/publication."""
import copy
from email.message import Message
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import advisory_cache as m


def group():
    return dict(name='AVG-1', packages=['demo'], status='Unknown', severity='High',
                type='test advisory', affected='1-1', fixed=None, ticket=None,
                issues=['CVE-2026-12345'], advisories=['ASA-202610-1', 'ASA-202610-1'])


class Response(io.BytesIO):
    status, url = 200, m.a.URL

    def __init__(self, raw, headers=None):
        super().__init__(raw)
        self.headers = Message()
        for name, value in (headers if headers is not None else [
                ('Content-Type', 'application/json'), ('Content-Length', str(len(raw)))]):
            self.headers[name] = value


class Opener:
    def __init__(self, response): self.response = response
    def open(self, request, timeout):
        assert request.full_url == m.a.URL
        assert request.get_header('Accept-encoding') == 'identity'
        assert request.get_header('Authorization') is None
        assert request.get_header('Cookie') is None
        assert 0 < timeout <= 30
        return self.response


class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.output = self.base / 'snapshot'
        self.raw = m.a.encoded([group()])

    def fetch(self, response=None, **kwargs):
        response = Response(self.raw) if response is None else response
        with patch.object(m.urllib.request, 'build_opener', return_value=Opener(response)):
            return m.acquire(self.output, m.a.URL, **kwargs)

    def cli(self, *args):
        return subprocess.run([sys.executable, '-B', str(Path(m.__file__)), *map(str, args)],
                              cwd=self.base, capture_output=True, text=True, timeout=5)

    def test_acquisition_exact_original_bytes_and_offline_planner(self):
        result = self.fetch()
        self.assertEqual((self.output / 'advisories.json').read_bytes(), self.raw)
        metadata = m.a.decode((self.output / 'provenance.json').read_bytes())
        self.assertEqual(metadata['sha256'], m.a.pin(self.raw)['sha256'])
        self.assertEqual(metadata['transport']['request_count'], 1)
        self.assertEqual(metadata['transport']['redirects'], 0)
        self.assertTrue(metadata['transport']['supervision']['reaped'])
        self.assertEqual(metadata['transport']['supervision']['signals'], [])
        self.assertEqual(set(metadata['implementation']), set(m.SOURCES))
        inventory = self.base / 'inventory.json'
        inventory.write_bytes(m.a.encoded([dict(name='demo', version='1-1', arch='aarch64')]))
        status = m.a.main(['--inventory', str(inventory), '--advisories', str(self.output/'advisories.json'),
                           '--provenance', str(self.output/'provenance.json'), '--output', str(self.base/'review')])
        self.assertEqual(status, 0)
        report = m.a.decode((self.base/'review/report.json').read_bytes())
        finding = report['packages'][0]['findings'][0]
        self.assertEqual(finding['advisories'], group()['advisories'])
        self.assertEqual(finding['arm_applicability'], 'UNKNOWN')
        self.assertEqual(finding['version_relation'], 'UNKNOWN_NO_ARCH_FIXED_VERSION')
        self.assertEqual(result['arm_security_status'], 'UNKNOWN')

    def test_offline_verify_cli_and_api_without_any_socket(self):
        result = self.fetch()
        with (patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')),
             patch.object(m, 'transport', side_effect=AssertionError('transport forbidden'))):
            value = m.verify(self.output, result['snapshot_sha256'])
        self.assertEqual(value['status'], 'VERIFIED_RETAINED_DATA_OFFLINE')
        self.assertEqual(value['cache']['tracker_completeness'], 'UNKNOWN')
        command = self.cli('verify', '--snapshot', self.output, '--snapshot-sha256', result['snapshot_sha256'])
        self.assertEqual(command.returncode, 0, command.stderr)

    def test_private_snapshot_modes(self):
        self.fetch()
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        for path in self.output.iterdir():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.stat().st_nlink, 1)

    def test_existing_any_node_refused_before_transport(self):
        for make in (lambda: self.output.mkdir(), lambda: self.output.write_bytes(b'prior'),
                     lambda: self.output.symlink_to(self.base/'absent')):
            make()
            with patch.object(m, 'transport', side_effect=AssertionError('no GET')):
                with self.assertRaises(m.a.Error): self.fetch()
            if self.output.is_dir(): self.output.rmdir()
            else: self.output.unlink()

    def test_concurrent_output_not_overwritten(self):
        original = m.publish
        def raced(parent, stage, output, inode):
            self.output.mkdir()
            (self.output/'marker').write_bytes(b'other writer')
            original(parent, stage, output, inode)
        with patch.object(m, 'publish', side_effect=raced), self.assertRaises(FileExistsError):
            self.fetch()
        self.assertEqual((self.output/'marker').read_bytes(), b'other writer')
        self.assertEqual(list(self.base.iterdir()), [self.output])

    def test_post_rename_failure_preserves_complete_published_snapshot(self):
        original = m.publish
        def interrupted(*args):
            original(*args)
            raise OSError('synthetic post-rename failure')
        with patch.object(m, 'publish', side_effect=interrupted), self.assertRaises(OSError): self.fetch()
        self.assertEqual(set(p.name for p in self.output.iterdir()), set(m.FILES))
        checksum = m.a.pin((self.output/'snapshot.json').read_bytes())['sha256']
        self.assertEqual(m.verify(self.output, checksum)['arm_security_status'], 'UNKNOWN')

    def test_staging_substitution_not_published_or_deleted(self):
        original = m.publish
        def substituted(parent, stage, output, inode):
            os.rename(self.base/stage, self.base/'retained-original-stage')
            (self.base/stage).mkdir()
            (self.base/stage/'marker').write_bytes(b'other directory')
            original(parent, stage, output, inode)
        with patch.object(m, 'publish', side_effect=substituted), self.assertRaises(m.a.Error): self.fetch()
        self.assertFalse(self.output.exists())
        substitute = next(p for p in self.base.iterdir() if p.name.startswith('.advisory-'))
        self.assertEqual((substitute/'marker').read_bytes(), b'other directory')

    def test_invalid_body_never_published_and_stage_cleaned(self):
        for raw in (b'', b'<html>challenge</html>', b'[]', b'{"x":1,"x":2}',
                    m.a.encoded([dict(group(), issues=['invalid'])])):
            with self.subTest(raw=raw[:20]), self.assertRaises(ValueError):
                self.fetch(Response(raw))
            self.assertEqual(list(self.base.iterdir()), [])

    def test_chunked_or_absent_length_supported_with_exact_body(self):
        for extra in ([], [('Transfer-Encoding', 'chunked')]):
            response = Response(self.raw, [('Content-Type', 'application/json; charset=utf-8'), *extra])
            self.fetch(response)
            self.assertEqual((self.output/'advisories.json').read_bytes(), self.raw)
            for path in self.output.iterdir(): path.unlink()
            self.output.rmdir()

    def test_http_framing_encoding_and_type_rejections(self):
        variants = [[('Content-Type', 'text/html')], [('Content-Type', 'application/json'), ('Content-Encoding', 'gzip')],
                    [('Content-Type', 'application/json'), ('Content-Length', '-1')],
                    [('Content-Type', 'application/json'), ('Content-Length', str(len(self.raw)+1))],
                    [('Content-Type', 'application/json'), ('Content-Length', str(len(self.raw)-1))],
                    [('Content-Type', 'application/json'), ('Content-Length', '1'), ('Content-Length', '1')],
                    [('Content-Type', 'application/json'), ('Content-Type', 'application/json')],
                    [('Content-Type', 'application/json'), ('Transfer-Encoding', 'chunked'), ('Content-Length', '1')],
                    [('Content-Type', 'application/json'), ('Transfer-Encoding', 'gzip')], []]
        for headers in variants:
            with self.subTest(headers=headers), self.assertRaises(m.a.Error): self.fetch(Response(self.raw, headers))
            self.assertFalse(self.output.exists())

    def test_streamed_oversize_and_header_oversize_refused(self):
        for headers in ([('Content-Type', 'application/json')],
                        [('Content-Type', 'application/json'), ('Content-Length', str(len(self.raw)))]):
            with self.assertRaises(m.a.Error): self.fetch(Response(self.raw, headers), maximum=len(self.raw)-1)
            self.assertEqual(list(self.base.iterdir()), [])

    def test_unexpected_http_status_or_final_url_refused(self):
        for field, value in (('status', 304), ('status', 404), ('url', 'https://elsewhere.invalid/')):
            response = Response(self.raw); setattr(response, field, value)
            with self.assertRaises(m.a.Error): self.fetch(response)

    def test_redirects_refused_by_existing_handler(self):
        for url in (m.a.URL, 'https://security.archlinux.org/all.json', 'http://security.archlinux.org/',
                    'https://evil.invalid/', 'https://user:secret@security.archlinux.org/'):
            with self.assertRaises(m.sd.Error):
                m.sc.NoRedirect().redirect_request(None, None, 302, 'ignored', Message(), url)

    def test_no_environment_proxy_auth_or_ssl_overrides_copied(self):
        actual = m.urllib.request.build_opener
        observed = []
        def inspect(*handlers):
            opener = actual(*handlers)
            observed.extend(opener.handlers)
            return Opener(Response(self.raw))
        with (patch.dict(os.environ, {'HTTPS_PROXY': 'https://user:secret@evil.invalid/',
                                     'SSL_CERT_FILE': '/nonexistent', 'SSL_CERT_DIR': '/nonexistent'}),
              patch.object(m.urllib.request, 'build_opener', side_effect=inspect)):
            with tempfile.TemporaryFile() as stream:
                metadata = m.download(stream.fileno(), 1, m.a.CAP)
        self.assertFalse(any(isinstance(h, (m.urllib.request.HTTPBasicAuthHandler,
                                           m.urllib.request.HTTPCookieProcessor)) for h in observed))
        self.assertEqual(metadata['proxy'], 'DISABLED')

    def test_url_timeout_and_size_bounds_before_network(self):
        for url in ('http://security.archlinux.org/issues/all.json', m.a.URL+'?x=1', m.a.URL+'#x',
                    'https://user:pass@security.archlinux.org/issues/all.json', 'https://evil.invalid/'):
            with self.assertRaises(m.a.Error): m.settings(url, 1, 1)
        for seconds in (0, .1, 121, float('inf'), float('nan'), True):
            with self.assertRaises(m.a.Error): m.settings(m.a.URL, seconds, 1)
        for maximum in (0, m.a.CAP+1, True):
            with self.assertRaises(m.a.Error): m.settings(m.a.URL, 1, maximum)

    def test_wall_clock_timeout_reaps_real_child(self):
        def stall(*args): time.sleep(5)
        before = time.monotonic()
        with patch.object(m, 'download', side_effect=stall), self.assertRaises(m.a.Error):
            self.fetch(seconds=1)
        self.assertLess(time.monotonic()-before, 1.8)
        self.assertEqual(list(self.base.iterdir()), [])
        with self.assertRaises(ChildProcessError): os.waitpid(-1, os.WNOHANG)

    def test_stolen_child_custody_never_signals_or_probes_after_reap(self):
        original = m.op.supervise
        observed = []
        def stolen(pid, **kwargs):
            os.waitpid(pid, 0)
            with (patch.object(m.op.os, 'kill', side_effect=AssertionError('no numeric signal')),
                 patch.object(m.op, '_stat', side_effect=AssertionError('no numeric probe'))):
                outcome = original(pid, **kwargs)
                observed.append(outcome)
                return outcome
        with patch.object(m.op, 'supervise', side_effect=stolen), self.assertRaises(m.a.Error): self.fetch()
        self.assertEqual(observed[0]['ownership'], 'UNKNOWN')
        self.assertEqual(observed[0]['signals'], [])
        self.assertEqual(list(self.base.iterdir()), [])

    def test_tampering_any_file_refused_without_repair(self):
        result = self.fetch()
        for name in m.FILES:
            path = self.output/name; prior = path.read_bytes(); path.write_bytes(prior+b' ')
            with (patch.object(m, 'transport', side_effect=AssertionError('no refresh')),
                  self.assertRaises(m.a.Error)):
                m.verify(self.output, result['snapshot_sha256'])
            self.assertEqual(path.read_bytes(), prior+b' ')
            path.write_bytes(prior)

    def test_wrong_pin_extra_entry_modes_hardlinks_and_symlinks_refused(self):
        result = self.fetch(); checksum = result['snapshot_sha256']
        with self.assertRaises(m.a.Error): m.verify(self.output, '0'*64)
        extra = self.output/'extra'; extra.write_bytes(b'extra')
        with self.assertRaises(m.a.Error): m.verify(self.output, checksum)
        extra.unlink()
        target = self.output/'advisories.json'; prior = target.read_bytes()
        target.chmod(0o644)
        with self.assertRaises(m.sd.Error): m.verify(self.output, checksum)
        target.chmod(0o600); os.link(target, self.base/'hardlink')
        with self.assertRaises(m.sd.Error): m.verify(self.output, checksum)
        (self.base/'hardlink').unlink()
        target.unlink(); target.symlink_to(self.base/'absent')
        with self.assertRaises(OSError): m.verify(self.output, checksum)
        target.unlink(); target.write_bytes(prior); target.chmod(0o600)
        alias = self.base/'alias'; alias.symlink_to(self.output, target_is_directory=True)
        with self.assertRaises(OSError): m.verify(alias, checksum)

    def test_unsafe_parent_relative_path_and_fifo_never_fetch(self):
        alias = self.base/'alias'; alias.symlink_to(self.base, target_is_directory=True)
        for output in (alias/'new', Path('relative'), self.base/'..'/'escaped'):
            with (patch.object(m, 'transport', side_effect=AssertionError('no GET')),
                  self.assertRaises((OSError, m.a.Error))):
                m.acquire(output, m.a.URL)
        os.mkfifo(self.output)
        with (patch.object(m, 'transport', side_effect=AssertionError('no GET')),
              self.assertRaises(m.a.Error)):
            m.acquire(self.output, m.a.URL)

    def test_read_only_verify_stale_future_and_timestamp_preserved(self):
        result = self.fetch()
        meta_path = self.output/'provenance.json'; initial = meta_path.read_bytes()
        with patch.object(m.a, 'utc', wraps=m.a.utc):
            value = m.verify(self.output, result['snapshot_sha256'], '2099-01-01T00:00:00Z')
        self.assertTrue(value['cache']['cache_stale'])
        self.assertEqual(meta_path.read_bytes(), initial)
        with self.assertRaises(m.a.Error): m.verify(self.output, result['snapshot_sha256'], '2000-01-01T00:00:00Z')

    def test_cli_bad_arguments_and_failure_have_no_remote_echo(self):
        result = self.cli('acquire', '--url', 'https://user:secret@evil.invalid/', '--output', self.output)
        self.assertEqual(result.returncode, 2)
        for value in ('user', 'secret', 'evil.invalid'):
            self.assertNotIn(value, result.stdout + result.stderr)
        result = self.cli('verify', '--snapshot', self.output, '--snapshot-sha256', 'f'*64)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('evil', result.stderr)


if __name__ == '__main__':
    unittest.main()
