#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite manifest/transport controls using local streams; never access network."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import signal
import tempfile
import time
import unittest
import urllib.request

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fetch16k', HERE/'fetch_inputs.py')
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)


class Response(io.BytesIO):
    status = 200
    def __init__(self, data, url, headers=None):
        super().__init__(data); self.url = url; self.headers = headers or {}
    def geturl(self): return self.url


class Opener:
    def __init__(self, response): self.response = response; self.calls = 0
    def open(self, request, timeout):
        self.calls += 1; return self.response


class Controls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='fetch-controls-', dir=HERE)
        self.addCleanup(self.temp.cleanup); self.out = Path(self.temp.name)

    def item(self, data=b'bounded'):
        item = copy.deepcopy(f.EXPECTED[0]); item.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        return item

    def test_exact_manifest_and_drift_refusal(self):
        manifest, _ = f.load_manifest(HERE/'inputs.json')
        for mutate in (lambda v: v.update(schema=True), lambda v: v.update(extra=1),
                       lambda v: v['inputs'][0].update(bytes=262965559.0),
                       lambda v: v['inputs'][0].update(url='https://other.invalid/archive'),
                       lambda v: v['inputs'][0].update(sha256='0'*64),
                       lambda v: v['inputs'][1]['allowed_hosts'].append('other.invalid')):
            value = copy.deepcopy(manifest); mutate(value)
            path = self.out/'bad.json'; path.write_text(json.dumps(value))
            with self.assertRaises(ValueError): f.load_manifest(path)
        path.write_text('{"schema":1,"schema":1,"inputs":[]}')
        with self.assertRaises(ValueError): f.load_manifest(path)

    def test_transport_origin_refusals(self):
        for url in ('http://github.com/x', 'https://other.invalid/x', 'https://u@github.com/x',
                    'https://github.com:444/x', 'https://github.com/x#fragment'):
            with self.subTest(url=url), self.assertRaises(ValueError): f.allowed(url, ['github.com'])
        request = urllib.request.Request(f.EXPECTED[0]['url']); redirects = f.Redirects(['github.com', 'codeload.github.com'])
        target = 'https://codeload.github.com/AsahiLinux/linux/tar.gz/asahi-7.1.13-3'
        self.assertEqual(redirects.redirect_request(request, None, 302, '', {}, target).full_url, target)
        with self.assertRaises(ValueError): redirects.redirect_request(request, None, 302, '', {}, 'http://github.com/x')

    def test_single_attempt_success_and_provenance(self):
        item = self.item(); response = Response(b'bounded', item['url'], {'Content-Length': '7'})
        opener = Opener(response)
        receipt = f.fetch_one(item, self.out, time.monotonic()+1, opener)
        self.assertEqual(opener.calls, 1); self.assertEqual(receipt['attempts'], 1)
        self.assertEqual(receipt['sha256'], item['sha256']); self.assertEqual(receipt['final_url'], item['url'])
        self.assertEqual((self.out/item['filename']).read_bytes(), b'bounded')
        self.assertFalse((self.out/(item['filename']+'.partial')).exists())

    def test_short_overflow_corruption_and_headers_remove_partial(self):
        for payload, headers, url in [(b'short', {}, None), (b'bounded-extra', {}, None),
                                      (b'corrupt', {}, None), (b'bounded', {'Content-Length': '8'}, None),
                                      (b'bounded', {'Content-Encoding': 'gzip'}, None),
                                      (b'bounded', {}, 'https://other.invalid/x')]:
            with self.subTest(payload=payload, headers=headers, url=url):
                item = self.item(); response = Response(payload, url or item['url'], headers)
                with self.assertRaises(ValueError): f.fetch_one(item, self.out, time.monotonic()+1, Opener(response))
                self.assertEqual(list(self.out.iterdir()), [])

    def test_deadline_and_foreign_existing_file_preserved(self):
        item = self.item(); opener = Opener(Response(b'bounded', item['url']))
        with self.assertRaises(TimeoutError): f.fetch_one(item, self.out, time.monotonic()-1, opener)
        self.assertEqual(opener.calls, 0); self.assertEqual(list(self.out.iterdir()), [])
        partial = self.out/(item['filename']+'.partial'); partial.write_bytes(b'foreign')
        with self.assertRaises(FileExistsError): f.fetch_one(item, self.out, time.monotonic()+1, opener)
        self.assertEqual(partial.read_bytes(), b'foreign')

    def test_hard_deadline_interrupts_and_restores_alarm(self):
        handler = signal.getsignal(signal.SIGALRM)
        with self.assertRaises(TimeoutError):
            with f.deadline_alarm(.02): time.sleep(1)
        self.assertEqual(signal.getsignal(signal.SIGALRM), handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))


if __name__ == '__main__': unittest.main()
