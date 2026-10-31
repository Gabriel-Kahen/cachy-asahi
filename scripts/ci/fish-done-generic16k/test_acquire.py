# SPDX-License-Identifier: MIT
"""Inert transport controls: mocked network only, no source download or actors."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import urllib.error
import acquire_kernel as a

ROOT=next((p for p in Path(__file__).resolve().parents if (p/'scripts/virtual/generic16k/fetch_inputs.py').is_file()),None)
if ROOT is None:raise RuntimeError('repository source root unavailable')
spec=importlib.util.spec_from_file_location('unchanged_pinned_fetch',ROOT/'scripts/virtual/generic16k/fetch_inputs.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)


class Controls(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.out=Path(self.tmp.name)/'inputs';self.out.mkdir(mode=0o700)
        self.receipt=self.out.parent/'receipt.json';self.item=copy.deepcopy(f.EXPECTED[0])
        for target in ('subprocess.Popen','urllib.request.OpenerDirector.open'):
            guard=patch(target,side_effect=AssertionError('live actor/network forbidden'));guard.start();self.addCleanup(guard.stop)
        quiet=contextlib.redirect_stdout(io.StringIO());quiet.__enter__();self.addCleanup(quiet.__exit__,None,None,None)

    def result(self,url=None):return dict(final_url=url or a.URLS[0],bytes=a.SIZE,sha256=a.SHA)

    def call(self,fetch=f):return a.acquire(fetch,self.item,self.out,'a'*64,self.receipt)

    def test_primary_direct_tag_preserves_all_historical_pins(self):
        with patch.object(f,'fetch_one',return_value=self.result()) as call:
            report=self.call()
        args=call.call_args.args;self.assertEqual(args[0],dict(self.item,url=a.URLS[0],allowed_hosts=['codeload.github.com']))
        self.assertEqual(report['original_input'],self.item);self.assertEqual(len(report['attempts']),1)
        self.assertEqual(report['status'],'FETCHED_HASH_VERIFIED');self.assertTrue(report['partial_absent'])
        self.assertEqual(json.loads(self.receipt.read_text()),report)

    def test_one_429_fallback_is_explicit_capped_and_has_no_redirect(self):
        error=urllib.error.HTTPError(a.URLS[0],429,'rate limited',{'Retry-After':'999999'},None)
        with patch.object(f,'fetch_one',side_effect=[error,self.result(a.URLS[1])]) as call,patch.object(a.time,'sleep') as sleep:
            report=self.call()
        self.assertEqual(call.call_count,2);sleep.assert_called_once_with(10)
        self.assertEqual([r['requested_url'] for r in report['attempts']],list(a.URLS))
        self.assertEqual(report['attempts'][0]['http_status'],429)
        with self.assertRaises(ValueError):a.NoRedirect().redirect_request(None,None,None,None,None,None)

    def test_second_failure_stops_without_third_attempt(self):
        errors=[urllib.error.HTTPError(url,429,'rate',{},None) for url in a.URLS]
        with patch.object(f,'fetch_one',side_effect=errors) as call,patch.object(a.time,'sleep'):
            with self.assertRaises(urllib.error.HTTPError):self.call()
        self.assertEqual(call.call_count,2);report=json.loads(self.receipt.read_text())
        self.assertEqual(report['status'],'FAIL');self.assertEqual(len(report['attempts']),2)

    def test_hash_or_length_refusal_does_not_try_another_endpoint(self):
        with patch.object(f,'fetch_one',side_effect=ValueError('input length/hash mismatch')) as call,patch.object(a.time,'sleep') as sleep:
            with self.assertRaises(ValueError):self.call()
        self.assertEqual(call.call_count,1);sleep.assert_not_called()
        self.assertEqual(json.loads(self.receipt.read_text())['status'],'FAIL')

    def test_changed_historical_pin_refuses_before_network(self):
        self.item['sha256']='0'*64
        with patch.object(f,'fetch_one') as call:
            with self.assertRaises(ValueError):self.call()
        call.assert_not_called();self.assertFalse(self.receipt.exists())

    def test_nontransient_http_error_has_no_fallback(self):
        with patch.object(f,'fetch_one',side_effect=urllib.error.HTTPError(a.URLS[0],404,'missing',{},None)) as call:
            with self.assertRaises(urllib.error.HTTPError):self.call()
        self.assertEqual(call.call_count,1)

    def test_real_unchanged_reader_rejects_truncation_and_removes_partial(self):
        class Response:
            status=200;headers={}
            def geturl(self):return a.URLS[0]
            def __enter__(self):self.stream=io.BytesIO(b'inert truncated bytes');return self
            def __exit__(self,*_):self.stream.close()
            def read1(self,n):return self.stream.read(n)
        fake=SimpleNamespace(open=lambda *args,**kwargs:Response())
        with patch.object(a,'opener',return_value=fake):
            with self.assertRaisesRegex(ValueError,'input length/hash mismatch'):self.call()
        self.assertFalse((self.out/'kernel.tar.gz.partial').exists());self.assertFalse((self.out/'kernel.tar.gz').exists())
        self.assertEqual(len(json.loads(self.receipt.read_text())['attempts']),1)

    def test_hard_deadline_will_not_start_a_fallback(self):
        with patch.object(f,'fetch_one',side_effect=TimeoutError('network deadline')) as call,patch.object(a.time,'monotonic',side_effect=[0,299]),patch.object(a.time,'sleep') as sleep:
            with self.assertRaisesRegex(TimeoutError,'no remaining'):self.call()
        self.assertEqual(call.call_count,1);sleep.assert_not_called()


if __name__=='__main__':unittest.main()
