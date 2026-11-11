"""Bounded acquisition refusal fixtures; no network/install/compiler invocation."""
import hashlib
import io
import json
import http.server
import multiprocessing
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock
import acquisition as acq


class FailureDiagnosticTests(unittest.TestCase):
    def state(self):
        return {'binding_sha256': hashlib.sha256(b'a'*32).hexdigest(), 'phase':'ROOT_PREFLIGHT', 'input_ordinal':None, 'failure':None}

    def fixture(self, root):
        source=Path(acq.__file__).resolve().parents[3]
        for name in list(acq.PINS)+[acq.PREFIX+'embedded-config.txt']:
            target=root/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((source/name).read_bytes())

    def test_all35_exact_fetch_ordinals_are_observed_without_network(self):
        for wanted in range(35):
            with self.subTest(ordinal=wanted),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);self.fixture(root);state=self.state();calls=[]
                first=ValueError('HTTP acquisition failed: private=/home/secret token=NEVER_EXPORT')
                def fetch(item,*args):
                    ordinal=len(calls);calls.append(item['filename'])
                    if ordinal==wanted:raise first
                    return {'filename':item['filename']}
                with patch.object(acq,'fetch',side_effect=fetch),patch.object(acq,'http_download',side_effect=AssertionError('network forbidden')):
                    with self.assertRaises(ValueError) as caught:acq.acquire(root,root/'artifacts/kernel-native-stage/test',diagnostic=state)
                self.assertIs(caught.exception,first);record=state['failure']
                expected='PACKAGE_FETCH' if wanted<30 else 'ARCHIVE_FETCH' if wanted==30 else 'PATCH_FETCH' if wanted==31 else 'KEY_FETCH'
                self.assertEqual((record['phase'],record['input_ordinal'],record['refusal']),(expected,wanted,'HTTP_CHILD'))
                self.assertEqual(len(calls),wanted+1);self.assertNotIn('secret',str(record));self.assertLess(len(json.dumps(record)),512)

    def test_preflight_and_source_pins_are_not_relaxed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.fixture(root);name=next(iter(acq.PINS));(root/name).write_bytes(b'changed')
            state=self.state()
            with patch.object(acq,'fetch',side_effect=AssertionError('fetch after source refusal')):
                with self.assertRaisesRegex(ValueError,'frozen acquisition source differs') as caught:
                    acq.acquire(root,root/'artifacts/kernel-native-stage/test',diagnostic=state)
            acq.diagnostic_failure(state,caught.exception)
            self.assertEqual(state['failure']['phase'],'SOURCE_PINS');self.assertEqual(state['failure']['refusal'],'SOURCE_PIN')

    def test_dispatcher_failure_footer_is_closed_and_original_exception_is_held(self):
        import contextlib
        first=ValueError('input size/hash differs');stdout=io.StringIO()
        argv=['acquisition','--root','/owned','--output','/owned/new','--diagnostic-nonce','a'*32]
        with patch.object(sys,'argv',argv),patch.object(acq,'acquire',side_effect=first),contextlib.redirect_stdout(stdout):
            with self.assertRaises(ValueError) as caught:acq.main()
        self.assertIs(caught.exception,first);lines=stdout.getvalue().splitlines();self.assertEqual(len(lines),1)
        self.assertTrue(lines[0].startswith(acq.DIAGNOSTIC_PREFIX));record=json.loads(lines[0][len(acq.DIAGNOSTIC_PREFIX):])
        self.assertEqual(record['refusal'],'SIZE_HASH');self.assertEqual(record['binding_sha256'],hashlib.sha256(b'a'*32).hexdigest())
        self.assertNotIn('/owned',lines[0]);self.assertNotIn('a'*32,lines[0])

    def test_footer_write_failure_preserves_primary_and_secondary_control(self):
        first=ValueError('input size/hash differs');control=KeyboardInterrupt();prior=RuntimeError('prior');first.__cause__=prior
        argv=['acquisition','--root','/owned','--output','/owned/new','--diagnostic-nonce','a'*32]
        with patch.object(sys,'argv',argv),patch.object(acq,'acquire',side_effect=first),patch('builtins.print',side_effect=control):
            with self.assertRaises(ValueError) as caught:acq.main()
        self.assertIs(caught.exception,first);self.assertEqual(first.__cause__.exceptions,(prior,control))

    def test_success_and_direct_control_emit_no_diagnostic(self):
        import contextlib
        argv=['acquisition','--root','/owned','--output','/owned/new','--diagnostic-nonce','a'*32]
        for result in ({'owned':'success'},KeyboardInterrupt(),SystemExit(9)):
            stdout=io.StringIO()
            with patch.object(sys,'argv',argv),patch.object(acq,'acquire',side_effect=result if isinstance(result,BaseException) else None,return_value=result),contextlib.redirect_stdout(stdout):
                if isinstance(result,BaseException):
                    with self.assertRaises(type(result)) as caught:acq.main()
                    self.assertIs(caught.exception,result);self.assertEqual(stdout.getvalue(),'')
                else:self.assertEqual(acq.main(),0);self.assertNotIn(acq.DIAGNOSTIC_PREFIX,stdout.getvalue())

    def test_failure_context_is_first_and_refusal_strings_stay_private(self):
        state=self.state();acq.diagnostic_phase(state,'PACKAGE_FETCH',7)
        for error in (OSError('private /home/key'),ValueError('HTTP acquisition failed: password=secret')):
            acq.diagnostic_failure(state,error)
        self.assertEqual(state['failure']['error_kind'],'IO');self.assertEqual(state['failure']['refusal'],'UNKNOWN')
        self.assertEqual(state['failure']['input_ordinal'],7);self.assertNotIn('private',str(state['failure']))


class DelayedResponse(io.BytesIO):
    url='https://github.com/AsahiLinux/test/input.bin'
    headers={'Content-Length':'3'}
    def read(self,size=-1):
        time.sleep(2)
        return super().read(size)


class TrickleHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200);self.send_header('Content-Length','100');self.end_headers()
        try:
            for _ in range(100):
                self.wfile.write(b'a');self.wfile.flush();time.sleep(0.02)
        except (BrokenPipeError,ConnectionResetError): pass
    def log_message(self,*args): pass


def local_server(send):
    server=http.server.HTTPServer(('127.0.0.1',0),TrickleHandler)
    send.send(server.server_port);send.close()
    server.serve_forever(poll_interval=0.01)


class AcquisitionTests(unittest.TestCase):
    def setUp(self):
        self.work=tempfile.TemporaryDirectory();self.root=Path(self.work.name)
        self.item={'filename':'input.bin','size':3,'sha256':hashlib.sha256(b'abc').hexdigest(),
                   'url':'https://github.com/AsahiLinux/test/input.bin'}
    def tearDown(self):self.work.cleanup()

    def test_exact_hash_reuse(self):
        source=self.root/'source';source.write_bytes(b'abc');cache=self.root/'cache';cache.mkdir()
        with patch('urllib.request.build_opener',side_effect=AssertionError('network forbidden')):
            result=acq.fetch(self.item,cache,acq.Budget(),[source])
        self.assertEqual((cache/'input.bin').read_bytes(),b'abc');self.assertEqual(result['reused'],str(source))

    def test_wrong_reuse_is_rejected_without_network(self):
        source=self.root/'source';source.write_bytes(b'xyz');cache=self.root/'cache';cache.mkdir()
        with patch('urllib.request.build_opener',side_effect=AssertionError('network forbidden')):
            with self.assertRaises(ValueError):acq.fetch(self.item,cache,acq.Budget(),[source])
        self.assertEqual(list(cache.iterdir()),[])

    def test_symlink_reuse_is_rejected(self):
        source=self.root/'source';source.write_bytes(b'abc');link=self.root/'link';link.symlink_to(source)
        cache=self.root/'cache';cache.mkdir()
        with self.assertRaises(ValueError):acq.fetch(self.item,cache,acq.Budget(),[link])
        self.assertFalse((cache/'input.bin').exists())

    def test_symlink_output_parent_is_rejected(self):
        real=self.root/'real';real.mkdir();link=self.root/'link';link.symlink_to(real)
        with self.assertRaises(ValueError):acq.canonical(link/'new')

    def test_path_traversal_input_is_rejected(self):
        self.item['filename']='../input.bin'
        with self.assertRaises(ValueError):acq.record(self.item)

    def test_oversized_stream_is_rejected(self):
        with self.assertRaises(ValueError):acq.transfer(io.BytesIO(b'abcd'),io.BytesIO(),self.item,acq.Budget())

    def test_short_stream_is_rejected(self):
        with self.assertRaises(ValueError):acq.transfer(io.BytesIO(b'ab'),io.BytesIO(),self.item,acq.Budget())

    def test_same_size_wrong_hash_is_rejected(self):
        with self.assertRaises(ValueError):acq.transfer(io.BytesIO(b'xyz'),io.BytesIO(),self.item,acq.Budget())

    def test_total_cap_is_rejected(self):
        with self.assertRaises(ValueError):acq.transfer(io.BytesIO(b'abc'),io.BytesIO(),self.item,acq.Budget(maximum=2))

    def test_global_deadline_is_checked_each_read(self):
        with patch.object(acq.time,'monotonic',side_effect=[0,1,3]):
            budget=acq.Budget(seconds=2)
            with self.assertRaises(ValueError):acq.transfer(io.BytesIO(b'abc'),io.BytesIO(),self.item,budget)

    def test_source_redirect_is_exact(self):
        source={'url':'https://github.com/AsahiLinux/linux/archive/asahi-7.1.13-3.tar.gz'}
        self.assertTrue(acq.allowed_response(source,'https://codeload.github.com/AsahiLinux/linux/tar.gz/refs/tags/asahi-7.1.13-3'))
        self.assertFalse(acq.allowed_response(source,'https://codeload.github.com/AsahiLinux/linux/tar.gz/main'))
        self.assertFalse(acq.allowed_response(self.item,'https://example.org/input.bin'))

    def test_redirect_is_rejected_before_following(self):
        handler=acq.ExactRedirect(self.item)
        with self.assertRaises(ValueError):handler.redirect_request(None,None,302,'',{},'https://example.org/input.bin')

    def test_negative_size_is_rejected(self):
        self.item['size']=-1
        with self.assertRaises(ValueError):acq.record(self.item)

    def test_plain_http_is_rejected(self):
        self.item['url']='http://github.com/AsahiLinux/test/input.bin'
        with self.assertRaises(ValueError):acq.record(self.item)

    def test_existing_output_is_rejected(self):
        (self.root/'input.bin').write_bytes(b'abc')
        with self.assertRaises(ValueError):acq.fetch(self.item,self.root,acq.Budget())


    def test_delayed_read_is_interrupted_by_outer_deadline_and_reaped(self):
        cache=self.root/'cache';cache.mkdir()
        started=time.monotonic()
        with patch('urllib.request.OpenerDirector.open',return_value=DelayedResponse(b'abc')):
            with self.assertRaisesRegex(ValueError,'deadline'):
                acq.fetch(self.item,cache,acq.Budget(seconds=0.06))
        self.assertLess(time.monotonic()-started,0.5)
        self.assertEqual(list(cache.iterdir()),[])
        self.assertFalse(multiprocessing.active_children())

    def test_real_local_trickle_read_is_interrupted_and_child_reaped(self):
        context=multiprocessing.get_context('fork');receive,send=context.Pipe(duplex=False)
        server=context.Process(target=local_server,args=(send,));server.start();send.close()
        self.assertTrue(receive.poll(1));port=receive.recv();receive.close()
        local=dict(self.item,url=f'http://127.0.0.1:{port}/input',size=100,
                   sha256=hashlib.sha256(b'a'*100).hexdigest())
        try:
            with (self.root/'local-output').open('wb') as destination:
                started=time.monotonic()
                with self.assertRaisesRegex(ValueError,'deadline'):
                    acq.http_download(local,destination,acq.Budget(seconds=0.08))
                self.assertLess(time.monotonic()-started,0.5)
            self.assertEqual(multiprocessing.active_children(),[server])
        finally:
            server.terminate();server.join(timeout=1);self.assertFalse(server.is_alive());server.close()

    def test_cancellation_reaps_blocked_download_and_removes_partial(self):
        cache=self.root/'cache';cache.mkdir()
        real_join=multiprocessing.process.BaseProcess.join
        joins=[]
        def interrupted_join(process,timeout=None):
            joins.append(process.pid)
            if len(joins)==1: raise KeyboardInterrupt()
            return real_join(process,timeout)
        with patch('urllib.request.OpenerDirector.open',return_value=DelayedResponse(b'abc')):
            with patch.object(multiprocessing.process.BaseProcess,'join',interrupted_join):
                with self.assertRaises(KeyboardInterrupt):acq.fetch(self.item,cache,acq.Budget(seconds=1))
        self.assertEqual(list(cache.iterdir()),[])
        self.assertFalse(multiprocessing.active_children())
        with self.assertRaises(ProcessLookupError):os.kill(joins[0],0)


    def test_pending_spawn_signal_arrives_after_child_is_tracked(self):
        cache=self.root/'cache';cache.mkdir();real_mask=signal.pthread_sigmask;restores=[]
        def mask(how,signals):
            result=real_mask(how,signals)
            if how==signal.SIG_SETMASK:
                restores.append(how)
                if len(restores)==1:raise KeyboardInterrupt('pending spawn cancellation')
            return result
        with patch('urllib.request.OpenerDirector.open',return_value=DelayedResponse(b'abc')):
            with patch.object(signal,'pthread_sigmask',side_effect=mask):
                with self.assertRaisesRegex(KeyboardInterrupt,'spawn cancellation'):
                    acq.fetch(self.item,cache,acq.Budget(seconds=1))
        self.assertFalse(multiprocessing.active_children());self.assertEqual(list(cache.iterdir()),[])
        self.assertEqual(len(restores),2)

    def test_second_cancellation_deferred_until_cleanup_is_finished(self):
        class LateCancellation(KeyboardInterrupt):pass
        cache=self.root/'cache';cache.mkdir();real_mask=signal.pthread_sigmask;restores=[]
        def mask(how,signals):
            result=real_mask(how,signals)
            if how==signal.SIG_SETMASK:
                restores.append(how)
                if len(restores)==2:raise LateCancellation('pending cleanup cancellation')
            return result
        with patch('urllib.request.OpenerDirector.open',return_value=DelayedResponse(b'abc')):
            with patch.object(signal,'pthread_sigmask',side_effect=mask):
                with self.assertRaises(LateCancellation):acq.fetch(self.item,cache,acq.Budget(seconds=0.03))
        self.assertFalse(multiprocessing.active_children());self.assertEqual(list(cache.iterdir()),[])

    def test_term_default_is_restored_after_cancel_cleanup(self):
        previous=signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM,signal.SIG_DFL)
        try:
            with acq._term_cancellation():
                handler=signal.getsignal(signal.SIGTERM)
                with self.assertRaises(KeyboardInterrupt):handler(signal.SIGTERM,None)
            self.assertEqual(signal.getsignal(signal.SIGTERM),signal.SIG_DFL)
        finally:signal.signal(signal.SIGTERM,previous)


    def test_parent_death_guard_binds_expected_parent(self):
        libc=Mock();libc.prctl.return_value=0
        with patch.object(acq.ctypes,'CDLL',return_value=libc):
            with patch.object(acq.os,'getppid',return_value=123):acq._parent_death_guard(123)
        libc.prctl.assert_called_once_with(1,signal.SIGKILL,0,0,0)

    def test_parent_death_guard_refuses_orphan_race(self):
        libc=Mock();libc.prctl.return_value=0
        with patch.object(acq.ctypes,'CDLL',return_value=libc):
            with patch.object(acq.os,'getppid',return_value=1):
                with self.assertRaisesRegex(ValueError,'parent changed'):acq._parent_death_guard(123)


    def test_isolated_cli_help_imports_owned_common(self):
        result=subprocess.run([sys.executable,'-I','-B',str(Path(acq.__file__)), '--help'],
                              capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('--reuse-cache',result.stdout)


if __name__=='__main__':unittest.main()
