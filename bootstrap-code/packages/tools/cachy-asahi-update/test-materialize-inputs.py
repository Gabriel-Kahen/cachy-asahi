#!/usr/bin/env python3
"""Finite mocked HTTPS/process fixtures only; no Cargo or network in tests."""
import hashlib
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

BASE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('materialize',BASE/'materialize-inputs.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


class Response(io.BytesIO):
    status=200
    url='https://static.crates.io/crates/fixture/fixture-1.crate'


class MaterializerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='cachy-materializer-test-');self.root=Path(self.temp.name)

    def tearDown(self): self.temp.cleanup()

    def fetch(self,data=b'fixture',size=7,pin=None,url=Response.url):
        response=Response(data)
        opener=SimpleNamespace(open=lambda *_args,**_kwargs:response)
        return m.fetch(url,self.root/'fixture',pin or hashlib.sha256(b'fixture').hexdigest(),size,time.monotonic()+3,opener)

    def test_exact_https_data_and_fresh_destination(self):
        self.assertEqual(self.fetch(),7)
        self.assertEqual((self.root/'fixture').read_bytes(),b'fixture')
        with self.assertRaises(m.MaterializeError): self.fetch()

    def test_wrong_hash_oversize_and_truncation_leave_no_success_input(self):
        for data in (b'changed',b'fixture-extra',b'short'):
            with self.subTest(data=data),self.assertRaises(m.MaterializeError):self.fetch(data)
            self.assertFalse((self.root/'fixture').exists());self.assertFalse((self.root/'fixture.partial').exists())

    def test_http_other_host_and_redirect_refused(self):
        for url in ('http://static.crates.io/x','https://example.com/x','https://user@static.crates.io/x'):
            with self.subTest(url=url),self.assertRaises(m.MaterializeError):self.fetch(url=url)
        redirect=m.ExactHTTPS()
        request=SimpleNamespace(full_url=Response.url)
        with self.assertRaises(m.MaterializeError):redirect.redirect_request(request,None,302,'',{},'http://static.crates.io/x')
        with self.assertRaises(m.MaterializeError):redirect.redirect_request(request,None,302,'',{},'https://elsewhere/x')

    def test_external_pin_drift_fails_before_any_generator_import(self):
        m.save(self.root/'materializer-result.json',{'schema_version':1,'scope':'private source materialization','status':'RUNNING','phase':'launch-data-worker','runner_inputs_sha256':'0'*64})
        with mock.patch.object(m,'module') as module,self.assertRaises(m.MaterializeError):
            m.reconstruct(self.root,'0'*64)
        module.assert_not_called()

    def test_real_frozen_source_pin_set_verifies(self):
        pin=hashlib.sha256((BASE/'runner-inputs.lock.json').read_bytes()).hexdigest()
        self.assertEqual(m.verify_pins(pin)['registry_packages'],167)

    def test_decoded_tar_drift_and_expansion_refused(self):
        path=self.root/'data.gz';path.write_bytes(gzip.compress(b'fixture',mtime=0))
        with mock.patch.dict(m.TAR_INPUTS,sanitized=(hashlib.sha256(b'fixture').hexdigest(),7)):
            self.assertEqual(m.tar_identity(path,'sanitized'),hashlib.sha256(b'fixture').hexdigest())
        for expected,size in (('0'*64,7),(hashlib.sha256(b'fixture').hexdigest(),6)):
            with mock.patch.dict(m.TAR_INPUTS,sanitized=(expected,size)),self.assertRaises(m.MaterializeError):
                m.tar_identity(path,'sanitized')

    def test_portable_factory_restored_after_generator_error(self):
        original=gzip.GzipFile;portable=m.module('portable-gzip.py')
        with self.assertRaisesRegex(ValueError,'generator failed'):
            with m.portable_encoding(portable):
                self.assertIs(gzip.GzipFile,portable.GzipFile)
                raise ValueError('generator failed')
        self.assertIs(gzip.GzipFile,original)

    def test_special_and_aggregate_private_data_refused(self):
        (self.root/'link').symlink_to('/etc/hosts')
        with self.assertRaises(m.MaterializeError):m.disk_bound(self.root)
        (self.root/'link').unlink();(self.root/'file').write_bytes(b'12345')
        with mock.patch.dict(m.LIMITS,retained_bytes=4),self.assertRaises(m.MaterializeError):m.disk_bound(self.root)

    def test_mismatched_effective_user_refused_before_reads(self):
        with mock.patch.object(m.os,'getuid',return_value=1000),mock.patch.object(m.os,'geteuid',return_value=0),mock.patch.object(m,'verify_pins') as pins:
            with self.assertRaises(m.MaterializeError):m.run(self.root/'out','a'*64)
        pins.assert_not_called()

    def test_cancellation_during_wait_kills_owned_group_and_durable_cancel(self):
        output=self.root/'out'
        child=mock.Mock(pid=987654,returncode=-9)
        child.wait.side_effect=[m.Cancelled(),None]
        with mock.patch.object(m,'verify_pins'),mock.patch.object(m.subprocess,'Popen',return_value=child),mock.patch.object(m.os,'killpg') as kill:
            with self.assertRaises(m.Cancelled):m.run(output,'a'*64)
        kill.assert_called_once_with(987654,signal.SIGKILL)
        self.assertEqual(json.loads((output/'materializer-result.json').read_bytes())['status'],'CANCELLED')

    def test_real_spawn_registration_cancellation_reaps_group_and_restores_masks(self):
        driver=self.root/'spawn-driver.py'
        driver.write_text('''import importlib.util,json,os,signal,subprocess,sys,time
from pathlib import Path
from unittest import mock
spec=importlib.util.spec_from_file_location('materializer',sys.argv[1]);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
output=Path(sys.argv[2]);signum=int(sys.argv[3]);owned=[]
signal.signal(signum,lambda *_:(_ for _ in ()).throw(m.Cancelled()))
before=signal.pthread_sigmask(signal.SIG_BLOCK,[]);real_spawn=subprocess.Popen
def spawn(_command,**kwargs):
 code="import json,signal,time;from pathlib import Path;Path("+repr(str(output/'mask.json'))+").write_text(json.dumps(sorted(int(s) for s in signal.pthread_sigmask(signal.SIG_BLOCK,[]))));time.sleep(20)"
 child=real_spawn([sys.executable,'-I','-c',code],**kwargs);owned.append(child)
 deadline=time.monotonic()+3
 while not (output/'mask.json').exists():
  if time.monotonic()>deadline:raise RuntimeError('fixture startup deadline')
  time.sleep(.005)
 os.kill(os.getpid(),signum) # Real signal after fork/session and before assignment.
 return child
try:
 with mock.patch.object(m,'verify_pins'),mock.patch.object(m.subprocess,'Popen',side_effect=spawn):
  try:m.run(output,'a'*64)
  except m.Cancelled:pass
 result=json.loads((output/'materializer-result.json').read_bytes())
 after=signal.pthread_sigmask(signal.SIG_BLOCK,[])
 try:os.killpg(owned[0].pid,0);absent=False
 except ProcessLookupError:absent=True
 print(json.dumps({'status':result['status'],'group_absent':absent,'parent_mask_restored':before==after,
  'child_mask_restored':json.loads((output/'mask.json').read_bytes())==sorted(int(s) for s in before),
  'reaped':owned[0].returncode is not None}))
finally:
 for child in owned:
  try:os.killpg(child.pid,signal.SIGKILL)
  except ProcessLookupError:pass
  child.wait(timeout=3)
''')
        for signum in (signal.SIGTERM,signal.SIGINT,signal.SIGALRM):
            with self.subTest(signal=signum):
                result=subprocess.run([sys.executable,'-I',str(driver),str(BASE/'materialize-inputs.py'),
                                       str(self.root/('spawn-'+str(int(signum)))),str(int(signum))],
                                      capture_output=True,text=True,timeout=10)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(json.loads(result.stdout),{'status':'CANCELLED','group_absent':True,
                    'parent_mask_restored':True,'child_mask_restored':True,'reaped':True})

    def test_spawn_error_restores_parent_mask(self):
        before=signal.pthread_sigmask(signal.SIG_BLOCK,[])
        with mock.patch.object(m,'verify_pins'),mock.patch.object(m.subprocess,'Popen',side_effect=OSError('fixture spawn')):
            with self.assertRaises(OSError):m.run(self.root/'out','a'*64)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK,[]),before)
        self.assertEqual(json.loads((self.root/'out/materializer-result.json').read_bytes())['status'],'FAIL')

    def test_cancel_during_first_handler_installation_is_durable_without_spawn(self):
        real_signal=signal.signal;calls=[]
        before=signal.pthread_sigmask(signal.SIG_BLOCK,[])
        handlers={s:signal.getsignal(s) for s in (signal.SIGTERM,signal.SIGINT)}
        def install(signum,handler):
            previous=real_signal(signum,handler);calls.append(signum)
            if len(calls)==1:os.kill(os.getpid(),signal.SIGTERM)
            return previous
        with mock.patch.object(m,'verify_pins'),mock.patch.object(m.subprocess,'Popen') as spawn,\
             mock.patch.object(m.signal,'signal',side_effect=install):
            with self.assertRaises(m.Cancelled):m.run(self.root/'out','a'*64)
        spawn.assert_not_called()
        self.assertEqual(json.loads((self.root/'out/materializer-result.json').read_bytes())['status'],'CANCELLED')
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK,[]),before)
        self.assertEqual({s:signal.getsignal(s) for s in handlers},handlers)

    def test_wait_failure_and_cleanup_signal_still_kill_reap_and_save(self):
        output=self.root/'out';child=mock.Mock(pid=987654,returncode=-9)
        child.wait.side_effect=[OSError('fixture wait failure'),None]
        def kill(*_args):signal.raise_signal(signal.SIGTERM)
        with mock.patch.object(m,'verify_pins'),mock.patch.object(m.subprocess,'Popen',return_value=child),\
             mock.patch.object(m.os,'killpg',side_effect=kill) as killed:
            with self.assertRaises(OSError):m.run(output,'a'*64)
        killed.assert_called_once_with(child.pid,signal.SIGKILL)
        self.assertEqual(child.wait.call_count,2)
        self.assertEqual(json.loads((output/'materializer-result.json').read_bytes())['status'],'CANCELLED')

    def test_cleanup_cancellation_cannot_preserve_pass(self):
        output=self.root/'out'
        child=mock.Mock(pid=987654,returncode=0)
        def spawn(*_args,**_kwargs):
            m.save(output/'materializer-result.json',{'schema_version':1,'scope':'private source materialization','status':'PASS'})
            return child
        def kill(*_args): signal.raise_signal(signal.SIGTERM)
        with mock.patch.object(m,'verify_pins'),mock.patch.object(m.subprocess,'Popen',side_effect=spawn),mock.patch.object(m.os,'killpg',side_effect=kill):
            with self.assertRaises(m.Cancelled):m.run(output,'a'*64)
        self.assertEqual(json.loads((output/'materializer-result.json').read_bytes())['status'],'CANCELLED')

    def test_late_final_commit_signal_cannot_preserve_pass(self):
        output=self.root/'out'
        child=mock.Mock(pid=987654,returncode=0)
        original_save=m.save
        writes=[]
        def save(path,value):
            original_save(path,value)
            writes.append(value['status'])
            if len(writes)==3:signal.raise_signal(signal.SIGTERM)
        def spawn(*_args,**_kwargs):
            m.save(output/'materializer-result.json',{'schema_version':1,'scope':'private source materialization','status':'PASS'})
            return child
        with mock.patch.object(m,'verify_pins'),mock.patch.object(m.subprocess,'Popen',side_effect=spawn),mock.patch.object(m.os,'killpg'),mock.patch.object(m,'save',side_effect=save):
            with self.assertRaises(m.Cancelled):m.run(output,'a'*64)
        self.assertEqual(json.loads((output/'materializer-result.json').read_bytes())['status'],'CANCELLED')
        self.assertEqual(writes[-1],'CANCELLED')

    def test_direct_child_refuses_nonprivate_or_missing_launch_receipt(self):
        for mode in (0o755,0o700):
            output=self.root/('out-'+str(mode));output.mkdir(mode=mode)
            with mock.patch.object(m,'module') as module,mock.patch.object(m,'verify_pins') as pins:
                with self.assertRaises(m.MaterializeError):m.reconstruct(output,'a'*64)
            pins.assert_not_called();module.assert_not_called()
        output=self.root/'source-link';output.symlink_to(self.root)
        with self.assertRaises(m.MaterializeError):m.reconstruct(output,'a'*64)

    def test_partial_failed_worker_remains_authoritative_failure(self):
        output=self.root/'out'
        child=mock.Mock(pid=987654,returncode=1)
        def spawn(*_args,**_kwargs):
            m.save(output/'materializer-result.json',{'schema_version':1,'scope':'private source materialization','status':'FAIL','phase':'fetch-registry','completed_registry':3,'error_type':'MaterializeError'})
            return child
        with mock.patch.object(m,'verify_pins'),mock.patch.object(m.subprocess,'Popen',side_effect=spawn),mock.patch.object(m.os,'killpg'):
            with self.assertRaises(m.MaterializeError):m.run(output,'a'*64)
        report=json.loads((output/'materializer-result.json').read_bytes())
        self.assertEqual(report['status'],'FAIL');self.assertEqual(report['completed_registry'],3)


if __name__=='__main__':unittest.main()
