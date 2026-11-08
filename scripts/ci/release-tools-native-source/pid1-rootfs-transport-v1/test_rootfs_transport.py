"""DATA callbacks only: no HTTP, Source actors, readers, or real rootfs bytes."""
import argparse
import copy
import importlib.util
import json
import time
from unittest.mock import patch
from pathlib import Path
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('rootfs_dispatch', HERE/'payload/native/bootstrap_inputs.py')
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
parser = argparse.ArgumentParser()
parser.add_argument('--parent-source', type=Path, required=True)
ARGS, TEST_ARGS = parser.parse_known_args()
ORIGINAL = json.loads((ARGS.parent_source/'bootstrap/scripts/ci/inputs.lock.json').read_bytes())
EXTRAS = json.loads((ARGS.parent_source/'native/input-profile.json').read_bytes())['additions']['rows']
ROOTFS = {key: ORIGINAL['rootfs'][key] for key in ('filename', 'url', 'sha256', 'size')}
# The actual base dispatch row retains signature metadata, exactly as original fetch received it.
ROOTFS = copy.deepcopy(ORIGINAL['rootfs'])
CACHE = Path('/tmp/release-rootfs-data-test-cache')

class AcquisitionError(ValueError):
    def __init__(self, name, category='HTTPS transport failure', status=None):
        self.filename, self.category, self.http_status = name, category, status

class Controls(unittest.TestCase):
    def bound(self, effects, package=None):
        self.calls = []; self.packages = []; self.diagnostics = {}
        def parent(row, cache):
            self.calls.append((copy.deepcopy(row), cache))
            value = effects[len(self.calls)-1]
            if isinstance(value, BaseException):
                row['url'] = 'https://callback-mutation.invalid/'
                raise value
            return value
        def packages(row, cache):
            self.packages.append((row, cache))
            if isinstance(package, BaseException): raise package
            return 'PACKAGE'
        return module.bind_fetch(ORIGINAL, EXTRAS, CACHE, packages, parent, AcquisitionError, self.diagnostics, time.monotonic()+30)

    def test_first_success_is_one_original_call(self):
        self.assertEqual(self.bound(['PASS'])(ROOTFS, CACHE), 'PASS'); self.assertEqual(len(self.calls), 1)

    def test_exact_transport_gets_one_fresh_identical_retry(self):
        call=self.bound([AcquisitionError(ROOTFS['filename']), 'PASS'])
        self.assertEqual(call(ROOTFS, CACHE), 'PASS')
        self.assertEqual(self.calls, [(ROOTFS, CACHE), (ROOTFS, CACHE)])
        records=self.diagnostics['attempts']
        self.assertEqual([r['status'] for r in records], ['FAIL','PASS'])
        self.assertEqual(records[0]['error'],'HTTPS transport failure')
        self.assertTrue(all(type(r['elapsed_ns']) is int and r['elapsed_ns'] >= 0 and r['received_bytes'] is None for r in records))

    def test_second_transport_failure_propagates_no_third_call(self):
        error=AcquisitionError(ROOTFS['filename']);call=self.bound([error,error])
        with self.assertRaises(AcquisitionError) as got: call(ROOTFS,CACHE)
        self.assertIs(got.exception,error);self.assertEqual(len(self.calls),2)

    def test_http_failures_are_never_retried(self):
        for code in (403,404,429,500,503):
            with self.subTest(code=code):
                call=self.bound([AcquisitionError(ROOTFS['filename'],'HTTP failure',code)])
                with self.assertRaises(AcquisitionError):call(ROOTFS,CACHE)
                self.assertEqual(len(self.calls),1)

    def test_pin_cache_or_other_exception_is_never_retried(self):
        for error in (ValueError('checksum mismatch'), OSError('cache failure'), TimeoutError()):
            with self.subTest(error=type(error).__name__):
                call=self.bound([error])
                with self.assertRaises(type(error)):call(ROOTFS,CACHE)
                self.assertEqual(len(self.calls),1)

    def test_unmatched_transport_error_is_not_retried(self):
        class Child(AcquisitionError):pass
        for error in (Child(ROOTFS['filename']), AcquisitionError('other'), AcquisitionError(ROOTFS['filename'],status=503)):
            call=self.bound([error])
            with self.assertRaises(AcquisitionError):call(ROOTFS,CACHE)
            self.assertEqual(len(self.calls),1)

    def test_other_base_and_rootfs_signature_never_retry(self):
        rows=[*ORIGINAL['keyring_files'],module._signature(ROOTFS)]
        for row in rows:
            call=self.bound([AcquisitionError(row['filename'])])
            with self.assertRaises(AcquisitionError):call(row,CACHE)
            self.assertEqual(len(self.calls),1)

    def test_package_cache_failure_never_uses_parent(self):
        call=self.bound([],ValueError('missing signed package cache'))
        with self.assertRaises(ValueError):call(ORIGINAL['packages'][0],CACHE)
        self.assertEqual(self.calls,[]);self.assertEqual(len(self.packages),1)

    def test_changed_url_hash_size_or_cache_refused_before_callback(self):
        for key,value in [('url','https://other.invalid/rootfs'),('sha256','0'*64),('size',ROOTFS['size']+1)]:
            row=dict(ROOTFS);row[key]=value;call=self.bound([])
            with self.assertRaises(ValueError):call(row,CACHE)
            self.assertEqual(self.calls,[])
        call=self.bound([])
        with self.assertRaises(ValueError):call(ROOTFS,Path('/tmp/other-cache'))
        self.assertEqual(self.calls,[])

    def test_consumed_failed_attempts_cannot_be_reentered(self):
        error=AcquisitionError(ROOTFS['filename']);call=self.bound([error,error])
        with self.assertRaises(AcquisitionError):call(ROOTFS,CACHE)
        with self.assertRaisesRegex(ValueError,'ATTEMPTS_CONSUMED'):call(ROOTFS,CACHE)
        self.assertEqual(len(self.calls),2)

    def test_existing_outer_deadline_cannot_reset_for_retry(self):
        call=self.bound([AcquisitionError(ROOTFS['filename']),'PASS'])
        with patch.object(module.time,'monotonic',side_effect=[0,0,10**20]):
            with self.assertRaisesRegex(ValueError,'DEADLINE_REFUSED'):call(ROOTFS,CACHE)
        self.assertEqual(len(self.calls),1)

    def test_successful_acquisition_cannot_fetch_again_after_cache_loss(self):
        call=self.bound(['PASS'])
        self.assertEqual(call(ROOTFS,CACHE),'PASS')
        with self.assertRaisesRegex(ValueError,'CACHE_LOST_REFUSED'):call(ROOTFS,CACHE)
        self.assertEqual(len(self.calls),1)
        call=self.bound(['PASS','CACHED'])
        self.assertEqual(call(ROOTFS,CACHE),'PASS')
        with patch.object(module.Path,'exists',return_value=True):
            self.assertEqual(call(ROOTFS,CACHE),'CACHED')
            with self.assertRaisesRegex(ValueError,'CACHE_VALIDATION_CONSUMED'):call(ROOTFS,CACHE)
        self.assertEqual(len(self.calls),2)
        self.assertEqual(self.diagnostics['cache_validations'][0]['status'],'PASS')

    def test_binding_is_inert_and_input_pins_remain_required(self):
        self.bound([]);self.assertEqual(self.calls,[]);self.assertEqual(self.packages,[])
        changed=copy.deepcopy(ORIGINAL);changed['rootfs']['size']+=1
        with self.assertRaises(ValueError):module.bind_fetch(changed,EXTRAS,CACHE,lambda *a:None,lambda *a:None,AcquisitionError,{},time.monotonic()+30)

if __name__ == '__main__':unittest.main(argv=['test_rootfs_transport.py', *TEST_ARGS], verbosity=2)
