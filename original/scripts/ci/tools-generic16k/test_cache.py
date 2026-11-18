# SPDX-License-Identifier: MIT
"""Real byte-copy cache controls with tiny private fixtures; no network/actors."""
import ast
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
import urllib.error
import acquire_kernel as a

ROOT=next(p for p in Path(__file__).resolve().parents if (p/'scripts/virtual/generic16k/fetch_inputs.py').is_file())


class Cache(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        self.data=b'private exact archive fixture\n';self.digest=hashlib.sha256(self.data).hexdigest()
        for target,value in [('SIZE',len(self.data)),('SHA',self.digest)]:
            item=patch.object(a,target,value);item.start();self.addCleanup(item.stop)
        for target in ('subprocess.Popen','urllib.request.OpenerDirector.open'):
            item=patch(target,side_effect=AssertionError('actual actor/network forbidden'));item.start();self.addCleanup(item.stop)
        quiet=contextlib.redirect_stdout(io.StringIO());quiet.__enter__();self.addCleanup(quiet.__exit__,None,None,None)
        self.out=self.root/'inputs';self.out.mkdir();self.receipt=self.root/'receipt.json';directory=self.root/'cache'/self.digest;directory.mkdir(parents=True);self.archive=directory/'kernel.tar.gz'
        self.item=dict(name='kernel',filename='kernel.tar.gz',bytes=len(self.data),sha256=self.digest,source_revision=a.REVISION,url=a.URLS[0],allowed_hosts=['codeload.github.com'])
        self.fetch=SimpleNamespace(EXPECTED=[copy.deepcopy(self.item)],deadline_alarm=lambda seconds:contextlib.nullcontext(),fetch_one=Mock(side_effect=self.network))

    def network(self,item,out,deadline,opener):
        (out/'kernel.tar.gz').write_bytes(self.data)
        return dict(final_url=item['url'],bytes=len(self.data),sha256=self.digest)

    def call(self,hit='',matched='',retained=None):
        return a.acquire(self.fetch,self.item,self.out,'a'*64,self.receipt,cache_archive=self.archive,cache_hit=hit,cache_matched_key=matched,retained_archive=retained)

    def test_hit_hashes_and_copies_every_byte_without_network(self):
        self.archive.write_bytes(self.data);report=self.call('true',a.cache_key())
        self.fetch.fetch_one.assert_not_called();self.assertEqual(report['status'],'RESTORED_HASH_VERIFIED');self.assertEqual(report['attempts'],[])
        self.assertEqual((self.out/'kernel.tar.gz').read_bytes(),self.data);self.assertFalse(report['cache']['save_requested'])
        self.assertEqual(report['cache']['validation']['sha256'],self.digest);self.assertEqual(json.loads(self.receipt.read_text()),report)

    def test_miss_uses_original_fetch_and_stages_verified_single_archive_for_early_save(self):
        report=self.call();self.assertEqual(self.fetch.fetch_one.call_count,1);self.assertEqual(report['status'],'FETCHED_HASH_VERIFIED')
        self.assertEqual(self.archive.read_bytes(),self.data);self.assertEqual({p.name for p in self.archive.parent.iterdir()},{'kernel.tar.gz'})
        self.assertTrue(report['cache']['save_requested']);self.assertEqual(report['cache']['status'],'MISS_FETCHED_HASH_VERIFIED')
        self.assertTrue(report['partial_absent'] and report['cache_partial_absent'])

    def test_explicit_local_retained_archive_on_miss_is_distinct_from_cache_hit(self):
        seed=self.root/'retained-kernel.tar.gz';seed.write_bytes(self.data);report=self.call(retained=seed)
        self.fetch.fetch_one.assert_not_called();self.assertEqual(report['status'],'RETAINED_ARCHIVE_HASH_VERIFIED')
        self.assertEqual(report['attempts'],[]);self.assertFalse(report['retained_source']['cache_hit_credit'])
        self.assertEqual(self.archive.read_bytes(),self.data);self.assertTrue(report['cache']['save_requested'])

    def test_declared_retained_archive_can_occupy_cache_path_on_true_miss(self):
        self.archive.write_bytes(self.data);report=self.call(retained=self.archive)
        self.fetch.fetch_one.assert_not_called();self.assertEqual((self.out/'kernel.tar.gz').read_bytes(),self.data)
        self.assertEqual(report['cache']['status'],'MISS_RETAINED_ARCHIVE_HASH_VERIFIED');self.assertTrue(report['cache']['save_requested'])

    def test_corrupt_retained_seed_is_fatal_without_url_fallback(self):
        seed=self.root/'retained-kernel.tar.gz';seed.write_bytes(b'x'*len(self.data))
        with self.assertRaises(ValueError):self.call(retained=seed)
        self.fetch.fetch_one.assert_not_called();self.assertFalse((self.out/'kernel.tar.gz').exists());self.assertFalse(self.archive.exists())
        self.assertEqual(json.loads(self.receipt.read_text())['status'],'FAIL')

    def test_exact_visible_cache_hit_does_not_read_or_relabel_retained_seed(self):
        self.archive.write_bytes(self.data);report=self.call('true',a.cache_key(),self.root/'missing-seed')
        self.assertEqual(report['status'],'RESTORED_HASH_VERIFIED');self.assertNotIn('retained_source',report);self.fetch.fetch_one.assert_not_called()

    def test_invalid_historical_pin_refuses_cache_and_network(self):
        self.item['source_revision']='0'*40
        with self.assertRaises(ValueError):self.call()
        self.fetch.fetch_one.assert_not_called();self.assertFalse(self.receipt.exists())

    def test_hit_missing_file_foreign_key_and_partial_match_fail_without_fetch(self):
        for hit,matched in [('true',a.cache_key()),('true','foreign'),('false','foreign')]:
            with self.subTest(hit=hit,matched=matched):
                self.receipt.unlink(missing_ok=True)
                with self.assertRaises(ValueError):self.call(hit,matched)
                self.fetch.fetch_one.assert_not_called()

    def test_unexpected_miss_file_and_extra_restored_member_are_fatal(self):
        self.archive.write_bytes(self.data)
        with self.assertRaises(ValueError):self.call('false','')
        self.receipt.unlink();(self.archive.parent/'unexpected').write_text('not a source cache')
        with self.assertRaises(ValueError):self.call('true',a.cache_key())
        self.fetch.fetch_one.assert_not_called()

    def test_corrupt_short_and_oversize_hits_never_extract_publish_or_fetch(self):
        for raw in (b'x'*len(self.data),self.data[:-1],self.data+b'x'):
            with self.subTest(size=len(raw)):
                self.receipt.unlink(missing_ok=True);self.archive.write_bytes(raw)
                with self.assertRaises(ValueError):self.call('true',a.cache_key())
                self.fetch.fetch_one.assert_not_called();self.assertFalse((self.out/'kernel.tar.gz').exists());self.assertFalse((self.out/'kernel.tar.gz.partial').exists())
                self.assertEqual(self.archive.read_bytes(),raw);self.assertEqual(json.loads(self.receipt.read_text())['status'],'FAIL')

    def test_alias_hardlink_and_fifo_restore_are_refused_without_reading_outside(self):
        target=self.root/'outside';target.write_bytes(self.data);self.archive.symlink_to(target)
        with self.assertRaises(ValueError):self.call('true',a.cache_key())
        self.archive.unlink();self.receipt.unlink();os.link(target,self.archive)
        with self.assertRaises(ValueError):self.call('true',a.cache_key())
        self.archive.unlink();self.receipt.unlink();os.mkfifo(self.archive)
        with self.assertRaises(ValueError):self.call('true',a.cache_key())
        self.fetch.fetch_one.assert_not_called()

    def test_existing_destination_is_preserved(self):
        self.archive.write_bytes(self.data);target=self.out/'kernel.tar.gz';target.write_bytes(b'preserve existing')
        with self.assertRaises(ValueError):self.call('true',a.cache_key())
        self.assertEqual(target.read_bytes(),b'preserve existing');self.fetch.fetch_one.assert_not_called()

    def test_mutated_source_identity_cannot_publish(self):
        self.archive.write_bytes(self.data);original=self.archive.stat()
        fields=('st_mode','st_nlink','st_uid','st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
        after=SimpleNamespace(**{n:getattr(original,n) for n in fields});after.st_mtime_ns+=1
        with patch.object(a.os,'fstat',side_effect=[original,after]):
            with self.assertRaisesRegex(ValueError,'identity'):a.copy_exact(self.archive,self.out/'kernel.tar.gz',float('inf'))
        self.assertFalse((self.out/'kernel.tar.gz').exists());self.assertFalse((self.out/'kernel.tar.gz.partial').exists())

    def test_deadline_removes_only_its_partial(self):
        self.archive.write_bytes(self.data)
        with patch.object(a.time,'monotonic',return_value=10):
            with self.assertRaises(TimeoutError):a.copy_exact(self.archive,self.out/'kernel.tar.gz',9)
        self.assertFalse((self.out/'kernel.tar.gz.partial').exists());self.assertEqual(self.archive.read_bytes(),self.data)

    def test_noclobber_publish_race_preserves_new_destination(self):
        self.archive.write_bytes(self.data);target=self.out/'kernel.tar.gz'
        def race(*args,**kwargs):target.write_bytes(b'other writer');raise FileExistsError()
        with patch.object(a.os,'link',side_effect=race):
            with self.assertRaises(FileExistsError):a.copy_exact(self.archive,target,float('inf'))
        self.assertEqual(target.read_bytes(),b'other writer');self.assertFalse((self.out/'kernel.tar.gz.partial').exists())

    def test_cache_copy_failure_does_not_retry_network(self):
        with patch.object(a,'copy_exact',side_effect=OSError('cache I/O failed')):
            with self.assertRaises(OSError):self.call()
        self.assertEqual(self.fetch.fetch_one.call_count,1);self.assertEqual(json.loads(self.receipt.read_text())['status'],'FAIL')

    def test_true_miss_keeps_exact_two_429_attempts_and_no_save_request(self):
        self.fetch.fetch_one.side_effect=[urllib.error.HTTPError(url,429,'rate',{},None) for url in a.URLS]
        with patch.object(a.time,'sleep'):
            with self.assertRaises(urllib.error.HTTPError):self.call()
        report=json.loads(self.receipt.read_text());self.assertEqual([r['requested_url'] for r in report['attempts']],list(a.URLS));self.assertEqual(self.fetch.fetch_one.call_count,2)
        self.assertFalse(report['cache']['save_requested']);self.assertFalse(self.archive.exists());self.assertTrue(report['cache_partial_absent'])

    def test_copy_hashes_actual_fetched_bytes_before_cache_save(self):
        def forged(*args,**kwargs):
            (self.out/'kernel.tar.gz').write_bytes(b'x'*len(self.data));return dict(final_url=a.URLS[0],bytes=len(self.data),sha256=self.digest)
        self.fetch.fetch_one.side_effect=forged
        with self.assertRaisesRegex(ValueError,'hash'):self.call()
        self.assertFalse(self.archive.exists());self.assertFalse(Path(str(self.archive)+'.partial').exists());self.assertEqual(self.fetch.fetch_one.call_count,1)


class Source(unittest.TestCase):
    def setUp(self):
        for target in ('subprocess.Popen','urllib.request.OpenerDirector.open'):
            item=patch(target,side_effect=AssertionError('actual actor/network forbidden'));item.start();self.addCleanup(item.stop)

    def test_production_pins_and_official_action_identity_are_exact(self):
        tree=ast.parse(Path(a.__file__).read_text());constants={n.targets[0].id:ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id in ('SHA','SIZE','REVISION')}
        self.assertEqual(constants,dict(SIZE=262965559,SHA='874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad',REVISION='94fb23346d522edf53722357c426a3e58030beea'))
        record=json.loads((Path(__file__).with_name('cache-action.json')).read_text());self.assertEqual(record['verified_commit'],'0057852bfaa89a56745cba8c7296529d2fc39830');self.assertEqual(set(record['metadata']),{'restore/action.yml','save/action.yml'})

    def test_two_workflows_share_exact_archive_key_and_save_before_build(self):
        for lane in ('tools','fish-done'):
            text=(ROOT/'.github/workflows'/('native-arm-'+lane+'-generic16k.yml')).read_text()
            for action in ('restore','save'):self.assertIn('actions/cache/'+action+'@0057852bfaa89a56745cba8c7296529d2fc39830',text)
            self.assertNotIn('restore-keys:',text);self.assertEqual(text.count('key: '+a.cache_key()),2)
            expected='${{ runner.temp }}/kernel-source-cache/'+a.SHA+'/kernel.tar.gz';self.assertEqual(text.count('path: '+expected),2)
            self.assertLess(text.index('Restore only the exact'),text.index('id: kernel_acquire'));self.assertLess(text.index('Save verified archive'),text.index('timeout-minutes: 63'))
            self.assertIn("acquire=s.load(root,'scripts/ci/tools-generic16k/acquire_kernel.py')",text)
            self.assertIn('cache_hit=os.environ',text);self.assertIn('cache_matched_key=os.environ',text)
            self.assertNotIn('continue-on-error:',text)


if __name__=='__main__':unittest.main()
