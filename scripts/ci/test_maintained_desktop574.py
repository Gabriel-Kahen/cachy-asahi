"""Focused hosted reconstruction checks; no secrets, downloads, GPG or Docker."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock,patch
import urllib.error

HERE=Path(__file__).absolute().parent
spec=importlib.util.spec_from_file_location('desktop574',HERE/'maintained_desktop574.py')
entry=importlib.util.module_from_spec(spec);spec.loader.exec_module(entry)
INPUTS=json.loads((HERE/'maintained-desktop574-inputs.json').read_bytes())
ROOT=next(p for p in HERE.parents if(p/'scripts/ci/old_four_seed.py').is_file())
spec=importlib.util.spec_from_file_location('existing_seed',ROOT/'scripts/ci/old_four_seed.py')
old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)

class Response(io.BytesIO):
    def __init__(self,body,url='https://ca.us.mirror.archlinuxarm.org/input'):
        super().__init__(body);self.url=url

class HostedTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.base=Path(self.tmp.name)
    def item(self,name='test.pkg.tar.xz',body=b'archive'):
        return dict(filename=name,target=self.base/name,url='https://ca.us.mirror.archlinuxarm.org/'+name,
                    size=len(body),sha256=hashlib.sha256(body).hexdigest())
    def test_full_plan_and_legacy_seed_binding_are_distinct(self):
        items=entry.plan(INPUTS,self.base)
        self.assertEqual(len(items),1153)
        self.assertEqual(len({r['target']for r in items}),1153)
        self.assertEqual(INPUTS['accepted_prior_input_sha256'],old.RETAINED_BUBBLEWRAP_INPUT_SHA256)
        self.assertNotEqual(hashlib.sha256((HERE/'maintained-desktop574-inputs.json').read_bytes()).hexdigest(),INPUTS['accepted_prior_input_sha256'])
        helper=types.SimpleNamespace(OLD_FOUR_PRIVATE_ROWS=old.OLD_FOUR_PRIVATE_ROWS,
            RETAINED_BUBBLEWRAP_PRIVATE_ROWS=old.RETAINED_BUBBLEWRAP_PRIVATE_ROWS,seed_current_build_cache=Mock())
        with patch.dict(os.environ,{'CACHY_OLD_FOUR_TEST':'synthetic','ACTIONS_RUNTIME_TOKEN':'synthetic'},clear=True):
            entry.seed(INPUTS,items,self.base/'context/deps',helper)
            helper.seed_current_build_cache.assert_called_once_with(self.base/'context/deps',INPUTS['accepted_prior_input_sha256'])
            self.assertEqual(set(os.environ),{'PATH','LC_ALL','LANG','HOME'})
            self.assertEqual(os.environ['HOME'],str(self.base/'home'))
    def test_wrong_six_file_descriptor_refuses_and_scrubs_environment(self):
        items=entry.plan(INPUTS,self.base);items[0]=dict(items[0],sha256='0'*64)
        helper=types.SimpleNamespace(OLD_FOUR_PRIVATE_ROWS=(('not-selected',1,'0'*64,'X',1),),
            RETAINED_BUBBLEWRAP_PRIVATE_ROWS=(),seed_current_build_cache=Mock())
        with patch.dict(os.environ,{'CACHY_OLD_FOUR_TEST':'synthetic'},clear=True):
            with self.assertRaises(ValueError):entry.seed(INPUTS,items,self.base/'context/deps',helper)
            helper.seed_current_build_cache.assert_not_called()
            self.assertNotIn('CACHY_OLD_FOUR_TEST',os.environ)
    def test_download_preserves_exact_hash_and_existing_seed_skips_network(self):
        item=self.item();opener=Mock(return_value=Response(b'archive'))
        entry.fetch(item,opener)
        self.assertEqual(item['target'].read_bytes(),b'archive')
        opener=Mock(side_effect=AssertionError('network not expected'))
        self.assertEqual(entry.fetch(item,opener)['source'],'existing_exact_seed')
        opener.assert_not_called()
    def test_only_exact_zlib_404_uses_archboot_fallback(self):
        item=self.item(entry.ZLIB)
        opener=Mock(side_effect=[urllib.error.HTTPError(item['url'],404,'missing',{},None),Response(b'archive',entry.ARCHBOOT+entry.ZLIB)])
        result=entry.fetch(item,opener)
        self.assertEqual(result['source'],entry.ARCHBOOT+entry.ZLIB)
        self.assertEqual(opener.call_count,2)
        item=self.item('other.pkg.tar.xz');opener=Mock(side_effect=urllib.error.HTTPError(item['url'],404,'missing',{},None))
        with self.assertRaises(urllib.error.HTTPError):entry.fetch(item,opener)
        self.assertEqual(opener.call_count,1)
    def test_non404_does_not_trigger_fallback(self):
        item=self.item(entry.ZLIB);opener=Mock(side_effect=urllib.error.HTTPError(item['url'],503,'unavailable',{},None))
        with self.assertRaises(urllib.error.HTTPError):entry.fetch(item,opener)
        self.assertEqual(opener.call_count,1)
    def test_wrong_hash_oversize_and_http_redirect_leave_no_cache_file(self):
        for index,response in enumerate([Response(b'corrupt'),Response(b'oversize'),Response(b'archive','http://invalid/input')]):
            item=self.item('bad'+str(index)+'.pkg.tar.xz')
            with self.assertRaises(ValueError):entry.fetch(item,Mock(return_value=response))
            self.assertFalse(item['target'].exists());self.assertFalse(item['target'].with_name(item['target'].name+'.partial').exists())
    def test_symlink_seed_is_refused(self):
        item=self.item();source=self.base/'source';source.write_bytes(b'archive');item['target'].symlink_to(source)
        opener=Mock()
        with self.assertRaises(ValueError):entry.fetch(item,opener)
        opener.assert_not_called()
    def test_context_has_exact_inventory_and_transaction_policy(self):
        context=self.base/'context';context.mkdir();entry.configure(INPUTS,context)
        self.assertEqual(len((context/'expected-packages.lock').read_text().splitlines()),574)
        self.assertEqual(len((context/'disabled-hooks.txt').read_text().splitlines()),41)
        self.assertIn('--noscriptlet',entry.DOCKERFILE);self.assertIn('cmp /expected-packages.lock /builder-packages.lock',entry.DOCKERFILE)
        self.assertIn('SigLevel = Required',entry.PACMAN)
        invalid=copy.deepcopy(INPUTS);invalid['bootstrap_hook_masks']=['bad;command.hook']
        with self.assertRaises(ValueError):entry.configure(invalid,context)

if __name__=='__main__':unittest.main()
