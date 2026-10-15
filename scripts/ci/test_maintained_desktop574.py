"""Focused hosted reconstruction checks; no secrets, downloads, GPG or Docker."""
import copy
import hashlib
import importlib.util
import io
import json
import os
import stat
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
        self.assertEqual((context/'finish-keyring.py').read_text(),entry.KEYRING_FINALIZER)
        self.assertEqual(entry.DOCKERFILE.count('\nRUN '),1)
        self.assertLess(entry.DOCKERFILE.index('pacman-key --init'),entry.DOCKERFILE.index('/usr/bin/python3 -B /tmp/finish-keyring.py'))
        self.assertLess(entry.DOCKERFILE.index('cmp /expected-packages.lock /builder-packages.lock'),entry.DOCKERFILE.index('/usr/bin/python3 -B /tmp/finish-keyring.py'))
        self.assertNotIn('unlink(',entry.KEYRING_FINALIZER)
        self.assertNotIn("'all'",entry.KEYRING_FINALIZER)
        invalid=copy.deepcopy(INPUTS);invalid['bootstrap_hook_masks']=['bad;command.hook']
        with self.assertRaises(ValueError):entry.configure(invalid,context)

class ProducerTests(unittest.TestCase):
    def setUp(self):
        self.api=types.ModuleType('inert_keyring_finalizer')
        exec(compile(entry.KEYRING_FINALIZER,'<generated-keyring-finalizer>','exec'),self.api.__dict__)
        self.directory=types.SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0)

    def finish(self,states,clock=(0,)):
        with patch.object(Path,'lstat',return_value=self.directory), \
             patch.object(self.api,'snapshot',side_effect=[{'fixed':'same'},{'fixed':'same'}]), \
             patch.object(self.api,'present',side_effect=states), \
             patch.object(self.api.subprocess,'run') as run, \
             patch.object(self.api.time,'monotonic',side_effect=clock), \
             patch.object(self.api.time,'sleep') as sleep:
            self.api.finish()
        return run,sleep

    def test_stop_is_exact_home_once_before_absence_with_finite_wait(self):
        run,sleep=self.finish([('S.gpg-agent',),('S.gpg-agent',),(),()],(10,10))
        run.assert_called_once()
        args,opts=run.call_args
        self.assertEqual(args[0],['/usr/bin/gpgconf','--homedir','/etc/pacman.d/gnupg','--kill','gpg-agent'])
        self.assertEqual(opts['timeout'],15);self.assertTrue(opts['check'])
        self.assertEqual(opts['stdout'],self.api.subprocess.DEVNULL)
        self.assertEqual(opts['stderr'],self.api.subprocess.DEVNULL)
        self.assertNotIn('GNUPGHOME',opts['env']);sleep.assert_called_once_with(0.05)

    def test_absent_producer_still_gets_one_home_scoped_stop(self):
        run,sleep=self.finish([(),(),()])
        run.assert_called_once();sleep.assert_not_called()

    def test_failure_timeout_remaining_reappearance_or_trust_drift_refuses(self):
        for mode in ('nonzero','timeout','remaining','reappeared','trust'):
            with self.subTest(mode=mode),patch.object(Path,'lstat',return_value=self.directory), \
                 patch.object(self.api,'snapshot',side_effect=[{'fixed':'same'},{'fixed':'changed' if mode=='trust' else 'same'}]), \
                 patch.object(self.api,'present',side_effect=[('S.gpg-agent',),('S.gpg-agent',) if mode=='remaining' else (),('S.gpg-agent',) if mode=='reappeared' else ()]), \
                 patch.object(self.api.subprocess,'run',side_effect=(self.api.subprocess.CalledProcessError(1,['inert']) if mode=='nonzero' else self.api.subprocess.TimeoutExpired(['inert'],15) if mode=='timeout' else None)), \
                 patch.object(self.api.time,'monotonic',side_effect=[0,5]), \
                 patch.object(self.api.time,'sleep'):
                with self.assertRaises((ValueError,self.api.subprocess.SubprocessError)):self.api.finish()

    def test_wrong_endpoint_type_and_unsafe_home_refuse_without_process(self):
        for mode,uid in ((stat.S_IFREG|0o600,0),(stat.S_IFLNK|0o777,0),(stat.S_IFSOCK|0o600,1000)):
            with patch.object(Path,'lstat',return_value=types.SimpleNamespace(st_mode=mode,st_uid=uid)):
                with self.assertRaises(ValueError):self.api.present()
        with patch.object(Path,'lstat',return_value=types.SimpleNamespace(st_mode=stat.S_IFDIR|0o777,st_uid=0)),patch.object(self.api.subprocess,'run') as run:
            with self.assertRaises(ValueError):self.api.finish()
        run.assert_not_called()

    def test_snapshot_preserves_content_mode_owner_and_refuses_wrong_nodes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);home=root/'gnupg';home.mkdir()
            (home/'trustdb.gpg').write_bytes(b'inert public trust')
            config=root/'pacman.conf';config.write_bytes(b'inert fixed configuration')
            actual_path=Path
            self.api.HOME=home
            self.api.Path=lambda path:config if str(path)=='/etc/pacman.conf' else actual_path(path)
            lstat=Path.lstat;fstat=os.fstat
            def root_owned(info):
                values={name:getattr(info,name)for name in ('st_dev','st_ino','st_mode','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
                return types.SimpleNamespace(**values,st_uid=0)
            with patch.object(Path,'lstat',lambda path:root_owned(lstat(path))), \
                 patch.object(os,'fstat',lambda fd:root_owned(fstat(fd))):
                first=self.api.snapshot();self.assertEqual(self.api.snapshot(),first)
                (home/'trustdb.gpg').write_bytes(b'changed inert public trust')
                self.assertNotEqual(self.api.snapshot(),first)
                (home/'public-keys.d').symlink_to(root,target_is_directory=True)
                with self.assertRaisesRegex(ValueError,'public key directory'):self.api.snapshot()
                (home/'public-keys.d').unlink()
                (home/'pubring.kbx').symlink_to(config)
                with self.assertRaises(ValueError):self.api.snapshot()

if __name__=='__main__':unittest.main()
