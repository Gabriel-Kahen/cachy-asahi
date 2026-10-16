# SPDX-License-Identifier: MIT
"""Inert exact-asset stream/secret/cleanup controls; no GH/network/actor execution."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import acquire_kernel as a
import retained_kernel as r


class Retained(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.data=b'fixed retained source fixture';self.sha=hashlib.sha256(self.data).hexdigest();self.archive=self.root/self.sha/'kernel.tar.gz';self.archive.parent.mkdir();self.receipt=self.root/'seed.json'
        for module in (a,r):
            for name,value in [('SIZE',len(self.data)),('SHA',self.sha)]:
                guard=patch.object(module,name,value);guard.start();self.addCleanup(guard.stop)
        for target in ('subprocess.Popen','urllib.request.OpenerDirector.open'):
            guard=patch(target,side_effect=AssertionError('actual actor/network forbidden'));guard.start();self.addCleanup(guard.stop)
        guard=patch.dict(os.environ,GH_TOKEN='inert-readonly-token',GH_DEBUG='api',HTTP_PROXY='http://never');guard.start();self.addCleanup(guard.stop)

    def process(self,data,stderr=b'',code=0):
        pipes=[]
        for raw in (data,stderr):
            read,write=os.pipe();os.write(write,raw);os.close(write);pipes.append(os.fdopen(read,'rb'))
        self.events=[]
        return SimpleNamespace(pid=234567,stdout=pipes[0],stderr=pipes[1],wait=lambda timeout:self.events.append('wait') or code)

    def run_fake(self,data,stderr=b'',code=0):
        process=self.process(data,stderr,code)
        def signal(pid,sig):
            self.events.append(sig)
            if sig==0:raise ProcessLookupError()
        with patch.object(r.subprocess,'Popen',return_value=process) as spawn,patch.object(r.os,'waitid',return_value=object()),patch.object(r.os,'killpg',side_effect=signal):
            result=r.download(self.archive,a,lambda seconds:contextlib.nullcontext(),self.receipt)
        return result,spawn

    def test_exact_stream_publishes_source_only_and_token_never_enters_receipt(self):
        result,spawn=self.run_fake(self.data,b'inert-readonly-token')
        self.assertEqual(self.archive.read_bytes(),self.data);self.assertEqual(result['status'],'RETAINED_ASSET_DOWNLOADED_HASH_VERIFIED');self.assertTrue(result['group_absent']);self.assertEqual(spawn.call_args.args[0],r.COMMAND)
        env=spawn.call_args.kwargs['env'];self.assertEqual(env['GH_TOKEN'],'inert-readonly-token');self.assertNotIn('GH_DEBUG',env);self.assertNotIn('HTTP_PROXY',env);self.assertFalse(Path(env['HOME']).exists())
        self.assertNotIn('inert-readonly-token',self.receipt.read_text());self.assertNotIn('stderr_text',result)
        self.assertEqual(self.events,[r.signal.SIGTERM,r.signal.SIGKILL,'wait',0]);self.assertEqual(json.loads(self.receipt.read_text()),result)

    def test_wrong_hash_short_or_oversize_asset_cannot_publish(self):
        for data in (b'x'*len(self.data),self.data[:-1],self.data+b'x'):
            with self.subTest(size=len(data)):
                self.receipt.unlink(missing_ok=True)
                with self.assertRaises(ValueError):self.run_fake(data)
                self.assertFalse(self.archive.exists());self.assertFalse(Path(str(self.archive)+'.partial').exists());self.assertEqual(json.loads(self.receipt.read_text())['status'],'FAIL')

    def test_completed_unavailable_transport_is_explicit_and_never_publishes(self):
        result,_=self.run_fake(self.data,code=1)
        self.assertEqual(result['status'],'RETAINED_ASSET_UNAVAILABLE');self.assertEqual(result['direct_url_fallback'],'ALLOWED_TRUE_CACHE_MISS_ONLY')
        self.assertFalse(self.archive.exists());self.assertFalse(Path(str(self.archive)+'.partial').exists());self.assertEqual(json.loads(self.receipt.read_text())['exit'],1)

    def test_missing_token_refuses_before_spawn_or_output(self):
        with patch.dict(os.environ,GH_TOKEN=''),patch.object(r.subprocess,'Popen') as spawn:
            with self.assertRaises(ValueError):r.download(self.archive,a,lambda seconds:contextlib.nullcontext(),self.receipt)
        spawn.assert_not_called();self.assertFalse(self.archive.exists());self.assertFalse(self.receipt.exists())

    def test_existing_archive_and_alias_refuse_without_overwrite(self):
        self.archive.write_bytes(b'preserve')
        with self.assertRaises(ValueError):r.download(self.archive,a,lambda seconds:contextlib.nullcontext(),self.receipt)
        self.assertEqual(self.archive.read_bytes(),b'preserve');self.archive.unlink();self.archive.symlink_to(self.root/'outside')
        with self.assertRaises(ValueError):r.download(self.archive,a,lambda seconds:contextlib.nullcontext(),self.receipt)

    def test_spawn_failure_cleans_owned_partial_and_private_config(self):
        with patch.object(r.subprocess,'Popen',side_effect=OSError('spawn failed')):
            with self.assertRaises(OSError):r.download(self.archive,a,lambda seconds:contextlib.nullcontext(),self.receipt)
        self.assertFalse(Path(str(self.archive)+'.partial').exists());self.assertFalse(self.archive.exists());self.assertEqual({p.name for p in self.root.iterdir()},{self.sha,'seed.json'})

    def test_deadline_retires_owned_group_before_receipt(self):
        with patch.object(r.time,'monotonic',side_effect=[0,301]):
            with self.assertRaisesRegex(ValueError,'deadline'):self.run_fake(self.data)
        self.assertFalse(self.archive.exists());self.assertEqual(self.events,[r.signal.SIGTERM,r.signal.SIGKILL,'wait',0]);self.assertFalse(json.loads(self.receipt.read_text())['natural_exit'])

    def test_endpoint_and_digest_are_fixed_to_roots_supplied_asset(self):
        metadata=json.loads(Path(__file__).with_name('retained-kernel-asset.json').read_text())
        self.assertEqual(r.ASSET_ID,647949735);self.assertEqual(r.RELEASE_ID,415175342);self.assertEqual(metadata['asset']['url'],r.URL)
        self.assertEqual(r.URL,'https://api.github.com/repos/Gabriel-Kahen/cachy-asahi/releases/assets/647949735');self.assertEqual(r.COMMAND,['gh','api','-H','Accept: application/octet-stream',r.URL])
        self.assertFalse(metadata['release_draft']);self.assertTrue(metadata['release_prerelease']);self.assertEqual(metadata['asset']['size'],262965559);self.assertEqual(metadata['asset']['digest'],'sha256:874ef68d04ac8c831b90bb01a387cfabb58fceb60842c49a0d0e58bcd6c146ad')


if __name__=='__main__':unittest.main()
