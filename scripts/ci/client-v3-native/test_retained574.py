# SPDX-License-Identifier: MIT
"""Focused retained DATA controls; no network, Docker, Source or Reader calls."""
import hashlib
import importlib.util
from pathlib import Path
import os
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('trusted_client_retained574', Path(__file__).with_name('retained574.py'))
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)

def deny(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec', 'os.spawn', 'os.fork', 'os.posix_spawn')) or event in ('os.system', 'pty.spawn'):
        raise RuntimeError('DATA actor denied: ' + event)
sys.addaudithook(deny)

class Retained(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.source = self.root/'packages'; self.source.mkdir(mode=0o700)
        self.cache = self.root/'cache'; self.cache.mkdir(mode=0o700)
        self.rows = {}
        for name, raw in [('a.pkg.tar.xz', b'exact archive'), ('a.pkg.tar.xz.sig', b'exact signature')]:
            (self.source/name).write_bytes(raw)
            self.rows[name] = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

    def run_join(self):
        return R.join(self.source, self.cache, self.rows, time.monotonic()+10)

    def test_exact_copy_and_existing_inode_preserved(self):
        name = next(iter(self.rows)); (self.cache/name).write_bytes((self.source/name).read_bytes())
        before = R.identity((self.cache/name).stat()); result = self.run_join()
        self.assertEqual((result['files'], result['added'], result['existing']), (2,1,1))
        self.assertEqual(R.identity((self.cache/name).stat()), before)
        self.assertEqual(result['network_requests'], 0)
        self.assertEqual(result['signature_authentication'], 'ORIGINAL_NATIVE_GATE_REQUIRED')

    def test_missing_or_extra_source_refuses_before_write(self):
        (self.source/'extra').write_bytes(b'no');
        with self.assertRaises(ValueError): self.run_join()
        (self.source/'extra').unlink(); (self.source/'a.pkg.tar.xz.sig').unlink()
        with self.assertRaises(ValueError): self.run_join()
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_tampered_source_refuses_before_write(self):
        (self.source/'a.pkg.tar.xz.sig').write_bytes(b'tamper')
        with self.assertRaises(ValueError): self.run_join()
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_tampered_existing_cache_is_not_replaced(self):
        target = self.cache/'a.pkg.tar.xz'; target.write_bytes(b'bad')
        with self.assertRaises(ValueError): self.run_join()
        self.assertEqual(target.read_bytes(), b'bad')

    def test_source_alias_and_hardlink_refused(self):
        target = self.source/'a.pkg.tar.xz'; saved=self.root/'saved'; target.rename(saved); target.symlink_to(saved)
        with self.assertRaises(ValueError): self.run_join()
        target.unlink(); os.link(saved,target)
        with self.assertRaises(ValueError): self.run_join()
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_foreign_cache_and_nonprivate_cache_refused(self):
        (self.cache/'foreign').write_bytes(b'no')
        with self.assertRaises(ValueError): self.run_join()
        (self.cache/'foreign').unlink(); self.cache.chmod(0o755)
        with self.assertRaises(ValueError): self.run_join()

    def test_expired_deadline_does_not_reset(self):
        with self.assertRaises(ValueError): R.join(self.source,self.cache,self.rows,time.monotonic()-1)
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_copy_failure_cleans_only_owned_partial(self):
        original=R.exact
        def changed(path, row, deadline, output=None):
            if output is not None:
                output.write(b'partial'); raise ValueError('MODELED source changed during copy')
            return original(path,row,deadline,output)
        with patch.object(R,'exact',side_effect=changed):
            with self.assertRaises(ValueError): self.run_join()
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_concurrent_target_is_never_clobbered(self):
        original=os.link
        def occupied(source,target,**kwargs):
            Path(target).write_bytes(b'concurrent target')
            return original(source,target,**kwargs)
        with patch.object(R.os,'link',side_effect=occupied):
            with self.assertRaises(FileExistsError): self.run_join()
        self.assertEqual((self.cache/'a.pkg.tar.xz').read_bytes(),b'concurrent target')
        self.assertFalse(list(self.cache.glob('*.partial')))

    def test_original_lock_pin_refuses_any_substitute(self):
        with self.assertRaises(ValueError): R.package_rows(b'{"packages":[]}')

if __name__ == '__main__': unittest.main()
