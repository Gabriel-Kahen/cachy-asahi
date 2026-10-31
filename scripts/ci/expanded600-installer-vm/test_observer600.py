# SPDX-License-Identifier: MIT
"""Readonly temporary-tree controls; no namespace, mount, native or VM actors."""
import ast
import ctypes
import errno
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'scripts/update/full_root.py').is_file())
sys.path.insert(0,str(ROOT/'scripts/ci/expanded600-installer-vm'))
import contract as C

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module

roots=load('_test_observer600_original',ROOT/'scripts/update/full_root.py')
backend=load('_test_observer600_backend',HERE/'observer600.py')
adapter=load('_test_observer600_adapter',HERE/'adapter.py')

class Calls:
    def __init__(self,errno_value=None,mask=0x1000,value=7):self.error=errno_value;self.mask=mask;self.value=value;self.calls=[]
    def __call__(self,fd,path,flags,mask,pointer):
        self.calls.append((fd,path,flags,mask))
        if self.error is not None:ctypes.set_errno(self.error);return -1
        pointer._obj.mask=self.mask;pointer._obj.mnt_id=self.value;return 0

class MountQuery(unittest.TestCase):
    def limits(self):return roots.Limits(deadline=time.monotonic()+600)
    def query(self,call,old):
        with patch.object(ctypes,'CDLL',return_value=SimpleNamespace(statx=call)):
            return backend._mount600(old)
    def test_same_descriptor_api_matches_fdinfo_and_distinct_real_mount(self):
        query=backend._mount600(roots._mount_id)
        with tempfile.TemporaryDirectory() as directory:
            descriptors=[os.open(directory,os.O_RDONLY|os.O_DIRECTORY),os.open('/proc',os.O_RDONLY|os.O_DIRECTORY)]
            try:
                values=[query(fd,self.limits()) for fd in descriptors]
                self.assertEqual(values,[roots._mount_id(fd,self.limits()) for fd in descriptors]);self.assertNotEqual(*values)
            finally:
                for fd in descriptors:os.close(fd)
    def test_every_call_queries_live_fd_no_mount_result_cache(self):
        call=Calls();old=[];query=self.query(call,lambda fd,limits:old.append(fd) or 7)
        self.assertEqual(query(31,self.limits()),7);call.value=19
        self.assertEqual(query(32,self.limits()),19);self.assertEqual(query(32,self.limits()),19)
        self.assertEqual(old,[31]);self.assertEqual(call.calls,[(31,b'',0x1000,0x1000),(32,b'',0x1000,0x1000),(32,b'',0x1000,0x1000)])
    def test_api_disagreement_zero_and_badfd_refuse(self):
        for call,exception in ((Calls(value=9),ValueError),(Calls(value=0),ValueError),(Calls(errno_value=errno.EBADF),OSError),
                               (Calls(errno_value=errno.EACCES),OSError)):
            with self.subTest(error=call.error,value=call.value),self.assertRaises(exception):self.query(call,lambda *a:7)(31,self.limits())
    def test_unsupported_symbol_mask_or_syscall_use_original_each_descriptor(self):
        for call in (Calls(errno_value=errno.ENOSYS),Calls(errno_value=errno.EINVAL),Calls(errno_value=errno.EOPNOTSUPP),
                     Calls(errno_value=errno.EPERM),Calls(mask=0)):
            old=[];query=self.query(call,lambda fd,limits:old.append(fd) or fd)
            self.assertEqual(query(31,self.limits()),31);self.assertEqual(query(32,self.limits()),32)
            self.assertEqual(old,[31,32]);self.assertEqual(len(call.calls),1)
        with patch.object(ctypes,'CDLL',return_value=SimpleNamespace()):
            self.assertEqual(backend._mount600(lambda fd,limits:23)(31,self.limits()),23)
    def test_unsupported_abi_falls_back_without_loading_libc(self):
        with patch.object(sys,'byteorder','big'),patch.object(ctypes,'CDLL') as libc:
            self.assertEqual(backend._mount600(lambda *a:23)(31,self.limits()),23);libc.assert_not_called()

class CompleteWalker(unittest.TestCase):
    def fixture(self,root):
        (root/'nested').mkdir();(root/'nested/content').write_bytes(bytes(range(256))*8193)
        os.link(root/'nested/content',root/'alias');(root/'relative').symlink_to('nested/content')
        (root/'absolute').symlink_to('/usr/lib/fixture');(root/'empty').write_bytes(b'');(root/'directory').mkdir()
    def observe(self,root,fast=True,**limits):
        return (lambda *a,**k:backend._observer600(roots,*a,**k) if fast else roots.observe(*a,**k))(
            root,limits=roots.Limits(deadline=time.monotonic()+600,**limits),hardlinks='generic-development-internal')
    def test_complete_exact_content_metadata_hardlinks_symlink_equality(self):
        original_mount=roots._mount_id;original_observe=roots.observe
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.fixture(root);old=self.observe(root,False);new=self.observe(root)
            self.assertTrue(new['complete']);self.assertEqual(new,old)
            self.assertEqual(new['nodes']['nested/content']['sha256'],hashlib.sha256((root/'nested/content').read_bytes()).hexdigest())
            self.assertEqual(new['hardlink_groups']['alias']['members'],('alias','nested/content'))
        self.assertIs(roots._mount_id,original_mount);self.assertIs(roots.observe,original_observe)
    def test_original_backend_fallback_produces_same_complete_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.fixture(root);old=self.observe(root,False)
            with patch.object(ctypes,'CDLL',return_value=SimpleNamespace(statx=Calls(errno_value=errno.ENOSYS))):
                self.assertEqual(self.observe(root),old)
    def test_external_hardlink_alias_remains_incomplete_not_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory);root=parent/'target';root.mkdir();self.fixture(root);os.link(root/'alias',parent/'outside')
            for fast in (False,True):
                value=self.observe(root,fast);self.assertFalse(value['complete']);self.assertIn('hardlink group not closed',value['unsupported_counts'])
    def test_real_file_content_drift_refuses_both_backends(self):
        read=os.read
        for fast in (False,True):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory);path=root/'data';path.write_bytes(b'x'*2097152);changed=False
                def drift(fd,count):
                    nonlocal changed
                    value=read(fd,count)
                    if value and not changed:
                        changed=True
                        with path.open('ab') as stream:stream.write(b'y')
                    return value
                with patch.object(os,'read',side_effect=drift):value=self.observe(root,fast)
                self.assertFalse(value['complete']);self.assertTrue({'file grew during observation','file content drift'}&value['unsupported_counts'].keys())
    def test_mount_crossing_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.fixture(root)
            fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY)
            try:call=Calls(value=roots._mount_id(fd,roots.Limits(deadline=time.monotonic()+600)))
            finally:os.close(fd)
            original=call.__call__;count=0
            def change(*args):
                nonlocal count
                count+=1
                if count>2:call.value+=1
                return original(*args)
            class Changed:
                def __call__(self,*args):return change(*args)
            with patch.object(ctypes,'CDLL',return_value=SimpleNamespace(statx=Changed())):value=self.observe(root)
            self.assertFalse(value['complete']);self.assertIn('mount crossing refused',value['unsupported_counts'])
    def test_unchanged_node_byte_depth_and_deadline_caps(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);self.fixture(root)
            for limits,reason in ((dict(max_nodes=1),'root node limit'),(dict(max_bytes=1),'root byte limit'),
                                  (dict(max_file_bytes=1),'root file byte limit')):
                old=self.observe(root,False,**limits);new=self.observe(root,**limits)
                self.assertEqual(new,old);self.assertFalse(new['complete']);self.assertIn(reason,new['unsupported_counts'])
            for fast in (False,True):
                with patch.object(time,'monotonic',side_effect=[0,0]+[601]*50):value=self.observe(root,fast)
                self.assertFalse(value['complete']);self.assertIn('root observation deadline',value['unsupported_counts'])
    def test_changed_source_refuses_before_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            fake=Path(directory)/'full_root.py';fake.write_bytes(Path(roots.__file__).read_bytes()+b'\n')
            with patch.object(roots,'__file__',str(fake)),self.assertRaisesRegex(ValueError,'held root observer source differs'):
                self.observe(Path(directory))

class SourceIntegration(unittest.TestCase):
    def numeric(self):return (ROOT/'scripts/ci/full-composition-installer-vm/numeric_vm.py').read_bytes()
    def test_exact_original_functions_except_one_independent_call_and_new_backend(self):
        new,receipt=adapter.transform(self.numeric(),'numeric_vm.py')
        # Reversing the one call and removing the exact appended backend must
        # reproduce the entire frozen pre-optimization600 module, byte for byte.
        body=(HERE/'observer600.py').read_bytes()
        self.assertTrue(new.endswith(b'\n'+body))
        prior=new[:-len(body)-1].replace(b'observation=_observer600(roots,target,',b'observation=roots.observe(target,')
        self.assertEqual(len(prior),14588)
        self.assertEqual(hashlib.sha256(prior).hexdigest(),'04e6cda983ef346b788c6355e1a5cdbd3cf041a5c3865d8250d969f0aad7a664')
        self.assertEqual(receipt['edits'],2)
        self.assertIn(b'deadline=started+600',new);self.assertIn(b'max_nodes=200000,max_bytes=6*p.GIB,max_file_bytes=p.GIB',new)
        self.assertIn(b'worker.compare_payload(normalize(observation)',new)
        self.assertIn(b'driver.database(target,max_packages=600',new)
        compile(new,'<numeric600-source>','exec')
    def test_backend_or_original_source_drift_refuses(self):
        with self.assertRaisesRegex(ValueError,'source bytes differ'):adapter.transform(self.numeric()+b'\n','numeric_vm.py')
        original=Path.read_bytes
        def altered(path):return original(path)+b'\n' if path==HERE/'observer600.py' else original(path)
        with patch.object(Path,'read_bytes',altered),self.assertRaisesRegex(ValueError,'backend bytes differ'):
            adapter.transform(self.numeric(),'numeric_vm.py')

if __name__=='__main__':unittest.main()
