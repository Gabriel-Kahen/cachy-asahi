#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real temporary tree races and mocked child controls; no compiler/VM actors."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock,patch
spec=importlib.util.spec_from_file_location('derived_scan_kernel',Path(__file__).with_name('build_kernel.py'))
H=importlib.util.module_from_spec(spec);spec.loader.exec_module(H)


class Scan(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        (self.root/'build/lib').mkdir(parents=True);(self.root/'linux-asahi-7.1.13-3/lib').mkdir(parents=True)
        self.child=SimpleNamespace(poll=lambda:None)

    def disappearance(self,path,active):
        path.write_bytes(b'data');original=Path.lstat;done=False
        def lstat(p,*a,**kw):
            nonlocal done
            if p==path and not done:done=True;p.unlink()
            return original(p,*a,**kw)
        with patch.object(Path,'lstat',autospec=True,side_effect=lstat):return H.usage(self.root,active_child=active)

    def test_active_compiler_dependency_file_disappearance_is_transient(self):
        self.assertGreaterEqual(self.disappearance(self.root/'build/lib/.bitrev.o.d',self.child),0)

    def test_completed_child_and_strict_final_scan_refuse_same_disappearance(self):
        for child in (None,SimpleNamespace(poll=lambda:0)):
            with self.subTest(child=child),self.assertRaises(FileNotFoundError):
                self.disappearance(self.root/'build/lib/.bitrev.o.d',child)

    def test_active_source_and_workspace_metadata_disappearance_stay_fatal(self):
        for path in (self.root/'linux-asahi-7.1.13-3/lib/bitrev.c',self.root/'build-receipt.json'):
            with self.subTest(path=path),self.assertRaises(FileNotFoundError):self.disappearance(path,self.child)

    def test_missing_workspace_or_compiler_output_root_stay_fatal(self):
        with self.assertRaises(FileNotFoundError):H.usage(self.root/'missing',self.child)
        (self.root/'build/lib').rmdir();(self.root/'build').rmdir()
        with self.assertRaises(FileNotFoundError):H.usage(self.root,self.child)

    def test_permission_and_other_errors_stay_fatal(self):
        target=self.root/'build/lib/entry';target.write_bytes(b'x');original=Path.lstat
        for error in (PermissionError('denied'),NotADirectoryError('changed'),OSError('I/O failure')):
            def lstat(p,*a,**kw):
                if p==target:raise error
                return original(p,*a,**kw)
            with patch.object(Path,'lstat',autospec=True,side_effect=lstat),self.assertRaises(type(error)):H.usage(self.root,self.child)

    def test_directory_enumeration_source_error_not_silently_swallowed(self):
        original=H.os.scandir;source=self.root/'linux-asahi-7.1.13-3'
        def scan(p):
            if p==source:raise PermissionError('source directory denied')
            return original(p)
        with patch.object(H.os,'scandir',side_effect=scan),self.assertRaises(PermissionError):H.usage(self.root,self.child)

    def test_symbolic_links_are_not_followed_or_charged_as_target(self):
        before=H.usage(self.root);(self.root/'outside').symlink_to('/nonexistent/private-data')
        self.assertEqual(H.usage(self.root),before)

    def run_mock(self,allocation=0,deadline=1,final_allocation=0):
        child=Mock(pid=123456,returncode=0);child.poll.side_effect=[None,0,0]
        with patch.object(H.subprocess,'Popen',return_value=child),patch.object(H.os,'killpg',side_effect=ProcessLookupError),\
             patch.object(H.time,'sleep'),patch.object(H.time,'monotonic',return_value=0),\
             patch.object(H,'usage',side_effect=[allocation,final_allocation]) as scan:
            H.run(['mocked-make'],self.root/'command.log',{},self.root,deadline,[])
            self.assertEqual(scan.call_args_list[0].kwargs,dict(active_child=child))
            self.assertEqual(scan.call_args_list[1].kwargs,{})

    def test_periodic_and_completed_quota_and_deadline_stay_fatal(self):
        for periodic,final,deadline,reason in ((H.TOTAL_LIMIT+1,0,1,'workspace allocation'),
            (0,H.TOTAL_LIMIT+1,1,'completed command'),(0,0,-1,'whole build deadline')):
            with self.subTest(reason=reason),self.assertRaisesRegex(ValueError,reason):self.run_mock(periodic,deadline,final)
            (self.root/'command.log').unlink()

    def test_active_scans_and_final_strict_scan_have_separate_call_contracts(self):self.run_mock()


if __name__=='__main__':unittest.main(verbosity=2)
