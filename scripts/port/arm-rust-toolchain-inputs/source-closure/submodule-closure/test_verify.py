#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline retained-record controls; no network, archive scan or publisher imports."""
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import resource
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('submodule_identity_verifier',HERE/'verify.py')
V=importlib.util.module_from_spec(spec);spec.loader.exec_module(V)


class IdentityControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.records={}
        for p in(HERE/'records').iterdir():
            raw=V.read(p)
            cls.records[p.name]=raw if p.suffix=='.graphql'else V.decode(raw)
            if p.suffix=='.json':cls.records[p.name+'_raw']=raw
        cls.source=V.decode(V.read(HERE.parent/'source-inputs.json'))
        cls.auth=V.decode(V.read(HERE.parent/'authentication/successor-evidence.json'))
        projection=cls.records['archive-declarations.json'];archive=cls.source['archives']['rustc-1.99.0-src.tar.xz']
        # Minimal modeled view of retained scan fields. Actual full2.7MiB report rejoin is a separate CLI replay.
        cls.inventory=dict(status='COMPLETE_BOUNDED_SCAN',authenticated_source_pin_verified=True,
            compressed_bytes_read=archive['bytes'],compressed_sha256_observed=archive['checksums']['sha256'],
            selected_metadata=[projection['gitmodules']],submodule_declarations=projection['submodule_declarations'])

    def reconcile(self,records=None,inventory=None):
        return V.reconcile(records or self.records,inventory or self.inventory,self.source,self.auth)

    def test_retained_identities_and_precise_GCC_lower_bound(self):
        report=self.reconcile();self.assertEqual(report,V.decode(V.read(HERE/'report.json')))
        self.assertEqual(len(report['submodules']),12);self.assertEqual(report['metadata_requests'],4)
        gcc=next(r for r in report['submodules']if r['path']=='src/gcc')
        self.assertEqual(gcc['minimum_absent_upstream_root_regular_files'],45)
        self.assertEqual(gcc['minimum_absent_upstream_root_payload_bytes'],2592801)
        self.assertTrue(all(r['payload_identity_at_gitlink_commit']=='NOT_VERIFIED'for r in report['submodules']))

    def test_tree_bytes_omissions_modes_and_duplicate_names_refuse(self):
        for change in('omission','oid','mode','duplicate'):
            d=deepcopy(self.records);t=d['rust-tree.json']['data']['rust']['doc']
            if change=='omission':t['entries'].pop()
            elif change=='oid':t['entries'][0]['oid']='0'*40
            elif change=='mode':t['entries'][0]['mode']=0o100600
            else:t['entries'].append(deepcopy(t['entries'][0]))
            with self.subTest(change=change),self.assertRaises(ValueError):self.reconcile(d)

    def test_Rust_commit_root_and_disconnected_path_tree_refuse(self):
        for change in('commit','root','src'):
            d=deepcopy(self.records);r=d['rust-tree.json']['data']['rust']
            if change=='commit':r['commit']['oid']='0'*40
            elif change=='root':r['commit']['tree']['oid']='0'*40
            else:r['src']=deepcopy(r['doc'])
            with self.subTest(change=change),self.assertRaises(ValueError):self.reconcile(d)

    def test_repository_owner_identity_or_missing_commit_refuses(self):
        for change in('owner','name','id','missing','commit'):
            d=deepcopy(self.records);r=d['upstreams.json']['data']['r6']
            if change=='owner':r['owner']['login']='llvm'
            elif change=='name':r['nameWithOwner']='llvm/llvm-project'
            elif change=='id':r['databaseId']=True
            elif change=='missing':r['object']=None
            else:r['object']['oid']='0'*40
            with self.subTest(change=change),self.assertRaises(ValueError):self.reconcile(d)

    def test_upstream_truncated_tree_and_GCC_sizes_fail(self):
        d=deepcopy(self.records);d['upstream-root-trees.json']['data']['r0']['object']['tree']['entries'].pop()
        with self.assertRaises(ValueError):self.reconcile(d)
        d=deepcopy(self.records);e=next(e for e in d['gcc-root-sizes.json']['data']['gcc']['object']['tree']['entries']if e['mode']==0o100644)
        e['object']['byteSize']=True
        with self.assertRaises(ValueError):self.reconcile(d)

    def test_archive_pin_declaration_and_presence_mismatch_refuses(self):
        for change in('pin','declaration','presence','status'):
            d=deepcopy(self.inventory)
            if change=='pin':d['selected_metadata'][0]['sha256']='0'*64
            elif change=='declaration':d['selected_metadata'][0]['declarations']['submodules'][0]['url']='https://github.com/other/repo.git'
            elif change=='presence':d['submodule_declarations'].pop()
            else:d['status']='PARTIAL'
            with self.subTest(change=change),self.assertRaises(ValueError):self.reconcile(inventory=d)

    def test_unsafe_or_duplicate_gitmodule_paths_and_urls_refuse(self):
        text=self.records['rust-tree.json']['data']['rust']['modules']['text']
        for old,new in [('path = src/doc/nomicon','path = ../escape'),
                        ('path = src/doc/nomicon','path = src/tools/cargo'),
                        ('https://github.com/rust-lang/nomicon.git','http://github.com/rust-lang/nomicon.git')]:
            self.assertIn(old,text)
            with self.subTest(new=new),self.assertRaises(ValueError):V.declarations(text.replace(old,new))

    def test_primary_errors_and_request_budget_or_receipt_mismatch_refuse(self):
        for change in('errors','requests','bytes','response'):
            d=deepcopy(self.records)
            if change=='errors':d['upstreams.json']['errors']=[{'message':'partial'}]
            elif change=='requests':d['requests.json']['requests']*=6
            elif change=='bytes':d['requests.json']['requests'][0]['bytes']=8*1024**2+1
            else:d['requests.json']['requests'][0]['sha256']='0'*64
            with self.subTest(change=change),self.assertRaises(ValueError):self.reconcile(d)

    def test_duplicate_JSON_and_nonfinite_values_refuse(self):
        for raw in(b'{"x":1,"x":2}',b'{"x":NaN}'):
            with self.assertRaises(ValueError):V.decode(raw)

    def test_read_refuses_symlink_FIFO_hardlink_oversize_and_bad_pin(self):
        with tempfile.TemporaryDirectory()as d:
            r=Path(d);p=r/'data';p.write_bytes(b'{}')
            with self.assertRaises(ValueError):V.read(p,dict(bytes=2,sha256='0'*64))
            s=r/'link';s.symlink_to(p)
            with self.assertRaises(ValueError):V.read(s)
            s.unlink();os.mkfifo(s)
            with self.assertRaises(ValueError):V.read(s)
            s.unlink();os.link(p,s)
            with self.assertRaises(ValueError):V.read(p)
            s.unlink()
            with p.open('wb')as f:f.truncate(4*1024**2+1)
            with self.assertRaises(ValueError):V.read(p)

    def test_read_race_to_symlink_or_FIFO_refuses_without_blocking(self):
        for kind in('symlink','FIFO'):
            with tempfile.TemporaryDirectory()as d:
                p=Path(d)/'data';p.write_bytes(b'{}');original_open=os.open
                def replace(path,flags):
                    p.rename(p.with_suffix('.old'))
                    if kind=='symlink':p.symlink_to(p.with_suffix('.old'))
                    else:os.mkfifo(p)
                    return original_open(path,flags)
                with self.subTest(kind=kind),patch.object(V.os,'open',replace),self.assertRaises((ValueError,OSError)):V.read(p)

    def test_read_growth_is_bounded_and_refused(self):
        with tempfile.TemporaryDirectory()as d:
            p=Path(d)/'data';p.write_bytes(b'{}');original=os.fdopen
            def grow(fd,*args):
                stream=original(fd,*args)
                with p.open('wb')as f:f.truncate(5*1024**2)
                return stream
            with patch.object(V.os,'fdopen',grow),self.assertRaises(ValueError):V.read(p)


if __name__=='__main__':
    resource.setrlimit(resource.RLIMIT_AS,(128*1024**2,128*1024**2))
    unittest.main(verbosity=2)
