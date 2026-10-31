#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert exact numeric-metadata admission; no namespace, ALPM or chown actors."""
import copy
import gzip
import hashlib
import importlib.util
import io
from pathlib import Path
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
ROOT=next(p for p in HERE.parents if (p/'manifests/packages.toml').is_file())


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module


p=load('profile',HERE/'profile.py')
stream=load('numeric_archive_stream',ROOT/'scripts/update/archive_stream.py')


def member(name,value):
    kind,uid,gid,mode,size=value
    row=tarfile.TarInfo(name);row.type=kind;row.uid=uid;row.gid=gid;row.mode=mode;row.size=size;return row


def fixture(rows):
    raw=io.BytesIO()
    with tarfile.open(fileobj=raw,mode='w') as archive:
        for row in rows:archive.addfile(row,io.BytesIO(b'x'*row.size) if row.isfile() else None)
    return gzip.compress(raw.getvalue())


def limits():return stream.Limits(1024**2,2*1024**2,4*1024**2,100,1024**2,16*1024**2,time.monotonic()+30)


class ExactPolicyControls(unittest.TestCase):
    def test_all_six_signed_rows_preserve_numbers_and_special_modes(self):
        seen=[]
        for key,declared in p.GROUP_METADATA.items():
            for name,value in declared.items():
                actual=p.numeric_metadata(member(name,value),name,declared)
                self.assertEqual(actual,dict(mode=value[3],uid=value[1],gid=value[2]));seen.append(actual)
        self.assertEqual(len(seen),6);self.assertEqual({r['gid'] for r in seen},{5,11,50,81,102})
        self.assertIn(0o4110,{r['mode'] for r in seen});self.assertIn(0o2755,{r['mode'] for r in seen})
    def test_each_changed_uid_gid_mode_type_or_size_refuses(self):
        for _,declared in p.GROUP_METADATA.items():
            for name,value in declared.items():
                for index,new in ((0,b'2'),(1,1),(2,999),(3,0o755),(4,value[4]+1)):
                    wrong=list(value);wrong[index]=new
                    with self.subTest(path=name,index=index),self.assertRaisesRegex(ValueError,'metadata differs'):
                        p.numeric_metadata(member(name,wrong),name,declared)
    def test_flattening_known_group_to_root_is_also_refused(self):
        declared=next(iter(p.GROUP_METADATA.values()));name,value=next(iter(declared.items()))
        wrong=list(value);wrong[2]=0
        with self.assertRaisesRegex(ValueError,'metadata differs'):p.numeric_metadata(member(name,wrong),name,declared)
    def test_other_nonroot_names_or_packages_are_never_authorized(self):
        value=(b'0',0,81,0o4110,1)
        for name,declared in (('elsewhere',next(iter(p.GROUP_METADATA.values()))),('usr/lib/dbus-daemon-launch-helper',{})):
            with self.assertRaisesRegex(ValueError,'undeclared nonroot'):p.numeric_metadata(member(name,value),name,declared)
    def test_single_id_backend_refuses_real_group_requirements_without_flattening(self):
        payload={'nodes':{str(i):dict(uid=0,gid=gid) for i,gid in enumerate((0,5,11,50,81,102))}}
        before=copy.deepcopy(payload)
        with self.assertRaisesRegex(ValueError,'NUMERIC_ID_ADAPTER_REQUIRED'):p.require_single_id_backend(payload)
        self.assertEqual(payload,before)
        self.assertEqual(p.require_single_id_backend({'nodes':{'root-owned':dict(uid=0,gid=0)}}),dict(uids=[0],gids=[0]))


class StreamBindingControls(unittest.TestCase):
    def inspect(self,rows,*,catalog=None,package=None):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'test.tar.gz';path.write_bytes(fixture(rows))
            key=('inert-fixture','1-1',hashlib.sha256(path.read_bytes()).hexdigest())
            row=dict(name=key[0],version=key[1],sha256=key[2]) if package is None else package
            with patch.dict(p.GROUP_METADATA,{key:catalog or {}},clear=False):
                return p.archive(path,stream,limits(),dict(bytes=0,nodes=0,compressed_bytes=0),package=row)
    def test_catalog_bound_fixture_preserves_group_and_setgid_mode_in_payload(self):
        declaration={'usr/bin/inert':(b'0',0,5,0o2755,1)}
        rows,groups=self.inspect([member('usr/bin/inert',declaration['usr/bin/inert'])],catalog=declaration)
        self.assertEqual(rows['usr/bin/inert']['gid'],5);self.assertEqual(rows['usr/bin/inert']['mode'],0o2755)
        self.assertEqual(groups,[])
    def test_real_package_label_cannot_authorize_different_archive_bytes(self):
        key=next(iter(p.GROUP_METADATA));declared=p.GROUP_METADATA[key];name,value=next(iter(declared.items()))
        with self.assertRaisesRegex(ValueError,'archive bytes differ'):
            self.inspect([member(name,(b'0',0,value[2],value[3],1))],package=dict(name=key[0],version=key[1],sha256=key[2]))
    def test_wrong_package_version_or_digest_never_gets_exception(self):
        for change in (dict(name='other'),dict(version='other'),dict(sha256='0'*64)):
            with tempfile.TemporaryDirectory() as temp:
                key=next(iter(p.GROUP_METADATA));row=dict(name=key[0],version=key[1],sha256=key[2]);row.update(change)
                with self.assertRaisesRegex(ValueError,'undeclared nonroot'):
                    self.inspect([member('usr/lib/dbus-daemon-launch-helper',(b'0',0,81,0o4110,1))],package=row)
    def test_expected_exception_member_must_exist(self):
        with self.assertRaisesRegex(ValueError,'entry missing'):
            self.inspect([member('other',(b'0',0,0,0o644,1))],catalog={'missing':(b'0',0,5,0o2755,1)})
    def test_duplicate_member_remains_refused_even_if_exactly_authorized(self):
        declaration={'inert':(b'0',0,5,0o2755,1)};row=member('inert',declaration['inert'])
        with self.assertRaisesRegex(ValueError,'duplicate'):self.inspect([row,row],catalog=declaration)
    def test_special_member_and_undeclared_nonroot_still_refuse(self):
        with self.assertRaisesRegex(ValueError,'special'):
            self.inspect([member('fifo',(tarfile.FIFOTYPE,0,0,0o644,0))])
        with self.assertRaisesRegex(ValueError,'undeclared nonroot'):
            self.inspect([member('other',(b'0',0,7,0o644,1))])


if __name__=='__main__':unittest.main()
