#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Temporary real package archives only; never touch the host ALPM/cache directories."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('package_cache', Path(__file__).with_name('package_cache.py'))
c = importlib.util.module_from_spec(spec);spec.loader.exec_module(c)


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='package-cache-test-');self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name);self.cache = self.root/'cache';self.db = self.root/'db'
        self.cache.mkdir(mode=0o700);self.db.mkdir(mode=0o700)
        self.archives = {v:self.package(v) for v in range(1, 6)}
        self.duplicate = self.package(2, suffix='xz')
        pin = self.archives[1]
        self.policy = {'schema_version':1, 'retain_versions':3, 'known_packages':[{'name':'demo','arch':'any'}],
            'protected':[{'filename':pin.name, 'name':'demo', 'version':'1.0-1', 'arch':'any',
                          'sha256':hashlib.sha256(pin.read_bytes()).hexdigest()}]}

    def package(self, version, name='demo', suffix='gz', payload=b'package fixture\n', arch='any'):
        path = self.cache/f'{name}-{version}.0-1-{arch}.pkg.tar.{suffix}'
        raw = f'pkgname = {name}\npkgver = {version}.0-1\narch = {arch}\nlicense = MIT\n'.encode()
        with tarfile.open(path,'w:'+suffix) as archive:
            for name,data in {'.PKGINFO':raw,'usr/share/fixture':payload}.items():
                member = tarfile.TarInfo(name);member.size=len(data);archive.addfile(member,io.BytesIO(data))
        return path

    def preview(self):return c.preview(self.cache,self.db,self.policy)

    def apply(self, plan, selected):
        return c.apply(self.cache,self.db,self.policy,plan,c.digest(c.encoded(plan)),selected)

    def snapshot(self):
        return {p.name:('link',os.readlink(p)) if p.is_symlink() else ('file',p.read_bytes())
                for p in self.cache.iterdir() if p.is_file() or p.is_symlink()}

    def test_preview_preserves_rollback_and_three_versions_and_duplicates(self):
        before=self.snapshot();plan=self.preview()
        actions={r['filename']:r['action'] for r in plan['entries']}
        self.assertEqual(actions[self.archives[1].name],'protected')
        for v in (3,4,5):self.assertEqual(actions[self.archives[v].name],'retained')
        self.assertEqual(actions[self.archives[2].name],'candidate')
        self.assertEqual(actions[self.duplicate.name],'candidate')
        self.assertEqual(self.snapshot(),before);self.assertEqual(list(self.db.iterdir()),[])

    def test_apply_deletes_only_selected_duplicate(self):
        plan=self.preview();before=self.snapshot()
        result=self.apply(plan,[self.duplicate.name])
        self.assertEqual(result,{'status':'applied','deleted':[self.duplicate.name],'retained_quarantine':None})
        del before[self.duplicate.name];self.assertEqual(self.snapshot(),before)
        self.assertEqual(list(self.db.iterdir()),[])

    def test_unknown_corrupt_foreign_arch_and_symlinks_are_preserved(self):
        unknown=self.package(1,name='unlisted');foreign=self.package(1,name='demo',arch='x86_64')
        corrupt=self.cache/'corrupt.pkg.tar.gz';corrupt.write_bytes(b'not an archive')
        link=self.cache/'linked.pkg.tar.gz';link.symlink_to(self.archives[2])
        sidecar=self.cache/(self.archives[2].name+'.sig');sidecar.write_bytes(b'opaque signature')
        before=self.snapshot();plan=self.preview();rows={r['filename']:r for r in plan['entries']}
        for path in (unknown,foreign,corrupt,link,sidecar):
            self.assertEqual(rows[path.name]['action'],'unknown')
            with self.assertRaises(c.ApplyError):self.apply(plan,[path.name])
        self.assertEqual(self.snapshot(),before)

    def test_bad_compression_trailer_is_unknown_and_cannot_be_deleted(self):
        raw=bytearray(self.archives[2].read_bytes());raw[-8] ^= 1;self.archives[2].write_bytes(raw)
        plan=self.preview();row=next(r for r in plan['entries'] if r['filename']==self.archives[2].name)
        self.assertEqual(row['action'],'unknown')
        with self.assertRaises(c.ApplyError):self.apply(plan,[self.archives[2].name])
        self.assertEqual(self.archives[2].read_bytes(),raw)

    def test_all_duplicates_of_a_protected_version_are_kept(self):
        duplicate=self.package(1,suffix='xz',payload=b'another copy of rollback version')
        plan=self.preview();row=next(r for r in plan['entries'] if r['filename']==duplicate.name)
        self.assertEqual(row['action'],'protected')
        with self.assertRaises(c.ApplyError):self.apply(plan,[duplicate.name])

    def test_retention_uses_real_alpm_version_order(self):
        for version in (2,3,4,5):self.archives[version].unlink()
        self.duplicate.unlink()
        old=self.package('1.9');retained=[self.package(v) for v in ('1.10','1.11',2)]
        actions={r['filename']:r['action'] for r in self.preview()['entries']}
        self.assertEqual(actions[old.name],'candidate')
        for path in retained:self.assertEqual(actions[path.name],'retained')

    def test_protected_missing_or_changed_refuses_before_deletion(self):
        plan=self.preview();self.archives[1].write_bytes(b'changed rollback archive')
        before=self.snapshot()
        with self.assertRaises(c.Error):self.preview()
        with self.assertRaises(c.ApplyError):self.apply(plan,[self.archives[2].name])
        self.assertEqual(self.snapshot(),before)

    def test_preview_replacement_changed_policy_and_digest_refuse(self):
        plan=self.preview();old=self.archives[2].read_bytes();self.archives[2].unlink();self.archives[2].write_bytes(old)
        before=self.snapshot()
        with self.assertRaises(c.ApplyError):self.apply(plan,[self.archives[2].name])
        plan=self.preview();self.policy['retain_versions']=4
        with self.assertRaises(c.ApplyError):self.apply(plan,[self.archives[2].name])
        with self.assertRaises(c.ApplyError):c.apply(self.cache,self.db,self.policy,plan,'0'*64,[self.archives[2].name])
        self.assertEqual(self.snapshot(),before)

    def test_active_or_stale_alpm_lock_is_never_removed(self):
        plan=self.preview();lock=self.db/'db.lck';lock.write_bytes(b'foreign transaction\n');before=self.snapshot()
        with self.assertRaises(c.Error):self.preview()
        with self.assertRaises(c.ApplyError):self.apply(plan,[self.archives[2].name])
        self.assertEqual(lock.read_bytes(),b'foreign transaction\n');self.assertEqual(self.snapshot(),before)

    def test_protected_retained_empty_duplicate_and_traversal_selections_refuse(self):
        plan=self.preview();before=self.snapshot()
        for selected in ([],[self.archives[1].name],[self.archives[5].name],['../escape.pkg.tar.gz'],[self.duplicate.name]*2):
            with self.subTest(selected=selected),self.assertRaises(c.ApplyError):self.apply(plan,selected)
        self.assertEqual(self.snapshot(),before)

    def test_replacement_at_claim_is_restored_without_deletion(self):
        plan=self.preview();name=self.archives[2].name;original=c.os.rename
        def replace(source,target,**kwargs):
            self.archives[2].unlink();self.archives[2].write_bytes(b'foreign replacement')
            return original(source,target,**kwargs)
        with mock.patch.object(c.os,'rename',side_effect=replace):
            with self.assertRaises(c.ApplyError) as failure:self.apply(plan,[name])
        self.assertEqual(failure.exception.deleted,[]);self.assertIsNone(failure.exception.quarantine)
        self.assertEqual(self.archives[2].read_bytes(),b'foreign replacement')
        self.assertFalse((self.db/'db.lck').exists())

    def test_restore_collision_preserves_both_replacements_and_reports_quarantine(self):
        plan=self.preview();name=self.archives[2].name;original=c.os.rename
        def replace(source,target,**kwargs):
            self.archives[2].unlink();self.archives[2].write_bytes(b'claimed foreign bytes')
            result=original(source,target,**kwargs);self.archives[2].write_bytes(b'concurrent cache bytes');return result
        with mock.patch.object(c.os,'rename',side_effect=replace):
            with self.assertRaises(c.ApplyError) as failure:self.apply(plan,[name])
        self.assertEqual(failure.exception.deleted,[])
        self.assertEqual(self.archives[2].read_bytes(),b'concurrent cache bytes')
        self.assertEqual((Path(failure.exception.quarantine)/name).read_bytes(),b'claimed foreign bytes')
        self.assertFalse((self.db/'db.lck').exists())

    def test_cancellation_before_and_during_batch_reports_partial_progress(self):
        plan=self.preview();before=self.snapshot();original=c.record
        with mock.patch.object(c,'record',side_effect=KeyboardInterrupt('cancelled')):
            with self.assertRaises(c.ApplyError) as stopped:self.apply(plan,[self.duplicate.name])
        self.assertTrue(stopped.exception.cancelled);self.assertEqual(stopped.exception.deleted,[])
        self.assertEqual(self.snapshot(),before);self.assertFalse((self.db/'db.lck').exists())
        count=[]
        def cancel_second(fd,name):
            row=original(fd,name)
            if row.get('sha256') and row['package']['version']=='2.0-1':
                count.append(name)
                # Two candidate records in whole-preview recheck, then source/claimed first.
                if len(count)==5:raise KeyboardInterrupt('cancelled')
            return row
        with mock.patch.object(c,'record',side_effect=cancel_second):
            with self.assertRaises(c.ApplyError) as stopped:self.apply(plan,[self.duplicate.name,self.archives[2].name])
        self.assertEqual(stopped.exception.deleted,[self.duplicate.name])
        self.assertTrue(self.archives[2].exists());self.assertFalse(self.duplicate.exists())
        self.assertFalse((self.db/'db.lck').exists())

    def test_replaced_alpm_lock_is_retained_and_no_archive_deleted(self):
        plan=self.preview();original=c.plan_for
        def replace(*args):
            result=original(*args);lock=self.db/'db.lck';lock.unlink();lock.write_bytes(b'foreign');return result
        with mock.patch.object(c,'plan_for',side_effect=replace):
            with self.assertRaises(c.ApplyError) as failure:self.apply(plan,[self.duplicate.name])
        self.assertEqual(failure.exception.deleted,[])
        self.assertEqual((self.db/'db.lck').read_bytes(),b'foreign')
        self.assertTrue(failure.exception.cleanup_notes)

    def test_acquisition_fstat_failure_retains_unknown_lock_and_first_cause(self):
        first=OSError('acquisition fstat failed');original=c.os.fstat
        old_mask=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGUSR1})
        expected_mask=signal.pthread_sigmask(signal.SIG_BLOCK,set())
        try:
            with c.roots(self.cache,self.db) as (paths,fds):
                def fail_lock(fd):
                    if fd not in fds:raise first
                    return original(fd)
                with mock.patch.object(c.os,'fstat',side_effect=fail_lock):
                    with self.assertRaises(OSError) as failure:
                        with c.transaction_lock(paths,fds):self.fail('identity-unknown lock was yielded')
                self.assertIs(failure.exception,first)
                self.assertTrue(any('identity unavailable' in n for n in first.__notes__))
            self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK,set()),expected_mask)
            self.assertEqual((self.db/'db.lck').read_bytes(),b'')
        finally:signal.pthread_sigmask(signal.SIG_SETMASK,old_mask)

    def test_close_failure_always_restores_signal_mask(self):
        close_error=OSError('injected close failure');original=c.os.close;closed=[]
        old_mask=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGUSR1})
        expected_mask=signal.pthread_sigmask(signal.SIG_BLOCK,set())
        try:
            with c.roots(self.cache,self.db) as (paths,fds):
                def close_then_fail(fd):
                    original(fd)
                    if fd not in fds:closed.append(fd);raise close_error
                with mock.patch.object(c.os,'close',side_effect=close_then_fail):
                    with self.assertRaises(OSError) as failure:
                        with c.transaction_lock(paths,fds) as guard:guard()
                self.assertIs(failure.exception,close_error)
            self.assertEqual(len(closed),1)
            self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK,set()),expected_mask)
            self.assertFalse((self.db/'db.lck').exists())
            self.assertTrue(any('closure uncertain' in n for n in close_error.__notes__))
        finally:signal.pthread_sigmask(signal.SIG_SETMASK,old_mask)

    def test_close_failure_cannot_replace_body_first_error(self):
        first=c.Error('original apply failure');original=c.os.close
        before=signal.pthread_sigmask(signal.SIG_BLOCK,set())
        with c.roots(self.cache,self.db) as (paths,fds):
            def close_then_fail(fd):
                original(fd)
                if fd not in fds:raise OSError('later close failure')
            with mock.patch.object(c.os,'close',side_effect=close_then_fail):
                with self.assertRaises(c.Error) as failure:
                    with c.transaction_lock(paths,fds):raise first
        self.assertIs(failure.exception,first)
        self.assertTrue(any('later close failure' in n for n in first.__notes__))
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK,set()),before)
        self.assertFalse((self.db/'db.lck').exists())

    def test_real_sigterm_after_unlink_records_completed_delete(self):
        plan=self.preview();name=self.duplicate.name;original=c.os.unlink;queued=[]
        def interrupt(target,**kwargs):
            if target==name and not queued:
                queued.append(True);os.kill(os.getpid(),signal.SIGTERM)
            return original(target,**kwargs)
        previous=signal.signal(signal.SIGTERM,c.cancelled)
        try:
            with mock.patch.object(c.os,'unlink',side_effect=interrupt):
                with self.assertRaises(c.ApplyError) as failure:self.apply(plan,[name,self.archives[2].name])
        finally:signal.signal(signal.SIGTERM,previous)
        self.assertTrue(failure.exception.cancelled)
        self.assertEqual(failure.exception.deleted,[name])
        self.assertFalse(self.duplicate.exists());self.assertTrue(self.archives[2].exists())
        self.assertFalse((self.db/'db.lck').exists())

    def test_zstd_metadata_and_corrupt_zstd_are_preserved_safely(self):
        if c.zstd is None:
            path=self.cache/'opaque.pkg.tar.zst';path.write_bytes(b'unsupported compression')
            row=next(r for r in self.preview()['entries'] if r['filename']==path.name)
            self.assertEqual(row['action'],'unknown');return
        raw=io.BytesIO()
        with tarfile.open(fileobj=raw,mode='w') as archive:
            metadata=b'pkgname = demo\npkgver = 2.0-1\narch = any\nlicense = MIT\n'
            member=tarfile.TarInfo('.PKGINFO');member.size=len(metadata);archive.addfile(member,io.BytesIO(metadata))
        path=self.cache/'demo-2.0-1-any.pkg.tar.zst';path.write_bytes(c.zstd.compress(raw.getvalue()))
        row=next(r for r in self.preview()['entries'] if r['filename']==path.name)
        self.assertEqual(row['action'],'candidate')
        path.write_bytes(b'invalid zstd')
        row=next(r for r in self.preview()['entries'] if r['filename']==path.name)
        self.assertEqual(row['action'],'unknown')

    def test_symlink_roots_overlap_and_writable_directories_refuse(self):
        link=self.root/'alias';link.symlink_to(self.cache)
        for cache,database in ((link,self.db),('/'+str(self.cache),self.db),(self.cache,self.cache)):
            with self.assertRaises(c.Error):c.preview(cache,database,self.policy)
        self.cache.chmod(0o777)
        with self.assertRaises(c.Error):self.preview()

    def test_no_candidates_preview_and_changed_plan_types_are_not_authority(self):
        self.policy['retain_versions']=5;before=self.snapshot();plan=self.preview()
        self.assertFalse(any(r['action']=='candidate' for r in plan['entries']))
        self.assertEqual(self.snapshot(),before)
        self.policy['retain_versions']=3;plan=self.preview();plan['schema_version']=True
        with self.assertRaises(c.ApplyError):self.apply(plan,[self.duplicate.name])
        self.assertEqual(self.snapshot(),before)

    def test_minimum_retention_and_strict_json(self):
        for value in (0,1,2,True):
            policy=copy.deepcopy(self.policy);policy['retain_versions']=value
            with self.assertRaises(c.Error):c.preview(self.cache,self.db,policy)
        for raw in (b'{"a":1,"a":2}',b'{"a":1.0}',b'{"a":NaN}'):
            with self.assertRaises(c.Error):c.decode(raw)

    def test_cli_preview_and_explicit_apply_only_temporary_paths(self):
        policy=self.root/'policy.json';policy.write_bytes(c.encoded(self.policy))
        argv=[sys.executable,'-I','-B',str(Path(c.__file__)), '--cache',str(self.cache),'--db-path',str(self.db),'--policy',str(policy)]
        result=subprocess.run(argv,capture_output=True,timeout=30);self.assertEqual(result.returncode,0,result.stderr)
        plan=self.root/'preview.json';plan.write_bytes(result.stdout)
        result=subprocess.run(argv+['--apply','--plan',str(plan),'--plan-sha256',c.digest(result.stdout),'--select',self.duplicate.name],capture_output=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['deleted'],[self.duplicate.name])


if __name__=='__main__':unittest.main()
