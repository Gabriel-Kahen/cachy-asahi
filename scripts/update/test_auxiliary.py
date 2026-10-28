#!/usr/bin/env python3
"""Inert copied files and real descriptor/chroot controls; no held ELF execution.

Run as mapped root: unshare --user --map-root-user python3 -B <this file>.
Positive closure fixtures patch only the held binary/target byte pins to inert
bytes. UID/mode/config/comparator and containment rules stay production values.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).absolute().parent
REPO=HERE.parents[1]
sys.path.insert(0,str(HERE))
import aux_checkpoint as aux
import aux_initialize as init
import aux_runtime as runtime

COMPARATOR=REPO/'scripts/ci/full-development-composition/audio_aux.py'

def digest(data): return hashlib.sha256(data).hexdigest()

def encoded(rows):
    strings=bytearray(b'\0'); records=[]
    for key in rows:
        name=b'libfixture.so'; offset=len(strings); strings.extend(name+b'\0')
        records.append(struct.pack('<QQQQiII',*key,1,offset,0)+b'\0'*4)
    return b'glibc-ld.so.auxcache-2.0'+struct.pack('<II',len(rows),len(strings))+b''.join(records)+bytes(strings)

class Dependency(unittest.TestCase):
    def limits(self): return aux.roots.Limits(deadline=time.monotonic()+20,max_nodes=1000,max_bytes=64*1024**2,max_file_bytes=8*1024**2)
    def test_exact_comparator_loaded_from_pinned_bytes(self):
        module=aux.load_comparator(COMPARATOR,self.limits())
        self.assertEqual(module.compare(b'inert',b'inert'),{'kind':'RAW_EQUAL'})
    def test_changed_or_symlinked_source_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/'module.py'; path.write_text("raise AssertionError('must not execute')\n")
            with self.assertRaisesRegex(ValueError,'source-pin'): aux.load_comparator(path,self.limits())
            path.unlink(); path.symlink_to(COMPARATOR)
            with self.assertRaises(OSError): aux.load_comparator(path,self.limits())

@unittest.skipUnless(os.geteuid()==0,'mapped root required for exact UID0 fixtures')
class Closure(unittest.TestCase):
    limits=Dependency.limits
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='aux-fixture-'); self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name); self.work=self.base/'work'; self.work.mkdir(mode=0o700)
        self.root=self.work/'root'; self.root.mkdir(); self.source=self.base/'source'
        self.comparator=aux.load_comparator(COMPARATOR,self.limits())
        helper=b'INERT helper bytes; never executed\n'; self.write(aux.HELPER_NODE,helper,0o755)
        self.write('etc/ld.so.conf',b'# Dynamic linker/loader configuration.\n# See ld.so(8) and ldconfig(8) for details.\n\ninclude /etc/ld.so.conf.d/*.conf\ninclude /usr/lib/ld.so.conf.d/*.conf\n')
        self.write(aux.FAKE_CONF,b'/usr/lib/libfakeroot\n')
        self.mkdir(aux.FAKE_DIR)
        self.write('usr/lib/libfixture-a.so',b'\x7fELFinert library a')
        self.write('usr/lib/libfixture-b.so',b'\x7fELFinert library b')
        (self.root/'usr/lib/libfixture.so').symlink_to('libfixture-a.so')
        (self.root/'usr/lib64').symlink_to('lib')
        (self.root/'usr/sbin').symlink_to('bin'); (self.root/'sbin').symlink_to('usr/bin')
        targets={}
        for name in aux.TARGETS:
            data=('inert '+name).encode(); self.write(name,data,0o755); targets[name]=(len(data),digest(data))
        self.write(aux.MAIN_CACHE,b'opaque held main cache')
        self.mkdir('var/cache/ldconfig',0o700)
        self.write(aux.AUX_CACHE,encoded(self.keys()),0o600)
        self.write('home/user/config',b'user content')
        self.write('var/lib/pacman/local/cachy-asahi-setup-0.1.0-3/desc',b'inert DB')
        for name in runtime.FILES-{'usr/bin/cachy-asahi-repository','usr/share/doc/cachy-asahi-setup/repository-enrollment.md'}:
            self.write(name,b'old setup content')
        for name,value in (('HELPER',(digest(helper),len(helper))),('TARGETS',targets)):
            p=patch.object(aux,name,value); p.start(); self.addCleanup(p.stop)
        p=patch.object(aux,'load_comparator',return_value=self.comparator); p.start(); self.addCleanup(p.stop)
        shutil.copytree(self.root,self.source,symlinks=True)
        self.args=SimpleNamespace(root=str(self.root),workspace=str(self.work),scale='inert',scale_sha256='0'*64)

    def mkdir(self,name,mode=0o755):
        path=self.root/name; path.mkdir(parents=True,exist_ok=True); path.chmod(mode); return path
    def write(self,name,data,mode=0o644):
        path=self.root/name; path.parent.mkdir(parents=True,exist_ok=True)
        # pathlib's intermediate mkdir obeys umask; the fixture needs held0755 dirs.
        for parent in path.parents:
            if parent==self.root: break
            parent.chmod(0o755)
        path.write_bytes(data); path.chmod(mode); return path
    def keys(self):
        rows=[]
        for name in ('usr/lib/libfixture-a.so','usr/lib/libfixture-b.so'):
            s=(self.root/name).stat(); rows.append((s.st_ino,s.st_ctime_ns//10**9,s.st_size,s.st_dev))
        return rows
    def observation(self): return aux.roots.observe(self.root,limits=self.limits(),hardlinks='generic-development-internal')
    def state(self): return aux.checkpoint(self.root,self.observation(),self.limits())
    def config(self):
        return dict(platform_mode='generic-development',limits=dict(root_nodes=1000,root_bytes=64*1024**2,
            file_bytes=8*1024**2,package_files=1000,archive_bytes=1024**2,archive_total_bytes=2*1024**2,
            decoded_bytes=4*1024**2,archive_members=1000,window_bytes=1024**2,seconds=30))

    def test_checkpoint_joins_live_keys_without_host_resolve(self):
        with patch.object(Path,'resolve',side_effect=AssertionError('host resolve forbidden')):
            state=self.state()
        self.assertEqual(aux.live_keys(state,self.comparator)['records'],2)
        self.assertEqual(aux.compare(state,state,self.comparator)['auxiliary_exit_status'],'NOT OBSERVED')

    def test_helper_config_special_or_temporary_refused(self):
        for name,data,reason in ((aux.HELPER_NODE,b'wrong','helper-pin'),('etc/ld.so.conf',b'wrong','main-config-pin'),
                                 ('etc/ld.so.conf.d/bad.conf',b'include /outside/*\n','include-content'),
                                 (aux.AUX_CACHE+'~',b'leftover','temporary-cache')):
            with self.subTest(name=name):
                path=self.root/name; old=path.read_bytes() if path.exists() else None; mode=path.stat().st_mode&0o777 if old is not None else 0o644
                self.write(name,data,mode)
                with self.assertRaisesRegex(ValueError,reason): self.state()
                if old is None: path.unlink()
                else: self.write(name,old,mode)
        path=self.root/'usr/lib/fifo.so'; os.mkfifo(path)
        with self.assertRaises(ValueError): self.state()

    def test_listing_and_live_alias_drift_refused(self):
        reader=aux.Reader(self.root,self.observation(),self.limits())
        self.write('usr/lib/new.so',b'new')
        with self.assertRaisesRegex(ValueError,'listing-drift'): reader.children('usr/lib',8192)
        (self.root/'usr/lib/new.so').unlink()
        alias=self.root/'usr/lib64'; alias.unlink(); alias.symlink_to('bin')
        with self.assertRaisesRegex(ValueError,'link-target'): reader.capture('usr/lib64/ldconfig')

    def test_absolute_library_escape_cannot_read_host_target(self):
        outside=self.base/'host-secret'; outside.write_bytes(b'HOST SECRET')
        (self.root/'usr/lib/escape.so').symlink_to(outside)
        with self.assertRaises(ValueError): self.state()
        self.assertEqual(outside.read_bytes(),b'HOST SECRET')

    def test_stale_or_forged_auxiliary_keys_rejected(self):
        self.write(aux.AUX_CACHE,encoded([(1,2,3,4)]),0o600)
        with self.assertRaisesRegex(ValueError,'stale-or-unobserved'): aux.live_keys(self.state(),self.comparator)

    def test_exact_order_after_commit_only_and_main_bytes_held(self):
        keys=self.keys()
        expected=sorted(keys,key=lambda key:self.comparator.bucket(key,1021))
        before_order=list(reversed(expected)); self.write(aux.AUX_CACHE,encoded(before_order),0o600); before=self.state()
        self.write(aux.AUX_CACHE,encoded(expected),0o600); after=self.state()
        self.assertEqual(aux.compare(before,after,self.comparator,committed=True)['auxiliary_transition']['kind'],'EXACT_LOAD_SAVE_ORDER')
        with self.assertRaisesRegex(ValueError,'aux-changed-before-commit'): aux.compare(before,after,self.comparator)
        changed=copy.deepcopy(after); changed['main_bytes']=b'changed'
        with self.assertRaisesRegex(ValueError,'main-cache-content'): aux.compare(after,changed,self.comparator,committed=True)

    def invoke_initialization(self,worker):
        with patch.object(init.scale.bound,'guard'), patch.object(init.scale,'configuration',return_value=self.config()), \
             patch.object(init.supervision,'run',side_effect=worker):
            return init.initialize(self.args,self.source,comparator_path=COMPARATOR)
    def worker_result(self):
        return dict(returncode=0,termination=None,direct_child_reaped=True,group_kill_sent=False)

    def test_one_preparation_updates_only_caches_and_preserves_source(self):
        self.write(aux.AUX_CACHE,encoded([(1,2,3,4)]),0o600); calls=[]
        def worker(argv,**kwargs):
            calls.append((argv,kwargs)); self.write(aux.AUX_CACHE,encoded(self.keys()),0o600); return self.worker_result()
        row=self.invoke_initialization(worker)
        self.assertEqual(row['status'],'PASS',row); self.assertTrue(row['source_preserved']); self.assertTrue(row['root_initialized'])
        self.assertFalse(row['copy_byte_identical_after_initialization']); self.assertEqual(len(calls),1)
        self.assertIn('--worker',calls[0][0]); self.assertNotIn('LD_PRELOAD',calls[0][1]['env'])
        again=self.invoke_initialization(worker)
        self.assertEqual(again['status'],'FAIL'); self.assertFalse(again['initialization_started']); self.assertEqual(len(calls),1)

    def test_initialization_failure_or_unrelated_mutation_cannot_pass(self):
        for kind in ('timeout','nonzero','user','source','stale'):
            with self.subTest(kind=kind):
                marker=self.work/'aux-initialization-started'
                if marker.exists(): marker.unlink() # Independent inert cases, not production retry.
                self.write('home/user/config',b'user content')
                def worker(*args,**kwargs):
                    row=self.worker_result()
                    if kind=='timeout': row.update(returncode=-9,termination='timeout')
                    elif kind=='nonzero': row['returncode']=1
                    elif kind=='user': self.write('home/user/config',b'changed')
                    elif kind=='source': (self.source/'home/user/config').write_bytes(b'changed source')
                    else: self.write(aux.AUX_CACHE,encoded([(1,2,3,4)]),0o600)
                    return row
                row=self.invoke_initialization(worker)
                self.assertEqual(row['status'],'FAIL',row)
                if kind!='source': self.assertIsNot(row['root_initialized'],True)
                if kind=='source': self.assertIs(row['source_preserved'],False)
                if kind=='stale': self.write(aux.AUX_CACHE,encoded(self.keys()),0o600)

    def test_initializer_guard_failure_prevents_worker(self):
        with patch.object(init.scale.bound,'guard',side_effect=ValueError('guard refused')),patch.object(init.supervision,'run') as worker:
            row=init.initialize(self.args,self.source,comparator_path=COMPARATOR)
        self.assertEqual(row['status'],'FAIL'); self.assertFalse(row['initialization_started']); worker.assert_not_called()

    def test_worker_real_chroot_and_fd_pinning_without_executing_fixture(self):
        read,write=os.pipe(); pid=os.fork()
        if pid==0:
            os.close(read)
            try:
                def executed(fd,argv,env):
                    assert isinstance(fd,int) and argv==['/usr/bin/ldconfig']
                    assert os.getcwd()=='/' and Path('/home/user/config').read_bytes()==b'user content'
                    assert not Path(str(self.source)).exists()
                    assert digest(os.pread(fd,4096,0))==aux.HELPER[0]
                    assert env=={'PATH':'/usr/bin:/bin','LC_ALL':'C','LANG':'C','HOME':'/','TMPDIR':'/tmp'}
                    os.write(write,b'CHROOT_AND_FD_EXEC_BOUNDARY_PASS'); raise RuntimeError('inert exec boundary')
                original=os.execve
                with patch.object(init.scale.bound,'guard'),patch.object(os,'execve',side_effect=executed) as mocked, \
                     patch.object(os,'supports_fd',{mocked}):
                    try: init.exec_helper(self.root,self.work)
                    except RuntimeError as error: assert str(error)=='inert exec boundary'
                os._exit(0)
            except BaseException as error:
                os.write(write,(type(error).__name__+': '+str(error)).encode()); os._exit(1)
        os.close(write)
        with os.fdopen(read,'rb') as stream: data=stream.read(4096)
        _,status=os.waitpid(pid,0)
        self.assertEqual(status,0,data); self.assertEqual(data,b'CHROOT_AND_FD_EXEC_BOUNDARY_PASS')
        self.assertEqual((self.root/'home/user/config').read_bytes(),b'user content')

    def test_worker_missing_chroot_capability_cannot_exec_or_leak_fds(self):
        before=len(os.listdir('/proc/self/fd')); saved=os.open('.',os.O_RDONLY|os.O_DIRECTORY)
        try:
            with patch.object(init.scale.bound,'guard'),patch.object(os,'chroot',side_effect=PermissionError('SYS_CHROOT absent')), \
                 patch.object(os,'execve') as execute,patch.object(os,'supports_fd',{execute}):
                with self.assertRaises(PermissionError): init.exec_helper(self.root,self.work)
                execute.assert_not_called()
        finally: os.fchdir(saved); os.close(saved)
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_worker_rechecks_pinned_fd_after_checkpoint(self):
        real=aux.checkpoint
        def changed(*args):
            value=real(*args); self.write(aux.HELPER_NODE,b'changed after checkpoint',0o755); return value
        with patch.object(init.scale.bound,'guard'),patch.object(aux,'checkpoint',side_effect=changed), \
             patch.object(os,'chroot') as chroot,patch.object(os,'execve') as execute,patch.object(os,'supports_fd',{execute}):
            with self.assertRaisesRegex(ValueError,'initialization-helper-pin'): init.exec_helper(self.root,self.work)
            chroot.assert_not_called(); execute.assert_not_called()

    def test_opt_in_runtime_holds_closure_and_setup_payload(self):
        instance=runtime.Runtime(self.args,self.config(),comparator_path=COMPARATOR)
        seed=instance.tree(self.root)
        instance.old_paths=set(runtime.FILES)-{'usr/bin/cachy-asahi-repository','usr/share/doc/cachy-asahi-setup/repository-enrollment.md'}
        payload={name:dict(type='file',mode=0o644,uid=0,gid=0,bytes=3,sha256=digest(b'new')) for name in runtime.FILES}
        projected=instance.projected_paths(seed,payload)
        self.assertIn(aux.HELPER_NODE,projected)
        with patch.object(scale_runtime(),'precommit'): instance.precommit()
        for name in runtime.FILES: self.write(name,b'new')
        instance.tree(self.root)
        self.assertEqual([row['checkpoint'] for row in instance.auxiliary_checks],['observe-before','precommit','observe-after'])
        self.assertEqual(instance.auxiliary_checks[-1]['auxiliary_exit_status'],'NOT OBSERVED')

    def test_opt_in_runtime_rejects_absolute_and_postcommit_cache_tamper(self):
        instance=runtime.Runtime(self.args,self.config(),comparator_path=COMPARATOR)
        instance.tree(self.root)
        instance.projected=instance.baseline['nodes']; instance.aux_precommit=instance.aux_before; instance.commit_ready=True
        self.write(aux.MAIN_CACHE,b'changed cache')
        with self.assertRaisesRegex(ValueError,'main-cache-content'): instance.tree(self.root)
        self.write(aux.MAIN_CACHE,b'opaque held main cache')
        (self.root/'absolute').symlink_to('/usr/lib')
        with self.assertRaisesRegex(ValueError,'strict-auxiliary-only'): instance.tree(self.root)

    def test_precommit_drift_cannot_set_commit_flag(self):
        instance=runtime.Runtime(self.args,self.config(),comparator_path=COMPARATOR)
        instance.tree(self.root); instance.projected=instance.baseline['nodes']
        self.write('usr/lib/libfixture-a.so',b'drift')
        with patch.object(scale_runtime(),'precommit'):
            with self.assertRaises(ValueError): instance.precommit()
        self.assertFalse(getattr(instance,'commit_ready',False))


def scale_runtime(): return runtime.scale.Runtime

if __name__=='__main__': unittest.main()
