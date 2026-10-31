# SPDX-License-Identifier: MIT
"""Synthetic source/protocol controls. One private host fork tests SIGSTOP/KILL only."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as C
import interruption as I


def prepared():
    return dict(prepared_add={C.NAME:C.VERSION},prepared_remove={'glibc':'held'},
                dependencies='PASS_ALPM_PREPARE',commit_started=True,observer_root='INTACT_OUTER_HELD574',
                hooks='DISABLED',scriptlets='DISABLED_EXPLICIT_HELD_POST_UPGRADE_LATER')


class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
        blocked=patch.object(subprocess,'Popen',side_effect=AssertionError('no process commands'));blocked.start();self.addCleanup(blocked.stop)
        self.point=dict(removed='usr/z',remaining='usr/a',remaining_sha256=C.sha(b'a'))
        (self.root/'usr').mkdir();(self.root/'usr/a').write_bytes(b'a');(self.root/'usr/z').write_bytes(b'z')
        (self.root/'var/lib/pacman').mkdir(parents=True)

    def fake_lock(self,root):return I.identity((root/I.LOCK).lstat())

    def make_lock(self):
        path=self.root/I.LOCK;path.touch(mode=0);return self.fake_lock(self.root)

    def row(self):
        return dict(type='CHECKPOINT',pid=42,pgid=42,phase='ALPM_COMMIT_REMOVE_PAYLOAD_BEFORE_OLD_DATABASE_REMOVAL',
                    event=4,package='glibc',percent=0,howmany=1,current=1,point=self.point,lock=[1],prepared=prepared())

    def test_unbound_refuses_before_output(self):
        with self.assertRaisesRegex(ValueError,'UNBOUND'):C.configuration(self.root,'0'*64)
        self.assertFalse((self.root/'interruption-input.json').exists())

    def test_deterministic_point_is_held_only_and_exact(self):
        old=dict(nodes={'usr/a':dict(type='file',sha256=C.sha(b'a')),
                        'usr/z':dict(type='file',sha256=C.sha(b'z')),
                        'usr/zz':dict(type='file',sha256='f'*64)})
        new=dict(nodes={'usr/zz':old['nodes']['usr/zz']})
        before=dict(nodes=copy.deepcopy(old['nodes']))
        self.assertEqual(I.choose(before,old,new),self.point)
        before['nodes']['usr/z']['sha256']='e'*64
        with self.assertRaises(ValueError):I.choose(before,old,new)

    def test_two_distinct_held_files_are_required(self):
        one=dict(nodes={'usr/a':dict(type='file',sha256='a'*64)})
        with self.assertRaises(ValueError):I.choose(one,one,dict(nodes={}))

    def test_precommit_unchanged_payload_does_not_qualify(self):
        with self.assertRaisesRegex(ValueError,'real held payload removal'):I.partial(self.root,self.point)

    def test_real_synthetic_partial_requires_surviving_held_payload(self):
        (self.root/'usr/z').unlink();I.partial(self.root,self.point)
        (self.root/'usr/a').write_bytes(b'changed')
        with self.assertRaises(ValueError):I.partial(self.root,self.point)

    def test_exact_checkpoint_rejects_forged_phase_or_owner(self):
        (self.root/'usr/z').unlink();good=self.row()
        with patch.object(I,'lock_identity',return_value=[1]):
            I.validate_checkpoint(good,42,self.root,self.point)
            for key,value in [('phase','PREPARED'),('pid',43),('percent',100),('event',0),('howmany',2)]:
                bad=dict(good,**{key:value})
                with self.assertRaises(ValueError):I.validate_checkpoint(bad,42,self.root,self.point)

    def test_progress_not_armed_during_prepare(self):
        def setter(*args):return 0
        alpm=NS(handle=1,lib=NS(alpm_option_set_progresscb=setter),ok=lambda code,label:C.need(code==0,label))
        observer=I.Checkpoint(self.root,self.point,-1);observer.bind(alpm)
        with patch.object(I.os,'kill',side_effect=AssertionError('no premature kill')):
            observer.callback(None,4,b'glibc',0,1,1)
        self.assertFalse(observer.hit)
        self.assertEqual(setter.argtypes,[I.ctypes.c_void_p,I.CALLBACK,I.ctypes.c_void_p])

    def test_lock_requires_actual_writer_absence(self):
        expected=self.make_lock()
        with self.assertRaises(ValueError):I.clear_owned_lock(self.root,expected,dict(group_absence_verified=False,exit_code=-9))
        self.assertTrue((self.root/I.LOCK).exists())

    def test_foreign_lock_is_preserved(self):
        self.make_lock();expected=[-1]
        with patch.object(I,'lock_identity',side_effect=self.fake_lock):
            with self.assertRaises(ValueError):I.clear_owned_lock(self.root,expected,dict(group_absence_verified=True,exit_code=-9))
        self.assertTrue((self.root/I.LOCK).exists())

    def test_lock_bad_mode_or_size_refused(self):
        self.make_lock();(self.root/I.LOCK).chmod(0o600)
        with self.assertRaises(ValueError):I.lock_identity(self.root)

    def test_exact_owned_synthetic_lock_removed_only_after_absence(self):
        expected=self.make_lock()
        with patch.object(I,'lock_identity',side_effect=self.fake_lock):
            result=I.clear_owned_lock(self.root,expected,dict(group_absence_verified=True,exit_code=-9))
        self.assertIn('AFTER_GROUP_ABSENCE',result['status']);self.assertFalse((self.root/I.LOCK).exists())

    def test_complete_local_db_projection_keeps_every_record(self):
        snap=dict(nodes={I.LOCAL:dict(type='directory'),I.LOCAL+'/x/desc':dict(sha256='a'),
                         I.LOCAL+'/x/files':dict(sha256='b'),'etc/other':dict(sha256='c')})
        self.assertEqual(set(I.local_nodes(snap)),{I.LOCAL,I.LOCAL+'/x/desc',I.LOCAL+'/x/files'})

    def test_protocol_deadline_output_and_eof_refused(self):
        import time
        for raw in (b'',b'x'*4097,b'{}\n{}\n'):
            r,w=os.pipe();os.write(w,raw);os.close(w)
            try:
                with self.assertRaises(ValueError):I.receive(r,time.monotonic()+.2)
            finally:os.close(r)

    def test_unknown_partial_database_blocks_lock_removal_and_recovery(self):
        (self.root/'usr/z').unlink()
        before=dict(nodes={I.LOCAL+'/glibc-held/desc':dict(sha256='original')})
        interrupted=dict(nodes={I.LOCAL+'/glibc-held/desc':dict(sha256='mutated')})
        lane=NS(snapshot=lambda *a:interrupted,CONFIGS=())
        with patch.object(I,'choose',return_value=self.point), patch.object(I,'outer_identity',return_value={}), \
             patch.object(I,'stop_and_kill',return_value=dict(prepared=prepared())), \
             patch.object(I,'clear_owned_lock',side_effect=AssertionError('must not unlock unknown DB')):
            with self.assertRaisesRegex(ValueError,'COMPLETE unchanged'):
                I.exercise({},lane,self.root,{},dict(glibc='held'),{}, {},before,'synthetic',{})

    def test_partial_config_mutation_blocks_external_recovery(self):
        (self.root/'usr/z').unlink()
        before=dict(nodes={'etc/gai.conf':dict(sha256='user')})
        interrupted=dict(nodes={'etc/gai.conf':dict(sha256='changed')})
        lane=NS(snapshot=lambda *a:interrupted,CONFIGS=('etc/gai.conf',))
        with patch.object(I,'choose',return_value=self.point), patch.object(I,'outer_identity',return_value={}), \
             patch.object(I,'stop_and_kill',return_value=dict(prepared=prepared())), \
             patch.object(I,'clear_owned_lock',side_effect=AssertionError('must not unlock unknown config state')):
            with self.assertRaisesRegex(ValueError,'all config/backup mutation'):
                I.exercise({},lane,self.root,{},dict(glibc='held'),{}, {},before,'synthetic',{})

    def test_dependency_bypass_cannot_forge_checkpoint(self):
        (self.root/'usr/z').unlink();bad=self.row();bad['prepared']['dependencies']='BYPASSED'
        with patch.object(I,'lock_identity',return_value=[1]):
            with self.assertRaisesRegex(ValueError,'dependency-checked'):
                I.validate_checkpoint(bad,42,self.root,self.point)

    def test_synthetic_host_stop_kill_and_real_group_absence(self):
        # No libalpm or native archive is opened. Real POSIX actor on private temp data only.
        def transaction(api,root,archive,remove,add,log,progress):
            self.make_lock()
            def setter(*args):return 0
            alpm=NS(handle=1,lib=NS(alpm_option_set_progresscb=setter),ok=lambda code,label:C.need(code==0,label))
            progress.bind(alpm);progress.prepared=prepared();progress.armed=True
            (root/self.point['removed']).unlink()
            progress.callback(None,4,b'glibc',0,1,1)
            raise AssertionError('stopped synthetic callback must not return')
        lane=NS(INPUTS=self.root,OUT=self.root,transaction=transaction)
        report={}
        with patch.object(I,'lock_identity',side_effect=self.fake_lock):
            actual=I.stop_and_kill({},lane,self.root,dict(archives=dict(a=dict(path='unused'))),self.point,'synthetic',report)
        self.assertEqual(actual['type'],'CHECKPOINT');self.assertEqual(report['writer']['exit_code'],-signal.SIGKILL)
        self.assertTrue(report['writer']['group_absence_verified']);self.assertNotIn('status',report)
        self.assertTrue((self.root/I.LOCK).exists())

    def test_synthetic_writer_completion_without_checkpoint_never_passes(self):
        lane=NS(INPUTS=self.root,OUT=self.root,transaction=lambda *a,**k:None);report={}
        with self.assertRaises(ValueError):
            I.stop_and_kill({},lane,self.root,dict(archives=dict(a=dict(path='unused'))),self.point,'synthetic',report)
        self.assertTrue(report['writer']['group_absence_verified']);self.assertNotIn('status',report)


if __name__=='__main__':unittest.main()
