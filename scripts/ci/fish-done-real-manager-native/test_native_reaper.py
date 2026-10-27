#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inert causal controls; no subprocess, prctl or native actor is executed."""
import copy
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch,Mock
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE));import root_contract as ROOT
DATA=HERE.parent/'fish-done-real-manager-data';sys.path.insert(0,str(DATA))
spec=importlib.util.spec_from_file_location('causal_native_build',DATA/'native_build.py')
B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)
ORIGINAL=None
def proof():return dict(status='VERIFIED_CHILD_SUBREAPER',pid=os.getpid(),before=0,enabled=1)
def observed():
    if ORIGINAL is not None:return copy.deepcopy(ORIGINAL)
    return dict(pid=10,exit=0,wait_status=0,reap_count=1,ownership='REAPED',observations=5,
        completed=True,timed_out=False,group_absent=False,retirement='PRESENT',signals=[],
        audit=[dict(event='LAUNCHED_NEW_SESSION',pid=10),dict(event='WNOWAIT_VERIFIED'),
            dict(event='WNOWAIT_EXIT',code=os.CLD_EXITED,status=0),dict(event='REAP_LEADER_ONCE',wait_status=0),
            dict(event='CENSUS_AFTER_REAP',complete=True,members=1)],
        census=dict(complete=True,error_types=[],members=[dict(pid=151,ppid=1,pgid=10,sid=10,state='Z',start_ticks=31876)]))
EMPTY=dict(complete=True,error_types=[],members=[])
class Controls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(dir=WORK);self.addCleanup(self.tmp.cleanup)
        self.command=B.Commands(Path(self.tmp.name),{});self.command.child_reaper=proof()
    def test_original_actual_census_is_not_accepted(self):
        receipt=observed()
        self.assertEqual(receipt['census']['members'],[dict(pid=151,ppid=1,pgid=10,sid=10,state='Z',start_ticks=31876)])
        with self.assertRaises(ValueError):B.R.assert_verified(receipt)
    def test_leader_reap_then_adopted_reap_then_census(self):
        events=[]
        def run(*a,**k):events.append('leader-reaped');return observed()
        def wait(pid,flags):
            self.assertEqual((pid,flags),(-1,os.WNOHANG));events.append('adopted-wait')
            if events.count('adopted-wait')==1:return (151,0)
            raise ChildProcessError()
        def census(*a):
            self.assertEqual(events[-1],'adopted-wait');events.append('census');return EMPTY
        with patch.object(B.R,'run',side_effect=run),patch.object(B.os,'waitpid',side_effect=wait),patch.object(B.R,'_census',side_effect=census),patch.object(B.os,'killpg',side_effect=AssertionError('post-reap numeric action')):
            self.assertEqual(self.command(['/usr/bin/meson','setup']), '')
        self.assertEqual(events,['leader-reaped','adopted-wait','adopted-wait','census'])
        row=self.command.rows[0]
        self.assertEqual(row['adopted_drain'],dict(status='VERIFIED_NO_CHILDREN',reaped=[dict(pid=151,wait_status=0)]))
        B.R.assert_verified(row['supervision']);ROOT.child_reaper_proof(dict(child_reaper=proof(),commands=[row]))
    def test_unknown_ownership_never_waits_censuses_or_passes(self):
        receipt=observed();receipt.update(ownership='LOST',reap_count=0,exit=None,completed=False)
        with patch.object(B.R,'run',return_value=receipt),patch.object(B.os,'waitpid',side_effect=AssertionError('lost wait')),patch.object(B.R,'_census',side_effect=AssertionError('lost census')):
            with self.assertRaises(ValueError):self.command(['inert'])
        row=self.command.rows[0];self.assertIsNone(row['exit']);self.assertEqual(row['adopted_drain']['status'],'SKIPPED_UNKNOWN_OWNERSHIP')
        self.assertEqual(row['supervision']['retirement'],'UNKNOWN')
    def test_incomplete_drain_refuses_even_empty_group(self):
        with patch.object(B.R,'run',return_value=observed()),patch.object(B,'drain_adopted',return_value=dict(status='INCOMPLETE',reaped=[])),patch.object(B.R,'_census',return_value=EMPTY):
            with self.assertRaises(ValueError):self.command(['inert'])
        self.assertEqual(self.command.rows[0]['adopted_drain']['status'],'INCOMPLETE')
    def test_unconfigured_reaper_refuses_before_actor(self):
        self.command.child_reaper=None
        with patch.object(B.R,'run',side_effect=AssertionError('actor')):
            with self.assertRaises(ValueError):self.command(['inert'])
    def test_configure_get_set_verify(self):
        calls=[]
        def prctl(option,arg,*rest):
            calls.append((option,arg))
            if option==37:ctypes.cast(arg,ctypes.POINTER(ctypes.c_int))[0]=int(len(calls)>1)
            return 0
        libc=Mock();libc.prctl=Mock(side_effect=prctl)
        with patch.object(B.ctypes,'CDLL',return_value=libc):self.assertEqual(B.configure_child_reaper(),proof())
        self.assertEqual([x[0] for x in calls],[37,36,37]);self.assertEqual(calls[1],(36,1))
    def test_configure_denied_or_unverified_fails_closed(self):
        for fail_at in (0,1,2):
            calls=[]
            def prctl(option,arg,*rest):
                index=len(calls);calls.append(option)
                if index==fail_at:return -1
                if option==37:ctypes.cast(arg,ctypes.POINTER(ctypes.c_int))[0]=int(index==2)
                return 0
            libc=Mock();libc.prctl=Mock(side_effect=prctl)
            with self.subTest(fail_at=fail_at),patch.object(B.ctypes,'CDLL',return_value=libc):
                with self.assertRaises(ValueError):B.configure_child_reaper()
                self.assertEqual(len(calls),fail_at+1)
        libc=Mock()
        def already(option,arg,*rest):ctypes.cast(arg,ctypes.POINTER(ctypes.c_int))[0]=1;return 0
        libc.prctl=Mock(side_effect=already)
        with patch.object(B.ctypes,'CDLL',return_value=libc):
            with self.assertRaises(ValueError):B.configure_child_reaper()
            self.assertEqual(libc.prctl.call_count,1)
    def test_policy_rejects_before_prctl(self):
        with patch.object(B.signal,'getsignal',return_value=signal.SIG_IGN),patch.object(B.ctypes,'CDLL',side_effect=AssertionError('setup')):
            with self.assertRaises(ValueError):B.configure_child_reaper()
        with patch.object(B.threading,'active_count',return_value=2),patch.object(B.ctypes,'CDLL',side_effect=AssertionError('setup')):
            with self.assertRaises(ValueError):B.configure_child_reaper()
    def test_drain_has_monotonic_deadline_and_no_positive_pid_target(self):
        with patch.object(B.time,'monotonic',side_effect=[0,3]),patch.object(B.os,'waitpid',return_value=(0,0)) as wait:
            self.assertEqual(B.drain_adopted(),dict(status='INCOMPLETE',reaped=[]))
        wait.assert_called_once_with(-1,os.WNOHANG)
    def test_root_refuses_missing_mismatched_incomplete_or_leader_reap(self):
        row=dict(pid=10,child_reaper=proof(),adopted_drain=dict(status='VERIFIED_NO_CHILDREN',reaped=[dict(pid=151,wait_status=0)]))
        good=dict(child_reaper=proof(),commands=[row]);ROOT.child_reaper_proof(good);variants=[]
        v=copy.deepcopy(good);del v['child_reaper'];variants.append(v)
        v=copy.deepcopy(good);v['commands'][0]['child_reaper']['pid']+=1;variants.append(v)
        v=copy.deepcopy(good);v['commands'][0]['adopted_drain']['status']='INCOMPLETE';variants.append(v)
        v=copy.deepcopy(good);v['commands'][0]['adopted_drain']['reaped'][0]['pid']=10;variants.append(v)
        for v in variants:
            with self.assertRaises((ValueError,KeyError)):ROOT.child_reaper_proof(v)
if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--actual-commands',type=Path)
    a,rest=p.parse_known_args();WORK=a.work.absolute()
    if a.actual_commands:ORIGINAL=json.loads(a.actual_commands.read_text())[2]['supervision']
    unittest.main(argv=[sys.argv[0],*rest])
