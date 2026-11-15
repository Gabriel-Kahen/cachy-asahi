# SPDX-License-Identifier: MIT
"""FENCED mocks/temp DATA only: no subprocess, daemon, actor or Root invocation."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import types
import unittest
from unittest.mock import Mock,patch
from contextlib import ExitStack

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('fenced_vm_runtime',HERE/'runtime.py')
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)


def need(ok,why):
    if not ok:raise ValueError(why)


def retired(code=0):
    return dict(passed=code==0,reaped=True,ownership='REAPED',exit=code,group_census='EMPTY_TWICE',output_complete=True,signals=[],timeout=False,error=None,seconds=.01)


class Cancellation:
    def __init__(self,cleaning=False):self.cleaning=cleaning;self.pending=[]
    def handler(self,number,frame):
        self.pending.append(number)
        if not self.cleaning:raise KeyboardInterrupt('FENCED cancellation')


class SignalModel:
    def __init__(self,owner):
        self.handlers={n:owner.handler for n in (signal.SIGINT,signal.SIGTERM)};self.mask=set();self.queued=set()
    def getsignal(self,number):return self.handlers[number]
    def signal(self,number,handler):old=self.handlers[number];self.handlers[number]=handler;return old
    def pthread_sigmask(self,operation,mask):
        previous=set(self.mask)
        self.mask=self.mask|set(mask) if operation==signal.SIG_BLOCK else set(mask)
        for number in sorted(self.queued-self.mask):
            self.queued.remove(number);self.handlers[number](number,None)
        return previous
    def sigpending(self):return set(self.queued)
    def sigtimedwait(self,numbers,timeout):
        for number in self.queued & set(numbers):self.queued.remove(number);return types.SimpleNamespace(si_signo=number)
        return None
    def emit(self,number):
        if number in self.mask:self.queued.add(number)
        else:self.handlers[number](number,None)


class Clock:
    def __init__(self):self.value=100.;self.step=.01
    def monotonic(self):self.value+=self.step;return self.value
    def sleep(self,seconds):self.value+=seconds


class Harness:
    def __init__(self,out,*,code=0,cleaning=False):
        self.out=out;self.clock=Clock();self.owner=Cancellation(cleaning);self.signals=SignalModel(self.owner)
        self.row=retired(code);self.child=types.SimpleNamespace(pid=12345)
        self.owned=types.SimpleNamespace(prepare=Mock(),supervise=Mock(side_effect=lambda *a,**k:copy.deepcopy(self.row)))
        self.contract=types.SimpleNamespace(need=need,helper=lambda name:self.owned)
        self.preexec=None;self.during_spawn=None
    def spawn(self,argv,**kwargs):
        self.preexec=kwargs['preexec_fn']
        if self.during_spawn:self.during_spawn()
        kwargs['stdout'].write(b'FENCED stdout\n');kwargs['stderr'].write(b'FENCED stderr\n')
        return self.child
    def enter(self):
        stack=ExitStack()
        stack.enter_context(patch.object(r,'module',return_value=self.contract))
        stack.enter_context(patch.object(r.time,'monotonic',side_effect=self.clock.monotonic))
        stack.enter_context(patch.object(r.time,'sleep',side_effect=self.clock.sleep))
        for name in ('getsignal','signal','pthread_sigmask','sigpending','sigtimedwait'):
            stack.enter_context(patch.object(r.signal,name,side_effect=getattr(self.signals,name)))
        stack.enter_context(patch.object(r.subprocess,'Popen',side_effect=self.spawn))
        stack.enter_context(patch.object(r.os,'waitid',return_value=types.SimpleNamespace(si_pid=12345)))
        stack.enter_context(patch.dict(os.environ,{'DOCKER_HOST':'unix:///FENCED.sock','HOME':'/FENCED-home','XDG_RUNTIME_DIR':'/FENCED-runtime'},clear=True))
        return stack


class RuntimeControls(unittest.TestCase):
    def test_default_bytes_and_completed_nonzero_semantics(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp);h=Harness(out)
            with h.enter():
                self.assertEqual(r.command(['FENCED-tool'],out,'bytes'),b'FENCED stdout\nFENCED stderr\n')
            h=Harness(out,code=3)
            with h.enter():
                result=r.command(['docker','container','inspect','FENCED'],out,'nonzero',check=False,completed=True)
            self.assertIsInstance(result,subprocess.CompletedProcess)
            self.assertEqual((result.returncode,result.stdout,result.stderr),(3,b'FENCED stdout\n',b'FENCED stderr\n'))
            h=Harness(out,code=3)
            with h.enter(),self.assertRaisesRegex(ValueError,'nonzero'):
                r.command(['FENCED-tool'],out,'check')

    def test_nonzero_does_not_accept_forced_or_unknown_retirement(self):
        for change in ({'signals':['SIGTERM']},{'ownership':'UNKNOWN'},{'reaped':False},{'group_census':'PRESENT_OR_REUSED'},{'exit':-15}):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as tmp:
                h=Harness(Path(tmp),code=3);h.row.update(change)
                with h.enter(),self.assertRaisesRegex(ValueError,'naturally retired'):
                    r.command(['docker','inspect','FENCED'],h.out,'rejected',check=False,completed=True)

    def test_known_cancellation_refuses_before_spawn(self):
        with tempfile.TemporaryDirectory() as tmp:
            h=Harness(Path(tmp));h.signals.queued.add(signal.SIGTERM)
            with h.enter(),self.assertRaises(KeyboardInterrupt):
                r.command(['FENCED-tool'],h.out,'cancel-before')
            h.owned.prepare.assert_not_called();h.owned.supervise.assert_not_called()
            self.assertEqual(h.owner.pending,[signal.SIGTERM])
            self.assertEqual(json.loads((h.out/'cancel-before.json').read_bytes())['command_cancelled'],[signal.SIGTERM])

    def test_signal_during_popen_is_recorded_through_frozen_handoff(self):
        with tempfile.TemporaryDirectory() as tmp:
            h=Harness(Path(tmp));h.during_spawn=lambda:h.signals.emit(signal.SIGINT)
            with h.enter(),self.assertRaises(KeyboardInterrupt):
                r.command(['FENCED-tool'],h.out,'cancel-spawn')
            h.owned.supervise.assert_called_once()
            self.assertEqual(h.owner.pending,[signal.SIGINT])
            self.assertEqual(json.loads((h.out/'cancel-spawn.json').read_bytes())['command_cancelled'],[signal.SIGINT])

    def test_cleanup_defers_and_forwards_signals_without_interrupting(self):
        with tempfile.TemporaryDirectory() as tmp:
            h=Harness(Path(tmp),cleaning=True);h.signals.queued.add(signal.SIGTERM)
            with h.enter():
                result=r.command(['docker','container','ls'],h.out,'cleanup',defer_cancel=True,check=False,completed=True)
            self.assertEqual(result.returncode,0);h.owned.supervise.assert_called_once()
            self.assertEqual(h.owner.pending,[signal.SIGTERM])
            h=Harness(Path(tmp),cleaning=False)
            with h.enter(),self.assertRaisesRegex(ValueError,'active bound cleanup'):
                r.command(['FENCED-tool'],h.out,'not-cleanup',defer_cancel=True)
            h.owned.prepare.assert_not_called()

    def test_cleanup_forwards_cancellation_even_when_final_watch_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            h=Harness(Path(tmp),cleaning=True);h.during_spawn=lambda:h.signals.emit(signal.SIGTERM)
            with h.enter(),patch.object(r,'allocated',side_effect=[0,101]),patch.object(r.shutil,'disk_usage',return_value=types.SimpleNamespace(free=1000)),self.assertRaisesRegex(ValueError,'final watched'):
                r.command(['docker','inspect','FENCED'],h.out,'watch-cleanup',defer_cancel=True,watched_tree=(h.out,100,10))
            self.assertEqual(h.owner.pending,[signal.SIGTERM]);h.owned.supervise.assert_called_once()

    def test_qemu_file_cap_only_in_child_preexec_parent_unchanged(self):
        with tempfile.TemporaryDirectory() as tmp:
            h=Harness(Path(tmp))
            with h.enter(),patch.object(r.resource,'getrlimit',return_value=(r.resource.RLIM_INFINITY,r.resource.RLIM_INFINITY)),patch.object(r.resource,'setrlimit') as limits:
                r.command(['/usr/bin/qemu-system-aarch64'],h.out,'qemu',child_file_size_cap=512*1024**2)
                limits.assert_not_called()
                h.preexec()
                limits.assert_called_once_with(r.resource.RLIMIT_FSIZE,(512*1024**2,512*1024**2))
            h=Harness(Path(tmp))
            with h.enter(),self.assertRaisesRegex(ValueError,'only for the fixed QEMU'):
                r.command(['qemu-img','convert'],h.out,'convert',child_file_size_cap=512*1024**2)

    def test_docker_call_unique_logs_shared_deadline_and_separate_streams(self):
        with tempfile.TemporaryDirectory() as tmp:
            h=Harness(Path(tmp),code=1)
            with h.enter():
                first=r.docker_call(['docker','inspect','FENCED'],h.out,119.,shared_deadline=110.)
                second=r.docker_call(['docker','inspect','FENCED'],h.out,119.,shared_deadline=110.)
            self.assertEqual(first.returncode,1);self.assertEqual(second.stderr,b'FENCED stderr\n')
            records=list(h.out.glob('owned-docker-*.json'));self.assertEqual(len(records),2)
            self.assertEqual(len({p.stem for p in records}),2)
            self.assertTrue(all(json.loads(p.read_bytes())['operation_cap_seconds']<=8 for p in records))
            for call in h.owned.supervise.call_args_list:self.assertLess(call.kwargs['cap'],8)

    def test_allocation_census_counts_links_without_following(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);(root/'child').mkdir();(root/'child/file').write_bytes(b'FENCED')
            (root/'link').symlink_to('/outside-never-followed')
            expected=sum(p.lstat().st_blocks*512 for p in [root,root/'child',root/'child/file',root/'link'])
            self.assertEqual(r.allocated(root),expected)
            with self.assertRaisesRegex(ValueError,'ordinary watched root'):r.allocated(root/'link')

    def test_expired_original_budget_still_hands_off_once_and_cannot_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            h=Harness(Path(tmp));h.during_spawn=lambda:setattr(h.clock,'value',150.)
            with h.enter(),self.assertRaisesRegex(TimeoutError,'original command budget overrun'):
                r.command(['FENCED-tool'],h.out,'overrun',seconds=10)
            h.owned.supervise.assert_called_once()
            call=h.owned.supervise.call_args
            self.assertEqual(call.kwargs['cap'],.5)
            self.assertEqual(call.kwargs['retirement'],.45)
            row=json.loads((h.out/'overrun.json').read_bytes())
            self.assertTrue(row['original_budget_overrun'])
            self.assertTrue(row['emergency_retirement'])
            self.assertTrue(row['command_timed_out'])
            self.assertFalse(r.natural(row))
            self.assertFalse(r._retired(row,defer_cancel=True))

    def test_watched_cap_and_reserve_refuse_before_spawn(self):
        for allocation,free in ((101,1000),(0,9)):
            with self.subTest(allocation=allocation,free=free),tempfile.TemporaryDirectory() as tmp:
                h=Harness(Path(tmp))
                with h.enter(),patch.object(r,'allocated',return_value=allocation),patch.object(r.shutil,'disk_usage',return_value=types.SimpleNamespace(free=free)),self.assertRaises(ValueError):
                    r.command(['FENCED-tool'],h.out,'watch',watched_tree=(h.out,100,10))
                h.owned.prepare.assert_not_called()

    def test_live_allocation_failure_still_transfers_child_for_retirement(self):
        with tempfile.TemporaryDirectory() as tmp:
            h=Harness(Path(tmp));h.clock.step=.2
            with h.enter(),patch.object(r.os,'waitid',return_value=None),patch.object(r,'allocated',side_effect=[0,101,101]),patch.object(r.shutil,'disk_usage',return_value=types.SimpleNamespace(free=1000)),self.assertRaises(ValueError):
                r.command(['FENCED-tool'],h.out,'watch-live',watched_tree=(h.out,100,10))
            h.owned.supervise.assert_called_once()
            self.assertTrue((h.out/'watch-live.json').exists())


if __name__=='__main__':unittest.main()
