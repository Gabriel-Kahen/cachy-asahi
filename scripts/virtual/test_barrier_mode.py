# SPDX-License-Identifier: MIT
"""Closed guest fixture controls and owned local process retirement, no VM/native actor."""
import ast
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import Mock, patch
import common
import controller
import guest
import prepare
import run


class BarrierMode(unittest.TestCase):
    nonce = 'a' * 32
    selection = 'b' * 64

    def contract(self):
        return {'purpose': common.BARRIER_PURPOSE, 'barrier_fixture': {
            'source_commit': common.BARRIER_SOURCE, 'test': common.BARRIER_TEST,
            'files': copy.deepcopy(common.BARRIER_FILES)}}

    def boot(self):
        return {'event':'boot','nonce':self.nonce,'arch':'aarch64','page_size':4096,'kernel':common.KERNEL}

    def event(self):
        return {'event': 'barrier_result', 'nonce': self.nonce, 'selection_sha256': self.selection,
            'fixture_source': common.BARRIER_SOURCE, 'uid': 23001, 'gid': 23001,
            'tests': 1, 'failures': 0, 'errors': 0, 'skips': 0, 'status': 'PASS_BARRIER_ONLY',
            'first_failure': None, 'report': {
                'status': 'PASS-barrier-only', 'worker_sha256': common.BARRIER_FILES['scripts/install/local_transaction.py']['sha256'],
                'outside_errno': 30, 'uid': 0, 'namespace_changed': True,
                'denied_service_syscalls': {str(n): 1 for n in (203,206,211,269,425,426,427)},
                'capabilities': {'CapEff': 0x400cb, 'CapPrm': 0x400cb, 'CapBnd': 0x400cb, 'CapInh':0, 'CapAmb':0},
                'no_new_privileges': 1, 'libalpm_initialized': False, 'package_commit': False,
                'host_namespace_unchanged': True, 'outside_bytes_unchanged': True,
                'guest_file_absent_on_host': True, 'evidence_marker_persisted': True}}

    def test_default_and_exact_fixture_no_mixed_routes(self):
        self.assertFalse(common.barrier_contract({}))
        self.assertTrue(common.barrier_contract(self.contract()))
        for mutate in (lambda c: c.update(purpose='other'),
                       lambda c: c['barrier_fixture'].update(source_commit='0'*40),
                       lambda c: c['barrier_fixture'].update(test='test_anything'),
                       lambda c: c['barrier_fixture']['files'].pop('scripts/port/kernel-native-job/runtime.py'),
                       lambda c: c.pop('purpose')):
            c=self.contract(); mutate(c)
            with self.subTest(c=c), self.assertRaises(ValueError): common.barrier_contract(c)

    def test_stage_exact_three_bytes_and_proof(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root=Path(tmp); closure=root/'fixture'; rows={}
            for name in common.BARRIER_FILES:
                target=closure/name;target.parent.mkdir(parents=True,exist_ok=True)
                data=('inert '+name).encode();target.write_bytes(data)
                rows[name]={'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
            with patch('common.BARRIER_FILES',rows),patch('prepare.BARRIER_FILES',rows):
                proof=root/'selected.json';common.save(proof,self.contract())
                report={'fixture_changes':[]}
                def pin(_root,name,sha):return common.pinned(closure,name,sha)
                with patch('prepare.pinned',side_effect=pin):
                    prepare.stage_barrier(root/'stage',self.contract(),proof,common.digest(proof),report)
                self.assertEqual(len(report['fixture_changes']),4)
                for name,row in rows.items():
                    target=root/'stage/usr/local/share/virtual-proof/barrier-source'/name
                    self.assertEqual(target.stat().st_size,row['bytes'])
                    self.assertEqual(common.digest(target),row['sha256'])
                    self.assertEqual(target.stat().st_mode&0o777,0o644)

    def test_result_gate_and_typed_nested_facts(self):
        self.assertEqual(common.barrier_event(self.event(),self.nonce,self.selection),self.event())
        cases=[]
        for key,value in (('skips',1),('tests',0),('uid',0),('gid',0),('selection_sha256','c'*64)):
            row=self.event();row[key]=value;cases.append(row)
        for key,value in (('uid',False),('namespace_changed',1),('outside_errno',1),('package_commit',True)):
            row=self.event();row['report'][key]=value;cases.append(row)
        row=self.event();row['report']['denied_service_syscalls'].pop('203');cases.append(row)
        for row in cases:
            with self.subTest(row=row),self.assertRaises(ValueError):common.barrier_event(row,self.nonce,self.selection)

    def test_natural_child_completion_order_and_no_desktop_substitution(self):
        result=self.event();end={'event':'barrier_child_exit','nonce':self.nonce,
            'selection_sha256':self.selection,'returncode':0,'error':None}
        run.validate_barrier_completion([self.boot(),result,end],self.nonce,self.selection)
        for rows in ([result,end],[self.boot(),result],[self.boot(),end,result],[self.boot(),result,result,end],
                     [self.boot(),result,end,end],[self.boot(),result,end,{'event':'guest_pass'}],
                     [self.boot(),result,dict(end,returncode=1)], [dict(self.boot(),kernel='wrong'),result,end]):
            with self.subTest(rows=rows),self.assertRaises(ValueError):run.validate_barrier_completion(rows,self.nonce,self.selection)

    def test_actual_uart_batch_ast_refuses_duplicate_malformed_and_partial(self):
        tree=ast.parse(Path(run.__file__).read_text())
        main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
        loop=next(n for n in ast.walk(main) if isinstance(n,ast.For) and isinstance(n.target,ast.Name) and n.target.id=='line')
        tail=next(n for n in ast.walk(main) if isinstance(n,ast.If) and
                  isinstance(n.test,ast.Compare) and ast.unparse(n.test).startswith("report['status'] in"))
        program=compile(ast.fix_missing_locations(ast.Module(body=[loop],type_ignores=[])),'selected-QEMU-UART-loop','exec')
        partial_check=compile(ast.fix_missing_locations(ast.Module(body=tail.body[:1],type_ignores=[])),'selected-QEMU-partial-check','exec')
        result=self.event();end={'event':'barrier_child_exit','nonce':self.nonce,'selection_sha256':self.selection,'returncode':0,'error':None}
        def line(row):return ('CACHY_ASAHI_EVENT '+json.dumps(row)).encode()
        cases=([line(result),line(end),line(result)],[line(result),line(end),line(end)],
               [line(result),line(end),b'CACHY_ASAHI_EVENT malformed'])
        for lines in cases:
            scope=vars(run).copy()|{'lines':lines,'report':{'events':[self.boot()],'status':'FAILED'},
                'c':{'nonce':self.nonce},'args':types.SimpleNamespace(contract_sha256=self.selection),
                'barrier':True,'boot':True}
            with self.assertRaises((ValueError,KeyError)):exec(program,scope)
        scope=vars(run).copy()|{'lines':[line(result),line(end)],'report':{'events':[self.boot()],'status':'FAILED'},
                'c':{'nonce':self.nonce},'args':types.SimpleNamespace(contract_sha256=self.selection),
                'barrier':True,'boot':True,'partial':b'CACHY_ASAHI_EV'}
        exec(program,scope)
        with self.assertRaises(ValueError):exec(partial_check,scope)

    def test_final_uart_eof_rejects_late_events_partial_marker_and_deadline(self):
        for blocks in ([b'ordinary shutdown\\n',b''],[b'CACHY_',b'ASAHI_EVENT {}\\n',b''],[b'CACHY_ASAHI_EV',b'']):
            uart=Mock();uart.recv.side_effect=blocks
            with patch('run.time.monotonic',return_value=0):
                if blocks[0].startswith(b'ordinary'):
                    run.finish_barrier_uart(uart,io.BytesIO(),0,1)
                else:
                    with self.assertRaises(ValueError):run.finish_barrier_uart(uart,io.BytesIO(),0,1)
        uart=Mock();uart.recv.side_effect=BlockingIOError
        with patch('run.time.monotonic',side_effect=[0,0,2,2,2]),patch('run.time.sleep'),self.assertRaises(ValueError):
            run.finish_barrier_uart(uart,io.BytesIO(),0,1)

    def test_only_exact_method_runs_and_real_testresult_cleanup_error_refuses(self):
        good=self.event()['report'];called=[]
        class Fixture(unittest.TestCase):
            def test_actual_isolate_keeps_host_readonly_and_only_evidence_persistent(self):
                called.append('one');type(self).last_report=good
            def test_unselected(self): raise AssertionError('must never run')
        module=types.SimpleNamespace(BarrierTests=Fixture)
        with patch('guest.os.geteuid',return_value=23001),patch('guest.os.getegid',return_value=23001),patch('guest.emit') as emit:
            row=guest.barrier_test(module,{},self.nonce,self.selection)
        self.assertEqual(called,['one']);self.assertEqual(row,self.event());emit.assert_called_once()
        original=getattr(Fixture,common.BARRIER_TEST)
        def failed(case):
            case.addCleanup(lambda: (_ for _ in ()).throw(OSError(5,'PRIVATE cleanup')))
            original(case)
        setattr(Fixture,common.BARRIER_TEST,failed)
        with patch('guest.os.geteuid',return_value=23001),patch('guest.os.getegid',return_value=23001),patch('guest.emit') as emit,self.assertRaises(ValueError):
            guest.barrier_test(module,{},self.nonce,self.selection)
        self.assertEqual(emit.call_args.kwargs['status'],'FAIL')
        self.assertEqual(emit.call_args.kwargs['errors'],1)
        self.assertNotIn('PRIVATE',json.dumps(emit.call_args.kwargs))

    def test_actual_shaped_unshare_errno_suffix_and_frame_privacy(self):
        def failed(): raise AssertionError('1 != 0 : unshare: mount /proc failed: Operation not permitted\n')
        try: failed()
        except AssertionError:
            row=guest.barrier_failure(sys.exc_info(),{__file__:'SELECTED_TEST'})
        self.assertEqual(row['unshare_tool_error'],{'stage':'PROC_MOUNT','errno':1})
        self.assertEqual(row['exception'],'AssertionError');self.assertTrue(row['frames'])
        self.assertNotIn(__file__,json.dumps(row))
        for text in ('PRIVATE /secret', '1 != 0 : unshare: mount /proc failed: Operation not permitted\nPRIVATE',
                     '1 != 0 : unshare: mount /else failed: Operation not permitted'):
            row=guest.barrier_failure((AssertionError,AssertionError(text),None),{})
            self.assertEqual(row['unshare_tool_error']['stage'],'UNRECOGNIZED_OR_ABSENT')
            self.assertNotIn('PRIVATE',json.dumps(row))

    def test_unknown_exception_metaclass_is_not_consulted(self):
        class Meta(type):
            def __eq__(self,other):raise AssertionError('foreign metaclass hook')
        class Foreign(Exception,metaclass=Meta):pass
        row=guest.barrier_failure((Foreign,Foreign('PRIVATE'),None),{})
        self.assertEqual(row['exception'],'OTHER');self.assertIsNone(row['errno'])
        self.assertNotIn('PRIVATE',json.dumps(row))

    def test_skip_cannot_pass_and_cancellation_preserves_identity(self):
        for error in (None,KeyboardInterrupt('PRIVATE cancel'),SystemExit(7)):
            class Fixture(unittest.TestCase):
                def test_actual_isolate_keeps_host_readonly_and_only_evidence_persistent(self):
                    if error is None:self.skipTest('PRIVATE unavailable')
                    raise error
            with patch('guest.os.geteuid',return_value=23001),patch('guest.os.getegid',return_value=23001),patch('guest.emit') as emit:
                with self.assertRaises(ValueError if error is None else type(error)) as caught:
                    guest.barrier_test(types.SimpleNamespace(BarrierTests=Fixture),{},self.nonce,self.selection)
                if error is not None:self.assertIs(caught.exception,error)
                self.assertEqual(emit.call_args.kwargs['status'],'FAIL')
                self.assertNotIn('PRIVATE',json.dumps(emit.call_args.kwargs))

    def test_controller_projects_fixed_result_and_refuses_changed_selection(self):
        event=self.event();end={'event':'barrier_child_exit','nonce':self.nonce,
            'selection_sha256':self.selection,'returncode':0,'error':None}
        image='sha256:'+'c'*64;receipt='d'*64
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root=Path(tmp);raw=root/'raw';raw.mkdir();target=root/'public';target.mkdir()
            report={'purpose':common.BARRIER_PURPOSE,'proof_contract_sha256':self.selection,
                'prepare_receipt_sha256':receipt,'barrier_nonce':self.nonce,'stages':{'tooling':{'image_id':image}}}
            result={'status':'PASS_BARRIER_ONLY','events':[self.boot(),event,end],'nonce':self.nonce,
                'contract_sha256':self.selection,'prepare_receipt_sha256':receipt,'image_id':image,
                'barrier_result':event,'frames':{},'owned_group_retirement':'PASS','cleanup_uncertain':False}
            common.save(raw/'result.json',result)
            controller.project(raw,target,report)
            self.assertEqual(report['barrier_result'],event);self.assertEqual(report['frames'],{})
            result['contract_sha256']='e'*64;common.save(raw/'result.json',result)
            with self.assertRaises(ValueError):controller.project(raw,target,report)


    def test_barrier_user_wrong_uid_refuses_before_source_read(self):
        for uid,gid in ((0,0),(23001,0),(1000,1000)):
            with patch('guest.guest_guard'),patch('guest.os.geteuid',return_value=uid),\
                    patch('guest.os.getegid',return_value=gid),patch('guest.identity_bytes') as read,\
                    self.assertRaises(ValueError):guest.barrier_user()
            read.assert_not_called()


    def test_boot_forwards_closed_failure_without_raw_child_output(self):
        row=self.event();row.update(status='FAIL',report=None,failures=1,
            first_failure=guest.barrier_failure((AssertionError,AssertionError('PRIVATE'),None),{}))
        result={'stdout':guest.PREFIX+json.dumps(row)+'\n','stderr':'PRIVATE traceback','returncode':1,'error':None}
        with patch('guest.bounded',return_value=result) as child,patch('guest.emit') as emit,patch('guest.Path.mkdir'),patch('guest.os.chown'),self.assertRaises(ValueError):
            guest.boot_barrier({'purpose':common.BARRIER_PURPOSE,'nonce':self.nonce,'proof_contract_sha256':self.selection})
        self.assertEqual(child.call_args.kwargs['timeout'],600)
        self.assertEqual(emit.call_args.args,('barrier_result',))
        self.assertNotIn('PRIVATE',str(emit.call_args))


class Reservation(unittest.TestCase):
    def test_mock_pid_reuse_no_signal_after_reap_and_echild_never_signals(self):
        events=[];process=Mock(pid=123,returncode=None)
        def wait(**_):events.append('reap');process.returncode=0;return 0
        process.wait.side_effect=wait
        with patch('common.os.waitid',side_effect=lambda *a:events.append('reserve')),patch('common.os.killpg',side_effect=lambda *a:events.append('signal')):
            common.reap(process)
            with self.assertRaises(ValueError):common.reap(process)
        self.assertEqual(events,['reserve','signal','reap'])
        process=Mock(pid=123,returncode=None)
        with patch('common.os.waitid',side_effect=ChildProcessError),patch('common.os.killpg') as kill,self.assertRaises(ValueError): common.reap(process)
        kill.assert_not_called();process.wait.assert_not_called()

    def test_primary_error_survives_retirement_and_stream_close_fault(self):
        error=KeyboardInterrupt('first');process=Mock(pid=123,returncode=None)
        process.stdout.fileno.side_effect=error
        process.stdout.close.side_effect=OSError(5,'close')
        with patch('common.subprocess.Popen',return_value=process),patch('common.reap',side_effect=OSError(5,'retire')) as reap,self.assertRaises(KeyboardInterrupt) as caught:
            common.bounded(['inert'])
        self.assertIs(caught.exception,error);reap.assert_called_once();process.stderr.close.assert_called_once()
        self.assertIn('uncertain',error.__notes__[0])

    def test_timeout_and_overflow_first_category_survives_cleanup_failure(self):
        for timeout,limit,block,reason in ((0,8,b'', 'timeout'),(5,1,b'ab','output overflow')):
            process=Mock(pid=123,returncode=None)
            selector=Mock();selector.get_map.return_value={1:1}
            selector.select.return_value=[(types.SimpleNamespace(fd=1,data='stdout'),1)]
            manager=Mock();manager.__enter__=Mock(return_value=selector);manager.__exit__=Mock(return_value=False)
            with patch('common.subprocess.Popen',return_value=process),patch('selectors.DefaultSelector',return_value=manager),\
                    patch('common.os.set_blocking'),patch('common.os.read',return_value=block),\
                    patch('common.reap',side_effect=OSError(5,'later cleanup')),self.assertRaises(common.Refused) as caught:
                common.bounded(['inert'],timeout=timeout,limit=limit)
            self.assertEqual(str(caught.exception),reason)
            self.assertIn('uncertain',caught.exception.__notes__[0])
            process.stdout.close.assert_called_once();process.stderr.close.assert_called_once()

    def test_qemu_absence_probe_after_reap_is_nonmutating_and_refuses_reuse(self):
        process=Mock(pid=123,returncode=None);events=[]
        def wait(**_):events.append('reap');process.returncode=0
        process.wait.side_effect=wait
        def kill(pid,sig):
            events.append(sig)
            if sig==0:raise ProcessLookupError
        with patch('common.os.waitid'),patch('common.os.killpg',side_effect=kill):
            common.reap(process,verify_absence=True)
        self.assertEqual(events,[signal.SIGKILL,'reap',0])
        process=Mock(pid=123,returncode=None);events=[]
        def wait_again(**_):events.append('reap');process.returncode=0
        process.wait.side_effect=wait_again
        with patch('common.os.waitid'),patch('common.os.killpg',side_effect=lambda pid,sig:events.append(sig)),\
                patch('time.monotonic',side_effect=[0,0,2]),self.assertRaisesRegex(ValueError,'absence unverified'):
            common.reap(process,timeout=1,verify_absence=True)
        self.assertEqual(events,[signal.SIGKILL,'reap',0])

    def test_registered_spawn_cancellation_adopts_child_then_retires(self):
        real=subprocess.Popen;children=[]
        def spawn(*args,**kw):
            child=real(*args,**kw);children.append(child)
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM,None)
            return child
        previous=signal.signal(signal.SIGTERM,lambda *a:(_ for _ in ()).throw(KeyboardInterrupt('owned cancel')))
        try:
            with patch('common.subprocess.Popen',side_effect=spawn),self.assertRaises(KeyboardInterrupt):
                common.bounded([sys.executable,'-c','import time;time.sleep(20)'],timeout=.3)
        finally:signal.signal(signal.SIGTERM,previous)
        self.assertEqual(len(children),1);self.assertIsNotNone(children[0].returncode)

    def test_owned_real_exit_with_live_descendant_reserved_until_last_signal(self):
        # Isolated subreaper only inside this owned helper; no host process policy changes.
        code = r"""import ctypes,os,signal,subprocess,sys,time
from pathlib import Path
import common
import controller
assert ctypes.CDLL(None).prctl(36,1,0,0,0)==0
root=Path(sys.argv[1]); pidfile=root/'descendant'
source="import os,time;from pathlib import Path;p=os.fork();Path("+repr(str(pidfile))+").write_text(str(p)) if p else None;os._exit(0) if p else time.sleep(20)"
p=subprocess.Popen([sys.executable,'-c',source],start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
try:
    row=common.await_terminal(p,time.monotonic()+2)
    assert row.si_code==os.CLD_EXITED and row.si_status==0 and p.returncode is None
    descendant=int(pidfile.read_text());assert descendant>0
    calls=[];real=os.killpg
    def signal_group(pid,sig):
        assert p.returncode is None
        assert os.waitid(os.P_PID,p.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is not None
        calls.append((pid,sig));real(pid,sig)
    common.os.killpg=signal_group
    assert common.reap(p)==0
    assert calls==[(p.pid,signal.SIGKILL)]
    adopted,status=os.waitpid(descendant,0)
    assert adopted==descendant and os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGKILL
finally:
    if p.returncode is None:common.reap(p)
print('OWNED_DESCENDANT_RETIRED')
"""
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as temporary:
            env=dict(os.environ,PYTHONPATH=str(Path(common.__file__).parent))
            result=common.bounded([sys.executable,'-B','-c',code,temporary],env=env,timeout=6)
        self.assertEqual(result['returncode'],0,result['stderr']);self.assertIsNone(result['error'])
        self.assertEqual(result['stdout'],'OWNED_DESCENDANT_RETIRED\n')

    def test_qemu_source_has_no_reaping_observers_and_drainer_owner_only(self):
        source=Path(run.__file__).read_text();tree=ast.parse(source)
        self.assertFalse(any(isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr in ('poll','wait') for n in ast.walk(tree)))
        self.assertIn('owner_signals_only=True',source)
        self.assertIn('with registered_spawn():',source)


if __name__ == '__main__':unittest.main()
