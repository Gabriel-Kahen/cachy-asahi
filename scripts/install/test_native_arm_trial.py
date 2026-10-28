# SPDX-License-Identifier: MIT
"""Source/data/process mocks only; never launch native/GPG/namespace/package actors."""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent

def loaded():
    p=HERE/'native_arm_trial.py';m=types.ModuleType('native_receiver_fixture');m.__file__=str(p);exec(compile(p.read_bytes(),str(p),'exec'),m.__dict__);return m


class ReceiverTests(unittest.TestCase):
    def setUp(self):
        self.m=loaded();self.tmp=tempfile.TemporaryDirectory(prefix='native-receiver-model-');self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)
    def selection(self):
        sources={}
        for n in self.m.SOURCE_PATHS:
            source=HERE.parents[1]/n;p=self.root/n;p.parent.mkdir(parents=True,exist_ok=True);b=source.read_bytes();
            if p.exists():p.chmod(0o600)
            p.write_bytes(b);p.chmod(0o400)
            sources[n]={'size':len(b),'sha256':self.m.sha(b)}
        return dict(schema_version=1,purpose='native-arm-synthetic-installer',phase='preflight',source_commit='a'*40,
                    sources=sources,tool_profile_sha256=self.m.sha(self.m.PROFILE_BYTES),native_inputs_sha256=self.m.INPUTS_SHA,
                    builder_packages_sha256=self.m.BASE_SHA,image_id='sha256:'+'a'*64,image_config_sha256='b'*64,
                    native_handoff_sha256='c'*64,nonce='d'*32)
    def record(self):
        return dict(schema_version=1,status='PASS_NATIVE_PREFLIGHT_ONLY',phase='complete',barrier='PASS',ABI='NOT_RUN',matrix='NOT_RUN',
                    tests=1,failures=0,errors=0,skips=0,termination=False,owned_child_cleanup='PASS',first_failure='NONE')
    def test_selected_source_bytes_and_runtime_exact(self):
        s=self.selection();self.assertEqual(set(self.m.source_blobs(s,self.root,time.monotonic()+5)),set(self.m.SOURCE_PATHS))
    def test_stale_source_refuses(self):
        s=self.selection();p=self.root/self.m.SOURCE_PATHS[0];p.chmod(0o600);p.write_bytes(b'substitute')
        with self.assertRaises(ValueError):self.m.source_blobs(s,self.root,time.monotonic()+5)
    def test_missing_source_row_refuses(self):
        s=self.selection();del s['sources'][self.m.SOURCE_PATHS[-1]]
        with self.assertRaises(ValueError):self.m.source_blobs(s,self.root,time.monotonic()+5)
    def test_mutated_source_size_and_nonboolean_caps_refuse(self):
        for value in (True,-1,0,128*1024+1,1.5):
            s=self.selection();s['sources'][self.m.SOURCE_PATHS[0]]['size']=value
            with self.assertRaises(ValueError):self.m.source_blobs(s,self.root,time.monotonic()+5)
    def test_expired_input_performs_no_open(self):
        with patch.object(self.m.os,'open',side_effect=AssertionError('I/O forbidden')) as actor:
            with self.assertRaises(ValueError):self.m.read(self.root/'unused',8,time.monotonic()-1)
        actor.assert_not_called()
    def test_fifo_is_refused_before_readable_open(self):
        path=self.root/'pipe';os.mkfifo(path);old=self.m.os.open;calls=[]
        def opened(p,flags,*a,**kw):calls.append(flags);return old(p,flags,*a,**kw)
        with patch.object(self.m.os,'open',side_effect=opened):
            with self.assertRaises(ValueError):self.m.read(path,10,time.monotonic()+5)
        self.assertTrue(all(f & os.O_PATH for f in calls));self.assertTrue(calls[-1]&os.O_NOFOLLOW)
    def test_ancestor_and_leaf_symlinks_are_refused(self):
        actual=self.root/'real';actual.mkdir();(actual/'data').write_bytes(b'same');(self.root/'alias').symlink_to(actual,target_is_directory=True)
        for path in (self.root/'alias/data',self.root/'leaf'):
            if path.name=='leaf':path.symlink_to(actual/'data')
            with self.assertRaises((OSError,ValueError)):self.m.read(path,20,time.monotonic()+5)
    def test_same_bytes_inode_substitution_refused(self):
        p=self.root/'data';p.write_bytes(b'original');p.chmod(0o600);old=self.m.os.read;changed=False
        def reader(fd,size):
            nonlocal changed
            b=old(fd,size)
            if not changed:
                changed=True;q=self.root/'new';q.write_bytes(b'original');q.chmod(0o600);q.replace(p)
            return b
        with patch.object(self.m.os,'read',side_effect=reader):
            with self.assertRaises(ValueError):self.m.read(p,20,time.monotonic()+5)
    def test_unknown_selection_field_and_mutable_bool_refuse(self):
        for key,value in (('accepted',True),('schema_version',True),('native_inputs_sha256','e'*64),('tool_profile_sha256','f'*64),('purpose','real-candidate')):
            s=self.selection();s[key]=value
            with self.assertRaises(ValueError):self.m.validate_selection(s)
    def test_closed_docker_profile_never_relaxes_or_exposes_socket(self):
        s=self.selection()
        with patch.object(self.m.os,'uname',return_value=types.SimpleNamespace(machine='aarch64')):
            cmd=self.m.docker_command(s,Path('/test/source'),Path('/test/input'),Path('/test/output'))
        for flag in ('--network=none','--cap-drop=ALL','--security-opt=no-new-privileges','--read-only','--pull=never','--platform=linux/arm64'):self.assertIn(flag,cmd)
        self.assertFalse(any('privileged' in a or 'unconfined' in a or 'SYS_ADMIN' in a or 'docker.sock' in a for a in cmd))
        self.assertEqual(cmd[cmd.index('--user')+1],f'{os.getuid()}:{os.getgid()}')
    def test_x86_constructor_refuses_native_emulation_claim(self):
        with patch.object(self.m.os,'uname',return_value=types.SimpleNamespace(machine='x86_64')):
            with self.assertRaises(ValueError):self.m.docker_command(self.selection(),Path('/s'),Path('/i'),Path('/o'))
    def test_command_unsafe_bind_refused(self):
        s=self.selection()
        for p in ('relative','/test/a,b','/test/a\n'):
            with patch.object(self.m.os,'uname',return_value=types.SimpleNamespace(machine='aarch64')):
                with self.assertRaises(ValueError):self.m.docker_command(s,Path(p),Path('/i'),Path('/o'))
    def test_profile_or_tool_refusal_before_module_and_actor(self):
        s=self.selection()
        with patch.object(self.m,'source_blobs',return_value={}),patch.object(self.m,'verify_environment',side_effect=ValueError('TOOL_HASH')),patch.object(self.m,'module',side_effect=AssertionError('loaded actor')) as actor:
            with self.assertRaises(ValueError):self.m.execute(s,self.root,self.root,time.monotonic()+60,time.monotonic()+59)
        actor.assert_not_called()
    def test_preflight_absolute_cutoff_never_renews_after_source_preparation(self):
        s=self.selection()
        with patch.object(self.m,'source_blobs',side_effect=AssertionError('source I/O forbidden')) as actor:
            with self.assertRaises(ValueError):self.m.execute(s,self.root,self.root,time.monotonic()+1800,time.monotonic()-1)
        actor.assert_not_called()
    def test_code_mutation_same_function_object_refused(self):
        m=types.ModuleType('inert');exec('def entry(): return 1',m.__dict__);bound=self.m.functions(m)
        exec('def replacement(): return 2',m.__dict__);m.entry.__code__=m.replacement.__code__
        with self.assertRaises(ValueError):self.m.check_functions(bound)
    def test_closure_cell_change_refused(self):
        m=types.ModuleType('inert');exec('def factory():\n x=object()\n def entry():return x\n return entry\nentry=factory()',m.__dict__);bound=self.m.functions(m)
        m.entry.__closure__[0].cell_contents=object()
        with self.assertRaises(ValueError):self.m.check_functions(bound)
    def test_public_preflight_does_not_grant_matrix_or_ABI(self):
        r=self.record();value=json.loads(self.m.public(r));self.assertEqual(value['ABI'],'NOT_RUN');self.assertEqual(value['matrix'],'NOT_RUN')
    def test_public_missing_cleanup_or_cancel_never_passes(self):
        for k,v in (('owned_child_cleanup','UNKNOWN'),('termination',True),('failures',1),('skips',1),('tests',True),('phase','/secret')):
            r=self.record();r[k]=v
            with self.assertRaises(ValueError):self.m.public(r)
    def test_public_partial_matrix_refuses(self):
        r=self.record();r.update(status='PASS_NATIVE_FIXTURE_ONLY',tests=26,matrix='PASS')
        with self.assertRaises(ValueError):self.m.public(r)
        r['ABI']='PASS';self.assertLess(len(self.m.public(r)),4096)
    def test_required_role_profile_no_generic_Tk_completion_claim(self):
        profile=json.loads(self.m.PROFILE_BYTES);self.assertEqual(len(profile['excluded_optional_not_reachable_from_selected_role']),1)
        self.assertEqual(len(profile['excluded_generic_missing']),2)
        self.assertFalse(any('/_tkinter.' in r['path'] for r in profile['files']))
        self.assertIn('/usr/lib/libalpm.so.16.0.1',{r['path'] for r in profile['files']})
    def test_runtime_matrix_has_exact_26_original_methods(self):
        self.assertEqual(sum(map(len,self.m.SELECTED.values())),26)
        self.assertEqual(len(self.m.SELECTED['ActualTransactionTests']),17)
    def test_duplicate_nonfinite_json_refuses(self):
        for raw in (b'{"a":1,"a":2}',b'{"a":NaN}',b'{"a":Infinity}'):
            with self.assertRaises(ValueError):self.m.strict(raw)



class ProcessMockTests(unittest.TestCase):
    def setUp(self):
        self.m=loaded();self.ended=[]
        class Stream:
            def __init__(self,n):self.n=n;self.closed=False
            def fileno(self):return self.n
            def close(self):self.closed=True
        self.process=types.SimpleNamespace(pid=1234,stdout=Stream(11),stderr=Stream(12),returncode=None)
        @contextlib.contextmanager
        def deferred():yield []
        def cleanup(p):self.ended.append(p);p.returncode=0
        self.rt=types.SimpleNamespace(SIGNALS=(2,15),defer_signals=deferred,_cleanup=cleanup,
                                     _child_setup=lambda *args:None,Cancelled=type('Cancelled',(BaseException,),{}))
        class Selector:
            def __init__(self):self.rows={}
            def register(self,stream,events,index):self.rows[stream.fileno()]=types.SimpleNamespace(fd=stream.fileno(),fileobj=stream,data=index)
            def get_map(self):return self.rows
            def select(self,timeout):return [(k,1) for k in list(self.rows.values())]
            def unregister(self,stream):self.rows.pop(stream.fileno())
            def close(self):self.rows.clear()
        self.selector=Selector
    @contextlib.contextmanager
    def mocks(self,mask=None,reader=None):
        values={11:iter((b'out',b'')),12:iter((b'err',b''))}
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(self.m.subprocess,'Popen',return_value=self.process))
            stack.enter_context(patch.object(self.m.selectors,'DefaultSelector',self.selector))
            stack.enter_context(patch.object(self.m.signal,'pthread_sigmask',side_effect=mask or (lambda *a:set())))
            stack.enter_context(patch.object(self.m.os,'set_blocking'))
            stack.enter_context(patch.object(self.m.os,'read',side_effect=reader or (lambda fd,size:next(values[fd]))))
            stack.enter_context(patch.object(self.m.os,'waitid',return_value=types.SimpleNamespace(si_pid=1234)))
            yield
    def test_separate_stdio_and_cleanup_match_existing_call_semantics(self):
        with self.mocks():r=self.m.Calls(time.monotonic()+20,self.rt,lambda:None,Path('/out')).run(['/usr/bin/python3','-I','-B'],timeout=10,capture_output=True)
        self.assertEqual((r.stdout,r.stderr,r.returncode),(b'out',b'err',0));self.assertEqual(self.ended,[self.process])
        self.assertTrue(self.process.stdout.closed and self.process.stderr.closed)
    def test_pending_termination_after_spawn_is_tracked_and_cleaned(self):
        calls=0
        def mask(how,signals):
            nonlocal calls
            calls+=1
            if calls==2:raise self.rt.Cancelled()
            return set()
        with self.mocks(mask=mask):
            with self.assertRaises(self.rt.Cancelled):self.m.Calls(time.monotonic()+20,self.rt,lambda:None,Path('/out')).run(['/usr/bin/python3'],timeout=10)
        self.assertEqual(self.ended,[self.process]);self.assertTrue(self.process.stdout.closed)
    def test_partial_output_refusal_reaps_owned_process(self):
        def reader(fd,size):raise ValueError('OUTPUT_CAP')
        with self.mocks(reader=reader):
            with self.assertRaises(ValueError):self.m.Calls(time.monotonic()+20,self.rt,lambda:None,Path('/out')).run(['/usr/bin/python3'],timeout=10)
        self.assertEqual(self.ended,[self.process])
    def test_cleanup_failure_is_sticky(self):
        def cleanup(p):raise ValueError('owned cleanup fail')
        self.rt._cleanup=cleanup;calls=self.m.Calls(time.monotonic()+20,self.rt,lambda:None,Path('/out'))
        with self.mocks():
            with self.assertRaises(ValueError):calls.run(['/usr/bin/python3'],timeout=10)
        self.assertFalse(calls.cleanup)
    def test_insufficient_remaining_cleanup_budget_refuses_before_spawn(self):
        with patch.object(self.m.subprocess,'Popen',side_effect=AssertionError('actor')) as actor:
            with self.assertRaises(ValueError):self.m.Calls(time.monotonic()+4,self.rt,lambda:None,Path('/out')).run(['/usr/bin/python3'],timeout=10)
        actor.assert_not_called()
    def test_unknown_command_refuses_before_spawn(self):
        with patch.object(self.m.subprocess,'Popen',side_effect=AssertionError('actor')) as actor:
            with self.assertRaises(ValueError):self.m.Calls(time.monotonic()+20,self.rt,lambda:None,Path('/out')).run(['/usr/bin/docker'],timeout=10)
        actor.assert_not_called()


class PipelineMockTests(unittest.TestCase):
    setUp=ReceiverTests.setUp
    selection=ReceiverTests.selection
    """Explicit fake environment/barrier/process facts: pipeline/source logic only."""
    def test_preflight_source_mock_succeeds_without_matrix_or_package(self):
        r=self.pipeline();self.assertEqual(r['status'],'PASS_NATIVE_PREFLIGHT_ONLY');self.assertEqual(r['ABI'],'NOT_RUN');self.assertEqual(r['matrix'],'NOT_RUN')
    def test_fake_result_without_owned_barrier_call_is_refused(self):
        r=self.pipeline(ordinal=0);self.assertEqual(r['status'],'FAIL');self.assertEqual(r['first_failure'],'BARRIER_FAILED')
    def test_preflight_failure_never_reaches_ABI(self):
        r=self.pipeline(success=False);self.assertEqual(r['status'],'FAIL');self.assertEqual(r['ABI'],'NOT_RUN')
    def test_pending_cleanup_termination_revokes_durable_status(self):
        r=self.pipeline(pending=True);self.assertEqual(r['status'],'FAIL');self.assertTrue(r['termination']);self.assertEqual(r['first_failure'],'CANCELLED')
        self.assertEqual(json.loads((self.root/'out/result.json').read_bytes())['status'],'FAIL')
    def test_late_terminal_close_failure_preserves_FAIL_in_loan(self):
        r=self.pipeline(close_fail=True);self.assertEqual(r['status'],'FAIL')
        self.assertEqual(json.loads((self.root/'out/result.json').read_bytes())['status'],'FAIL')
    def test_first_barrier_failure_not_replaced_by_late_cancel(self):
        r=self.pipeline(success=False,pending=True);self.assertEqual(r['status'],'FAIL');self.assertEqual(r['first_failure'],'BARRIER_FAILED');self.assertTrue(r['termination'])
    def pipeline(self,success=True,ordinal=1,pending=False,close_fail=False):
        m=self.m;s=self.selection();out=self.root/'out';out.mkdir(mode=0o700);factory=m.module;runtime=types.SimpleNamespace(__name__='mock_runtime',SIGNALS=(2,15),Cancelled=type('Cancelled',(BaseException,),{}))
        @contextlib.contextmanager
        def handlers(callback):yield
        @contextlib.contextmanager
        def deferred():yield [15] if pending else []
        runtime._handlers=handlers;runtime.defer_signals=deferred
        worker=None;class_result=types.SimpleNamespace(testsRun=1,skipped=[],wasSuccessful=lambda:success)
        class FakeCalls:
            def __init__(self,*args):self.ordinal=ordinal;self.cleanup=True
            def run(self,*args,**kwargs):raise AssertionError('actual actor forbidden')
        def modules(raw,path,name):
            nonlocal worker
            value=factory(raw,path,name)
            if name=='selected_installer':
                worker=value;worker.runtime=lambda:runtime
                if close_fail:
                    close=value.Evidence.close
                    def failed_close(instance):
                        close(instance)
                        if instance is not m.TERMINAL_LEASE:raise ValueError('close failure model')
                    value.Evidence.close=failed_close
            elif name=='selected_native_tests':value.BarrierTests.last_report={'worker_sha256':s['sources'][m.SOURCE_PATHS[0]]['sha256']}
            return value
        with patch.object(m,'verify_environment'),patch.object(m,'module',side_effect=modules),patch.object(m,'Calls',FakeCalls),patch.object(m.unittest,'TextTestRunner') as runner:
            runner.return_value.run.return_value=class_result
            try:r=m.execute(s,self.root,out,time.monotonic()+60,time.monotonic()+59)
            finally:
                if m.TERMINAL_LEASE is not None:
                    m.TERMINAL_LEASE.close();m.TERMINAL_LEASE=None
        return r

class CompletePhaseProjectionTests(unittest.TestCase):
    setUp=ReceiverTests.setUp
    record=ReceiverTests.record
    def pass_record(self,status,phase):
        record=self.record();record.update(status=status,phase=phase)
        if status=='PASS_NATIVE_FIXTURE_ONLY':record.update(ABI='PASS',matrix='PASS',tests=26)
        return record
    def test_both_PASS_statuses_refuse_all_incomplete_phases(self):
        for status in ('PASS_NATIVE_PREFLIGHT_ONLY','PASS_NATIVE_FIXTURE_ONLY'):
            for phase in ('inputs','preflight','ABI','matrix'):
                with self.subTest(status=status,phase=phase):
                    with self.assertRaisesRegex(ValueError,'PUBLIC_PASS'):
                        self.m.public(self.pass_record(status,phase))
    def test_both_complete_PASS_statuses_remain_accepted(self):
        for status in ('PASS_NATIVE_PREFLIGHT_ONLY','PASS_NATIVE_FIXTURE_ONLY'):
            with self.subTest(status=status):
                record=self.pass_record(status,'complete')
                self.assertEqual(json.loads(self.m.public(record)),record)
    def test_incomplete_failure_diagnostics_remain_accepted(self):
        for status in ('FAIL','REFUSED'):
            for phase in ('inputs','preflight','ABI','matrix'):
                with self.subTest(status=status,phase=phase):
                    record=self.record();record.update(status=status,phase=phase,first_failure='INPUT_REFUSED')
                    self.assertEqual(json.loads(self.m.public(record)),record)


if __name__=='__main__':unittest.main()
