# SPDX-License-Identifier: MIT
"""Source/data/process mocks only; never launch native/GPG/namespace/package actors."""
import contextlib
import hashlib
import io
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
        self.enterContext(patch.dict(os.environ, {'GITHUB_RUN_ID':'123456', 'GITHUB_RUN_ATTEMPT':'1'}))
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
        self.assertIn('--security-opt=seccomp=/test/input/dev-seccomp.json',cmd)
        self.assertIn('--security-opt=apparmor=cachy-asahi-p0-dev-123456-1',cmd)
    def test_dev_profile_requires_exact_synthetic_job_context(self):
        s=self.selection()
        for values in ({}, {'GITHUB_RUN_ID':'123456','GITHUB_RUN_ATTEMPT':'../foreign'}):
            with patch.dict(os.environ,values,clear=True),patch.object(self.m.os,'uname',return_value=types.SimpleNamespace(machine='aarch64')):
                with self.assertRaisesRegex(ValueError,'CONTAINER_POLICY'):
                    self.m.docker_command(s,Path('/s'),Path('/i'),Path('/o'))
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


class CurrentInputSuccessorTests(unittest.TestCase):
    """Exercise the actual receiver; stop modeled environment checks before tool I/O."""
    setUp=ReceiverTests.setUp
    selection=ReceiverTests.selection
    record=ReceiverTests.record

    def current_selection(self):
        value=self.selection();value.update(input_successor=dict(self.m.P0_CURRENT_CONTRACT),
            tool_profile_lineage=self.m.TOOL_PROFILE_LINEAGE,
            native_inputs_sha256=self.m.P0_CURRENT_CONTRACT['inputs_sha256'],
            builder_packages_sha256=self.m.P0_CURRENT_CONTRACT['packages_sha256'])
        return value

    def inventory(self,current):
        value=json.loads((HERE.parents[1]/'scripts/ci/inputs.lock.json').read_bytes())
        names={row['name'][0]:row['version'][0] for row in value['rootfs_packages']}
        names.update({row['name']:row['version'] for row in value['packages']})
        if current:names.update(vim='9.2.1178-1',**{'vim-runtime':'9.2.1178-1'})
        raw=''.join(name+' '+names[name]+'\n' for name in sorted(names)).encode()
        expected=self.m.P0_CURRENT_CONTRACT['packages_sha256'] if current else self.m.BASE_SHA
        self.assertEqual(self.m.sha(raw),expected)
        return raw

    def image(self,selection):
        config={'ArgsEscaped':False,'Cmd':[],'Entrypoint':[],
            'Env':['PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'],
            'ExposedPorts':None,'Healthcheck':None,'Labels':{},'Shell':[],
            'StopSignal':None,'User':'alarm','Volumes':None,'WorkingDir':'/tmp'}
        value=dict(source_commit=selection['source_commit'],image_id=selection['image_id'],
            inputs_sha256=selection['native_inputs_sha256'],packages_lock_sha256=selection['builder_packages_sha256'],
            architecture='arm64',os='linux',Config=config)
        if 'input_successor' in selection:value.update(input_successor=dict(selection['input_successor']),tool_profile_lineage=self.m.TOOL_PROFILE_LINEAGE)
        selection['image_config_sha256']=self.m.sha((json.dumps(config,sort_keys=True)+'\n').encode())
        return value

    def environment_model(self,selection,image,packages):
        """Real selection/image/inventory/profile checks; no actual tool or host trial."""
        raw=(json.dumps(image,sort_keys=True)+'\n').encode();selection['native_handoff_sha256']=self.m.sha(raw);reads=[]
        def read(path,*args):
            reads.append(str(path))
            if str(path)=='/inputs/image.json':return raw
            if str(path)=='/builder-packages.lock':return packages
            raise AssertionError('unexpected tool/payload read')
        status=dict(NoNewPrivs='1',**{key:'0' for key in ('CapEff','CapPrm','CapInh','CapAmb','CapBnd')})
        class ReachedToolAliases(Exception):pass
        self.reached_tools=ReachedToolAliases
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(self.m,'read',side_effect=read))
            stack.enter_context(patch.object(self.m,'proc_status',return_value=status))
            stack.enter_context(patch.object(self.m.os,'uname',return_value=types.SimpleNamespace(machine='aarch64')))
            for name in ('getuid','geteuid','getgid','getegid'):stack.enter_context(patch.object(self.m.os,name,return_value=1000))
            stack.enter_context(patch.object(self.m.os,'environ',{'CACHY_ASAHI_INSTALL_NONCE':selection['nonce'],'CACHY_ASAHI_INSTALL_IMAGE':selection['image_id']}))
            stack.enter_context(patch.object(self.m.Path,'resolve',side_effect=ReachedToolAliases))
            try:self.m.verify_environment(selection,time.monotonic()+5)
            except ReachedToolAliases:return reads
        raise AssertionError('expected stop before tool alias and file audit')

    def test_explicit_current_and_historical_routes_are_distinct(self):
        old=self.selection();current=self.current_selection()
        self.assertIs(self.m.validate_selection(old),old);self.assertIs(self.m.validate_selection(current),current)
        self.assertEqual(self.m.input_selection(),(self.m.INPUTS_SHA,self.m.BASE_SHA))
        self.assertEqual(self.m.input_selection(current['input_successor']),
            (current['native_inputs_sha256'],current['builder_packages_sha256']))
        self.assertNotEqual(self.m.input_selection(),self.m.input_selection(current['input_successor']))

    def test_current_pair_cannot_enter_without_explicit_selector(self):
        value=self.current_selection();del value['input_successor'];del value['tool_profile_lineage']
        with self.assertRaisesRegex(ValueError,'PROFILE_PIN'):self.m.validate_selection(value)

    def test_historical_or_mixed_hashes_refuse_current_selector(self):
        for old_inputs,old_packages in ((True,True),(True,False),(False,True)):
            value=self.current_selection()
            if old_inputs:value['native_inputs_sha256']=self.m.INPUTS_SHA
            if old_packages:value['builder_packages_sha256']=self.m.BASE_SHA
            with self.subTest(inputs=old_inputs,packages=old_packages),self.assertRaisesRegex(ValueError,'PROFILE_PIN'):self.m.validate_selection(value)

    def test_current_selector_is_closed_typed_and_version_pinned(self):
        original=dict(self.m.P0_CURRENT_CONTRACT)
        for key in original:
            value=dict(original);value[key]='not selected'
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'INPUT_SUCCESSOR'):self.m.validate_input_successor(value)
        class Text(str):pass
        class Number(int):pass
        for value in ({**original,'schema_version':True},{**original,'schema_version':1.0},
                {**original,'schema_version':Number(1)},{**original,'product':Text(original['product'])},
                {**original,'extra':1}):
            with self.assertRaisesRegex(ValueError,'INPUT_SUCCESSOR'):self.m.validate_input_successor(value)
        value=dict(original);value[Text('product')]=value.pop('product')
        with self.assertRaisesRegex(ValueError,'INPUT_SUCCESSOR'):self.m.validate_input_successor(value)

    def test_current_matrix_mode_and_current_audit_profile_claim_refuse(self):
        for key,value in (('phase','matrix'),('tool_profile_lineage','CURRENT_AUDIT')):
            selection=self.current_selection();selection[key]=value
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'PROFILE_LINEAGE'):self.m.validate_selection(selection)

    def test_real_environment_validation_selects_current_inventory(self):
        value=self.current_selection();image=self.image(value)
        self.assertEqual(self.environment_model(value,image,self.inventory(True)),['/inputs/image.json','/builder-packages.lock'])

    def test_real_environment_validation_preserves_historical_inventory_route(self):
        value=self.selection();image=self.image(value)
        self.assertEqual(self.environment_model(value,image,self.inventory(False)),['/inputs/image.json','/builder-packages.lock'])

    def test_current_environment_rejects_old_image_or_inventory(self):
        value=self.current_selection();image=self.image(value);image['inputs_sha256']=self.m.INPUTS_SHA
        with self.assertRaisesRegex(ValueError,'IMAGE_HANDOFF_BINDING'):self.environment_model(value,image,self.inventory(True))
        value=self.current_selection();image=self.image(value)
        with self.assertRaisesRegex(ValueError,'BUILDER_INVENTORY'):self.environment_model(value,image,self.inventory(False))

    def test_current_image_requires_selector_and_historical_profile_lineage(self):
        for key in ('input_successor','tool_profile_lineage'):
            value=self.current_selection();image=self.image(value);del image[key]
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'IMAGE_SUCCESSOR'):self.environment_model(value,image,self.inventory(True))

    def test_profile_bytes_are_historical_whitelist_not_new_tool_audit(self):
        profile=json.loads(self.m.PROFILE_BYTES)
        self.assertEqual(profile['inputs_sha256'],self.m.INPUTS_SHA)
        self.assertNotEqual(profile['inputs_sha256'],self.m.P0_CURRENT_CONTRACT['inputs_sha256'])
        self.assertEqual(self.m.sha(self.m.PROFILE_BYTES),'b7fbd65e357e132949432fb00e765a05e3c76ea29a41d1df93413870d9fd1ed8')
        self.assertFalse(any(row['owner'].split()[0] in ('vim','vim-runtime') for row in profile['files']))
        value=self.current_selection();image=self.image(value);profile['inputs_sha256']=self.m.P0_CURRENT_CONTRACT['inputs_sha256']
        with patch.object(self.m,'PROFILE_BYTES',(json.dumps(profile,sort_keys=True)+'\n').encode()):
            with self.assertRaisesRegex(ValueError,'PROFILE_PIN|PROFILE_LINEAGE'):self.environment_model(value,image,self.inventory(True))

    def test_current_public_result_retains_exact_selector_and_profile_lineage(self):
        record=self.record();record.update(input_successor=dict(self.m.P0_CURRENT_CONTRACT),tool_profile_lineage=self.m.TOOL_PROFILE_LINEAGE)
        self.assertEqual(json.loads(self.m.public(record)),record)
        for key in ('input_successor','tool_profile_lineage'):
            bad=dict(record);del bad[key]
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'PROFILE_LINEAGE'):self.m.public(bad)

    def test_main_refusal_after_current_selection_retains_product_provenance(self):
        selection=self.current_selection();raw=(json.dumps(selection,sort_keys=True)+'\n').encode();output=io.BytesIO()
        with patch.object(self.m.sys,'argv',['receiver','--selection','/inputs/trial.json','--selection-sha256',self.m.sha(raw)]),\
             patch.object(self.m.sys,'stdout',types.SimpleNamespace(buffer=output)),\
             patch.object(self.m,'read',return_value=raw),patch.object(self.m,'execute',side_effect=ValueError('inert pre-actor refusal')) as actor:
            code=self.m.main()
        value=json.loads(output.getvalue());self.assertEqual(code,2);actor.assert_called_once()
        self.assertEqual(value['status'],'REFUSED');self.assertEqual(value['input_successor'],self.m.P0_CURRENT_CONTRACT)
        self.assertEqual(value['tool_profile_lineage'],self.m.TOOL_PROFILE_LINEAGE)

    def test_main_invalid_selector_refuses_before_execute_without_current_provenance(self):
        selection=self.current_selection();selection['input_successor']['inputs_sha256']=self.m.INPUTS_SHA
        raw=(json.dumps(selection,sort_keys=True)+'\n').encode();output=io.BytesIO()
        with patch.object(self.m.sys,'argv',['receiver','--selection','/inputs/trial.json','--selection-sha256',self.m.sha(raw)]),\
             patch.object(self.m.sys,'stdout',types.SimpleNamespace(buffer=output)),\
             patch.object(self.m,'read',return_value=raw),patch.object(self.m,'execute',side_effect=AssertionError('actor forbidden')) as actor:
            code=self.m.main()
        value=json.loads(output.getvalue());self.assertEqual(code,2);actor.assert_not_called()
        self.assertEqual(value['status'],'REFUSED');self.assertNotIn('input_successor',value);self.assertNotIn('tool_profile_lineage',value)


if __name__=='__main__':unittest.main()
