# SPDX-License-Identifier: MIT
"""FENCED executor DATA controls: no process, daemon, privilege or native role."""
import copy
import contextlib
import io
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

def actor_denial_fence(event,args):
    if event.startswith(('subprocess.','socket.','ctypes.'))or event in (
        'os.system','os.exec','os.fork','os.posix_spawn','os.pidfd_open','os.kill','os.killpg','os.setuid','os.setgid','resource.setrlimit','fcntl.flock'):
        raise RuntimeError('FENCED MODEL controls deny actors: '+event)


sys.addaudithook(actor_denial_fence)

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('fenced_current_executor',HERE/'payload/native/owned_executor_current_v3.py')
E=importlib.util.module_from_spec(spec);spec.loader.exec_module(E)
POLICY=json.loads((HERE/'owned-executor-current-v3.policy.PROPOSAL.json').read_bytes())
NONCE='a'*64


def supervision(exit=0,output=b'{"FENCED":true}\n'):
    return dict(exit=exit,reaped=True,ownership='REAPED',timeout=False,signals=[],output=output,
                output_complete=True,group_census='EMPTY_TWICE',error=None,seconds=.01,passed=exit==0)


def tool(name):return dict(path='/usr/bin/'+name,candidate='/usr/bin/'+name,FENCED='NOT_AN_OBSERVED_HOST_TOOL')


class ModelStderr(io.BytesIO):
    """Inert bounded bytes for command MODELs; never a claimed kernel seal."""
    def __init__(self):
        super().__init__();self.truncate(E.MAX_OUTPUT)
    def write(self,raw):
        if self.tell()+len(raw)>E.MAX_OUTPUT:raise OSError('MODEL bounded stderr')
        return super().write(raw)


def model_runtime():
    """Install MODEL exports inside the actor fence, restoring real APIs afterward."""
    stack=contextlib.ExitStack()
    for name in ('memfd_create','pidfd_open'):
        stack.enter_context(patch.object(E.os,name,side_effect=AssertionError('MODEL API must not perform a kernel operation'),create=True))
    # Positive sentinel values satisfy export-shape checks only. They are never
    # supplied to real fcntl/memfd operations and make no runtime support claim.
    for module,names in ((E.os,('MFD_CLOEXEC','MFD_ALLOW_SEALING')),(E.fcntl,('F_ADD_SEALS','F_SEAL_GROW','F_SEAL_SHRINK'))):
        for name in names:stack.enter_context(patch.object(module,name,1,create=True))
    stack.enter_context(patch.object(E,'stderr_buffer',side_effect=ModelStderr))
    return stack


class FakeOwned:
    def __init__(self,row):self.row=row;self.calls=[]
    def prepare(self):self.calls.append('prepare')
    def supervise(self,child,**kwargs):self.calls.append(('supervise',kwargs));return copy.deepcopy(self.row)


class CommandControls(unittest.TestCase):
    def setUp(self):
        self.MODEL=model_runtime();self.addCleanup(self.MODEL.close)
        self.tmp=tempfile.TemporaryDirectory(prefix='FENCED-executor-');self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.O=FakeOwned(supervision());self.tools={name:tool(name)for name in E.NAMES}
        self.engine=E.CommandEngine(self.O,self.tools,self.root,10000,4);self.launch=[];self.stderr=b'FENCED diagnostic\n'
    def spawn(self,argv,**kwargs):
        self.assertEqual(self.O.calls[-1],'prepare')
        self.launch.append((argv,kwargs));kwargs['stderr'].write(self.stderr)
        return SimpleNamespace(FENCED='NOT_A_PROCESS',stdout=None)
    def call(self,*args,**kwargs):
        with patch.object(E,'checked_tool',side_effect=lambda row:row['path']),patch.object(E.subprocess,'Popen',side_effect=self.spawn),patch.object(E.time,'monotonic',return_value=1):
            return self.engine.run(*args,**kwargs)
    def test_exact_stdout_and_separate_stderr_with_natural_receipt(self):
        argv=['/usr/bin/docker','--host=unix:///FENCED/private.sock','info']
        value=self.call('inspect',argv,15)
        self.assertEqual(value['stdout'],b'{"FENCED":true}\n')
        row=value['receipt'];self.assertEqual(row['argv'],argv);self.assertEqual(row['step'],'inspect')
        self.assertEqual(row['output_pin'],E.pin(value['stdout']));self.assertEqual(row['stderr_pin'],E.pin(self.stderr))
        self.assertEqual(self.O.calls[0],'prepare');self.assertEqual(self.launch[0][1]['start_new_session'],True)
        self.assertNotIn('preexec_fn',self.launch[0][1]);self.assertNotIn('GH_TOKEN',self.launch[0][1]['env'])
        self.assertTrue((self.root/'command-0000.json').is_file())
    def test_expected_nonzero_uses_raw_exit_not_passed(self):
        self.O.row=supervision(7,b'FENCED expected failure')
        value=self.call('expected-seven',['/usr/bin/gpgconf','--version'],10,expected=7)
        self.assertFalse(value['receipt']['supervision']['passed']);self.assertEqual(value['receipt']['expected'],7)
    def test_unknown_forced_incomplete_or_wrong_exit_never_succeeds(self):
        for key,value in [('ownership','UNKNOWN'),('reaped',False),('group_census','PRESENT_OR_REUSED'),('signals',['SIGTERM']),('timeout',True),('error','FENCED'),('output_complete',False),('exit',2)]:
            self.O.row=supervision();self.O.row[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.call('case-'+key,['/usr/bin/gpgconf','--version'],10)
            self.engine.receipts.clear()
            for path in self.root.iterdir():path.unlink()
    def test_stderr_bound_refuses_and_keeps_exact_failed_intent(self):
        self.stderr=b'x'*E.MAX_OUTPUT
        with self.assertRaises(ValueError):self.call('stderr-cap',['/usr/bin/gpgconf','--version'],10)
        row=json.loads((self.root/'command-0000.json').read_bytes())
        self.assertEqual(row['step'],'stderr-cap');self.assertIn('failure',row)
    def test_spawn_latency_still_transfers_child_to_supervisor(self):
        with patch.object(E,'checked_tool',side_effect=lambda row:row['path']),patch.object(E.subprocess,'Popen',side_effect=self.spawn),patch.object(E.time,'monotonic',side_effect=[1,1,20]):
            with self.assertRaises(ValueError):self.engine.run('late-spawn',['/usr/bin/gpgconf','--version'],2)
        self.assertEqual(self.O.calls[-1][0],'supervise');self.assertEqual(self.O.calls[-1][1]['cap'],.6)
    def test_duplicate_step_and_expired_stage_refuse_before_spawn(self):
        self.call('once',['/usr/bin/gpgconf','--version'],10)
        with self.assertRaises(ValueError):self.call('once',['/usr/bin/gpgconf','--version'],10)
        self.engine.deadline=0
        with self.assertRaises(ValueError):self.call('expired',['/usr/bin/gpgconf','--version'],10)
        self.assertEqual(len(self.launch),1)
    def test_env_wrapper_resolves_both_real_tools_and_keeps_original_argv(self):
        self.tools['docker']['path']='/usr/sbin/docker'
        argv=['/usr/bin/env','DOCKER_BUILDKIT=0','/usr/bin/docker','--host=unix:///FENCED/private.sock','build']
        value=self.call('seed',argv,1800)
        self.assertEqual(value['receipt']['argv'],argv);self.assertEqual(value['receipt']['executed_argv'][2],'/usr/sbin/docker')
        for bad in (['/usr/bin/env','GH_TOKEN=FENCED','/usr/bin/docker','info','x'],['docker','info']):
            with self.assertRaises(ValueError):self.call('bad',bad,10)


class PolicyAndDomainControls(unittest.TestCase):
    def setUp(self):
        self.MODEL=model_runtime();self.addCleanup(self.MODEL.close)
    def delegation(self):return dict(capability=copy.deepcopy(POLICY['stage_capability_proposals']['backend']))
    def test_changed_delegation_refuses_before_any_source_program_import(self):
        with patch.object(E,'load_pinned',side_effect=AssertionError('untrusted code import'))as load:
            with self.assertRaises(ValueError):E.admitted_inputs(Path('/FENCED/source'),b'{"FENCED":"changed"}','0'*64,{})
            load.assert_not_called()
    def test_predispatch_future_ids_never_create_executor_facts(self):
        d=self.delegation();context=dict(issuer='DELEGATED_CONTEXT_PROGRAM_V3',binding=dict(run=None,job=None,attempt=1))
        H=SimpleNamespace(validate_context=lambda *args:None)
        with patch.object(E.os,'pidfd_open',create=True,side_effect=AssertionError('no process observation before actual context'))as pidfd:
            with self.assertRaises(ValueError):E.Executor(d,context,POLICY,Path('/FENCED/source'),{},Path('/FENCED/work'),H)
            pidfd.assert_not_called()
    def test_new_budget_is_finite_unissued_and_preserves_held_command_caps(self):
        p=E.validate_policy(POLICY,self.delegation())
        self.assertEqual(p['stage_seconds'],7200);self.assertGreater(p['service_seconds'],1800)
        self.assertEqual(p['controller_seconds'],p['setup_seconds']+p['stage_seconds']+p['cleanup_seconds'])
        self.assertIsNone(p['Root_issuance'])
        for mutation in ('old1200','swap','memory','disk','builder','issued'):
            policy=copy.deepcopy(POLICY);d=self.delegation()
            if mutation=='old1200':policy['executor_current_v3']['service_seconds']=1200
            elif mutation=='swap':policy['image_domains']['daemon']['memory.swap.max']='max'
            elif mutation=='memory':policy['executor_current_v3']['minimum_available_bytes']=1
            elif mutation=='disk':policy['executor_current_v3']['minimum_disk_bytes']=1
            elif mutation=='builder':d['capability']['builder_memory_bytes']*=2
            else:policy['executor_current_v3']['Root_issuance']='FENCED_CANNOT_ISSUE'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):E.validate_policy(policy,d)
    def test_actual_systemctl_duration_formats_are_exact_and_finite(self):
        self.assertEqual(E.runtime_microseconds('2h 3min'),7380*1000000)
        self.assertEqual(E.runtime_microseconds('7380000000'),7380*1000000)
        for value in ('infinity','2h 0.5s','unknown','2h; command'):
            with self.subTest(value=value),self.assertRaises(ValueError):E.runtime_microseconds(value)
    def test_unsubmitted_output_is_never_cleaned_or_adopted(self):
        with tempfile.TemporaryDirectory(prefix='FENCED-foreign-output-')as directory:
            root=Path(directory);foreign=root/'storage.img';foreign.write_bytes(b'FENCED_FOREIGN')
            c=E.Controller(Path('/FENCED/source'),root,self.delegation(),{'nonce':NONCE},POLICY,None,1001,1001)
            with patch.object(c,'run',side_effect=AssertionError('foreign operation')),patch.object(c,'retain',side_effect=AssertionError('foreign retain')):
                result=c.cleanup()
            self.assertFalse(result['submitted']);self.assertEqual(foreign.read_bytes(),b'FENCED_FOREIGN')
    def test_service_vectors_bound_owner_daemon_and_both_temp_aliases(self):
        volume=Path('/FENCED/volume')
        for role in ('owner','daemon'):
            argv=E.service_args('/usr/bin/systemd-run',NONCE,role,POLICY,volume,['/usr/bin/python3','FENCED'],1001,1001)
            self.assertIn('--property=RuntimeMaxSec=7380s',argv);self.assertIn('--property=KillMode=control-group',argv)
            self.assertEqual(sum(a.startswith('--property=ReadWritePaths=')for a in argv),1)
            self.assertEqual(sum(a.startswith('--property=Environment=')for a in argv),1)
            self.assertIn('--property=MemorySwapMax=0',argv)
            self.assertFalse(any('LimitFSIZE'in a for a in argv))
            self.assertTrue(any(':/tmp'in a and ':/var/tmp'in a for a in argv))
            if role=='daemon':self.assertIn('--property=DelegateSubgroup=daemon',argv)
            else:self.assertIn('--property=NoNewPrivileges=yes',argv)
    def executor(self):
        e=E.Executor.__new__(E.Executor);e.maximum_command_seconds=1800;e.endpoint='unix:///FENCED/private.sock'
        e.tools={name:tool(name)for name in E.NAMES};e.pidfds={};e._facts=dict(docker_endpoint=e.endpoint,binding={'FENCED':'NOT_ROOT'})
        return e
    def test_private_endpoint_and_command_role_checked_before_spawn(self):
        e=self.executor()
        with patch.object(e,'live'),patch.object(E,'checked_tool',side_effect=lambda row:row['path']),patch.object(E.CommandEngine,'run',return_value={'FENCED':'NOT_EXECUTED'})as run:
            e.run('private',['/usr/bin/docker','--host='+e.endpoint,'info'],15)
            self.assertEqual(run.call_count,1)
            for argv,seconds in [(['/usr/bin/docker','info'],15),(['/usr/bin/docker','--host=unix:///var/run/docker.sock','info'],15),(['/usr/bin/env','DOCKER_BUILDKIT=0','/usr/bin/docker','--host=unix:///var/run/docker.sock','build'],1800),(['/usr/bin/systemctl','status'],15),(['/usr/bin/gpgconf','--version'],1801)]:
                with self.subTest(argv=argv),self.assertRaises((ValueError,IndexError)):e.run('refuse',argv,seconds)
            self.assertEqual(run.call_count,1)
    def test_facts_copy_cannot_redirect_private_endpoint(self):
        e=self.executor();facts=e.facts;facts['docker_endpoint']='unix:///var/run/docker.sock';facts['binding']['FENCED']='changed'
        self.assertEqual(e.facts['docker_endpoint'],e.endpoint);self.assertEqual(e.facts['binding']['FENCED'],'NOT_ROOT')
    def test_lost_pidfd_prevents_numeric_process_observation(self):
        e=self.executor();e.pidfds={'daemon':91};e.observation={'daemon_domain':{'pid':123}}
        with patch.object(E,'alive',return_value=False),patch.object(E,'kernel_domain',side_effect=AssertionError('no PID probe after lost custody'))as proc:
            with self.assertRaises(ValueError):e.live()
            proc.assert_not_called()
    def test_pidfd_custody_retained_before_fallible_service_checks(self):
        c=E.Controller(Path('/FENCED/source'),Path('/FENCED/output'),self.delegation(),{'nonce':NONCE},POLICY,None,1001,1001)
        c.tools={'systemd-run':tool('systemd-run'),'python3':tool('python3')}
        row=dict(ActiveState='active',MainPID='77',Description='current-owned-'+NONCE+'-owner',ControlGroup='/system.slice/'+E.unit(NONCE,'owner'),RuntimeMaxUSec=str(7380*1000000))
        with patch.object(c,'show_unit',side_effect=[{'LoadState':'not-found'},row]),patch.object(c,'run',return_value=b''),patch.object(E,'checked_tool',side_effect=lambda row:row['path']),patch.object(E.os,'pidfd_open',create=True,return_value=91),patch.object(E,'alive',return_value=True),patch.object(E,'kernel_domain',side_effect=ValueError('FENCED observation failure')):
            with self.assertRaises(ValueError):c.start('owner',['/usr/bin/python3','FENCED'])
        self.assertEqual(c.pidfds['owner'],91);self.assertTrue(c.units['owner']['submitted'])
    def test_services_are_clipped_to_common_controller_retirement_deadline(self):
        c=E.Controller(Path('/FENCED/source'),Path('/FENCED/output'),self.delegation(),{'nonce':NONCE},POLICY,None,1001,1001)
        c.cleanup_end=100;c.end=80;c.tools={'systemd-run':tool('systemd-run'),'python3':tool('python3')}
        group='/system.slice/'+E.unit(NONCE,'owner')
        row=dict(ActiveState='active',MainPID='77',Description='current-owned-'+NONCE+'-owner',ControlGroup=group,RuntimeMaxUSec='1min 29s')
        domain=dict(pid=77,starttime=11,cgroup=group,limits=POLICY['image_domains']['owner'],executable='/usr/bin/python3')
        with patch.object(c,'show_unit',side_effect=[{'LoadState':'not-found'},row]),patch.object(c,'run',return_value=b'')as run,patch.object(E,'checked_tool',side_effect=lambda row:row['path']),patch.object(E.os,'pidfd_open',create=True,return_value=91),patch.object(E,'alive',return_value=True),patch.object(E,'kernel_domain',return_value=domain),patch.object(E.time,'monotonic',return_value=1):
            c.start('owner',['/usr/bin/python3','FENCED'])
        self.assertIn('--property=RuntimeMaxSec=89s',run.call_args.args[0])
        self.assertEqual(c.units['owner']['runtime_seconds'],89)
    def test_unknown_service_cleanup_retains_storage_and_stops_owner_first(self):
        with tempfile.TemporaryDirectory(prefix='FENCED-executor-cleanup-')as directory:
            root=Path(directory);(root/'storage.img').write_bytes(b'FENCED_NOT_A_STORAGE_IMAGE')
            c=E.Controller(Path('/FENCED/source'),root,self.delegation(),{'nonce':NONCE},POLICY,None,1001,1001)
            c.output_created=True;c.storage_created=True;c.tool=lambda name:'/usr/bin/'+name
            calls=[]
            def stop(role):
                calls.append(role)
                if role=='owner':raise ValueError('FENCED lost ownership')
                return {'natural':True}
            with patch.object(c,'stop',side_effect=stop),patch.object(c,'run',side_effect=AssertionError('no storage mutation after uncertain custody')),patch.object(c,'retain')as retain:
                result=c.cleanup()
            self.assertEqual(calls,['owner','daemon']);self.assertTrue((root/'storage.img').exists());self.assertTrue(result['errors']);retain.assert_not_called()
    def test_known_empty_services_precede_retention_and_storage_release(self):
        with tempfile.TemporaryDirectory(prefix='FENCED-executor-cleanup-')as directory:
            root=Path(directory);(root/'storage.img').write_bytes(b'FENCED_NOT_A_STORAGE_IMAGE')
            c=E.Controller(Path('/FENCED/source'),root,self.delegation(),{'nonce':NONCE},POLICY,None,1001,1001)
            c.output_created=True;c.storage_created=True;c.tool=lambda name:'/usr/bin/'+name
            calls=[]
            with patch.object(c,'stop',side_effect=lambda role:calls.append('stop-'+role)or{'natural':True}),patch.object(c,'retain',side_effect=lambda:calls.append('retain')),patch.object(c,'run',return_value=b'{"loopdevices":[]}'):
                result=c.cleanup()
            self.assertEqual(calls,['stop-owner','stop-daemon','retain']);self.assertTrue(result['owned_storage_absent']);self.assertFalse(result['errors'])


class AdapterControls(unittest.TestCase):
    def setUp(self):
        self.MODEL=model_runtime();self.addCleanup(self.MODEL.close)
    def test_callback_hold_is_not_promoted_to_delegated_completion(self):
        with tempfile.TemporaryDirectory(prefix='FENCED-owner-adapter-')as directory:
            root=Path(directory);marker=root/'observation.json';marker.write_text('{}')
            context=dict(delegation_pin={'sha256':'FENCED_NOT_ROOT'},binding={'FENCED':'NOT_A_PROVIDER_CASE'})
            delegation=dict(programs={'owner':{'FENCED':'NOT_A_PROGRAM'}})
            launch=root/'launch.json';launch.write_bytes(E.encoded(dict(source_root='/FENCED/source',delegation=delegation,context=context,work=str(root),observation=str(marker),inputs={})))
            executor=SimpleNamespace(endpoint='unix:///FENCED/private.sock',facts={'FENCED':'NOT_NATIVE'},close=lambda:None)
            callback=SimpleNamespace(run_owned_current_v3=lambda **kwargs:dict(completed=False,binding=context['binding'],Root_final_acceptance=None))
            with patch.object(E.os,'getuid',return_value=1001),patch.object(E.os,'geteuid',return_value=1001),patch.object(E,'admitted_inputs',return_value=(delegation,None,POLICY,None)),patch.object(E,'Executor',return_value=executor),patch.object(E,'load_pinned',return_value=callback),patch.object(E.resource,'setrlimit'),patch.dict(E.os.environ,{},clear=True):
                code=E.owner_main(launch)
            self.assertEqual(code,2)
            result=json.loads((root/'owner-result.json').read_bytes());self.assertEqual(result['status'],'HOLD');self.assertIsNone(result['Root_final_acceptance'])


class ContextContractControls(unittest.TestCase):
    """MODEL context bodies; exact production program registry is checked separately."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='FENCED-context-contract-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.bodies={v:('FENCED MODEL context program '+str(v)).encode()for v in (3,4)}
        self.pins={v:E.pin(raw)for v,raw in self.bodies.items()}
    def fixture(self,version):
        member='context-'+str(version)+'.MODEL';(self.root/member).write_bytes(self.bodies[version])
        suffix=str(version);delegation_kind='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V'+suffix
        kind='DELEGATED_CURRENT_ONBOARDING_CONTEXT_V'+suffix;issuer='DELEGATED_CONTEXT_PROGRAM_V'+suffix
        d=dict(schema=version,kind=delegation_kind,issuer='Root',programs=dict(context=dict(member=member,**self.pins[version])),MODEL_ONLY=True)
        c=dict(schema=version,kind=kind,issuer=issuer,operation=E.CONTEXT_OPERATION,program_pin=self.pins[version],MODEL_ONLY=True)
        H=SimpleNamespace(__file__=str(self.root/member),OPERATION=E.CONTEXT_OPERATION,DELEGATION=delegation_kind,CONTEXT=kind,ISSUER=issuer)
        return d,c,H
    def test_exact_v3_and_v4_schema_issuer_program_body_are_selected_together(self):
        self.assertEqual(E.CONTEXT_PROGRAM_PINS,{3:dict(bytes=21460,sha256='efa5a2687ac1504ef565763ac0828dd6c98c593563df97b2f540ccf4e0de9d2b'),4:dict(bytes=43482,sha256='2d08f9572b3f5f89d3ebac2b32e6d41a00ff4929739c35780c7c96a1d3d3b21d')})
        with patch.object(E,'CONTEXT_PROGRAM_PINS',self.pins):
            for version in (3,4):
                d,c,H=self.fixture(version)
                self.assertEqual(E.context_contract(d,c,H,self.root),version)
    def test_schema_issuer_module_or_source_body_substitution_refuses(self):
        with patch.object(E,'CONTEXT_PROGRAM_PINS',self.pins):
            for mutation in ('delegation_schema','delegation_kind','context_schema','context_issuer','context_pin','module_api','module_path','body'):
                d,c,H=self.fixture(4)
                if mutation=='delegation_schema':d['schema']=3
                elif mutation=='delegation_kind':d['kind']='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V3'
                elif mutation=='context_schema':c['schema']=3
                elif mutation=='context_issuer':c['issuer']='DELEGATED_CONTEXT_PROGRAM_V3'
                elif mutation=='context_pin':c['program_pin']=self.pins[3]
                elif mutation=='module_api':H.ISSUER='DELEGATED_CONTEXT_PROGRAM_V3'
                elif mutation=='module_path':H.__file__='/FENCED_OTHER_CONTEXT'
                else:(self.root/d['programs']['context']['member']).write_bytes(b'FENCED CHANGED BODY')
                with self.subTest(mutation=mutation),self.assertRaises(ValueError):E.context_contract(d,c,H,self.root)
    def test_unknown_program_or_v4_as_v3_refuses_before_source_import(self):
        for mutation in ('unknown','v4_as_v3'):
            d,c,H=self.fixture(4)
            if mutation=='unknown':d['programs']['context']['sha256']='0'*64
            else:d['programs']['context']=dict(member='context.MODEL',**E.CONTEXT_PROGRAM_PINS[4]);d['schema']=3;d['kind']='ROOT_DELEGATED_CURRENT_ONBOARDING_PRIVATE_EXECUTION_V3'
            raw=E.encoded(d)
            with patch.object(E,'load_pinned',side_effect=AssertionError('no unselected context import'))as load:
                with self.subTest(mutation=mutation),self.assertRaises(ValueError):E.admitted_inputs(self.root,raw,E.pin(raw)['sha256'],c)
                load.assert_not_called()


class ActualRuntimeControls(unittest.TestCase):
    def test_real_memfd_positive_or_explicit_real_unsupported_runtime(self):
        observed=E.runtime_capabilities()
        self.assertFalse(observed['kernel_qualification'])
        if observed['missing']:
            with patch.object(E.subprocess,'Popen',side_effect=AssertionError('no actor on unsupported runtime'))as spawn:
                with self.assertRaises(E.UnsupportedRuntime)as error:E.stderr_buffer()
                self.assertTrue(all(name in str(error.exception)for name in observed['missing']))
                spawn.assert_not_called()
            print('ACTUAL_RUNTIME_API_RESULT '+json.dumps(observed,sort_keys=True),flush=True)
        else:
            self.assertTrue(E.require_runtime_capabilities()['api_exports_available'])
            with E.stderr_buffer()as stream:
                self.assertEqual(os.fstat(stream.fileno()).st_size,E.MAX_OUTPUT)
                stream.write(b'ACTUAL_LOCAL_MEMFD_ONLY');stream.seek(0)
                self.assertEqual(stream.read(len(b'ACTUAL_LOCAL_MEMFD_ONLY')),b'ACTUAL_LOCAL_MEMFD_ONLY')
                with self.assertRaises(OSError):os.ftruncate(stream.fileno(),E.MAX_OUTPUT+1)
                with self.assertRaises(OSError):os.ftruncate(stream.fileno(),E.MAX_OUTPUT-1)
            print('ACTUAL_RUNTIME_API_RESULT '+json.dumps(dict(observed,memfd_grow_shrink_refusal='PASS_LOCAL_MEMFD_ONLY'),sort_keys=True),flush=True)
    def test_missing_api_holds_before_command_domain_or_entry_operations(self):
        with patch.object(E.os,'memfd_create',None,create=True),patch.object(E,'load_pinned',side_effect=AssertionError('no import')),patch.object(E,'read_data',side_effect=AssertionError('no input operation')),patch.object(E,'probe_tools',side_effect=AssertionError('no tool observation')):
            engine=E.CommandEngine(None,{},Path('/FENCED'),1,1)
            controller=E.Controller.__new__(E.Controller)
            calls=(lambda:engine.run('refuse',['/usr/bin/docker'],15),
                   lambda:controller.preflight(),lambda:controller.start('owner',[]),
                   lambda:E.Executor({}, {}, {},None,{},None,None),
                   lambda:E.owner_main(Path('/FENCED')),lambda:E.controller_main(None))
            for call in calls:
                with self.subTest(call=call),self.assertRaisesRegex(E.UnsupportedRuntime,'os.memfd_create'):call()
    def test_missing_pidfd_and_seal_exports_are_explicit_hard_refusals(self):
        for module,name in ((E.os,'pidfd_open'),(E.fcntl,'F_ADD_SEALS'),(E.fcntl,'F_SEAL_GROW'),(E.fcntl,'F_SEAL_SHRINK')):
            with patch.object(module,name,None,create=True):
                with self.subTest(name=name),self.assertRaisesRegex(E.UnsupportedRuntime,name):E.require_runtime_capabilities()


class ResolverControls(unittest.TestCase):
    def test_usr_sbin_tool_and_finite_alias_observations(self):
        with tempfile.TemporaryDirectory(prefix='FENCED-tools-')as directory:
            root=Path(directory);(root/'usr/bin').mkdir(parents=True);(root/'usr/sbin').mkdir()
            binary=root/'usr/sbin/mke2fs';binary.write_bytes(b'FENCED_NOT_EXECUTED');binary.chmod(0o755)
            (root/'usr/sbin/mkfs.ext4').symlink_to('mke2fs')
            row=E.inspect_tool('/usr/sbin/mkfs.ext4',root=root,trusted_uid=os.getuid())
            self.assertEqual(row['path'],str(binary));self.assertEqual(row['sha256'],E.pin(binary.read_bytes())['sha256'])
            self.assertIn('chain',row);self.assertIn('target_chain',row)
            binary.chmod(0o777)
            with self.assertRaises(ValueError):E.inspect_tool('/usr/sbin/mkfs.ext4',root=root,trusted_uid=os.getuid())
    def test_invalid_present_candidate_holds_instead_of_path_fallback(self):
        def observer(path):
            if path.startswith('/usr/bin/'):raise ValueError('FENCED invalid alias')
            return dict(path=path)
        result=E.probe_tools(observer)
        self.assertEqual(result['missing_or_invalid'],list(E.NAMES))
    def test_preuse_tool_drift_refuses(self):
        row=tool('docker')
        with patch.object(E,'inspect_tool',return_value=dict(row,sha256='FENCED_CHANGED')):
            with self.assertRaises(ValueError):E.checked_tool(row)


if __name__=='__main__':unittest.main()
