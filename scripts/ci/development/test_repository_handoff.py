"""Causal source/custody/clock models and harmless host fixtures; no native actors."""
from contextlib import contextmanager
import ast
import copy
import hashlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

PATH = Path(__file__).with_name('repository_handoff.py')
spec = importlib.util.spec_from_file_location('repository_handoff',PATH)
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)


class SourceFixtures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='handoff-adapter-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        rows = {}
        for i in range(239):
            path = self.root/f'file-{i}.txt';path.write_bytes(b'bound');path.chmod(0o644)
            rows[path.name] = {'sha256':adapter.digest(b'bound'),'mode':0o644}
        self.path = self.root/'callbacks.py'
        self.path.write_text('def receiver(path, *, deadline):\n    return {"path":path,"sha256":"a"*64}\n')
        self.path.chmod(0o644)
        rows['callbacks.py'] = {'sha256':adapter.digest(self.path.read_bytes()),'mode':0o644}
        self.grant = {'source_files':rows,'callbacks':{'public_receiver':{
            'path':'callbacks.py','module':'captured_callbacks','qualname':'receiver'}}}
        self.sources = adapter.Sources(self.root,self.grant,time.monotonic()+10)
        self.module = self.sources.module('captured_callbacks','callbacks.py')
        registration=patch.dict(sys.modules,{'captured_callbacks':self.module})
        registration.start();self.addCleanup(registration.stop)

    def test_capture_and_callback_code_bound(self):
        self.sources.callback('public_receiver',self.module.receiver,time.monotonic()+10)

    def test_replace_same_bytes_refused(self):
        replacement = self.root/'replacement';replacement.write_bytes(self.path.read_bytes());replacement.chmod(0o644)
        os.replace(replacement,self.path)
        with self.assertRaises(adapter.Refused):self.sources.guard(time.monotonic()+10)

    def test_mode_drift_refused(self):
        self.path.chmod(0o755)
        with self.assertRaises(adapter.Refused):self.sources.guard(time.monotonic()+10)

    def test_symlink_and_hardlink_refused(self):
        self.path.unlink();self.path.symlink_to(self.root/'file-0.txt')
        with self.assertRaises(OSError):adapter.read(self.path,time.monotonic()+5)
        self.path.unlink();os.link(self.root/'file-0.txt',self.path)
        with self.assertRaises(adapter.Refused):adapter.read(self.path,time.monotonic()+5)

    def test_fifo_read_refuses_without_blocking(self):
        self.path.unlink();os.mkfifo(self.path)
        with self.assertRaises(adapter.Refused):adapter.read(self.path,time.monotonic()+5)

    def test_callback_code_substitution_refused(self):
        def counterfeit(path,*,deadline):return {'path':path,'sha256':'a'*64}
        counterfeit=types.FunctionType(counterfeit.__code__,{'__file__':str(self.path),
            '__name__':'captured_callbacks','__builtins__':__builtins__})
        counterfeit.__module__='captured_callbacks';counterfeit.__qualname__='receiver'
        with self.assertRaises(adapter.Refused):
            self.sources.callback('public_receiver',counterfeit,time.monotonic()+10)

    def test_exact_code_transplanted_into_foreign_globals_refused(self):
        foreign=types.FunctionType(self.module.receiver.__code__,{
            '__name__':'captured_callbacks','__file__':str(self.path),'__builtins__':__builtins__})
        foreign.__qualname__='receiver'
        with self.assertRaises(adapter.Refused):
            self.sources.callback('public_receiver',foreign,time.monotonic()+10)

    def test_callback_ungranted_project_module_global_refused(self):
        extra=types.ModuleType('foreign_project');extra.__file__=str(self.root/'ungranted.py')
        self.module.foreign=extra
        with self.assertRaises(adapter.Refused):
            self.sources.callback('public_receiver',self.module.receiver,time.monotonic()+10)

    def test_callback_foreign_function_global_refused(self):
        self.module.helper=lambda:None
        with self.assertRaises(adapter.Refused):
            self.sources.callback('public_receiver',self.module.receiver,time.monotonic()+10)

    def test_callback_after_source_drift_refused(self):
        self.path.write_text('raise AssertionError("untrusted source imported")\n')
        with self.assertRaises(adapter.Refused):
            self.sources.callback('public_receiver',self.module.receiver,time.monotonic()+10)

    def test_unknown_import_not_executed(self):
        self.sources.raw['callbacks.py']=b'import repository_handoff_ungranted_helper\n'
        with self.assertRaises(adapter.Refused):self.sources.module('bad','callbacks.py')

    def test_source_deadline_and_cancel(self):
        with self.assertRaises(adapter.Refused):self.sources.guard(time.monotonic()-1)
        with self.assertRaises(KeyboardInterrupt):self.sources.guard(time.monotonic()+5,lambda:True)


class DataFixtures(unittest.TestCase):
    def setUp(self):
        # File/IPC-only cases do not model issuer class authentication; tested below.
        state=patch.object(adapter,'authority_state',return_value=None)
        state.start();self.addCleanup(state.stop)
    def test_default_cli_blocks_without_actor(self):
        result=subprocess.run([sys.executable,'-I','-B',str(PATH)],capture_output=True,timeout=5)
        self.assertEqual(result.returncode,1)
        self.assertEqual(json.loads(result.stdout),{'status':'BLOCKED','error_code':'grant-refused','actors':'NOT RUN'})

    def test_duplicate_float_and_unknown_grant_refused_before_import(self):
        for raw in (b'{"a":1,"a":2}',b'{"a":1.0}',b'{"a":NaN}',b'[]',adapter.encoded({'unknown':True})):
            with self.subTest(raw=raw),self.assertRaises((adapter.Refused,KeyError)):
                adapter.preflight('/unused',raw,adapter.digest(raw),deadline=time.monotonic()+5)

    def test_wrong_external_pin_before_source(self):
        with patch.object(adapter,'Sources',side_effect=AssertionError('source touched')):
            with self.assertRaises(adapter.Refused):adapter.preflight('/unused',b'{}','a'*64,deadline=time.monotonic()+5)

    def test_complete_authority_only_issued_status_changes(self):
        candidate={'status':'PENDING','crypto':{'status':'PENDING','receipt':{'sha256':'a'*64}},
                   'files':{'actual.txt':{'sha256':'b'*64,'bytes':10}},'nonce':'c'*32}
        accepted=copy.deepcopy(candidate);accepted['status']=accepted['crypto']['status']='PASS'
        adapter.authority_matches(candidate,accepted)
        self.assertEqual(candidate['status'],'PENDING')
        for action in (lambda x:x['files']['actual.txt'].update(bytes=9),lambda x:x.update(extra='RAW'),
                       lambda x:x.update(status='PENDING'),lambda x:x['crypto'].update(status='PENDING'),
                       lambda x:x.update(nonce='d'*32),lambda x:x['crypto']['receipt'].update(sha256='e'*64)):
            value=copy.deepcopy(accepted);action(value)
            with self.assertRaises(adapter.Refused):adapter.authority_matches(candidate,value)

    def test_returned_callback_actual_file_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'returned.json';path.write_bytes(b'{"status":"PASS"}');path.chmod(0o600)
            sources=types.SimpleNamespace(callback=lambda *a:None)
            result=adapter.returned_file(sources,'public_receiver',lambda *a,**kw:{
                'path':str(path),'sha256':adapter.digest(path.read_bytes())},(),deadline=time.monotonic()+5)
            self.assertEqual(result[1],path.read_bytes())
            with self.assertRaises(adapter.Refused):adapter.returned_file(sources,'public_receiver',lambda *a,**kw:{
                'path':str(path),'sha256':'0'*64},(),deadline=time.monotonic()+5)
            path.chmod(0o666)
            with self.assertRaises(adapter.Refused):adapter.returned_file(sources,'public_receiver',lambda *a,**kw:{
                'path':str(path),'sha256':adapter.digest(path.read_bytes())},(),deadline=time.monotonic()+5)

    def test_harmless_process_pipe_and_socket_receiver(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'result.json'
            # Real finite process stdout pipe; no project executable or compiler.
            result=subprocess.run([sys.executable,'-I','-B','-c','print("receipt")'],capture_output=True,timeout=3)
            self.assertEqual(result.returncode,0)
            left,right=socket.socketpair()
            try:
                left.settimeout(1);right.settimeout(1);left.sendall(result.stdout)
                self.assertEqual(right.recv(64),b'receipt\n')
            finally:left.close();right.close()
            path.write_bytes(adapter.encoded({'status':'fixture-only'}));path.chmod(0o600)
            sources=types.SimpleNamespace(callback=lambda *a:None)
            raw=adapter.returned_file(sources,'public_receiver',lambda *a,**kw:{
                'path':str(path),'sha256':adapter.digest(path.read_bytes())},(),deadline=time.monotonic()+3)[1]
            self.assertEqual(adapter.decode(raw),{'status':'fixture-only'})


class CleanupFixtures(unittest.TestCase):
    def test_private_nested_cleanup_and_no_external_deletion(self):
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory);root=parent/'private';root.mkdir(mode=0o700);node=adapter.identity(root.stat())
            nested=root/'nested';nested.mkdir();(nested/'data').write_bytes(b'fixture')
            external=parent/'external';external.write_bytes(b'preserve')
            adapter.remove_private(root,node,time.monotonic()+5)
            self.assertFalse(root.exists());self.assertEqual(external.read_bytes(),b'preserve')

    def test_private_replacement_foreign_type_and_deadline_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory);root=parent/'private';root.mkdir(mode=0o700);node=adapter.identity(root.stat())
            root.rename(parent/'moved');root.mkdir(mode=0o700)
            with self.assertRaises(adapter.Refused):adapter.remove_private(root,node,time.monotonic()+5)
            root.rmdir();root=(parent/'moved');node=adapter.identity(root.stat())
            (root/'symlink').symlink_to(parent)
            with self.assertRaises(adapter.Refused):adapter.remove_private(root,node,time.monotonic()+5)
            (root/'symlink').unlink()
            with self.assertRaises(adapter.Refused):adapter.remove_private(root,node,time.monotonic()-1)

    def test_revocation_never_follows_public_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);external=root/'external';external.mkdir();receipt=external/'result.json';receipt.write_bytes(b'PASS')
            alias=root/'phase-public';alias.symlink_to(external,target_is_directory=True)
            with self.assertRaises(adapter.Refused):adapter.revoke_phase_receipt(alias)
            self.assertEqual(receipt.read_bytes(),b'PASS')

    def test_failed_status_recovery_has_no_phase_public(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory);session=adapter.Session(types.SimpleNamespace(),output/'unused',job_deadline=time.monotonic()+5)
            adapter.publish_status(output/'status',session.result)
            self.assertEqual(adapter.public_paths(output),[output/'status'])
            value=copy.deepcopy(session.result);value.update(status='PASS',callback_entered=True,
                initial_exit_code=0,input_acceptance='PASS',restage='PASS',cleanup='PASS',
                source_commit='a'*40,run_id='1',run_attempt='1',execution_grant_sha256='b'*64)
            value['initial_invocation_sha256']='c'*64
            value['actor_contract_sha256']='d'*64
            adapter.publish_status(output/'status',value,replace=True)
            self.assertEqual(adapter.public_paths(output),[output/'status',output/'phase-public'])
            value.update(status='FAIL',error_code='cleanup-failed')
            adapter.publish_status(output/'status',value,replace=True)
            self.assertEqual(adapter.public_paths(output),[output/'status'])

    def test_actor_contract_status_binding_and_missing_success_refusal(self):
        source=types.SimpleNamespace(grant={'actor_contract_sha256':'d'*64})
        value=adapter.Session(source,'/unused',job_deadline=time.monotonic()+5).result
        self.assertEqual(adapter.status_projection(value)['actor_contract_sha256'],'d'*64)
        for changed in (None,True,'unknown','/private/actor'):
            poisoned=copy.deepcopy(value);poisoned['actor_contract_sha256']=changed
            if changed is None:poisoned['status']='PASS'
            with self.assertRaises(adapter.Refused):adapter.status_projection(poisoned)

    def test_finite_status_privacy_and_boolean_code(self):
        value=adapter.Session(types.SimpleNamespace(),'/unused',job_deadline=time.monotonic()+5).result
        for key,item in [('raw_error','SECRET'),('error_code','/private/path'),('initial_exit_code',True),
                         ('hardware_validation','PASS'),('selected_for_release',True),('cancelled',1)]:
            wrong={**value,key:item}
            with self.assertRaises(adapter.Refused):adapter.status_projection(wrong)


class WiringModels(unittest.TestCase):
    """Clock/one-use/restore causal models, not runtime source or authority admission."""
    def model(self, *, exit_code=0, broad_seconds=2000, capture_error=None, close_error=None, late_cancel=False):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        root=Path(temporary.name);events=[];clock=[1000]
        grant={'source_commit':'a'*40,'run_id':'1','run_attempt':'1','recipe_source_commit':'b'*40,
            'source_files':{'scripts/port/repository-client-native/entry.py':{'sha256':'c'*64},
                            'scripts/port/repository-client-phase-stage/entry.py':{'sha256':'d'*64}},
            'maps':{name:{'path':name+'.json','sha256':'e'*64} for name in ('runtime','collector','phase')}}
        runtime_contract={'cli_sha256':'f'*64,'endpoint_identity':[], 'env':{}}
        grant['actor_contract_sha256']=adapter.digest(adapter.encoded(runtime_contract))
        grant['initial_invocation_sha256']=adapter.digest(adapter.encoded({'argv':['integration'],'output':str(root/'output')}))
        raw={name+'.json':b'{}' for name in ('runtime','collector','phase')}
        sources=types.SimpleNamespace(root=root,grant=grant,raw=raw,grant_pin='c'*64,
            guard=lambda *a:events.append('guard'),callback=lambda role,*a:events.append('callback-'+role),
            source_graph=lambda *a,**kw:events.append('graph-source-check'))
        with patch.object(adapter.time,'monotonic',return_value=clock[0]):
            session=adapter.Session(sources,root/'output',job_deadline=10000)
        @contextmanager
        def interpose(*args):
            events.append('interpose')
            try:yield
            finally:events.append('restore')
        def broad(controller):events.append('broad');clock[0]+=broad_seconds
        def native(argv,*,integration_consumers):
            events.append('native-main')
            try:integration_consumers(types.SimpleNamespace())
            except BaseException:events.append('native-caught');return 1
            events.append('original-final-cleanup');clock[0]+=20
            return exit_code
        @contextmanager
        def originals(*args,**kwargs):
            events.append('original-source-before')
            try:yield {'native_arm':types.SimpleNamespace(main=native),'integration':types.SimpleNamespace(),
                'repository_projection':types.SimpleNamespace(inventory=types.ModuleType('inventory')),
                'desktop_projection':types.SimpleNamespace(policy=types.ModuleType('policy'))}
            finally:events.append('original-source-after')
        def close():
            events.append('transport-close')
            if close_error:raise close_error
        @contextmanager
        def defer():yield
        collector={'common':types.SimpleNamespace(defer_cancellation=defer)}
        def dependencies(*args,**kwargs):return ({}, {}) if kwargs.get('phase') else (collector,{})
        service={'pending':types.SimpleNamespace(interpose=interpose),'transport':types.SimpleNamespace(close=close)}
        entry=types.SimpleNamespace(authenticated=lambda *a,**kw:({},{}),dependency_entry=dependencies,
            services=lambda *a,**kw:service,original_modules=originals)
        sources.module=lambda *a:entry
        def pending(*args):
            events.append('pending');session.end=min(session.job_deadline,clock[0]+1200);session.work_end=session.end-60
            session.result['callback_entered']=True;session.pending_capture={}
            if capture_error:
                with session.step('capture-failed'):raise capture_error
        def terminal(*args):
            session.tick();events.append('terminal')
            adapter.need(type(args[0]) is int and args[0]==0,'initial-failed')
            session.result.update(input_acceptance='PASS',restage='PASS')
        callbacks={'existing_consumers':broad,'public_receiver':lambda *a:None,'authority_provider':lambda *a:None}
        session.pending_consumer=pending;session.terminal_consumer=terminal
        env={'GITHUB_SHA':grant['source_commit'],'GITHUB_RUN_ID':'1','GITHUB_RUN_ATTEMPT':'1'}
        with patch.object(adapter.time,'monotonic',side_effect=lambda:clock[0]),patch.dict(os.environ,env), \
             patch.object(adapter,'authority_state',return_value=None), \
             patch.object(adapter,'revoke_phase_receipt') as revoke:
            if late_cancel:
                original_publish=adapter.publish_status
                def publish(*args,**kwargs):
                    original_publish(*args,**kwargs)
                    if not kwargs.get('replace'):raise KeyboardInterrupt()
                with patch.object(adapter,'publish_status',side_effect=publish):
                    result=session.execute(['integration'],callbacks,{'cli_sha256':'f'*64,'endpoint_identity':[], 'env':{}})
            else:result=session.execute(['integration'],callbacks,{'cli_sha256':'f'*64,'endpoint_identity':[], 'env':{}})
        return session,result,events,clock

    def test_existing_consumers_precede_one_fixed_cutoff_and_native_return(self):
        session,result,events,clock=self.model()
        self.assertEqual(result['status'],'PASS');self.assertEqual(events.count('native-main'),1)
        self.assertLess(events.index('broad'),events.index('pending'))
        self.assertEqual(session.end,4200);self.assertEqual(session.work_end,4140)
        self.assertLess(events.index('original-final-cleanup'),events.index('terminal'))
        self.assertLess(events.index('terminal'),events.index('original-source-after'))
        self.assertIn('restore',events);self.assertIn('transport-close',events)
        with self.assertRaises(adapter.Refused):session.execute(['integration'],{}, {})

    def test_original_nonzero_or_boolean_exit_refuses(self):
        for value in (1,True):
            session,result,events,_=self.model(exit_code=value)
            self.assertEqual(result['status'],'FAIL');self.assertEqual(result['cleanup'],'PASS')
            self.assertEqual(result['error_code'],'initial-failed');self.assertIn('restore',events)

    def test_capture_first_failure_survives_original_return_and_cleanup(self):
        session,result,events,_=self.model(capture_error=ValueError('private/raw/error'))
        self.assertEqual(result['status'],'FAIL');self.assertEqual(result['error_code'],'capture-failed')
        self.assertEqual(result['initial_exit_code'],1);self.assertIn('restore',events)
        self.assertNotIn('private/raw/error',json.dumps(result))

    def test_cleanup_failure_prevents_success_and_retains_first_failure(self):
        session,result,_,_=self.model(close_error=OSError('PRIVATE'))
        self.assertEqual((result['status'],result['cleanup'],result['error_code']),('FAIL','FAIL','cleanup-failed'))
        _,result,_,_=self.model(capture_error=ValueError('first'),close_error=OSError('later'))
        self.assertEqual(result['error_code'],'capture-failed')
        self.assertFalse(session.private.exists())

    def test_late_publication_cancel_rewrites_fail(self):
        session,result,_,_=self.model(late_cancel=True)
        self.assertEqual(result['status'],'FAIL');self.assertTrue(result['cancelled'])
        self.assertEqual(adapter.decode((session.output/'status/result.json').read_bytes())['status'],'FAIL')

    def test_sticky_deadline_no_renewal(self):
        session,result,_,clock=self.model()
        clock[0]=session.end+1
        with patch.object(adapter.time,'monotonic',side_effect=lambda:clock[0]),self.assertRaises(adapter.Refused):session.tick()


class TerminalModels(unittest.TestCase):
    """Cross-receipt wiring using modeled gates; no cryptographic/native acceptance."""
    def run_case(self,*,mutate_issued=False,late_cancel=False,poison_capture=False):
        state=patch.object(adapter,'authority_state',return_value=None)
        state.start();self.addCleanup(state.stop)
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        root=Path(temporary.name);private=root/'private';private.mkdir(mode=0o700)
        output=root/'output';output.mkdir(mode=0o700)
        external=root/'external.json';first=adapter.encoded({'status':'PASS','bound':'initial'})
        external.write_bytes(first);external.chmod(0o600)
        source=types.SimpleNamespace(root=root,grant={'policy_path':'policy','license_path':'license'},
            raw={'policy':b'{}','license':b'MIT'},guard=lambda *a:None,callback=lambda *a:None)
        events=[];cancel=[False]
        session=adapter.Session(source,output,job_deadline=time.monotonic()+1200,cancelled=lambda:cancel[0])
        session.end=session.job_deadline;session.work_end=session.end-60;session.private=private
        session.pending_capture={};session.controller=object();session.job={};session.supervise=object()
        session.collected={'components':{'status':'PASS'}}
        (private/'pending/custody').mkdir(parents=True)
        (private/'pending/custody/launch.json').write_bytes(b'{}')
        capture=types.SimpleNamespace(encoded=adapter.encoded,decode=adapter.decode,
            read=lambda path,**kw:adapter.read(path,session.work_end)[0],
            write_atomic=lambda path,raw,**kw:Path(path).write_bytes(raw))
        candidate={'status':'PENDING','crypto':{'status':'PENDING','request':{'sha256':'a'*64},'receipt':{'sha256':'b'*64}},
                   'files':{'terminal/public-acceptance.json':{'sha256':adapter.digest(first),'bytes':len(first)}}}
        def stage(captured,receipt,controller,destination,**kwargs):
            events.append('terminal-inputs')
            external.write_bytes(adapter.encoded({'status':'FAIL','raw_text':'private'}))
            raw=kwargs['public_acceptance_path'].read_bytes()
            if poison_capture:raw=adapter.encoded({'status':'PASS','bound':'mutated'})
            return {'records':{'public_acceptance':adapter.decode(raw)},'files':{
                'terminal/public-acceptance.json':{'sha256':adapter.digest(raw),'bytes':len(raw)}}}
        def crypto(*args,**kwargs):
            events.append('crypto');target=Path(args[4]);target.mkdir()
            (target/'result.json').write_bytes(b'{"status":"PASS"}')
            self.assertNotEqual(target,kwargs['crypto_root'])
        def seal(*args,**kwargs):events.append('independent-seal');return {'status':'PASS-input-acceptance'}
        def restage(*args,**kwargs):
            events.append('independent-restage');destination=Path(args[11]);destination.mkdir(mode=0o700)
            value={'status':'PASS','cleanup':{'status':'PASS'},'public_files':{}}
            (destination/'result.json').write_bytes(adapter.encoded(value));return value
        broker=types.SimpleNamespace(capture_file_map=lambda *a,**kw:{},crypto_request=lambda *a,**kw:{
            'files':dict.fromkeys((str(i) for i in range(128)),{}),'signed_objects':[{}]*15},
            attest_crypto=crypto,terminal_inputs=stage,authority_candidate=lambda *a,**kw:{
                'status':'PENDING-external-authority','file_count':794,'authority':copy.deepcopy(candidate)},
            seal_terminal=seal,restage=restage)
        pending=types.SimpleNamespace(checkpoints=types.SimpleNamespace(records=[]))
        def receiver(*args,**kwargs):return {'path':str(external),'sha256':adapter.digest(first)}
        def issuer(path,pin,input_root,*,deadline):
            events.append('external-issuer');raw=path.read_bytes();self.assertEqual(adapter.digest(raw),pin)
            value=adapter.decode(raw);value['status']=value['crypto']['status']='PASS'
            if mutate_issued:value['files']['terminal/public-acceptance.json']['bytes']+=1
            issued=private/'issued.json';issued.write_bytes(adapter.encoded(value));issued.chmod(0o600)
            if late_cancel:cancel[0]=True
            return {'path':str(issued),'sha256':adapter.digest(issued.read_bytes())}
        collector={'common':types.SimpleNamespace(mapped=lambda *a:events.append('exact-public-map'))}
        callbacks={'public_receiver':receiver,'authority_provider':issuer}
        try:
            session.terminal_consumer(0,{'pending':pending},{'broker':broker,'capture':capture},collector,{},callbacks)
        except BaseException as error:return session,events,error,external
        return session,events,None,external

    def test_external_file_mutation_does_not_change_captured_public_acceptance(self):
        session,events,error,external=self.run_case()
        self.assertIsNone(error)
        self.assertEqual(session.result['restage'],'PASS')
        self.assertEqual(adapter.decode(external.read_bytes())['status'],'FAIL')
        self.assertLess(events.index('external-issuer'),events.index('independent-seal'))
        self.assertLess(events.index('independent-seal'),events.index('independent-restage'))
        self.assertIn('exact-public-map',events)

    def test_full_authority_data_mutation_refuses_before_phase(self):
        session,events,error,_=self.run_case(mutate_issued=True)
        self.assertIsInstance(error,adapter.Refused);self.assertNotIn('independent-seal',events)
        self.assertEqual(session.result['error_code'],'authority-failed')

    def test_owned_public_capture_mutation_is_not_new_authority(self):
        session,events,error,_=self.run_case(poison_capture=True)
        self.assertIsInstance(error,adapter.Refused);self.assertNotIn('external-issuer',events)

    def test_cancel_after_issuer_refuses_acceptance(self):
        session,events,error,_=self.run_case(late_cancel=True)
        self.assertIsInstance(error,KeyboardInterrupt);self.assertNotIn('independent-seal',events)


class InterfaceFixtures(unittest.TestCase):
    def test_exact_existing_broker_api_signatures_accept_adapter_call_shapes(self):
        source=Path(__file__).resolve().parents[2]/'port/repository-native-handoff/broker.py'
        tree=ast.parse(source.read_bytes());namespace={}
        functions=[]
        for node in tree.body:
            if isinstance(node,ast.FunctionDef):
                node.body=[ast.Pass()];node.decorator_list=[];node.returns=None;functions.append(node)
        exec(compile(ast.fix_missing_locations(ast.Module(body=functions,type_ignores=[])),str(source),'exec'),namespace)
        current=ast.parse(PATH.read_bytes())
        tested=[]
        for node in ast.walk(current):
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name) and node.func.value.id=='broker':
                self.assertIn(node.func.attr,namespace)
                args=[None for item in node.args];keywords={item.arg:None for item in node.keywords}
                self.assertNotIn(None,keywords)
                inspect.signature(namespace[node.func.attr]).bind(*args,**keywords)
                tested.append(node.func.attr)
        self.assertEqual(len(tested),12)


class AuthorityStateFixtures(unittest.TestCase):
    """Real captured method/class/state controls; no verifier/authority actor."""
    def setUp(self):
        SourceFixtures.setUp(self)
        self.path.write_text('class RootCallbacks:\n'
            '    def __init__(self, binding): self.binding = binding\n'
            '    def handoff_binding(self): return dict(self.binding)\n'
            '    def receiver(self, path, *, deadline): return {"path":path,"sha256":"a"*64}\n')
        grant=copy.deepcopy(self.grant)
        grant['source_files']['callbacks.py']['sha256']=adapter.digest(self.path.read_bytes())
        grant['callbacks']['public_receiver']['qualname']='RootCallbacks.receiver'
        grant.update(source_commit='a'*40,run_id='1',run_attempt='1',actor_contract_sha256='b'*64)
        grant['initial_invocation_sha256']='d'*64
        self.sources=adapter.Sources(self.root,grant,time.monotonic()+5);self.sources.grant_pin='c'*64
        self.module=self.sources.module('captured_callbacks','callbacks.py')
        sys.modules['captured_callbacks']=self.module
        self.binding={'schema_version':1,'purpose':'root-repository-handoff-live-binding',
            'source_commit':'a'*40,'run_id':'1','run_attempt':'1','actor_contract_sha256':'b'*64,
            'initial_invocation_sha256':'d'*64,
            'execution_grant_sha256':'c'*64,'integration_lock_sha256':adapter.INITIAL,
            'policy_sha256':adapter.POLICY,'license_sha256':adapter.LICENSE,'supported_models':[]}
        self.instance=self.module.RootCallbacks(copy.deepcopy(self.binding))

    def test_actual_method_class_and_live_data_binding(self):
        self.sources.callback('public_receiver',self.instance.receiver,time.monotonic()+5)
        adapter.authority_state(self.sources,self.instance.receiver,time.monotonic()+5)

    def test_foreign_self_and_subclass_refused(self):
        for instance in (types.SimpleNamespace(binding=self.binding),
                         type('Foreign',(self.module.RootCallbacks,),{})(self.binding)):
            callback=types.MethodType(self.module.RootCallbacks.receiver,instance)
            with self.assertRaises(adapter.Refused):self.sources.callback('public_receiver',callback,time.monotonic()+5)

    def test_contradictory_missing_unknown_self_state_refused(self):
        for action in (lambda x:x.update(run_id='2'),lambda x:x.pop('actor_contract_sha256'),
                       lambda x:x.update(extra='RAW'),lambda x:x.update(supported_models=['Mac']),
                       lambda x:x.update(schema_version=True)):
            instance=self.module.RootCallbacks(copy.deepcopy(self.binding));action(instance.binding)
            with self.assertRaises(adapter.Refused):adapter.authority_state(self.sources,instance.receiver,time.monotonic()+5)

    def test_injected_verifier_function_refused(self):
        self.instance.verifier=lambda *a:{'status':'PASS'}
        with self.assertRaises(adapter.Refused):adapter.authority_state(self.sources,self.instance.receiver,time.monotonic()+5)

    def test_substituted_class_constructor_code_refused(self):
        self.module.RootCallbacks.__init__=lambda *a:None
        with self.assertRaises(adapter.Refused):self.sources.callback('public_receiver',self.instance.receiver,time.monotonic()+5)

    def test_exact_code_transplanted_into_foreign_globals_refused(self):
        foreign=types.FunctionType(self.module.RootCallbacks.receiver.__code__,{
            '__name__':'captured_callbacks','__file__':str(self.path),'__builtins__':__builtins__})
        foreign.__qualname__='RootCallbacks.receiver'
        with self.assertRaises(adapter.Refused):self.sources.callback('public_receiver',foreign,time.monotonic()+5)


class InitialInvocationFixtures(unittest.TestCase):
    def test_path_hash_extra_arg_and_output_substitution_refuse_before_actor(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            argv=['integration','--inputs','/reviewed/inputs','--inputs-sha256','a'*64,
                  '--recipes','/reviewed/recipes','--recipes-sha256','b'*64,
                  '--integration','/reviewed/initial','--integration-sha256','c'*64]
            contract={'cli_sha256':'d'*64,'endpoint_identity':[],'env':{}}
            granted_output=root/'output'
            grant={'initial_invocation_sha256':adapter.digest(adapter.encoded({'argv':argv,'output':str(granted_output)})),
                   'actor_contract_sha256':adapter.digest(adapter.encoded(contract))}
            cases=[]
            for index in (2,4,6,8,10,12):
                changed=list(argv);changed[index]='changed';cases.append((changed,granted_output))
            cases += [(argv+['--probe'],granted_output),(argv,root/'foreign-output')]
            for changed,output in cases:
                source=types.SimpleNamespace(grant=grant,callback=lambda *a: (_ for _ in ()).throw(AssertionError('callback touched')))
                session=adapter.Session(source,output,job_deadline=time.monotonic()+5)
                with self.assertRaises(adapter.Refused):session.execute(changed,{},contract)
                self.assertFalse(output.exists())

class CapturedGraphFixtures(unittest.TestCase):
    """Actual captured 243-file import/slot graph; modeled grant, no actors."""
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='handoff-actual-graph-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root=Path(cls.temporary.name);project=PATH.parents[3]
        # Explicit source-only fixture closure; no unregistered packet-map read.
        names=set(json.loads((project/'scripts/ci/integration.lock.json').read_bytes())['source_files'])
        names.update('''
.github/workflows/native-arm-development.yml
artifacts/reviews/repository-native-handoff-implementation-20261012/root-policy-selection/generic-policy.json
manifests/reviewed/ksmctl.json
packages/tools/cachy-asahi-ksmctl/.SRCINFO
packages/tools/cachy-asahi-ksmctl/LICENSE
packages/tools/cachy-asahi-ksmctl/NOTICE
packages/tools/cachy-asahi-ksmctl/PKGBUILD
packages/tools/cachy-asahi-ksmctl/README.md
packages/tools/cachy-asahi-ksmctl/adaptation.patch
packages/tools/cachy-asahi-ksmctl/cachy-asahi-ksmctl
packages/tools/cachy-asahi-ksmctl/check-source.py
packages/tools/cachy-asahi-ksmctl/management-policy.md
packages/tools/cachy-asahi-ksmctl/native-stage.md
packages/tools/cachy-asahi-ksmctl/policy.py
packages/tools/cachy-asahi-ksmctl/source-provenance.json
packages/tools/cachy-asahi-ksmctl/test_ksmctl.py
packages/tools/cachy-asahi-ksmctl/test_policy.py
packages/tools/cachy-asahi-ksmctl/upstream-ksmctl
scripts/ci/development/base_stages.py
scripts/ci/development/common.py
scripts/ci/development/controller.py
scripts/ci/development/initial_artifacts.py
scripts/ci/development/packet.py
scripts/ci/development/repository_authority.py
scripts/ci/development/repository_handoff.py
scripts/ci/development/test_base_stages.py
scripts/ci/development/test_common.py
scripts/ci/development/test_controller.py
scripts/ci/development/test_initial_artifacts.py
scripts/ci/development/test_packet.py
scripts/ci/development/test_repository_authority.py
scripts/ci/development/test_repository_handoff.py
scripts/ci/development/test_virtual_stage.py
scripts/ci/development/virtual_stage.py
scripts/ci/integration.lock.json
scripts/client/client.py
scripts/client/stage.py
scripts/client/test_client.py
scripts/client/test_stage.py
scripts/experiments/arm_c01.py
scripts/experiments/corpus.py
scripts/experiments/stage.lock.json
scripts/experiments/stage.py
scripts/experiments/test_arm_c01.py
scripts/experiments/test_corpus.py
scripts/experiments/test_stage.py
scripts/port/refreshed-desktop/proposed-builder-inventory.lock
scripts/port/repository-client-native/base.py
scripts/port/repository-client-native/common.py
scripts/port/repository-client-native/crypto.py
scripts/port/repository-client-native/entry.py
scripts/port/repository-client-native/orchestrator.py
scripts/port/repository-client-native/provenance.py
scripts/port/repository-client-native/review.lock.json
scripts/port/repository-client-native/source-map.json
scripts/port/repository-client-native/worker.py
scripts/port/repository-client-phase-stage/adapter.py
scripts/port/repository-client-phase-stage/dependencies.py
scripts/port/repository-client-phase-stage/entry.py
scripts/port/repository-client-phase-stage/gate.py
scripts/port/repository-client-phase-stage/phases.py
scripts/port/repository-client-phase-stage/review.lock.json
scripts/port/repository-client-phase-stage/source-map.json
scripts/port/repository-client-stage/adapter.py
scripts/port/repository-client-stage/gate.py
scripts/port/repository-native-handoff/broker.py
scripts/port/repository-native-handoff/capture.py
scripts/port/repository-native-handoff/entry.py
scripts/port/repository-native-handoff/launch.py
scripts/port/repository-native-handoff/producer.py
scripts/port/repository-native-handoff/source-map.json
scripts/port/repository-native-handoff/supervisor.py
scripts/port/repository-native-handoff/transport.py
scripts/virtual/audit_tooling.py
scripts/virtual/common.py
scripts/virtual/controller.py
scripts/virtual/gbm_probe.c
scripts/virtual/guest.py
scripts/virtual/prepare.py
scripts/virtual/run.py
scripts/virtual/test_controller.py
scripts/virtual/test_virtual.py
scripts/virtual/tooling-audit.json
scripts/virtual/tooling.lock.json
'''.split())
        rows={}
        for name in sorted(names):
            raw=(project/name).read_bytes();destination=cls.root/name
            destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(raw)
            mode=(project/name).stat().st_mode&0o777;destination.chmod(mode)
            rows[name]={'sha256':adapter.digest(raw),'mode':mode}
        cls.a=types.ModuleType('handoff_actual_graph');cls.a.__file__=str(cls.root/'scripts/ci/development/repository_handoff.py')
        cls.registration=patch.dict(sys.modules,{cls.a.__name__:cls.a});cls.registration.start()
        cls.addClassCleanup(cls.registration.stop)
        exec(compile((cls.root/'scripts/ci/development/repository_handoff.py').read_bytes(),cls.a.__file__,'exec'),cls.a.__dict__)
        cls.deadline=time.monotonic()+600
        actor={'cli_sha256':'b'*64,'endpoint_identity':{'fixture':'NO ACTOR'},'env':{}}
        cls.grant={'schema_version':1,'purpose':'reviewed-same-job-handoff-execution',
            'source_peer_preflight':'PASS','development_only':True,'added_seconds':1200,
            'source_commit':'a'*40,'recipe_source_commit':'c'*40,'run_id':'123','run_attempt':'2',
            'source_files':rows,'maps':{},'callbacks':{},
            'policy_path':'artifacts/reviews/repository-native-handoff-implementation-20261012/root-policy-selection/generic-policy.json',
            'license_path':'LICENSE','actor_contract_sha256':adapter.digest(adapter.encoded(actor)),
            'initial_invocation_sha256':adapter.digest(adapter.encoded({'argv':['SOURCE-ONLY-NO-ACTOR'],
                                                                       'output':str(cls.root/'output')}))}
        for role,prefix in cls.a.PREFIXES.items():
            path=prefix+'/source-map.json';cls.grant['maps'][role]={'path':path,'sha256':rows[path]['sha256']}
        cls.grant['callbacks']['existing_consumers']={'path':'scripts/ci/development/repository_handoff.py',
            'module':cls.a.__name__,'qualname':'main'}
        for role in ('public_receiver','authority_provider'):
            cls.grant['callbacks'][role]={'path':'scripts/ci/development/repository_authority.py',
                'module':'handoff_actual_authority','qualname':'RootCallbacks.'+role}
        raw=cls.a.encoded(cls.grant);pin=cls.a.digest(raw)
        cls.sources=cls.a.preflight(cls.root,raw,pin,deadline=cls.deadline)
        cls.entry=cls.sources.module('handoff_actual_entry',cls.a.PREFIXES['runtime']+'/entry.py')
        cls.runtime,_=cls.entry.authenticated(cls.root/cls.grant['maps']['runtime']['path'],
            cls.grant['maps']['runtime']['sha256'],deadline=cls.deadline,source_root=cls.root/cls.a.PREFIXES['runtime'])
        def load(role):
            prefix=cls.a.PREFIXES[role]
            return cls.entry.dependency_entry(cls.root,prefix+'/entry.py',rows[prefix+'/entry.py']['sha256'],
                cls.grant['maps'][role]['path'],cls.grant['maps'][role]['sha256'],deadline=cls.deadline,phase=role=='phase')[0]
        cls.collector=load('collector');cls.phase=load('phase')
        cls.session=cls.a.Session(cls.sources,cls.root/'output',job_deadline=cls.deadline)
        cls.session.used=True  # Inert registration model; Session.execute is never called.
        cls.session.source_graph={'entry':cls.entry,'runtime':cls.runtime,'collector':cls.collector,
            'phase':cls.phase,'original':{},'original_aliases':{}}
        cls.sources.source_graph(cls.session,capture=True)
        cls.partial_observation=cls.sources.graph_observation
        with cls.entry.original_modules(cls.root,cls.root/'scripts/ci/integration.lock.json',cls.a.INITIAL,
            deadline=cls.deadline,verification_deadline=cls.deadline) as original:
            cls.original=original
            cls.session.source_graph.update(original=original,original_aliases={
                'repository_projection.inventory':original['repository_projection'].inventory,
                'desktop_projection.policy':original['desktop_projection'].policy})
            cls.sources.source_graph(cls.session,capture=True)
        cls.authority=cls.sources.module('handoff_actual_authority','scripts/ci/development/repository_authority.py')
        cls.authority_registration=patch.dict(sys.modules,{cls.authority.__name__:cls.authority})
        cls.authority_registration.start();cls.addClassCleanup(cls.authority_registration.stop)
        with patch.dict(os.environ,GITHUB_SHA=cls.grant['source_commit'],GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='2'):
            cls.callback=cls.authority.RootCallbacks(cls.root,raw,pin,cls.a.encoded(actor),cls.root/'output',
                deadline=cls.deadline,session=cls.session)

    def check(self):
        with patch.dict(os.environ,GITHUB_SHA=self.grant['source_commit'],GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='2'):
            self.a.authority_state(self.sources,self.callback.public_receiver,self.deadline)
        self.assertFalse((self.root/'output').exists())

    def refuse(self):
        with self.assertRaises(self.a.Refused):self.check()

    def test_actual_slots_and_full_source_namespaces_accept_inert_state(self):
        self.check()
        with patch.dict(os.environ,GITHUB_SHA=self.grant['source_commit'],GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='2'):
            self.assertEqual(len(self.callback.handoff_binding()),12)
        self.assertEqual(len(self.sources.raw),243)
        self.assertIs(self.sources.source_graph(self.session)['scripts/ci/integration.py'],self.original['integration'])

    def test_unobserved_graph_refuses_before_authority(self):
        with patch.object(self.sources,'graph_observation',None):self.refuse()

    def test_equal_code_foreign_namespace_refused(self):
        old=self.runtime['broker'];foreign=types.ModuleType(old.__name__);foreign.__dict__.update(old.__dict__)
        with patch.dict(self.runtime,broker=foreign):self.refuse()

    def test_loader_function_closure_substitution_refused(self):
        old=self.phase['dependencies'].load_collector
        cells=[types.CellType(cell.cell_contents) for cell in old.__closure__]
        foreign=types.FunctionType(old.__code__,old.__globals__,old.__name__,old.__defaults__,tuple(cells))
        foreign.__qualname__=old.__qualname__;foreign.__kwdefaults__=old.__kwdefaults__
        with patch.object(self.phase['dependencies'],'load_collector',foreign):self.refuse()

    def test_second_capture_refuses_poisoned_existing_dependency_graph(self):
        old=self.phase['dependencies'].load_collector
        foreign=types.FunctionType(old.__code__,old.__globals__,old.__name__,old.__defaults__,
            tuple(types.CellType(cell.cell_contents) for cell in old.__closure__))
        foreign.__qualname__=old.__qualname__;foreign.__kwdefaults__=old.__kwdefaults__
        with patch.object(self.sources,'graph_observation',self.partial_observation), \
             patch.object(self.phase['dependencies'],'load_collector',foreign):
            with self.assertRaises(self.a.Refused):self.sources.source_graph(self.session,capture=True)

    def test_same_function_cell_poisoned_root_refused(self):
        function=self.phase['dependencies'].load_collector
        cell=function.__closure__[function.__code__.co_freevars.index('root')];old=cell.cell_contents
        try:cell.cell_contents=self.root/'foreign';self.refuse()
        finally:cell.cell_contents=old

    def test_same_function_cell_poisoned_module_refused(self):
        function=self.phase['dependencies'].load_collector
        group=function.__closure__[function.__code__.co_freevars.index('collector')].cell_contents
        old=group['crypto'];foreign=types.ModuleType(old.__name__);foreign.__dict__.update(old.__dict__)
        with patch.dict(group,crypto=foreign):self.refuse()

    def test_nested_loader_namespace_method_poison_refused(self):
        hidden=self.phase['dependencies'].load_collector()['crypto']
        with patch.object(hidden,'attest',lambda *args,**kwargs:{'status':'PASS'}):self.refuse()

    def test_foreign_class_subclass_and_slot_descriptor_refused(self):
        with patch.object(self.authority,'RootCallbacks',type('RootCallbacks',(type(self.callback),),{})):self.refuse()
        old=type(self.callback)._session
        with patch.object(type(self.callback),'_session',property(lambda x:self.session)):self.refuse()
        self.assertIs(type(self.callback)._session,old)

    def test_same_source_helper_method_object_replacement_refused(self):
        old=type(self.session).tick
        foreign=types.FunctionType(old.__code__,old.__globals__,old.__name__,old.__defaults__)
        foreign.__qualname__=old.__qualname__;foreign.__kwdefaults__=old.__kwdefaults__
        with patch.object(type(self.session),'tick',foreign):self.refuse()

    def test_slot_uninitialized_or_extra_context_refused(self):
        with patch.object(type(self.callback),'handoff_binding',lambda x:self.callback.handoff_binding()):self.refuse()
        with patch.object(self.session,'cancelled',lambda:False):self.refuse()

    def test_contextmanager_same_wrapper_foreign_generator_refused(self):
        old=type(self.session).step
        foreign=types.FunctionType(old.__code__,old.__globals__,old.__name__,old.__defaults__,
            (types.CellType(lambda:None),));foreign.__wrapped__=lambda:None
        with patch.object(type(self.session),'step',foreign):self.refuse()

    def test_controller_foreign_class_refused(self):
        with patch.object(self.session,'controller',types.SimpleNamespace()):self.refuse()

    def test_real_controller_construction_source_state_without_stages(self):
        module=self.original['integration']
        controller=module.Controller('sha256:'+'a'*64,module.Path(self.root/'native-output'),
            module.Path(self.root/'controller-source-only'),
            self.a.decode(self.sources.raw['scripts/ci/integration.lock.json']),self.grant['source_commit'])
        with patch.object(self.session,'controller',controller):self.check()
        self.assertEqual(controller.report['stages'],{})
        self.assertEqual(controller.report['status'],'FAIL')

    def test_source_method_or_deadline_poison_refused(self):
        with patch.object(type(self.sources),'guard',lambda *a:None):self.refuse()
        with self.assertRaises(self.a.Refused):self.a.authority_state(self.sources,self.callback.public_receiver,time.monotonic()-1)

    def test_path_subclass_executable_state_refused(self):
        class ForeignPath(type(Path())):
            def __truediv__(self,other):raise AssertionError('foreign path executed')
        old=self.callback._root
        try:
            object.__setattr__(self.callback,'_root',ForeignPath(old))
            self.refuse()
        finally:object.__setattr__(self.callback,'_root',old)

    def test_recapture_after_full_graph_refused(self):
        with self.assertRaises(self.a.Refused):self.sources.source_graph(self.session,capture=True)

    def test_original_private_alias_foreign_namespace_refused(self):
        old=self.original['repository_projection'].inventory
        foreign=types.ModuleType(old.__name__);foreign.__dict__.update(old.__dict__)
        with patch.dict(self.session.source_graph['original_aliases'],{'repository_projection.inventory':foreign}):self.refuse()

    def test_supervisor_exact_captured_guard_and_grants_no_role_actor(self):
        module=self.runtime['supervisor'];code=next(code for code in self.a.code_objects(
            compile(self.sources.raw[self.a.PREFIXES['runtime']+'/entry.py'],self.entry.__file__,'exec'))
            if code.co_qualname=='services.<locals>.source_guard')
        rows=self.a.decode(self.sources.raw[self.grant['maps']['runtime']['path']])
        values={'cancelled':None,'job_deadline':self.session.job_deadline,
            'root':self.root/self.a.PREFIXES['runtime'],'rows':rows,'source_identities':None}
        guard=types.FunctionType(code,self.entry.__dict__,'source_guard',None,
            tuple(types.CellType(values[name]) for name in code.co_freevars))
        grants={role:{'module':'broker','source_file':str(self.root/self.a.PREFIXES['runtime']/'broker.py'),
            'source_sha256':rows['broker.py']['sha256']} for role in module.ROLES}
        with patch.object(self.session,'work_end',self.deadline-60):
            supervisor=module.RoleSupervisor(grants,deadline=self.session.work_end,source_guard=guard)
            with patch.object(self.session,'supervise',supervisor):
                self.check()
                with patch.dict(supervisor.grants,{'phase-accept':{**grants['phase-accept'],'module':'foreign'}}):self.refuse()
                cell=guard.__closure__[code.co_freevars.index('root')];old=cell.cell_contents
                try:cell.cell_contents=self.root/'foreign';self.refuse()
                finally:cell.cell_contents=old
        self.assertEqual(supervisor.receipts,[])
        self.assertFalse(supervisor.active)


if __name__ == '__main__':unittest.main()
