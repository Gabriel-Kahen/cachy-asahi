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
import shutil
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
    def model(self, *, exit_code=0, broad_seconds=2000, capture_error=None, close_error=None, late_cancel=False, phase_descriptor=None):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        root=Path(temporary.name);events=[];clock=[1000]
        grant={'schema_version':2,'source_commit':'a'*40,'run_id':'1','run_attempt':'1','recipe_source_commit':'b'*40,
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
            if phase_descriptor is not None:
                session.phase_export_raw=adapter.encoded(phase_descriptor)
                session.phase_export_sha256=adapter.digest(session.phase_export_raw)
        callbacks={'existing_consumers':broad,'public_receiver':lambda *a:None,'authority_provider':lambda *a:None}
        session.pending_consumer=pending;session.terminal_consumer=terminal
        # Budget-only models; explicit view/frame custody is exercised by actual-source fixtures below.
        session.view_plan=lambda argv:root/'output'/'original-view'
        session.prepare_view=lambda path:None
        session.observe_native_consumer=lambda controller:setattr(session,'controller',controller)
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

    def test_return_only_phase_descriptor_after_cleanup_and_durable_success(self):
        descriptor={'path':'MODEL ONLY','receipt_sha256':'a'*64,'receipt_bytes':12,'public_files':{}}
        session,result,events,_=self.model(phase_descriptor=descriptor)
        self.assertEqual(result['phase_public'],{'descriptor_bytes':adapter.encoded(descriptor),
            'sha256':adapter.digest(adapter.encoded(descriptor))})
        self.assertEqual(result['cleanup'],'PASS')
        self.assertNotIn('phase_public',adapter.decode((session.output/'status/result.json').read_bytes()))
        self.assertLess(events.index('terminal'),events.index('transport-close'))

    def test_cleanup_or_late_cancel_never_returns_captured_phase_authority(self):
        for options in ({'close_error':OSError('private')},{'late_cancel':True},{'exit_code':1}):
            session,result,_,_=self.model(phase_descriptor={'path':'MODEL ONLY'},**options)
            self.assertEqual(result['status'],'FAIL');self.assertIsNone(result['phase_public'])
            self.assertEqual(result['public'],[str(session.output/'status')])
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

    def test_phase_descriptor_captures_the_validated_receipt_and_exact_map(self):
        session,events,error,_=self.run_case()
        self.assertIsNone(error)
        descriptor=adapter.decode(session.phase_export_raw)
        raw=(session.output/'phase-public/result.json').read_bytes()
        self.assertEqual(descriptor,{'path':str(session.output/'phase-public'),
            'receipt_sha256':adapter.digest(raw),'receipt_bytes':len(raw),
            'public_files':{**adapter.decode(raw)['public_files'],
                'result.json':{'sha256':adapter.digest(raw),'bytes':len(raw)}}})
        self.assertEqual(session.phase_export_sha256,adapter.digest(session.phase_export_raw))
        (session.output/'phase-public/result.json').write_bytes(b'changed')
        self.assertEqual(descriptor,adapter.decode(session.phase_export_raw))

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
    """Actual selected258 source/slot graph; modeled registered policy, no actors."""
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='handoff-actual-graph-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root=Path(cls.temporary.name)/'source';cls.root.mkdir()
        cls.output=Path(cls.temporary.name)/'output';project=PATH.parents[3]
        # Explicit source-only fixture closure; no unregistered packet-map read.
        names=set(json.loads((project/'scripts/ci/integration.lock.json').read_bytes())['source_files'])
        names.update('''
.github/workflows/native-arm-development.yml
manifests/reviewed/repository-generic-policy.json
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
scripts/virtual/image_decode_probe.c
scripts/virtual/image_decode_report.py
scripts/virtual/test_image_decode_probe.py
packages/shells/cachy-asahi-zsh-autosuggestions/.SRCINFO
packages/shells/cachy-asahi-zsh-autosuggestions/LICENSE.project
packages/shells/cachy-asahi-zsh-autosuggestions/LICENSE.upstream
packages/shells/cachy-asahi-zsh-autosuggestions/NOTICE
packages/shells/cachy-asahi-zsh-autosuggestions/PKGBUILD
packages/shells/cachy-asahi-zsh-autosuggestions/README.md
packages/shells/cachy-asahi-zsh-autosuggestions/check-module.py
packages/shells/cachy-asahi-zsh-autosuggestions/integration-proposal.json
packages/shells/cachy-asahi-zsh-autosuggestions/opt-in.zsh
packages/shells/cachy-asahi-zsh-autosuggestions/source-provenance.json
packages/shells/cachy-asahi-zsh-autosuggestions/usage.md
packages/shells/cachy-asahi-zsh-autosuggestions/zsh-autosuggestions.zsh
'''.split())
        names.update(getattr(cls,'ADDITIONAL_SOURCES',()))
        rows={}
        for name in sorted(names):
            # Explicit harmless fixture bytes, never an ignored artifact dependency
            # or authority for production. Root registers the actual policy path.
            raw=(b'{\n  "coordinated_sets": [\n    {\n      "name": "generic-Hyprland-builder",\n      "versions": {\n        "aquamarine": "0.15.1-1",\n        "hyprgraphics": "0.5.1-4",\n        "hyprland": "0.56.2-4",\n        "hyprlang": "0.6.8-5",\n        "hyprutils": "0.14.2-1"\n      }\n    }\n  ],\n  "platform_scope": "generic-builder-only",\n  "protected_packages": [\n    "pacman",\n    "glibc",\n    "bash",\n    "filesystem"\n  ],\n  "purpose": "reviewed-generic-restage-policy",\n  "review_status": "ACCEPTED",\n  "selected_packages": [\n    "cachy-asahi-fish-config",\n    "cachy-asahi-hyprland-settings",\n    "cachy-asahi-setup",\n    "cachy-asahi-zsh-config"\n  ],\n  "supported_models": []\n}\n' if name=='manifests/reviewed/repository-generic-policy.json'
                 else (project/name).read_bytes());destination=cls.root/name
            destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(raw)
            mode=0o644 if name=='manifests/reviewed/repository-generic-policy.json' else (project/name).stat().st_mode&0o777
            destination.chmod(mode)
            rows[name]={'sha256':adapter.digest(raw),'mode':mode}
        cls.a=types.ModuleType('handoff_actual_graph');cls.a.__file__=str(cls.root/'scripts/ci/development/repository_handoff.py')
        cls.registration=patch.dict(sys.modules,{cls.a.__name__:cls.a});cls.registration.start()
        cls.addClassCleanup(cls.registration.stop)
        exec(compile((cls.root/'scripts/ci/development/repository_handoff.py').read_bytes(),cls.a.__file__,'exec'),cls.a.__dict__)
        cls.deadline=time.monotonic()+600
        actor={'cli_sha256':'b'*64,'endpoint_identity':{'fixture':'NO ACTOR'},'env':{}}
        cls.grant={'schema_version':2,'purpose':'reviewed-same-job-handoff-execution',
            'source_peer_preflight':'PASS','development_only':True,'added_seconds':1200,
            'source_commit':'a'*40,'recipe_source_commit':'c'*40,'run_id':'123','run_attempt':'2',
            'source_files':rows,'maps':{},'callbacks':{},
            'policy_path':'manifests/reviewed/repository-generic-policy.json',
            'license_path':'LICENSE','actor_contract_sha256':adapter.digest(adapter.encoded(actor)),
            'initial_invocation_sha256':adapter.digest(adapter.encoded({'argv':['SOURCE-ONLY-NO-ACTOR'],
                                                                       'output':str(cls.output)}))}
        initial=json.loads((cls.root/'scripts/ci/integration.lock.json').read_bytes())
        cls.grant['original_view']={'schema_version':1,'purpose':'original-159-copy-view',
            'full_source_root':str(cls.root),'root':str(cls.output/'original-view'),
            'integration_lock_sha256':cls.a.INITIAL,'source_rows_sha256':cls.a.digest(cls.a.encoded(initial['source_files'])),
            'file_count':160,'argv_mode':'absolute-view-metadata'}
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
        cls.session=cls.a.Session(cls.sources,cls.output,job_deadline=cls.deadline,
                                 composition=getattr(cls,'COMPOSITION','repository-svg'))
        cls.output.mkdir(mode=0o700);cls.session.prepare_view(cls.output/'original-view')
        cls.session.used=True  # Inert registration model; Session.execute is never called.
        cls.session.source_graph={'entry':cls.entry,'runtime':cls.runtime,'collector':cls.collector,
            'phase':cls.phase,'original':{},'original_aliases':{}}
        if cls.session.composition == 'installer-preflight':
            cls.session.register_native_preflight()
            cls.installer=cls.session.source_graph['native_preflight']
            def unregister():
                if sys.modules.get('native_install_preflight') is cls.installer:del sys.modules['native_install_preflight']
            cls.addClassCleanup(unregister)
        cls.sources.source_graph(cls.session,capture=True)
        cls.partial_observation=cls.sources.graph_observation
        cls.scope=cls.entry.original_modules(cls.session.view_root,cls.session.view_root/'scripts/ci/integration.lock.json',
            cls.a.INITIAL,deadline=cls.deadline,verification_deadline=cls.deadline)
        cls.original=cls.scope.__enter__();cls.addClassCleanup(cls.scope.__exit__,None,None,None)
        cls.session.original_scope=cls.scope
        cls.session.source_graph.update(original=cls.original,original_aliases={
            'repository_projection.inventory':cls.original['repository_projection'].inventory,
            'desktop_projection.policy':cls.original['desktop_projection'].policy})
        cls.sources.source_graph(cls.session,capture=True)
        cls.authority=cls.sources.module('handoff_actual_authority','scripts/ci/development/repository_authority.py')
        cls.authority_registration=patch.dict(sys.modules,{cls.authority.__name__:cls.authority})
        cls.authority_registration.start();cls.addClassCleanup(cls.authority_registration.stop)
        with patch.dict(os.environ,GITHUB_SHA=cls.grant['source_commit'],GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='2'):
            cls.callback=cls.authority.RootCallbacks(cls.root,raw,pin,cls.a.encoded(actor),cls.output,
                deadline=cls.deadline,session=cls.session)

    def check(self):
        with patch.dict(os.environ,GITHUB_SHA=self.grant['source_commit'],GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='2'):
            self.a.authority_state(self.sources,self.callback.public_receiver,
                min(self.deadline,self.session.work_end) if self.session.work_end is not None else self.deadline)
        self.assertFalse((self.root/'output').exists())

    def refuse(self):
        with self.assertRaises(self.a.Refused):self.check()

    def test_actual_slots_and_full_source_namespaces_accept_inert_state(self):
        self.check()
        with patch.dict(os.environ,GITHUB_SHA=self.grant['source_commit'],GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='2'):
            self.assertEqual(len(self.callback.handoff_binding()),12)
        self.assertEqual(len(self.sources.raw),258)
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

    def test_view_is_exact160_original_only_with_real_original_scan(self):
        context=self.session.original_context(deadline=self.deadline)
        self.assertIs(context['original']['native_arm'],self.original['native_arm'])
        self.assertEqual(context['root'],self.session.view_root)
        self.assertEqual(len(self.original['integration'].scan(self.session.view_root)),159)
        target=self.output/'freeze-source-only.json'
        self.original['native_arm'].freeze_recipes(target)
        data=json.loads(target.read_bytes())
        self.assertEqual(len(data),4);self.assertEqual(sum(len(row) for row in data.values()),71)
        self.assertEqual(len(self.a.decode(context['receipt'])['files']),160)
        self.assertEqual(self.original['native_arm'].ROOT,self.session.view_root)

    def test_current_full_checkout_scanner_sees_addon_view_remains_original(self):
        project=PATH.parents[3]
        actual=self.original['integration'].scan(project)
        initial=self.a.decode(self.sources.raw['scripts/ci/integration.lock.json'])['source_files']
        self.assertGreaterEqual(len(actual),171)
        self.assertTrue(set('packages/shells/cachy-asahi-zsh-autosuggestions/'+name
            for name in ('.SRCINFO','LICENSE.project','LICENSE.upstream','NOTICE','PKGBUILD','README.md',
                         'check-module.py','integration-proposal.json','opt-in.zsh','source-provenance.json',
                         'usage.md','zsh-autosuggestions.zsh')) <= set(actual)-set(initial))
        self.assertEqual(len(self.original['integration'].scan(self.session.view_root)),159)

    def test_old_schema_refuses_current_preflight(self):
        grant=copy.deepcopy(self.grant);grant['schema_version']=1;grant.pop('original_view')
        raw=self.a.encoded(grant)
        with self.assertRaises(self.a.Refused):self.a.preflight(self.root,raw,self.a.digest(raw),deadline=self.deadline)

    def test_metadata_path_hash_duplicates_and_output_selection_before_actor(self):
        view=self.session.view_root
        argv=['integration']
        for flag,name in (('--inputs','inputs.lock.json'),('--recipes','recipes.lock.json'),('--integration','integration.lock.json')):
            argv.extend((flag,str(view/'scripts/ci'/name),flag+'-sha256',self.a.digest(self.sources.raw['scripts/ci/'+name])))
        argv.extend(('--cache',str(self.output/'cache'),'--output',str(self.output/'native'),
                     '--integration-output',str(self.output/'integration')))
        self.assertEqual(self.session.view_plan(argv),view)
        for index in (2,4,6,8,10,12):
            changed=list(argv);changed[index]='foreign'
            with self.assertRaises(self.a.Refused):self.session.view_plan(changed)
        with self.assertRaises(self.a.Refused):self.session.view_plan(argv+['--recipes',str(self.root/'scripts/ci/recipes.lock.json')])
        with patch.object(self.session,'output',self.output/'different'):
            with self.assertRaises(self.a.Refused):self.session.view_plan(argv)

    def test_view_extra_empty_directory_and_foreign_namespace_refuse(self):
        extra=self.session.view_root/'extra-empty';extra.mkdir(mode=0o700)
        try:self.refuse()
        finally:extra.rmdir()
        other=types.ModuleType('integration');other.__dict__.update(self.original['integration'].__dict__)
        with patch.dict(self.original,integration=other):self.refuse()

    def test_copy_same_bytes_replaced_inode_and_mode_refuse(self):
        path=self.session.view_root/'LICENSE';old=path.stat();raw=path.read_bytes()
        replacement=path.with_name('LICENSE-new');replacement.write_bytes(raw);replacement.chmod(old.st_mode&0o777)
        backup=path.with_name('LICENSE-private-backup');path.rename(backup)
        try:
            replacement.rename(path)
            with self.assertRaises(self.a.Refused):self.session.verify_view(self.deadline)
        finally:path.unlink();backup.rename(path)
        path.chmod(0o600)
        try:
            with self.assertRaises(self.a.Refused):self.session.verify_view(self.deadline)
        finally:path.chmod(old.st_mode&0o777)
        # A rename changes ctime. Restore fixture custody by a fresh copy rather
        # than rebinding the production receipt to changed bytes/nodes.
        self._refresh_view_fixture()

    def _refresh_view_fixture(self):
        try:self.scope.__exit__(None,None,None)
        except ValueError as error:self.assertEqual(str(error),'original-source-drift')
        self.a.remove_private(self.session.view_root,self.session.view_node,self.deadline)
        self.session.view_root=None;self.session.view_receipt=None
        self.session.prepare_view(self.output/'original-view')
        scope=self.entry.original_modules(self.session.view_root,self.session.view_root/'scripts/ci/integration.lock.json',
            self.a.INITIAL,deadline=self.deadline,verification_deadline=self.deadline)
        original=scope.__enter__();type(self).scope=scope;type(self).addClassCleanup(scope.__exit__,None,None,None)
        self.session.original_scope=scope
        self.session.source_graph.update(original=original,original_aliases={
            'repository_projection.inventory':original['repository_projection'].inventory,
            'desktop_projection.policy':original['desktop_projection'].policy})
        # Fixture reset only: actual producer forbids a second capture/copy.
        self.sources.graph_observation=self.partial_observation
        self.sources.source_graph(self.session,capture=True)
        type(self).original=original

    def test_fabricated_same_class_controller_has_no_native_frame_custody(self):
        module=self.original['integration']
        controller=module.Controller('sha256:'+'a'*64,module.Path(self.output/'no-native'),
            module.Path(self.output/'fabricated-controller'),
            self.a.decode(self.sources.raw['scripts/ci/integration.lock.json']),self.grant['source_commit'])
        with self.assertRaises(self.a.Refused):self.session.observe_native_consumer(controller)
        with self.assertRaises(self.a.Refused):self.session.original_context(deadline=self.deadline,controller=controller)
        self.assertIsNone(self.session.native_consumer_observation)

    def test_context_ready_does_not_accept_foreign_or_closed_generator(self):
        @contextmanager
        def foreign():yield self.original
        scope=foreign();scope.__enter__()
        try:
            with patch.object(self.session,'original_scope',scope):
                with self.assertRaises(self.a.Refused):self.session.original_context(deadline=self.deadline)
        finally:scope.__exit__(None,None,None)
        with patch.object(self.session,'original_scope',None):
            with self.assertRaises(self.a.Refused):self.session.original_context(deadline=self.deadline)

    def test_immutable_receipt_unknown_fields_or_wrong_live_binding_refuse(self):
        old=self.a.decode(self.session.view_receipt)
        for mutate in (lambda value:value.update(raw='private error'),lambda value:value.update(run_attempt='3'),
                       lambda value:value.update(file_count=True)):
            value=copy.deepcopy(old);mutate(value);raw=self.a.encoded(value)
            with patch.object(self.session,'view_receipt',raw),patch.object(self.session,'view_receipt_sha256',self.a.digest(raw)):
                with self.assertRaises(self.a.Refused):self.session.verify_view(self.deadline)

    def test_context_refuses_surplus_canonical_directory_receipt_row(self):
        value=copy.deepcopy(self.a.decode(self.session.view_receipt))
        value['directories']['ghost']=value['directories']['.'];raw=self.a.encoded(value)
        with patch.object(self.session,'view_receipt',raw),patch.object(self.session,'view_receipt_sha256',self.a.digest(raw)):
            with self.assertRaises(self.a.Refused):self.session.original_context(deadline=self.deadline)
        self.assertEqual(self.session.original_context(deadline=self.deadline)['receipt'],self.session.view_receipt)

    def test_context_refuses_noncanonical_directory_receipt_names(self):
        original=self.a.decode(self.session.view_receipt)
        for name in ('../ghost','./ghost','ghost/','a//b','/ghost','','..'):
            with self.subTest(name=name):
                value=copy.deepcopy(original);value['directories'][name]=value['directories']['.'];raw=self.a.encoded(value)
                with patch.object(self.session,'view_receipt',raw),patch.object(self.session,'view_receipt_sha256',self.a.digest(raw)):
                    with self.assertRaises(self.a.Refused):self.session.original_context(deadline=self.deadline)

    def test_context_refuses_missing_or_aliased_directory_receipt_rows(self):
        original=self.a.decode(self.session.view_receipt)
        child=next(name for name in original['directories'] if name!='.')
        for name,alias in (('.',None),(child,None),(child,child+'/..')):
            with self.subTest(name=name,alias=alias):
                value=copy.deepcopy(original);node=value['directories'].pop(name)
                if alias is not None:value['directories'][alias]=node
                raw=self.a.encoded(value)
                with patch.object(self.session,'view_receipt',raw),patch.object(self.session,'view_receipt_sha256',self.a.digest(raw)):
                    with self.assertRaises(self.a.Refused):self.session.original_context(deadline=self.deadline)


    def isolated_view(self):
        temporary=tempfile.TemporaryDirectory(prefix='original-view-control-');self.addCleanup(temporary.cleanup)
        output=Path(temporary.name)/'output';output.mkdir(mode=0o700)
        grant=copy.deepcopy(self.grant);grant['original_view']['root']=str(output/'original-view')
        sources=self.a.Sources(self.root,grant,self.deadline);sources.grant_pin=self.a.digest(self.a.encoded(grant))
        session=self.a.Session(sources,output,job_deadline=self.deadline)
        def cleanup():
            if session.view_root is not None and session.view_root.exists():
                self.a.remove_private(session.view_root,session.view_node,self.deadline)
        self.addCleanup(cleanup)
        return session

    def test_partial_copy_write_failure_registers_only_owned_cleanup(self):
        session=self.isolated_view()
        with patch.object(self.a.os,'write',side_effect=OSError('PRIVATE')):
            with self.assertRaises(OSError):session.prepare_view(session.output/'original-view')
        self.assertIsNotNone(session.view_node)
        self.assertIsNone(session.view_receipt)
        self.a.remove_private(session.view_root,session.view_node,self.deadline)
        self.assertFalse(session.view_root.exists())
        self.assertIsNone(self.session.result['initial_exit_code'])

    def test_view_copy_cancel_expiry_and_wrong_root_before_writes(self):
        for mode in ('cancel','expired','wrong-root'):
            session=self.isolated_view()
            if mode=='cancel':session.cancelled=lambda:True
            if mode=='expired':session.job_deadline=time.monotonic()-1
            root=session.output/('foreign' if mode=='wrong-root' else 'original-view')
            with self.assertRaises((self.a.Refused,KeyboardInterrupt)):session.prepare_view(root)
            self.assertFalse(root.exists())

    def test_directory_replacement_preserving_file_nodes_refuses(self):
        session=self.isolated_view();session.prepare_view(session.output/'original-view')
        directory=session.view_root/'examples';moved=session.output/'moved-examples'
        directory.rename(moved);directory.mkdir(mode=0o700)
        for child in list(moved.iterdir()):child.rename(directory/child.name)
        try:
            with self.assertRaises(self.a.Refused):session.verify_view(self.deadline)
        finally:moved.rmdir()

    def test_symlink_fifo_hardlink_and_added_file_refuse(self):
        for kind in ('symlink','fifo','hardlink','file'):
            session=self.isolated_view();session.prepare_view(session.output/'original-view')
            extra=session.view_root/'extra'
            if kind=='symlink':extra.symlink_to(session.view_root/'LICENSE')
            elif kind=='fifo':os.mkfifo(extra)
            elif kind=='hardlink':os.link(session.view_root/'LICENSE',extra)
            else:extra.write_bytes(b'PRIVATE')
            try:
                with self.assertRaises(self.a.Refused):session.verify_view(self.deadline)
            finally:extra.unlink()

    def test_view_cleanup_refuses_replaced_root_preserves_foreign_node(self):
        session=self.isolated_view();session.prepare_view(session.output/'original-view')
        original=session.output/'original-owned';session.view_root.rename(original)
        session.view_root.mkdir(mode=0o700);(session.view_root/'foreign').write_bytes(b'UNRELATED')
        try:
            with self.assertRaises(self.a.Refused):self.a.remove_private(session.view_root,session.view_node,self.deadline)
            self.assertEqual((session.view_root/'foreign').read_bytes(),b'UNRELATED')
        finally:
            (session.view_root/'foreign').unlink();session.view_root.rmdir();original.rename(session.view_root)



class InstallerGraphFixtures(unittest.TestCase):
    """Actual Session/Sources registration; no admitted controller/native frames."""
    COMPOSITION='installer-preflight'
    ADDITIONAL_SOURCES=('scripts/install/native_preflight.py','scripts/install/test_native_preflight.py',
        'scripts/install/local_transaction.py','scripts/install/test_local_transaction.py',
        'scripts/install/native_arm_trial.py','scripts/install/test_native_arm_trial.py',
        'scripts/port/kernel-native-job/runtime.py')
    @classmethod
    def setUpClass(cls): CapturedGraphFixtures.setUpClass.__func__(cls)
    def check(self): return self.sources.source_graph(self.session)
    @contextmanager
    def fresh_registration(self,composition='installer-preflight'):
        session=self.a.Session(self.sources,self.root/'no-actor-output',job_deadline=self.deadline,
                               composition=composition)
        session.used=True
        session.source_graph={key:self.session.source_graph[key] for key in ('entry','runtime','collector','phase')}
        session.source_graph.update(original={},original_aliases={})
        with patch.object(self.sources,'graph_observation',None),patch.dict(sys.modules):
            sys.modules.pop('native_install_preflight',None)
            try:yield session
            finally:sys.modules.pop('native_install_preflight',None)
    def test_exact_captured_module_callback_and_unchanged_original_graph(self):
        graph=self.check(); module=graph['scripts/install/native_preflight.py']
        self.assertIs(module,self.installer); self.assertIs(sys.modules['native_install_preflight'],module)
        self.assertEqual((module.OWN,module.run.__module__,module.run.__qualname__),
            ('scripts/install/native_preflight.py','native_install_preflight','run'))
        self.assertEqual(len(self.sources.raw),265)
        self.assertEqual(len(self.sources.grant),17); self.assertEqual(len(self.sources.grant['original_view']),8)
        self.assertEqual(len(self.sources.grant['callbacks']),3)
        self.assertEqual(set(self.session.source_graph),
            {'entry','runtime','collector','phase','original','original_aliases','native_preflight'})
        self.assertIs(graph['scripts/ci/integration.py'],self.original['integration'])
        self.assertIsNone(self.session.native_consumer_observation)
        self.assertIsNone(self.session.result['initial_exit_code'])
    def test_registration_and_graph_capture_validate_actual_bridge_before_and_after(self):
        calls=[]
        def trace(frame,event,arg):
            if event=='call' and frame.f_code.co_qualname=='namespace' and frame.f_globals.get('__name__')=='native_install_preflight':
                calls.append((frame.f_locals['module'],frame.f_locals['raw'],frame.f_locals['pin']))
            return trace
        with self.fresh_registration() as session:
            previous=sys.gettrace();sys.settrace(trace)
            try:
                callback=session.register_native_preflight()
                modules=self.sources.source_graph(session,capture=True)
            finally:sys.settrace(previous)
            module=modules['scripts/install/native_preflight.py']
            self.assertIs(callback,module.run);self.assertEqual(len(calls),4)
            for actual,raw,pin in calls:
                self.assertIs(actual,module);self.assertIs(raw,self.sources.raw[module.OWN])
                self.assertEqual(pin,self.sources.grant['source_files'][module.OWN]['sha256'])
    def test_unknown_modes_refuse_and_legacy_registration_starts_no_loader(self):
        for mode in ('installer',True,None,{}):
            with self.assertRaises(self.a.Refused):
                self.a.Session(self.sources,self.root/'absent',job_deadline=self.deadline,composition=mode)
        with self.fresh_registration('repository-svg') as session:
            with self.assertRaises(self.a.Refused):session.register_native_preflight()
            self.assertNotIn('native_install_preflight',sys.modules)
            self.assertNotIn('native_preflight',session.source_graph)
    def test_graph_mode_missing_extra_or_wrong_module_keys_refuse(self):
        with patch.object(self.session,'composition','repository-svg'):
            with self.assertRaises(self.a.Refused):self.check()
        for change in ({'extra':self.installer},{'native_preflight':None}):
            with patch.dict(self.session.source_graph,change):
                with self.assertRaises(self.a.Refused):self.check()
        with patch.dict(self.session.source_graph):
            del self.session.source_graph['native_preflight']
            with self.assertRaises(self.a.Refused):self.check()
    def test_foreign_mode_and_callback_identity_labels_refuse_without_equality(self):
        calls=[]
        class Foreign:
            def __eq__(self,other):calls.append('equality');raise RuntimeError('foreign equality')
        foreign=Foreign()
        for target,field in ((self.session,'composition'),(self.installer,'OWN'),
                             (self.installer,'__name__'),(self.installer.run,'__module__')):
            old=getattr(target,field);setattr(target,field,foreign)
            try:
                with self.assertRaises(self.a.Refused):self.check()
            finally:setattr(target,field,old)
        with self.fresh_registration() as session:
            session.composition=foreign
            with self.assertRaises(self.a.Refused):session.register_native_preflight()
        self.assertEqual(calls,[])
    def test_foreign_module_subclass_namespace_or_sys_modules_refuse(self):
        class ForeignModule(types.ModuleType): pass
        for replacement in (None,types.ModuleType('native_install_preflight'),ForeignModule('native_install_preflight')):
            with patch.dict(sys.modules,{'native_install_preflight':replacement}):
                with self.assertRaises(self.a.Refused):self.check()
        foreign=types.ModuleType('native_install_preflight');foreign.__dict__.update(self.installer.__dict__)
        with patch.dict(sys.modules,{'native_install_preflight':foreign}), \
             patch.dict(self.session.source_graph,{'native_preflight':foreign}):
            with self.assertRaises(self.a.Refused):self.check()
    def test_exact_callback_tuple_code_globals_defaults_and_import_custody_refuse(self):
        callback=self.installer.run
        foreign=types.FunctionType(callback.__code__,{'__builtins__':__builtins__})
        for replacement in (foreign,lambda *args,**kwargs:{'status':'PASS'}):
            with patch.object(self.installer,'run',replacement):
                with self.assertRaises(ValueError):self.check()
        for field,value in (('__module__','foreign'),('__qualname__','foreign'),
                            ('__defaults__',('foreign',)),('__kwdefaults__',{'nonce':'foreign'})):
            old=getattr(callback,field);setattr(callback,field,value)
            try:
                with self.assertRaises(ValueError):self.check()
            finally:setattr(callback,field,old)
        with patch.object(self.installer,'Path',type(Path())):
            with self.assertRaises(ValueError):self.check()
    def test_each_required_source_and_grant_row_is_required_before_registration(self):
        for path in self.ADDITIONAL_SOURCES:
            for rows in (self.sources.raw,self.sources.grant['source_files']):
                with self.fresh_registration() as session,patch.dict(rows):
                    del rows[path]
                    with self.assertRaises(self.a.Refused):session.register_native_preflight()
                    self.assertNotIn('native_install_preflight',sys.modules)
                    self.assertNotIn('native_preflight',session.source_graph)
    def test_ambient_module_once_registration_and_recapture_refuse(self):
        with self.fresh_registration() as session:
            with patch.dict(sys.modules,{'native_install_preflight':self.installer}):
                with self.assertRaises(self.a.Refused):session.register_native_preflight()
            session.register_native_preflight();self.sources.source_graph(session,capture=True)
            with self.assertRaises(self.a.Refused):session.register_native_preflight()
            with self.assertRaises(self.a.Refused):self.sources.source_graph(session,capture=True)
        with self.assertRaises(self.a.Refused):self.sources.source_graph(self.session,capture=True)
    def test_equal_source_bytes_replacement_is_refused_by_actual_source_guard(self):
        with tempfile.TemporaryDirectory(prefix='installer-graph-source-identity-') as temporary:
            root=Path(temporary)/'source';shutil.copytree(self.root,root)
            sources=self.a.Sources(root,self.grant,self.deadline)
            path=root/'scripts/install/native_preflight.py';saved=path.with_suffix('.retained')
            path.rename(saved)
            path.write_bytes(saved.read_bytes());path.chmod(saved.stat().st_mode&0o777)
            with self.assertRaises(self.a.Refused):sources.guard(self.deadline)
        self.check()
    def test_registration_refusal_after_attachment_rolls_back_owned_namespace(self):
        # A synchronous source-only trace trips the existing deadline after attachment.
        with self.fresh_registration() as session:
            old=self.deadline
            def trace(frame,event,arg):
                if event=='line' and frame.f_code is self.a.Session.register_native_preflight.__code__ and 'native_preflight' in session.source_graph:
                    session.job_deadline=time.monotonic()-1
                return trace
            previous=sys.gettrace();sys.settrace(trace)
            try:
                with self.assertRaises(self.a.Refused):session.register_native_preflight()
            finally:sys.settrace(previous);session.job_deadline=old
            self.assertNotIn('native_install_preflight',sys.modules)
            self.assertNotIn('native_preflight',session.source_graph)


class CurrentP0InputContractTests(unittest.TestCase):
    """Actual current SDK guards over public Source metadata; no actor substitutes."""
    @classmethod
    def setUpClass(cls):
        cls.contract = copy.deepcopy(adapter.P0_CURRENT_CONTRACT)
        driver_path = PATH.with_name('p0_ci.py')
        driver_spec = importlib.util.spec_from_file_location('p0_current_inputs_test_driver', driver_path)
        driver = importlib.util.module_from_spec(driver_spec)
        driver_spec.loader.exec_module(driver)
        cls.historical = (PATH.parents[1] / 'inputs.lock.json').read_bytes()
        cls.current = driver.current_inputs(cls.historical)
        value = json.loads(cls.current)
        versions = {row['name'][0]: row['version'][0] for row in value['rootfs_packages']}
        versions.update({row['name']: row['version'] for row in value['packages']})
        cls.packages = ''.join(name + ' ' + versions[name] + '\n' for name in sorted(versions)).encode()
        cls.historical_packages = (PATH.parents[2] / 'port/refreshed-desktop/proposed-builder-inventory.lock').read_bytes()

    def test_current_metadata_pair_is_distinct_from_held_historical_source(self):
        self.assertEqual(adapter.digest(self.historical), self.contract['historical_inputs_sha256'])
        self.assertEqual(adapter.digest(self.historical_packages), self.contract['historical_packages_sha256'])
        self.assertEqual(adapter.digest(self.current), self.contract['inputs_sha256'])
        self.assertEqual(adapter.digest(self.packages), self.contract['packages_sha256'])
        self.assertEqual((len(self.current), len(self.packages), len(self.packages.splitlines())), (328101, 6674, 341))
        before, after = json.loads(self.historical), json.loads(self.current)
        self.assertEqual([old['name'] for old, new in zip(before['packages'], after['packages']) if old != new],
                         ['vim', 'vim-runtime'])
        self.assertEqual({k:v for k,v in before.items() if k != 'packages'},
                         {k:v for k,v in after.items() if k != 'packages'})
        self.assertEqual(adapter.validate_current_inputs(self.current, self.packages, self.contract), self.contract)

    def test_selector_requires_exact_closed_builtin_types_without_hooks(self):
        class DictSubclass(dict): pass
        class IntSubclass(int): pass
        class StrSubclass(str): pass
        class ForeignValue:
            def __eq__(self, other): raise AssertionError('foreign equality executed')
        valid = adapter.validate_input_successor(self.contract)
        self.assertEqual(valid, self.contract)
        self.assertIsNot(valid, self.contract)
        cases = [DictSubclass(self.contract), {**self.contract, 'extra': None},
                 {**self.contract, 'product': ForeignValue()},
                 {**self.contract, 'inputs_sha256': self.contract['historical_inputs_sha256']}]
        for key, value in self.contract.items():
            missing = dict(self.contract); missing.pop(key); cases.append(missing)
            cases.append({**self.contract, key: True if type(value) is int else StrSubclass(value)})
            if type(value) is int: cases.append({**self.contract, key: IntSubclass(value)})
        bad_key = dict(self.contract); bad_key.pop('product'); bad_key[StrSubclass('product')] = self.contract['product']
        cases.append(bad_key)
        for index, value in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(adapter.Refused):
                adapter.validate_input_successor(value)

    def test_current_byte_guard_refuses_historical_mixed_mutable_and_tampered_data(self):
        cases = [(self.historical, self.historical_packages), (self.historical, self.packages),
                 (self.current, self.historical_packages), (bytearray(self.current), self.packages),
                 (self.current, bytearray(self.packages)),
                 (bytes([self.current[0] ^ 1]) + self.current[1:], self.packages),
                 (self.current, bytes([self.packages[0] ^ 1]) + self.packages[1:])]
        for index, (inputs, packages) in enumerate(cases):
            with self.subTest(index=index), self.assertRaisesRegex(adapter.Refused, 'source-refused'):
                adapter.validate_current_inputs(inputs, packages, self.contract)

    def test_p0_selector_and_exact_recipe_refuse_before_real_source_construction(self):
        class PathBoundary(Exception): pass
        class UnusableRoot:
            def __fspath__(self): raise PathBoundary('no Source reads allowed in metadata model')
        grant = dict(schema_version=2, purpose='reviewed-installer-P0-execution',
            source_peer_preflight='PASS', development_only=True, added_seconds=0,
            source_commit='a'*40, recipe_source_commit=self.contract['recipe_source_commit'], run_id='1', run_attempt='1',
            source_files={}, maps=dict.fromkeys(adapter.PREFIXES, {}), callbacks=dict.fromkeys(adapter.CALLBACKS, None),
            policy_path='held', license_path='held', actor_contract_sha256='b'*64, initial_invocation_sha256='c'*64,
            original_view={'purpose':'P0-157-held-2-overlay-copy-view'}, input_successor=self.contract)
        def invoke(value):
            raw = adapter.encoded(value)
            return adapter.preflight(UnusableRoot(), raw, adapter.digest(raw), deadline=time.monotonic()+5)
        for purpose in ('reviewed-installer-P0-preparation', 'reviewed-installer-P0-execution'):
            selected = {**grant, 'purpose': purpose}
            with self.subTest(purpose=purpose), self.assertRaises(PathBoundary): invoke(selected)
            missing = dict(selected); missing.pop('input_successor')
            for invalid in (missing, {**selected, 'input_successor':{**self.contract, 'packages': True}},
                            {**selected, 'recipe_source_commit':'0'*40}):
                with self.subTest(purpose=purpose), self.assertRaisesRegex(adapter.Refused, 'grant-refused'): invoke(invalid)
        legacy = {**grant, 'purpose':'reviewed-same-job-handoff-execution', 'added_seconds':1200,
                  'original_view':{'purpose':'original-159-copy-view'}}
        with self.assertRaisesRegex(adapter.Refused, 'grant-refused'): invoke(legacy)
        legacy.pop('input_successor')
        with self.assertRaises(PathBoundary): invoke(legacy)


if __name__ == '__main__':unittest.main()
