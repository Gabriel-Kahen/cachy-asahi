# SPDX-License-Identifier: MIT
"""Pure/mock transaction-mode controls; no VM, signing, ALPM or namespace actor."""
import ast
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
import common
import controller
import guest
import prepare
import run


class TransactionMode(unittest.TestCase):
    nonce='a'*32
    selection='b'*64
    source='c'*40
    def contract(self):
        return dict(purpose=common.TRANSACTION_PURPOSE,source_commit=self.source,
            transaction_fixture=dict(source_commit=self.source,sources=copy.deepcopy(common.TRANSACTION_FILES),
                tool_profile=copy.deepcopy(common.TRANSACTION_PROFILE)),transaction_launcher=copy.deepcopy(common.TRANSACTION_LAUNCHER))
    def call(self,pattern):
        positive=pattern in ('PAIR','ADD','REMOVE','UPGRADE','PROTECTED_ADD')
        phase='complete' if positive else dict(REFUSED='NOT_REPORTED',CONFLICT='commit',SNAPSHOT='snapshot',PREPARE='prepare').get(pattern,'isolated')
        return dict(returncode=0 if positive else 2,worker_status='PASS-disposable-payload-transaction' if positive else 'REFUSED' if pattern=='REFUSED' else 'FAIL',
                    phase=phase,commit_started=positive or pattern=='CONFLICT',committed=positive)
    def methods(self):
        return [dict(method=name,calls=[self.call(p) for p in patterns]) for name,method,patterns in common.TRANSACTION_CASES]
    def event(self):
        return dict(event='transaction_result',nonce=self.nonce,selection_sha256=self.selection,fixture_source=self.source,
            uid=23001,gid=23001,tests=16,failures=0,errors=0,skips=0,status='PASS_TRANSACTION_ONLY',methods=self.methods(),
            first_failure=None,class_cleanups_returned=True,cancelled=False)
    def boot(self):
        return dict(event='boot',nonce=self.nonce,arch='aarch64',page_size=4096,kernel=common.KERNEL)
    def exited(self):
        return dict(event='transaction_child_exit',nonce=self.nonce,selection_sha256=self.selection,returncode=0,error=None)
    def test_exact_purpose_source_profile_launcher_and_no_mixed_route(self):
        self.assertTrue(common.transaction_contract(self.contract()));self.assertFalse(common.barrier_contract(self.contract()))
        self.assertFalse(common.transaction_contract({}))
        for change in ('source','worker','profile','launcher','mixed','purpose'):
            c=self.contract()
            if change=='source':c['transaction_fixture']['source_commit']='0'*40
            elif change=='worker':c['transaction_fixture']['sources']['scripts/install/local_transaction.py']['sha256']='0'*64
            elif change=='profile':c['transaction_fixture']['tool_profile']['sha256']='0'*64
            elif change=='launcher':c['transaction_launcher']['files']['/usr/bin/setpriv']['sha256']='0'*64
            elif change=='mixed':c['barrier_fixture']={}
            else:c['purpose']='desktop'
            with self.subTest(change=change),self.assertRaises(ValueError):common.transaction_contract(c)
    def test_profile_bytes_and_held_source_limits(self):
        self.assertEqual(hashlib.sha256(common.TRANSACTION_PROFILE_BYTES).hexdigest(),common.TRANSACTION_PROFILE['sha256'])
        p=json.loads(common.TRANSACTION_PROFILE_BYTES)
        self.assertEqual((len(p['files']),sum(r['size'] for r in p['files'])),(136,85445048))
        self.assertTrue(all(0<r['bytes']<=131072 for r in common.TRANSACTION_FILES.values()))
        self.assertNotIn('/usr/bin/setpriv',{r['path'] for r in p['files']})
    def test_closed_event_rejects_skip_missing_duplicate_private_or_unclean(self):
        common.transaction_event(self.event(),self.nonce,self.selection,self.source)
        for key,value in (('skips',1),('tests',2),('methods',self.methods()[:-1]),('class_cleanups_returned',False),
                          ('cancelled',True),('uid',0),('fixture_source','0'*40),('raw_private','SECRET')):
            e=self.event();e[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):common.transaction_event(e,self.nonce,self.selection,self.source)
        for index in (0,1,2):
            e=self.event();e['methods'][index]['calls'][0]['committed']=not e['methods'][index]['calls'][0]['committed']
            with self.assertRaises(ValueError):common.transaction_event(e,self.nonce,self.selection,self.source)
    def test_completion_requires_exact_order_natural_exit_and_source(self):
        good=[self.boot(),self.event(),self.exited()]
        run.validate_transaction_completion(good,self.nonce,self.selection,self.source)
        for events in (good[:-1],[good[1],good[0],good[2]],good+[self.event()],good+[dict(event='gbm_pass')],
                       [dict(self.boot(),page_size=True),*good[1:]],good+[dict(event='barrier_result')]):
            with self.assertRaises(ValueError):run.validate_transaction_completion(events,self.nonce,self.selection,self.source)
        for field,value in (('nonce','0'*32),('selection_sha256','0'*64),('returncode',1),('error','timeout')):
            events=copy.deepcopy(good);events[-1][field]=value
            with self.assertRaises(ValueError):run.validate_transaction_completion(events,self.nonce,self.selection,self.source)
    def fake_module(self, *, fail=None, cleanup_fail=None, skip=False, method_fail=None):
        owner=self;observed=[]
        class Cases(unittest.TestCase):
            execution_history=[]
            @classmethod
            def setUpClass(cls):
                cls.addClassCleanup(lambda:observed.append('last-cleanup'))
                def cleanup():
                    observed.append('first-cleanup')
                    if cleanup_fail is not None:raise cleanup_fail
                cls.addClassCleanup(cleanup)
                if fail is not None:raise fail
            def selected(self):
                if method_fail is not None:
                    self.addCleanup(lambda:observed.append('case-last-cleanup'))
                    def cleanup():
                        observed.append('case-first-cleanup');raise SystemExit(9)
                    self.addCleanup(cleanup)
                    raise method_fail
                if skip:self.skipTest('PRIVATE REASON')
                index=common.TRANSACTION_TESTS.index(self._testMethodName)
                type(self).execution_history.extend(dict(test=self._testMethodName) for p in common.TRANSACTION_CASES[index][2])
                observed.append(self._testMethodName)
        for name in common.TRANSACTION_TESTS:setattr(Cases,name,Cases.selected)
        return types.SimpleNamespace(ActualTransactionTests=Cases),observed
    def run_model(self,module):
        emitted=[];self.last_emitted=emitted
        def project(record,index,hop):
            self.assertEqual(record['test'],common.TRANSACTION_TESTS[index])
            return self.methods()[index]['calls'][hop]
        with patch.object(guest,'transaction_execution',side_effect=project),patch.object(guest,'emit',side_effect=lambda name,**row:emitted.append(dict(event=name,**row))), \
                patch.object(guest.os,'geteuid',return_value=23001),patch.object(guest.os,'getegid',return_value=23001):
            result=guest.transaction_test(module,{},self.nonce,self.selection,self.source)
        return result,emitted
    def test_real_testsuite_model_orders_sixteen_and_runs_class_cleanup(self):
        module,seen=self.fake_module();result,emitted=self.run_model(module)
        self.assertEqual(seen,[*common.TRANSACTION_TESTS,'first-cleanup','last-cleanup'])
        self.assertEqual(result['status'],'PASS_TRANSACTION_ONLY');self.assertEqual(len(emitted),1)
    def test_setup_cancel_and_cleanup_cancel_preserve_original_and_all_duties(self):
        primary=KeyboardInterrupt();secondary=SystemExit(7);module,seen=self.fake_module(fail=primary,cleanup_fail=secondary)
        with self.assertRaises(KeyboardInterrupt) as caught:self.run_model(module)
        self.assertIs(caught.exception,primary);self.assertEqual(seen,['first-cleanup','last-cleanup'])
    def test_method_cancel_drains_instance_and_class_cleanup_preserving_first(self):
        primary=KeyboardInterrupt();module,seen=self.fake_module(method_fail=primary)
        with self.assertRaises(KeyboardInterrupt) as caught:self.run_model(module)
        self.assertIs(caught.exception,primary)
        self.assertEqual(seen,['case-first-cleanup','case-last-cleanup','first-cleanup','last-cleanup'])
        self.assertEqual(self.last_emitted[0]['first_failure']['exception'],'KeyboardInterrupt')
        self.assertTrue(self.last_emitted[0]['cancelled']);self.assertEqual(self.last_emitted[0]['status'],'FAIL')
    def test_setup_or_class_cleanup_failure_and_skip_cannot_pass(self):
        for kw in (dict(fail=ValueError('PRIVATE')),dict(cleanup_fail=OSError(5,'PRIVATE')),dict(skip=True)):
            module,seen=self.fake_module(**kw)
            with self.subTest(kw=kw),self.assertRaises(ValueError):self.run_model(module)
            self.assertEqual(seen[-2:],['first-cleanup','last-cleanup'])
    def test_original_invalid_signature_needs_verify_failure_not_import_failure(self):
        record=dict(test=common.TRANSACTION_TESTS[3],worker_sha256=common.TRANSACTION_FILES['scripts/install/local_transaction.py']['sha256'],
                    worker_after_sha256=common.TRANSACTION_FILES['scripts/install/local_transaction.py']['sha256'],returncode=2,
                    report=dict(status='FAIL',phase='isolated',commit_started=False,committed=False),retained_evidence='/inert')
        for operation in ('--verify','--import'):
            auth=dict(argv=['/usr/bin/gpg','--batch',operation,'sig','archive'],returncode=2)
            with patch.object(guest,'identity_bytes',return_value=json.dumps(auth).encode()):
                if operation=='--verify':self.assertEqual(guest.transaction_execution(record,3)['phase'],'isolated')
                else:
                    with self.assertRaises(ValueError):guest.transaction_execution(record,3)
    def test_boot_real_drop_flags_private_output_and_declared_child_budget(self):
        c=dict(purpose=common.TRANSACTION_PURPOSE,nonce=self.nonce,proof_contract_sha256=self.selection,fixture_source=self.source)
        result=dict(stdout=guest.PREFIX+json.dumps(self.event())+'\n',stderr='',returncode=0,error=None)
        with patch.object(guest,'transaction_launcher') as launcher,patch.object(Path,'mkdir'),patch.object(Path,'chmod'), \
                patch.object(guest.os,'chown'),patch.object(guest,'bounded',return_value=result) as child,patch.object(guest,'emit'):
            guest.boot_transaction(c)
        launcher.assert_called_once_with(Path('/'));args=child.call_args.args[0]
        self.assertEqual(args[:7],['/usr/lib/ld-linux-aarch64.so.1','--inhibit-cache','--glibc-hwcaps-mask','','--library-path','/usr/lib','/usr/bin/setpriv'])
        for flag in ('--reuid=23001','--regid=23001','--clear-groups','--inh-caps=-all','--ambient-caps=-all','--bounding-set=-all','--no-new-privs'):
            self.assertIn(flag,args)
        self.assertEqual(child.call_args.kwargs['timeout'],900);self.assertEqual(child.call_args.kwargs['limit'],16384)
        self.assertEqual(args[-2:],[guest.__file__,'transaction-user']);self.assertNotIn('-I',args)
        self.assertNotIn('LD_PRELOAD',child.call_args.kwargs['env'])
    def test_boot_timeout_or_stderr_or_extra_event_refuses(self):
        c=dict(purpose=common.TRANSACTION_PURPOSE,nonce=self.nonce,proof_contract_sha256=self.selection,fixture_source=self.source)
        good=dict(stdout=guest.PREFIX+json.dumps(self.event())+'\n',stderr='',returncode=0,error=None)
        for variant in (dict(error='timeout'),dict(returncode=1),dict(stderr='PRIVATE'),dict(stdout=good['stdout']*2)):
            with patch.object(guest,'transaction_launcher'),patch.object(Path,'mkdir'),patch.object(Path,'chmod'),patch.object(guest.os,'chown'), \
                    patch.object(guest,'bounded',return_value=good|variant),patch.object(guest,'emit'),self.assertRaises(ValueError):
                guest.boot_transaction(c)
    def test_current_outer_and_old_barrier_budgets_remain_held(self):
        text=Path(run.__file__).read_text();tree=ast.parse(text)
        main=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
        self.assertIn('min(start + 1200, time.monotonic() + 900)',ast.get_source_segment(text,main))
        self.assertIn('signal.setitimer(signal.ITIMER_REAL, 1200)',ast.get_source_segment(text,main))
        self.assertIn('timeout=600',ast.get_source_segment(Path(guest.__file__).read_text(),next(n for n in ast.parse(Path(guest.__file__).read_text()).body if isinstance(n,ast.FunctionDef) and n.name=='boot_barrier')))
        self.assertIn('TimeoutStartSec=650',prepare.UNIT)
        for status in ('PASS_TRANSACTION_ONLY','PASS_BARRIER_ONLY','CAPTURED_REQUIRES_VISUAL_REVIEW'):
            ret=next(n for n in ast.walk(ast.parse(Path(controller.__file__).read_text())) if isinstance(n,ast.Return) and 'CANCELLED' in ast.unparse(n.value))
            self.assertTrue(eval(compile(ast.Expression(ret.value),'inert','eval'),dict(CANCELLED=False,report={'status':status})))
        self.assertFalse(eval(compile(ast.Expression(ret.value),'inert','eval'),dict(CANCELLED=True,report={'status':'PASS_TRANSACTION_ONLY'})))

    def test_early_guest_preflight_failure_precedes_test_code_and_has_closed_diagnostic(self):
        worker=b'def generic_preflight(*args): raise ValueError("PRIVATE PARENT FAILURE")\n'
        test=b'raise AssertionError("test/signing setup must not run")\n'
        files=copy.deepcopy(common.TRANSACTION_FILES)
        for name,body in zip(list(files)[:2],(worker,test)):files[name]=dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
        c=self.contract()|dict(nonce=self.nonce)
        raw=json.dumps(c).encode();selection=hashlib.sha256(raw).hexdigest()
        emitted=[];seen=[]
        def read(path,maximum):
            seen.append(str(path))
            return raw if path.name=='virtual-contract.json' else worker if path.name=='local_transaction.py' else test
        with patch.object(guest,'guest_guard'),patch.object(guest,'json_load',return_value=dict(nonce=self.nonce,proof_contract_sha256=selection)), \
                patch.object(guest,'identity_bytes',side_effect=read),patch.object(guest,'transaction_contract',return_value=True), \
                patch.object(guest,'TRANSACTION_FILES',files),patch.object(guest.os,'geteuid',return_value=23001), \
                patch.object(guest.os,'getegid',return_value=23001),patch.object(guest,'emit',side_effect=lambda name,**row:emitted.append(row)):
            with self.assertRaisesRegex(ValueError,'PRIVATE PARENT FAILURE'):guest.transaction_user()
        self.assertFalse(any(p.endswith('test_local_transaction.py') for p in seen))
        self.assertEqual(emitted[0]['tests'],0);self.assertEqual(emitted[0]['first_failure']['exception'],'ValueError')
        self.assertNotIn('PRIVATE',json.dumps(emitted))
    def test_failure_projection_stays_first_and_private_when_class_cleanup_also_fails(self):
        module,seen=self.fake_module(fail=ValueError('PRIVATE ORIGINAL'),cleanup_fail=OSError(5,'PRIVATE CLEANUP'))
        with self.assertRaises(ValueError):self.run_model(module)
        row=self.last_emitted[0]
        self.assertEqual(row['first_failure']['exception'],'ValueError');self.assertEqual(row['status'],'FAIL')
        self.assertFalse(row['class_cleanups_returned']);self.assertNotIn('PRIVATE',json.dumps(row))
    def test_launcher_guard_checks_alias_bytes_and_parent_protection(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            root=Path(tmp);files={}
            for name in ('/usr/bin/setpriv','/usr/lib/libcap-ng.so.0.0.0','/usr/lib/libc.so.6','/usr/lib/ld-linux-aarch64.so.1'):
                path=root/name.lstrip('/');path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(name.encode());path.chmod(0o755)
                files[name]=dict(bytes=len(name),sha256=hashlib.sha256(name.encode()).hexdigest())
            (root/'lib').symlink_to('usr/lib');(root/'usr/lib/libcap-ng.so.0').symlink_to('libcap-ng.so.0.0.0')
            original=Path.stat
            def metadata(path,*args,**kwargs):
                s=original(path,*args,**kwargs)
                return types.SimpleNamespace(**{name:getattr(s,name) for name in ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')},st_uid=0,st_gid=0)
            with patch.object(common,'TRANSACTION_LAUNCHER',dict(files=files,aliases=common.TRANSACTION_LAUNCHER['aliases'])),patch.object(Path,'stat',metadata):
                self.assertTrue(common.transaction_launcher(root))
                path=root/'usr/bin/setpriv';path.write_bytes(b'X'*len('/usr/bin/setpriv'))
                with self.assertRaises(ValueError):common.transaction_launcher(root)
                path.write_bytes(b'/usr/bin/setpriv');path.parent.chmod(0o777)
                with self.assertRaises(ValueError):common.transaction_launcher(root)
                path.parent.chmod(0o755);(root/'usr/lib/libcap-ng.so.0').unlink();(root/'usr/lib/libcap-ng.so.0').symlink_to('libc.so.6')
                with self.assertRaises(ValueError):common.transaction_launcher(root)
    def test_source_staging_refuses_changed_proof_before_copying(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).parent) as tmp:
            path=Path(tmp)/'proof.json';path.write_text('{}')
            with patch.object(prepare,'transaction_launcher') as launcher,patch.object(prepare,'changed') as changed,self.assertRaises(ValueError):
                prepare.stage_transaction(Path(tmp),self.contract(),path,'0'*64,{})
            launcher.assert_not_called();changed.assert_not_called()

    def record(self,index,hop=0):
        pattern=common.TRANSACTION_CASES[index][2][hop];call=self.call(pattern)
        body=dict(status=call.pop('worker_status'),**{k:v for k,v in call.items() if k!='returncode'})
        a,b='caa-install-fixture-a','caa-install-fixture-b'
        maps={'PAIR':({},{a:'1.0-1',b:'1.0-1'}),'ADD':({},{a:'1.0-1'}),'REMOVE':({a:'1.0-1'},{}),
              'UPGRADE':({a:'1.0-1'},{a:'2.0-1'}),'PROTECTED_ADD':({a:'1.0-1'},{a:'1.0-1',b:'1.0-1'})}
        if pattern in maps:body.update(before=maps[pattern][0],after=maps[pattern][1],installed_payload_verified=True,parent_export_verified=True)
        if pattern=='REFUSED':body.pop('phase')
        pin=common.TRANSACTION_FILES['scripts/install/local_transaction.py']['sha256']
        return dict(test=common.TRANSACTION_TESTS[index],worker_sha256=pin,worker_after_sha256=pin,
                    returncode=call['returncode'],report=body,retained_evidence='/inert')
    def test_fixed_definition_order_excludes_only_extra_contract_control(self):
        tree=ast.parse((Path(__file__).resolve().parents[1]/'install/test_local_transaction.py').read_text())
        cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='ActualTransactionTests')
        methods=[n.name for n in cls.body if isinstance(n,ast.FunctionDef) and n.name.startswith('test_')]
        self.assertEqual(len(methods),17)
        self.assertEqual(tuple(n for n in methods if n.startswith('test_actual_')),common.TRANSACTION_TESTS)
        self.assertEqual(sum(len(p) for _,_,p in common.TRANSACTION_CASES),21)
        self.assertEqual(len(json.dumps(self.event())),len(json.dumps(common.transaction_event(self.event(),self.nonce,self.selection,self.source))))
        self.assertLess(len(json.dumps(self.event())),8192)
    def test_every_positive_hop_requires_exact_maps_payload_and_export(self):
        for index,(_,_,patterns) in enumerate(common.TRANSACTION_CASES):
            for hop,pattern in enumerate(patterns):
                if pattern not in ('PAIR','ADD','REMOVE','UPGRADE','PROTECTED_ADD'):continue
                record=self.record(index,hop);guest.transaction_execution(record,index,hop)
                for key,value in (('before',{'foreign':'1'}),('after',{'foreign':'1'}),('installed_payload_verified',False),('parent_export_verified',False)):
                    bad=copy.deepcopy(record);bad['report'][key]=value
                    with self.subTest(index=index,hop=hop,key=key),self.assertRaises(ValueError):guest.transaction_execution(bad,index,hop)
    def test_conflict_started_and_refused_phase_not_invented(self):
        self.assertTrue(guest.transaction_execution(self.record(9),9)['commit_started'])
        for index in (10,11):
            row=guest.transaction_execution(self.record(index,1),index,1)
            self.assertEqual(row['phase'],'NOT_REPORTED');self.assertFalse(row['commit_started'])
            bad=self.record(index,1);bad['report']['phase']='prepare'
            with self.assertRaises(ValueError):guest.transaction_execution(bad,index,1)
    def test_signed_wrong_signer_and_escaping_require_original_verify_success(self):
        for index,message in ((2,'signature signer/status refused'),(7,'noncanonical payload path')):
            record=self.record(index);record['report']['error']=message
            for rc in (0,2):
                auth=dict(argv=['/usr/bin/gpg','--batch','--verify','sig','archive'],returncode=rc)
                with patch.object(guest,'identity_bytes',return_value=json.dumps(auth).encode()):
                    if rc==0:guest.transaction_execution(record,index)
                    else:
                        with self.assertRaises(ValueError):guest.transaction_execution(record,index)
            record['report']['error']='PRIVATE arbitrary reason'
            with patch.object(guest,'identity_bytes',return_value=json.dumps(dict(argv=['/usr/bin/gpg','--batch','--verify','s','a'],returncode=0)).encode()),self.assertRaises(ValueError):guest.transaction_execution(record,index)
    def test_secret_certificate_projection_does_not_invent_deciding_reason(self):
        record=self.record(4);record['report']['error']='PRIVATE import or key policy reason'
        row=guest.transaction_execution(record,4);self.assertEqual(row,self.call('SECRET'))
        self.assertNotIn('PRIVATE',json.dumps(row))
    def test_stale_history_refuses_before_class_setup(self):
        module,seen=self.fake_module();module.ActualTransactionTests.execution_history=[dict(test='stale')]
        with self.assertRaises(ValueError):self.run_model(module)
        self.assertEqual(seen,[]);self.assertEqual(self.last_emitted[0]['tests'],0)
    def test_wrong_method_record_or_extra_hop_cannot_pass(self):
        for kind in ('wrong','extra','missing'):
            module,seen=self.fake_module();original=module.ActualTransactionTests.selected
            def changed(test):
                original(test)
                if kind=='wrong':test.execution_history[-1]['test']='foreign'
                elif kind=='extra':test.execution_history.append(dict(test=test._testMethodName))
                else:test.execution_history.pop()
            setattr(module.ActualTransactionTests,common.TRANSACTION_TESTS[0],changed)
            with self.subTest(kind=kind),self.assertRaises((ValueError,AssertionError)):self.run_model(module)
            self.assertEqual(self.last_emitted[0]['status'],'FAIL')
    def test_later_two_hop_failure_retains_seed_prefix_and_class_cleanup(self):
        module,seen=self.fake_module()
        def partial(test):
            type(test).execution_history.append(dict(test=test._testMethodName))
            raise AssertionError('PRIVATE second operation missing')
        setattr(module.ActualTransactionTests,common.TRANSACTION_TESTS[10],partial)
        with self.assertRaises(ValueError):self.run_model(module)
        event=self.last_emitted[0]
        self.assertEqual(len(event['methods']),11);self.assertEqual(len(event['methods'][-1]['calls']),1)
        self.assertEqual(event['methods'][-1]['method'],'PROTECTED_UPGRADE')
        self.assertEqual(seen[-2:],['first-cleanup','last-cleanup']);self.assertNotIn('PRIVATE',json.dumps(event))
    def test_projection_cancellation_after_prior_methods_is_sticky(self):
        module,seen=self.fake_module();primary=KeyboardInterrupt()
        emitted=[]
        def project(record,index,hop):
            if index==10 and hop==1:raise primary
            return self.methods()[index]['calls'][hop]
        with patch.object(guest,'transaction_execution',side_effect=project),patch.object(guest,'emit',side_effect=lambda name,**row:emitted.append(row)), \
             patch.object(guest.os,'geteuid',return_value=23001),patch.object(guest.os,'getegid',return_value=23001),self.assertRaises(KeyboardInterrupt) as caught:
            guest.transaction_test(module,{},self.nonce,self.selection,self.source)
        self.assertIs(caught.exception,primary);self.assertTrue(emitted[0]['cancelled'])
        self.assertEqual(len(emitted[0]['methods'][-1]['calls']),1)
        self.assertEqual(seen[-2:],['first-cleanup','last-cleanup'])


if __name__=='__main__':unittest.main()
