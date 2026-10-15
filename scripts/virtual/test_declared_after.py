# SPDX-License-Identifier: MIT
"""Selected pure worker contracts and unchanged method; no signing/ALPM/VM actor."""
import ast
import copy
import hashlib
from pathlib import Path
import re
import types
import unittest
from unittest.mock import patch
import common
import guest

WORKER=Path(__file__).resolve().parents[1]/'install/local_transaction.py'
TEST=WORKER.with_name('test_local_transaction.py')

def pure_worker(path=WORKER):
    names={'need','package_map','declared_after','architecture_profile','validate_contract','cli_failure','GenericDeclaredAfterMismatch'}
    tree=ast.parse(path.read_bytes())
    nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names]
    ns=dict(re=re,MAX_PACKAGES=128,NAME=re.compile(r'[A-Za-z0-9][A-Za-z0-9@+_.-]{0,127}\Z'),
        HEX=re.compile(r'[0-9a-f]{64}\Z'),FPR=re.compile(r'[0-9A-F]{40}\Z'),
        LIBRARY_SHA='da30edd45277cf4b1000485658976042f8106fe0b97378d1e6c4e81a9d7c4888',
        NATIVE_LIBRARY_SHA='94c013b9026772ffe4f227f508a2cdf0c61323dc1f7b7836fe629b49bfbc3902',
        NATIVE_PROFILE_SHA='b7fbd65e357e132949432fb00e765a05e3c76ea29a41d1df93413870d9fd1ed8',
        GENERIC_SCOPE='generic-aarch64-fixture',OWNED_OUTPUT=None,Evidence=type('NeverEvidence',(),{}))
    exec(compile(ast.Module(body=nodes,type_ignores=[]),str(path),'exec'),ns)
    return types.SimpleNamespace(**ns)

class DeclaredAfter(unittest.TestCase):
    def setUp(self):self.m=pure_worker()
    def contract(self,mode='generic'):
        m=self.m
        c=dict(schema_version=3,scope=m.GENERIC_SCOPE,workspace='/inert',architecture='aarch64',
            before={},after={'caa-install-fixture-a':'1.0-1'},protected={},remove={},
            add=[dict(name='caa-install-fixture-a',version='1.0-1',archive={},signature={},signer='A'*40)],
            keyring={},timeout_seconds=90,libalpm_sha256=m.NATIVE_LIBRARY_SHA,
            profile_sha256=m.NATIVE_PROFILE_SHA,generic_vm_contract_sha256='b'*64)
        args=dict(generic_vm_contract_sha256='b'*64)
        if mode=='native':
            del c['generic_vm_contract_sha256'];c.update(schema_version=2,scope='native-aarch64-fixture',input_selection_sha256='b'*64)
            args=dict(selection_sha256='b'*64)
        elif mode=='x86':
            del c['generic_vm_contract_sha256'];del c['profile_sha256']
            c.update(schema_version=1,scope='synthetic-fixture',architecture='x86_64',libalpm_sha256=m.LIBRARY_SHA);args={}
        return c,args
    def test_valid_three_routes_are_unchanged_and_literal_never_admits(self):
        for mode in ('generic','native','x86'):
            c,args=self.contract(mode);self.assertIs(self.m.validate_contract(c,**args),c)
            c['after']['undeclared-extra']='1'
            with self.subTest(mode=mode),self.assertRaises(ValueError) as caught:self.m.validate_contract(c,**args)
            self.assertIs(type(caught.exception),self.m.GenericDeclaredAfterMismatch if mode=='generic' else ValueError)
    def test_exact_generic_literal_version_and_after_only_allowance(self):
        for field,value in (('after',{'undeclared-other':'1'}),('after',{'undeclared-extra':'2'}),
                ('before',{'undeclared-extra':'1'}),('protected',{'undeclared-extra':'1'}),('remove',{'undeclared-extra':'1'})):
            c,args=self.contract();c[field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError) as caught:self.m.validate_contract(c,**args)
            self.assertIs(type(caught.exception),ValueError)
        c,args=self.contract();c['add'][0]['name']='undeclared-extra';c['after']={'undeclared-extra':'1'}
        with self.assertRaises(ValueError) as caught:self.m.validate_contract(c,**args)
        self.assertIs(type(caught.exception),ValueError)
    def test_aliased_before_after_still_hits_name_guard_not_declaration_marker(self):
        c,args=self.contract();shared={'undeclared-extra':'1'};c['before']=c['after']=shared
        with self.assertRaises(ValueError) as caught:self.m.validate_contract(c,**args)
        self.assertIs(type(caught.exception),ValueError)
        self.assertNotIn('phase',self.m.cli_failure(caught.exception))
        self.assertIs(c['before'],c['after'])
    def test_marker_exact_type_not_text_or_subclass_and_no_commit(self):
        marker=self.m.GenericDeclaredAfterMismatch
        class Foreign(marker):pass
        for error in (ValueError('declared full after map differs'),Foreign('anything'),RuntimeError('declaration-after')):
            row=self.m.cli_failure(error);self.assertNotIn('phase',row)
            self.assertEqual(row,dict(status='REFUSED',commit_started=False,committed=False,output=None))
        self.assertEqual(self.m.cli_failure(marker('PRIVATE')),dict(status='REFUSED',commit_started=False,committed=False,output=None,phase='declaration-after'))
    def test_original_unchanged_method_hits_exact_equality_refusal_without_actor(self):
        tree=ast.parse(TEST.read_bytes());cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='ActualTransactionTests')
        method=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='test_declared_after_mismatch_refuses_before_commit')
        ns={};exec(compile(ast.Module(body=[method],type_ignores=[]),str(TEST),'exec'),ns)
        owner=self;seen=[]
        class Case(unittest.TestCase):
            def package(self):
                c,_=owner.contract();return c['add'][0],{}
            def contract(self,rows,after):
                c,_=owner.contract();c.update(add=rows,after=after);return c
            def assert_failure(self,c):
                try:owner.m.validate_contract(c,generic_vm_contract_sha256='b'*64)
                except owner.m.GenericDeclaredAfterMismatch as error:
                    tb=error.__traceback__
                    while tb.tb_next:tb=tb.tb_next
                    self.assertEqual(tb.tb_frame.f_code.co_name,'validate_contract')
                    line=ast.parse(WORKER.read_bytes());raising=next(n for n in ast.walk(line) if isinstance(n,ast.Raise) and isinstance(n.exc,ast.Call) and getattr(n.exc.func,'id',None)=='GenericDeclaredAfterMismatch')
                    self.assertEqual(tb.tb_lineno,raising.lineno);seen.append('exact-declaration-refusal')
                    return owner.m.cli_failure(error)
                self.fail('declared after unexpectedly admitted')
        ns[method.name](Case())
        self.assertEqual(seen,['exact-declaration-refusal'])
    def test_generic_earlier_selection_and_identity_refusals_cannot_claim_marker(self):
        for field,value in (('scope','real-candidate'),('architecture','x86_64'),('timeout_seconds',True),
                            ('profile_sha256','0'*64),('libalpm_sha256','0'*64),('schema_version',True)):
            c,args=self.contract();c['after']['undeclared-extra']='1';c[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError) as caught:self.m.validate_contract(c,**args)
            self.assertIs(type(caught.exception),ValueError);self.assertNotIn('phase',self.m.cli_failure(caught.exception))
    def test_selected_projection_requires_marker_without_reading_error_text(self):
        index=common.TRANSACTION_SELECTORS.index('DECLARED_AFTER');pin=common.TRANSACTION_FILES['scripts/install/local_transaction.py']['sha256']
        body=self.m.cli_failure(self.m.GenericDeclaredAfterMismatch('PRIVATE'))
        record=dict(test=common.TRANSACTION_TESTS[index],worker_sha256=pin,worker_after_sha256=pin,returncode=2,report=body)
        with patch.object(guest,'identity_bytes',side_effect=AssertionError('no archive/auth record read')):
            row=guest.transaction_execution(record,index)
            self.assertEqual(row['phase'],'declaration-after');self.assertNotIn('PRIVATE',str(row))
            for key,value in (('phase','NOT_REPORTED'),('commit_started',True),('committed',True),('status','FAIL')):
                bad=copy.deepcopy(record);bad['report'][key]=value
                with self.subTest(key=key),self.assertRaises(ValueError):guest.transaction_execution(bad,index)
    def test_first_refusal_precedes_generic_preflight_capture_and_output_creation(self):
        tree=ast.parse(WORKER.read_bytes());fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='execute')
        calls=[(n.lineno,n.func.id) for n in ast.walk(fn) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)]
        validate=next(line for line,name in calls if name=='validate_contract')
        self.assertLess(validate,next(line for line,name in calls if name=='generic_preflight'))
        self.assertLess(validate,next(line for line,name in calls if name=='private'))
        self.assertLess(validate,next(line for line,name in calls if name=='runtime'))
        self.assertEqual(hashlib.sha256(TEST.read_bytes()).hexdigest(),'1987ed23821da917215e9e3366545810d565ece08406fafd429a8c3c772eb2cd')

if __name__=='__main__':unittest.main()
