# SPDX-License-Identifier: MIT
"""Injected into a private pinned guest, never a host test entrypoint."""

def transaction_test(module, source_paths, nonce, selection, source):
    import unittest
    import types
    selected = FULL26_SELECTED
    order = [(cls, name) for cls, names in selected.items() for name in names]
    classes = [getattr(module, name) for name in selected]
    actual = module.ActualTransactionTests
    require(not getattr(actual,'execution_history',[]), 'stale full26 transaction history')
    actual.execution_history=[]
    original_selection = (module.FIXTURE_SELECTION_SHA256, module.GENERIC_VM_CONTRACT,
                          module.GENERIC_VM_CONTRACT_SHA256)
    require(original_selection[0] is None and all(v is not None for v in original_selection[1:]),
            'full26 requires separate generic selection')
    def functions():
        result=[]
        for value in vars(module).values():
            if isinstance(value, types.FunctionType) and value.__module__ == module.__name__:result.append(value)
            elif isinstance(value, type) and value.__module__ == module.__name__:
                for function in vars(value).values():
                    if isinstance(function,(staticmethod,classmethod)):function=function.__func__
                    if isinstance(function,types.FunctionType):result.append(function)
        return tuple(result)
    identities=functions()
    bound=[(f,f.__code__,f.__globals__,f.__defaults__,f.__kwdefaults__,f.__closure__) for f in identities]
    def guards():
        require(functions()==identities and all(f.__code__ is code and f.__globals__ is glob and
                f.__defaults__ is defaults and f.__kwdefaults__ is kwdefaults and f.__closure__ is closure
                for f,code,glob,defaults,kwdefaults,closure in bound), 'full26 loaded function drift')
        for name, row in TRANSACTION_FILES.items():
            raw = identity_bytes(Path(source_paths_inverse[name]), 128*1024)
            require(len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256'],
                    'full26 held source changed')
    # source_paths carries existing closed frame labels; source roots stay fixed.
    source_root = Path(module.__file__).parents[2]
    source_paths_inverse = {name: str(source_root/name) for name in TRANSACTION_FILES}
    class Result(unittest.TestResult):
        def __init__(self):
            super().__init__(); self.methods=[]; self.duties=[]; self.first_failure=None
            self.cancellation=None; self.cursor=0; self.active=None; self.collected=False
        def startTest(self, test):
            guards()
            expected = order[len(self.duties)]
            require((type(test).__name__, test._testMethodName) == expected, 'full26 exact method order')
            require(len(actual.execution_history) == sum(len(r['calls']) for r in self.methods), 'full26 worker history cursor')
            self.cursor=len(actual.execution_history);self.active=test;self.collected=False
            if type(test) is module.BarrierTests:
                # The unchanged barrier uses this truthy marker only to choose
                # AArch64 syscall numbers; it never enters native_authority.
                module.FIXTURE_SELECTION_SHA256=selection
                module.GENERIC_VM_CONTRACT=module.GENERIC_VM_CONTRACT_SHA256=None
            else:
                require((module.FIXTURE_SELECTION_SHA256,module.GENERIC_VM_CONTRACT,module.GENERIC_VM_CONTRACT_SHA256)
                        == original_selection, 'full26 generic authority drift')
            super().startTest(test)
        def stopTest(self, test):
            module.FIXTURE_SELECTION_SHA256,module.GENERIC_VM_CONTRACT,module.GENERIC_VM_CONTRACT_SHA256=original_selection
            super().stopTest(test)
        def collect(self, test, status):
            if test is not self.active or self.collected:return
            guards(); index=len(self.methods); entries=actual.execution_history[self.cursor:]
            if type(test) is actual:
                require(index < 17 and test._testMethodName == TRANSACTION_TESTS[index] and
                        len(entries) <= len(TRANSACTION_CASES[index][2]), 'full26 transaction history shape')
                calls=[transaction_execution(r,index,hop) for hop,r in enumerate(entries)]
                row=dict(method=TRANSACTION_SELECTORS[index],calls=calls)
                transaction_method(row,index,complete=status=='PASS');self.methods.append(row)
            else:require(not entries, 'nontransaction duty cannot create transaction history')
            self.duties.append(dict(cls=type(test).__name__,method=test._testMethodName,status=status))
            self.collected=True
        def failed(self, test, error, kind):
            if self.first_failure is None:self.first_failure=barrier_failure(error,source_paths,TRANSACTION_FRAME_LINES)
            if error[0] in (KeyboardInterrupt,SystemExit):self.cancellation=error[1]
            getattr(self,kind).append((test,'closed original method failure'));self.stop()
            try:self.collect(test,'FAIL' if kind=='failures' else 'ERROR')
            except BaseException:pass
        def addFailure(self,test,error):self.failed(test,error,'failures')
        def addError(self,test,error):self.failed(test,error,'errors')
        def addSkip(self,test,reason):
            self.skipped.append((test,'closed original method skip'));self.stop();self.collect(test,'SKIP')
        def addSuccess(self,test):
            try:self.collect(test,'PASS')
            except BaseException:self.addError(test,sys.exc_info())
    result=Result();cases=[getattr(module,c)(n) for c,n in order]
    suite=unittest.TestSuite(cases)
    try:
        require(not actual.execution_history, 'stale full26 transaction history')
        suite.run(result)  # Preserve real setUpClass/tearDownClass and registered cleanups.
    except BaseException:result.addError(None,sys.exc_info())
    finally:
        module.FIXTURE_SELECTION_SHA256,module.GENERIC_VM_CONTRACT,module.GENERIC_VM_CONTRACT_SHA256=original_selection
        stacks=[(case,getattr(case,'_cleanups',[])) for case in cases]
        stacks += [(None,getattr(cls,'_class_cleanups',[])) for cls in classes]
        for case,pending in stacks:
            # SourceLoaderTests registers four base cleanups and up to two
            # extra capsule FDs. The old transaction-only cap4 cannot cover it.
            if len(pending)>6:
                try:require(False,'unexpected original cleanup stack')
                except ValueError:result.addError(case,sys.exc_info())
                continue
            while pending:
                function,args,kwargs=pending.pop()
                try:function(*args,**kwargs)
                except BaseException:result.addError(case,sys.exc_info())
        row=dict(event='transaction_result',nonce=nonce,selection_sha256=selection,fixture_source=source,
            uid=os.geteuid(),gid=os.getegid(),tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),
            skips=len(result.skipped),status='FAIL',methods=result.methods,duties=result.duties,
            first_failure=result.first_failure,class_cleanups_returned=not any(s for _,s in stacks) and not result.errors,
            cancelled=result.cancellation is not None,scope='GENERIC_ARM_FULL26_ORIGINAL_METHODS_SOFTWARE_ONLY',
            barrier_report=getattr(module.BarrierTests,'last_report',None))
        if result.testsRun==26 and result.wasSuccessful() and not result.skipped and result.first_failure is None and len(actual.execution_history)==22:
            row['status']='PASS_GENERIC_ARM_FULL26'
        transaction_event(row,nonce,selection,source)
        emit('transaction_result',**{k:v for k,v in row.items() if k!='event'})
    if result.cancellation is not None:raise result.cancellation
    require(row['status']=='PASS_GENERIC_ARM_FULL26','full26 original matrix failed')
    return row
