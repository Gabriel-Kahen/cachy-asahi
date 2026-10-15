# SPDX-License-Identifier: MIT
"""Captured graph and caller-deadline controls; no Docker/native/GPG actors."""
import ast
import builtins
from contextlib import contextmanager
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

HERE=Path(__file__).absolute().parent
spec=importlib.util.spec_from_file_location('ksm_producer_driver_fixture',HERE/'producer_driver.py')
driver=importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)
ROOT=HERE.parents[2]
IMAGE='sha256:'+'1'*64
COMMAND=['docker','run','--rm','--pull=never','--network=none','--cap-drop=ALL',
         '--security-opt=no-new-privileges','--read-only','--entrypoint=/bin/cat',IMAGE,'/builder-packages.lock']


class _TestOnlyEntry(Exception):
    """Stop an authentic function at entry, before any actor or producer body."""


class _TestOnlyFacade:
    def __init__(self, module, original, calls, action=None):
        self.module,self.original,self.calls,self.action=module,original,calls,action
        self.primary=None; self.refusals=[]
    def run(self,*args,**kwargs):
        previous=sys.getprofile(); previous_trace=sys.gettrace(); result=['reply']
        self.primary=None; self.refusals=[]
        def trace(frame,event,arg):
            if event=='exception' and frame.f_globals is driver.__dict__ and type(arg[1]) is ValueError:
                self.refusals.append(arg[1].args)
            return trace
        def profile(frame,event,arg):
            if event=='call' and frame.f_code is self.original.__code__ and frame.f_globals is self.original.__globals__:
                values=frame.f_locals
                self.calls.append((values['command'],values['log'],values['timeout']))
                if self.action is not None: result[0]=self.action(*self.calls[-1])
                self.primary=_TestOnlyEntry()
                raise self.primary
        sys.setprofile(profile); sys.settrace(trace)
        try:
            try: return self.module.run(*args,**kwargs)
            except _TestOnlyEntry as error:
                if error is not self.primary: raise
                return result[0]
        finally:
            sys.settrace(previous_trace); sys.setprofile(previous)


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name); self.root=self.base/'source'; self.root.mkdir(mode=0o700)
        self.private=self.base/'private'; self.private.mkdir(mode=0o700); self.output=self.private/'producer'
        for relative,_ in driver.SOURCES.values():
            path=self.root/relative; path.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(ROOT/relative,path); path.chmod(0o644)
        self.end=time.monotonic()+20

    def graph(self):
        return driver.load_graph(self.root,deadline=self.end)

    def image(self, mode=0o644):
        self.output.mkdir(mode=0o700)
        p=self.output/'image-id'; p.write_text(IMAGE+'\n'); p.chmod(mode)
        return p

    def wrapped(self, original=None):
        parent=driver.bind_output(self.root,self.output); self.image()
        context=self.graph(); module,guard=context.__enter__(); self.addCleanup(context.__exit__,None,None,None)
        source_run=module.run; calls=[]
        driver.wrap_run(module,self.output,deadline=self.end,guard=guard,parent_identity=parent)
        return _TestOnlyFacade(module,source_run,calls,original),calls

    def state(self):
        return (dict(sys.modules),list(sys.path),list(sys.meta_path),list(sys.path_hooks),dict(sys.path_importer_cache),
                {k:getattr(builtins,k) for k in ('__import__','compile','exec')})

    def test_actual_copied_graph_load_and_caller_state_restore(self):
        before=self.state()
        with self.graph() as (native,guard):
            self.assertEqual(native.__name__,'_ksm_native_arm'); self.assertEqual(native.recipe.__module__,'_ksm_package_checks')
            self.assertEqual(native.__file__,str(self.root/'scripts/ci/native_arm.py')); guard()
            self.assertIsNot(native.subprocess,sys.modules.get('foreign_subprocess'))
        self.assertEqual(self.state(),before)

    def test_foreign_project_stdlib_cache_paths_finders_hooks_builtins_ignored(self):
        foreign=types.ModuleType('json'); foreign.__file__='/usr/lib/python3.14/json/__init__.py'
        foreign.loads=lambda *a:(_ for _ in ()).throw(AssertionError('poison cache'))
        project=types.ModuleType('package_checks'); project.recipe=lambda *a:(_ for _ in ()).throw(AssertionError('foreign project'))
        class BadFinder:
            def find_spec(self,*args): raise AssertionError('foreign finder')
        def bad(*args,**kwargs): raise AssertionError('foreign import/compile/exec/hook')
        saved=self.state()
        try:
            sys.modules['json']=foreign; sys.modules['package_checks']=project; sys.path.insert(0,str(self.base/'foreign'))
            sys.meta_path[:]=[BadFinder()]; sys.path_hooks[:]=[bad]; sys.path_importer_cache['bad']='bad'
            builtins.__import__=bad; builtins.compile=bad; builtins.exec=bad
            poisoned=self.state()
            with self.graph() as (native,guard):
                self.assertIsNot(native.json,foreign); self.assertIsNot(native.recipe,project.recipe)
                self.assertEqual(native.json.loads('{"ok":true}'),{'ok':True}); guard()
            self.assertEqual(self.state(),poisoned)
        finally:
            modules,paths,meta,hooks,cache,operations=saved
            sys.modules.clear(); sys.modules.update(modules); sys.path[:]=paths; sys.meta_path[:]=meta
            sys.path_hooks[:]=hooks; sys.path_importer_cache.clear(); sys.path_importer_cache.update(cache)
            for k,v in operations.items(): setattr(builtins,k,v)

    def test_authenticated_code_defaults_globals_policy_and_class_poison_refused_restored(self):
        def marker(*args,**kwargs): return 'INERT_UNREVIEWED_CODE'
        changes={
            'peer_same_run_code':lambda n,g:setattr(n.run,'__code__',marker.__code__),
            'main_code':lambda n,g:setattr(n.main,'__code__',marker.__code__),
            'recipe_defining_graph_code':lambda n,g:setattr(n.recipe,'__code__',marker.__code__),
            'class_method_code':lambda n,g:setattr(n.AcquisitionError.__init__,'__code__',marker.__code__),
            'run_defaults':lambda n,g:setattr(n.run,'__defaults__',(None,999999)),
            'run_kwdefaults':lambda n,g:setattr(n.run,'__kwdefaults__',{'unreviewed':True}),
            'function_attributes':lambda n,g:setattr(n.run,'__dict__',{'unreviewed':True}),
            'subprocess_global':lambda n,g:setattr(n,'subprocess',types.SimpleNamespace(check_output=marker)),
            'main_global_delete':lambda n,g:n.__dict__.pop('main'),
            'extra_global':lambda n,g:n.__dict__.update(unreviewed=True),
            'global_root_path':lambda n,g:n.ROOT._raw_paths.__setitem__(0,'/foreign-source'),
            'package_policy_set':lambda n,g:n.recipe.__globals__['PROTECTED_PACKAGES'].clear(),
            'package_fields_set':lambda n,g:n.recipe.__globals__['FIELDS'].clear(),
            'package_arch_fields':lambda n,g:n.recipe.__globals__['ARCH_FIELDS'].clear(),
            'builtin_binding':lambda n,g:n.__dict__['__builtins__'].__setitem__('__import__',marker),
            'class_method_slot':lambda n,g:setattr(n.AcquisitionError,'__init__',marker),
            'stdlib_check_output_code':lambda n,g:setattr(n.subprocess.check_output,'__code__',marker.__code__),
            'stdlib_json_loads_slot':lambda n,g:setattr(n.json,'loads',marker),
            'guard_disk_code':lambda n,g:setattr(g._disk,'__code__',n.run.__code__),
        }
        for label,change in changes.items():
            with self.subTest(case=label):
                before=self.state()
                with self.assertRaises((ValueError,KeyError)):
                    with self.graph() as (native,guard):
                        original=native.run; code=original.__code__; defaults=original.__defaults__; main=native.main
                        change(native,guard)
                        self.assertIs(driver._GRAPHS[id(native)][3],original)
                        driver.wrap_run(native,self.output,deadline=self.end,guard=guard,parent_identity=driver.directory(self.private))
                self.assertIs(native.run,original); self.assertIs(original.__code__,code)
                self.assertIs(original.__defaults__,defaults); self.assertIs(native.main,main)
                self.assertNotIn(id(native),driver._GRAPHS); self.assertNotIn(id(guard),driver._GUARDS)
                self.assertEqual(self.state(),before)

    def test_importer_code_defaults_closure_and_cells_refused_restored(self):
        for label in ('code','defaults','closure_cell','empty_cell'):
            with self.subTest(case=label),self.assertRaises(ValueError):
                with self.graph() as (native,guard):
                    importer=native.__dict__['__builtins__']['__import__']; oldcode=importer.__code__
                    cell=importer.__closure__[0]; oldcontent=cell.cell_contents
                    if label=='code':
                        # Same freevar count, different bytecode; no function body executed.
                        importer.__code__=importer.__code__.replace(co_firstlineno=999999)
                    elif label=='defaults': importer.__defaults__=(None,None,(),999999)
                    elif label=='closure_cell': cell.cell_contents=object()
                    else: del cell.cell_contents
                    guard()
            self.assertIs(importer.__code__,oldcode); self.assertIs(cell.cell_contents,oldcontent)

    def test_readonly_guard_wrapper_and_postinstall_slot_poison(self):
        parent=driver.bind_output(self.root,self.output); self.image()
        for slot in ('_native','_original','_guard','_output','_end','_parent'):
            with self.subTest(slot=slot),self.assertRaises(ValueError):
                with self.graph() as (native,guard):
                    original=native.run
                    driver.wrap_run(native,self.output,deadline=self.end,guard=guard,parent_identity=parent)
                    wrapper=native.run
                    for attr in ('__class__','__code__','__closure__',slot):
                        with self.assertRaises(AttributeError): setattr(wrapper,attr,object())
                    object.__setattr__(wrapper,slot,object())
                    wrapper(COMMAND,timeout=60)
            self.assertIs(native.run,original)

    def test_guard_slot_poison_checked_by_independent_anchor(self):
        for slot in ('_disk','_custody'):
            with self.subTest(slot=slot),self.assertRaises(ValueError):
                with self.graph() as (native,guard):
                    for attr in ('__class__','__code__','__closure__',slot):
                        with self.assertRaises(AttributeError): setattr(guard,attr,object())
                    object.__setattr__(guard,slot,object())
                    guard()

    def test_installed_run_replacement_refuses_before_context_restoration(self):
        with self.assertRaises(ValueError):
            with self.graph() as (native,guard):
                original=native.run
                driver.wrap_run(native,self.output,deadline=self.end,guard=guard,parent_identity=driver.directory(self.private))
                native.run=lambda *args: 'INERT_UNREVIEWED_CODE'
        self.assertIs(native.run,original); self.assertNotIn(id(native),driver._GRAPHS)

    def test_late_test_only_entry_poison_never_delegates_or_leaks(self):
        def poison(*args):
            live=self.subject
            live.main.__code__=live.main.__code__.replace(co_firstlineno=999999)
            return 'late unreviewed result'
        facade,calls=self.wrapped(poison); self.subject=facade.module
        # This context intentionally fails at entry and again at exit; close it here.
        cleanup=self._cleanups.pop(); close,args,kwargs=cleanup
        # The inert entry exception is the primary: held policy preserves it
        # over a later custody refusal. Always close the graph, even if a test
        # assertion fails, so quarantine cannot leak into the next import.
        try:
            self.assertEqual(facade.run(COMMAND,timeout=60),'late unreviewed result')
            self.assertIsInstance(facade.primary,_TestOnlyEntry)
            self.assertIn(('producer-code-custody',),facade.refusals)
        finally:
            with self.assertRaisesRegex(ValueError,'producer-code-custody'): close(*args,**kwargs)
        self.assertEqual(len(calls),1); self.assertNotIn(id(self.subject),driver._GRAPHS)

    def test_late_fixture_assertion_failure_restores_caller_and_next_import(self):
        before=self.state(); profile=sys.getprofile(); trace=sys.gettrace()
        handlers={s:signal.getsignal(s) for s in (signal.SIGINT,signal.SIGTERM)}
        mask=signal.pthread_sigmask(signal.SIG_BLOCK,set())
        with self.assertRaisesRegex(AssertionError,'^injected fixture assertion$'):
            with patch.object(self,'assertEqual',side_effect=AssertionError('injected fixture assertion')):
                self.test_late_test_only_entry_poison_never_delegates_or_leaks()
        self.assertEqual(self.state(),before)
        self.assertIs(sys.getprofile(),profile); self.assertIs(sys.gettrace(),trace)
        self.assertEqual({s:signal.getsignal(s) for s in handlers},handlers)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK,set()),mask)
        self.assertFalse(driver._GRAPHS); self.assertFalse(driver._GUARDS)
        self.test_machinery_export_replacements_do_not_rebuild_trusted_hook()

    def test_role_expiry_still_restores_graph_and_caller_state(self):
        before=self.state(); end=self.end
        context=self.graph(); native,guard=context.__enter__(); original=native.run
        driver.wrap_run(native,self.output,deadline=end,guard=guard,parent_identity=driver.directory(self.private))
        # The fixed original end expires; no new phase clock is created.
        with patch.object(driver.time,'monotonic',return_value=end+1),self.assertRaises(ValueError): context.__exit__(None,None,None)
        self.assertIs(native.run,original); self.assertNotIn(id(native),driver._GRAPHS); self.assertEqual(self.state(),before)

    def test_custody_collection_bound_refuses_and_restores(self):
        with self.assertRaises(ValueError):
            with self.graph() as (native,guard):
                native.__dict__.update((f'unreviewed{i}',i) for i in range(4100)); guard()
        self.assertNotIn('unreviewed0',native.__dict__)

    def test_module_subclass_rejected_before_foreign_attribute_dispatch(self):
        hits=[]
        class ForeignModule(types.ModuleType):
            def __getattribute__(self,name):
                hits.append(name); return types.ModuleType.__getattribute__(self,name)
        with self.assertRaises(ValueError):
            with self.graph() as (native,guard):
                namespace=vars(native); native.__class__=ForeignModule; guard()
        self.assertEqual(hits,[]); self.assertIs(type(native),types.ModuleType); self.assertIs(vars(native),namespace)

    def test_untrusted_path_elements_and_namespace_keys_never_invoke_methods(self):
        hits=[]
        class Foreign:
            def __eq__(self,other): hits.append('eq'); return True
            def __fspath__(self): hits.append('fspath'); return '/foreign'
            def __str__(self): hits.append('str'); return '/foreign'
            def __hash__(self): return hash('run')
        for case in ('path','key'):
            with self.subTest(case=case),self.assertRaises(ValueError):
                with self.graph() as (native,guard):
                    if case=='path': native.ROOT._raw_paths[0]=Foreign()
                    else:
                        # No collision with existingkeys during insertion; validation must
                        # reject the non-string key before stringcomparison orlookup.
                        class Key(Foreign):
                            def __hash__(self): return 123456789
                        native.__dict__[Key()]=True
                    guard()
            self.assertEqual(hits,[])
        parent=driver.bind_output(self.root,self.output); self.image()
        with self.assertRaises(ValueError):
            with self.graph() as (native,guard):
                driver.wrap_run(native,self.output,deadline=self.end,guard=guard,parent_identity=parent)
                native.run._output._raw_paths[0]=Foreign(); native.run(COMMAND,timeout=60)
        self.assertEqual(hits,[])

    def test_signal_builtin_quarantine_preserves_handlers_mask_and_runtime_deferral(self):
        code=r"""import importlib.util,os,signal,sys,time,types
from pathlib import Path
p=Path(sys.argv[1]); spec=importlib.util.spec_from_file_location('signal_driver',p)
driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
builtin=sys.modules['_signal']
def handler(signum,frame): pass
signal.signal(signal.SIGINT,handler);signal.signal(signal.SIGTERM,handler)
oldmask=signal.pthread_sigmask(signal.SIG_BLOCK,{signal.SIGUSR1})
expectedmask=signal.pthread_sigmask(signal.SIG_BLOCK,set())
expected={s:signal.getsignal(s) for s in (signal.SIGINT,signal.SIGTERM)}
foreign=types.ModuleType('_signal');foreign.__spec__=types.SimpleNamespace(origin='built-in')
sys.modules['_signal']=foreign
with driver.load_graph(p.parents[3],deadline=time.monotonic()+20) as (native,guard):
 assert native.subprocess.signal._signal is builtin
 assert {s:signal.getsignal(s) for s in expected}==expected
 assert signal.pthread_sigmask(signal.SIG_BLOCK,set())==expectedmask
assert sys.modules['_signal'] is foreign
assert {s:signal.getsignal(s) for s in expected}==expected
assert signal.pthread_sigmask(signal.SIG_BLOCK,set())==expectedmask
sys.modules['_signal']=builtin
runtime_path=Path(sys.argv[2]); spec=importlib.util.spec_from_file_location('signal_follow_on_runtime',runtime_path)
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
with runtime.defer_signals() as events: os.kill(os.getpid(),signal.SIGINT)
assert events==[signal.SIGINT]
assert {s:signal.getsignal(s) for s in expected}==expected
assert signal.pthread_sigmask(signal.SIG_BLOCK,set())==expectedmask
signal.pthread_sigmask(signal.SIG_SETMASK,oldmask)
print('trusted builtin identity, custom handlers, nonempty mask, real runtime deferral: PASS')
"""
        result=subprocess.run([sys.executable,'-I','-B','-S','-c',code,str(HERE/'producer_driver.py'),str(HERE/'runtime.py')],
                              capture_output=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr.decode()); self.assertIn(b'PASS',result.stdout)

    def test_machinery_export_replacements_do_not_rebuild_trusted_hook(self):
        def bad(*args,**kwargs): raise AssertionError('foreign loader/hook')
        before=self.state()
        with patch.object(driver.machinery,'FileFinder',types.SimpleNamespace(path_hook=bad)), \
             patch.object(driver.machinery,'ExtensionFileLoader',bad), \
             patch.object(driver.machinery,'EXTENSION_SUFFIXES',['.foreign']), \
             patch.object(driver.machinery,'SOURCE_SUFFIXES',['.foreign']):
            with self.graph() as (native,guard):
                self.assertEqual(native.json.loads('{"safe":1}'),{'safe':1}); guard()
        self.assertEqual(self.state(),before)

    def test_foreign_project_pyc_never_executes(self):
        p=self.root/'scripts/checks/package_checks.pyc'; p.write_bytes(b'foreign sourceless code')
        with self.graph() as (native,_): self.assertEqual(native.recipe.__module__,'_ksm_package_checks')
        (self.root/'scripts/checks/package_checks.py').unlink()
        with self.assertRaises(OSError):
            with self.graph(): self.fail('missing source accepted')

    def test_both_sources_hash_and_mode_refused_before_load(self):
        for relative,_ in driver.SOURCES.values():
            p=self.root/relative; raw=p.read_bytes()
            with self.subTest(relative=relative,change='hash'):
                p.write_bytes(raw+b'\n# stale\n')
                with self.assertRaises(ValueError):
                    with self.graph(): self.fail('stale source accepted')
                p.write_bytes(raw)
            with self.subTest(relative=relative,change='mode'):
                p.chmod(0o600)
                with self.assertRaises(ValueError):
                    with self.graph(): self.fail('wrong mode accepted')
                p.chmod(0o644)

    def test_same_bytes_inode_replacement_is_sticky_refusal(self):
        p=self.root/'scripts/checks/package_checks.py'; before=self.state()
        with self.assertRaisesRegex(ValueError,'producer-source-drift'):
            with self.graph():
                q=p.with_suffix('.replacement'); q.write_bytes(p.read_bytes()); q.chmod(0o644); q.replace(p)
        self.assertEqual(self.state(),before)

    def test_source_mutation_restores_state_even_body_failure(self):
        p=self.root/'scripts/ci/native_arm.py'; before=self.state()
        with self.assertRaisesRegex(RuntimeError,'^body refused$'):
            with self.graph():
                p.write_bytes(p.read_bytes()+b'\n# changed\n'); raise RuntimeError('body refused')
        self.assertEqual(self.state(),before)

    def test_compile_failure_restores_state(self):
        before=self.state()
        with patch.object(driver.SourceOnly,'get_code',side_effect=ValueError('fixture compiler refusal')):
            with self.assertRaises(ValueError):
                with self.graph(): self.fail('failed compiler accepted')
        self.assertEqual(self.state(),before)

    def test_project_import_graph_is_closed(self):
        with self.graph() as (native,_):
            importer=native.__dict__['__builtins__']['__import__']
            for name,level in [('foreign_project',0),('integration',0),('package_checks',1)]:
                expected=ValueError if level else ModuleNotFoundError
                with self.subTest(name=name,level=level),self.assertRaises(expected) as caught:
                    importer(name,native.__dict__,fromlist=('recipe',),level=level)
                if not level:
                    self.assertIs(type(caught.exception),ModuleNotFoundError)
                    self.assertEqual(caught.exception.name,name)
                    self.assertEqual(driver.refusal_record(caught.exception,'GRAPH_LOAD'),
                        dict(schema_version=1,last_source_gate='GRAPH_LOAD',predicate='producer-unbound-import',rejected_import_root=name))

    def test_expired_graph_refuses_without_loading(self):
        self.end=time.monotonic()-1
        with self.assertRaises(ValueError):
            with self.graph(): self.fail('expired graph accepted')

    def test_source_symlink_and_hardlink_refused(self):
        p=self.root/'scripts/ci/native_arm.py'; raw=p.read_bytes(); p.unlink(); other=self.base/'other'; other.write_bytes(raw)
        p.symlink_to(other)
        with self.assertRaises(OSError):
            with self.graph(): self.fail('source symlink accepted')
        p.unlink(); os.link(other,p)
        with self.assertRaises(ValueError):
            with self.graph(): self.fail('hardlinked source accepted')

    def test_source_ancestor_symlink_refused(self):
        p=self.root/'scripts/checks'; other=self.root/'scripts/foreign'; p.rename(other); p.symlink_to(other,target_is_directory=True)
        with self.assertRaises(OSError):
            with self.graph(): self.fail('symlinked ancestor accepted')

    def test_original_output_remains_absent_until_native(self):
        driver.bind_output(self.root,self.output); self.assertFalse(self.output.exists())
        self.output.mkdir(mode=0o700)
        with self.assertRaises(ValueError): driver.bind_output(self.root,self.output)

    def test_output_requires_private_parent_and_outside_source(self):
        self.private.chmod(0o755)
        with self.assertRaises(ValueError): driver.bind_output(self.root,self.output)
        with self.assertRaises(ValueError): driver.bind_output(self.root,self.root/'out')

    def test_exact_inventory_timer_extends_only_to_fixed_cap(self):
        self.end=time.monotonic()+500; module,calls=self.wrapped()
        self.assertEqual(module.run(COMMAND,timeout=60),'reply')
        self.assertEqual(len(calls),1); self.assertEqual(calls[0][:2],(COMMAND,None)); self.assertEqual(calls[0][2],180)

    def test_inventory_clipped_to_existing_absolute_end(self):
        module,calls=self.wrapped(); module.run(COMMAND,timeout=60)
        self.assertGreater(calls[0][2],0); self.assertLessEqual(calls[0][2],20)

    def test_all_argv_changes_and_other_timeouts_forward_identically(self):
        module,calls=self.wrapped()
        for index in range(len(COMMAND)):
            changed=COMMAND.copy(); changed[index]+='-changed'; module.run(changed,timeout=60)
            self.assertIs(calls[-1][0],changed); self.assertEqual(calls[-1][1:],(None,60))
        for timeout in (30,120,1800,60.0,True,None):
            module.run(COMMAND,timeout=timeout); self.assertIs(calls[-1][2],timeout)
        logged=self.base/'private-driver.log'; module.run(COMMAND,logged,60); self.assertEqual(calls[-1][1],logged); self.assertEqual(calls[-1][2],60)
        query=['docker','image','inspect',IMAGE]; module.run(query,timeout=60); self.assertEqual(calls[-1],(query,None,60))

    def test_image_private_safe_0600_and_0644(self):
        module,calls=self.wrapped()
        for mode in (0o600,0o644):
            (self.output/'image-id').chmod(mode); module.run(COMMAND,timeout=60)
        self.assertEqual(len(calls),2)

    def test_image_binding_wrong_bytes_mode_link_size_missing_refused(self):
        module,calls=self.wrapped(); p=self.output/'image-id'; raw=p.read_bytes()
        for data in (b'latest\n',b'sha256:'+b'2'*64+b'\n',b'x'*129,b''):
            p.write_bytes(data)
            with self.assertRaises(ValueError): module.run(COMMAND,timeout=60)
        p.write_bytes(raw); p.chmod(0o666)
        with self.assertRaises(ValueError): module.run(COMMAND,timeout=60)
        p.chmod(0o644); other=self.base/'image'; other.write_bytes(raw); p.unlink(); p.symlink_to(other)
        with self.assertRaises(OSError): module.run(COMMAND,timeout=60)
        p.unlink()
        with self.assertRaises(OSError): module.run(COMMAND,timeout=60)
        self.assertEqual(calls,[])

    def test_image_post_forward_drift_refuses(self):
        def mutate(*args): (self.output/'image-id').write_text(IMAGE+' \n'); return 'late'
        module,_=self.wrapped(mutate)
        self.assertEqual(module.run(COMMAND,timeout=60),'late')
        self.assertIsInstance(module.primary,_TestOnlyEntry)
        self.assertIn(('producer-image-drift',),module.refusals)

    def test_private_parent_identity_drift_refuses_before_forward(self):
        module,calls=self.wrapped(); old=self.base/'old'; self.private.rename(old); self.private.mkdir(mode=0o700)
        self.output.mkdir(mode=0o700); (self.output/'image-id').write_text(IMAGE+'\n')
        with self.assertRaises(ValueError): module.run(COMMAND,timeout=60)
        self.assertFalse(calls)

    def test_boundary_refuses_before_forward(self):
        module,calls=self.wrapped()
        with patch.object(driver.time,'monotonic',return_value=self.end+1),self.assertRaises(ValueError):
            module.run(COMMAND,timeout=60)
        self.assertFalse(calls)

    def test_late_return_never_passes(self):
        def late(*args):
            driver.time=types.SimpleNamespace(monotonic=lambda:self.end+1)
            return 'late'
        module,_=self.wrapped(late); old=driver.time
        try:
            self.assertEqual(module.run(COMMAND,timeout=60),'late')
            self.assertIsInstance(module.primary,_TestOnlyEntry)
            self.assertIn(('producer-deadline',),module.refusals)
        finally: driver.time=old

    def test_wrapper_refuses_forged_or_expired_module_identity_grants(self):
        fake=types.SimpleNamespace(run=lambda *a:None,__file__=str(self.root/'scripts/ci/native_arm.py'))
        with self.assertRaises(ValueError):
            driver.wrap_run(fake,self.output,deadline=self.end,guard=lambda:None,parent_identity=())
        with self.graph() as (native,guard):
            saved=native
            with self.assertRaises(ValueError):
                driver.wrap_run(native,self.output,deadline=self.end+1,guard=guard,parent_identity=())
        with self.assertRaises(ValueError):
            driver.wrap_run(saved,self.output,deadline=self.end,guard=guard,parent_identity=())

    def test_cli_binding_cap_and_exact_native_main_once(self):
        calls=[]; native_args=['build','--cache',str(self.private/'cache'),'--output',str(self.output)]
        actual_graph=driver.load_graph
        @contextmanager
        def graph(*a,**k):
            with actual_graph(*a,**k) as (module,guard):
                original=module.run; main=module.main; previous=sys.getprofile()
                def profile(frame,event,arg):
                    if event=='call' and frame.f_code is main.__code__ and frame.f_globals is main.__globals__:
                        calls.append(frame.f_locals['argv']); raise _TestOnlyEntry()
                sys.setprofile(profile)
                try: yield module,guard
                finally: sys.setprofile(previous)
            self.assertIs(module.run,original)
        args=[*native_args,'--','--producer-end',str(self.end),'--producer-output',str(self.output),'--inventory-seconds','180']
        with patch.object(driver,'load_graph',graph),patch.object(driver,'__file__',str(self.root/'scripts/port/ksm-native-job/producer_driver.py')):
            with self.assertRaises(_TestOnlyEntry): driver.main(args)
            self.assertEqual(calls,[native_args])
            for old,new in [('180','181'),(str(self.output),str(self.private/'foreign'))]:
                changed=args.copy(); changed[changed.index(old)]=new; self.assertEqual(driver.main(changed),125)
        self.assertFalse(self.output.exists()); self.assertEqual(len(calls),1)

    def test_output_original_0755_creation_mode_is_accepted(self):
        module,calls=self.wrapped(); self.output.chmod(0o755)
        self.assertEqual(module.run(COMMAND,timeout=60),'reply'); self.assertEqual(len(calls),1)

    def test_image_uid_and_output_writability_refuse_before_forward(self):
        module,calls=self.wrapped(); self.output.chmod(0o777)
        with self.assertRaises(ValueError): module.run(COMMAND,timeout=60)
        self.output.chmod(0o700)
        with patch.object(driver.os,'geteuid',return_value=os.geteuid()+1),self.assertRaises(ValueError):
            module.run(COMMAND,timeout=60)
        self.assertFalse(calls)

    def test_real_copied_cli_loads_without_packet_map_and_refuses_before_actors(self):
        target=self.root/'scripts/port/ksm-native-job/producer_driver.py'; target.parent.mkdir(parents=True)
        shutil.copyfile(HERE/'producer_driver.py',target)
        command=[sys.executable,'-I','-B','-S',str(target),'build','--output',str(self.output),
                 '--','--producer-end',str(self.end),'--producer-output',str(self.output),'--inventory-seconds','180']
        result=subprocess.run(command,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,2); self.assertFalse(self.output.exists())
        self.assertIn(b'--cache',result.stderr); self.assertFalse((target.parent/'packet.lock.json').exists())

    def test_existing_consumer_driver_trailer_and_original_default_layout(self):
        spec=importlib.util.spec_from_file_location('driver_consumer_fixture',HERE/'consumer.py')
        consumer=importlib.util.module_from_spec(spec); spec.loader.exec_module(consumer)
        options={'inputs_sha':'1'*64,'recipes_sha':'2'*64}
        old=consumer.producer_command(self.root,self.private,**options)
        actual=consumer.producer_command(self.root,self.private,producer_end=self.end,**options)
        self.assertEqual(old[2],str(self.root/'scripts/ci/native_arm.py'))
        self.assertEqual(actual[2],str(self.root/'scripts/port/ksm-native-job/producer_driver.py'))
        split=actual.index('--'); self.assertEqual(actual[3:split],old[3:])
        self.assertEqual(actual[split+1:],['--producer-end',str(self.end),'--producer-output',str(self.output),'--inventory-seconds','180'])
        actual.insert(1,'-I'); actual.insert(3,'-S'); self.assertEqual(actual[5],'build')
        pipeline=next(n for n in ast.parse((HERE/'executor.py').read_bytes()).body if isinstance(n,ast.FunctionDef) and n.name=='pipeline')
        call=next(n for n in ast.walk(pipeline) if isinstance(n,ast.Call) and ast.unparse(n.func)=='consumer.producer_command')
        self.assertEqual(next(k.value.id for k in call.keywords if k.arg=='producer_end'),'producer_end')

    def test_real_copied_graph_native_main_parse_refusal_no_actors(self):
        # Actual argparse exits before native producer creates its output or launches an actor.
        with self.graph() as (native,_),self.assertRaises(SystemExit): native.main(['--not-a-native-option'])
        self.assertFalse(self.output.exists())


class RefusalLeafTests(unittest.TestCase):
    def issued(self, reason='producer-source-pin', *, import_root=None):
        try: driver.need(False,reason,import_root=import_root)
        except (ValueError,ModuleNotFoundError) as error: return error
        self.fail('original refusal absent')

    def test_all_source_issued_tags_preserve_original_builtin_message(self):
        for reason in driver.REFUSAL_PREDICATES:
            unbound=reason=='producer-unbound-import'
            error=self.issued(reason,import_root='foreign_project' if unbound else None)
            self.assertIs(type(error),ModuleNotFoundError if unbound else ValueError)
            self.assertEqual(error.args,(reason,))
            expected={'schema_version':1,'last_source_gate':'GRAPH_LOAD','predicate':reason}
            if unbound:
                self.assertEqual(error.name,'foreign_project')
                expected['rejected_import_root']='foreign_project'
            self.assertEqual(driver.refusal_record(error,'GRAPH_LOAD'),expected)
        error=self.issued('foreign not in enum')
        self.assertEqual(error.args,('foreign not in enum',))
        self.assertEqual(driver.refusal_record(error,'GRAPH_LOAD')['predicate'],'UNKNOWN')

    def test_old_getter_trap_is_red_and_safe_reader_never_dispatches(self):
        effects=[]
        class Foreign(ValueError):
            @property
            def ksm_refusal_predicate(self):
                effects.append('getter'); raise RuntimeError('inert observer trap')
        error=Foreign('original')
        with self.assertRaises(RuntimeError): getattr(error,'ksm_refusal_predicate','UNKNOWN')
        self.assertEqual(effects,['getter']); effects.clear()
        self.assertEqual(driver.refusal_record(error,'WRAP')['predicate'],'UNKNOWN')
        self.assertEqual(effects,[]); self.assertEqual(error.args,('original',))

    def test_foreign_untagged_class_or_hostile_value_cannot_selfgrant(self):
        effects=[]
        class Hostile:
            def __eq__(self,*args): effects.append('equality'); raise AssertionError('foreign equality')
            def __str__(self): effects.append('string'); raise AssertionError('foreign string')
        errors=[ValueError('producer-source-pin'),OSError('private'),self.issued()]
        errors[-1].__dict__['ksm_refusal_predicate']=Hostile()
        forged=ValueError('original'); forged.__dict__.update(ksm_refusal_predicate='producer-source-pin',ksm_refusal_issuer=object())
        errors.append(forged)
        for error in errors:
            self.assertEqual(driver.refusal_record(error,Hostile()),
                {'schema_version':1,'last_source_gate':'UNKNOWN','predicate':'UNKNOWN'})
        self.assertEqual(effects,[])
        class ClassTag(ValueError): ksm_refusal_predicate='producer-source-pin'
        self.assertEqual(driver.refusal_record(ClassTag(),'WRAP')['predicate'],'UNKNOWN')

    def test_record_is_fixed_bounded_and_ordinary_output_fault_is_observational(self):
        error=self.issued(); stream=io.StringIO()
        with patch.object(driver.sys,'stdout',stream): driver.emit_refusal(error,'OUTPUT_BIND')
        text=stream.getvalue(); self.assertLessEqual(len(text.encode('ascii')),512)
        self.assertTrue(text.startswith(driver.REFUSAL_PREFIX)); self.assertEqual(text.count('\n'),1)
        self.assertEqual(set(json.loads(text[len(driver.REFUSAL_PREFIX):])),{'schema_version','last_source_gate','predicate'})
        with patch.object(driver.json,'dumps',side_effect=OSError('inert observation failure')):
            self.assertIsNone(driver.emit_refusal(error,'OUTPUT_BIND'))
        self.assertEqual(error.args,('producer-source-pin',))

    def args(self):
        return ['build','--output','/unused','--','--producer-end',str(time.monotonic()+20),
                '--producer-output','/unused','--inventory-seconds','181']

    def test_preflight125_exports_only_source_tag_and_normal_control_stays_original(self):
        stdout,stderr=io.StringIO(),io.StringIO()
        with patch.object(driver.sys,'stdout',stdout),patch.object(driver.sys,'stderr',stderr):
            self.assertEqual(driver.main(self.args()),125)
        record=json.loads(stdout.getvalue()[len(driver.REFUSAL_PREFIX):])
        self.assertEqual(record,{'schema_version':1,'last_source_gate':'PREFLIGHT','predicate':'producer-inventory-cap'})
        self.assertEqual(stderr.getvalue(),'scoped original producer driver refused\n')
        for control in (KeyboardInterrupt('inert original'),SystemExit(17)):
            with patch.object(driver,'alive',side_effect=control),patch.object(driver,'emit_refusal') as observer:
                with self.assertRaises(type(control)) as caught: driver.main(self.args())
            self.assertIs(caught.exception,control); observer.assert_not_called()

    def test_business125_survives_ordinary_telemetry_fault_but_control_is_not_hidden(self):
        with patch.object(driver.json,'dumps',side_effect=RuntimeError('inert telemetry defect')), \
             patch.object(driver.sys,'stderr',io.StringIO()):
            self.assertEqual(driver.main(self.args()),125)
        # Synthetic control exceptions have the same type as a genuine delivery;
        # the current driver has no authenticated signal-origin bit.
        for control in (KeyboardInterrupt('inert observer control'),SystemExit(19)):
            with patch.object(driver.sys,'stdout') as output:
                output.write.side_effect=control
                with self.assertRaises(type(control)) as caught: driver.main(self.args())
            self.assertIs(caught.exception,control)


class FirstCausePreservationTests(unittest.TestCase):
    """Exact public definitions over inert namespaces; no producer/provider actors."""
    DRIVER_PATH = HERE/'producer_driver.py'
    IMAGE = 'sha256:'+'1'*64

    def definitions(self, *names):
        tree=ast.parse(self.DRIVER_PATH.read_bytes())
        nodes=[n for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in names]
        for node in nodes:
            if isinstance(node,ast.FunctionDef):node.decorator_list=[]
        namespace={'__builtins__':builtins.__dict__,'LANGUAGE':types.MappingProxyType(vars(builtins).copy())}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),str(self.DRIVER_PATH),'exec',dont_inherit=True),namespace)
        # Compatibility harness for the six existing policy tests only. This
        # function is never installed in product Source. Its handler/policy are
        # selected from the actual inline Forwarder finalizer, not reimplemented.
        if '_finish' in names:
            forward=next((n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='_Forwarder'),None)
            call=next(n for n in forward.body if isinstance(n,ast.FunctionDef) and n.name=='__call__')
            policy=next((n for n in call.body if isinstance(n,ast.Assign) and isinstance(n.targets[0],ast.Name) and n.targets[0].id=='_first_cause_policy'),None)
            if policy is not None:
                handler=next(n for n in ast.walk(call) if isinstance(n,ast.ExceptHandler) and isinstance(n.name,str) and n.name.startswith('_secondary_'))
                class Flag(ast.NodeTransformer):
                    def visit_Name(self,node):
                        if node.id.startswith('_preserve_'):node.id='failed'
                        return node
                handler=Flag().visit(handler)
                harness=ast.parse('def _finish(finalize,failed):\n pass').body[0]
                action=ast.parse('try:\n finalize()\nexcept Exception:\n raise').body[0];action.handlers=[handler]
                harness.body=[policy,action];ast.fix_missing_locations(harness)
                exec(compile(ast.Module(body=[harness],type_ignores=[]),'<test-only-inline-policy-harness>','exec',dont_inherit=True),namespace)
        return namespace

    def raised(self, action):
        try:action()
        except BaseException as error:return error
        self.fail('expected refusal')

    def test_finish_preserves_primary_identity_and_traceback(self):
        ns=self.definitions('_finish');primary=TypeError('primary');secondary=ValueError('secondary')
        calls=[];first=[]
        def finish():calls.append('finish');raise secondary
        def call():
            try:
                try:raise primary
                except BaseException:
                    first.append(primary.__traceback__);raise
            finally:ns['_finish'](finish,True)
        error=self.raised(call)
        self.assertIs(error,primary);self.assertEqual(calls,['finish'])
        self.assertIs(error.__traceback__.tb_next,first[0])
        self.assertIsNone(error.__cause__);self.assertIsNone(error.__context__)

    def test_finish_sole_failure_refuses_and_success_runs_once(self):
        ns=self.definitions('_finish');calls=[];error=ValueError('sole')
        self.assertIs(self.raised(lambda:ns['_finish'](lambda:(_ for _ in ()).throw(error),False)),error)
        for failed in (False,True):ns['_finish'](lambda:calls.append(failed),failed)
        self.assertEqual(calls,[False,True])

    def test_finish_known_builtin_secondary_errors(self):
        ns=self.definitions('_finish')
        for kind in (ValueError,TypeError,AttributeError,KeyError,IndexError,RuntimeError,OSError,
                     FileNotFoundError,PermissionError,NotADirectoryError,IsADirectoryError,
                     UnicodeError,ImportError,ModuleNotFoundError):
            with self.subTest(kind=kind.__name__):
                primary=TypeError('primary')
                def call():
                    try:raise primary
                    finally:ns['_finish'](lambda:(_ for _ in ()).throw(kind('secondary')),True)
                self.assertIs(self.raised(call),primary)

    def test_finish_cancellation_both_priorities(self):
        ns=self.definitions('_finish')
        class Cancelled(BaseException):pass
        class BrokerCancelled(ValueError):pass
        for primary,secondary,expected in ((Cancelled(),ValueError(),0),(KeyboardInterrupt(),TypeError(),0),
                (SystemExit(2),ValueError(),0),(TypeError(),Cancelled(),1),
                (ValueError(),KeyboardInterrupt(),1),(ValueError(),BrokerCancelled(),1)):
            with self.subTest(primary=type(primary),secondary=type(secondary)):
                def call():
                    try:raise primary
                    finally:ns['_finish'](lambda:(_ for _ in ()).throw(secondary),True)
                self.assertIs(self.raised(call),(primary,secondary)[expected])

    def test_finish_no_hostile_exception_attribute_hooks(self):
        ns=self.definitions('_finish');hooks=[]
        class Hostile(BaseException):
            def __getattribute__(self,name):hooks.append(('get',name));raise AssertionError('hook')
            def __setattr__(self,name,value):hooks.append(('set',name));raise AssertionError('hook')
        primary=Hostile()
        def call():
            try:raise primary
            finally:ns['_finish'](lambda:(_ for _ in ()).throw(ValueError()),True)
        self.assertIs(self.raised(call),primary);self.assertEqual(hooks,[])
        class Secondary(ValueError):
            def __getattribute__(self,name):hooks.append(('secondary',name));raise AssertionError('hook')
        secondary=Secondary()
        self.assertIs(self.raised(lambda:ns['_finish'](lambda:(_ for _ in ()).throw(secondary),True)),secondary)
        self.assertEqual(hooks,[])

    def forward(self, inventory=False, primary=None, secondary=None, fail='postguard', pre=False):
        ns=self.definitions('_finish','_Forwarder');events=[]
        guard_calls=[0];reads=[0];native=object()
        state=types.SimpleNamespace(cancelled=False,ownership_uncertain=True,cleanup='FAIL',first_failure=primary)
        def guard():
            guard_calls[0]+=1;events.append('guard')
            if (pre and guard_calls[0]==1 or not pre and guard_calls[0]==2) and fail=='postguard' and secondary is not None:raise secondary
        def original(*args):
            events.append('original')
            if primary is not None:raise primary
            return 'reply'
        def read(*args):
            reads[0]+=1;events.append('read')
            if reads[0]==2 and fail=='readback' and secondary is not None:raise secondary
            return (self.IMAGE.encode(),(1,))
        class Output:
            parent='parent'
            def __truediv__(self,other):return 'image-id'
            def lstat(self):return types.SimpleNamespace(st_mode=0o40700,st_uid=7)
        custody=types.SimpleNamespace(native=native,original=original,guard=guard,verify=lambda:events.append('verify'))
        wrapper=object.__new__(ns['_Forwarder'])
        for key,value in zip(wrapper.__slots__,(native,original,guard,Output(),200,'parent-id')):object.__setattr__(wrapper,key,value)
        custody.wrapper=wrapper
        def need(ok,reason):
            if not ok:raise ValueError(reason)
        ns.update(_GRAPHS={id(native):(None,None,None,None,custody)},need=need,alive=lambda end:events.append('alive'),
            re=__import__('re'),stat=__import__('stat'),os=types.SimpleNamespace(geteuid=lambda:7),read=read,
            directory=lambda path:'parent-id',CAP=180,time=types.SimpleNamespace(monotonic=lambda:100))
        command=['docker','run','--rm','--pull=never','--network=none','--cap-drop=ALL','--security-opt=no-new-privileges',
                 '--read-only','--entrypoint=/bin/cat',self.IMAGE,'/builder-packages.lock'] if inventory else ['inert']
        def call():return wrapper(command,timeout=60 if inventory else 1800)
        return call,events,state

    def test_forward_success_action_order(self):
        for inventory in (False,True):
            call,events,state=self.forward(inventory)
            self.assertEqual(call(),'reply')
            self.assertEqual(events,['verify','guard','alive']+(['read'] if inventory else [])+['original']+(['read'] if inventory else [])+['guard'])
            self.assertEqual((state.cleanup,state.ownership_uncertain,state.cancelled),('FAIL',True,False))

    def test_forward_primary_only_and_dual_finalizers(self):
        for inventory,fail in ((False,'postguard'),(True,'postguard'),(True,'readback')):
            for dual in (False,True):
                primary=TypeError('primary');secondary=ValueError('secondary') if dual else None
                call,events,state=self.forward(inventory,primary,secondary,fail)
                self.assertIs(self.raised(call),primary);self.assertEqual(events.count('original'),1)
                self.assertIs(state.first_failure,primary);self.assertEqual(state.cleanup,'FAIL');self.assertTrue(state.ownership_uncertain)

    def test_forward_sole_finalizer_failure_and_precheck_refuse(self):
        for inventory,fail in ((False,'postguard'),(True,'postguard'),(True,'readback')):
            secondary=ValueError('secondary');call,events,_=self.forward(inventory,secondary=secondary,fail=fail)
            self.assertIs(self.raised(call),secondary)
        secondary=ValueError('pre');call,events,_=self.forward(secondary=secondary,pre=True)
        self.assertIs(self.raised(call),secondary);self.assertNotIn('original',events)

    def test_forward_cancellation_is_not_swallowed(self):
        class Cancelled(BaseException):pass
        class BrokerCancelled(ValueError):pass
        for primary,secondary,expected in ((Cancelled(),ValueError(),0),(TypeError(),Cancelled(),1),(TypeError(),BrokerCancelled(),1)):
            call,events,_=self.forward(primary=primary,secondary=secondary)
            self.assertIs(self.raised(call),(primary,secondary)[expected]);self.assertEqual(events.count('original'),1)

    def quarantine(self, primary=None, secondary=None, post_alive=None):
        ns=self.definitions('_finish','quarantine');events=[]
        class Modules(dict):
            def clear(self):
                events.append('restore-modules')
                if secondary is not None:raise secondary
                super().clear()
        fake_sys=types.SimpleNamespace(modules=Modules(held=object()),path=['old-path'],meta_path=['old-meta'],
            path_hooks=['old-hooks'],path_importer_cache={'old':'cache'})
        fake_builtins=types.SimpleNamespace(__import__=object(),compile=object(),exec=object())
        old_ops=vars(fake_builtins).copy();old_modules=dict(fake_sys.modules);calls=[0]
        def alive(end):
            calls[0]+=1;events.append('alive')
            if calls[0]==1 and post_alive is not None:raise post_alive
        ns.update(STANDARD='/inert',Path=Path,sys=fake_sys,builtins=fake_builtins,STDLIB=frozenset(),BOOTSTRAP={},
            LANGUAGE=dict(vars(builtins),__import__=lambda *a:None,compile=object(),exec=object()),FINDERS=('finder',),FILE_HOOK='hook',
            alive=alive,need=lambda ok,reason,**kw:None)
        generator=ns['quarantine'](200);next(generator)
        def finish():
            if primary is not None:generator.throw(primary)
            else:
                try:next(generator)
                except StopIteration:return 'done'
        return finish,events,fake_sys,fake_builtins,old_ops,old_modules

    def test_quarantine_success_restores_only_inert_state(self):
        call,events,state,operations,old_ops,old_modules=self.quarantine()
        self.assertEqual(call(),'done');self.assertEqual(state.modules,old_modules)
        self.assertEqual((state.path,state.meta_path,state.path_hooks,state.path_importer_cache),(['old-path'],['old-meta'],['old-hooks'],{'old':'cache'}))
        self.assertEqual(vars(operations),old_ops);self.assertEqual(events,['alive','restore-modules'])

    def test_quarantine_primary_and_dual_restore_failure(self):
        for secondary in (None,ValueError('secondary')):
            primary=TypeError('primary');call,events,*_=self.quarantine(primary,secondary)
            self.assertIs(self.raised(call),primary);self.assertEqual(events,['restore-modules'])

    def test_quarantine_sole_restore_or_postyield_failure_refuses(self):
        secondary=ValueError('restore');call,*_=self.quarantine(secondary=secondary)
        self.assertIs(self.raised(call),secondary)
        primary=TypeError('postyield');call,*_=self.quarantine(secondary=ValueError(),post_alive=primary)
        self.assertIs(self.raised(call),primary)

    def test_quarantine_cancellation_both_priorities(self):
        class Cancelled(BaseException):pass
        for primary,secondary,expected in ((Cancelled(),ValueError(),0),(TypeError(),Cancelled(),1)):
            call,*_=self.quarantine(primary,secondary)
            self.assertIs(self.raised(call),(primary,secondary)[expected])

    def graph(self, primary=None, failures=None):
        ns=self.definitions('_finish','load_graph');events=[];failures=failures or {};phase=['entry'];exit_reads=[0]
        class FakePath(list):
            def __setitem__(self,key,value):
                events.append('path-restore')
                if 'path' in failures:raise failures['path']
                super().__setitem__(key,value)
        class Grants(dict):
            def pop(self,key,default=None):
                events.append('pop')
                if 'pop' in failures:raise failures['pop']
                return super().pop(key,default)
        class Guard:
            def __init__(self,disk):self._disk=disk
            def __call__(self):events.append('guard');self._disk()
        class Custody:
            def __init__(self,modules,guard,original,deadline):self.native=modules['native_arm'];self.guard=guard
            def verify(self):
                events.append('verify')
                if 'verify' in failures:raise failures['verify']
            def restore(self):
                events.append('restore')
                if 'restore' in failures:raise failures['restore']
        @contextmanager
        def quarantine(deadline):yield lambda *a:None,['inert-path']
        def read(path,*args):
            events.append('read')
            if phase[0]=='exit':
                exit_reads[0]+=1
                key='outer_disk' if exit_reads[0]>2 else 'disk'
                if key in failures:raise failures[key]
            return b'inert',(1,)
        def execute(code,namespace):
            events.append('exec')
            if 'exec' in failures:raise failures['exec']
            namespace['run']=lambda *args:None
        ns.update(absolute=lambda x:x,read=read,SOURCES={'package_checks':('checks.py','pin'),'native_arm':('native.py','pin')},
            hashlib=types.SimpleNamespace(sha256=lambda raw:types.SimpleNamespace(hexdigest=lambda:'pin')),
            need=lambda ok,reason:None,_Guard=Guard,types=types,quarantine=quarantine,
            LANGUAGE=dict(vars(builtins),compile=lambda *a:None,exec=execute),sys=types.SimpleNamespace(path=FakePath()),
            _Custody=Custody,_GRAPHS=Grants(),_GUARDS=Grants())
        generator=ns['load_graph'](Path('/inert'),deadline=200)
        def call():
            next(generator);phase[0]='exit';events.append('yielded')
            if primary is not None:generator.throw(primary)
            else:
                try:next(generator)
                except StopIteration:return 'done'
        return call,events,ns

    def test_graph_success_order_and_grant_lifetime(self):
        call,events,ns=self.graph();self.assertEqual(call(),'done')
        self.assertEqual(events.count('exec'),2);self.assertEqual(events.count('path-restore'),2)
        tail=events[events.index('yielded')+1:]
        self.assertEqual(tail,['verify','read','read','restore','pop','pop','read','read'])
        self.assertFalse(ns['_GRAPHS']);self.assertFalse(ns['_GUARDS'])

    def test_graph_outer_disk_and_yield_finalizers_preserve_primary(self):
        for site in ('verify','disk','restore','pop','outer_disk'):
            primary=TypeError('primary');call,events,_=self.graph(primary,{site:ValueError('secondary')})
            self.assertIs(self.raised(call),primary,site)
            self.assertEqual(events.count('exec'),2)

    def test_graph_nested_restore_and_pop_preserve_first_failure(self):
        for first,second in (('verify','restore'),('restore','pop')):
            primary=TypeError(first);call,events,_=self.graph(failures={first:primary,second:ValueError(second)})
            self.assertIs(self.raised(call),primary)
            self.assertIn('restore',events);self.assertIn('pop',events)

    def test_graph_sole_finalizer_failure_refuses(self):
        for site in ('verify','disk','restore','pop','outer_disk'):
            error=ValueError(site);call,events,_=self.graph(failures={site:error})
            self.assertIs(self.raised(call),error,site)

    def test_graph_exec_path_restore_dual_and_sole_failure(self):
        primary=TypeError('exec');call,events,_=self.graph(failures={'exec':primary,'path':ValueError('restore')})
        self.assertIs(self.raised(call),primary);self.assertEqual(events.count('exec'),1)
        secondary=ValueError('path');call,events,_=self.graph(failures={'path':secondary})
        self.assertIs(self.raised(call),secondary)

    def test_graph_cancellation_both_priorities(self):
        class Cancelled(BaseException):pass
        for primary,secondary,expected in ((Cancelled(),ValueError(),0),(TypeError(),Cancelled(),1)):
            call,events,_=self.graph(primary,{'verify':secondary})
            self.assertIs(self.raised(call),(primary,secondary)[expected])

    def test_exact_cancellation_classes_and_sticky_signal_state(self):
        support=getattr(self,'SUPPORT_ROOT',HERE)
        selected={}
        for filename,names in (('runtime.py',('Cancelled','_Cancellation','ResourceFailure')),('broker.py',('Cancelled',))):
            tree=ast.parse((support/filename).read_bytes())
            nodes=[n for n in tree.body if isinstance(n,ast.ClassDef) and n.name in names]
            ns={'contextmanager':contextmanager}
            exec(compile(ast.Module(body=nodes,type_ignores=[]),filename,'exec',dont_inherit=True),ns)
            selected[filename]=ns
        runtime=selected['runtime.py'];finish=self.definitions('_finish')['_finish'];state=runtime['_Cancellation']()
        def interrupt():
            try:state.interrupt(15)
            finally:finish(lambda:(_ for _ in ()).throw(ValueError('secondary')),True)
        error=self.raised(interrupt)
        self.assertIs(type(error),runtime['Cancelled']);self.assertEqual((state.signum,state.deferrals),(15,0))
        self.assertIs(type(self.raised(state.check)),runtime['Cancelled'])
        for secondary in (selected['broker.py']['Cancelled'](),runtime['ResourceFailure']({'reason':'resource'})):
            primary=TypeError('first')
            def call():
                try:raise primary
                finally:finish(lambda:(_ for _ in ()).throw(secondary),True)
            self.assertIs(self.raised(call),secondary)


class CorrectionRegressionTests(unittest.TestCase):
    """Exact selected scopes and synthetic callbacks; no product imports/actors."""
    def probe(self):return FirstCausePreservationTests()
    @staticmethod
    def cell(function,name):return dict(zip(function.__code__.co_freevars,(cell.cell_contents for cell in function.__closure__)))[name]
    def test_driver_has_no_helper_or_generated_finalizer_closures(self):
        tree=ast.parse((HERE/'producer_driver.py').read_bytes())
        self.assertFalse(any(isinstance(n,ast.Name) and n.id=='_finish' for n in ast.walk(tree)))
        self.assertFalse(any(isinstance(n,ast.FunctionDef) and (n.name=='_finish' or n.name.startswith('_finalize_')) for n in ast.walk(tree)))
    def test_forward_helper_rebind_and_code_mutation_cannot_skip_postguards(self):
        for inventory in (False,True):
            probe=self.probe();secondary=ValueError('guard');call,events,_=probe.forward(inventory,secondary=secondary)
            wrapper=self.cell(call,'wrapper');namespace=type(wrapper).__call__.__globals__
            old=object.__getattribute__(wrapper,'_original')
            def former_helper(finalize,failed):finalize()
            def no_op(*args):pass
            namespace['_finish']=former_helper
            def action(*args):
                former_helper.__code__=no_op.__code__
                namespace['_finish']=no_op
                return old(*args)
            object.__setattr__(wrapper,'_original',action)
            self.assertIs(probe.raised(call),secondary);self.assertEqual(events.count('original'),1);self.assertEqual(events.count('guard'),2)
    def test_forward_inventory_readback_remains_mandatory_after_helper_poison(self):
        probe=self.probe();error=ValueError('readback');call,events,_=probe.forward(True,secondary=error,fail='readback')
        wrapper=self.cell(call,'wrapper');namespace=type(wrapper).__call__.__globals__;namespace['_finish']=lambda *args:None
        self.assertIs(probe.raised(call),error);self.assertEqual(events.count('read'),2)
    def test_forward_exception_policy_survives_midbody_globals_and_language_poison(self):
        probe=self.probe();primary=TypeError('first');secondary=MemoryError('resource')
        call,events,_=probe.forward(primary=primary,secondary=secondary)
        wrapper=self.cell(call,'wrapper');namespace=type(wrapper).__call__.__globals__;old=object.__getattribute__(wrapper,'_original')
        def action(*args):
            namespace.update(type=lambda value:ValueError,GeneratorExit=TypeError,Exception=BaseException,ValueError=MemoryError)
            namespace['LANGUAGE']={'type':lambda value:ValueError,'GeneratorExit':TypeError,'Exception':BaseException,'ValueError':MemoryError}
            return old(*args)
        object.__setattr__(wrapper,'_original',action)
        self.assertIs(probe.raised(call),secondary)
    def test_quarantine_close_restoration_error_remains_outward(self):
        probe=self.probe();error=ValueError('restore');call,events,state,*_=probe.quarantine(secondary=error)
        state.modules['late-inert-entry']=object();generator=self.cell(call,'generator')
        self.assertIs(probe.raised(generator.close),error);self.assertIn('late-inert-entry',state.modules);self.assertIn('restore-modules',events)
    def test_quarantine_normal_close_runs_restoration_once(self):
        probe=self.probe();call,events,state,operations,old_ops,old_modules=probe.quarantine()
        state.modules['late-inert-entry']=object();generator=self.cell(call,'generator')
        self.assertIsNone(generator.close());self.assertEqual(events,['restore-modules']);self.assertEqual(state.modules,old_modules);self.assertEqual(vars(operations),old_ops)
    def test_quarantine_close_and_pending_primary_ignore_helper_mutation(self):
        for closing in (False,True):
            probe=self.probe();primary=TypeError('primary');secondary=ValueError('restore')
            call,events,*_=probe.quarantine(primary,secondary);generator=self.cell(call,'generator')
            generator.gi_frame.f_globals['_finish']=lambda *args:None
            self.assertIs(probe.raised(generator.close if closing else call),secondary if closing else primary)
            self.assertEqual(events,['restore-modules'])
    def test_graph_close_preserves_verify_failure_and_retires_grants(self):
        probe=self.probe();secondary=ValueError('verify');call,events,namespace=probe.graph(failures={'verify':secondary})
        generator=self.cell(call,'generator');next(generator)
        self.assertIs(probe.raised(generator.close),secondary);self.assertFalse(namespace['_GRAPHS']);self.assertFalse(namespace['_GUARDS']);self.assertIn('restore',events)
    def test_graph_helper_poison_cannot_skip_verify_restore_pop_or_disk(self):
        probe=self.probe();call,events,namespace=probe.graph();namespace['_finish']=lambda *args:None
        self.assertEqual(call(),'done');tail=events[events.index('yielded')+1:]
        self.assertEqual(tail,['verify','read','read','restore','pop','pop','read','read'])
        self.assertFalse(namespace['_GRAPHS']);self.assertFalse(namespace['_GUARDS'])
    def test_secondary_metaclass_equality_cannot_selfgrant_suppression(self):
        probe=self.probe();namespace=probe.definitions('_finish');effects=[]
        class Compare(type):
            def __eq__(self,other):effects.append('equality');return True
        class CustomCancelled(ValueError,metaclass=Compare):pass
        primary=TypeError('primary');secondary=CustomCancelled('secondary')
        def call():
            try:raise primary
            finally:namespace['_finish'](lambda:(_ for _ in ()).throw(secondary),True)
        self.assertIs(probe.raised(call),secondary);self.assertEqual(effects,[])
    def test_exact_unicode_subcategories_remain_covered(self):
        probe=self.probe();namespace=probe.definitions('_finish')
        for secondary in (UnicodeDecodeError('utf8',b'x',0,1,'reason'),UnicodeEncodeError('utf8','x',0,1,'reason'),UnicodeTranslateError('x',0,1,'reason')):
            primary=TypeError('primary')
            def call():
                try:raise primary
                finally:namespace['_finish'](lambda:(_ for _ in ()).throw(secondary),True)
            self.assertIs(probe.raised(call),primary)
    def test_generator_exit_policy_is_captured_before_body_mutation(self):
        probe=self.probe();secondary=ValueError('restore');call,events,*_=probe.quarantine(secondary=secondary)
        generator=self.cell(call,'generator');namespace=generator.gi_frame.f_globals
        namespace.update(type=lambda value:TypeError,GeneratorExit=TypeError,BaseException=Exception,Exception=BaseException)
        namespace['LANGUAGE']={}
        self.assertIs(probe.raised(generator.close),secondary)


class KernelRecordCompatibilityTests(unittest.TestCase):
    """Exact probe definition, inert observations; no subprocess or host probe."""
    def fixture(self, *, system='Linux', machine='aarch64', docker_arch='aarch64', uid=1000,
                endpoint='unix:///run/docker.sock', docker_host=None, uname_error=None):
        path=HERE.parents[1]/'ci/native_arm.py'
        tree=ast.parse(path.read_bytes())
        node=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='probe')
        calls=[];saved=[]
        kernel=types.SimpleNamespace(sysname='Linux',nodename='inert-node',release='inert-release',
                                     version='inert-version',machine='aarch64')
        def uname():
            calls.append('os.uname')
            if uname_error is not None:raise uname_error
            return kernel
        def forbidden():raise AssertionError('lazy platform uname must not be requested')
        def run(command,log=None,timeout=1800):
            calls.append((command,log,timeout))
            replies={('docker','info','--format','{{.Architecture}}'):docker_arch,
                     ('docker','version'):'inert-docker-version',('lscpu',):'inert-cpu',
                     ('docker','context','inspect'):json.dumps([{'Endpoints':{'docker':{'Host':endpoint}}}])}
            return replies[tuple(command)]
        env={'RUNNER_ARCH':'ARM64','RUNNER_OS':'Linux','GITHUB_REPOSITORY':'inert/repository',
             'GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'123','ImageVersion':'inert-image','ImageOS':'inert-linux'}
        if docker_host is not None:env['DOCKER_HOST']=docker_host
        namespace=dict(os=types.SimpleNamespace(uname=uname,sysconf=lambda name:16384,getuid=lambda:uid,
                        getgid=lambda:1000,environ=env),platform=types.SimpleNamespace(uname=forbidden,
                        system=lambda:system,machine=lambda:machine),run=run,json=json,
                        sys=types.SimpleNamespace(version='inert-python'),sha=lambda p:'b'*64,
                        Path=Path,__file__=str(path),save=lambda path,value:saved.append(json.loads(json.dumps(value))))
        exec(compile(ast.Module(body=[node],type_ignores=[]),str(path),'exec'),namespace)
        return lambda:namespace['probe'](Path('/inert/output')),calls,saved

    def test_five_native_kernel_fields_without_lazy_processor(self):
        call,calls,saved=self.fixture();record=call()
        self.assertEqual(record['kernel'],dict(system='Linux',node='inert-node',release='inert-release',
                          version='inert-version',machine='aarch64'))
        self.assertEqual(calls.count('os.uname'),1);self.assertNotIn('processor',record['kernel'])
        self.assertEqual(len(calls),5);self.assertEqual(len(saved),2)
        self.assertTrue(all(row[1:] == (None,60) for row in calls if type(row) is tuple))

    def test_provenance_environment_and_page_size_preserved(self):
        call,_,_=self.fixture();record=call()
        expected=dict(page_size=16384,python='inert-python',uid=1000,gid=1000,runner_arch='ARM64',
                      runner_os='Linux',repository='inert/repository',commit='a'*40,run_id='123',
                      bootstrap_script_sha256='b'*64,image_version='inert-image',image_os='inert-linux',
                      native_build='NOT RUN',hardware_validation='NOT RUN')
        self.assertEqual({k:record[k] for k in expected},expected)

    def test_platform_system_check_remains_required(self):
        call,_,saved=self.fixture(system='Darwin')
        with self.assertRaisesRegex(ValueError,'native Linux ARM'):call()
        self.assertEqual(len(saved),1)

    def test_platform_architecture_check_remains_required(self):
        call,_,_=self.fixture(machine='x86_64')
        with self.assertRaisesRegex(ValueError,'native Linux ARM'):call()

    def test_daemon_architecture_check_remains_required(self):
        call,_,_=self.fixture(docker_arch='amd64')
        with self.assertRaisesRegex(ValueError,'native Linux ARM'):call()

    def test_arm64_alias_remains_supported(self):
        call,_,_=self.fixture(machine='arm64',docker_arch='arm64');self.assertEqual(call()['docker_server_arch'],'arm64')

    def test_root_coordinator_remains_rejected(self):
        call,_,_=self.fixture(uid=0)
        with self.assertRaisesRegex(ValueError,'non-root'):call()

    def test_remote_endpoint_remains_rejected(self):
        call,_,_=self.fixture(endpoint='tcp://inert.invalid:2375')
        with self.assertRaisesRegex(ValueError,'default local Docker socket'):call()

    def test_remote_environment_override_remains_rejected(self):
        call,_,_=self.fixture(docker_host='tcp://inert.invalid:2375')
        with self.assertRaisesRegex(ValueError,'default local Docker socket'):call()

    def test_both_local_endpoint_aliases_remain_supported(self):
        for endpoint in ('unix:///run/docker.sock','unix:///var/run/docker.sock'):
            call,_,_=self.fixture(endpoint=endpoint);self.assertEqual(call()['docker_endpoint'],endpoint)

    def test_native_uname_error_is_not_swallowed(self):
        error=OSError('inert uname failure');call,calls,saved=self.fixture(uname_error=error)
        try:call()
        except OSError as observed:self.assertIs(observed,error)
        else:self.fail('expected exact uname error')
        self.assertEqual(calls,['os.uname']);self.assertEqual(saved,[])


if __name__=='__main__': unittest.main()
