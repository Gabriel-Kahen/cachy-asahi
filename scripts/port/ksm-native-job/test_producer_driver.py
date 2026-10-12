# SPDX-License-Identifier: MIT
"""Captured graph and caller-deadline controls; no Docker/native/GPG actors."""
import ast
import builtins
from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import shutil
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
    def run(self,*args,**kwargs):
        previous=sys.getprofile(); result=['reply']
        def profile(frame,event,arg):
            if event=='call' and frame.f_code is self.original.__code__ and frame.f_globals is self.original.__globals__:
                values=frame.f_locals
                self.calls.append((values['command'],values['log'],values['timeout']))
                if self.action is not None: result[0]=self.action(*self.calls[-1])
                raise _TestOnlyEntry()
        sys.setprofile(profile)
        try:
            try: return self.module.run(*args,**kwargs)
            except _TestOnlyEntry: return result[0]
        finally: sys.setprofile(previous)


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
        with self.assertRaises(ValueError): facade.run(COMMAND,timeout=60)
        with self.assertRaises(ValueError): close(*args,**kwargs)
        self.assertEqual(len(calls),1); self.assertNotIn(id(self.subject),driver._GRAPHS)

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
        with self.assertRaises(ValueError):
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
                with self.subTest(name=name,level=level),self.assertRaises(ValueError): importer(name,native.__dict__,fromlist=('recipe',),level=level)

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
        with self.assertRaises(ValueError): module.run(COMMAND,timeout=60)

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
            with self.assertRaises(ValueError): module.run(COMMAND,timeout=60)
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


if __name__=='__main__': unittest.main()
