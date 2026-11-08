"""NEW bounded current-code DATA controls; no legacy actor or lifecycle execution."""
import ast
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SOURCE = REPO/'scripts/update/aux_initialize.py'
ORIGINAL = REPO/'scripts/install/local_transaction.py'
_ACTIVE = False

def _fence(event, args):
    if _ACTIVE and (event.startswith(('subprocess.','socket.','ctypes.','os.exec','os.spawn')) or
                    event in ('os.system','os.fork','os.posix_spawn','os.kill','os.killpg')):
        raise RuntimeError('initializer DATA control actor denied: '+event)

sys.addaudithook(_fence)

def _disable_fence():
    global _ACTIVE
    _ACTIVE = False

def function(text, name):
    nodes = [n for n in ast.parse(text).body if isinstance(n, ast.FunctionDef) and n.name == name]
    if len(nodes) != 1: raise AssertionError(name)
    return ast.get_source_segment(text,nodes[0])

def need(ok, why):
    if not ok: raise ValueError(why)

class PrivateRelative(unittest.TestCase):
    def setUp(self):
        global _ACTIVE
        self.addCleanup(_disable_fence)
        _ACTIVE = True
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.original_text = function(ORIGINAL.read_text(), 'relative')
        self.path = Path(self.temporary.name)/'installer.py'
        self.path.write_text(self.original_text+'\n')
        namespace = dict(need=need,Path=Path)
        exec(compile(self.original_text,'<trusted-original-relative-definition>','exec'),namespace)
        self.original = namespace['relative']; self.calls = []
        def counted(value):
            self.calls.append(value)
            return self.original(value)
        self.module = SimpleNamespace(__file__=str(self.path),relative=counted)
        self.namespace = dict(Path=Path,hashlib=hashlib,os=SimpleNamespace(name='posix'))
        exec(compile(function(SOURCE.read_text(),'_initializer_relative_api'),'<new-private-relative>','exec'),self.namespace)
        self.api = self.namespace['_initializer_relative_api']

    def test_exact_original_definition(self):
        self.assertEqual(hashlib.sha256(self.original_text.encode()).hexdigest(),'486c47ebbe2e6cfc392bde908003baf7559fd70d2f6ed17684f2ba34340fac41')

    def test_canonical_text_avoids_original_and_returns_same_object(self):
        relative = self.api(self.module)
        for value in ('usr/lib/x','a','~user/cache','a b/c','é/文件','a/'+'x'*300):
            self.assertEqual(self.original(value),value)
            self.assertIs(relative(value),value)
        self.assertEqual(self.calls,[])

    def test_uncertain_text_matches_full_original(self):
        relative = self.api(self.module)
        class Text(str): pass
        for value in ('','.','./a','a/.','a//b','a/','../a','a/../b','/a','//a','a\0b',None,False,1,[],{},Text('a/b')):
            try: expected = ('ok',self.original(value))
            except Exception as error: expected = (type(error),str(error))
            try: actual = ('ok',relative(value))
            except Exception as error: actual = (type(error),str(error))
            self.assertEqual(actual,expected)
        self.assertEqual(len(self.calls),17)

    def test_non_posix_preserves_original_callable(self):
        self.namespace['os'].name='nt'
        self.assertIs(self.api(self.module),self.module.relative)

    def test_changed_definition_is_refused(self):
        self.path.write_text(self.original_text.replace('return value','return str(value)'))
        with self.assertRaisesRegex(ValueError,'whole original initializer relative validator source'): self.api(self.module)
        self.assertEqual(self.calls,[])

    def test_duplicate_definition_is_refused(self):
        self.path.write_text(self.original_text+'\n'+self.original_text)
        with self.assertRaises(ValueError): self.api(self.module)

    def test_no_success_or_failure_cache(self):
        relative = self.api(self.module)
        for _ in range(5):
            with self.assertRaises(ValueError): relative('a//b')
        self.assertEqual(self.calls,['a//b']*5)
        self.calls.clear()
        for _ in range(5): self.assertEqual(relative('a/b'),'a/b')
        self.assertEqual(self.calls,[])
        self.assertEqual(relative.__code__.co_freevars,('original',))

    def test_actual_facade_routes_private_root_without_global_mutation(self):
        text=SOURCE.read_text(); ns=dict(self.namespace)
        import types
        def clone(f, globals):
            result=types.FunctionType(f.__code__,globals,f.__name__,f.__defaults__,f.__closure__)
            result.__kwdefaults__=f.__kwdefaults__; return result
        def mount_factory(original): return original
        def root_observe(value, **kwargs): return installer.relative(value)
        roots=SimpleNamespace(installer=self.module,observe=root_observe,_mount_id=lambda *a:1,_file_hash=lambda *a:'digest')
        @contextmanager
        def parent(*a,**kw): yield None
        def empty(*a,**kw): return None
        copy=SimpleNamespace(_parent=parent,_root_check=empty,_source_alias=empty)
        aux=SimpleNamespace(Reader=type('Reader',(),{}),checkpoint=empty,load_comparator=empty)
        held=dict(roots=roots)
        exec('def observe(value, limits): return roots.observe(value)',held)
        ns.update(_initializer_clone=clone,_initializer_mount600=mount_factory,_initializer_hash_api=lambda original,state: original._file_hash,
                  _initializer_original=dict(observe=held['observe'],limits_from=empty,exec_helper=empty,initialize=empty))
        exec(compile(function(text,'_initializer_facade'),'<actual-new-facade>','exec'),ns)
        state=SimpleNamespace(mount=empty,phase_start=empty,observed=lambda root,limits,call:call(root,limits),worker_row=empty)
        api=ns['_initializer_facade'](dict(roots=roots,copy=copy,aux=aux,supervision=SimpleNamespace(run=empty)),state,None)
        self.assertEqual(api.observe('usr/lib/a',None),'usr/lib/a')
        self.assertIsNot(api.roots.installer,self.module)
        self.assertEqual(self.calls,[])
        with self.assertRaises(ValueError): api.roots.observe('usr//lib')
        self.assertEqual(self.calls,['usr//lib'])
        self.assertIs(roots.installer,self.module)
        self.assertIs(roots.installer.relative,self.module.relative)
        self.assertIs(root_observe.__globals__.get('installer'),None)

    def test_main_and_source_helper_identical(self):
        other=HERE/'frozen-aux_initialize.py.txt'
        self.assertEqual(function(SOURCE.read_text(),'_initializer_relative_api'),function(other.read_text(),'_initializer_relative_api'))

    def test_actual_worker_keeps_150_second_observation_budget(self):
        class StopObservation(Exception): pass
        captured=[]
        def executable(*a): raise AssertionError('no actor')
        def limits(**kw): captured.append(kw['deadline']); return object()
        def observe(*a): raise StopObservation()
        ns=dict(scale=SimpleNamespace(bound=SimpleNamespace(guard=lambda *a:None)),
                aux=SimpleNamespace(need=need),os=SimpleNamespace(execve=executable,supports_fd={executable}),
                roots=SimpleNamespace(Limits=limits),time=SimpleNamespace(monotonic=lambda:19),observe=observe)
        exec(compile(function(SOURCE.read_text(),'exec_helper'),'<actual-worker-budget-seam>','exec'),ns)
        with self.assertRaises(StopObservation): ns['exec_helper']('root','workspace')
        self.assertEqual(captured,[169])

if __name__=='__main__': unittest.main()
