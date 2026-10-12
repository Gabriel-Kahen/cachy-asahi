#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-granted same-job repository handoff; imports/preflight start no actor."""
import sys
if __name__ == '__main__' and not (sys.flags.isolated and sys.flags.dont_write_bytecode and sys.flags.no_site):
    sys.stdout.write('{"status":"BLOCKED","error_code":"grant-refused","actors":"NOT RUN"}\n')
    raise SystemExit(1)
import argparse
import ast
import builtins
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sysconfig
import tempfile
import threading
import time
import types

FILE_LIMIT, TOTAL_LIMIT = 8 * 1024**2, 64 * 1024**2
INITIAL = 'd4d603146f094c86242eaafbb887042959c510c9bb948579dd749d065dd8fc31'
POLICY = 'ff424921c5be38799f64e5c6264bb098cf71737d7be83608a4c91dee83f0365e'
LICENSE = '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7'
BLOCKED_RUNTIME_MAP = '9e6aa90e3cf9f6fc65bb8d410ec5acdbdfe2024f0bd1462cd51d52a5479d085e'
PREFIXES = {'runtime':'scripts/port/repository-native-handoff',
            'collector':'scripts/port/repository-client-native',
            'phase':'scripts/port/repository-client-phase-stage'}
COUNTS = {'runtime':7, 'collector':7, 'phase':5}
MAP_NAMES = {
    'runtime':{name+'.py' for name in ('entry','capture','producer','launch','transport','supervisor','broker')},
    'collector':{name+'.py' for name in ('entry','common','base','worker','provenance','crypto','orchestrator')},
    'phase':{name+'.py' for name in ('entry','dependencies','phases','gate','adapter')},
}
CALLBACKS = {'existing_consumers', 'public_receiver', 'authority_provider'}
CODES = {'grant-refused', 'source-refused', 'callback-refused', 'initial-failed',
         'capture-failed', 'baseline-failed', 'public-receiver-failed', 'crypto-failed',
         'authority-failed', 'acceptance-failed', 'restage-failed', 'cancelled',
         'deadline', 'cleanup-failed', 'status-persistence-failed'}
STATUS_FIELDS = {'schema_version','purpose','status','initial_exit_code','callback_entered',
    'input_acceptance','restage','cleanup','cancelled','error_code','hardware_validation',
    'production_trust','stable_promotion','development_only','selected_for_release','original_B_continuity',
    'source_commit','run_id','run_attempt','execution_grant_sha256','initial_invocation_sha256',
    'actor_contract_sha256'}


class Refused(ValueError):
    pass


def need(value, reason):
    if not value:
        raise Refused(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def decode(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'grant-refused'); value[key] = item
        return value
    def invalid(_):
        raise Refused('grant-refused')
    need(type(raw) is bytes and 0 < len(raw) <= FILE_LIMIT, 'grant-refused')
    value = json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    need(type(value) is dict, 'grant-refused')
    return value


def relative(name):
    need(type(name) is str and len(name) <= 512 and
         re.fullmatch(r'[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+)*', name) and
         all(part not in ('.', '..') for part in name.split('/')), 'source-refused')
    return name


def check(deadline, cancelled=None):
    need(type(deadline) in (int, float) and math.isfinite(deadline) and
         time.monotonic() < deadline, 'deadline')
    if cancelled is not None and cancelled():
        raise KeyboardInterrupt()


def identity(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_nlink',
        'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def read(path, deadline, limit=FILE_LIMIT):
    """Bound bytes to opened and still-named file/ancestor identities."""
    path = Path(path).absolute()
    need('..' not in path.parts, 'source-refused')
    fds, ancestors, fd = [], [], None
    try:
        fds.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        current = Path('/')
        for part in path.parts[1:-1]:
            check(deadline)
            fds.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1]))
            current /= part; ancestors.append((current, os.fstat(fds[-1])))
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fds[-1])
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit, 'source-refused')
        chunks, size = [], 0
        while True:
            check(deadline)
            block = os.read(fd, min(65536, limit + 1 - size))
            if not block: break
            chunks.append(block); size += len(block)
            need(size <= limit, 'source-refused')
        need(size == before.st_size and identity(before) == identity(os.fstat(fd)) ==
             identity(os.stat(path.name, dir_fd=fds[-1], follow_symlinks=False)), 'source-refused')
        for name, info in ancestors:
            now = name.lstat()
            need((now.st_dev, now.st_ino, now.st_mode) == (info.st_dev, info.st_ino, info.st_mode), 'source-refused')
        return b''.join(chunks), stat.S_IMODE(before.st_mode), identity(before)
    finally:
        if fd is not None: os.close(fd)
        for item in reversed(fds): os.close(item)


def code_objects(code):
    yield code
    for item in code.co_consts:
        if isinstance(item, types.CodeType):
            yield from code_objects(item)


class Sources:
    def __init__(self, root, grant, deadline):
        self.root, self.grant = Path(root).absolute(), grant
        self.raw, self.identities = {}, {}
        self.codes = {}
        self.grant_pin = None
        self.graph_observation = None
        rows = grant['source_files']
        need(type(rows) is dict and 240 <= len(rows) <= 20000, 'source-refused')
        total = 0
        for name, row in rows.items():
            relative(name)
            need(type(row) is dict and set(row) == {'sha256', 'mode'} and
                 type(row['mode']) is int and row['mode'] in (0o644, 0o755) and
                 type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'source-refused')
            raw, mode, node = read(self.root / name, deadline)
            total += len(raw)
            need(total <= TOTAL_LIMIT and mode == row['mode'] and digest(raw) == row['sha256'], 'source-refused')
            self.raw[name], self.identities[name] = raw, node

    def guard(self, deadline, cancelled=None):
        for name, original in self.raw.items():
            check(deadline, cancelled)
            raw, mode, node = read(self.root / name, deadline)
            need(raw == original and mode == self.grant['source_files'][name]['mode'] and
                 node == self.identities[name], 'source-refused')

    def module(self, name, path):
        value = types.ModuleType(name); value.__file__ = str(self.root / path)
        def importer(module, globals=None, locals=None, fromlist=(), level=0):
            need(not level and module.split('.')[0] in sys.stdlib_module_names, 'source-refused')
            standard = sysconfig.get_path('stdlib')
            previous = list(sys.path)
            try:
                sys.path[:] = [standard,str(Path(standard)/'lib-dynload')]
                value = builtins.__import__(module, globals, locals, fromlist, level)
                for key in (module.split('.')[0],module):
                    item = sys.modules.get(key)
                    origin = getattr(item,'__file__',None)
                    if origin:
                        need(Path(origin).absolute().is_relative_to(standard),'source-refused')
                    else:
                        need(getattr(getattr(item,'__spec__',None),'origin',None) in ('built-in','frozen'),'source-refused')
                return value
            finally:sys.path[:] = previous
        value.__dict__['__builtins__'] = {**vars(builtins), '__import__': importer}
        exec(compile(self.raw[path], value.__file__, 'exec'), value.__dict__)
        return value

    def callback(self, role, callback, deadline):
        self.guard(deadline)
        row = self.grant['callbacks'][role]
        need(type(row) is dict and set(row) == {'path', 'module', 'qualname'}, 'callback-refused')
        path = relative(row['path'])
        function = callback.__func__ if isinstance(callback, types.MethodType) else callback
        namespace = getattr(function,'__globals__',{})
        loaded = sys.modules.get(row['module'])
        need(type(function) is types.FunctionType and path in self.raw and
             function.__module__ == row['module'] and function.__qualname__ == row['qualname'] and
             type(loaded) is types.ModuleType and loaded.__dict__ is namespace and
             namespace.get('__name__') == row['module'] and
             namespace.get('__file__') == str(self.root / path) and
             function.__code__.co_filename == str(self.root / path), 'callback-refused')
        candidates = [code for code in code_objects(compile(self.raw[path], str(self.root / path), 'exec'))
                      if code.co_qualname == row['qualname']]
        need(len(candidates) == 1 and function.__code__ == candidates[0], 'callback-refused')
        if isinstance(callback,types.MethodType):
            owner = loaded
            for part in row['qualname'].split('.')[:-1]:
                need(part != '<locals>','callback-refused')
                owner = vars(owner).get(part)
                need(owner is not None,'callback-refused')
            need(type(callback.__self__) is owner and owner.__module__ == row['module'],'callback-refused')
            qualifier = '.'.join(row['qualname'].split('.')[:-1])
            nodes = ast.parse(self.raw[path]).body
            declaration = None
            for part in qualifier.split('.'):
                matches = [node for node in nodes if isinstance(node,ast.ClassDef) and node.name == part]
                need(len(matches) == 1,'callback-refused')
                declaration = matches[0];nodes = declaration.body
            need(owner.__qualname__ == qualifier and not declaration.bases and owner.__bases__ == (object,),
                 'callback-refused')
            declared_methods = {node.name for node in nodes if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef))}
            for key,value in vars(owner).items():
                if isinstance(value,(staticmethod,classmethod)):value = value.__func__
                if isinstance(value,types.FunctionType):
                    need(key in declared_methods and value.__qualname__ == qualifier+'.'+key,'callback-refused')
                    self.global_function(value)
            need(all(key in vars(owner) for key in declared_methods),'callback-refused')
        # Same code transplanted into a fabricated globals dictionary is refused.
        # Project-module globals must originate in this authenticated closure.
        for value in namespace.values():
            if isinstance(value,types.ModuleType):
                origin = getattr(value,'__file__',None)
                if origin and Path(origin).absolute().is_relative_to(self.root):
                    relative_path = Path(origin).absolute().relative_to(self.root).as_posix()
                    need(relative_path in self.raw,'callback-refused')
                    for member in value.__dict__.values():
                        if isinstance(member,types.FunctionType):self.global_function(member)
            elif isinstance(value,types.FunctionType):self.global_function(value)

    def global_function(self, function):
        filename = Path(function.__code__.co_filename).absolute()
        if filename.is_relative_to(sysconfig.get_path('stdlib')):return
        need(filename.is_relative_to(self.root),'callback-refused')
        path = filename.relative_to(self.root).as_posix()
        need(path in self.raw,'callback-refused')
        if path not in self.codes:
            self.codes[path] = list(code_objects(compile(self.raw[path],str(filename),'exec')))
        need(any(function.__code__ == code for code in self.codes[path]),'callback-refused')
        module = sys.modules.get(function.__module__)
        need(type(module) is types.ModuleType and module.__dict__ is function.__globals__ and
             function.__globals__.get('__file__') == str(filename),'callback-refused')

    def class_state(self, value, path, module):
        """Exact captured class/method/descriptor state, including declared slots."""
        need(type(module) is types.ModuleType and module.__file__ == str(self.root/path)
             and path in self.raw, 'callback-refused')
        cls = type(value)
        declarations = [node for node in ast.parse(self.raw[path]).body
                        if isinstance(node, ast.ClassDef) and node.name == cls.__name__]
        need(len(declarations) == 1 and not declarations[0].bases and cls.__bases__ == (object,)
             and module.__dict__.get(cls.__name__) is cls and cls.__module__ == module.__name__
             and cls.__qualname__ == cls.__name__, 'callback-refused')
        declaration = declarations[0]
        methods = {node.name:node for node in declaration.body if isinstance(node,ast.FunctionDef)}
        compiled = {code.co_qualname:code for code in code_objects(
            compile(self.raw[path], str(self.root/path), 'exec'))}
        constants = {}
        def literal(node):
            if isinstance(node,ast.Name):
                need(node.id in constants,'callback-refused');return constants[node.id]
            if isinstance(node,ast.Tuple):return tuple(literal(item) for item in node.elts)
            if isinstance(node,ast.BinOp) and isinstance(node.op,(ast.Mult,ast.Pow,ast.Add,ast.Sub)):
                left,right = literal(node.left),literal(node.right)
                need(type(left) is int and type(right) is int and abs(left) <= 2**63 and
                     abs(right) <= 2**63 and (not isinstance(node.op,ast.Pow) or 0 <= right <= 32),'callback-refused')
                result = left*right if isinstance(node.op,ast.Mult) else left**right if isinstance(node.op,ast.Pow) else (
                    left+right if isinstance(node.op,ast.Add) else left-right)
                need(abs(result) <= 2**63,'callback-refused');return result
            try:return ast.literal_eval(node)
            except (ValueError,TypeError):raise Refused('callback-refused') from None
        for node in ast.parse(self.raw[path]).body:
            if isinstance(node,ast.Assign) and len(node.targets) == 1:
                try:constant = literal(node.value)
                except Refused:continue
                target = node.targets[0]
                if isinstance(target,ast.Name):constants[target.id] = constant
                elif isinstance(target,ast.Tuple) and type(constant) is tuple and len(target.elts) == len(constant) and all(
                        isinstance(item,ast.Name) for item in target.elts):
                    constants.update({item.id:entry for item,entry in zip(target.elts,constant)})
        def default(node):
            return literal(node)
        for name,node in methods.items():
            function = vars(cls).get(name)
            if node.decorator_list:
                need(len(node.decorator_list) == 1 and isinstance(node.decorator_list[0],ast.Name)
                     and node.decorator_list[0].id == 'contextmanager'
                     and type(function) is types.FunctionType and
                     function.__code__ == contextmanager(lambda:None).__code__ and
                     function.__globals__ is contextmanager.__globals__ and
                     function.__code__.co_freevars == ('func',) and function.__closure__ is not None
                     and len(function.__closure__) == 1 and
                     function.__closure__[0].cell_contents is getattr(function,'__wrapped__',None)
                     and function.__defaults__ is None and function.__kwdefaults__ is None,'callback-refused')
                function = function.__wrapped__
            need(type(function) is types.FunctionType and function.__globals__ is module.__dict__
                 and function.__code__ == compiled.get(cls.__name__+'.'+name)
                 and function.__qualname__ == cls.__name__+'.'+name and not function.__closure__,'callback-refused')
            expected = tuple(default(item) for item in node.args.defaults) or None
            keyword = {key.arg:default(item) for key,item in zip(node.args.kwonlyargs,node.args.kw_defaults)
                       if item is not None} or None
            need(type(function.__defaults__) is type(expected) and function.__defaults__ == expected and
                 function.__kwdefaults__ == keyword and encoded(function.__defaults__) == encoded(expected)
                 and encoded(function.__kwdefaults__) == encoded(keyword),'callback-refused')
        slots = [node for node in declaration.body if isinstance(node,ast.Assign) and
                 any(isinstance(target,ast.Name) and target.id == '__slots__' for target in node.targets)]
        boilerplate = {'__module__','__doc__','__dict__','__weakref__','__firstlineno__','__static_attributes__'}
        if slots:
            need(len(slots) == 1,'callback-refused')
            names = ast.literal_eval(slots[0].value)
            need(type(names) is tuple and len(set(names)) == len(names) and
                 all(type(name) is str and name not in ('__dict__','__weakref__') for name in names)
                 and vars(cls).get('__slots__') == names and '__dict__' not in vars(cls),'callback-refused')
            for name in names:
                descriptor = vars(cls).get(name)
                need(type(descriptor) is types.MemberDescriptorType and descriptor.__objclass__ is cls
                     and descriptor.__name__ == name,'callback-refused')
            state = {name:vars(cls)[name].__get__(value,cls) for name in names}
            allowed = set(methods)|boilerplate|set(names)|{'__slots__'}
        else:
            need('__slots__' not in vars(cls),'callback-refused')
            state = object.__getattribute__(value,'__dict__')
            need(type(state) is dict,'callback-refused')
            fields = {node.attr for node in ast.walk(declaration) if isinstance(node,ast.Attribute)
                      and isinstance(node.value,ast.Name) and node.value.id == 'self'
                      and isinstance(node.ctx,ast.Store)}
            need(set(state) <= fields,'callback-refused')
            allowed = set(methods)|boilerplate
        need(set(vars(cls)) <= allowed,'callback-refused')
        return dict(state)

    def graph_function(self, function, module, compiled=None):
        """Private loader namespaces bind objects, never filename labels alone."""
        need(type(function) is types.FunctionType and type(module) is types.ModuleType
             and function.__globals__ is module.__dict__,'callback-refused')
        path = Path(module.__file__).absolute().relative_to(self.root).as_posix()
        if compiled is None:compiled = {}
        if path in self.raw and path not in compiled:
            compiled[path] = tuple(code_objects(compile(self.raw[path],str(self.root/path),'exec')))
        need(path in self.raw and function.__code__.co_filename == str(self.root/path) and
             any(function.__code__ == code for code in compiled.get(path,())),'callback-refused')

    def source_graph(self, session, *, capture=False):
        """Explicit actual namespaces supplied by this Session's captured loaders."""
        module = sys.modules.get(type(session).__module__)
        state = self.class_state(session,'scripts/ci/development/repository_handoff.py',module)
        need(session.sources is self,'callback-refused')
        self.class_state(self,'scripts/ci/development/repository_handoff.py',module)
        graph = state['source_graph']
        need(type(graph) is dict and (not graph or set(graph) == {'entry','runtime','collector','phase','original','original_aliases'}),
             'callback-refused')
        modules = {}
        compiled = {}
        if graph:
            modules['scripts/port/repository-native-handoff/entry.py'] = graph['entry']
            expected = {'runtime':{'capture','producer','launch','transport','supervisor','broker'},
                'collector':{'common','base','provenance','crypto','orchestrator'},
                'phase':{'dependencies','phases','gate','adapter'}}
            for role,names in expected.items():
                need(type(graph[role]) is dict and set(graph[role]) == names,'callback-refused')
                for name,value in graph[role].items():modules[PREFIXES[role]+'/'+name+'.py'] = value
            original = {'package_checks':'scripts/checks/package_checks.py',**{
                name:'scripts/ci/'+name+'.py' for name in ('native_arm','integration_export','lifecycle_inventory',
                    'repository_projection','desktop_projection','commit_image','sign_fixture','integration')}}
            need(type(graph['original']) is dict and (not graph['original'] or set(graph['original']) == set(original)),
                 'callback-refused')
            for name,value in graph['original'].items():modules[original[name]] = value
            aliases = graph['original_aliases']
            need(type(aliases) is dict and (not aliases if not graph['original'] else
                 set(aliases) == {'repository_projection.inventory','desktop_projection.policy'}),'callback-refused')
            alias_paths = {'repository_projection.inventory':'scripts/ci/lifecycle_inventory.py',
                           'desktop_projection.policy':'scripts/ci/integration_export.py'}
            for label,value in aliases.items():
                parent,name = label.split('.')
                need(graph['original'][parent].__dict__.get(name) is value and type(value) is types.ModuleType
                     and value.__file__ == str(self.root/alias_paths[label]),'callback-refused')
            for path,value in modules.items():
                need(type(value) is types.ModuleType and value.__file__ == str(self.root/path) and path in self.raw,
                     'callback-refused')
                self.graph_namespace(value,path,modules,aliases,compiled)
            for label,value in aliases.items():self.graph_namespace(value,alias_paths[label],modules,aliases,compiled)
            observation = self.graph_identity((module,)+tuple(modules.values())+tuple(aliases.values()))
            if capture:
                # Only the two authenticated loader boundaries may establish it.
                need(session.used is True and session.controller is None and
                     ((self.graph_observation is None and not graph['original']) or
                      (self.graph_observation is not None and graph['original'])), 'callback-refused')
                if self.graph_observation is not None:
                    prior = tuple(value for path,value in modules.items() if path not in original.values())
                    need(self.graph_identity((module,)+prior) == self.graph_observation,'callback-refused')
                self.guard(session.job_deadline,session.cancelled)
                self.graph_observation = observation
            else:
                need(self.graph_observation is not None and observation == self.graph_observation,'callback-refused')
        return modules

    def graph_identity(self, modules):
        """Exact observed executable references plus closed loader closure data."""
        seen = set();count = 0;compiled = {};namespaces = set();functions = []
        def observe(value,depth=0):
            nonlocal count
            count += 1
            need(depth <= 64 and count <= 100000,'callback-refused')
            if value is None or type(value) in (str,bytes,int,bool,float):return (type(value),value)
            if isinstance(value,Path):return (type(value),str(value))
            if id(value) in seen:return ('reference',id(value))
            seen.add(id(value))
            if type(value) is types.ModuleType:
                origin = getattr(value,'__file__',None)
                if not origin or not Path(origin).absolute().is_relative_to(self.root):return ('module',id(value))
                path = Path(origin).absolute().relative_to(self.root).as_posix()
                need(path in self.raw,'callback-refused');namespaces.add(id(value.__dict__))
                items = []
                for name,item in sorted(value.__dict__.items()):
                    if type(item) is types.FunctionType:
                        filename = Path(getattr(item,'__wrapped__',item).__code__.co_filename).absolute()
                        if filename.is_relative_to(self.root):
                            if filename == Path(origin).absolute():
                                need(getattr(item,'__wrapped__',item).__globals__ is value.__dict__,'callback-refused')
                            items.append((name,observe(item,depth+1)))
                    elif type(item) is type:items.append((name,observe(item,depth+1)))
                    elif type(item) is types.ModuleType:
                        child = getattr(item,'__file__',None)
                        if child and Path(child).absolute().is_relative_to(self.root):items.append((name,observe(item,depth+1)))
                return ('module',id(value),tuple(items))
            if type(value) is types.FunctionType:
                origin = Path(value.__code__.co_filename).absolute()
                if origin.is_relative_to(self.root):
                    path = origin.relative_to(self.root).as_posix()
                    if path in self.raw and path not in compiled:
                        compiled[path] = tuple(code_objects(compile(self.raw[path],str(origin),'exec')))
                    need(path in self.raw and value.__globals__.get('__file__') == str(origin) and
                         any(value.__code__ == code for code in compiled.get(path,())),
                         'callback-refused')
                    functions.append(value)
                else:need(origin.is_relative_to(sysconfig.get_path('stdlib')),'callback-refused')
                cells = []
                for name,cell in zip(value.__code__.co_freevars,value.__closure__ or ()):
                    # These three source-owned caches grow when captured imports run.
                    # Their references remain fixed; executable/guard/data cells do not.
                    item = cell.cell_contents
                    cells.append((name,id(cell),('cache',id(item)) if name in ('trusted','compiled','contexts')
                                  else observe(item,depth+1)))
                return ('function',id(value),id(value.__globals__),value.__code__,
                        observe(value.__defaults__,depth+1),observe(value.__kwdefaults__,depth+1),tuple(cells))
            if type(value) is type:
                return ('class',id(value),tuple((name,observe(item,depth+1)) for name,item in sorted(vars(value).items())
                    if type(item) is types.FunctionType or isinstance(item,(types.MemberDescriptorType,property))))
            if type(value) is dict:
                need(all(type(key) in (str,int) for key in value),'callback-refused')
                return ('dict',tuple((type(key).__name__,key,observe(item,depth+1)) for key,item in
                                     sorted(value.items(),key=lambda row:(type(row[0]).__name__,row[0]))))
            if type(value) in (list,tuple):return (type(value),tuple(observe(item,depth+1) for item in value))
            if type(value) in (set,frozenset):
                need(all(type(item) in (str,int) for item in value),'callback-refused')
                return (type(value),tuple(sorted(value,key=lambda item:(type(item).__name__,item))))
            # Opaque standard-library handles/descriptors are bound by identity.
            return ('opaque',type(value),id(value))
        result = tuple(observe(module) for module in modules)
        need(all(id(function.__globals__) in namespaces for function in functions),'callback-refused')
        return result

    def graph_namespace(self,module,path,modules,aliases,cache):
        """All declared functions/import hooks retain their captured implementation."""
        entry_path = PREFIXES['runtime']+'/entry.py'
        overrides = {
            (PREFIXES['collector']+'/common.py','load_snapshot'):'dependency_entry.<locals>.load_snapshot',
            (PREFIXES['collector']+'/orchestrator.py','load_snapshot'):'dependency_entry.<locals>.load_snapshot',
            (PREFIXES['phase']+'/dependencies.py','load_collector'):'dependency_entry.<locals>.load_collector',
            (PREFIXES['phase']+'/dependencies.py','source'):'dependency_entry.<locals>.source',
        }
        if path not in cache:cache[path] = tuple(code_objects(compile(self.raw[path],str(self.root/path),'exec')))
        compiled = {code.co_qualname:code for code in cache[path]}
        for node in ast.parse(self.raw[path]).body:
            if not isinstance(node,ast.FunctionDef):continue
            value = module.__dict__.get(node.name)
            if (path,node.name) in overrides:
                self.graph_function(value,modules[entry_path],cache)
                need(value.__code__.co_qualname == overrides[path,node.name],'callback-refused')
                continue
            if node.decorator_list:
                need(len(node.decorator_list) == 1 and isinstance(node.decorator_list[0],ast.Name)
                     and node.decorator_list[0].id == 'contextmanager' and type(value) is types.FunctionType
                     and value.__code__ == contextmanager(lambda:None).__code__
                     and value.__globals__ is contextmanager.__globals__ and value.__closure__ is not None
                     and len(value.__closure__) == 1 and
                     value.__closure__[0].cell_contents is getattr(value,'__wrapped__',None),'callback-refused')
                value = value.__wrapped__
            self.graph_function(value,module,cache)
            need(value.__code__ == compiled.get(node.name),'callback-refused')
        for value in module.__dict__.values():
            if type(value) is types.FunctionType:
                unwrapped = getattr(value,'__wrapped__',value)
                filename = Path(unwrapped.__code__.co_filename).absolute()
                if filename.is_relative_to(self.root):
                    function_path = filename.relative_to(self.root).as_posix()
                    need(function_path in modules,'callback-refused')
                    self.graph_function(unwrapped,module if function_path == path else modules[function_path],cache)
            if type(value) is types.ModuleType:
                origin = getattr(value,'__file__',None)
                if origin and Path(origin).absolute().is_relative_to(self.root):
                    relative_path = Path(origin).absolute().relative_to(self.root).as_posix()
                    need(modules.get(relative_path) is value or any(value is item for item in aliases.values()),
                         'callback-refused')
        language = module.__dict__.get('__builtins__')
        need(type(language) is dict,'callback-refused')
        for name in ('__import__','compile','exec'):
            value = language.get(name)
            if value is vars(builtins)[name]:continue
            need(type(value) is types.FunctionType,'callback-refused')
            filename = Path(value.__code__.co_filename).absolute()
            if filename == self.root/entry_path:self.graph_function(value,modules[entry_path],cache)
            else:self.global_function(value)


def preflight(root, grant_raw, grant_pin, *, deadline):
    """Authenticate complete sources/maps/policy before executing project imports."""
    check(deadline)
    need(type(grant_pin) is str and re.fullmatch('[0-9a-f]{64}', grant_pin) and
         digest(grant_raw) == grant_pin, 'grant-refused')
    grant = decode(grant_raw)
    need(set(grant) == {'schema_version', 'purpose', 'source_peer_preflight', 'development_only',
        'added_seconds', 'source_commit', 'recipe_source_commit', 'run_id', 'run_attempt',
        'source_files', 'maps', 'callbacks', 'policy_path', 'license_path','actor_contract_sha256',
        'initial_invocation_sha256'} and
        type(grant['schema_version']) is int and grant['schema_version'] == 1 and
        grant['purpose'] == 'reviewed-same-job-handoff-execution' and
        grant['source_peer_preflight'] == 'PASS' and grant['development_only'] is True and
        type(grant['added_seconds']) is int and grant['added_seconds'] == 1200 and
        type(grant['maps']) is dict and set(grant['maps']) == set(PREFIXES) and
        type(grant['callbacks']) is dict and set(grant['callbacks']) == CALLBACKS, 'grant-refused')
    for key in ('actor_contract_sha256','initial_invocation_sha256'):
        need(type(grant[key]) is str and re.fullmatch('[0-9a-f]{64}',grant[key]),'grant-refused')
    for key, pattern in {'source_commit':'[0-9a-f]{40}', 'recipe_source_commit':'[0-9a-f]{40}',
                        'run_id':'[1-9][0-9]{0,19}', 'run_attempt':'[1-9][0-9]{0,9}'}.items():
        need(type(grant[key]) is str and re.fullmatch(pattern, grant[key]), 'grant-refused')
    sources = Sources(root, grant, deadline)
    initial = 'scripts/ci/integration.lock.json'
    need(initial in sources.raw and digest(sources.raw[initial]) == INITIAL, 'source-refused')
    lock = decode(sources.raw[initial])
    need(len(lock['source_files']) == 159 and len(lock['generated_fixture_files']) == 125 and
         all(grant['source_files'].get(name) == row for name, row in lock['source_files'].items()), 'source-refused')
    for path, pin in ((grant['policy_path'], POLICY), (grant['license_path'], LICENSE)):
        need(relative(path) in sources.raw and digest(sources.raw[path]) == pin, 'grant-refused')
    policy = decode(sources.raw[grant['policy_path']])
    need(policy.get('supported_models') == [] and policy.get('platform_scope') == 'generic-builder-only'
         and policy.get('review_status') == 'ACCEPTED', 'grant-refused')
    for role, prefix in PREFIXES.items():
        row = grant['maps'][role]
        need(type(row) is dict and set(row) == {'path', 'sha256'} and relative(row['path']) in sources.raw
             and digest(sources.raw[row['path']]) == row['sha256'], 'source-refused')
        mapping = decode(sources.raw[row['path']])
        need(set(mapping) == MAP_NAMES[role] and all(type(value) is dict and
             grant['source_files'].get(prefix + '/' + name) == value
             for name, value in mapping.items()), 'source-refused')
    sources.grant_pin = grant_pin
    return sources


def bindings(sources, callbacks, deadline):
    need(type(callbacks) is dict and set(callbacks) == CALLBACKS, 'callback-refused')
    for role, callback in callbacks.items():
        sources.callback(role, callback, deadline)
        if role != 'existing_consumers':authority_state(sources,callback,deadline)


def authority_state(sources,callback,deadline):
    """Authenticate actual issuer/receiver self and its closed immutable live state."""
    need(isinstance(callback,types.MethodType),'callback-refused')
    instance = callback.__self__
    declared = type(instance).__dict__.get('handoff_binding')
    need(type(declared) is types.FunctionType,'callback-refused')
    sources.global_function(declared)
    binding = getattr(instance,'handoff_binding')
    need(isinstance(binding,types.MethodType) and binding.__self__ is instance and
         binding.__func__ is declared,'callback-refused')
    module = sys.modules.get(type(instance).__module__)
    path = Path(callback.__func__.__code__.co_filename).relative_to(sources.root).as_posix()
    state = sources.class_state(instance,path,module)
    session = state.get('_session')
    graph = sources.source_graph(session) if session is not None else {}
    path_types = {type(Path())}
    for namespace in (callback.__func__.__globals__,*(module.__dict__ for module in graph.values())):
        base = namespace.get('Path')
        constructor = vars(base).get('__new__') if type(base) is type else None
        if type(constructor) is types.FunctionType and constructor.__code__ == Path.__new__.__code__:
            need(constructor.__globals__.get('Path') is base,'callback-refused')
            concrete = constructor.__globals__.get('PosixPath')
            need(type(concrete) is type and issubclass(concrete,base),'callback-refused')
            path_types.add(concrete)
    # No injected executable attributes can substitute a fake verification result.
    seen = set();count = 0
    def inspect_state(value,depth=0):
        nonlocal count
        check(deadline);count += 1
        need(depth <= 32 and count <= 20000,'callback-refused')
        if id(value) in seen:return
        seen.add(id(value))
        if isinstance(value,(types.FunctionType,types.MethodType)):raise Refused('callback-refused')
        if isinstance(value,types.ModuleType):
            origin = getattr(value,'__file__',None)
            need(origin is not None and Path(origin).absolute().is_relative_to(sources.root),'callback-refused')
            path = Path(origin).absolute().relative_to(sources.root).as_posix()
            need(path in sources.raw,'callback-refused')
            for member in value.__dict__.values():
                if isinstance(member,types.FunctionType):sources.global_function(member)
        elif type(value) is dict:
            for key,item in value.items():
                need(type(key) is str,'callback-refused');inspect_state(item,depth+1)
        elif type(value) in (list,tuple):
            for item in value:inspect_state(item,depth+1)
        elif value is None or type(value) in (str,bytes,int,bool) or type(value) in path_types:pass
        elif type(value) is float:need(math.isfinite(value),'callback-refused')
        elif value is session and session is not None:
            owner = sys.modules.get(type(value).__module__)
            session_state = sources.class_state(value,'scripts/ci/development/repository_handoff.py',owner)
            for name,item in session_state.items():
                if name == 'source_graph':continue  # Namespace objects are authenticated above.
                if name == 'supervise' and item is not None:
                    supervisor_state(item,value);continue
                if name == 'controller' and item is not None:
                    need('scripts/ci/integration.py' in graph,'callback-refused')
                    inspect_state(sources.class_state(item,'scripts/ci/integration.py',graph['scripts/ci/integration.py']),depth+1);continue
                if name == 'cancelled' and item is not None:
                    need(type(item) is types.FunctionType,'callback-refused');sources.global_function(item)
                    need(not item.__closure__,'callback-refused');continue
                inspect_state(item,depth+1)
        elif value is sources:
            owner = sys.modules.get(type(value).__module__)
            source_state = sources.class_state(value,'scripts/ci/development/repository_handoff.py',owner)
            need(source_state['root'] == sources.root and digest(encoded(source_state['grant'])) == sources.grant_pin,
                 'callback-refused')
            for name,item in source_state.items():
                if name == 'graph_observation':continue  # Compared with actual namespaces above.
                if name == 'codes':
                    need(type(item) is dict,'callback-refused')
                    for source_path,codes in item.items():
                        need(source_path in sources.raw and type(codes) is list and codes == list(code_objects(
                            compile(sources.raw[source_path],str(sources.root/source_path),'exec'))),'callback-refused')
                else:inspect_state(item,depth+1)
        else:raise Refused('callback-refused')
    def supervisor_state(value,owner):
        path = PREFIXES['runtime']+'/supervisor.py'
        need(path in graph,'callback-refused')
        data = sources.class_state(value,path,graph[path])
        guard = data.pop('source_guard')
        entry = graph[PREFIXES['runtime']+'/entry.py']
        sources.graph_function(guard,entry)
        need(guard.__code__.co_qualname == 'services.<locals>.source_guard' and guard.__closure__ is not None,
             'callback-refused')
        closure = dict(zip(guard.__code__.co_freevars,(cell.cell_contents for cell in guard.__closure__)))
        runtime_rows = decode(sources.raw[sources.grant['maps']['runtime']['path']])
        need(set(closure) == {'cancelled','job_deadline','root','rows','source_identities'} and
             closure['cancelled'] is owner.cancelled and closure['job_deadline'] == owner.job_deadline and
             closure['root'] == sources.root/PREFIXES['runtime'] and closure['rows'] == runtime_rows and
             closure['source_identities'] == {name:sources.identities[PREFIXES['runtime']+'/'+name]
                                             for name in runtime_rows} and
             value.deadline == owner.work_end and value.cleanup_seconds == 30 and
             value.result_limit == graph[path].RESULT_LIMIT and value.stream_limit == graph[path].STREAM_LIMIT,
             'callback-refused')
        expected_grants = {role:{'module':'broker','source_file':str(sources.root/PREFIXES['runtime']/'broker.py'),
                               'source_sha256':runtime_rows['broker.py']['sha256']} for role in graph[path].ROLES}
        broker_identity = graph[path].source(sources.root/PREFIXES['runtime']/'broker.py')
        need(data['grants'] == expected_grants and data['source_identities'] == {
             role:broker_identity for role in expected_grants},'callback-refused')
        inspect_state(data)
    inspect_state(state)
    expected = {'schema_version':1,'purpose':'root-repository-handoff-live-binding',
        **{key:sources.grant[key] for key in ('source_commit','run_id','run_attempt','actor_contract_sha256',
                                          'initial_invocation_sha256')},
        'execution_grant_sha256':sources.grant_pin,'integration_lock_sha256':INITIAL,
        'policy_sha256':POLICY,'license_sha256':LICENSE,'supported_models':[]}
    observed = binding()
    check(deadline)
    need(type(observed) is dict and observed == expected and encoded(observed) == encoded(expected) and
         len(encoded(observed)) <= 4096,'callback-refused')


def returned_file(sources, role, callback, args, *, deadline):
    sources.callback(role, callback, deadline)
    authority_state(sources,callback,deadline)
    value = callback(*args, deadline=deadline)
    sources.callback(role, callback, deadline)
    authority_state(sources,callback,deadline)
    need(type(value) is dict and set(value) == {'path', 'sha256'} and
         type(value['path']) is str and Path(value['path']).is_absolute() and
         type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['sha256']), 'callback-refused')
    raw, _, node = read(value['path'], deadline)
    need(digest(raw) == value['sha256'] and node[4] == os.geteuid() and not node[2] & 0o022,
         'callback-refused')
    return Path(value['path']), raw, value['sha256']


def authority_matches(candidate, accepted):
    """Check issued complete data; this function never manufactures acceptance."""
    need(type(candidate) is dict and type(accepted) is dict and set(accepted) == set(candidate), 'authority-failed')
    expected = json.loads(json.dumps(candidate))
    need(expected.get('status') == 'PENDING' and accepted.get('status') == 'PASS' and
         type(expected.get('crypto')) is dict and expected['crypto'].get('status') == 'PENDING' and
         type(accepted.get('crypto')) is dict and accepted['crypto'].get('status') == 'PASS', 'authority-failed')
    # Normalize only the comparison copy; accepted bytes come solely from issuer.
    expected['status'], expected['crypto']['status'] = 'PASS', 'PASS'
    need(expected == accepted and encoded(expected) == encoded(accepted), 'authority-failed')


class Session:
    """One original producer plus one deadline-bound baseline/phase consumer."""
    def __init__(self, sources, output, *, job_deadline, cancelled=None):
        check(job_deadline, cancelled)
        self.sources, self.output = sources, Path(output).absolute()
        self.job_deadline, self.cancelled = job_deadline, cancelled
        self.used = False; self.end = None; self.work_end = None
        self.controller = self.pending_capture = self.collected = self.supervise = None
        self.private = None; self.private_node = None
        self.operation = 'source-refused'
        self.source_graph = {}
        self.result = {'schema_version':1, 'purpose':'same-job-repository-handoff', 'status':'NOT RUN',
            'initial_exit_code':None, 'callback_entered':False, 'input_acceptance':'NOT RUN',
            'restage':'NOT RUN', 'cleanup':'NOT RUN', 'cancelled':False, 'error_code':None,
            'hardware_validation':'NOT RUN', 'production_trust':'NOT RUN', 'stable_promotion':'NOT RUN',
            'development_only':True, 'selected_for_release':False, 'original_B_continuity':False,
            'source_commit':getattr(sources,'grant',{}).get('source_commit'),
            'run_id':getattr(sources,'grant',{}).get('run_id'),
            'run_attempt':getattr(sources,'grant',{}).get('run_attempt'),
            'execution_grant_sha256':getattr(sources,'grant_pin',None),
            'actor_contract_sha256':getattr(sources,'grant',{}).get('actor_contract_sha256'),
            'initial_invocation_sha256':getattr(sources,'grant',{}).get('initial_invocation_sha256')}

    @contextmanager
    def step(self, code):
        need(code in CODES,'grant-refused')
        try:yield
        except BaseException as error:
            if self.result['error_code'] is None:
                self.result['error_code'] = 'cancelled' if isinstance(error,KeyboardInterrupt) else (
                    str(error) if type(error) is Refused and str(error) in CODES else code)
            raise

    def tick(self):
        check(self.work_end, self.cancelled)
        self.sources.guard(self.work_end, self.cancelled)

    def pending_consumer(self, controller, services, modules, collector, collector_pins):
        # Existing broad consumers have already returned; no added work precedes E.
        self.end = min(self.job_deadline, time.monotonic() + 1200)
        self.work_end = self.end - 60
        self.tick()
        self.controller = controller; self.result['callback_entered'] = True
        self.operation = 'capture-failed'
        broker, capture = modules['broker'], modules['capture']
        self.supervise = services['supervise_factory'](self.work_end)
        job = {key:self.sources.grant[key] for key in ('source_commit','recipe_source_commit','run_id','run_attempt')}
        job.update(image_id=controller.image, nonce=services['pending'].contract['nonce'])
        broker.identity(job)
        with self.step('capture-failed'):
            selections = broker.authority_selections(controller,
                integration_lock_path=self.sources.root/'scripts/ci/integration.lock.json',
                integration_lock_pin=INITIAL, deadline=self.work_end, cancelled=self.cancelled)
            self.pending_capture = services['pending'].capture(controller, selections=selections,
                output=self.private/'pending', deadline=self.work_end)
        self.tick()
        self.operation = 'baseline-failed'
        provenance = broker.baseline_provenance(controller, job,
            repository_url='https://github.com/Gabriel-Kahen/cachy-asahi',
            deadline=self.work_end, cancelled=self.cancelled)
        need(provenance['file_count'] == 241, 'baseline-failed')
        broker.stage_exact(provenance['selections'], provenance['request']['files'], self.private/'provenance',
            deadline=self.work_end, cancelled=self.cancelled)
        raw = capture.encoded(provenance['request'])
        with self.step('baseline-failed'):
            self.collected = broker.collect_baseline(collector, collector_pins, controller,
                output=self.private/'base', provenance_root=self.private/'provenance',
                provenance_raw=raw, provenance_pin=digest(raw), deadline=self.work_end,
                supervise=self.supervise, cancelled=self.cancelled)
        base_result = capture.decode(capture.read(self.private/'base/result.json', deadline=self.work_end))
        need(len(base_result['files']) == 688 and self.collected.get('status') == 'PENDING', 'baseline-failed')
        self.job = job
        self.tick()
        return {'status':'PENDING', 'native_admission':'NOT RUN'}

    def terminal_consumer(self, code, services, modules, collector, phase, callbacks):
        self.tick()
        broker, capture = modules['broker'], modules['capture']
        pending = services['pending']
        need(type(code) is int and code == 0 and self.pending_capture is not None, 'initial-failed')
        self.operation = 'public-receiver-failed'
        with self.step('public-receiver-failed'):
            _, public_raw, _ = returned_file(self.sources,'public_receiver',callbacks['public_receiver'],
                (self.controller,self.pending_capture),deadline=self.work_end)
            path = self.private/'public-acceptance.json'
            capture.write_atomic(path,public_raw,deadline=self.work_end)
        self.tick()
        self.operation = 'crypto-failed'
        files = broker.capture_file_map(self.private/'pending',self.pending_capture,
                                       deadline=self.work_end,cancelled=self.cancelled)
        request = broker.crypto_request(self.private/'pending',files,'raw/result.json',self.job,
            public_prefix='public/',deadline=self.work_end,cancelled=self.cancelled)
        request_raw = capture.encoded(request)
        need(len(request['files']) == 128 and len(request['signed_objects']) == 15, 'crypto-failed')
        crypto_out = self.private/'crypto-output'
        with self.step('crypto-failed'):
            broker.attest_crypto(collector,self.private/'pending',request_raw,digest(request_raw),crypto_out,
                crypto_root=self.private/'crypto-inputs',deadline=self.work_end,
                supervise=self.supervise,cancelled=self.cancelled)
        # Collector publishes the actual receipt as result.json; no reconstruction.
        crypto_receipt_path = crypto_out/'result.json'
        request_path = self.private/'crypto-request.json'
        capture.write_atomic(request_path,request_raw,deadline=self.work_end)
        self.operation = 'authority-failed'
        staged = broker.terminal_inputs(self.private/'pending',self.pending_capture,self.controller,
            self.private/'authority-inputs',public_acceptance_path=path,
            crypto_request_path=request_path,crypto_receipt_path=crypto_receipt_path,
            deadline=self.work_end,cancelled=self.cancelled)
        need(staged['records']['public_acceptance'] == capture.decode(public_raw) and
             staged['files']['terminal/public-acceptance.json'] ==
             {'sha256':digest(public_raw),'bytes':len(public_raw)}, 'public-receiver-failed')
        launch_record = capture.decode(capture.read(self.private/'pending/custody/launch.json',deadline=self.work_end))
        checkpoints = pending.checkpoints.records
        candidate = broker.authority_candidate(self.private/'authority-inputs',staged['files'],self.job,
            records=staged['records'],launch_record=launch_record,checkpoints=checkpoints,native_exit=code,
            crypto_request_ref='crypto/request.json',crypto_receipt_ref='crypto/receipt.json',
            deadline=self.work_end,cancelled=self.cancelled)
        need(candidate['status'] == 'PENDING-external-authority' and candidate['file_count'] == 794, 'authority-failed')
        candidate_raw = capture.encoded(candidate['authority'])
        candidate_path = self.private/'authority-candidate.json'
        capture.write_atomic(candidate_path,candidate_raw,deadline=self.work_end)
        self.tick()
        with self.step('authority-failed'):
            _, authority_raw, authority_pin = returned_file(self.sources,'authority_provider',callbacks['authority_provider'],
                (candidate_path,digest(candidate_raw),self.private/'authority-inputs'),deadline=self.work_end)
            authority_matches(candidate['authority'],capture.decode(authority_raw))
        self.tick()
        self.operation = 'acceptance-failed'
        with self.step('acceptance-failed'):
            terminal = broker.seal_terminal(self.private/'authority-inputs',authority_raw,authority_pin,
                records=staged['records'],job=self.job,launch_record=launch_record,checkpoints=checkpoints,
                native_exit=code,phase_modules=phase,repo_root=self.sources.root,deadline=self.work_end,
                supervise=self.supervise,cancelled=self.cancelled)
        need(terminal.get('status') == 'PASS-input-acceptance', 'acceptance-failed')
        self.result['input_acceptance'] = 'PASS'
        self.tick()
        self.operation = 'restage-failed'
        components_raw = capture.encoded(self.collected['components'])
        with self.step('restage-failed'):
            outcome = broker.restage(phase,collector,self.private/'authority-inputs',authority_raw,authority_pin,
                components_raw,digest(components_raw),self.sources.raw[self.sources.grant['policy_path']],POLICY,
                self.sources.raw[self.sources.grant['license_path']],LICENSE,self.output/'phase-public',
                terminal=terminal,repo_root=self.sources.root,deadline=self.work_end,
                supervise=self.supervise,cancelled=self.cancelled)
        need(outcome.get('status') == 'PASS' and outcome.get('cleanup',{}).get('status') == 'PASS', 'restage-failed')
        self.tick()
        # Only the phase adapter's closed approved map is eligible for root export.
        raw = capture.read(self.output/'phase-public/result.json',deadline=self.work_end)
        need(capture.decode(raw) == outcome, 'restage-failed')
        collector['common'].mapped(self.output/'phase-public',{
            **outcome['public_files'], 'result.json':{'sha256':digest(raw),'bytes':len(raw)}})
        self.result['restage'] = 'PASS'

    def execute(self, argv, callbacks, runtime_contract):
        """Explicit root contract required; no default native executable callback."""
        need(not self.used, 'grant-refused'); self.used = True
        need(os.getuid() == os.geteuid() > 0 and os.getgid() == os.getegid() > 0 and
             threading.current_thread() is threading.main_thread(),'grant-refused')
        need(type(argv) is list and 0 < len(argv) <= 64 and argv[0] == 'integration' and
             all(type(item) is str and len(item) <= 4096 and '\0' not in item for item in argv) and
             type(runtime_contract) is dict and set(runtime_contract) == {'cli_sha256','endpoint_identity','env'}, 'grant-refused')
        argv = list(argv)
        check(self.job_deadline,self.cancelled)
        grant = self.sources.grant
        need(digest(encoded({'argv':argv,'output':str(self.output)})) == grant['initial_invocation_sha256'],
             'grant-refused')
        need(digest(encoded(runtime_contract)) == grant['actor_contract_sha256'],'grant-refused')
        bindings(self.sources,callbacks,self.job_deadline)
        need(all(os.environ.get(env) == grant[key] for env,key in
             (('GITHUB_SHA','source_commit'),('GITHUB_RUN_ID','run_id'),('GITHUB_RUN_ATTEMPT','run_attempt'))), 'grant-refused')
        need(grant['maps']['runtime']['sha256'] != BLOCKED_RUNTIME_MAP, 'grant-refused')
        need(not self.output.exists(), 'grant-refused')
        self.output.mkdir(mode=0o700,parents=False)
        self.private = Path(tempfile.mkdtemp(prefix='handoff-',dir=self.output))
        self.private_node = identity(self.private.lstat())
        services = collector = None
        try:
            root = self.sources.root
            entry_path = PREFIXES['runtime']+'/entry.py'
            entry = self.sources.module('root_handoff_entry',entry_path)
            maps = grant['maps']
            modules,_ = entry.authenticated(root/maps['runtime']['path'],maps['runtime']['sha256'],
                deadline=self.job_deadline,source_root=root/PREFIXES['runtime'])
            collector,collector_pins = entry.dependency_entry(root,PREFIXES['collector']+'/entry.py',
                grant['source_files'][PREFIXES['collector']+'/entry.py']['sha256'],maps['collector']['path'],
                maps['collector']['sha256'],deadline=self.job_deadline)
            phase,_ = entry.dependency_entry(root,PREFIXES['phase']+'/entry.py',
                grant['source_files'][PREFIXES['phase']+'/entry.py']['sha256'],maps['phase']['path'],
                maps['phase']['sha256'],deadline=self.job_deadline,phase=True)
            self.source_graph = {'entry':entry,'runtime':modules,'collector':collector,'phase':phase,
                                 'original':{},'original_aliases':{}}
            self.sources.source_graph(self,capture=True)
            (self.private/'custody').mkdir(mode=0o700)
            # Registration precedes replay of TERM/INT from service construction.
            with collector['common'].defer_cancellation():
                services = entry.services(modules,decode(self.sources.raw[maps['runtime']['path']]),
                    source_root=root/PREFIXES['runtime'],private_root=self.private/'custody',
                    job_deadline=self.job_deadline,cancelled=self.cancelled,**runtime_contract)
            # Checkpoint storage must be a distinct private0700 original-budget root.
            def callback(controller):
                self.sources.callback('existing_consumers',callbacks['existing_consumers'],self.job_deadline)
                callbacks['existing_consumers'](controller)
                self.sources.callback('existing_consumers',callbacks['existing_consumers'],self.job_deadline)
                # Original native.main catches consumer errors; retain the first
                # finite added failure before that enclosing returned exit1.
                try:return self.pending_consumer(controller,services,modules,collector,collector_pins)
                except BaseException as error:
                    if self.result['error_code'] is None:
                        self.result['error_code'] = 'cancelled' if isinstance(error,KeyboardInterrupt) else (
                            str(error) if type(error) is Refused and str(error) in CODES else self.operation)
                    raise
            self.operation = 'initial-failed'
            with entry.original_modules(root,root/'scripts/ci/integration.lock.json',INITIAL,
                    deadline=self.job_deadline,verification_deadline=self.job_deadline) as original:
                self.source_graph['original'] = original
                self.source_graph['original_aliases'] = {
                    'repository_projection.inventory':original['repository_projection'].inventory,
                    'desktop_projection.policy':original['desktop_projection'].policy}
                self.sources.source_graph(self,capture=True)
                with services['pending'].interpose(original['integration'],services['transport']):
                    check(self.job_deadline,self.cancelled)
                    code = original['native_arm'].main(argv,integration_consumers=callback)
                need(type(code) is int, 'initial-failed')
                self.result['initial_exit_code'] = code
                if self.end is not None:
                    self.tick()
                    self.operation = 'authority-failed'
                    self.terminal_consumer(code,services,modules,collector,phase,callbacks)
                else:
                    raise Refused('initial-failed')
            self.tick()
            self.result['status'] = 'PASS'
        except KeyboardInterrupt:
            self.result.update(status='FAIL',cancelled=True,error_code=self.result['error_code'] or 'cancelled')
        except BaseException as error:
            code = str(error) if type(error) is Refused and str(error) in CODES else self.operation
            self.result.update(status='FAIL',error_code=self.result['error_code'] or code)
        finally:
            cleanup_end = self.end or self.job_deadline
            def cleanup():
                error = None
                try:
                    if services is not None: services['transport'].close()
                except BaseException as item:error = item
                try:
                    check(cleanup_end)
                    remove_private(self.private,self.private_node,cleanup_end)
                    check(cleanup_end)
                except BaseException as item:error = error or item
                if error is not None:raise error
                self.result['cleanup'] = 'PASS'
            try:
                if collector is not None:
                    with collector['common'].defer_cancellation(): cleanup()
                else: cleanup()
            except BaseException as error:
                self.result.update(status='FAIL',cleanup='FAIL')
                if isinstance(error,KeyboardInterrupt): self.result['cancelled'] = True
                if self.result['error_code'] is None: self.result['error_code'] = 'cleanup-failed'
            if self.cancelled is not None and self.cancelled():
                self.result.update(status='FAIL',cancelled=True,error_code=self.result['error_code'] or 'cancelled')
            if self.result['status'] != 'PASS':
                # Failed/late cleanup must never leave an independently promotable PASS receipt.
                try:revoke_phase_receipt(self.output/'phase-public')
                except BaseException:
                    self.result['cleanup'] = 'FAIL'
                    self.result['error_code'] = self.result['error_code'] or 'cleanup-failed'
            try:
                publish_status(self.output/'status',self.result)
                check(cleanup_end,self.cancelled)
            except BaseException as error:
                self.result.update(status='FAIL',cancelled=self.result['cancelled'] or isinstance(error,KeyboardInterrupt),
                    error_code=self.result['error_code'] or ('cancelled' if isinstance(error,KeyboardInterrupt) else 'status-persistence-failed'))
                revoke_phase_receipt(self.output/'phase-public')
                # The first publication's close/check is part of the transaction.
                publish_status(self.output/'status',self.result,replace=True)
        return {**self.result,'public':[str(self.output/'status')]+(
            [str(self.output/'phase-public')] if self.result['status']=='PASS' else [])}


def remove_private(path, original, deadline):
    """Delete only the registered private directory using no-follow child FDs."""
    stable = lambda value: (value[0],value[1],value[2],value[4],value[5])
    need(path is not None and stable(identity(path.lstat())) == stable(original), 'cleanup-failed')
    parent = os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    root = None; count = 0
    try:
        root = os.open(path.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent)
        need(stable(identity(os.fstat(root))) == stable(original), 'cleanup-failed')
        def walk(fd, depth):
            nonlocal count
            check(deadline); need(depth <= 32, 'cleanup-failed')
            for name in os.listdir(fd):
                check(deadline);count += 1;need(count <= 20000, 'cleanup-failed')
                node = os.stat(name,dir_fd=fd,follow_symlinks=False)
                need(node.st_uid == os.geteuid() and node.st_dev == original[0], 'cleanup-failed')
                if stat.S_ISDIR(node.st_mode):
                    child = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                    try:
                        need(identity(os.fstat(child)) == identity(node), 'cleanup-failed');walk(child,depth+1)
                    finally:os.close(child)
                    need(os.stat(name,dir_fd=fd,follow_symlinks=False).st_ino == node.st_ino, 'cleanup-failed')
                    os.rmdir(name,dir_fd=fd)
                else:
                    need(stat.S_ISREG(node.st_mode) and node.st_nlink == 1, 'cleanup-failed')
                    os.unlink(name,dir_fd=fd)
        walk(root,0)
        need(os.stat(path.name,dir_fd=parent,follow_symlinks=False).st_ino == original[1], 'cleanup-failed')
        os.rmdir(path.name,dir_fd=parent)
    finally:
        if root is not None:os.close(root)
        os.close(parent)


def revoke_phase_receipt(path):
    """Invalidate only the source-owned named receipt; never traverse a link."""
    if not path.exists() and not path.is_symlink():return
    node = path.lstat()
    need(stat.S_ISDIR(node.st_mode) and node.st_uid == os.geteuid() and
         not node.st_mode & 0o022,'cleanup-failed')
    fd = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        need(identity(os.fstat(fd)) == identity(node),'cleanup-failed')
        try:receipt = os.stat('result.json',dir_fd=fd,follow_symlinks=False)
        except FileNotFoundError:return
        need(stat.S_ISREG(receipt.st_mode) and receipt.st_uid == os.geteuid() and
             receipt.st_nlink == 1,'cleanup-failed')
        os.unlink('result.json',dir_fd=fd);os.fsync(fd)
    finally:os.close(fd)


def status_projection(value):
    need(type(value) is dict and set(value) == STATUS_FIELDS and type(value['schema_version']) is int and
         value['schema_version'] == 1 and value['purpose'] == 'same-job-repository-handoff' and
         value['status'] in ('PASS','FAIL','NOT RUN') and value['error_code'] in CODES|{None},'status-persistence-failed')
    for key in ('callback_entered','cancelled','development_only','selected_for_release','original_B_continuity'):
        need(type(value[key]) is bool,'status-persistence-failed')
    need(value['development_only'] is True and value['selected_for_release'] is False and
         value['original_B_continuity'] is False and all(value[key] == 'NOT RUN' for key in
         ('hardware_validation','production_trust','stable_promotion')),'status-persistence-failed')
    need(value['initial_exit_code'] is None or type(value['initial_exit_code']) is int and
         -64 <= value['initial_exit_code'] <= 255,'status-persistence-failed')
    need(all(value[key] in ('PASS','FAIL','NOT RUN') for key in ('input_acceptance','restage','cleanup')),
         'status-persistence-failed')
    for key,pattern in {'source_commit':'[0-9a-f]{40}','run_id':'[1-9][0-9]{0,19}',
                       'run_attempt':'[1-9][0-9]{0,9}','execution_grant_sha256':'[0-9a-f]{64}',
                       'actor_contract_sha256':'[0-9a-f]{64}',
                       'initial_invocation_sha256':'[0-9a-f]{64}'}.items():
        need(value[key] is None and value['status'] != 'PASS' or type(value[key]) is str and
             re.fullmatch(pattern,value[key]),'status-persistence-failed')
    if value['status'] == 'PASS':
        need(value['initial_exit_code'] == 0 and value['callback_entered'] and not value['cancelled'] and
             value['error_code'] is None and all(value[key] == 'PASS' for key in
             ('input_acceptance','restage','cleanup')),'status-persistence-failed')
    return value


def publish_status(path,value,*,replace=False):
    status_projection(value)
    raw = encoded(value);need(len(raw) <= 4096, 'status-persistence-failed')
    if not replace:path.mkdir(mode=0o700)
    fd = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    name = None
    try:
        info = os.fstat(fd)
        need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,'status-persistence-failed')
        if replace:
            try:
                prior = os.stat('result.json',dir_fd=fd,follow_symlinks=False)
                need(stat.S_ISREG(prior.st_mode) and prior.st_uid == os.geteuid() and
                     prior.st_nlink == 1,'status-persistence-failed')
            except FileNotFoundError:pass
        descriptor,name = tempfile.mkstemp(prefix='.status-',dir=path)
        with os.fdopen(descriptor,'wb') as stream:
            stream.write(raw);stream.flush();os.fsync(stream.fileno())
        need(path.lstat().st_ino == info.st_ino,'status-persistence-failed')
        os.replace(Path(name).name,'result.json',src_dir_fd=fd,dst_dir_fd=fd)
        name = None;os.fsync(fd)
    finally:
        if name is not None:os.unlink(Path(name).name,dir_fd=fd)
        os.close(fd)


def public_paths(output):
    """Recovery selects only fixed source-bound directories after valid status."""
    output = Path(output).absolute()
    raw,_,_ = read(output/'status/result.json',time.monotonic()+5,4096)
    value = status_projection(decode(raw))
    names = ['status']
    if value['status'] == 'PASS':
        need(value.get('cleanup') == value.get('input_acceptance') == value.get('restage') == 'PASS'
             and value.get('cancelled') is False and value.get('initial_exit_code') == 0,'status-persistence-failed')
        names.append('phase-public')
    return [output/name for name in names]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parents[3])
    parser.add_argument('--grant');parser.add_argument('--grant-sha256')
    args = parser.parse_args(argv)
    try:
        need(args.grant is not None and args.grant_sha256 is not None,'grant-refused')
        end = time.monotonic()+180
        sources = preflight(args.root,read(args.grant,end)[0],args.grant_sha256,deadline=end)
        print(json.dumps({'status':'PASS-source-preflight','files':len(sources.raw),'actors':'NOT RUN'}))
        return 0
    except BaseException:
        print(json.dumps({'status':'BLOCKED','error_code':'grant-refused','actors':'NOT RUN'}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
