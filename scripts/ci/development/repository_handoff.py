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
import importlib.machinery as machinery
import math
import os
from pathlib import Path, PurePath
import re
import stat
import sysconfig
import tempfile
import threading
import time
import types

FILE_LIMIT, TOTAL_LIMIT = 8 * 1024**2, 64 * 1024**2
INITIAL = '50947880c7d72a982221d0416ba758fb922fb2595cbfe6ebbdc08db972ce504f'
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
        error = Refused(reason)
        frame = sys._getframe(1)
        # A closed source-method label only; no filename, code or raw message.
        site = {
            'Sources.class_state':'CLASS_STATE',
            'Sources.class_state.<locals>.literal':'CLASS_LITERAL',
            'Sources.callback':'CALLBACK', 'Sources.global_function':'GLOBAL_FUNCTION',
            'Sources.graph_function':'GRAPH_FUNCTION', 'Sources.frozen_file_hook':'FROZEN_FILE_HOOK', 'Sources.graph_namespace':'GRAPH_NAMESPACE',
            'Sources.graph_identity':'GRAPH_IDENTITY',
            'Sources.graph_identity.<locals>.observe':'GRAPH_IDENTITY',
            'Sources.source_graph':'SOURCE_GRAPH', 'Session.register_native_preflight':'INSTALLER_REGISTRATION',
            'Session._original_context':'ORIGINAL_CONTEXT',
            'Session.prepare_view':'VIEW_COPY', 'Session.verify_view':'VIEW_VERIFY',
            'check':'DEADLINE_CHECK', 'bindings':'CALLBACK_BINDINGS',
            'authority_state':'AUTHORITY_STATE',
            'authority_state.<locals>.inspect_state':'AUTHORITY_STATE',
            'Session.observe_native_consumer':'NATIVE_FRAME', 'remove_private':'OWNED_CLEANUP',
        }.get(frame.f_code.co_qualname, 'OTHER') if frame.f_globals is globals() else 'OTHER'
        error._source_refusal_site = site
        raise error


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
        self.original_root = None
        self.original_rows = None
        self.zsh_admission = None
        self.zsh_history = None
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

    def locate(self, filename):
        filename = Path(filename).absolute()
        if self.original_root is not None and filename.is_relative_to(self.original_root):
            path = filename.relative_to(self.original_root).as_posix()
            need(path in self.original_rows and path in self.raw,'callback-refused')
            return path
        need(filename.is_relative_to(self.root),'callback-refused')
        return filename.relative_to(self.root).as_posix()

    def project_file(self, filename):
        filename = Path(filename).absolute()
        return filename.is_relative_to(self.root) or (self.original_root is not None and
                                                      filename.is_relative_to(self.original_root))

    def global_function(self, function):
        filename = Path(function.__code__.co_filename).absolute()
        if filename.is_relative_to(sysconfig.get_path('stdlib')):return
        path = self.locate(filename)
        need(path in self.raw,'callback-refused')
        key = str(filename)
        if key not in self.codes:self.codes[key] = list(code_objects(compile(self.raw[path],key,'exec')))
        need(any(function.__code__ == code for code in self.codes[key]),'callback-refused')
        module = sys.modules.get(function.__module__)
        need(type(module) is types.ModuleType and module.__dict__ is function.__globals__ and
             function.__globals__.get('__file__') == str(filename),'callback-refused')

    def class_state(self, value, path, module, *, scope=None):
        """Exact captured class/method/descriptor state, including declared slots."""
        scope = self.root if scope is None else scope
        need(scope == self.root or scope == self.original_root and path in self.original_rows,'callback-refused')
        need(type(module) is types.ModuleType and module.__file__ == str(scope/path)
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
            compile(self.raw[path], str(scope/path), 'exec'))}
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

    def graph_function(self, function, module, compiled=None, *, callsite='OTHER'):
        """Private loader namespaces bind objects, never filename labels alone."""
        try:
            need(type(function) is types.FunctionType and type(module) is types.ModuleType
                 and function.__globals__ is module.__dict__,'callback-refused')
        except Refused as error:
            try:
                if type(error) is Refused:
                    trace = error.__traceback__
                    if (trace is not None and trace.tb_frame.f_code is Sources.graph_function.__code__
                            and trace.tb_frame.f_globals is globals() and trace.tb_next is not None
                            and trace.tb_next.tb_frame.f_code is need.__code__
                            and trace.tb_next.tb_frame.f_globals is globals() and trace.tb_next.tb_next is None):
                        error._source_refusal_site = 'GRAPH_OBJECT_BINDING'
                        error._graph_object_clause = ('FUNCTION_TYPE' if type(function) is not types.FunctionType else
                            'MODULE_TYPE' if type(module) is not types.ModuleType else 'GLOBALS')
                        caller = trace.tb_frame.f_back
                        sites = ('DECLARED','OVERRIDE','IMPORTED','LAUNCH_VALIDATOR','COMMON_VALIDATOR','LANGUAGE')
                        if (type(callsite) is str and callsite in sites and caller is not None and
                                caller.f_code is Sources.graph_namespace.__code__ and caller.f_globals is globals()):
                            error._graph_object_callsite = callsite
            except BaseException:pass
            raise
        filename = str(Path(module.__file__).absolute());path = self.locate(filename)
        if compiled is None:compiled = {}
        if path in self.raw and filename not in compiled:
            compiled[filename] = tuple(code_objects(compile(self.raw[path],filename,'exec')))
        try:
            need(path in self.raw and function.__code__.co_filename == filename and
                 any(function.__code__ == code for code in compiled.get(filename,())),'callback-refused')
        except Refused as error:
            try:
                if type(error) is Refused:
                    trace = error.__traceback__
                    if (trace is not None and trace.tb_frame.f_code is Sources.graph_function.__code__
                            and trace.tb_frame.f_globals is globals() and trace.tb_next is not None
                            and trace.tb_next.tb_frame.f_code is need.__code__
                            and trace.tb_next.tb_frame.f_globals is globals() and trace.tb_next.tb_next is None):
                        error._source_refusal_site = 'GRAPH_HELD_CODE_BINDING'
            except BaseException:pass
            raise

    def native_executor_state(self, session, modules, cache):
        """One Source-owned active interposer; no arbitrary cross-namespace route."""
        endpoint = session.work_end if session.work_end is not None else session.job_deadline
        check(endpoint,session.cancelled)
        if session.native_executor_scope is None:
            need(session.native_executor is None and session.native_services is None and
                 session.native_runtime_contract is None,'callback-refused')
            return None
        integration = modules.get('scripts/ci/integration.py')
        broker = modules[PREFIXES['runtime']+'/broker.py']
        launch = modules[PREFIXES['runtime']+'/launch.py']
        transport_module = modules[PREFIXES['runtime']+'/transport.py']
        entry = modules[PREFIXES['runtime']+'/entry.py']
        services, runtime = session.native_services, session.native_runtime_contract
        need(type(services) is dict and all(type(key) is str for key in services) and
             set(services) == {'pending','transport','supervise_factory'} and
             type(runtime) is dict and all(type(key) is str for key in runtime) and
             set(runtime) == {'cli_sha256','endpoint_identity','env'} and
             type(runtime['cli_sha256']) is str and re.fullmatch('[0-9a-f]{64}',runtime['cli_sha256']) and
             type(runtime['endpoint_identity']) in (tuple,list) and len(runtime['endpoint_identity']) == 6 and
             all(type(value) is int for value in runtime['endpoint_identity']) and
             type(runtime['env']) is dict and all(type(key) is str and type(value) is str
                 for key,value in runtime['env'].items()) and
             digest(encoded(runtime)) == self.grant['actor_contract_sha256'],'callback-refused')
        pending, transport = services['pending'], services['transport']
        self.class_state(pending,PREFIXES['runtime']+'/broker.py',broker)
        self.class_state(transport,PREFIXES['runtime']+'/transport.py',transport_module)
        need(type(pending) is broker.Pending and type(transport) is transport_module.DockerTransport and
             pending.transport is transport and type(session.private) is type(self.root) and
             type(pending.root) is type(self.root) and pending.root == session.private/'custody' and
             pending.deadline is session.job_deadline and pending.cancelled is session.cancelled and
             type(pending.producer_raw) is bytes and pending.producer_raw == self.raw[PREFIXES['runtime']+'/producer.py'] and
             type(pending.producer_pin) is str and pending.producer_pin == self.grant['source_files'][PREFIXES['runtime']+'/producer.py']['sha256'] and
             type(transport.cli) is dict and type(transport.cli.get('sha256')) is str and
             transport.cli['sha256'] == runtime['cli_sha256'] and type(transport.env) is dict and
             all(type(key) is str and type(value) is str for key,value in transport.env.items()) and
             transport.env == runtime['env'] and type(transport.endpoint) is tuple and
             all(type(value) is int for value in transport.endpoint) and
             transport.endpoint == tuple(runtime['endpoint_identity']),'callback-refused')
        def method(value, owner, declaration):
            need(type(value) is types.MethodType and value.__self__ is owner and
                 value.__func__ is declaration,'callback-refused')
        method(transport.validator,pending,broker.Pending.approve_create)
        guard = transport.guard
        self.graph_function(guard,entry,cache)
        need(guard.__code__.co_qualname == 'services.<locals>.source_guard' and
             guard.__closure__ is not None,'callback-refused')
        closure = dict(zip(guard.__code__.co_freevars,(cell.cell_contents for cell in guard.__closure__)))
        need(set(closure) == {'cancelled','job_deadline','root','rows','source_identities'} and
             closure['cancelled'] is session.cancelled and closure['job_deadline'] is session.job_deadline and
             type(closure['root']) is type(self.root) and closure['root'] == self.root/PREFIXES['runtime'] and
             type(closure['rows']) is dict and all(type(name) is str and type(row) is dict and
                 all(type(key) is str and type(value) in (str,int) for key,value in row.items())
                 for name,row in closure['rows'].items()) and closure['rows'] == decode(self.raw[self.grant['maps']['runtime']['path']]),'callback-refused')
        self.graph_function(broker.Pending.interpose.__wrapped__,broker,cache)
        self.graph_function(launch.scoped_executor.__wrapped__,launch,cache)
        scope = session.native_executor_scope
        need(type(scope) is contextmanager.__globals__['_GeneratorContextManager'],'callback-refused')
        generator = object.__getattribute__(scope,'gen')
        need(type(generator) is types.GeneratorType and generator.gi_frame is not None and
             not generator.gi_running and generator.gi_code is broker.Pending.interpose.__wrapped__.__code__ and
             generator.gi_frame.f_globals is broker.__dict__,'callback-refused')
        outer = generator.gi_frame.f_locals
        need(outer.get('self') is pending and outer.get('integration') is integration and
             outer.get('transport') is transport and outer.get('executor') is session.native_executor,'callback-refused')
        inner_scope = outer.get('scope')
        need(type(inner_scope) is contextmanager.__globals__['_GeneratorContextManager'],'callback-refused')
        inner = object.__getattribute__(inner_scope,'gen')
        need(type(inner) is types.GeneratorType and inner.gi_frame is not None and not inner.gi_running and
             inner.gi_code is launch.scoped_executor.__wrapped__.__code__ and
             inner.gi_frame.f_globals is launch.__dict__,'callback-refused')
        local = inner.gi_frame.f_locals
        function, original, options = session.native_executor, local.get('original'),local.get('options')
        need(type(integration) is types.ModuleType and local.get('module') is integration and
             type(local.get('identity')) is int and local['identity'] == id(integration) and type(launch._SCOPES) is set and
             all(type(value) is int for value in launch._SCOPES) and id(integration) in launch._SCOPES and local.get('executor') is function and
             integration.__dict__.get('execute_container') is function,'callback-refused')
        self.graph_function(function,launch,cache)
        self.graph_function(original,integration,cache)
        need(function.__code__.co_qualname == 'scoped_executor.<locals>.executor' and
             type(function.__defaults__) is tuple and len(function.__defaults__) == 2 and
             type(function.__defaults__[0]) is int and function.__defaults__[0] == 1800 and
             type(function.__defaults__[1]) is bool and function.__defaults__[1] is False and
             function.__kwdefaults__ is None and
             function.__closure__ is not None and function.__code__.co_freevars == ('options','original') and
             function.__closure__[0].cell_contents is options and function.__closure__[1].cell_contents is original and
             original.__code__.co_qualname == 'execute_container' and original.__closure__ is None and
             type(original.__defaults__) is tuple and len(original.__defaults__) == 2 and
             type(original.__defaults__[0]) is int and original.__defaults__[0] == 1800 and
             type(original.__defaults__[1]) is bool and original.__defaults__[1] is False and
             original.__kwdefaults__ is None,'callback-refused')
        need(type(options) is dict and all(type(key) is str for key in options) and set(options) == {'private_root','contract','run','deadline',
             'checkpoint_handler','producer_pin','prepare_runner'} and options['private_root'] is pending.root and
             options['run'] is transport and options['deadline'] is session.job_deadline and
             options['producer_pin'] is pending.producer_pin,'callback-refused')
        method(options['contract'],pending,broker.Pending.resolve)
        method(options['checkpoint_handler'],pending,broker.Pending.checkpoint)
        method(options['prepare_runner'],pending,broker.Pending.prepare)
        check(endpoint,session.cancelled)
        return (function,original)

    def source_graph(self, session, *, capture=False):
        """Explicit actual namespaces supplied by this Session's captured loaders."""
        module = sys.modules.get(type(session).__module__)
        state = self.class_state(session,'scripts/ci/development/repository_handoff.py',module)
        need(session.sources is self,'callback-refused')
        self.class_state(self,'scripts/ci/development/repository_handoff.py',module)
        graph = state['source_graph']
        composition = state.get('composition')
        need(type(composition) is str and composition in ('repository-svg-maintained-v1','installer-preflight-maintained-v1'),'callback-refused')
        fields = {'entry','runtime','collector','phase','original','original_aliases'}
        if composition == 'installer-preflight-maintained-v1':fields.add('native_preflight')
        if composition == 'repository-svg-zsh':fields.add('zsh')
        need(type(graph) is dict and (not graph or set(graph) == fields),
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
            if graph['original']:
                context = session._original_context(deadline=session.work_end if session.work_end is not None else session.job_deadline)
                need(all(context['original'][name] is value for name,value in graph['original'].items()),'callback-refused')
            for name,value in graph['original'].items():modules[original[name]] = value
            installer = None
            if composition == 'installer-preflight-maintained-v1':
                installer = graph['native_preflight']
                installer_path,name,qualname = ('scripts/install/native_preflight.py','native_install_preflight','run')
                need(type(installer) is types.ModuleType and type(installer.__name__) is str and installer.__name__ == name and
                     sys.modules.get(name) is installer and installer_path in self.raw and
                     type(installer.__dict__.get('OWN')) is str and installer.__dict__['OWN'] == installer_path,'callback-refused')
                callback = installer.__dict__.get(qualname)
                need(type(callback) is types.FunctionType and type(callback.__module__) is str and callback.__module__ == name and
                     type(callback.__qualname__) is str and callback.__qualname__ == qualname and callback.__globals__ is installer.__dict__,
                     'callback-refused')
                modules[installer_path] = installer
            if composition == 'repository-svg-zsh':
                zsh = graph['zsh']
                need(type(zsh) is dict and set(zsh) == {'zsh_addon','zsh_session'},'callback-refused')
                for name,value in zsh.items():
                    path = 'scripts/ci/development/'+name+'.py'
                    need(type(value) is types.ModuleType and value.__name__ == 'development_'+name
                         and sys.modules.get(value.__name__) is value,'callback-refused')
                    modules[path] = value
            aliases = graph['original_aliases']
            need(type(aliases) is dict and (not aliases if not graph['original'] else
                 set(aliases) == {'repository_projection.inventory','desktop_projection.policy'}),'callback-refused')
            alias_paths = {'repository_projection.inventory':'scripts/ci/lifecycle_inventory.py',
                           'desktop_projection.policy':'scripts/ci/integration_export.py'}
            for label,value in aliases.items():
                parent,name = label.split('.')
                need(graph['original'][parent].__dict__.get(name) is value and type(value) is types.ModuleType
                     and value.__file__ == str(self.original_root/alias_paths[label]),'callback-refused')
            interposer = self.native_executor_state(session,modules,compiled)
            for path,value in modules.items():
                domain = self.original_root if path in original.values() else self.root
                need(type(value) is types.ModuleType and value.__file__ == str(domain/path) and path in self.raw,
                     'callback-refused')
                self.graph_namespace(value,path,modules,aliases,compiled,interposer=interposer)
            for label,value in aliases.items():self.graph_namespace(value,alias_paths[label],modules,aliases,compiled,interposer=interposer)
            if installer is not None:
                installer.namespace(installer,self.raw[installer_path],self.grant['source_files'][installer_path]['sha256'])
            admission = ()
            if composition == 'repository-svg-zsh':
                state = self.zsh_admission
                need(type(state) is tuple and len(state) == 4 and state[0] is graph['zsh'] and
                     all(type(value) is types.FunctionType for value in state[1:]),'callback-refused')
                admission = (('zsh-admission',id(state),*(id(value) for value in state)),
                             ('zsh-guards',self.zsh_guard_identity(state)))
            else:need(self.zsh_admission is None,'callback-refused')
            observation = self.graph_identity((module,)+tuple(modules.values())+tuple(aliases.values()),interposer=interposer)+admission
            proof = (('zsh-proof',self.zsh_proof()),) if admission else ()
            if capture:
                # Only the two authenticated loader boundaries may establish it.
                need(session.used is True and session.controller is None and
                     ((self.graph_observation is None and not graph['original']) or
                      (self.graph_observation is not None and graph['original'])), 'callback-refused')
                if self.graph_observation is not None:
                    prior = tuple(value for path,value in modules.items() if path not in original.values())
                    need(self.graph_identity((module,)+prior)+admission+proof == self.graph_observation,'callback-refused')
                self.guard(session.job_deadline,session.cancelled)
                self.graph_observation = observation+proof
            else:
                need(self.graph_observation is not None and observation+proof == self.graph_observation,'callback-refused')
            if admission:
                for validator in state[1:]:validator()
                self.graph_observation = observation+(('zsh-proof',self.zsh_proof()),)
            if installer is not None:
                installer.namespace(installer,self.raw[installer_path],self.grant['source_files'][installer_path]['sha256'])
        return modules

    def graph_identity(self, modules, *, interposer=None):
        """Exact observed executable references plus closed loader closure data."""
        seen = set();count = 0;compiled = {};namespaces = set();functions = []
        def observe(value,depth=0):
            nonlocal count
            if interposer is not None and value is interposer[0]:value = interposer[1]
            count += 1
            need(depth <= 64 and count <= 100000,'callback-refused')
            if value is None or type(value) in (str,bytes,int,bool,float):return (type(value),value)
            if isinstance(value,Path):return (type(value),str(value))
            if id(value) in seen:return ('reference',id(value))
            seen.add(id(value))
            if type(value) is types.ModuleType:
                origin = getattr(value,'__file__',None)
                if not origin or not self.project_file(origin):return ('module',id(value))
                path = self.locate(origin)
                need(path in self.raw,'callback-refused');namespaces.add(id(value.__dict__))
                if path in ('scripts/ci/development/zsh_addon.py','scripts/ci/development/zsh_session.py'):
                    admission = self.zsh_admission
                    name = Path(path).stem
                    need(type(admission) is tuple and len(admission) == 4 and type(admission[0]) is dict and
                         admission[0].get(name) is value and value.__name__ == 'development_'+name and
                         sys.modules.get(value.__name__) is value,'callback-refused')
                    # Full functions/classes/policy/imports live in the authenticated
                    # Source-owned snapshot/capsules; legacy graph predicates stay closed.
                    return ('zsh-module',id(value),id(value.__dict__),value.__name__,origin)
                items = []
                for name,item in sorted(value.__dict__.items()):
                    if type(item) is types.FunctionType:
                        if path == PREFIXES['runtime']+'/entry.py' and name == 'FILE_HOOK':
                            self.frozen_file_hook(item,value)
                            details = item.__closure__[1].cell_contents
                            items.append((name,('frozen-file-hook',id(item),item.__code__,id(item.__globals__),
                                tuple((key,id(cell),id(cell.cell_contents)) for key,cell in zip(item.__code__.co_freevars,item.__closure__)),
                                tuple((id(pair),id(pair[0]),id(pair[1]),tuple(pair[1])) for pair in details))))
                            continue
                        filename = Path(getattr(item,'__wrapped__',item).__code__.co_filename).absolute()
                        if self.project_file(filename):
                            if filename == Path(origin).absolute():
                                need(getattr(item,'__wrapped__',item).__globals__ is value.__dict__,'callback-refused')
                            items.append((name,observe(item,depth+1)))
                    elif type(item) is type:items.append((name,observe(item,depth+1)))
                    elif type(item) is types.ModuleType:
                        child = getattr(item,'__file__',None)
                        if child and self.project_file(child):items.append((name,observe(item,depth+1)))
                return ('module',id(value),tuple(items))
            if type(value) is types.FunctionType:
                origin = Path(value.__code__.co_filename).absolute()
                if self.project_file(origin):
                    path = self.locate(origin)
                    if path in self.raw and str(origin) not in compiled:
                        compiled[str(origin)] = tuple(code_objects(compile(self.raw[path],str(origin),'exec')))
                    need(path in self.raw and value.__globals__.get('__file__') == str(origin) and
                         any(value.__code__ == code for code in compiled.get(str(origin),())),
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

    def frozen_file_hook(self, value, module):
        """The entry's exact stdlib factory hook is not a project filename.

        Bind code/globals/defaults/cells and the reviewed constructor; never
        grant arbitrary frozen-looking filenames or foreign hook namespaces.
        """
        path = PREFIXES['runtime']+'/entry.py'
        declarations = [node for node in ast.parse(self.raw[path]).body if isinstance(node,ast.Assign)
                        and any(isinstance(name,ast.Name) and name.id == 'FILE_HOOK' for name in node.targets)]
        expected = ast.parse("FILE_HOOK = machinery.FileFinder.path_hook((machinery.ExtensionFileLoader, machinery.EXTENSION_SUFFIXES), (machinery.SourceFileLoader, machinery.SOURCE_SUFFIXES))").body[0]
        need(len(declarations) == 1 and ast.dump(declarations[0]) == ast.dump(expected)
             and type(module) is types.ModuleType and module.__dict__.get('machinery') is machinery
             and module.__dict__.get('FILE_HOOK') is value
             and {name for name,item in module.__dict__.items() if item is value} == {'FILE_HOOK'},'callback-refused')
        reference = machinery.FileFinder.path_hook(
            (machinery.ExtensionFileLoader,machinery.EXTENSION_SUFFIXES),
            (machinery.SourceFileLoader,machinery.SOURCE_SUFFIXES))
        need(type(value) is types.FunctionType and value.__code__ is reference.__code__
             and value.__globals__ is reference.__globals__ and value.__name__ == reference.__name__
             and value.__qualname__ == reference.__qualname__ and value.__module__ == reference.__module__
             and value.__defaults__ is None and value.__kwdefaults__ is None
             and type(value.__dict__) is dict and not value.__dict__
             and type(value.__annotations__) is dict and not value.__annotations__
             and value.__code__.co_freevars == ('cls','loader_details')
             and type(value.__closure__) is tuple and len(value.__closure__) == 2
             and all(type(cell) is types.CellType for cell in value.__closure__),'callback-refused')
        cls,details = (cell.cell_contents for cell in value.__closure__)
        need(cls is machinery.FileFinder and type(details) is tuple and len(details) == 2,'callback-refused')
        for item,loader,suffixes in zip(details,(machinery.ExtensionFileLoader,machinery.SourceFileLoader),
                                       (machinery.EXTENSION_SUFFIXES,machinery.SOURCE_SUFFIXES)):
            need(type(item) is tuple and len(item) == 2 and item[0] is loader and item[1] is suffixes
                 and type(suffixes) is list and len(suffixes) <= 64
                 and all(type(suffix) is str for suffix in suffixes),'callback-refused')

    def graph_namespace(self,module,path,modules,aliases,cache, *, interposer=None):
        """All declared functions/import hooks retain their captured implementation."""
        entry_path = PREFIXES['runtime']+'/entry.py'
        overrides = {
            (PREFIXES['collector']+'/common.py','load_snapshot'):'dependency_entry.<locals>.load_snapshot',
            (PREFIXES['collector']+'/orchestrator.py','load_snapshot'):'dependency_entry.<locals>.load_snapshot',
            (PREFIXES['phase']+'/dependencies.py','load_collector'):'dependency_entry.<locals>.load_collector',
            (PREFIXES['phase']+'/dependencies.py','source'):'dependency_entry.<locals>.source',
        }
        filename = module.__file__
        if filename not in cache:cache[filename] = tuple(code_objects(compile(self.raw[path],filename,'exec')))
        compiled = {code.co_qualname:code for code in cache[filename]}
        for node in ast.parse(self.raw[path]).body:
            if not isinstance(node,ast.FunctionDef):continue
            value = module.__dict__.get(node.name)
            if path == 'scripts/ci/integration.py' and node.name == 'execute_container' and interposer is not None:
                need(value is interposer[0] and interposer[1].__code__ == compiled.get(node.name),'callback-refused')
                self.graph_function(value,modules[PREFIXES['runtime']+'/launch.py'],cache,callsite='OVERRIDE')
                continue
            if (path,node.name) in overrides:
                self.graph_function(value,modules[entry_path],cache,callsite='OVERRIDE')
                need(value.__code__.co_qualname == overrides[path,node.name],'callback-refused')
                continue
            if node.decorator_list:
                decorator = node.decorator_list[0]
                selected = (isinstance(decorator,ast.Name) and decorator.id == 'contextmanager') or (
                    path == 'scripts/ci/development/zsh_addon.py' and node.name == 'defer_cancel' and
                    isinstance(decorator,ast.Attribute) and isinstance(decorator.value,ast.Name) and
                    decorator.value.id == 'contextlib' and decorator.attr == 'contextmanager')
                need(len(node.decorator_list) == 1 and selected and type(value) is types.FunctionType
                     and value.__code__ == contextmanager(lambda:None).__code__
                     and value.__globals__ is contextmanager.__globals__ and value.__closure__ is not None
                     and len(value.__closure__) == 1 and
                     value.__code__.co_freevars == ('func',) and value.__defaults__ is None and value.__kwdefaults__ is None
                     and value.__closure__[0].cell_contents is getattr(value,'__wrapped__',None),'callback-refused')
                value = value.__wrapped__
            self.graph_function(value,module,cache,callsite='DECLARED')
            need(value.__code__ == compiled.get(node.name),'callback-refused')
        for value in module.__dict__.values():
            if type(value) is types.FunctionType:
                if path == entry_path and value is module.__dict__.get('FILE_HOOK'):
                    self.frozen_file_hook(value,module)
                    continue
                unwrapped = getattr(value,'__wrapped__',value)
                filename = Path(unwrapped.__code__.co_filename).absolute()
                if self.project_file(filename):
                    function_path = self.locate(filename)
                    need(function_path in modules,'callback-refused')
                    self.graph_function(unwrapped,module if function_path == path else modules[function_path],cache,callsite='IMPORTED')
            if type(value) is types.ModuleType:
                origin = getattr(value,'__file__',None)
                if origin and self.project_file(origin):
                    relative_path = self.locate(origin)
                    need(modules.get(relative_path) is value or any(value is item for item in aliases.values()),
                         'callback-refused')
        if path == PREFIXES['runtime']+'/launch.py':
            validator=module.__dict__.get('cancellation_state')
            self.graph_function(validator,module,cache,callsite='LAUNCH_VALIDATOR')
            need(validator.__defaults__ == (None,) and validator.__kwdefaults__ is None and
                 validator.__closure__ is None,'callback-refused')
            validator()

        if path == PREFIXES['collector']+'/common.py':
            validator = module.__dict__.get('cancellation_state')
            self.graph_function(validator, module, cache,callsite='COMMON_VALIDATOR')
            need(validator.__defaults__ is None and validator.__kwdefaults__ is None and
                 validator.__closure__ is None, 'callback-refused')
            validator()
        language = module.__dict__.get('__builtins__')
        need(type(language) is dict,'callback-refused')
        for name in ('__import__','compile','exec'):
            value = language.get(name)
            if value is vars(builtins)[name]:continue
            need(type(value) is types.FunctionType,'callback-refused')
            filename = Path(value.__code__.co_filename).absolute()
            if filename == self.root/entry_path:self.graph_function(value,modules[entry_path],cache,callsite='LANGUAGE')
            else:self.global_function(value)

    def zsh_guards(self, session, modules):
        """Four closed live registries; all other code/policy/dependencies stay frozen."""
        stage = session.output.parent/'zsh-addon'
        need(not stage.exists() and not stage.is_symlink() and not stage.is_relative_to(self.root) and
             not self.root.is_relative_to(stage) and not stage.is_relative_to(session.output) and
             not session.output.is_relative_to(stage),'callback-refused')
        parent = stage.parent.lstat()
        parent_key = (parent.st_dev,parent.st_ino,parent.st_mode,parent.st_uid,parent.st_gid)
        need(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid() and parent.st_gid == os.getgid()
             and not stat.S_IMODE(parent.st_mode)&0o022,'callback-refused')
        addon, consumer = modules['zsh_addon'],modules['zsh_session']
        names = ('_RECEIPT_FILES','_RECEIPT_FDS','_RECEIPT_UNCERTAIN','_PROCESS_DISPOSAL_UNCERTAIN')
        objects = tuple(addon.__dict__.get(name) for name in names)
        need(all(type(value) is dict and not value for value in objects[:3]) and
             type(objects[3]) is list and not objects[3],'callback-refused')
        need(self.zsh_history is None,'callback-refused')
        self.zsh_history = {'stage':None,'uncertain':{},'process':False}
        history = self.zsh_history
        proof = (None,(),False)
        def directory(path):
            need(path.is_relative_to(stage) and '..' not in path.parts and
                 all(stat.S_ISDIR(item.lstat().st_mode) for item in (path,*path.parents)), 'callback-refused')
            row = path.lstat()
            need(row.st_uid == os.getuid() and row.st_gid == os.getgid() and
                 not stat.S_IMODE(row.st_mode)&0o022,'callback-refused')
            return (row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid)
        def state():
            nonlocal proof
            check(session.job_deadline,session.cancelled)
            if self.zsh_admission is not None and self.graph_observation is not None:
                need(self.graph_observation[-1][0] == 'zsh-proof' and
                     self.zsh_proof_matches(self.graph_observation[-1][1]),'callback-refused')
            need(self.zsh_history is history and type(history) is dict and set(history) == {'stage','uncertain','process'} and
                 type(history['uncertain']) is dict and len(history['uncertain']) <= 256 and
                 type(history['process']) is bool and history['stage'] == proof[0] and history['process'] is proof[2] and
                 tuple(history['uncertain']) == tuple(key for key,_ in proof[1]) and
                 all(history['uncertain'][key] is error for key,error in proof[1]),'callback-refused')
            stage_key,uncertain,process_uncertain = history['stage'],history['uncertain'],history['process']
            need(all(addon.__dict__.get(name) is value for name,value in zip(names,objects)), 'callback-refused')
            files,fds,pending,process = objects
            need(type(files) is dict and len(files) <= 256 and type(fds) is dict and len(fds) <= 16 and
                 type(pending) is dict and len(pending) <= 256 and type(process) is list and
                 len(process) <= 1 and all(value is True for value in process),'callback-refused')
            row = stage.parent.lstat()
            need((row.st_dev,row.st_ino,row.st_mode,row.st_uid,row.st_gid) == parent_key,'callback-refused')
            if stage.exists() or stage.is_symlink():
                key = directory(stage)
                need(stage_key is None or stage_key == key,'callback-refused');history['stage'] = key
            else:need(stage_key is None and not any(objects),'callback-refused')
            total = 0
            for name,record in files.items():
                need(type(name) is str and len(name) <= 4096 and type(record) is dict and
                     set(record) == {'parent','identity','sha256'},'callback-refused')
                path = Path(name)
                need(path.is_absolute() and str(path) == name and path != stage and
                     type(record['parent']) is tuple and len(record['parent']) == 5 and
                     all(type(value) is int for value in record['parent']) and
                     type(record['identity']) is tuple and len(record['identity']) == 7 and
                     all(type(value) is int for value in record['identity']) and
                     type(record['sha256']) is str and re.fullmatch('[0-9a-f]{64}',record['sha256']) and
                     directory(path.parent) == record['parent'],'callback-refused')
                node = path.lstat()
                actual = (node.st_dev,node.st_ino,node.st_mode,node.st_nlink,node.st_uid,node.st_gid,node.st_size)
                need(actual == record['identity'] and stat.S_ISREG(node.st_mode) and node.st_nlink == 1 and
                     node.st_uid == os.getuid() and node.st_gid == os.getgid() and
                     stat.S_IMODE(node.st_mode) == 0o600 and 0 <= node.st_size <= FILE_LIMIT,'callback-refused')
                raw,mode,_ = read(path,session.job_deadline)
                total += len(raw)
                need(mode == 0o600 and digest(raw) == record['sha256'] and total <= TOTAL_LIMIT,'callback-refused')
            for fd,owned in fds.items():
                need(type(fd) is int and 0 <= fd <= 2**31 and type(owned) is tuple and len(owned) == 4 and
                     all(type(value) is int for value in owned),'callback-refused')
                row = os.fstat(fd)
                need((row.st_dev,row.st_ino,stat.S_IFMT(row.st_mode),row.st_rdev) == owned and
                     row.st_uid == os.getuid() and row.st_gid == os.getgid() and
                     (stat.S_ISDIR(row.st_mode) or stat.S_ISREG(row.st_mode)),'callback-refused')
                target = os.readlink('/proc/self/fd/'+str(fd));path = Path(target)
                need(path.is_absolute() and path.is_relative_to(stage) and not target.endswith(' (deleted)'), 'callback-refused')
                if stat.S_ISDIR(row.st_mode):directory(path)
                else:
                    directory(path.parent);node = path.lstat()
                    need((node.st_dev,node.st_ino,node.st_mode,node.st_nlink,node.st_uid,node.st_gid) ==
                         (row.st_dev,row.st_ino,row.st_mode,row.st_nlink,row.st_uid,row.st_gid) and row.st_nlink == 1 and
                         stat.S_IMODE(row.st_mode) == 0o600 and row.st_size <= FILE_LIMIT,'callback-refused')
            for key,error in pending.items():
                need(type(key) is tuple and len(key) == 2 and type(key[0]) is tuple and len(key[0]) == 5 and
                     all(type(value) is int for value in key[0]) and type(key[1]) is str and
                     re.fullmatch('[A-Za-z0-9._-]{1,255}\\.partial-[0-9a-f]{16}',key[1]) and
                     isinstance(error,BaseException),'callback-refused')
                need(key not in uncertain or uncertain[key] is error,'callback-refused')
            need(all(key in pending and pending[key] is error for key,error in uncertain.items()),'callback-refused')
            if pending:
                parents = {directory(stage)};count = 0
                for parent,children,_ in os.walk(stage,followlinks=False):
                    count += 1
                    need(count <= 1024 and len(Path(parent).relative_to(stage).parts) <= 16,'callback-refused')
                    parents.add(directory(Path(parent)))
                    need(all(not (Path(parent)/name).is_symlink() for name in children),'callback-refused')
                need(all(key[0] in parents for key in pending),'callback-refused')
            uncertain.update(pending)
            need(not process_uncertain or process == [True],'callback-refused')
            history['process'] = process_uncertain or bool(process)
            proof = (history['stage'],tuple(uncertain.items()),history['process'])
            if self.zsh_admission is not None and self.graph_observation is not None:
                self.graph_observation = self.graph_observation[:-1]+(('zsh-proof',self.zsh_proof()),)
        runtime = {name:(lambda value,index=index: (need(value is objects[index],'callback-refused'),state()))
                   for index,name in enumerate(names)}
        first = self.zsh_snapshot(addon,self.raw['scripts/ci/development/zsh_addon.py'],runtime=runtime)
        second = self.zsh_snapshot(consumer,self.raw['scripts/ci/development/zsh_session.py'])
        return modules,first,second,state

    def zsh_snapshot(self, module, source, *, runtime=None, interfaces=None):
        """Return a private checker; do not expose or replace its frozen closure.

        runtime is an exact symbol -> checker table selected by root, not by modules.
        Unsupported opaque values retain identity only. Root must reject such values
        if they are execution policy, rather than claiming their contents are bound.
        """
        METADATA = frozenset(('__loader__', '__spec__', '__cached__'))
        MAX_NODES, MAX_DEPTH, MAX_TEXT = 40000, 32, 16 * 1024**2
        LIVE_DEPENDENCIES = frozenset((('sys', 'modules'), ('sys', 'path'), ('os', 'environ')))
        def _exec_require(value):need(value, 'callback-refused')
        def dependency_paths(source, namespace):
            result = set()
            for node in ast.walk(ast.parse(source)):
                if not isinstance(node,ast.Attribute):continue
                names,current = [],node
                while isinstance(current,ast.Attribute):
                    names.append(current.attr);current = current.value
                if isinstance(current,ast.Name) and isinstance(namespace.get(current.id),types.ModuleType):
                    result.add((current.id,*reversed(names)))
            return tuple(sorted(result))
        namespace = module.__dict__
        runtime = dict(runtime or {})
        interfaces = dict(interfaces or {})
        names = tuple(sorted(key for key in namespace if key not in METADATA))
        _exec_require(set(runtime) <= set(names))
        paths = dependency_paths(source, namespace)
        _exec_require(set(interfaces) <= set(paths))
        builtin_value = namespace.get('__builtins__')
        builtin_namespace = vars(builtin_value) if isinstance(builtin_value, types.ModuleType) else builtin_value
        _exec_require(type(builtin_namespace) is dict)
        builtin_names = tuple(sorted({node.id for node in ast.walk(ast.parse(source))
                                     if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
                                     and node.id not in namespace and node.id in builtin_namespace}))
        holders = []  # Retain baseline objects so identity integers cannot be reused.

        def snapshot(retain):
            seen, nodes, text = set(), 0, 0
            local_holders = []

            def freeze(value, depth=0):
                nonlocal nodes, text
                nodes += 1
                _exec_require(nodes <= MAX_NODES and depth <= MAX_DEPTH)
                kind = type(value)
                if kind in (type(None), bool, int, float, str, bytes):
                    if kind is float:
                        _exec_require(math.isfinite(value))
                    if kind in (str, bytes):
                        text += len(value)
                        _exec_require(text <= MAX_TEXT)
                    return ('scalar', kind.__name__, value)
                if value is sys.modules or value is sys.path or value is os.environ:
                    return ('live-identity',id(value))
                if any(value is namespace[name] for name in runtime):
                    return ('runtime-registry',id(value))
                local_holders.append(value)  # Keep transient bound methods alive in this snapshot.
                key = id(value)
                if retain:
                    holders.append(value)
                if key in seen:
                    return ('reference', key)
                seen.add(key)
                child = lambda item: freeze(item, depth + 1)
                if kind in (tuple, list):
                    return (kind.__name__, key, tuple(child(item) for item in value))
                if kind is dict:
                    rows = [(child(k), child(v)) for k, v in value.items()]
                    return ('dict', key, tuple(sorted(rows, key=lambda row: repr(row[0]))))
                if kind in (set, frozenset):
                    return (kind.__name__, key, tuple(sorted((child(v) for v in value), key=repr)))
                if isinstance(value, re.Pattern):
                    return ('pattern', key, value.pattern, value.flags)
                if isinstance(value, PurePath):
                    # Explicitly selected CPython pathlib representation, never an
                    # arbitrary object-state walker. Root must review its runtime.
                    attribute = '_raw_paths' if hasattr(value, '_raw_paths') else '_parts'
                    raw = object.__getattribute__(value, attribute)
                    _exec_require(type(raw) in (list, tuple) and all(type(p) is str for p in raw))
                    return ('path', key, attribute, child(raw), str(value), value.parts)
                if isinstance(value, types.CodeType):
                    return ('code', key)
                if isinstance(value, types.FunctionType):
                    cells = tuple((id(cell), child(cell.cell_contents)) for cell in (value.__closure__ or ()))
                    return ('function', key, id(value.__code__), id(value.__globals__),
                            child(value.__defaults__), child(value.__kwdefaults__),
                            child(value.__dict__), child(value.__annotations__), cells)
                if isinstance(value, (staticmethod, classmethod)):
                    return (kind.__name__, key, child(value.__func__))
                if isinstance(value, property):
                    return ('property', key, child(value.fget), child(value.fset), child(value.fdel))
                if isinstance(value, type) and value.__module__ == module.__name__:
                    rows = tuple((name, child(item)) for name, item in sorted(vars(value).items())
                                 if name not in ('__dict__', '__weakref__'))
                    return ('owned-class', key, tuple(id(base) for base in value.__bases__), rows)
                if isinstance(value, types.BuiltinMethodType) and value.__self__ is not None and not isinstance(value.__self__, types.ModuleType):
                    return ('builtin-method', id(value.__self__), value.__name__,
                            id(vars(type(value.__self__)).get(value.__name__)))
                # Imported module/class/function identity is retained. Relevant
                # mutable module attributes are separately included below.
                return ('identity', kind.__module__, kind.__qualname__, key)

            bindings = tuple((name, ('runtime',) if name in runtime else freeze(namespace[name])) for name in names)
            dependencies = [(('__builtins__', name), freeze(builtin_namespace[name])) for name in builtin_names]
            for path in paths:
                value = namespace[path[0]]
                for index, name in enumerate(path[1:], 1):
                    value = getattr(value, name)
                    if path[:index + 1] in interfaces:
                        interfaces[path[:index + 1]](value)
                        dependencies.append((path[:index + 1], ('private-role',)))
                        break
                    if path[:index + 1] in LIVE_DEPENDENCIES:
                        dependencies.append((path[:index + 1], ('live-identity', id(value))))
                        break
                else:
                    dependencies.append((path, freeze(value)))
            return bindings, tuple(dependencies)

        baseline = snapshot(True)
        for name, check in runtime.items():
            check(namespace[name])

        def check():
            _exec_require(module.__dict__ is namespace and tuple(sorted(key for key in namespace if key not in METADATA)) == names)
            for name, validator in runtime.items():
                validator(namespace[name])
            observed = snapshot(False)
            _exec_require(observed == baseline)
        return check

    def zsh_guard_identity(self, state):
        """Guard executable capsules are frozen; only the four exact registries vary."""
        modules = state[0]
        owner = sys.modules.get(type(self).__module__)
        known = (owner,modules['zsh_addon'],modules['zsh_session'])
        runtime = tuple(modules['zsh_addon'].__dict__[name] for name in
            ('_RECEIPT_FILES','_RECEIPT_FDS','_RECEIPT_UNCERTAIN','_PROCESS_DISPOSAL_UNCERTAIN'))
        namespaces = tuple(value.__dict__ for value in known)
        seen = set();count = 0
        def freeze(value, depth=0):
            nonlocal count
            count += 1
            need(count <= 200000 and depth <= 64,'callback-refused')
            if value is None or type(value) in (str,bytes,int,bool,float):return (type(value),value)
            if any(value is item for item in runtime):return ('registry',type(value),id(value))
            if any(value is item for item in namespaces):return ('namespace',id(value))
            if value is sys.modules or value is sys.path or value is os.environ:return ('live-identity',id(value))
            if id(value) in seen:return ('reference',id(value))
            seen.add(id(value))
            if isinstance(value,Path):return ('path',type(value),id(value),str(value))
            if type(value) is types.FunctionType:
                filename = Path(value.__code__.co_filename).absolute()
                if self.project_file(filename):
                    match = [item for item in known if value.__globals__ is item.__dict__]
                    need(len(match) == 1,'callback-refused');self.graph_function(value,match[0])
                else:
                    standard = sys.modules.get(value.__module__)
                    symbol = standard
                    for part in value.__qualname__.split('.'):
                        symbol = vars(symbol).get(part) if hasattr(symbol,'__dict__') else None
                        if isinstance(symbol,(staticmethod,classmethod)):symbol = symbol.__func__
                    frozen = (value.__code__.co_filename.startswith('<frozen ') and type(standard) is types.ModuleType and
                              standard.__dict__ is value.__globals__ and value.__module__ in sys.stdlib_module_names and
                              getattr(getattr(standard,'__spec__',None),'origin',None) == 'frozen' and symbol is value)
                    need(filename.is_relative_to(sysconfig.get_path('stdlib')) or frozen,'callback-refused')
                sticky = value.__code__.co_qualname == 'Sources.zsh_guards.<locals>.state'
                cells = dict(zip(value.__code__.co_freevars,value.__closure__ or ()))
                if sticky:
                    need(value.__globals__ is owner.__dict__ and cells['self'].cell_contents is self,'callback-refused')
                    history,proof = cells['history'].cell_contents,cells['proof'].cell_contents
                    need(history is self.zsh_history and type(history) is dict and set(history) == {'stage','uncertain','process'} and
                         type(history['uncertain']) is dict and type(proof) is tuple and len(proof) == 3 and
                         history['stage'] == proof[0] and history['process'] is proof[2] and
                         tuple(history['uncertain']) == tuple(key for key,_ in proof[1]) and
                         all(history['uncertain'][key] is error for key,error in proof[1]),'callback-refused')
                return ('function',id(value),value.__code__,id(value.__globals__),freeze(value.__defaults__,depth+1),
                    freeze(value.__kwdefaults__,depth+1),freeze(value.__dict__,depth+1),
                    tuple((name,id(cell),('sticky-history',id(history)) if sticky and name == 'history' else
                          ('sticky-proof',) if sticky and name == 'proof' else freeze(cell.cell_contents,depth+1)) for name,cell in
                          zip(value.__code__.co_freevars,value.__closure__ or ())))
            if type(value) is dict:
                return ('dict',id(value),tuple((freeze(key,depth+1),freeze(item,depth+1)) for key,item in value.items()))
            if type(value) in (tuple,list):
                return (type(value),id(value),tuple(freeze(item,depth+1) for item in value))
            if type(value) in (set,frozenset):return (type(value),id(value),frozenset(freeze(item,depth+1) for item in value))
            return ('opaque',type(value),id(value))
        return tuple(freeze(function) for function in state[1:])

    def zsh_proof(self):
        history = self.zsh_history
        need(type(history) is dict and set(history) == {'stage','uncertain','process'} and
             type(history['uncertain']) is dict and len(history['uncertain']) <= 256 and
             type(history['process']) is bool,'callback-refused')
        key = history['stage']
        need(key is None or type(key) is tuple and len(key) == 5 and all(type(value) is int for value in key),
             'callback-refused')
        return key,tuple(history['uncertain'].items()),history['process']

    def zsh_proof_matches(self, proof):
        current = self.zsh_proof()
        return (type(proof) is tuple and len(proof) == 3 and proof[0] == current[0] and proof[2] is current[2] and
                type(proof[1]) is tuple and len(proof[1]) == len(current[1]) and
                all(type(old) is tuple and len(old) == 2 and old[0] == new[0] and old[1] is new[1]
                    for old,new in zip(proof[1],current[1])))


def preflight(root, grant_raw, grant_pin, *, deadline):
    """Authenticate complete sources/maps/policy before executing project imports."""
    check(deadline)
    need(type(grant_pin) is str and re.fullmatch('[0-9a-f]{64}', grant_pin) and
         digest(grant_raw) == grant_pin, 'grant-refused')
    grant = decode(grant_raw)
    need(set(grant) == {'schema_version', 'purpose', 'source_peer_preflight', 'development_only',
        'added_seconds', 'source_commit', 'recipe_source_commit', 'run_id', 'run_attempt',
        'source_files', 'maps', 'callbacks', 'policy_path', 'license_path','actor_contract_sha256',
        'initial_invocation_sha256','baseline_view'} and
        type(grant['schema_version']) is int and grant['schema_version'] == 2 and
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
    need(len(lock['source_files']) == 160 and len(lock['generated_fixture_files']) == 125 and
         all(grant['source_files'].get(name) == row for name, row in lock['source_files'].items()), 'source-refused')
    view = grant['baseline_view']
    need(type(view) is dict and set(view) == {'schema_version','purpose','full_source_root','root',
         'integration_lock_sha256','source_rows_sha256','file_count','argv_mode','baseline_id'} and
         type(view['schema_version']) is int and view['schema_version'] == 2 and
         view['baseline_id'] == 'maintained-native-baseline-v2-client48-vim-9.2.1178-1' and
         view['purpose'] == 'maintained-v2-160-copy-view' and view['full_source_root'] == str(sources.root) and
         type(view['root']) is str and Path(view['root']).is_absolute() and '..' not in Path(view['root']).parts and
         view['integration_lock_sha256'] == INITIAL and
         view['source_rows_sha256'] == digest(encoded(lock['source_files'])) and
         type(view['file_count']) is int and view['file_count'] == 161 and
         view['argv_mode'] == 'absolute-view-metadata','grant-refused')
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
                if name in ('original_scope','native_consumer_observation'):
                    if item is not None:
                        value.original_context(deadline=deadline,controller=value.controller if name == 'native_consumer_observation' else None)
                    continue
                if name == 'supervise' and item is not None:
                    supervisor_state(item,value);continue
                if name == 'controller' and item is not None:
                    need('scripts/ci/integration.py' in graph,'callback-refused')
                    inspect_state(sources.class_state(item,'scripts/ci/integration.py',graph['scripts/ci/integration.py'],
                        scope=sources.original_root),depth+1);continue
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
                if name in ('zsh_admission','zsh_history') and item is not None:
                    need(session is not None and session.composition == 'repository-svg-zsh' and
                         'scripts/ci/development/zsh_session.py' in graph,'callback-refused')
                    sources.source_graph(session)  # Exact admitted capsules/lifecycle, never generic functions.
                    continue
                if name == 'codes':
                    need(type(item) is dict,'callback-refused')
                    for source_path,codes in item.items():
                        path = sources.locate(source_path)
                        need(path in sources.raw and type(codes) is list and codes == list(code_objects(
                            compile(sources.raw[path],source_path,'exec'))),'callback-refused')
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
    def __init__(self, sources, output, *, job_deadline, cancelled=None, composition='repository-svg-maintained-v1'):
        check(job_deadline, cancelled)
        need(type(composition) is str and composition in ('repository-svg-maintained-v1','installer-preflight-maintained-v1'),'grant-refused')
        self.composition = composition
        self.sources, self.output = sources, Path(output).absolute()
        self.job_deadline, self.cancelled = job_deadline, cancelled
        self.used = False; self.end = None; self.work_end = None
        self.controller = self.pending_capture = self.collected = self.supervise = None
        self.private = None; self.private_node = None
        self.operation = 'source-refused'
        self.startup_phase = 'source-bound'
        self.startup_failure = None
        self.native_hook_entered = False
        self.source_graph = {}
        self.view_root = self.view_node = self.view_parent_node = None
        self.view_receipt = self.view_receipt_sha256 = None
        self.original_scope = self.native_consumer_observation = None
        self.native_executor_scope = self.native_executor = None
        self.native_services = self.native_runtime_contract = None
        self.phase_export_raw = self.phase_export_sha256 = None
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

    def service_failure_site(self, error):
        """Diagnostic-only labels from held Source code and exact graph namespaces."""
        if type(error) is not TypeError or self.startup_phase != 'construct-services':return 'OTHER'
        graph = self.source_graph
        if type(graph) is not dict:return 'OTHER'
        runtime,collector = graph.get('runtime'),graph.get('collector')
        if type(runtime) is not dict or type(collector) is not dict:return 'OTHER'
        rows = (
            (PREFIXES['runtime']+'/entry.py',graph.get('entry'),{
                'services':'SERVICE_CALL','services.<locals>.source_guard':'SERVICE_SOURCE_GUARD',
                'captures':'SERVICE_SOURCE_CAPTURE','pinned':'SERVICE_SOURCE_READ','read':'SERVICE_SOURCE_READ'}),
            (PREFIXES['runtime']+'/broker.py',runtime.get('broker'),{'Pending.__init__':'SERVICE_PENDING'}),
            (PREFIXES['runtime']+'/transport.py',runtime.get('transport'),{
                'DockerTransport.__init__':'SERVICE_TRANSPORT_INIT','DockerTransport._preflight':'SERVICE_TRANSPORT_PREFLIGHT',
                'read_file':'SERVICE_TRANSPORT_CLI','directory':'SERVICE_TRANSPORT_DIRECTORY'}),
            (PREFIXES['collector']+'/common.py',collector.get('common'),{
                'defer_cancellation':'SERVICE_CANCEL_CONTEXT','_signal_handlers':'SERVICE_CANCEL_SIGNALS'}))
        if type(self.sources) is not Sources:return 'OTHER'
        if type(self.sources.root) is not type(Path('/')):return 'OTHER'
        raw,grants = self.sources.raw,self.sources.grant
        if type(raw) is not dict or type(grants) is not dict or type(grants.get('source_files')) is not dict:return 'OTHER'
        candidates=[]
        for path,module,labels in rows:
            if type(module) is not types.ModuleType or path not in raw:continue
            data,pin = raw[path],grants['source_files'].get(path)
            if type(data) is not bytes or len(data)>FILE_LIMIT or type(pin) is not dict or type(pin.get('sha256')) is not str or digest(data)!=pin['sha256']:continue
            filename=str(self.sources.root/path)
            if type(module.__dict__.get('__file__')) is not str or module.__dict__['__file__'] != filename:continue
            compiled={code.co_qualname:code for code in code_objects(compile(data,filename,'exec'))}
            exits,exit_calls={},{}
            if path == PREFIXES['collector']+'/common.py':
                calls={ast.dump(ast.parse(expression,mode='eval').body,include_attributes=False):label
                    for expression,label in (
                        ('signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)','SERVICE_CANCEL_EXIT_BLOCK'),
                        ('signal.signal(number, original)','SERVICE_CANCEL_EXIT_SET_HANDLER'),
                        ('signal.getsignal(number) == original','SERVICE_CANCEL_EXIT_HANDLER_CHECK'),
                        ('number not in mask and number in signal.sigpending()','SERVICE_CANCEL_EXIT_PENDING_CHECK'),
                        ('signal.sigwait({number})','SERVICE_CANCEL_EXIT_PENDING_WAIT'),
                        ('signal.pthread_sigmask(signal.SIG_SETMASK, mask)','SERVICE_CANCEL_EXIT_SET_MASK'),
                        ('handler(number, None)','SERVICE_CANCEL_EXIT_REPLAY'))}
                for node in ast.parse(data).body:
                    if type(node) is ast.FunctionDef and node.name in ('defer_cancellation','_signal_handlers'):
                        regions=[part for item in ast.walk(node) if type(item) is ast.Try for part in item.finalbody]
                        exits[node.name]=tuple((part.lineno,part.end_lineno) for part in regions)
                        if node.name == '_signal_handlers':
                            matches={}
                            for region in regions:
                                for call in ast.walk(region):
                                    if type(call) in (ast.Call,ast.Compare,ast.BoolOp):
                                        label=calls.get(ast.dump(call,include_attributes=False))
                                        if label is not None:matches[(call.lineno,call.end_lineno)]=label
                            exit_calls[node.name]=tuple((start,end,label) for (start,end),label in matches.items())
            candidates.append((module.__dict__,filename,compiled,labels,exits,exit_calls))
        site='OTHER';trace=error.__traceback__;count=0
        while trace is not None:
            if type(trace) is not types.TracebackType or count>=64:return 'OTHER'
            count+=1;frame=trace.tb_frame;code=frame.f_code
            for namespace,filename,compiled,labels,exits,exit_calls in candidates:
                name=code.co_qualname
                if frame.f_globals is namespace and code.co_filename==filename and name in labels and code==compiled.get(name):
                    site=labels[name]
                    if name in exits:
                        site='SERVICE_CANCEL_EXIT' if any(start<=trace.tb_lineno<=end for start,end in exits[name]) else 'SERVICE_CANCEL_ENTER'
                        for start,end,label in exit_calls.get(name,()):
                            if start<=trace.tb_lineno<=end:
                                site=label
                                if label == 'SERVICE_CANCEL_EXIT_SET_HANDLER':
                                    api=frame.f_globals.get('signal')
                                    wrapper=api.__dict__.get('signal') if type(api) is types.ModuleType else None
                                    child=trace.tb_next
                                    # Saved restoration errors outlive the loop's current original.
                                    # Read only the direct API frame before its handler assignment.
                                    templates=tuple(next(code for code in code_objects(compile(prefix+
                                        'def signal(signalnum, handler):\n    handler = _signal.signal(_enum_to_int(signalnum), _enum_to_int(handler))\n    return _int_to_enum(handler, Handlers)\n',
                                        '<closed-signal-api-shape>','exec',dont_inherit=True)) if code.co_name == 'signal')
                                        for prefix in ('import _signal\n',''))
                                    template=templates[0]
                                    fields=('co_code','co_names','co_varnames','co_argcount','co_posonlyargcount',
                                        'co_kwonlyargcount','co_freevars','co_cellvars')
                                    refusal=None
                                    if type(api) is not types.ModuleType or type(api.__dict__.get('__name__')) is not str or api.__dict__['__name__'] != 'signal':
                                        refusal='API_MODULE'
                                    elif type(wrapper) is not types.FunctionType:
                                        refusal='WRAPPER_TYPE'
                                    elif wrapper.__globals__ is not api.__dict__:
                                        refusal='WRAPPER_GLOBALS'
                                    elif wrapper.__defaults__ is not None or wrapper.__kwdefaults__ is not None or wrapper.__closure__ is not None:
                                        refusal='WRAPPER_STATE'
                                    elif len(wrapper.__code__.co_consts) != 1 or wrapper.__code__.co_consts[0] is not None:
                                        refusal='WRAPPER_CONSTANTS'
                                    elif type(wrapper.__code__.co_flags) is not type(template.co_flags) or wrapper.__code__.co_flags != template.co_flags:
                                        refusal='WRAPPER_FLAGS'
                                    elif not any(all(type(getattr(wrapper.__code__,key)) is type(getattr(candidate,key)) and
                                            (all(type(item) is str for item in getattr(wrapper.__code__,key)) if type(getattr(candidate,key)) is tuple else True) and
                                            getattr(wrapper.__code__,key) == getattr(candidate,key) for key in fields) for candidate in templates):
                                        refusal='WRAPPER_CODE'
                                    elif type(child) is not types.TracebackType or child.tb_frame.f_code is not wrapper.__code__ or child.tb_frame.f_globals is not api.__dict__:
                                        refusal='API_FRAME'
                                    else:
                                        template=next(candidate for candidate in templates if all(getattr(wrapper.__code__,key) == getattr(candidate,key) for key in fields))
                                        if not any(start<=child.tb_lasti<end and line == template.co_firstlineno+1 for start,end,line in template.co_lines()):
                                            refusal='API_OFFSET'
                                    if refusal is not None:
                                        site='SERVICE_CANCEL_EXIT_SET_HANDLER_'+refusal
                                    else:
                                        original=child.tb_frame.f_locals['handler']
                                        handler_kind=('NONE' if original is None else
                                            'DEFAULT' if original is api.__dict__.get('SIG_DFL') or type(original) is int and original == 0 else
                                            'IGNORE' if original is api.__dict__.get('SIG_IGN') or type(original) is int and original == 1 else
                                            'CALLABLE' if callable(original) else 'OTHER')
                                        args=error.args
                                        api_code=('BAD_HANDLER_API' if type(args) is tuple and len(args) == 1 and type(args[0]) is str and
                                            args[0] == 'signal handler must be signal.SIG_IGN, signal.SIG_DFL, or a callable object' else 'OTHER_TYPEERROR')
                                        site='SERVICE_CANCEL_EXIT_SET_HANDLER_'+handler_kind+'_'+api_code
            trace=trace.tb_next
        return site

    def cancellation_observed(self, collector, events):
        """Failure disposition from the exact captured common observer/registry."""
        path = PREFIXES['collector']+'/common.py'
        need(type(collector) is dict and type(events) is set and type(self.sources) is Sources,
             'callback-refused')
        module = collector.get('common')
        need(type(module) is types.ModuleType and type(module.__dict__.get('__file__')) is str and
             module.__file__ == str(self.sources.root/path) and
             module.__dict__.get('CANCELLATION_EVENTS') is events, 'callback-refused')
        callback = module.__dict__.get('cancellation_requested')
        self.sources.graph_function(callback, module)
        need(callback.__defaults__ is None and callback.__kwdefaults__ is None and
             callback.__closure__ is None, 'callback-refused')
        validator = module.__dict__.get('cancellation_state')
        self.sources.graph_function(validator, module)
        for name in ('defer_cancellation', 'cancellation_handlers'):
            factory = module.__dict__.get(name)
            need(type(factory) is types.FunctionType and
                 factory.__code__ == contextmanager(lambda:None).__code__ and
                 factory.__globals__ is contextmanager.__globals__ and
                 type(factory.__closure__) is tuple and len(factory.__closure__) == 1 and
                 factory.__closure__[0].cell_contents is getattr(factory,'__wrapped__',None),
                 'callback-refused')
            self.sources.graph_function(factory.__wrapped__, module)
        result = callback()
        need(type(result) is bool, 'callback-refused')
        return result

    def cancellation_teardown_uncertain(self, collector, registry):
        """Authenticated closed uncertainty, independent of first error/cancel."""
        path = PREFIXES['collector']+'/common.py'
        need(type(collector) is dict and type(registry) is set and type(self.sources) is Sources,
             'callback-refused')
        module = collector.get('common')
        need(type(module) is types.ModuleType and type(module.__dict__.get('__file__')) is str and
             module.__file__ == str(self.sources.root/path) and
             module.__dict__.get('CANCELLATION_UNCERTAIN') is registry, 'callback-refused')
        for name in ('cancellation_state','cancellation_uncertain'):
            callback = module.__dict__.get(name)
            self.sources.graph_function(callback, module)
            need(callback.__defaults__ is None and callback.__kwdefaults__ is None and
                 callback.__closure__ is None, 'callback-refused')
        result = module.cancellation_uncertain()
        need(type(result) is bool, 'callback-refused')
        return result

    def downstream_signal_disposition(self, runtime, events, uncertainty):
        """Exact Source observer; cancellation and teardown uncertainty stay independent."""
        path=PREFIXES['runtime']+'/launch.py'
        need(type(runtime) is dict and type(events) is set and type(uncertainty) is set and
             type(self.sources) is Sources,'callback-refused')
        module=runtime.get('launch')
        need(type(module) is types.ModuleType and module.__dict__.get('__file__') == str(self.sources.root/path)
             and module.__dict__.get('CANCELLATION_EVENTS') is events and
             module.__dict__.get('CANCELLATION_UNCERTAIN') is uncertainty,'callback-refused')
        for name in ('cancellation_state','cancellation_requested','cancellation_uncertain','_raise_signal_faults','retain_fault'):
            callback=module.__dict__.get(name);self.sources.graph_function(callback,module)
            need(callback.__closure__ is None and callback.__kwdefaults__ is None and
                 callback.__defaults__ == ((None,) if name == 'cancellation_state' else None),'callback-refused')
        factory=module.__dict__.get('_signal_handlers')
        need(type(factory) is types.FunctionType and factory.__code__ == contextmanager(lambda:None).__code__ and
             factory.__globals__ is contextmanager.__globals__ and type(factory.__closure__) is tuple and
             len(factory.__closure__)==1 and factory.__closure__[0].cell_contents is getattr(factory,'__wrapped__',None),
             'callback-refused')
        self.sources.graph_function(factory.__wrapped__,module)
        cls=module.__dict__.get('Cancellation')
        need(type(cls) is type and cls.__module__ == module.__name__,'callback-refused')
        for name in ('__init__','handler'):
            self.sources.graph_function(vars(cls).get(name),module)
        deferred=vars(cls).get('defer')
        need(type(deferred) is types.FunctionType and deferred.__code__ == contextmanager(lambda:None).__code__ and
             deferred.__globals__ is contextmanager.__globals__ and type(deferred.__closure__) is tuple and
             len(deferred.__closure__)==1 and deferred.__closure__[0].cell_contents is getattr(deferred,'__wrapped__',None),
             'callback-refused')
        self.sources.graph_function(deferred.__wrapped__,module)
        cancelled=vars(cls).get('cancelled');need(type(cancelled) is property,'callback-refused')
        for callback in (cancelled.fget,cancelled.fset):self.sources.graph_function(callback,module)
        result=module.cancellation_requested(),module.cancellation_uncertain()
        need(all(type(value) is bool for value in result),'callback-refused')
        return result

    def startup_failed(self, error):
        """Keep the first finite observation without changing the exception/cause."""
        if self.startup_failure is not None:return
        kind = ('INTERRUPT' if isinstance(error,KeyboardInterrupt) else
                'FATAL' if isinstance(error,SystemExit) else
                'SOURCE_REFUSAL' if type(error) is Refused else
                'OS_ERROR' if isinstance(error,OSError) else
                'VALUE_ERROR' if isinstance(error,ValueError) else
                'TYPE_ERROR' if isinstance(error,TypeError) else 'OTHER')
        site = vars(error).get('_source_refusal_site','OTHER') if type(error) is Refused else 'OTHER'
        if site == 'OTHER' and type(error) is TypeError:
            try:site = self.service_failure_site(error)
            except BaseException:pass  # Optional attribution never replaces the first cause.
        self.startup_failure = {'phase':self.startup_phase,'kind':kind,'site':site,
            'object_clause':vars(error).get('_graph_object_clause','OTHER') if type(error) is Refused else 'OTHER',
            'object_callsite':vars(error).get('_graph_object_callsite','OTHER') if type(error) is Refused else 'OTHER'}

    def startup_projection(self):
        """Failure-only closed observations; never an acceptance/status receipt."""
        phases = ('source-bound', 'load-runtime', 'load-collector', 'load-phase', 'copy-view', 'register-installer', 'capture-dependencies', 'construct-services', 'load-original', 'capture-original', 'call-original', 'native-hook', 'original-returned', 'cleanup', 'status-publication')
        kinds = ('INTERRUPT','FATAL','SOURCE_REFUSAL','OS_ERROR','VALUE_ERROR','TYPE_ERROR','OTHER')
        sites = ('CLASS_STATE','CLASS_LITERAL','CALLBACK','GLOBAL_FUNCTION','GRAPH_FUNCTION',
                 'GRAPH_OBJECT_BINDING','GRAPH_HELD_CODE_BINDING',
                 'GRAPH_NAMESPACE','FROZEN_FILE_HOOK','GRAPH_IDENTITY','SOURCE_GRAPH','INSTALLER_REGISTRATION',
                 'ORIGINAL_CONTEXT','NATIVE_FRAME','OWNED_CLEANUP','VIEW_COPY','VIEW_VERIFY',
                 'DEADLINE_CHECK','CALLBACK_BINDINGS','AUTHORITY_STATE',
                 'SERVICE_CALL','SERVICE_SOURCE_GUARD','SERVICE_SOURCE_CAPTURE','SERVICE_SOURCE_READ',
                 'SERVICE_PENDING','SERVICE_TRANSPORT_INIT','SERVICE_TRANSPORT_PREFLIGHT',
                 'SERVICE_TRANSPORT_CLI','SERVICE_TRANSPORT_DIRECTORY','SERVICE_CANCEL_CONTEXT',
                 'SERVICE_CANCEL_SIGNALS','SERVICE_CANCEL_ENTER','SERVICE_CANCEL_EXIT',
                 'SERVICE_CANCEL_EXIT_BLOCK','SERVICE_CANCEL_EXIT_SET_HANDLER','SERVICE_CANCEL_EXIT_HANDLER_CHECK',
                 'SERVICE_CANCEL_EXIT_PENDING_CHECK','SERVICE_CANCEL_EXIT_PENDING_WAIT',
                 'SERVICE_CANCEL_EXIT_SET_MASK','SERVICE_CANCEL_EXIT_REPLAY',
                 'SERVICE_CANCEL_EXIT_SET_HANDLER_NONE_BAD_HANDLER_API',
                 'SERVICE_CANCEL_EXIT_SET_HANDLER_NONE_OTHER_TYPEERROR',
                 'SERVICE_CANCEL_EXIT_SET_HANDLER_DEFAULT_BAD_HANDLER_API',
                 'SERVICE_CANCEL_EXIT_SET_HANDLER_DEFAULT_OTHER_TYPEERROR',
                 'SERVICE_CANCEL_EXIT_SET_HANDLER_IGNORE_BAD_HANDLER_API',
                 'SERVICE_CANCEL_EXIT_SET_HANDLER_IGNORE_OTHER_TYPEERROR',
                 'SERVICE_CANCEL_EXIT_SET_HANDLER_CALLABLE_BAD_HANDLER_API',
                 'SERVICE_CANCEL_EXIT_SET_HANDLER_CALLABLE_OTHER_TYPEERROR',
                 'SERVICE_CANCEL_EXIT_SET_HANDLER_OTHER_BAD_HANDLER_API',
                 'SERVICE_CANCEL_EXIT_SET_HANDLER_OTHER_OTHER_TYPEERROR',
                 'SERVICE_CANCEL_EXIT_SET_HANDLER_API_MODULE','SERVICE_CANCEL_EXIT_SET_HANDLER_WRAPPER_TYPE',
                 'SERVICE_CANCEL_EXIT_SET_HANDLER_WRAPPER_GLOBALS','SERVICE_CANCEL_EXIT_SET_HANDLER_WRAPPER_STATE',
                 'SERVICE_CANCEL_EXIT_SET_HANDLER_WRAPPER_CONSTANTS','SERVICE_CANCEL_EXIT_SET_HANDLER_WRAPPER_FLAGS',
                 'SERVICE_CANCEL_EXIT_SET_HANDLER_WRAPPER_CODE','SERVICE_CANCEL_EXIT_SET_HANDLER_API_FRAME',
                 'SERVICE_CANCEL_EXIT_SET_HANDLER_API_OFFSET','OTHER')
        failure = self.startup_failure
        need(type(self.startup_phase) is str and self.startup_phase in phases and
             type(self.native_hook_entered) is bool and type(failure) is dict and
             set(failure) == {'phase','kind','site','object_clause','object_callsite'} and
             all(type(failure[key]) is str for key in failure) and
             failure['phase'] in phases and failure['kind'] in kinds and failure['site'] in sites and
             failure['object_clause'] in ('FUNCTION_TYPE','MODULE_TYPE','GLOBALS','OTHER') and
             failure['object_callsite'] in ('DECLARED','OVERRIDE','IMPORTED','LAUNCH_VALIDATOR','COMMON_VALIDATOR','LANGUAGE','OTHER'),
             'status-persistence-failed')
        status = status_projection(self.result)
        need(status['status'] == 'FAIL' and status['error_code'] in CODES,'status-persistence-failed')
        return {'schema_version':2,'purpose':'maintained-composed-startup-refusal','status':'FAIL',
                'phase':failure['phase'],'kind':failure['kind'],'site':failure['site'],
                'object_clause':failure['object_clause'],'object_callsite':failure['object_callsite'],
                'native_hook_entered':self.native_hook_entered,
                'error_code':status['error_code'],'cleanup':status['cleanup']}

    def emit_startup_refusal(self, deadline):
        """Existing endpoint and captured class/source custody; no new allowance."""
        check(deadline)
        owner = sys.modules.get(type(self).__module__)
        self.sources.class_state(self,'scripts/ci/development/repository_handoff.py',owner)
        self.sources.guard(deadline)
        raw = encoded(self.startup_projection())
        need(len(raw) <= 1024,'status-persistence-failed')
        check(deadline)
        print('MAINTAINED_COMPOSED_STARTUP_REFUSAL='+raw.decode('ascii').replace('\n',''),flush=True)

    def register_native_preflight(self):
        """Explicit source-only registration before the first dependency capture."""
        need(type(self.composition) is str and self.composition == 'installer-preflight-maintained-v1' and self.used is True and self.controller is None and
             self.sources.graph_observation is None and type(self.source_graph) is dict and
             set(self.source_graph) == {'entry','runtime','collector','phase','original','original_aliases'} and
             not self.source_graph['original'] and not self.source_graph['original_aliases'], 'callback-refused')
        path,name,qualname = ('scripts/install/native_preflight.py','native_install_preflight','run')
        required = (path,'scripts/install/test_native_preflight.py','scripts/install/local_transaction.py',
            'scripts/install/test_local_transaction.py','scripts/install/native_arm_trial.py',
            'scripts/install/test_native_arm_trial.py','scripts/port/kernel-native-job/runtime.py')
        need(all(item in self.sources.raw and item in self.sources.grant['source_files'] for item in required) and
             name not in sys.modules,'callback-refused')
        owner = sys.modules.get(type(self).__module__)
        self.sources.class_state(self,'scripts/ci/development/repository_handoff.py',owner)
        self.sources.class_state(self.sources,'scripts/ci/development/repository_handoff.py',owner)
        self.sources.guard(self.job_deadline,self.cancelled)
        module = self.sources.module(name,path)
        self.sources.graph_namespace(module,path,{path:module},{},{})
        callback = module.__dict__.get(qualname)
        need(type(callback) is types.FunctionType and type(callback.__module__) is str and callback.__module__ == name and
             type(callback.__qualname__) is str and callback.__qualname__ == qualname and callback.__globals__ is module.__dict__, 'callback-refused')
        module.namespace(module,self.sources.raw[path],self.sources.grant['source_files'][path]['sha256'])
        self.source_graph['native_preflight'] = module
        sys.modules[name] = module
        try:
            self.sources.guard(self.job_deadline,self.cancelled)
            module.namespace(module,self.sources.raw[path],self.sources.grant['source_files'][path]['sha256'])
        except BaseException:
            if sys.modules.get(name) is module:del sys.modules[name]
            if self.source_graph.get('native_preflight') is module:del self.source_graph['native_preflight']
            raise
        return callback

    def register_zsh(self):
        """Exact held pair before the first capture; no addon loader or producer."""
        need(self.composition == 'repository-svg-zsh' and self.used is True and self.controller is None and
             self.sources.graph_observation is None and self.sources.zsh_admission is None and
             self.view_root is not None and type(self.source_graph) is dict and
             set(self.source_graph) == {'entry','runtime','collector','phase','original','original_aliases'} and
             not self.source_graph['original'] and not self.source_graph['original_aliases'],'callback-refused')
        required = ('scripts/ci/development/zsh_addon.py','scripts/ci/development/zsh_session.py',
            'scripts/ci/development/test_zsh_addon.py','scripts/ci/development/test_zsh_session.py',
            'manifests/reviewed/zsh-native-addon.json')
        need(all(path in self.sources.raw and path in self.sources.grant['source_files'] for path in required) and
             all('development_'+name not in sys.modules for name in ('zsh_addon','zsh_session')),'callback-refused')
        owner = sys.modules.get(type(self).__module__)
        self.sources.class_state(self,'scripts/ci/development/repository_handoff.py',owner)
        self.sources.class_state(self.sources,'scripts/ci/development/repository_handoff.py',owner)
        self.sources.guard(self.job_deadline,self.cancelled)
        modules = {name:self.sources.module('development_'+name,'scripts/ci/development/'+name+'.py')
                   for name in ('zsh_addon','zsh_session')}
        for name,module in modules.items():
            self.sources.graph_namespace(module,'scripts/ci/development/'+name+'.py',
                {'scripts/ci/development/'+key+'.py':value for key,value in modules.items()},{},{})
        consumer = modules['zsh_session'].__dict__.get('run_zsh')
        need(type(consumer) is types.FunctionType and consumer.__module__ == 'development_zsh_session' and
             consumer.__qualname__ == 'run_zsh' and consumer.__globals__ is modules['zsh_session'].__dict__, 'callback-refused')
        admission = self.sources.zsh_guards(self,modules)
        try:
            for module in modules.values():sys.modules[module.__name__] = module
            self.source_graph['zsh'] = modules;self.sources.zsh_admission = admission
            self.sources.guard(self.job_deadline,self.cancelled)
            for validator in admission[1:]:validator()
        except BaseException:
            for module in modules.values():
                if sys.modules.get(module.__name__) is module:del sys.modules[module.__name__]
            self.source_graph.pop('zsh',None);self.sources.zsh_admission = None
            raise
        return consumer

    def retire_zsh(self):
        """After original scope exit: retire exact healthy modules, never clear custody."""
        try:
            need(self.composition == 'repository-svg-zsh' and self.original_scope is None,'callback-refused')
            modules = self.source_graph.get('zsh');state = self.sources.zsh_admission
            need(type(modules) is dict and set(modules) == {'zsh_addon','zsh_session'} and
                 type(state) is tuple and len(state) == 4 and state[0] is modules and
                 all(type(value) is types.FunctionType for value in state[1:]) and
                 self.sources.graph_observation is not None and self.sources.graph_observation[-3:-1] ==
                 (('zsh-admission',id(state),*(id(value) for value in state)),
                  ('zsh-guards',self.sources.zsh_guard_identity(state))) and
                 self.sources.graph_observation[-1][0] == 'zsh-proof' and
                 self.sources.zsh_proof_matches(self.sources.graph_observation[-1][1]),'callback-refused')
            for name,module in modules.items():
                need(type(module) is types.ModuleType and module.__name__ == 'development_'+name and
                     module.__file__ == str(self.sources.root/'scripts/ci/development'/ (name+'.py')) and
                     sys.modules.get(module.__name__) is module,'callback-refused')
            self.sources.guard(self.job_deadline)
            for validator in state[1:]:validator()
            addon = modules['zsh_addon']
            need(not any(addon.__dict__[name] for name in ('_RECEIPT_FILES','_RECEIPT_FDS',
                 '_RECEIPT_UNCERTAIN','_PROCESS_DISPOSAL_UNCERTAIN')),'callback-refused')
            for module in modules.values():del sys.modules[module.__name__]
            return True
        except BaseException:return False

    def view_plan(self, argv):
        grant = self.sources.grant
        need(type(grant.get('schema_version')) is int and grant['schema_version'] == 2,'grant-refused')
        need(grant.get('schema_version') == 2 and type(grant.get('baseline_view')) is dict,'grant-refused')
        plan = grant['baseline_view'];root = self.output/'maintained-view'
        need(plan['root'] == str(root) and plan['full_source_root'] == str(self.sources.root) and
             not root.is_relative_to(self.sources.root),'grant-refused')
        selected = {}
        need(len(argv)%2 == 1,'grant-refused')
        for index in range(1,len(argv),2):
            flag,value = argv[index:index+2]
            need(flag in ('--inputs','--inputs-sha256','--recipes','--recipes-sha256','--integration',
                          '--integration-sha256','--cache','--output','--integration-output') and flag not in selected,
                 'grant-refused')
            selected[flag] = value
        need(set(selected) == {'--inputs','--inputs-sha256','--recipes','--recipes-sha256','--integration',
                              '--integration-sha256','--cache','--output','--integration-output'},'grant-refused')
        for flag,name in (('--inputs','inputs.lock.json'),('--recipes','recipes.lock.json'),
                          ('--integration','integration.lock.json')):
            path = 'scripts/ci/'+name
            need(selected[flag] == str(root/path) and selected[flag+'-sha256'] == digest(self.sources.raw[path]),
                 'grant-refused')
        for flag in ('--cache','--output','--integration-output'):
            need(Path(selected[flag]).is_absolute() and '..' not in Path(selected[flag]).parts,'grant-refused')
        return root

    def prepare_view(self, root):
        """One maintained160+lock copy; original producer budget, no actor or E renewal."""
        deadline = self.job_deadline
        self.sources.guard(deadline,self.cancelled)
        need(self.view_root is None and root == self.output/'maintained-view' and
             str(root) == self.sources.grant['baseline_view']['root'] and
             not root.exists() and not root.is_symlink(),'source-refused')
        lock = decode(self.sources.raw['scripts/ci/integration.lock.json'])
        rows = {**lock['source_files'],'scripts/ci/integration.lock.json':{'sha256':INITIAL,'mode':0o644}}
        root.mkdir(mode=0o700)
        self.view_root,self.view_node = root,identity(root.lstat())  # Register before copying.
        self.view_parent_node = identity(root.parent.lstat())
        nodes = {};total = 0
        for name,row in sorted(rows.items()):
            check(deadline,self.cancelled)
            raw = self.sources.raw[name];total += len(raw)
            need(total <= TOTAL_LIMIT and digest(raw) == row['sha256'],'source-refused')
            target = root/name
            parents = [os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)]
            fd = None
            try:
                need(identity(os.fstat(parents[0]))[:2] == self.view_node[:2],'source-refused')
                for part in Path(name).parts[:-1]:
                    check(deadline,self.cancelled)
                    try:os.mkdir(part,0o700,dir_fd=parents[-1])
                    except FileExistsError:pass
                    parents.append(os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parents[-1]))
                    node = os.fstat(parents[-1])
                    need(node.st_uid == os.geteuid() and node.st_dev == self.view_node[0] and
                         stat.S_IMODE(node.st_mode) == 0o700,'source-refused')
                fd = os.open(Path(name).name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
                             row['mode'],dir_fd=parents[-1])
                os.fchmod(fd,row['mode']);position = 0
                while position < len(raw):
                    check(deadline,self.cancelled);written = os.write(fd,raw[position:position+65536])
                    need(written > 0,'source-refused');position += written
                os.fsync(fd)
            finally:
                if fd is not None:os.close(fd)
                for parent in reversed(parents):os.close(parent)
            observed,mode,node = read(target,deadline)
            need(observed == raw and mode == row['mode'] and node[4] == os.geteuid() and node[3] == 1,
                 'source-refused')
            nodes[name] = {'sha256':row['sha256'],'mode':mode,'bytes':len(raw),
                           'source_node':list(self.sources.identities[name]),'copy_node':list(node)}
        self.sources.guard(deadline,self.cancelled)
        directories = {'.':list(identity(root.lstat()))}
        for name in rows:
            for parent in (root/name).parents:
                if parent == root:break
                relative_parent = parent.relative_to(root).as_posix()
                directories[relative_parent] = list(identity(parent.lstat()))
        receipt = {'schema_version':1,'purpose':'maintained-v2-160-copy-custody',
            'selection':self.sources.grant['baseline_view'],
            **{key:self.sources.grant[key] for key in ('source_commit','run_id','run_attempt',
                 'actor_contract_sha256','initial_invocation_sha256')},
            'execution_grant_sha256':self.sources.grant_pin,'view_node':list(self.view_node),
            'parent_node':list(self.view_parent_node),'directories':directories,
            'files':nodes,'file_count':161,'bytes':total}
        raw = encoded(receipt);need(len(raw) <= 256*1024,'source-refused')
        self.view_receipt = raw;self.view_receipt_sha256 = digest(raw)
        self.sources.original_root = root;self.sources.original_rows = rows
        self.verify_view(deadline)

    def verify_view(self, deadline):
        check(deadline,self.cancelled)
        need(self.view_root is not None and type(self.view_receipt) is bytes and
             len(self.view_receipt) <= 256*1024 and digest(self.view_receipt) == self.view_receipt_sha256,
             'source-refused')
        receipt = decode(self.view_receipt)
        need(set(receipt) == {'schema_version','purpose','selection','source_commit','run_id','run_attempt',
             'actor_contract_sha256','initial_invocation_sha256','execution_grant_sha256','view_node','parent_node',
             'directories','files','file_count','bytes'} and type(receipt['schema_version']) is int and
             receipt['schema_version'] == 1 and receipt['purpose'] == 'maintained-v2-160-copy-custody' and
             type(receipt['file_count']) is int and receipt['file_count'] == 161 and
             all(receipt[key] == self.sources.grant[key] for key in ('source_commit','run_id','run_attempt',
                 'actor_contract_sha256','initial_invocation_sha256')) and
             type(receipt['directories']) is dict and type(receipt['files']) is dict,'source-refused')
        stable = lambda row:(row[0],row[1],row[2],row[4],row[5])
        need(stable(identity(self.view_root.lstat())) == stable(self.view_node) and
             stable(identity(self.view_root.parent.lstat())) == stable(self.view_parent_node) and
             self.view_root == self.output/'maintained-view' and receipt['selection'] == self.sources.grant['baseline_view']
             and receipt['execution_grant_sha256'] == self.sources.grant_pin,'source-refused')
        expected = self.sources.original_rows
        locked = {**decode(self.sources.raw['scripts/ci/integration.lock.json'])['source_files'],
                  'scripts/ci/integration.lock.json':{'sha256':INITIAL,'mode':0o644}}
        need(type(expected) is dict and expected == locked and len(expected) == 161 and
             set(receipt['files']) == set(expected) and type(receipt['bytes']) is int and
             receipt['bytes'] == sum(len(self.sources.raw[name]) for name in expected),'source-refused')
        node_shape = lambda node:type(node) is list and len(node) == 9 and all(type(item) is int for item in node)
        need(node_shape(receipt['view_node']) and node_shape(receipt['parent_node']) and
             receipt['view_node'] == list(self.view_node) and receipt['parent_node'] == list(self.view_parent_node) and
             all(type(name) is str and node_shape(node) for name,node in receipt['directories'].items()),'source-refused')
        expected_directories = {'.'}
        for name in expected:
            parent = Path(relative(name)).parent
            while parent != Path('.'):
                expected_directories.add(parent.as_posix());parent = parent.parent
        for name in receipt['directories']:
            if name != '.':relative(name)
        need(set(receipt['directories']) == expected_directories,'source-refused')
        for row in receipt['files'].values():
            need(type(row) is dict and set(row) == {'sha256','mode','bytes','source_node','copy_node'} and
                 type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']) and
                 type(row['mode']) is int and type(row['bytes']) is int and
                 node_shape(row['source_node']) and node_shape(row['copy_node']),'source-refused')
        actual = set();directory_nodes = []
        def walk(path,depth=0):
            need(depth <= 32,'source-refused');check(deadline,self.cancelled)
            before = identity(path.lstat());need(stat.S_ISDIR(before[2]) and before[4] == os.geteuid()
                and before[0] == self.view_node[0] and stat.S_IMODE(before[2]) == 0o700,'source-refused')
            relative_directory = '.' if path == self.view_root else path.relative_to(self.view_root).as_posix()
            need(relative_directory in receipt['directories'] and stable(before) == stable(receipt['directories'][relative_directory]),
                 'source-refused')
            directory_nodes.append((path,stable(before)))
            need(len(directory_nodes) <= len(expected_directories),'source-refused')
            for name in sorted(os.listdir(path)):
                check(deadline,self.cancelled);child = path/name;node = child.lstat()
                if stat.S_ISDIR(node.st_mode):walk(child,depth+1)
                else:
                    relative_name = child.relative_to(self.view_root).as_posix()
                    need(relative_name in expected and stat.S_ISREG(node.st_mode) and node.st_nlink == 1
                         and node.st_uid == os.geteuid(),'source-refused')
                    raw,mode,current = read(child,deadline);row = receipt['files'][relative_name]
                    need(raw == self.sources.raw[relative_name] and digest(raw) == row['sha256'] and
                         len(raw) == row['bytes'] and mode == row['mode'] == expected[relative_name]['mode'] and
                         list(current) == row['copy_node'] and row['source_node'] == list(self.sources.identities[relative_name]),
                         'source-refused');actual.add(relative_name)
                    need(len(actual) <= 161,'source-refused')
        walk(self.view_root)
        need(actual == set(expected) and {'.' if path == self.view_root else path.relative_to(self.view_root).as_posix()
             for path,node in directory_nodes} == expected_directories and
             all(stable(identity(path.lstat())) == node for path,node in directory_nodes),
             'source-refused')
        self.sources.guard(deadline,self.cancelled)
        return receipt

    def original_context(self, *, deadline, controller=None):
        value = self._original_context(deadline=deadline,controller=controller)
        self.sources.source_graph(self)
        return value

    def _original_context(self, *, deadline, controller=None):
        """Actual suspended captured loader, receipt and observed native custody."""
        check(deadline,self.cancelled)
        limit = self.work_end if self.work_end is not None else self.job_deadline
        need(deadline <= limit,'source-refused');self.verify_view(deadline)
        scope = self.original_scope;entry = self.source_graph['entry']
        need(type(scope) is entry.original_modules.__globals__['_GeneratorContextManager'],'source-refused')
        generator = object.__getattribute__(scope,'gen')
        need(type(generator) is types.GeneratorType and generator.gi_frame is not None and not generator.gi_running
             and generator.gi_code is entry.original_modules.__wrapped__.__code__ and
             generator.gi_frame.f_globals is entry.__dict__,'source-refused')
        local = generator.gi_frame.f_locals
        need(local.get('entered') is True and local.get('modules') is self.source_graph['original'] and
             local.get('root') == self.view_root and local.get('lock_path') == self.view_root/'scripts/ci/integration.lock.json'
             and local.get('lock_pin') == INITIAL and local.get('deadline') == self.job_deadline
             and local.get('verification_deadline') == self.job_deadline,'source-refused')
        if controller is not None:
            observation = self.native_consumer_observation
            need(type(observation) is tuple and len(observation) == 3 and observation[2] is controller
                 and controller is self.controller,'source-refused')
            frame = observation[0];native = self.source_graph['original']['native_arm']
            run_frame = observation[1];module = self.source_graph['original']['integration']
            need(type(frame) is types.FrameType and frame.f_code is native.main.__code__ and
                 frame.f_globals is native.__dict__ and frame.f_locals.get('controller') is controller and
                 type(run_frame) is types.FrameType and run_frame.f_code is module.Controller.run.__code__ and
                 run_frame.f_globals is module.__dict__ and run_frame.f_locals.get('self') is controller,
                 'source-refused')
            active = [];current = sys._getframe()
            for _ in range(64):
                active.append(current)
                if current.f_back is None:break
                current = current.f_back
            returned = self.result['initial_exit_code']
            need(frame in active and run_frame in active if returned is None else
                 type(returned) is int and frame not in active and run_frame not in active,'source-refused')
            need(type(controller) is module.Controller and module.ROOT == self.view_root
                 and native.ROOT == self.view_root and controller.commit == self.sources.grant['source_commit']
                 and frame.f_locals.get('image') == controller.image
                 and frame.f_locals.get('integration_lock') == controller.lock,'source-refused')
        return {'root':self.view_root,'receipt':self.view_receipt,'sha256':self.view_receipt_sha256,
                'original':dict(self.source_graph['original']),'aliases':dict(self.source_graph['original_aliases'])}

    def observe_native_consumer(self, controller):
        need(self.native_consumer_observation is None,'source-refused')
        need(type(controller) is self.source_graph['original']['integration'].Controller,'source-refused')
        native = self.source_graph['original']['native_arm'];module = self.source_graph['original']['integration']
        frame = sys._getframe().f_back
        callback_code = next(code for code in self.execute.__code__.co_consts if type(code) is types.CodeType and
                             code.co_qualname == 'Session.execute.<locals>.callback')
        need(frame.f_code is callback_code and frame.f_globals is self.execute.__globals__ and
             frame.f_locals.get('self') is self and frame.f_locals.get('controller') is controller,'source-refused')
        run_frame = None
        for _ in range(64):
            if frame is None:break
            if frame.f_code is module.Controller.run.__code__ and frame.f_globals is module.__dict__:
                need(frame.f_locals.get('self') is controller,'source-refused');run_frame = frame
            if frame.f_code is native.main.__code__ and frame.f_globals is native.__dict__:
                need(frame.f_locals.get('controller') is controller and frame.f_locals.get('image') == controller.image
                     and frame.f_locals.get('accepted_commit') == self.sources.grant['source_commit']
                     and run_frame is not None,'source-refused')
                self.native_consumer_observation = (frame,run_frame,controller);self.controller = controller
                self.original_context(deadline=self.job_deadline,controller=controller);return
            frame = frame.f_back
        raise Refused('source-refused')

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
        self.phase_export_raw = encoded({'path':str(self.output/'phase-public'),
            'receipt_sha256':digest(raw),'receipt_bytes':len(raw),
            'public_files':{**outcome['public_files'],'result.json':{'sha256':digest(raw),'bytes':len(raw)}}})
        need(len(self.phase_export_raw) <= FILE_LIMIT,'restage-failed')
        self.phase_export_sha256 = digest(self.phase_export_raw)
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
        view_root = self.view_plan(argv)
        bindings(self.sources,callbacks,self.job_deadline)
        need(all(os.environ.get(env) == grant[key] for env,key in
             (('GITHUB_SHA','source_commit'),('GITHUB_RUN_ID','run_id'),('GITHUB_RUN_ATTEMPT','run_attempt'))), 'grant-refused')
        need(grant['maps']['runtime']['sha256'] != BLOCKED_RUNTIME_MAP, 'grant-refused')
        need(not self.output.exists(), 'grant-refused')
        self.output.mkdir(mode=0o700,parents=False)
        self.private = Path(tempfile.mkdtemp(prefix='handoff-',dir=self.output))
        self.private_node = identity(self.private.lstat())
        services = collector = modules = None
        cancellation_events = None
        cancellation_uncertain = None
        downstream_events = downstream_uncertainty = None
        try:
            root = self.sources.root
            entry_path = PREFIXES['runtime']+'/entry.py'
            self.startup_phase = 'load-runtime'
            entry = self.sources.module('root_handoff_entry',entry_path)
            maps = grant['maps']
            modules,_ = entry.authenticated(root/maps['runtime']['path'],maps['runtime']['sha256'],
                deadline=self.job_deadline,source_root=root/PREFIXES['runtime'])
            downstream_events = modules['launch'].CANCELLATION_EVENTS
            downstream_uncertainty = modules['launch'].CANCELLATION_UNCERTAIN
            self.startup_phase = 'load-collector'
            collector,collector_pins = entry.dependency_entry(root,PREFIXES['collector']+'/entry.py',
                grant['source_files'][PREFIXES['collector']+'/entry.py']['sha256'],maps['collector']['path'],
                maps['collector']['sha256'],deadline=self.job_deadline)
            cancellation_events = collector['common'].CANCELLATION_EVENTS
            cancellation_uncertain = collector['common'].CANCELLATION_UNCERTAIN
            self.startup_phase = 'load-phase'
            phase,_ = entry.dependency_entry(root,PREFIXES['phase']+'/entry.py',
                grant['source_files'][PREFIXES['phase']+'/entry.py']['sha256'],maps['phase']['path'],
                maps['phase']['sha256'],deadline=self.job_deadline,phase=True)
            self.startup_phase = 'copy-view'
            self.prepare_view(view_root)
            self.source_graph = {'entry':entry,'runtime':modules,'collector':collector,'phase':phase,
                                 'original':{},'original_aliases':{}}
            if self.composition == 'installer-preflight-maintained-v1':
                self.startup_phase = 'register-installer'
                self.register_native_preflight()
            if self.composition == 'repository-svg-zsh':self.register_zsh()
            self.startup_phase = 'capture-dependencies'
            self.sources.source_graph(self,capture=True)
            (self.private/'custody').mkdir(mode=0o700)
            # Registration precedes replay of TERM/INT from service construction.
            self.startup_phase = 'construct-services'
            with collector['common'].defer_cancellation():
                services = entry.services(modules,decode(self.sources.raw[maps['runtime']['path']]),
                    source_root=root/PREFIXES['runtime'],private_root=self.private/'custody',
                    job_deadline=self.job_deadline,cancelled=self.cancelled,**runtime_contract)
            # Checkpoint storage must be a distinct private0700 original-budget root.
            def callback(controller):
                self.startup_phase = 'native-hook';self.native_hook_entered = True
                try:
                    self.observe_native_consumer(controller)
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
                except BaseException as error:
                    self.startup_failed(error)
                    raise
            self.operation = 'initial-failed'
            self.startup_phase = 'load-original'
            self.original_scope = entry.original_modules(view_root,view_root/'scripts/ci/integration.lock.json',INITIAL,
                    deadline=self.job_deadline,verification_deadline=self.job_deadline)
            with self.original_scope as original:
                self.source_graph['original'] = original
                self.source_graph['original_aliases'] = {
                    'repository_projection.inventory':original['repository_projection'].inventory,
                    'desktop_projection.policy':original['desktop_projection'].policy}
                self.startup_phase = 'capture-original'
                self.sources.source_graph(self,capture=True)
                native_scope = services['pending'].interpose(original['integration'],services['transport'])
                self.native_executor_scope = native_scope
                self.native_services = services;self.native_runtime_contract = runtime_contract
                try:
                    with native_scope as executor:
                        self.native_executor = executor
                        check(self.job_deadline,self.cancelled)
                        self.startup_phase = 'call-original'
                        code = original['native_arm'].main(argv,integration_consumers=callback)
                finally:
                    self.native_executor_scope = self.native_executor = None
                    self.native_services = self.native_runtime_contract = None
                need(type(code) is int, 'initial-failed')
                self.startup_phase = 'original-returned'
                self.result['initial_exit_code'] = code
                if self.end is not None:
                    self.tick()
                    self.operation = 'authority-failed'
                    self.terminal_consumer(code,services,modules,collector,phase,callbacks)
                else:
                    raise Refused('initial-failed')
            self.tick()
            self.result['status'] = 'PASS'
        except KeyboardInterrupt as error:
            self.startup_failed(error)
            self.result.update(status='FAIL',cancelled=True,error_code=self.result['error_code'] or 'cancelled')
        except BaseException as error:
            self.startup_failed(error)
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
                    if self.view_root is not None:
                        self.original_scope = None
                        remove_private(self.view_root,self.view_node,cleanup_end)
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
                if self.startup_failure is None:
                    self.startup_phase = 'cleanup';self.startup_failed(error)
                self.result.update(status='FAIL',cleanup='FAIL')
                if isinstance(error,KeyboardInterrupt): self.result['cancelled'] = True
                if self.result['error_code'] is None: self.result['error_code'] = 'cleanup-failed'
            try:
                if modules is not None:
                    downstream_cancelled,downstream_uncertain=self.downstream_signal_disposition(
                        modules,downstream_events,downstream_uncertainty)
                    if downstream_cancelled:
                        self.result.update(status='FAIL',cancelled=True,error_code=self.result['error_code'] or 'cancelled')
                    if downstream_uncertain:
                        self.result.update(status='FAIL',cleanup='FAIL',error_code=self.result['error_code'] or 'cleanup-failed')
                if collector is not None and self.cancellation_observed(collector, cancellation_events):
                    self.result.update(status='FAIL', cancelled=True,
                                       error_code=self.result['error_code'] or 'cancelled')
                if collector is not None and self.cancellation_teardown_uncertain(collector, cancellation_uncertain):
                    self.result.update(status='FAIL', cleanup='FAIL',
                                       error_code=self.result['error_code'] or 'cleanup-failed')
            except BaseException as error:
                # Observer refusal cannot replace an earlier failure or allow PASS.
                if self.startup_failure is None:
                    self.startup_phase = 'cleanup'; self.startup_failed(error)
                self.result.update(status='FAIL', cleanup='FAIL',
                                   error_code=self.result['error_code'] or 'callback-refused')
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
                if self.startup_failure is None:
                    self.startup_phase = 'status-publication';self.startup_failed(error)
                self.result.update(status='FAIL',cancelled=self.result['cancelled'] or isinstance(error,KeyboardInterrupt),
                    error_code=self.result['error_code'] or ('cancelled' if isinstance(error,KeyboardInterrupt) else 'status-persistence-failed'))
                revoke_phase_receipt(self.output/'phase-public')
                # The first publication's close/check is part of the transaction.
                publish_status(self.output/'status',self.result,replace=True)
        if self.result['status'] == 'FAIL' and self.startup_failure is not None:
            try:self.emit_startup_refusal(cleanup_end)
            except KeyboardInterrupt:
                self.result['cancelled'] = True
                try:publish_status(self.output/'status',self.result,replace=True)
                except BaseException:
                    pass  # Optional re-publication cannot replace the first failure.
            except BaseException:
                pass  # Optional diagnostic cannot replace the retained first failure.
        return {**self.result,'public':[str(self.output/'status')]+(
            [str(self.output/'phase-public')] if self.result['status']=='PASS' else []),
            'phase_public':{'descriptor_bytes':self.phase_export_raw,'sha256':self.phase_export_sha256}
                if self.result['status']=='PASS' else None}


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
