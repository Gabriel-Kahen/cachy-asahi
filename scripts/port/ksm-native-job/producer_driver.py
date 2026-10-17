#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Captured original producer; one inventory caller timer shares its phase end."""
import sys
if __name__ == '__main__' and not (sys.flags.isolated and sys.flags.dont_write_bytecode and sys.flags.no_site):
    raise SystemExit('Launch requires python -I -B -S')
import argparse
import _signal  # Trusted startup grant: reinitializing this builtin changes process-wide handler state.
import builtins
from contextlib import contextmanager
import hashlib
import importlib.machinery as machinery
import json
import math
import os
from pathlib import Path
import re
import stat
import sysconfig
import time
import types

_PATH_TYPE = type(Path('/'))
CAP = 180
SOURCES = {
    'native_arm': ('scripts/ci/native_arm.py', '077d3f8db24000dbbd7af23ba1a07757f4aeb21ff036498085618847ab5b5ce9'),
    'package_checks': ('scripts/checks/package_checks.py', 'e01eb55ee54133b60a7b73121ad8926d45769937ab058aac0868db0df60b6cd8')}
STANDARD = sysconfig.get_path('stdlib')
_GRAPHS = {}
_GUARDS = {}
LANGUAGE = types.MappingProxyType(vars(builtins).copy())
BOOTSTRAP = types.MappingProxyType({**{v.__name__: v for v in tuple(globals().values())
    if type(v) is types.ModuleType}, 'pathlib':sys.modules['pathlib'], 'contextlib':sys.modules['contextlib']})
STDLIB = frozenset(sys.stdlib_module_names)
FINDERS = (machinery.BuiltinImporter, machinery.FrozenImporter, machinery.PathFinder)
FIELDS = ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
REFUSAL_PREFIX = 'KSM_PRODUCER_REFUSAL_V1 '
REFUSAL_GATES = frozenset({'PREFLIGHT','OUTPUT_BIND','GRAPH_LOAD','WRAP','NATIVE_ENTRY','NATIVE_RETURN','CONTEXT_EXIT','UNKNOWN'})
REFUSAL_PREDICATES = frozenset({
    'producer-annotation-custody','producer-binding-missing','producer-code-custody',
    'producer-custody-bound','producer-custody-keys','producer-deadline','producer-file',
    'producer-file-bound','producer-file-drift','producer-guard-invalidated',
    'producer-image-binding','producer-image-drift','producer-inventory-cap',
    'producer-module-custody','producer-module-grant','producer-native-argv',
    'producer-output','producer-output-binding','producer-output-directory',
    'producer-output-exists','producer-output-parent-drift','producer-path',
    'producer-path-custody','producer-private-parent','producer-project-import',
    'producer-relative-project-import','producer-source-drift','producer-source-pin',
    'producer-unbound-import','producer-wrapper-custody','producer-wrapper-grant',
    'producer-wrapper-output','producer-wrapper-replay','producer-wrapper-slot','UNKNOWN'})
_REFUSAL_ISSUER = object()
_VALUE_ERROR = ValueError


def need(ok, reason, *, import_root=None):
    if not ok:
        error = ModuleNotFoundError(reason, name=import_root) if reason == 'producer-unbound-import' else ValueError(reason)
        try:
            if (type(error) is _VALUE_ERROR or type(error) is ModuleNotFoundError and reason == 'producer-unbound-import') and type(reason) is str and reason in REFUSAL_PREDICATES:
                error.__dict__.update(ksm_refusal_predicate=reason, ksm_refusal_issuer=_REFUSAL_ISSUER)
                if reason == 'producer-unbound-import' and import_root is not None:
                    root = import_root if type(import_root) is str and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', import_root) else 'UNKNOWN'
                    error.__dict__['ksm_refusal_import_root'] = root
        except Exception:
            pass
        raise error


def refusal_record(error, gate):
    """Only our exact issued error and bounded module-root fact are readable."""
    predicate = 'UNKNOWN'; root = None
    try:
        if type(error) is _VALUE_ERROR or type(error) is ModuleNotFoundError:
            state = vars(error)
            base = {'ksm_refusal_predicate', 'ksm_refusal_issuer'}
            if type(state) is dict and all(type(key) is str for key in state) and set(state) in (base, base | {'ksm_refusal_import_root'}):
                value = state.get('ksm_refusal_predicate')
                if state.get('ksm_refusal_issuer') is _REFUSAL_ISSUER and type(value) is str and value in REFUSAL_PREDICATES:
                    supplied = state.get('ksm_refusal_import_root')
                    if supplied is None and set(state) == base and type(error) is _VALUE_ERROR:
                        predicate = value
                    elif value == 'producer-unbound-import' and type(supplied) is str and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', supplied):
                        predicate, root = value, supplied
    except Exception:
        pass
    result = {'schema_version':1, 'last_source_gate':gate if type(gate) is str and gate in REFUSAL_GATES else 'UNKNOWN',
              'predicate':predicate}
    if root is not None: result['rejected_import_root'] = root
    return result


ROUTE_PREFIX = 'KSM_PRODUCER_ROUTE_V1 '


TYPEERROR_SITES = frozenset(('FORWARD_RUN_BODY', 'GRAPH_CONTEXT_BODY', 'GRAPH_DISK_GUARD_BODY', 'GRAPH_RESTORE_BODY', 'GRAPH_VERIFY_BODY', 'NATIVE_MAIN_BODY', 'NATIVE_PROBE_BODY', 'NATIVE_RUN_BODY', 'UNKNOWN'))


PROBE_STATEMENTS = frozenset(('CHECK_ENDPOINT', 'CHECK_PLATFORM', 'CHECK_UID', 'CONTEXT_ENDPOINT', 'LOCAL_ENDPOINTS', 'READ_CONTEXT', 'RECORD_ASSEMBLY', 'RECORD_CPU', 'RECORD_DOCKER_ARCH', 'RECORD_DOCKER_VERSION', 'RECORD_ENDPOINT', 'RECORD_ENVIRONMENT', 'RECORD_GID', 'RECORD_KERNEL', 'RECORD_PAGE_SIZE', 'RECORD_PYTHON', 'RECORD_SOURCE_HASH', 'RECORD_UID', 'RETURN_RECORD', 'SAVE_FINAL', 'SAVE_INITIAL', 'UNKNOWN'))
PROBE_SPANS = ((300, 4, 300, 23, 'RECORD_KERNEL'), (301, 4, 301, 145, 'RECORD_KERNEL'), (302, 45, 302, 71, 'RECORD_PAGE_SIZE'), (303, 36, 303, 104, 'RECORD_DOCKER_ARCH'), (304, 32, 304, 70, 'RECORD_DOCKER_VERSION'), (305, 21, 305, 47, 'RECORD_CPU'), (305, 59, 305, 70, 'RECORD_PYTHON'), (306, 21, 306, 32, 'RECORD_UID'), (306, 41, 306, 52, 'RECORD_GID'), (306, 69, 306, 98, 'RECORD_ENVIRONMENT'), (307, 27, 307, 54, 'RECORD_ENVIRONMENT'), (307, 73, 307, 103, 'RECORD_ENVIRONMENT'), (308, 26, 308, 51, 'RECORD_ENVIRONMENT'), (308, 67, 308, 102, 'RECORD_ENVIRONMENT'), (309, 24, 309, 52, 'RECORD_ENVIRONMENT'), (309, 64, 309, 95, 'RECORD_ENVIRONMENT'), (310, 41, 310, 60, 'RECORD_SOURCE_HASH'), (311, 30, 311, 39, 'RECORD_ASSEMBLY'), (311, 64, 311, 73, 'RECORD_ASSEMBLY'), (302, 4, 311, 74, 'RECORD_ASSEMBLY'), (312, 4, 312, 37, 'SAVE_INITIAL'), (313, 4, 314, 93, 'CHECK_PLATFORM'), (315, 4, 316, 73, 'CHECK_UID'), (317, 4, 317, 78, 'READ_CONTEXT'), (318, 4, 318, 53, 'CONTEXT_ENDPOINT'), (319, 4, 319, 70, 'LOCAL_ENDPOINTS'), (320, 4, 321, 102, 'CHECK_ENDPOINT'), (322, 4, 322, 40, 'RECORD_ENDPOINT'), (323, 4, 323, 37, 'SAVE_FINAL'), (324, 4, 324, 17, 'RETURN_RECORD'))
PROBE_LINES = {300: 'RECORD_KERNEL', 301: 'RECORD_KERNEL', 302: 'RECORD_ASSEMBLY', 303: 'RECORD_ASSEMBLY', 304: 'RECORD_ASSEMBLY', 305: 'RECORD_ASSEMBLY', 306: 'RECORD_ASSEMBLY', 307: 'RECORD_ASSEMBLY', 308: 'RECORD_ASSEMBLY', 309: 'RECORD_ASSEMBLY', 310: 'RECORD_ASSEMBLY', 311: 'RECORD_ASSEMBLY', 312: 'SAVE_INITIAL', 313: 'CHECK_PLATFORM', 314: 'CHECK_PLATFORM', 315: 'CHECK_UID', 316: 'CHECK_UID', 317: 'READ_CONTEXT', 318: 'CONTEXT_ENDPOINT', 319: 'LOCAL_ENDPOINTS', 320: 'CHECK_ENDPOINT', 321: 'CHECK_ENDPOINT', 322: 'RECORD_ENDPOINT', 323: 'SAVE_FINAL', 324: 'RETURN_RECORD'}
KERNEL_CALL_LINES = {300: 'CALL_UNAME', 301: 'CALL_KERNEL_FIELDS'}


def probe_location(trace, probe_code):
    """Closed expression-region labels from the exact held probe Source."""
    if trace.tb_frame.f_code is not probe_code:return 'UNKNOWN', None
    line = trace.tb_lineno
    if type(line) is int and line in KERNEL_CALL_LINES:
        return 'RECORD_KERNEL', KERNEL_CALL_LINES[line]
    position = None
    for offset, span in zip(range(0,len(probe_code.co_code),2),probe_code.co_positions()):
        if offset == trace.tb_lasti:
            position = span; break
    if position is None:return 'UNKNOWN', None
    if all(type(part) is int for part in position):
        first, last, column, end_column = position
        if (first,column) > (last,end_column):return 'UNKNOWN', None
        for start_line, start_column, end_line, end, label in PROBE_SPANS:
            if (start_line,start_column) <= (first,column) and (last,end_column) <= (end_line,end):
                return label, 'UNKNOWN' if label == 'RECORD_KERNEL' else None
        return 'UNKNOWN', None
    label = PROBE_LINES.get(line,'UNKNOWN')
    return label, 'UNKNOWN' if label == 'RECORD_KERNEL' else None


def probe_statement(trace, probe_code):
    """Compatibility projection of the single held-code position scan."""
    return probe_location(trace,probe_code)[0]


def typeerror_callsite(error, call_codes):
    """Finite deepest held frame and optional probe statement; never frame data."""
    if type(error) is not TypeError:return 'UNKNOWN', None, None
    found = 'UNKNOWN'; probe = None; trace = error.__traceback__
    for _ in range(64):
        if trace is None:
            if probe is None:return found, None, None
            statement, call = probe_location(*probe)
            return found, statement, call
        code = trace.tb_frame.f_code
        for held, label in call_codes:
            if code is held:
                found = label; probe = (trace,held) if label == 'NATIVE_PROBE_BODY' else None; break
        trace = trace.tb_next
    return 'UNKNOWN', None, None


def emit_route(route, gate, error=None, call_codes=()):
    """Finite failure route only; ordinary diagnostic faults cannot replace cause."""
    try:
        if route == 'native_return_nonzero':
            category = 'RETURN_NONZERO'
        else:
            category = 'UNKNOWN'
            for kind in (ImportError, TypeError, AttributeError, RuntimeError):
                if type(error) is kind:
                    category = kind.__name__
                    break
        value = {'schema_version':1, 'route':route,
                 'last_source_gate':gate if type(gate) is str and gate in REFUSAL_GATES else 'UNKNOWN',
                 'category':category}
        if route == 'driver_error' and category == 'TypeError' and gate == 'NATIVE_ENTRY':
            site, statement, call = typeerror_callsite(error,call_codes)
            value['callsite'] = site
            if site == 'NATIVE_PROBE_BODY':
                value['probe_statement'] = statement
                if statement == 'RECORD_KERNEL':value['kernel_call'] = call
        encoded = ROUTE_PREFIX + json.dumps(value, sort_keys=True, separators=(',',':')) + '\n'
        if len(encoded.encode('ascii')) <= 512:
            sys.stdout.write(encoded); sys.stdout.flush()
    except Exception:
        pass


def emit_refusal(error, gate):
    """Best-effort fixed record in existing stdout transport; never an outcome."""
    try:
        encoded = REFUSAL_PREFIX + json.dumps(refusal_record(error, gate), sort_keys=True, separators=(',',':')) + '\n'
        if len(encoded.encode('ascii')) <= 512:
            sys.stdout.write(encoded); sys.stdout.flush()
    except Exception:
        pass


def alive(end):
    need(type(end) in (int,float) and math.isfinite(end) and time.monotonic() < end, 'producer-deadline')


def absolute(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'producer-path')
    return path


def directory_fd(path):
    """Hold the final no-follow directory while recording its complete chain."""
    path=absolute(path); fds=[]; rows=[]
    try:
        fds.append(os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC))
        for part in path.parts[1:]:
            info=os.fstat(fds[-1]); rows.append((info.st_dev,info.st_ino,info.st_mode,info.st_uid))
            fds.append(os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fds[-1]))
        info=os.fstat(fds[-1]); rows.append((info.st_dev,info.st_ino,info.st_mode,info.st_uid))
        return os.dup(fds[-1]),tuple(rows)
    finally:
        for fd in reversed(fds): os.close(fd)


def directory(path):
    fd,rows=directory_fd(path)
    try: return rows
    finally: os.close(fd)


def read(path, end, modes, limit):
    alive(end); path=absolute(path); parent,parents=directory_fd(path.parent); fd=None
    try:
        fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
        before=os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==os.geteuid()
             and stat.S_IMODE(before.st_mode) in modes and 0 < before.st_size <= limit, 'producer-file')
        data=bytearray()
        while block:=os.read(fd,min(65536,limit+1-len(data))):
            alive(end); data.extend(block); need(len(data)<=limit,'producer-file-bound')
        identity=tuple(getattr(before,k) for k in FIELDS)
        need(len(data)==before.st_size and identity==tuple(getattr(os.fstat(fd),k) for k in FIELDS)
             and identity==tuple(getattr(path.lstat(),k) for k in FIELDS)
             and parents==directory(path.parent),'producer-file-drift')
        alive(end); return bytes(data),(identity,parents)
    finally:
        if fd is not None: os.close(fd)
        os.close(parent)


class SourceOnly(machinery.SourceFileLoader):
    def get_code(self, fullname):
        return self.source_to_code(self.get_data(self.path),self.path)


FILE_HOOK=machinery.FileFinder.path_hook(
    (machinery.ExtensionFileLoader,tuple(machinery.EXTENSION_SUFFIXES)),
    (SourceOnly,tuple(machinery.SOURCE_SUFFIXES)))


@contextmanager
def quarantine(end):
    """Use fixed finders/stdlib bytes, never caller cache entries or forged labels."""
    _first_cause_policy = (LANGUAGE['type'], LANGUAGE['GeneratorExit'], LANGUAGE['BaseException'], LANGUAGE['Exception'], (LANGUAGE['ValueError'], LANGUAGE['TypeError'], LANGUAGE['AttributeError'], LANGUAGE['KeyError'], LANGUAGE['IndexError'], LANGUAGE['RuntimeError'], LANGUAGE['OSError'], LANGUAGE['FileNotFoundError'], LANGUAGE['PermissionError'], LANGUAGE['NotADirectoryError'], LANGUAGE['IsADirectoryError'], LANGUAGE['UnicodeError'], LANGUAGE['UnicodeDecodeError'], LANGUAGE['UnicodeEncodeError'], LANGUAGE['UnicodeTranslateError'], LANGUAGE['ImportError'], LANGUAGE['ModuleNotFoundError']))
    paths = [STANDARD, str(Path(STANDARD) / 'lib-dynload')]
    old_modules = dict(sys.modules)
    old_path = list(sys.path)
    old_meta = list(sys.meta_path)
    old_hooks = list(sys.path_hooks)
    old_cache = dict(sys.path_importer_cache)
    operations = {k: getattr(builtins, k) for k in ('__import__', 'compile', 'exec')}

    def standard_import(name, globals=None, locals=None, fromlist=(), level=0):
        alive(end)
        root = ((globals or {}).get('__package__') or '').split('.')[0] if level else name.split('.')[0]
        need(root in STDLIB, 'producer-unbound-import', import_root=root)
        return LANGUAGE['__import__'](name, globals, locals, fromlist, level)
    _preserve_0 = False
    try:
        for key in tuple(sys.modules):
            if key.split('.')[0] in STDLIB:
                sys.modules.pop(key, None)
        sys.modules.update(BOOTSTRAP)
        sys.path[:] = paths
        sys.meta_path[:] = FINDERS
        sys.path_hooks[:] = [FILE_HOOK]
        sys.path_importer_cache.clear()
        builtins.__import__ = standard_import
        builtins.compile = LANGUAGE['compile']
        builtins.exec = LANGUAGE['exec']
        yield (standard_import, paths)
        alive(end)
    except _first_cause_policy[2] as _primary_0:
        _preserve_0 = _first_cause_policy[0](_primary_0) is not _first_cause_policy[1]
        raise
    finally:
        try:
            sys.path[:] = old_path
            sys.meta_path[:] = old_meta
            sys.path_hooks[:] = old_hooks
            sys.path_importer_cache.clear()
            sys.path_importer_cache.update(old_cache)
            for key, value in operations.items():
                setattr(builtins, key, value)
            sys.modules.clear()
            sys.modules.update(old_modules)
        except _first_cause_policy[3] as _secondary_0:
            _secondary_type_0 = _first_cause_policy[0](_secondary_0)
            if not _preserve_0 or not (_secondary_type_0 is _first_cause_policy[4][0] or _secondary_type_0 is _first_cause_policy[4][1] or _secondary_type_0 is _first_cause_policy[4][2] or (_secondary_type_0 is _first_cause_policy[4][3]) or (_secondary_type_0 is _first_cause_policy[4][4]) or (_secondary_type_0 is _first_cause_policy[4][5]) or (_secondary_type_0 is _first_cause_policy[4][6]) or (_secondary_type_0 is _first_cause_policy[4][7]) or (_secondary_type_0 is _first_cause_policy[4][8]) or (_secondary_type_0 is _first_cause_policy[4][9]) or (_secondary_type_0 is _first_cause_policy[4][10]) or (_secondary_type_0 is _first_cause_policy[4][11]) or (_secondary_type_0 is _first_cause_policy[4][12]) or (_secondary_type_0 is _first_cause_policy[4][13]) or (_secondary_type_0 is _first_cause_policy[4][14]) or (_secondary_type_0 is _first_cause_policy[4][15]) or (_secondary_type_0 is _first_cause_policy[4][16])):
                raise


class _Custody:
    """Creation-time executable/binding seal; private storage/dispatch is trusted."""
    def __init__(self, modules, guard, original, deadline):
        self.end=deadline; alive(deadline)
        self.native=modules['native_arm']; self.project=tuple(modules.values()); self.namespaces=tuple(vars(m) for m in self.project)
        self.native_namespace=vars(self.native); self.original=original; self.guard=guard
        self.wrapper=None; self.wrapper_state=None; self.records=[]; self.seen=set()
        self.names=set()
        def names(code):
            self.names.update(code.co_names)
            for constant in code.co_consts:
                if type(constant) is types.CodeType: names(constant)
        for module in modules.values():
            for value in vars(module).values():
                if type(value) is types.FunctionType: names(value.__code__)
                if type(value) is type and value.__module__.startswith('_ksm_'):
                    for member in vars(value).values():
                        if type(member) is types.FunctionType: names(member.__code__)
        object.__setattr__(guard,'_custody',self)
        for module in modules.values(): self.add(vars(module),True)
        self.add(guard,True)
        self.records=tuple(self.records)

    @staticmethod
    def token(value): return (id(type(value)),id(value))

    @staticmethod
    def path_state(value, initializing=False):
        need(type(value) is _PATH_TYPE,'producer-path-custody')
        raw=object.__getattribute__(value,'_raw_paths')
        need(type(raw) is list and len(raw)<=128 and all(type(x) is str for x in raw),'producer-path-custody')
        cached=getattr(value,'_str',None)
        if cached is None and initializing:
            cached=str(value)  # Trusted construction only, before exporting this object.
        need(type(cached) is str,'producer-path-custody')
        return (cached,tuple(_Custody.token(x) for x in raw))

    def state(self, value, kind, detail):
        t=self.token
        if kind in ('dict','sequence','set'): need(len(value)<=4096,'producer-custody-bound')
        if kind=='dict':
            need(all(type(key) is str for key in value),'producer-custody-keys')
            rows=[]
            for key,item in value.items():
                if value is self.native_namespace and key=='run' and self.wrapper is not None:
                    need(item is self.wrapper,'producer-wrapper-slot'); item=self.original
                rows.append((t(key),t(item)))
            return tuple(rows)
        if kind=='sequence': return tuple(t(x) for x in value)
        if kind=='set': return tuple(sorted(t(x) for x in value))
        if kind=='function':
            annotated,annotate=detail
            if annotated: need(getattr(value,'__annotate__',None) is annotate,'producer-annotation-custody')
            return (t(value.__code__),t(value.__globals__),t(value.__builtins__),t(value.__defaults__),
                    t(value.__kwdefaults__),t(value.__annotations__) if annotated else None,t(value.__dict__),
                    tuple((t(c),t(c.cell_contents)) for c in value.__closure__ or ()))
        if kind=='class':
            need(len(vars(value))<=4096,'producer-custody-bound')
            return (t(value.__bases__),tuple((t(k),t(v)) for k,v in vars(value).items()))
        if kind=='slots': return tuple(t(object.__getattribute__(value,k)) for k in detail)
        if kind=='binding':
            need(len(value)<=4096 and all(type(key) is str for key in value),'producer-custody-keys')
            need(all(key in value for key in detail),'producer-binding-missing')
            return tuple((key,t(value[key])) for key in detail)
        if kind=='path': return self.path_state(value)
        raise ValueError('producer-custody-kind')

    def add(self, value, deep=False, depth=0):
        alive(self.end); need(depth<=64 and len(self.seen)<=8192 and len(self.records)<=4096,'producer-custody-bound')
        if id(value) in self.seen: return
        self.seen.add(id(value)); typ=type(value); detail=None; children=[]
        if typ is dict:
            kind='dict'; saved=tuple(value.items()); children=[x for pair in saved for x in pair] if deep else []
        elif typ in (tuple,list):
            kind='sequence'; saved=tuple(value); children=list(value) if deep else []
        elif typ in (set,frozenset):
            kind='set'; saved=tuple(value); children=list(value) if deep else []
        elif typ is types.FunctionType:
            kind='function'; project=value.__module__.startswith('_ksm_')
            annotated=project or value.__globals__ is globals(); detail=(annotated,getattr(value,'__annotate__',None) if annotated else None)
            annotations=value.__annotations__ if annotated else None
            saved=(value.__code__,value.__defaults__,value.__kwdefaults__,annotations,tuple(value.__closure__ or ()),tuple(c.cell_contents for c in value.__closure__ or ()),detail,value.__dict__)
            children=[value.__defaults__,value.__kwdefaults__,annotations,value.__dict__,*(saved[-3])]
            if project: children.append(value.__builtins__)
            else:
                keys=tuple(k for k in value.__code__.co_names if k in value.__globals__)
                # Driver functions need exact referenced globals; system stdlib functions
                # bind code/globals identity, preserving legitimate runtime caches.
                if value.__globals__ is globals(): self.binding(value.__globals__,keys,depth+1)
        elif typ is type:
            kind='class'; saved=(value.__bases__,tuple(vars(value).items()))
            children=[v for v in vars(value).values() if type(v) in (types.FunctionType,staticmethod,classmethod,property)]
            if value.__module__.startswith('_ksm_'): children.extend(value.__bases__)
        elif typ in (staticmethod,classmethod):
            self.add(value.__func__,True,depth+1); return
        elif typ is property:
            for fn in (value.fget,value.fset,value.fdel):
                if fn is not None: self.add(fn,True,depth+1)
            return
        elif typ is types.ModuleType:
            if any(value is module for module in self.project):
                self.add(vars(value),True,depth+1); return
            keys=tuple(sorted(k for k in self.names if k in vars(value)))
            self.binding(vars(value),keys,depth+1)
            for key in keys:
                child=vars(value)[key]
                if type(child) in (types.FunctionType,types.ModuleType,type): self.add(child,False,depth+1)
            return
        elif typ is _PATH_TYPE:
            kind='path'; initial=self.path_state(value,initializing=True); saved=(initial[0],tuple(value._raw_paths),value._raw_paths)
        elif typ is _Guard:
            kind='slots'; detail=('_disk','_custody'); saved=tuple(object.__getattribute__(value,k) for k in detail)
            children=[value._disk]
        else: return
        self.records.append((value,typ,kind,detail,self.state(value,kind,detail),saved))
        for child in children: self.add(child,deep,depth+1)

    def binding(self, namespace, keys, depth=0):
        alive(self.end); need(depth<=64 and len(self.records)<=4096,'producer-custody-bound')
        saved=tuple((key,namespace[key]) for key in keys)
        self.records.append((namespace,dict,'binding',keys,self.state(namespace,'binding',keys),saved))
        for _,value in saved:
            if type(value) is types.FunctionType and value.__globals__ is globals(): self.add(value,True,depth+1)
            elif namespace is globals() and type(value) in (dict,list,set,tuple,frozenset,_PATH_TYPE): self.add(value,True,depth+1)

    def verify(self):
        alive(self.end); need(len(self.records)<=4096,'producer-custody-bound')
        for module,namespace in zip(self.project,self.namespaces):
            need(type(module) is types.ModuleType,'producer-module-custody')
            need(vars(module) is namespace,'producer-module-custody')
        for value,typ,kind,detail,state,_ in self.records:
            alive(self.end)
            need(type(value) is typ and self.state(value,kind,detail)==state,'producer-code-custody')
        if self.wrapper is not None:
            need(type(self.wrapper) is _Forwarder and self.wrapper.state()==self.wrapper_state,'producer-wrapper-custody')

    def install(self, output, end, parent):
        self.verify(); need(self.wrapper is None,'producer-wrapper-replay')
        wrapper=_Forwarder(self,output,end,parent)
        state=wrapper.state(); self.wrapper=wrapper; self.wrapper_state=state; self.native.run=wrapper
        self.verify(); return self.original

    def restore(self):
        # Restore original authenticated objects, never seal/adopt the caller's edits.
        for module in self.project: types.ModuleType.__setattr__(module,'__class__',types.ModuleType)
        for value,typ,kind,detail,_,saved in self.records:
            if kind in ('dict','binding'):
                if kind=='dict': value.clear()
                value.update(saved)
            elif kind=='sequence' and typ is list: value[:]=saved
            elif kind=='set' and typ is set: value.clear(); value.update(saved)
            elif kind=='function':
                code,defaults,kwdefaults,annotations,cells,contents,annotate,attributes=saved
                value.__code__=code; value.__defaults__=defaults; value.__kwdefaults__=kwdefaults; value.__dict__=attributes
                if annotate[0]:
                    value.__annotations__=annotations
                    if hasattr(value,'__annotate__'): value.__annotate__=annotate[1]
                for cell,content in zip(cells,contents): cell.cell_contents=content
            elif kind=='class':
                bases,rows=saved
                if value.__bases__ is not bases: value.__bases__=bases
                original=dict(rows)
                for key in set(vars(value))-set(original): type.__delattr__(value,key)
                for key,item in rows:
                    if key not in ('__dict__','__weakref__') and vars(value).get(key) is not item: type.__setattr__(value,key,item)
            elif kind=='slots':
                for key,item in zip(detail,saved): object.__setattr__(value,key,item)
            elif kind=='path':
                saved[2][:]=saved[1]; value._raw_paths=saved[2]
                value._str=saved[0]
        self.native.run=self.original


class _Guard:
    __slots__=('_disk','_custody')
    def __setattr__(self,key,value): raise AttributeError('read-only captured guard')
    def __init__(self,disk): object.__setattr__(self,'_disk',disk); object.__setattr__(self,'_custody',None)
    def __call__(self):
        custody=_GUARDS.get(id(self))
        if custody is not None: custody.verify()
        else: need(self._custody is None,'producer-guard-invalidated')
        self._disk()


@contextmanager
def load_graph(root, *, deadline):
    """Authenticate the complete two-module closure before any project import."""
    _first_cause_policy = (LANGUAGE['type'], LANGUAGE['GeneratorExit'], LANGUAGE['BaseException'], LANGUAGE['Exception'], (LANGUAGE['ValueError'], LANGUAGE['TypeError'], LANGUAGE['AttributeError'], LANGUAGE['KeyError'], LANGUAGE['IndexError'], LANGUAGE['RuntimeError'], LANGUAGE['OSError'], LANGUAGE['FileNotFoundError'], LANGUAGE['PermissionError'], LANGUAGE['NotADirectoryError'], LANGUAGE['IsADirectoryError'], LANGUAGE['UnicodeError'], LANGUAGE['UnicodeDecodeError'], LANGUAGE['UnicodeEncodeError'], LANGUAGE['UnicodeTranslateError'], LANGUAGE['ImportError'], LANGUAGE['ModuleNotFoundError']))
    root = absolute(root)
    captured = {}
    for name, (relative, pin) in SOURCES.items():
        raw, identity = read(root / relative, deadline, {420}, 1024 ** 2)
        need(hashlib.sha256(raw).hexdigest() == pin, 'producer-source-pin')
        captured[name] = (raw, identity)

    def disk_guard():
        for name, (relative, _) in SOURCES.items():
            raw, identity = read(root / relative, deadline, {420}, 1024 ** 2)
            need((raw, identity) == captured[name], 'producer-source-drift')
    guard = _Guard(disk_guard)
    modules = {name: types.ModuleType('_ksm_' + name) for name in SOURCES}
    _preserve_4 = False
    try:
        with quarantine(deadline) as (standard_import, paths):

            def importer(name, globals=None, locals=None, fromlist=(), level=0):
                guard()
                need(not level, 'producer-relative-project-import')
                if name == 'package_checks' and (not level):
                    need((globals or {}).get('__name__') == '_ksm_native_arm' and fromlist == ('recipe',), 'producer-project-import')
                    result = modules[name]
                else:
                    result = standard_import(name, globals, locals, fromlist, level)
                guard()
                return result
            for name in ('package_checks', 'native_arm'):
                module = modules[name]
                module.__file__ = str(root / SOURCES[name][0])
                module.__dict__['__builtins__'] = {**LANGUAGE, '__import__': importer}
                guard()
                _preserve_0 = False
                try:
                    LANGUAGE['exec'](LANGUAGE['compile'](captured[name][0], module.__file__, 'exec'), module.__dict__)
                except _first_cause_policy[2] as _primary_0:
                    _preserve_0 = _first_cause_policy[0](_primary_0) is not _first_cause_policy[1]
                    raise
                finally:
                    try:
                        sys.path[:] = paths
                    except _first_cause_policy[3] as _secondary_0:
                        _secondary_type_0 = _first_cause_policy[0](_secondary_0)
                        if not _preserve_0 or not (_secondary_type_0 is _first_cause_policy[4][0] or _secondary_type_0 is _first_cause_policy[4][1] or _secondary_type_0 is _first_cause_policy[4][2] or (_secondary_type_0 is _first_cause_policy[4][3]) or (_secondary_type_0 is _first_cause_policy[4][4]) or (_secondary_type_0 is _first_cause_policy[4][5]) or (_secondary_type_0 is _first_cause_policy[4][6]) or (_secondary_type_0 is _first_cause_policy[4][7]) or (_secondary_type_0 is _first_cause_policy[4][8]) or (_secondary_type_0 is _first_cause_policy[4][9]) or (_secondary_type_0 is _first_cause_policy[4][10]) or (_secondary_type_0 is _first_cause_policy[4][11]) or (_secondary_type_0 is _first_cause_policy[4][12]) or (_secondary_type_0 is _first_cause_policy[4][13]) or (_secondary_type_0 is _first_cause_policy[4][14]) or (_secondary_type_0 is _first_cause_policy[4][15]) or (_secondary_type_0 is _first_cause_policy[4][16])):
                            raise
                guard()
            native = modules['native_arm']
            original = native.run
            custody = _Custody(modules, guard, original, deadline)
            _GRAPHS[id(native)] = (native, guard, deadline, original, custody)
            _GUARDS[id(guard)] = custody
            _preserve_3 = False
            try:
                guard()
                yield (native, guard)
            except _first_cause_policy[2] as _primary_3:
                _preserve_3 = _first_cause_policy[0](_primary_3) is not _first_cause_policy[1]
                raise
            finally:
                try:
                    _preserve_2 = False
                    try:
                        custody.verify()
                        custody.guard._disk()
                    except _first_cause_policy[2] as _primary_2:
                        _preserve_2 = _first_cause_policy[0](_primary_2) is not _first_cause_policy[1]
                        raise
                    finally:
                        try:
                            _preserve_1 = False
                            try:
                                custody.restore()
                            except _first_cause_policy[2] as _primary_1:
                                _preserve_1 = _first_cause_policy[0](_primary_1) is not _first_cause_policy[1]
                                raise
                            finally:
                                try:
                                    _GRAPHS.pop(id(custody.native), None)
                                    _GUARDS.pop(id(custody.guard), None)
                                except _first_cause_policy[3] as _secondary_1:
                                    _secondary_type_1 = _first_cause_policy[0](_secondary_1)
                                    if not _preserve_1 or not (_secondary_type_1 is _first_cause_policy[4][0] or _secondary_type_1 is _first_cause_policy[4][1] or _secondary_type_1 is _first_cause_policy[4][2] or (_secondary_type_1 is _first_cause_policy[4][3]) or (_secondary_type_1 is _first_cause_policy[4][4]) or (_secondary_type_1 is _first_cause_policy[4][5]) or (_secondary_type_1 is _first_cause_policy[4][6]) or (_secondary_type_1 is _first_cause_policy[4][7]) or (_secondary_type_1 is _first_cause_policy[4][8]) or (_secondary_type_1 is _first_cause_policy[4][9]) or (_secondary_type_1 is _first_cause_policy[4][10]) or (_secondary_type_1 is _first_cause_policy[4][11]) or (_secondary_type_1 is _first_cause_policy[4][12]) or (_secondary_type_1 is _first_cause_policy[4][13]) or (_secondary_type_1 is _first_cause_policy[4][14]) or (_secondary_type_1 is _first_cause_policy[4][15]) or (_secondary_type_1 is _first_cause_policy[4][16])):
                                        raise
                        except _first_cause_policy[3] as _secondary_2:
                            _secondary_type_2 = _first_cause_policy[0](_secondary_2)
                            if not _preserve_2 or not (_secondary_type_2 is _first_cause_policy[4][0] or _secondary_type_2 is _first_cause_policy[4][1] or _secondary_type_2 is _first_cause_policy[4][2] or (_secondary_type_2 is _first_cause_policy[4][3]) or (_secondary_type_2 is _first_cause_policy[4][4]) or (_secondary_type_2 is _first_cause_policy[4][5]) or (_secondary_type_2 is _first_cause_policy[4][6]) or (_secondary_type_2 is _first_cause_policy[4][7]) or (_secondary_type_2 is _first_cause_policy[4][8]) or (_secondary_type_2 is _first_cause_policy[4][9]) or (_secondary_type_2 is _first_cause_policy[4][10]) or (_secondary_type_2 is _first_cause_policy[4][11]) or (_secondary_type_2 is _first_cause_policy[4][12]) or (_secondary_type_2 is _first_cause_policy[4][13]) or (_secondary_type_2 is _first_cause_policy[4][14]) or (_secondary_type_2 is _first_cause_policy[4][15]) or (_secondary_type_2 is _first_cause_policy[4][16])):
                                raise
                except _first_cause_policy[3] as _secondary_3:
                    _secondary_type_3 = _first_cause_policy[0](_secondary_3)
                    if not _preserve_3 or not (_secondary_type_3 is _first_cause_policy[4][0] or _secondary_type_3 is _first_cause_policy[4][1] or _secondary_type_3 is _first_cause_policy[4][2] or (_secondary_type_3 is _first_cause_policy[4][3]) or (_secondary_type_3 is _first_cause_policy[4][4]) or (_secondary_type_3 is _first_cause_policy[4][5]) or (_secondary_type_3 is _first_cause_policy[4][6]) or (_secondary_type_3 is _first_cause_policy[4][7]) or (_secondary_type_3 is _first_cause_policy[4][8]) or (_secondary_type_3 is _first_cause_policy[4][9]) or (_secondary_type_3 is _first_cause_policy[4][10]) or (_secondary_type_3 is _first_cause_policy[4][11]) or (_secondary_type_3 is _first_cause_policy[4][12]) or (_secondary_type_3 is _first_cause_policy[4][13]) or (_secondary_type_3 is _first_cause_policy[4][14]) or (_secondary_type_3 is _first_cause_policy[4][15]) or (_secondary_type_3 is _first_cause_policy[4][16])):
                        raise
    except _first_cause_policy[2] as _primary_4:
        _preserve_4 = _first_cause_policy[0](_primary_4) is not _first_cause_policy[1]
        raise
    finally:
        try:
            disk_guard()
        except _first_cause_policy[3] as _secondary_4:
            _secondary_type_4 = _first_cause_policy[0](_secondary_4)
            if not _preserve_4 or not (_secondary_type_4 is _first_cause_policy[4][0] or _secondary_type_4 is _first_cause_policy[4][1] or _secondary_type_4 is _first_cause_policy[4][2] or (_secondary_type_4 is _first_cause_policy[4][3]) or (_secondary_type_4 is _first_cause_policy[4][4]) or (_secondary_type_4 is _first_cause_policy[4][5]) or (_secondary_type_4 is _first_cause_policy[4][6]) or (_secondary_type_4 is _first_cause_policy[4][7]) or (_secondary_type_4 is _first_cause_policy[4][8]) or (_secondary_type_4 is _first_cause_policy[4][9]) or (_secondary_type_4 is _first_cause_policy[4][10]) or (_secondary_type_4 is _first_cause_policy[4][11]) or (_secondary_type_4 is _first_cause_policy[4][12]) or (_secondary_type_4 is _first_cause_policy[4][13]) or (_secondary_type_4 is _first_cause_policy[4][14]) or (_secondary_type_4 is _first_cause_policy[4][15]) or (_secondary_type_4 is _first_cause_policy[4][16])):
                raise


def bind_output(root, output):
    root,output=absolute(root),absolute(output)
    need(output!=root and not output.is_relative_to(root),'producer-output')
    parent=directory(output.parent)
    info=output.parent.lstat()
    need(info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o700,'producer-private-parent')
    # Original native.main creates this directory; the driver must leave it absent.
    need(not output.exists() and not output.is_symlink(),'producer-output-exists')
    return parent


class _Forwarder:
    __slots__=('_native','_original','_guard','_output','_end','_parent')
    def __init__(self,custody,output,end,parent):
        for key,value in zip(self.__slots__,(custody.native,custody.original,custody.guard,output,end,parent)):
            object.__setattr__(self,key,value)
        _Custody.path_state(self._output,initializing=True)
    def __setattr__(self,key,value): raise AttributeError('read-only captured wrapper')
    def state(self):
        need(type(self._output) is _PATH_TYPE,'producer-wrapper-output')
        return (tuple(_Custody.token(object.__getattribute__(self,k)) for k in self.__slots__),
                _Custody.path_state(self._output))
    def __call__(self, command, log=None, timeout=1800):
        grant = _GRAPHS.get(id(self._native))
        need(grant is not None and grant[4].wrapper is self, 'producer-wrapper-grant')
        grant[4].verify()
        guard = self._guard
        deadline = self._end
        output = self._output
        parent_identity = self._parent
        original = self._original
        guard()
        alive(deadline)
        _first_cause_policy = (LANGUAGE['type'], LANGUAGE['GeneratorExit'], LANGUAGE['BaseException'], LANGUAGE['Exception'], (LANGUAGE['ValueError'], LANGUAGE['TypeError'], LANGUAGE['AttributeError'], LANGUAGE['KeyError'], LANGUAGE['IndexError'], LANGUAGE['RuntimeError'], LANGUAGE['OSError'], LANGUAGE['FileNotFoundError'], LANGUAGE['PermissionError'], LANGUAGE['NotADirectoryError'], LANGUAGE['IsADirectoryError'], LANGUAGE['UnicodeError'], LANGUAGE['UnicodeDecodeError'], LANGUAGE['UnicodeEncodeError'], LANGUAGE['UnicodeTranslateError'], LANGUAGE['ImportError'], LANGUAGE['ModuleNotFoundError']))
        selected = timeout
        if type(command) is list and len(command) == 11 and (log is None) and (type(timeout) is int) and (timeout == 60) and (type(command[9]) is str) and re.fullmatch('sha256:[0-9a-f]{64}', command[9]):
            expected = ['docker', 'run', '--rm', '--pull=never', '--network=none', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only', '--entrypoint=/bin/cat', command[9], '/builder-packages.lock']
            if command == expected:
                need(directory(output.parent) == parent_identity, 'producer-output-parent-drift')
                info = output.lstat()
                need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and (not info.st_mode & 18), 'producer-output-directory')
                raw, image_identity = read(output / 'image-id', deadline, {384, 420}, 128)
                need(raw.decode('ascii').strip() == command[9], 'producer-image-binding')
                selected = min(CAP, deadline - time.monotonic())
                need(selected > 0, 'producer-deadline')
                _preserve_0 = False
                try:
                    return original(command, log, selected)
                except _first_cause_policy[2] as _primary_0:
                    _preserve_0 = _first_cause_policy[0](_primary_0) is not _first_cause_policy[1]
                    raise
                finally:
                    try:
                        observed, current = read(output / 'image-id', deadline, {384, 420}, 128)
                        need((observed, current) == (raw, image_identity), 'producer-image-drift')
                        guard()
                    except _first_cause_policy[3] as _secondary_0:
                        _secondary_type_0 = _first_cause_policy[0](_secondary_0)
                        if not _preserve_0 or not (_secondary_type_0 is _first_cause_policy[4][0] or _secondary_type_0 is _first_cause_policy[4][1] or _secondary_type_0 is _first_cause_policy[4][2] or (_secondary_type_0 is _first_cause_policy[4][3]) or (_secondary_type_0 is _first_cause_policy[4][4]) or (_secondary_type_0 is _first_cause_policy[4][5]) or (_secondary_type_0 is _first_cause_policy[4][6]) or (_secondary_type_0 is _first_cause_policy[4][7]) or (_secondary_type_0 is _first_cause_policy[4][8]) or (_secondary_type_0 is _first_cause_policy[4][9]) or (_secondary_type_0 is _first_cause_policy[4][10]) or (_secondary_type_0 is _first_cause_policy[4][11]) or (_secondary_type_0 is _first_cause_policy[4][12]) or (_secondary_type_0 is _first_cause_policy[4][13]) or (_secondary_type_0 is _first_cause_policy[4][14]) or (_secondary_type_0 is _first_cause_policy[4][15]) or (_secondary_type_0 is _first_cause_policy[4][16])):
                            raise
        _preserve_1 = False
        try:
            return original(command, log, selected)
        except _first_cause_policy[2] as _primary_1:
            _preserve_1 = _first_cause_policy[0](_primary_1) is not _first_cause_policy[1]
            raise
        finally:
            try:
                guard()
            except _first_cause_policy[3] as _secondary_1:
                _secondary_type_1 = _first_cause_policy[0](_secondary_1)
                if not _preserve_1 or not (_secondary_type_1 is _first_cause_policy[4][0] or _secondary_type_1 is _first_cause_policy[4][1] or _secondary_type_1 is _first_cause_policy[4][2] or (_secondary_type_1 is _first_cause_policy[4][3]) or (_secondary_type_1 is _first_cause_policy[4][4]) or (_secondary_type_1 is _first_cause_policy[4][5]) or (_secondary_type_1 is _first_cause_policy[4][6]) or (_secondary_type_1 is _first_cause_policy[4][7]) or (_secondary_type_1 is _first_cause_policy[4][8]) or (_secondary_type_1 is _first_cause_policy[4][9]) or (_secondary_type_1 is _first_cause_policy[4][10]) or (_secondary_type_1 is _first_cause_policy[4][11]) or (_secondary_type_1 is _first_cause_policy[4][12]) or (_secondary_type_1 is _first_cause_policy[4][13]) or (_secondary_type_1 is _first_cause_policy[4][14]) or (_secondary_type_1 is _first_cause_policy[4][15]) or (_secondary_type_1 is _first_cause_policy[4][16])):
                    raise


def wrap_run(native, output, *, deadline, guard, parent_identity):
    grant=_GRAPHS.get(id(native))
    need(grant is not None and grant[0] is native and grant[1] is guard and grant[2] is deadline,
         'producer-module-grant')
    grant[4].verify(); guard()
    return grant[4].install(absolute(output),deadline,parent_identity)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--producer-end',type=float,required=True)
    parser.add_argument('--producer-output',type=Path,required=True)
    parser.add_argument('--inventory-seconds',type=int,required=True)
    argv=list(sys.argv[1:] if argv is None else argv)
    gate='PREFLIGHT'; call_codes = ()
    try:
        need(argv.count('--')==1,'producer-native-argv')
        split=argv.index('--'); native=argv[:split]; args=parser.parse_args(argv[split+1:])
        alive(args.producer_end); need(args.inventory_seconds==CAP,'producer-inventory-cap')
        need(native and native[0]=='build' and native.count('--output')==1
             and not any(x.startswith('--output=') for x in native),'producer-native-argv')
        i=native.index('--output'); need(i+1<len(native) and native[i+1]==str(args.producer_output),'producer-output-binding')
        root=Path(__file__).absolute().parents[3]
        gate='OUTPUT_BIND'
        parent=bind_output(root,args.producer_output)
        gate='GRAPH_LOAD'
        with load_graph(root,deadline=args.producer_end) as (module,guard):
            gate='WRAP'
            original=wrap_run(module,args.producer_output,deadline=args.producer_end,guard=guard,parent_identity=parent)
            grant=_GRAPHS[id(module)]
            grant[4].verify(); guard()
            call_codes = ((module.main.__code__,'NATIVE_MAIN_BODY'),(module.probe.__code__,'NATIVE_PROBE_BODY'),
                (original.__code__,'NATIVE_RUN_BODY'),(_Forwarder.__call__.__code__,'FORWARD_RUN_BODY'),
                (_Custody.verify.__code__,'GRAPH_VERIFY_BODY'),(_Custody.restore.__code__,'GRAPH_RESTORE_BODY'),
                (guard._disk.__code__,'GRAPH_DISK_GUARD_BODY'),(load_graph.__wrapped__.__code__,'GRAPH_CONTEXT_BODY'))
            gate='NATIVE_ENTRY'
            result=module.main(native)
            gate='NATIVE_RETURN'
            gate='CONTEXT_EXIT'
        if type(result) is int and result == 1:
            emit_route('native_return_nonzero', gate)
        return result
    except (ValueError,OSError,UnicodeError,ModuleNotFoundError) as error:
        emit_refusal(error,gate)
        sys.stderr.write('scoped original producer driver refused\n')
        return 125
    except Exception as error:
        emit_route('driver_error', gate, error, call_codes)
        raise


if __name__=='__main__':
    raise SystemExit(main())
