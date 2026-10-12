#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit root-bound repository receivers; import and construction start no actor."""
import builtins
import ast
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import sysconfig
import time
import types

FILE_LIMIT = 8 * 1024**2
TOTAL_LIMIT = 64 * 1024**2
INITIAL = 'd4d603146f094c86242eaafbb887042959c510c9bb948579dd749d065dd8fc31'
POLICY = 'ff424921c5be38799f64e5c6264bb098cf71737d7be83608a4c91dee83f0365e'
LICENSE = '51a352b3e94757560538ca5866bef929de5ec4864e5893fc635f291f7a5926c7'
PHASE_MAP = '5718ca6cda60d7f6c02952cba7e92ff46666e20f8252ce7c1cdf722825ec2e43'
PHASE_GATE = 'c6d37e45f7452b5d058a8b69622a36de3d73842d5cf20c799c9631e59853be2a'
HANDOFF = 'scripts/ci/development/repository_handoff.py'
OWN = 'scripts/ci/development/repository_authority.py'
RUNTIME = 'scripts/port/repository-native-handoff'
PHASE = 'scripts/port/repository-client-phase-stage'
MANIFEST_FIELDS = frozenset(('development_only', 'selected_for_release', 'production_credentials_used',
    'files', 'source_commit', 'purpose', 'cases', 'expected_negative_cases_retained'))
BINDING_FIELDS = frozenset(('schema_version', 'purpose', 'source_commit', 'run_id', 'run_attempt',
    'execution_grant_sha256', 'actor_contract_sha256', 'integration_lock_sha256', 'policy_sha256',
    'license_sha256', 'supported_models', 'initial_invocation_sha256'))
REASONS = frozenset(('grant-refused', 'source-refused', 'context-refused', 'public-refused',
    'authority-refused', 'deadline', 'cancelled', 'persistence-failed'))


class Refused(ValueError):
    pass


def need(value, reason):
    if not value:
        raise Refused(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def decode(raw):
    need(type(raw) is bytes and 0 < len(raw) <= FILE_LIMIT, 'source-refused')
    def unique(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'source-refused'); result[key] = value
        return result
    def invalid(_):
        raise Refused('source-refused')
    value = json.loads(raw, object_pairs_hook=unique, parse_constant=invalid)
    need(type(value) is dict, 'source-refused')
    return value


def check(deadline):
    need(type(deadline) in (int, float) and math.isfinite(deadline) and time.monotonic() < deadline, 'deadline')


def relative(name):
    need(type(name) is str and len(name) <= 512 and
         re.fullmatch(r'[A-Za-z0-9_.+-]+(?:/[A-Za-z0-9_.+-]+)*', name) and
         all(part not in ('.', '..') for part in name.split('/')), 'source-refused')
    return name


def identity(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_nlink',
        'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def close_owned(fd):
    object_id = lambda info:(info.st_dev,info.st_ino,stat.S_IFMT(info.st_mode),info.st_rdev)
    before = object_id(os.fstat(fd))
    try:
        os.close(fd)
    except BaseException as error:
        try:
            still_owned = object_id(os.fstat(fd)) == before
        except OSError:
            still_owned = False
        if still_owned:
            try: os.close(fd)
            except BaseException as later:
                if not isinstance(later,Exception) and isinstance(error,Exception): raise later from error
        raise


@contextmanager
def directory(path, deadline):
    path = Path(path).absolute(); need('..' not in path.parts, 'source-refused')
    fds, chain = [], []
    original = None
    try:
        fds.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        for name in path.parts[1:]:
            check(deadline)
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1])
            before = os.fstat(child)
            chain.append((fds[-1], name, child, (before.st_dev, before.st_ino, before.st_mode, before.st_uid, before.st_gid)))
            fds.append(child)
        yield fds[-1]
        for parent, name, child, expected in chain:
            for observed in (os.fstat(child), os.stat(name, dir_fd=parent, follow_symlinks=False)):
                need((observed.st_dev, observed.st_ino, observed.st_mode, observed.st_uid, observed.st_gid) == expected, 'source-refused')
    except BaseException as error:
        original = error; raise
    finally:
        failure, control = None, None
        for fd in reversed(fds):
            try: close_owned(fd)
            except BaseException as error:
                failure = failure or error
                if not isinstance(error,Exception): control = control or error
        if control is not None and (original is None or isinstance(original,Exception)):
            raise control from (original or failure)
        if original is None and failure is not None: raise failure


def read(path, deadline, *, limit=FILE_LIMIT, private=False):
    path = Path(path).absolute()
    with directory(path.parent, deadline) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
                 'source-refused')
            if private:
                need(before.st_uid == os.geteuid() and not stat.S_IMODE(before.st_mode) & 0o022, 'source-refused')
            chunks, size = [], 0
            while True:
                check(deadline)
                block = os.read(fd, min(65536, limit+1-size))
                if not block: break
                chunks.append(block); size += len(block); need(size <= limit, 'source-refused')
            need(size == before.st_size and identity(before) == identity(os.fstat(fd)) ==
                 identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'source-refused')
            return b''.join(chunks), stat.S_IMODE(before.st_mode), identity(before)
        finally:
            active = sys.exc_info()[1]
            try: close_owned(fd)
            except BaseException as error:
                if active is None: raise
                if not isinstance(error,Exception) and isinstance(active,Exception): raise error from active


def mkdir(path, deadline):
    path = Path(path)
    with directory(path.parent, deadline) as parent:
        info = os.fstat(parent)
        need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, 'persistence-failed')
        os.mkdir(path.name, 0o700, dir_fd=parent); os.fsync(parent)


def write(path, raw, deadline, *, immutable=False, cleanup_deadline=None):
    """Fresh atomic publication; finalization failure revokes its exact named inode."""
    check(deadline); need(type(raw) is bytes and len(raw) <= FILE_LIMIT, 'persistence-failed')
    path = Path(path); temporary = '.pending-'+os.urandom(12).hex()
    published, fd, expected = None, None, None
    cleanup_deadline = deadline if cleanup_deadline is None else cleanup_deadline
    need(type(cleanup_deadline) in (int,float) and deadline <= cleanup_deadline <= deadline+60, 'deadline')
    try:
        with directory(path.parent, deadline) as parent:
            info = os.fstat(parent)
            need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, 'persistence-failed')
            try: os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError: pass
            else: raise Refused('persistence-failed')
            fd = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            opened = os.fstat(fd); expected = (opened.st_dev, opened.st_ino)
            try:
                offset = 0
                while offset < len(raw):
                    check(deadline); count = os.write(fd, raw[offset:offset+65536])
                    need(count > 0, 'persistence-failed'); offset += count
                if immutable: os.fchmod(fd, 0o400)
                os.fsync(fd); os.lseek(fd, 0, os.SEEK_SET)
                observed = bytearray()
                while len(observed) < len(raw):
                    block = os.read(fd, min(65536, len(raw)-len(observed)))
                    need(block, 'persistence-failed'); observed.extend(block)
                need(bytes(observed) == raw and identity(os.fstat(fd)) ==
                     identity(os.stat(temporary, dir_fd=parent, follow_symlinks=False)), 'persistence-failed')
                os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
                temporary = None; published = expected
                need((os.stat(path.name, dir_fd=parent, follow_symlinks=False).st_dev,
                      os.stat(path.name, dir_fd=parent, follow_symlinks=False).st_ino) == expected, 'persistence-failed')
                os.fsync(parent); check(deadline)
            finally:
                close_owned(fd); fd = None
            if temporary is not None: os.unlink(temporary, dir_fd=parent); temporary = None
    except BaseException as original:
        try:
            with directory(path.parent, cleanup_deadline) as parent:
                name = path.name if published is not None else temporary
                if name is not None and expected is not None:
                    try: info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    except FileNotFoundError: pass
                    else:
                        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                             (info.st_dev, info.st_ino) == (published or expected), 'persistence-failed')
                        os.unlink(name, dir_fd=parent); os.fsync(parent)
        except BaseException as later:
            if not isinstance(later,Exception) and isinstance(original,Exception): raise later from original
        raise
    return {'path': str(path.absolute()), 'sha256': digest(raw)}


def codes(code):
    yield code
    for value in code.co_consts:
        if isinstance(value, types.CodeType): yield from codes(value)


def constants(raw):
    result = {}
    for node in ast.parse(raw).body:
        if isinstance(node,ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0],ast.Name):
            name = node.targets[0].id
            if name.isupper():
                result[name] = eval(compile(ast.Expression(node.value),'source-constant','eval'),
                                    {'__builtins__':{},'frozenset':frozenset},result)
    return result


def defaults(function, declaration, scope):
    def value(node):
        return eval(compile(ast.Expression(node),'source-default','eval'),{'__builtins__':{}},scope)
    positional = tuple(value(node) for node in declaration.args.defaults) or None
    keyword = {name.arg:value(node) for name,node in zip(declaration.args.kwonlyargs,
                                                       declaration.args.kw_defaults) if node is not None} or None
    need(function.__defaults__ == positional and function.__kwdefaults__ == keyword, 'context-refused')


def slot_shape(value):
    cls = type(value)
    slots = ('_root','_grant_raw','_grant_pin','_actor_raw','_output','_deadline','_session',
             '_session_id','_failure','_cancelled','_public_used','_authority_used')
    need(cls is RootCallbacks and vars(cls).get('__slots__') == slots, 'context-refused')
    for name in slots:
        descriptor = vars(cls).get(name)
        need(type(descriptor) is types.MemberDescriptorType and descriptor.__objclass__ is cls and
             descriptor.__name__ == name, 'context-refused')


def state_shape(value):
    slot_shape(value)
    for name in ('_root','_output','_grant_pin'):
        need(type(getattr(value,name)) is str, 'context-refused')
    for name in ('_grant_raw','_actor_raw'):
        need(type(getattr(value,name)) is bytes, 'context-refused')
    need(type(value._deadline) in (int,float) and math.isfinite(value._deadline) and
         type(value._session_id) is int and (value._failure is None or type(value._failure) is str and value._failure in REASONS), 'context-refused')
    for name in ('_cancelled','_public_used','_authority_used'):
        need(type(getattr(value,name)) is bool, 'context-refused')


def authenticate_class(value, name, path, raw, *, registered=True):
    """Exact source class and descriptors, never __module__ labels alone."""
    cls = type(value)
    need(type(cls) is type and cls.__name__ == cls.__qualname__ == name and cls.__bases__ == (object,), 'context-refused')
    expected = {code.co_qualname:code for code in codes(compile(raw, str(path), 'exec'))}
    declarations = {node.name:node for cls_node in ast.parse(raw).body if isinstance(cls_node,ast.ClassDef)
                    and cls_node.name == name for node in cls_node.body if isinstance(node,ast.FunctionDef)}
    methods = {code.co_name:code for code in expected.values() if code.co_qualname.startswith(name+'.')
               and '.' not in code.co_qualname[len(name)+1:]}
    for key, code in methods.items():
        descriptor = vars(cls).get(key)
        function = descriptor.__func__ if isinstance(descriptor,(classmethod,staticmethod)) else descriptor
        decorators = declarations[key].decorator_list
        if decorators:
            need(len(decorators) == 1 and isinstance(decorators[0],ast.Name) and
                 decorators[0].id == 'contextmanager' and type(function) is types.FunctionType
                 and function.__code__ == contextmanager(lambda:None).__code__
                 and function.__globals__ is contextmanager.__globals__
                 and function.__code__.co_freevars == ('func',) and function.__closure__ is not None
                 and len(function.__closure__) == 1 and function.__closure__[0].cell_contents is function.__wrapped__
                 and function.__defaults__ is None and function.__kwdefaults__ is None, 'context-refused')
            function = function.__wrapped__
        need(type(function) is types.FunctionType and function.__code__ == code, 'context-refused')
        defaults(function,declarations[key],constants(raw))
    allowed = set(methods) | {'__module__','__doc__','__dict__','__weakref__','__slots__',
                            '__firstlineno__','__static_attributes__'} | set(vars(cls).get('__slots__',()))
    need(set(vars(cls)) <= allowed, 'context-refused')
    namespace = None
    for key, descriptor in vars(cls).items():
        function = descriptor.__func__ if isinstance(descriptor, (classmethod, staticmethod)) else descriptor
        if isinstance(function, types.FunctionType):
            if getattr(function,'__wrapped__',None) is not None: function = function.__wrapped__
            need(function.__qualname__ == name+'.'+key and function.__code__ == expected.get(name+'.'+key)
                 and function.__code__.co_filename == str(path) and not function.__closure__, 'context-refused')
            namespace = namespace or function.__globals__
            need(function.__globals__ is namespace and namespace.get('__file__') == str(path)
                 and namespace.get(name) is cls, 'context-refused')
    need(namespace is not None, 'context-refused')
    if registered:
        module = sys.modules.get(cls.__module__)
        need(type(module) is types.ModuleType and module.__dict__ is namespace, 'context-refused')
    for code in expected.values():
        if code.co_qualname.startswith(name+'.') and '.' not in code.co_qualname[len(name)+1:]:
            need(code.co_name in vars(cls), 'context-refused')
    return namespace


def load_module(root, name, path, row, deadline):
    raw, mode, _ = read(root/path, deadline)
    need(row == {'sha256':digest(raw), 'mode':mode}, 'source-refused')
    module = types.ModuleType(name); module.__file__ = str(root/path)
    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        need(not level and name.split('.')[0] in sys.stdlib_module_names, 'source-refused')
        standard = sysconfig.get_path('stdlib'); previous = list(sys.path)
        try:
            sys.path[:] = [standard, str(Path(standard)/'lib-dynload')]
            result = builtins.__import__(name, globals, locals, fromlist, level)
            for key in (name.split('.')[0], name):
                imported = sys.modules.get(key); origin = getattr(imported, '__file__', None)
                need(origin is None and getattr(getattr(imported, '__spec__', None), 'origin', None) in ('built-in', 'frozen')
                     or origin is not None and Path(origin).absolute().is_relative_to(standard), 'source-refused')
            return result
        finally: sys.path[:] = previous
    module.__dict__['__builtins__'] = {**vars(builtins), '__import__':importer}
    exec(compile(raw, module.__file__, 'exec'), module.__dict__)
    return module


class RootCallbacks:
    __slots__ = ('_root', '_grant_raw', '_grant_pin', '_actor_raw', '_output', '_deadline',
                 '_session', '_session_id', '_failure', '_cancelled', '_public_used', '_authority_used')

    def __setattr__(self, name, value):
        raise AttributeError('immutable root callback state')

    def __init__(self, source_root, grant_raw, grant_sha256, actor_contract_raw, output_root, *, deadline, session=None):
        slot_shape(self)
        check(deadline)
        need(type(grant_raw) is bytes and type(actor_contract_raw) is bytes and
             type(grant_sha256) is str and re.fullmatch('[0-9a-f]{64}', grant_sha256)
             and digest(grant_raw) == grant_sha256, 'grant-refused')
        values = dict(_root=str(Path(source_root).absolute()), _grant_raw=grant_raw, _grant_pin=grant_sha256,
            _actor_raw=actor_contract_raw, _output=str(Path(output_root).absolute()), _deadline=deadline,
            _session=session, _session_id=id(session), _failure=None, _cancelled=False,
            _public_used=False, _authority_used=False)
        for name, value in values.items(): object.__setattr__(self, name, value)
        self._context(deadline)

    def _context(self, deadline):
        state_shape(self)
        need(type(deadline) in (int,float) and deadline <= self._deadline, 'deadline')
        check(deadline)
        root = Path(self._root); grant = decode(self._grant_raw)
        need(digest(self._grant_raw) == self._grant_pin and id(self._session) == self._session_id, 'grant-refused')
        actor = decode(self._actor_raw)
        need(set(actor) == {'cli_sha256', 'endpoint_identity', 'env'} and
             digest(encoded(actor)) == grant.get('actor_contract_sha256'), 'grant-refused')
        for env, key in (('GITHUB_SHA','source_commit'), ('GITHUB_RUN_ID','run_id'), ('GITHUB_RUN_ATTEMPT','run_attempt')):
            need(os.environ.get(env) == grant.get(key), 'grant-refused')
        rows = grant.get('source_files'); need(type(rows) is dict and OWN in rows and HANDOFF in rows, 'grant-refused')
        handoff = load_module(root, '_repository_authority_handoff', HANDOFF, rows[HANDOFF], deadline)
        sources = handoff.preflight(root, self._grant_raw, self._grant_pin, deadline=deadline)
        need(grant['maps']['phase']['sha256'] == PHASE_MAP and
             rows[PHASE+'/gate.py']['sha256'] == PHASE_GATE, 'source-refused')
        authenticate_class(self, 'RootCallbacks', root/OWN, sources.raw[OWN])
        scope = constants(sources.raw[OWN])
        need(all(globals().get(key) == value for key,value in scope.items()), 'context-refused')
        declarations = {node.name:node for node in ast.parse(sources.raw[OWN]).body if isinstance(node,ast.FunctionDef)}
        for function in (need, digest, encoded, decode, check, relative, identity, directory, read,
                         close_owned, mkdir, write, codes, constants, defaults, slot_shape, state_shape, authenticate_class, load_module):
            sources.global_function(function)
            unwrapped = getattr(function,'__wrapped__',function)
            defaults(unwrapped,declarations[unwrapped.__name__],scope)
        for role in ('public_receiver', 'authority_provider'):
            row = grant['callbacks'][role]
            need(row == {'path':OWN,'module':type(self).__module__,'qualname':'RootCallbacks.'+role}, 'grant-refused')
            method = getattr(self, role)
            need(type(method) is types.MethodType and method.__self__ is self and
                 method.__func__ is vars(type(self))[role], 'context-refused')
        if self._session is not None:
            session = self._session
            authenticate_class(session, 'Session', root/HANDOFF, sources.raw[HANDOFF])
            authenticate_class(session.sources, 'Sources', root/HANDOFF, sources.raw[HANDOFF])
            need(session.sources.root == root and session.sources.grant == grant and
                 session.sources.grant_pin == self._grant_pin and str(session.output) == self._output
                 and session.job_deadline == self._deadline, 'context-refused')
        return grant, sources, handoff

    def handoff_binding(self):
        state_shape(self)
        grant, _, _ = self._context(self._deadline)
        return {'schema_version':1, 'purpose':'root-repository-handoff-live-binding',
            **{key:grant[key] for key in ('source_commit','run_id','run_attempt')},
            'execution_grant_sha256':self._grant_pin, 'actor_contract_sha256':grant['actor_contract_sha256'],
            'integration_lock_sha256':INITIAL, 'policy_sha256':POLICY, 'license_sha256':LICENSE,
            'supported_models':[], 'initial_invocation_sha256':grant['initial_invocation_sha256']}

    def _live(self, deadline):
        state_shape(self)
        need(self._failure is None and not self._cancelled and self._session is not None, 'context-refused')
        grant, sources, handoff = self._context(deadline)
        session = self._session
        need(session.used is True and type(session.result) is dict and
             type(session.result.get('initial_exit_code')) is int and session.result['initial_exit_code'] == 0
             and session.result.get('callback_entered') is True and session.result.get('cancelled') is False
             and session.result.get('error_code') is None and
             session.result.get('initial_invocation_sha256') == grant['initial_invocation_sha256']
             and session.result.get('execution_grant_sha256') == self._grant_pin and type(session.work_end) in (int,float)
             and type(session.end) in (int,float) and deadline <= session.work_end < session.end <= self._deadline
             and session.end-session.work_end == 60 and time.monotonic() < deadline, 'context-refused')
        controller = session.controller
        authenticate_class(controller, 'Controller', sources.root/'scripts/ci/integration.py',
                           sources.raw['scripts/ci/integration.py'], registered=False)
        need(controller.commit == grant['source_commit'] and controller.image == session.job['image_id']
             and controller.cancelled is False and controller.lock == decode(sources.raw['scripts/ci/integration.lock.json'])
            and controller.work == controller.out/'work' and controller.public == controller.out/'public'
             and controller.source == controller.work/'source' and controller.generated == controller.work/'fixtures', 'context-refused')
        need(all(session.job.get(key) == grant[key] for key in ('source_commit','recipe_source_commit','run_id','run_attempt'))
             and re.fullmatch('[0-9a-f]{32}', session.job.get('nonce','')) and
             session.pending_capture.get('identity') == {key:session.job[key] for key in ('source_commit','image_id','nonce')}, 'context-refused')
        root = session.private
        need(type(root) is type(Path('/')) and type(session.output) is type(Path('/')), 'context-refused')
        with directory(root, deadline) as fd:
            node = os.fstat(fd)
            need(node.st_uid == os.geteuid() and stat.S_IMODE(node.st_mode) == 0o700 and
                 (node.st_dev,node.st_ino) == tuple(session.private_node[:2]) and
                 root.parent == session.output and root.name.startswith('handoff-'), 'context-refused')
        return grant, sources, handoff, session

    def _modules(self, sources, deadline):
        grant, root = sources.grant, sources.root
        entry = sources.module('_repository_authority_runtime', RUNTIME+'/entry.py')
        maps = grant['maps']
        runtime, _ = entry.authenticated(root/maps['runtime']['path'], maps['runtime']['sha256'],
                                        deadline=deadline, source_root=root/RUNTIME)
        phase, _ = entry.dependency_entry(root, PHASE+'/entry.py', grant['source_files'][PHASE+'/entry.py']['sha256'],
            maps['phase']['path'], maps['phase']['sha256'], deadline=deadline, phase=True)
        return runtime, phase

    def _storage(self, session, deadline):
        root = session.private/'external-authority'
        if not root.exists(): mkdir(root, deadline)
        with directory(root, deadline) as fd:
            info = os.fstat(fd)
            need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, 'persistence-failed')
        return root

    def _latch(self, error, reason):
        slot_shape(self)
        if isinstance(error, (KeyboardInterrupt,SystemExit)):
            object.__setattr__(self, '_cancelled', True)
            if not isinstance(error.__cause__,Exception): reason = 'cancelled'
        if self._failure is None: object.__setattr__(self, '_failure', reason)

    def public_receiver(self, controller, pending_capture, *, deadline):
        slot_shape(self)
        try:
            grant, sources, _, session = self._live(deadline)
            need(not self._public_used and controller is session.controller and
                 type(pending_capture) is dict and pending_capture == session.pending_capture, 'public-refused')
            object.__setattr__(self, '_public_used', True)
            runtime, phase = self._modules(sources, deadline)
            aggregate_raw, _, _ = read(controller.out/'result.json',deadline,private=True)
            native_raw, _, _ = read(controller.native_out/'result.json',deadline,private=True)
            aggregate, native = decode(aggregate_raw), decode(native_raw)
            need(aggregate == controller.report and aggregate.get('status') == 'PASS' and
                 aggregate.get('source_commit') == session.job['source_commit'] and
                 aggregate.get('base_image') == session.job['image_id'] and aggregate.get('cancelled') is False
                 and aggregate.get('owned_image_cleanup',{}).get('status') == 'PASS'
                 and aggregate['owned_image_cleanup'].get('absence_verified') is True
                 and aggregate['owned_image_cleanup'].get('cleanup_uncertain') is False
                 and native.get('status') == 'native-builds-and-virtual-integration-pass'
                 and native.get('mode') == 'integration' and native.get('native_build') == native.get('virtual_integration') == 'PASS'
                 and native.get('integration_sha256') == INITIAL, 'public-refused')
            files = pending_capture.get('files')
            need(set(pending_capture) == {'schema_version','purpose','status','files','native_admission','identity'}
                 and type(pending_capture['schema_version']) is int and pending_capture['schema_version'] == 1
                 and pending_capture['purpose'] == 'pending-private-repository-capture'
                 and pending_capture['status'] == 'PENDING' and pending_capture['native_admission'] == 'NOT RUN', 'public-refused')
            raw, _ = self._capture(session.private/'pending', files, deadline, extras=('capture.json',))
            index_raw, _, _ = read(session.private/'pending/capture.json',deadline,private=True)
            need(decode(index_raw) == {key:value for key,value in pending_capture.items() if key != 'identity'}, 'public-refused')
            manifest = decode(raw['public/manifest.json']); repository = decode(raw['raw/result.json'])
            contract = decode(raw['raw/contract.json'])
            receipt = self._public_facts(manifest, repository, contract, raw, files, grant, session.job, phase['gate'])
            sources.guard(deadline)
            self._live(deadline)
            return write(self._storage(session,deadline)/'public-accepted.json', encoded(receipt), deadline,
                         cleanup_deadline=session.end)
        except BaseException as error:
            self._latch(error, 'public-refused'); raise

    def _capture(self, root, files, deadline, *, extras=()):
        need(type(files) is dict and 0 < len(files) <= 1024, 'authority-refused')
        self._tree(root,set(files)|set(extras),deadline)
        result, nodes, total = {}, {}, 0
        for name, row in files.items():
            relative(name)
            need(type(row) is dict and set(row) == {'sha256','bytes'} and type(row['bytes']) is int
                 and 0 <= row['bytes'] <= FILE_LIMIT and type(row['sha256']) is str
                 and re.fullmatch('[0-9a-f]{64}',row['sha256']), 'authority-refused')
            data, _, node = read(Path(root)/name, deadline, private=True)
            need(row == {'sha256':digest(data), 'bytes':len(data)}, 'authority-refused')
            total += len(data); need(total <= TOTAL_LIMIT, 'authority-refused'); result[name] = data; nodes[name] = node
        self._tree(root,set(files)|set(extras),deadline)
        for name, expected in nodes.items():
            path = Path(root)/name
            with directory(path.parent,deadline) as fd:
                need(identity(os.stat(path.name,dir_fd=fd,follow_symlinks=False)) == expected, 'authority-refused')
        return result, total

    def _tree(self, root, expected, deadline):
        seen = set()
        with directory(root,deadline) as root_fd:
            need(os.fstat(root_fd).st_uid == os.geteuid() and
                 stat.S_IMODE(os.fstat(root_fd).st_mode) == 0o700, 'authority-refused')
            def visit(fd, prefix, depth):
                check(deadline); need(depth <= 32 and len(seen) <= 1024, 'authority-refused')
                for name in os.listdir(fd):
                    relative(name); full = prefix+name
                    info = os.stat(name,dir_fd=fd,follow_symlinks=False)
                    need(info.st_uid == os.geteuid() and not stat.S_IMODE(info.st_mode) & 0o022, 'authority-refused')
                    if stat.S_ISDIR(info.st_mode):
                        child = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                        try: visit(child,full+'/',depth+1)
                        finally: os.close(child)
                    else:
                        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and full in expected, 'authority-refused')
                        seen.add(full)
            visit(root_fd,'',0)
        need(seen == expected, 'authority-refused')

    def _public_facts(self, manifest, repository, contract, raw, files, grant, job, gate):
        need(set(manifest) == MANIFEST_FIELDS and manifest['purpose'] == 'TEST-ONLY-offline-repository-case-verification'
             and manifest['source_commit'] == grant['source_commit'] and manifest['development_only'] is True
             and manifest['selected_for_release'] is False and manifest['production_credentials_used'] is False
             and manifest['expected_negative_cases_retained'] is True, 'public-refused')
        gate.case_rows(manifest['cases'])
        need(repository.get('status') == 'PASS' and repository.get('purpose') == 'disposable-generic-repository-test'
             and repository.get('source_commit') == job['source_commit'] and repository.get('cases') == manifest['cases']
             and contract.get('source_commit') == job['source_commit'] and contract.get('nonce') == job['nonce']
             and contract.get('image_id') == job['image_id'], 'public-refused')
        public = manifest['files']; need(type(public) is dict and 0 < len(public) <= 512, 'public-refused')
        expected = {'TEST-signer-A-public.asc','TEST-signer-B-public.asc','TEST-verifier-public.asc',
            'TEST-signer-A-revoked-public.asc','TEST-repository-aliases.json','TEST-repository-aliases.json.sig','TEST-pacman.conf'}
        baseline, upgrade = contract.get('baseline'), contract.get('upgrade')
        need(type(baseline) is list and type(upgrade) is list and len(baseline) == len(upgrade) == 4
             and {r.get('name') for r in baseline} == {r.get('name') for r in upgrade} == set(gate.ORIGINALS), 'public-refused')
        for label in gate.LABELS:
            rows = baseline if label == 'baseline-A' else upgrade
            packages = {Path(row['archive']).name for row in rows}
            packages.add(gate.PROBE+('-1-1-any.pkg.tar.xz' if label == 'baseline-A' else '-2-1-any.pkg.tar.xz'))
            names = packages | {name+'.sig' for name in packages} | {
                'integration.db.tar.gz','integration.db.tar.gz.sig','integration.files.tar.gz','integration.files.tar.gz.sig',
                'integration.db','integration.db.sig','integration.files','integration.files.sig'}
            if label == 'missing-package-signature-B': names.remove(gate.PROBE+'-2-1-any.pkg.tar.xz.sig')
            if label == 'missing-database-signature-B': names -= {'integration.db.tar.gz.sig','integration.db.sig'}
            expected.update('TEST-repositories/'+label+'/'+name for name in names)
            for row in rows:
                name = 'TEST-repositories/'+label+'/'+Path(row['archive']).name
                need(public.get(name,{}).get('sha256') == row.get('sha256'), 'public-refused')
        need(set(public) == expected and {name for name in raw if name.startswith('public/')} ==
             {'public/'+name for name in expected} | {'public/manifest.json'}, 'public-refused')
        for name, row in public.items():
            relative(name); data = raw['public/'+name]
            need(type(row) is dict and set(row) == {'sha256','bytes'} and type(row['bytes']) is int
                 and row == files['public/'+name] == {'sha256':digest(data),'bytes':len(data)}
                 and repository.get('evidence_sha256',{}).get(name) == row['sha256'], 'public-refused')
            need(b'PRIVATE KEY' not in data and b'PRIVATE KEY' not in name.encode(), 'public-refused')
            if name.endswith('.asc'):
                need(data.startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----') and
                     b'-----END PGP PUBLIC KEY BLOCK-----' in data, 'public-refused')
            if name.endswith('.sig'):
                need(0 < len(data) <= 8192 and data[0]&0x80 and
                     (data[0]&63 if data[0]&0x40 else (data[0]>>2)&15) == 2, 'public-refused')
        need(sum(row['bytes'] for row in public.values()) <= 12*1024**2, 'public-refused')
        need(raw['public/TEST-pacman.conf'] == gate.STRICT_CONFIG, 'public-refused')
        aliases = {'active':{'target':'updated-B','kind':'directory'}}
        alias_names = {'integration.db':'integration.db.tar.gz','integration.db.sig':'integration.db.tar.gz.sig',
                       'integration.files':'integration.files.tar.gz','integration.files.sig':'integration.files.tar.gz.sig'}
        for label in gate.LABELS:
            for alias,target in alias_names.items():
                first,second = 'TEST-repositories/'+label+'/'+alias,'TEST-repositories/'+label+'/'+target
                if first not in public: continue
                need(public[first] == public[second], 'public-refused')
                aliases[label+'/'+alias] = {'target':label+'/'+target,'kind':'file','regular_copy_sha256':public[first]['sha256']}
        need(decode(raw['public/TEST-repository-aliases.json']) == aliases, 'public-refused')
        proof = manifest['cases'][8]['rejection_contract']
        need(set(proof) == {'kind','missing','repository','reference','repository_bytes','reference_bytes'}
             and Path(proof['repository']).name == 'missing-database-signature-B'
             and Path(proof['reference']).name == 'updated-B', 'public-refused')
        for role,label in (('reference_bytes','updated-B'),('repository_bytes','missing-database-signature-B')):
            expected_rows = {}
            prefix = 'TEST-repositories/'+label+'/'
            for name,row in public.items():
                if not name.startswith(prefix): continue
                base = name[len(prefix):]; expected_rows[base] = {'sha256':row['sha256']}
                if base in alias_names: expected_rows[base]['alias'] = alias_names[base]
            need(proof[role] == expected_rows, 'public-refused')
        receipt = {'schema_version':1,'purpose':'accepted-repository-public-artifacts','status':'PASS',
            **{key:job[key] for key in ('source_commit','run_id','run_attempt','nonce','image_id')},
            'manifest_sha256':digest(raw['public/manifest.json']), 'development_only':True,
            'selected_for_release':False,'production_credentials_used':False,'native_admission':'NOT RUN'}
        need(len(encoded(receipt)) <= 4096, 'public-refused')
        return receipt

    def authority_provider(self, candidate_path, candidate_sha256, input_root, *, deadline):
        slot_shape(self)
        try:
            grant, sources, _, session = self._live(deadline)
            need(self._public_used and not self._authority_used and Path(candidate_path).absolute() ==
                 session.private/'authority-candidate.json' and Path(input_root).absolute() == session.private/'authority-inputs', 'authority-refused')
            object.__setattr__(self, '_authority_used', True)
            candidate_raw, _, _ = read(candidate_path, deadline, private=True, limit=4*1024**2)
            need(type(candidate_sha256) is str and digest(candidate_raw) == candidate_sha256, 'authority-refused')
            candidate = decode(candidate_raw)
            need(candidate.get('status') == 'PENDING' and candidate.get('crypto',{}).get('status') == 'PENDING'
                 and candidate.get('integration_lock_sha256') == INITIAL and candidate.get('archive_role') == 'baseline'
                 and all(candidate.get(key) == session.job[key] for key in ('source_commit','recipe_source_commit','run_id','nonce','image_id')), 'authority-refused')
            raw, _ = self._capture(input_root, candidate['files'], deadline)
            storage = self._storage(session,deadline); staged = storage/'verification-inputs'; mkdir(staged,deadline)
            for name, data in raw.items():
                target = staged/name
                for parent in reversed(target.parent.parents):
                    if parent.is_relative_to(staged) and not parent.exists(): mkdir(parent,deadline)
                if not target.parent.exists(): mkdir(target.parent,deadline)
                write(target,data,deadline,immutable=True,cleanup_deadline=session.end)
            provisional = decode(candidate_raw); provisional['status'] = provisional['crypto']['status'] = 'PASS'
            verification_raw = encoded(provisional); verification_pin = digest(verification_raw)
            runtime, phase = self._modules(sources,deadline)
            records = {name:decode(raw[provisional['refs'][name]]) for name in ('aggregate','public_acceptance')}
            records['native_result'] = decode(raw['terminal/native-result.json'])
            launch = decode(raw['custody/launch.json'])
            checkpoints = []
            previous = '0'*64
            for sequence in (1,2):
                parsed = runtime['producer'].parse_frame(runtime['producer'].FRAME_MARKER+raw[f'custody/checkpoint-{sequence}.json'],
                    nonce=session.job['nonce'],sequence=sequence,previous_frame_sha256=previous)
                previous = parsed['frame_sha256']
                checkpoints.append({'sequence':sequence,'phase':parsed['frame']['phase'],'sha256':previous,
                    'payload_sha256':parsed['frame']['payload_sha256'],'durable_host_digest':True})
            root = sources.root; own_row = grant['source_files'][OWN]
            supervisor = runtime['supervisor'].RoleSupervisor({'phase-accept':{
                'module':__name__,'source_file':str(root/OWN),'source_sha256':own_row['sha256']}},
                deadline=deadline, source_guard=lambda:sources.guard(deadline))
            def verify():
                runtime['broker'].validate_terminal(records,session.job,launch,checkpoints,
                                                     native_exit=session.result['initial_exit_code'])
                self._custody(raw, provisional, runtime, records, launch, checkpoints, session.job)
                return phase['gate'].accept(staged,verification_raw,verification_pin,repo_root=root)
            verified = supervisor('phase-accept',verify,deadline=min(deadline,time.monotonic()+330))
            need(type(verified) is dict and verified.get('status') == 'PASS-input-acceptance'
                 and supervisor.receipts[-1].get('status') == 'PASS' and
                 supervisor.receipts[-1].get('cleanup',{}).get('status') == 'PASS', 'authority-refused')
            sources.guard(deadline); self._live(deadline)
            return write(storage/'accepted-authority.json',verification_raw,deadline,cleanup_deadline=session.end)
        except BaseException as error:
            self._latch(error, 'authority-refused'); raise

    def _custody(self, raw, authority, runtime, records, launch, checkpoints, job):
        need(records['public_acceptance'].get('manifest_sha256') == authority['files'][authority['refs']['public_manifest']]['sha256']
             and records['native_result'].get('integration_sha256') == INITIAL, 'authority-refused')
        for sequence, checkpoint in enumerate(checkpoints,1):
            name = f'custody/checkpoint-{sequence}.json'
            need(authority['files'][name] == {'sha256':digest(raw[name]),'bytes':len(raw[name])}, 'authority-refused')
        cleanup = decode(raw[authority['refs']['cleanup']])
        need(cleanup.get('status') == 'PASS' and all(cleanup.get(key) == launch.get(key) for key in
             ('container','container_id','absence_verified','name_absence_verified','id_absence_verified')), 'authority-refused')


if __name__ == '__main__':
    sys.stdout.write('{"status":"BLOCKED","actors":"NOT RUN","error_code":"grant-refused"}\n')
    raise SystemExit(1)
