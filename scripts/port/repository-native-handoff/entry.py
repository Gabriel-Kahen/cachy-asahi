#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source authentication first. CLI performs preflight only; actors are injected."""
import sys
if __name__ == '__main__' and (not sys.flags.isolated or not sys.flags.dont_write_bytecode or not sys.flags.no_site):
    raise SystemExit('Launch requires python -I -B -S')
import argparse
import ast
import builtins
from contextlib import contextmanager
import hashlib
import importlib.machinery as machinery
import json
import math
import os
from pathlib import Path
import stat
import sysconfig
import time
import types

MODULES = ('capture', 'producer', 'launch', 'transport', 'supervisor', 'broker')
SOURCES = {name + '.py' for name in (*MODULES, 'entry')}
ORIGINAL = {'package_checks': 'scripts/checks/package_checks.py', **{
    name: 'scripts/ci/' + name + '.py' for name in ('native_arm', 'integration_export',
    'lifecycle_inventory', 'repository_projection', 'desktop_projection', 'commit_image', 'sign_fixture', 'integration')}}
COLLECTOR = ('common', 'base', 'provenance', 'crypto', 'orchestrator')
PHASE = ('dependencies', 'phases', 'gate', 'adapter')
COLLECTOR_ROOT = 'scripts/port/repository-client-native'
PHASE_ROOT = 'scripts/port/repository-client-phase-stage'
PREDECESSORS = ('scripts/port/repository-client-stage/gate.py',
                'scripts/port/repository-client-stage/adapter.py',
                'scripts/release/release.py', 'scripts/client/client.py')
# Trust the authenticated launcher's explicit stdlib bootstrap objects, never
# arbitrary caller cache entries or plausible __file__/spec labels.
BOOTSTRAP = types.MappingProxyType({**{value.__name__: value for value in tuple(globals().values())
    if type(value) is types.ModuleType}, 'pathlib': sys.modules['pathlib'],
    'contextlib': sys.modules['contextlib']})
LANGUAGE = types.MappingProxyType(vars(builtins).copy())
FINDERS = (machinery.BuiltinImporter, machinery.FrozenImporter, machinery.PathFinder)
FILE_HOOK = machinery.FileFinder.path_hook(
    (machinery.ExtensionFileLoader, machinery.EXTENSION_SUFFIXES),
    (machinery.SourceFileLoader, machinery.SOURCE_SUFFIXES))


def check(deadline):
    if type(deadline) not in (int, float) or not math.isfinite(deadline) or time.monotonic() >= deadline:
        raise ValueError('source-deadline')


def read(path, limit=1024**2, *, deadline=None, with_identity=False):
    """Small bootstrap reader; authenticate capture.py before using its APIs."""
    path = Path(path).absolute()
    if deadline is not None:
        check(deadline)
    if '..' in path.parts:
        raise ValueError('source-path')
    fds, snapshots, fd = [], [], None
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    try:
        fds.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        current = Path('/')
        snapshots.append((current, os.fstat(fds[-1])))
        for part in path.parts[1:-1]:
            if deadline is not None: check(deadline)
            fds.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[-1]))
            current /= part; snapshots.append((current, os.fstat(fds[-1])))
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fds[-1])
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 <= before.st_size <= limit:
            raise ValueError('source-type-bound')
        chunks, size = [], 0
        while block := os.read(fd, min(65536, limit + 1 - size)):
            if deadline is not None: check(deadline)
            chunks.append(block); size += len(block)
            if size > limit:
                raise ValueError('source-bound')
        if size != before.st_size or any(getattr(before, key) != getattr(os.fstat(fd), key)
                or getattr(before, key) != getattr(path.lstat(), key) for key in fields):
            raise ValueError('source-drift')
        for ancestor, old in snapshots:
            new = ancestor.lstat()
            if (new.st_dev, new.st_ino, new.st_mode) != (old.st_dev, old.st_ino, old.st_mode):
                raise ValueError('source-ancestor-drift')
        if deadline is not None: check(deadline)
        result = (b''.join(chunks), stat.S_IMODE(before.st_mode))
        return (*result, tuple(getattr(before, key) for key in fields)) if with_identity else result
    finally:
        if fd is not None:
            os.close(fd)
        for item in reversed(fds):
            os.close(item)


def obj(raw):
    def pairs(rows):
        result = {}
        for name, value in rows:
            if name in result:
                raise ValueError('source-duplicate')
            result[name] = value
        return result
    def invalid(_):
        raise ValueError('source-number')
    result = json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    if type(result) is not dict:
        raise ValueError('source-object')
    return result


def pinned(path, pin, *, deadline):
    raw, _ = read(path, deadline=deadline)
    if hashlib.sha256(raw).hexdigest() != pin:
        raise ValueError('external-source-pin')
    return raw


def captures(root, rows, *, deadline, count=None, identities=None):
    check(deadline)
    if type(rows) is not dict or count is not None and len(rows) != count:
        raise ValueError('source-closure')
    result, total = {}, 0
    for name, row in rows.items():
        check(deadline)
        if type(name) is not str or Path(name).is_absolute() or any(part in ('', '.', '..') for part in name.split('/')):
            raise ValueError('source-relative')
        if type(row) is not dict or set(row) != {'sha256', 'mode'} or type(row['mode']) is not int or row['mode'] not in (0o644, 0o755):
            raise ValueError('source-row')
        raw, mode, observed = read(Path(root) / name, deadline=deadline, with_identity=True)
        total += len(raw)
        if total > 64 * 1024**2 or mode != row['mode'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
            raise ValueError('source-bytes-mode')
        result[name] = raw
        if identities is not None:
            identities[name] = observed
    return result


def stdlib_importer(modules):
    """Captured project imports only; normal imports search the isolated stdlib."""
    paths = [sysconfig.get_path('stdlib'), str(Path(sysconfig.get_path('stdlib')) / 'lib-dynload')]
    def importer(name, globals=None, locals=None, fromlist=(), level=0):
        if level:
            raise ValueError('relative-runtime-import')
        if name in modules:
            return modules[name]
        if name.split('.')[0] not in sys.stdlib_module_names:
            raise ValueError('unbound-runtime-import')
        before = list(sys.path)
        try:
            sys.path[:] = paths
            module = builtins.__import__(name, globals, locals, fromlist, level)
            for key in (name.split('.')[0], name):
                candidate = sys.modules.get(key)
                origin = getattr(candidate, '__file__', None)
                spec = getattr(candidate, '__spec__', None)
                if not origin and getattr(spec, 'origin', None) not in ('built-in', 'frozen'):
                    raise ValueError('stdlib-origin')
                if origin and not Path(origin).absolute().is_relative_to(paths[0]):
                    raise ValueError('stdlib-origin')
            return module
        finally:
            sys.path[:] = before
    return importer


def compile_modules(root, raw_sources, ordered, *, deadline):
    modules = {name: types.ModuleType(name) for name, _ in ordered}
    importer = stdlib_importer(modules)
    for name, relative in ordered:
        check(deadline)
        module = modules[name]
        module.__file__ = str(Path(root) / relative)
        module.__dict__['__builtins__'] = {**vars(builtins), '__import__': importer}
        exec(compile(raw_sources[relative], module.__file__, 'exec'), module.__dict__)
        check(deadline)
    return modules


def authenticated(map_path, pin, *, deadline, source_root=None):
    root = Path(source_root or Path(__file__).absolute().parent)
    rows = obj(pinned(map_path, pin, deadline=deadline))
    if set(rows) != SOURCES:
        raise ValueError('exact-handoff-closure')
    data = captures(root, rows, deadline=deadline)
    modules = compile_modules(root, data, [(name, name + '.py') for name in MODULES], deadline=deadline)
    return modules, rows


@contextmanager
def original_modules(root, lock_path, lock_pin, *, deadline, verification_deadline, source_overlay=None):
    lock = obj(pinned(lock_path, lock_pin, deadline=deadline))
    rows = dict(lock['source_files'])
    if source_overlay is not None:
        if type(source_overlay) is not dict or set(source_overlay) != {'scripts/ci/native_arm.py','scripts/ci/integration.py'}:
            raise ValueError('P0-source-overlay')
        for name,row in source_overlay.items():
            if type(row) is not dict or set(row) != {'sha256','mode'} or row['mode'] != 0o644 or type(row['sha256']) is not str or len(row['sha256']) != 64 or any(c not in '0123456789abcdef' for c in row['sha256']):
                raise ValueError('P0-source-overlay')
        rows.update(source_overlay)
    identities = {}
    data = captures(root, rows, count=159, deadline=deadline, identities=identities)
    if not set(ORIGINAL.values()) <= set(data):
        raise ValueError('original-module-closure')
    before, paths = {name: sys.modules.get(name) for name in ORIGINAL}, list(sys.path)
    entered = False
    try:
        modules = compile_modules(root, data, list(ORIGINAL.items()), deadline=deadline)
        sys.modules.update(modules)
        entered = True
        yield modules
    finally:
        try:
            if entered:
                for name, raw in data.items():
                    observed, mode, current = read(Path(root) / name, deadline=verification_deadline, with_identity=True)
                    if observed != raw or mode != rows[name]['mode'] or current != identities[name]:
                        raise ValueError('original-source-drift')
        finally:
            sys.path[:] = paths
            for name, old in before.items():
                if old is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = old


def literals(raw, names):
    """Read frozen dependency declarations without executing project code."""
    values = {}
    for node in LANGUAGE['compile'](raw, '<frozen-dependency-declarations>', 'exec', ast.PyCF_ONLY_AST).body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in names:
                    if target.id in values:
                        raise ValueError('dependency-declaration')
                    values[target.id] = ast.literal_eval(node.value)
    if set(values) != set(names):
        raise ValueError('dependency-declaration')
    return values


def dependency_entry(root, path, pin, map_path, map_pin, *, deadline, phase=False):
    """Authenticate the full frozen graph first; execute captured strings only."""
    check(deadline)
    root = Path(root).absolute()
    prefix = PHASE_ROOT if phase else COLLECTOR_ROOT
    if type(phase) is not bool or path != prefix + '/entry.py' or map_path != prefix + '/source-map.json':
        raise ValueError('dependency-path')
    data, rows, identities = {}, {}, {}
    def capture(name, expected):
        raw, mode, identity = read(root / name, deadline=deadline, with_identity=True)
        if mode != expected['mode'] or hashlib.sha256(raw).hexdigest() != expected['sha256']:
            raise ValueError('dependency-source')
        data[name], rows[name], identities[name] = raw, expected, identity
        return raw
    def mapped(prefix, expected_pin, names):
        raw = capture(prefix + '/source-map.json', {'sha256': expected_pin, 'mode': 0o644})
        manifest = obj(raw)
        if set(manifest) != {name + '.py' for name in names}:
            raise ValueError('dependency-closure')
        # Validate the complete row contract before any project execution.
        relative_rows = {prefix + '/' + name: row for name, row in manifest.items()}
        observed = {}
        captured = captures(root, relative_rows, deadline=deadline, count=len(names), identities=observed)
        data.update(captured); rows.update(relative_rows); identities.update(observed)
        return manifest
    selected = mapped(prefix, map_pin, (*PHASE, 'entry') if phase else (*COLLECTOR, 'entry', 'worker'))
    if selected['entry.py']['sha256'] != pin:
        raise ValueError('external-source-pin')
    if phase:
        declared = literals(data[PHASE_ROOT + '/dependencies.py'],
                            ('COLLECTOR', 'COLLECTOR_MAP_SHA256', 'PREDECESSORS'))
        collector_rows = mapped(COLLECTOR_ROOT, declared['COLLECTOR_MAP_SHA256'], (*COLLECTOR, 'entry', 'worker'))
        if declared['COLLECTOR'] != {name: row['sha256'] for name, row in collector_rows.items()} or any(
                row['mode'] != 0o644 for row in collector_rows.values()):
            raise ValueError('dependency-collector-declaration')
    else:
        collector_rows = selected
    held = literals(data[COLLECTOR_ROOT + '/orchestrator.py'], ('HELD', 'DEPENDENCIES'))
    predecessor_rows = {'scripts/port/repository-client-stage/' + name: pin for name, pin in held['HELD'].items()}
    predecessor_rows.update(held['DEPENDENCIES'])
    if set(predecessor_rows) != set(PREDECESSORS) or phase and declared['PREDECESSORS'] != predecessor_rows:
        raise ValueError('dependency-predecessor-declaration')
    for name, expected in predecessor_rows.items():
        capture(name, {'sha256': expected, 'mode': 0o755 if name == 'scripts/release/release.py' else 0o644})

    def guard():
        for name, raw in data.items():
            current, mode, identity = read(root / name, deadline=deadline, with_identity=True)
            if current != raw or mode != rows[name]['mode'] or identity != identities[name]:
                raise ValueError('dependency-source-drift')
    guard()
    trusted = dict(BOOTSTRAP)
    standard = sysconfig.get_path('stdlib')
    paths = [standard, str(Path(standard) / 'lib-dynload')]
    def standard_import(name, globals=None, locals=None, fromlist=(), level=0):
        check(deadline)
        if level or name.split('.')[0] not in sys.stdlib_module_names:
            raise ValueError('unbound-runtime-import')
        old_paths = list(sys.path)
        old_meta, old_hooks, old_cache = list(sys.meta_path), list(sys.path_hooks), dict(sys.path_importer_cache)
        operations = {key: getattr(builtins, key) for key in ('__import__', 'compile', 'exec')}
        previous = {key: value for key, value in sys.modules.copy().items()
                    if key.split('.')[0] in sys.stdlib_module_names}
        try:
            # Quarantine ungranted transitive caches, including forged labels.
            for key in previous:
                sys.modules.pop(key, None)
            sys.modules.update(trusted)
            sys.path[:] = paths
            sys.meta_path[:] = FINDERS
            sys.path_hooks[:] = [FILE_HOOK]
            sys.path_importer_cache.clear()
            for key in operations:
                setattr(builtins, key, LANGUAGE[key])
            result = LANGUAGE['__import__'](name, globals, locals, fromlist, level)
            for key, value in sys.modules.copy().items():
                if key.split('.')[0] in sys.stdlib_module_names:
                    if key not in trusted:
                        origin = getattr(value, '__file__', None)
                        if origin and not Path(origin).absolute().is_relative_to(standard):
                            raise ValueError('stdlib-origin')
                        if not origin and getattr(getattr(value, '__spec__', None), 'origin', None) not in ('built-in', 'frozen'):
                            raise ValueError('stdlib-origin')
                    trusted[key] = value
            check(deadline)
            return result
        finally:
            sys.path[:] = old_paths
            sys.meta_path[:] = old_meta
            sys.path_hooks[:] = old_hooks
            sys.path_importer_cache.clear(); sys.path_importer_cache.update(old_cache)
            for key, value in operations.items():
                setattr(builtins, key, value)
            for key in list(sys.modules):
                if key.split('.')[0] in sys.stdlib_module_names:
                    sys.modules.pop(key, None)
            sys.modules.update(previous)

    collector, predecessors, successor = {}, {}, {}
    compiled, contexts = {}, {}
    def importer(graph):
        def load(name, globals=None, locals=None, fromlist=(), level=0):
            check(deadline)
            if not level and name in graph:
                return graph[name]
            return standard_import(name, globals, locals, fromlist, level)
        return load
    importers = {'collector': importer(collector), 'predecessor': importer(predecessors), 'phase': importer(successor)}
    def compile_captured(source, filename, mode, *args, **kwargs):
        guard()
        if type(source) is not bytes or mode != 'exec' or args or kwargs or source not in data.values():
            raise ValueError('unbound-runtime-source')
        code = LANGUAGE['compile'](source, filename, mode)
        compiled[id(code)] = (code, next(name for name, raw in data.items() if raw == source))
        return code
    def execute(code, namespace, local=None):
        guard()
        if id(code) not in compiled or compiled[id(code)][0] is not code or type(namespace) is not dict or local is not None:
            raise ValueError('unbound-runtime-code')
        name = compiled[id(code)][1]
        kind = 'phase' if name.startswith(PHASE_ROOT + '/') else 'collector' if name.startswith(COLLECTOR_ROOT + '/') else 'predecessor'
        selected_importer = contexts.get(id(namespace), importers[kind])
        namespace['__builtins__'] = {**LANGUAGE, '__import__': selected_importer,
                                     'compile': compile_captured, 'exec': execute}
        LANGUAGE['exec'](code, namespace)
        guard()
    def modules(prefix, names, graph):
        for name in names:
            value = types.ModuleType(name); value.__file__ = str(root / prefix / (name + '.py'))
            graph[name] = value
        for name in names:
            value = graph[name]
            execute(compile_captured(data[prefix + '/' + name + '.py'], value.__file__, 'exec'), value.__dict__)
    names, missing = (*COLLECTOR, *PHASE), object()
    previous, old_paths = {name: sys.modules.get(name, missing) for name in names}, list(sys.path)
    try:
        # Historical gate/adapter and successor gate/adapter have separate maps.
        modules('scripts/port/repository-client-stage', ('gate', 'adapter'), predecessors)
        collector.update(predecessors)
        modules(COLLECTOR_ROOT, COLLECTOR, collector)
        def load_snapshot(snapshot, names):
            guard()
            if tuple(names) != ('gate', 'adapter'):
                raise ValueError('dependency-snapshot-closure')
            snapshot = Path(snapshot)
            expected = {name + '.py': rows['scripts/port/repository-client-stage/' + name + '.py'] for name in names}
            if obj(read(snapshot / '.source-map.json', deadline=deadline)[0]) != expected:
                raise ValueError('dependency-snapshot-map')
            captured = captures(snapshot, expected, count=2, deadline=deadline)
            graph = {name: types.ModuleType(name) for name in names}
            bound = importer(graph)
            for name, value in graph.items():
                value.__file__ = str(snapshot / (name + '.py'))
                contexts[id(value.__dict__)] = bound
                execute(compile_captured(captured[name + '.py'], value.__file__, 'exec'), value.__dict__)
            guard()
            return graph
        collector['common'].load_snapshot = load_snapshot
        collector['orchestrator'].load_snapshot = load_snapshot
        if phase:
            modules(PHASE_ROOT, ('dependencies',), successor)
            dependency = successor['dependencies']
            def load_collector(repo_root=root):
                if Path(repo_root).absolute() != root:
                    raise ValueError('dependency-root')
                guard()
                return {name: collector[name] for name in COLLECTOR}
            dependency.load_collector = load_collector
            def source(path, expected, *, mode=0o644):
                path = Path(path).absolute()
                if not path.is_relative_to(root):
                    raise ValueError('dependency-root')
                name = path.relative_to(root).as_posix()
                if name not in data or rows[name] != {'sha256': expected, 'mode': mode}:
                    raise ValueError('unbound-runtime-source')
                guard()
                return data[name]
            dependency.source = source
            # Keep the original frozen predicates/read API; bind only the root.
            dependency.ROOT = root
            modules(PHASE_ROOT, ('phases', 'gate', 'adapter'), successor)
        guard()
        return ({name: successor[name] for name in PHASE} if phase else
                {name: collector[name] for name in COLLECTOR}), selected
    finally:
        sys.path[:] = old_paths
        for name, old in previous.items():
            if old is missing:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old


def services(modules, rows, *, source_root, private_root, job_deadline, cli_sha256,
             endpoint_identity, env, cancelled=None):
    """Explicit inert construction from the authenticated seven-source closure."""
    if set(rows) != SOURCES or set(modules) != set(MODULES):
        raise ValueError('exact-service-closure')
    check(job_deadline)
    root = Path(source_root).absolute()
    source_identities = None
    def source_guard():
        nonlocal source_identities
        current = {}
        captures(root, rows, deadline=job_deadline, count=7, identities=current)
        if source_identities is not None and current != source_identities:
            raise ValueError('service-source-identity-drift')
        source_identities = current
        if cancelled is not None and cancelled():
            raise ValueError('service-cancelled')
    source_guard()
    broker = modules['broker']
    producer_raw = pinned(root / 'producer.py', rows['producer.py']['sha256'], deadline=job_deadline)
    pending = broker.Pending(private_root, producer_raw, rows['producer.py']['sha256'],
                             job_deadline=job_deadline, cancelled=cancelled)
    # The registered callbacks are broker-defined lambdas closing over separately
    # authenticated dependency modules. Their exact source file/module are fixed.
    grants = {role: {'module': 'broker', 'source_file': str(root / 'broker.py'),
                     'source_sha256': rows['broker.py']['sha256']} for role in modules['supervisor'].ROLES}
    supervision_started = False
    def supervise_factory(deadline):
        nonlocal supervision_started
        if supervision_started:
            raise ValueError('one-added-supervision-envelope')
        check(deadline)
        if deadline > job_deadline:
            raise ValueError('supervision-enclosing-deadline')
        source_guard()
        supervision_started = True
        return modules['supervisor'].RoleSupervisor(grants, deadline=deadline, source_guard=source_guard)
    transport = modules['transport'].DockerTransport(cli_sha256=cli_sha256, endpoint_identity=endpoint_identity,
        env=env, create_validator=pending.approve_create, identity_guard=source_guard)
    return {'pending': pending, 'transport': transport, 'supervise_factory': supervise_factory}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-map', required=True)
    parser.add_argument('--source-map-sha256', required=True)
    args = parser.parse_args()
    try:
        _, pins = authenticated(args.source_map, args.source_map_sha256, deadline=time.monotonic() + 180)
        print(json.dumps({'status': 'PASS-source-preflight', 'source_count': len(pins),
                          'actors': 'NOT RUN', 'native_admission': 'NOT RUN'}, sort_keys=True))
        return 0
    except BaseException as error:
        print(json.dumps({'status': 'FAIL', 'error_type': type(error).__name__, 'actors': 'NOT RUN'}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
