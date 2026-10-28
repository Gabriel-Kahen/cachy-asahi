#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Materialize the persistent data of one owned container; never grant an update."""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

RUNTIME = frozenset(('proc', 'sys', 'dev', 'run', 'tmp'))
INFRASTRUCTURE = frozenset(('inputs', 'out', 'source', 'workspace', 'measurement',
    'measurement-source', 'footprint.py', 'runner.py', 'lifecycle.py', 'setup4.py',
    'upgrade-code', 'upgrade-config.json', 'upgrade-pair', 'upgrade-hook.py',
    'persistent_scope.py', 'upgrade-signing'))
MOUNT_FILES = frozenset(('etc/hosts', 'etc/hostname', 'etc/resolv.conf'))
NON_DISK = frozenset(('tmpfs', 'ramfs', 'proc', 'sysfs', 'devtmpfs', 'devpts',
    'cgroup', 'cgroup2', 'mqueue', 'securityfs', 'debugfs', 'tracefs', 'hugetlbfs'))


def need(ok, reason):
    if not ok: raise ValueError(reason)


def _apis(code):
    directory = Path(code) / 'scripts/update'
    sys.path.insert(0, str(directory))
    try:
        import full_root
        import measure_copy
        import root_path
    finally: sys.path.pop(0)
    path = Path(code) / 'scripts/ci/full-root-upgrade/root_upgrade.py'
    spec = importlib.util.spec_from_file_location('_persistent_scope_driver', path)
    driver = importlib.util.module_from_spec(spec); spec.loader.exec_module(driver)
    need(Path(full_root.__file__).resolve() == (directory / 'full_root.py').resolve()
         and Path(measure_copy.__file__).resolve() == (directory / 'measure_copy.py').resolve()
         and Path(root_path.__file__).resolve() == (directory / 'root_path.py').resolve(),
         'selected scope API origin differs')
    return persistent_apis(full_root, measure_copy, root_path, driver)


def mounts(raw):
    need(type(raw) is str and len(raw.encode()) <= 1024**2, 'bounded mount table required')
    result = []
    for line in raw.splitlines():
        left, right = line.split(' - ', 1); fields, tail = left.split(), right.split()
        need(len(fields) >= 6 and len(tail) >= 3 and fields[0].isdigit()
             and fields[4].startswith('/') and '\\' not in fields[4], 'reviewed mount encoding required')
        result.append(dict(id=int(fields[0]), path=fields[4], fs=tail[0]))
    need(result and len({r['path'] for r in result}) == len(result), 'unambiguous mount table required')
    return result


def _mount_table():
    with Path('/proc/self/mountinfo').open('r') as stream: raw = stream.read(1024**2 + 1)
    need(len(raw.encode()) <= 1024**2, 'bounded mount table required')
    return raw


def mount_policy(source, target, rows):
    """Only literal container infrastructure and runtime submounts may be omitted."""
    def containing(path):
        hits = [r for r in rows if path == Path(r['path']) or path.is_relative_to(Path(r['path']))]
        need(hits, 'mount identity unavailable')
        return max(hits, key=lambda r: len(Path(r['path']).parts))
    source_mount, output = containing(source), containing(target.parent)
    need(output['fs'] not in NON_DISK, 'disk-backed persistent stage required')
    if target.is_relative_to(source):
        need(target.relative_to(source).parts[0] == 'measurement', 'stage must be outside persistent source data')
    selected = []
    for row in rows:
        point = Path(row['path'])
        if point == source or not point.is_relative_to(source): continue
        relative = point.relative_to(source).as_posix()
        first = relative.split('/')[0]
        need(first in RUNTIME or relative in INFRASTRUCTURE or relative in MOUNT_FILES,
             'unrecognized source mount refused')
        selected.append(relative)
    if source == Path('/'):
        need('upgrade-signing' in selected, 'separate TEST signer mount required')
        need(output['path'] == '/measurement' and output['id'] != source_mount['id'],
             'owned separate measurement volume required')
    return dict(source_mount=source_mount['id'], target_mount=output['id'],
                observed_mounts=sorted(selected))


@contextmanager
def _parent(roots, source, name, limits):
    """Nofollow parent traversal; final symlinks are read as literal data."""
    roots.installer.relative(name); fd = roots._open_root(source); held = [fd]
    try:
        for part in name.split('/')[:-1]:
            limits.tick()
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            held.append(fd)
        yield fd, name.split('/')[-1]
    finally:
        for fd in reversed(held): os.close(fd)


def source_manifest(source, limits, roots, policy):
    """Bounded read-only coverage observation; copying stays in measure_copy."""
    nodes, groups, excluded = {}, {}, []
    total_bytes = 0
    source = Path(source)
    infrastructure = INFRASTRUCTURE & set(policy['observed_mounts'])
    def walk(fd, prefix='', depth=0):
        nonlocal total_bytes
        limits.tick(); need(depth <= limits.max_depth, 'persistent scope depth limit')
        initial = roots._identity(os.fstat(fd)); names = sorted(os.listdir(fd))
        need(roots._mount_id(fd, limits) == policy['source_mount'], 'persistent directory mount crossing')
        for leaf in names:
            limits.tick(); name = prefix + leaf
            roots.installer.relative(name)
            if name in infrastructure:
                excluded.append(name); continue
            info = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
            node = dict(mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid)
            need(len(nodes) < limits.max_nodes, 'persistent scope node limit')
            if stat.S_ISDIR(info.st_mode):
                node['type'] = 'directory'; nodes[name] = node
                if name in RUNTIME:
                    excluded.append(name + '/*')
                else:
                    child = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    try:
                        need(roots._identity(os.fstat(child)) == roots._identity(info), 'persistent directory drift')
                        walk(child, name + '/', depth + 1)
                    finally: os.close(child)
            elif stat.S_ISREG(info.st_mode):
                need(info.st_size <= limits.max_file_bytes, 'persistent file byte limit')
                total_bytes += info.st_size
                need(total_bytes <= limits.max_bytes, 'persistent scope byte limit')
                child = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
                try:
                    need(name in MOUNT_FILES or roots._mount_id(child, limits) == policy['source_mount'],
                         'persistent file mount crossing')
                    if name in MOUNT_FILES: need(info.st_nlink == 1, 'ordinary mount file hardlink refused')
                    node.update(type='file', bytes=info.st_size, sha256=roots._file_hash(child, info, limits))
                finally: os.close(child)
                nodes[name] = node
                if info.st_nlink > 1:
                    group = groups.setdefault((info.st_dev, info.st_ino), dict(nlink=info.st_nlink, members=[]))
                    need(group['nlink'] == info.st_nlink, 'persistent hardlink drift'); group['members'].append(name)
            elif stat.S_ISLNK(info.st_mode):
                need(name not in RUNTIME and name not in MOUNT_FILES, 'runtime or mount-file alias refused')
                node.update(type='symlink', target=os.readlink(leaf, dir_fd=fd)); nodes[name] = node
            else: raise ValueError('persistent special node refused')
            need(name not in RUNTIME or node['type'] == 'directory', 'runtime directory required')
            need(roots._identity(os.stat(leaf, dir_fd=fd, follow_symlinks=False)) == roots._identity(info),
                 'persistent named entry drift')
        need(names == sorted(os.listdir(fd)) and roots._identity(os.fstat(fd)) == initial,
             'persistent directory changed')
    with _updater_phase('SOURCE_WALK'):
        fd = roots._open_root(source)
        try:
            initial = roots._identity(os.fstat(fd)); walk(fd)
            rebound = roots._open_root(source)
            try:
                need(roots._identity(os.fstat(rebound)) == roots._identity(os.fstat(fd)) == initial
                     and roots._mount_id(rebound, limits) == policy['source_mount'], 'persistent root path drift')
            finally: os.close(rebound)
        finally: os.close(fd)
    with _updater_phase('SOURCE_HARDLINKS'):
        need(len(groups) <= limits.max_hardlink_groups, 'persistent hardlink group limit')
        aliases = 0
        for group in groups.values():
            members = sorted(group['members']); aliases += len(members)
            need(len(members) == group['nlink'] and len(members) <= limits.max_hardlink_members,
                 'persistent hardlink group not closed')
            for name in members: nodes[name]['hardlink_group'] = members[0]
        need(aliases <= limits.max_hardlink_aliases, 'persistent hardlink alias limit')
    return nodes, sorted(excluded)


def _restore_boundaries(source, target, nodes, roots, copier, limits):
    """Only empty runtime directory nodes and three literal ordinary files."""
    for name in sorted(RUNTIME & nodes.keys()):
        node = nodes[name]; path = target / name
        path.mkdir(mode=0o700)
        os.chown(path, node['uid'], node['gid']); os.chmod(path, node['mode'])
    for name in sorted(MOUNT_FILES & nodes.keys()):
        node = nodes[name]; need(node['type'] == 'file', 'ordinary mount file required')
        with _parent(roots, source, name, limits) as (old_parent, leaf), _parent(roots, target, name, limits) as (new_parent, _):
            old = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=old_parent)
            try:
                initial = roots._identity(os.fstat(old))
                new = os.open(leaf, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=new_parent)
                try:
                    total, digest = 0, hashlib.sha256()
                    while True:
                        limits.tick(); block = os.read(old, min(1024**2, node['bytes'] - total + 1))
                        if not block: break
                        total += len(block); need(total <= node['bytes'], 'ordinary mount file grew')
                        digest.update(block); copier._write(new, block, limits)
                    need(total == node['bytes'] and digest.hexdigest() == node['sha256']
                         and roots._identity(os.fstat(old)) == initial, 'ordinary mount file changed')
                    os.fchown(new, node['uid'], node['gid']); os.fchmod(new, node['mode'])
                finally: os.close(new)
            finally: os.close(old)


def owned_coverage(packages, nodes, resolver, limits):
    owners = {}
    for package in packages:
        for name in package['files']:
            limits.tick(); need(name not in owners, 'overlapping installed ownership')
            parent, _, leaf = name.rpartition('/')
            endpoint, _ = resolver.resolve(nodes, parent, limits=limits)
            actual = endpoint + '/' + leaf if endpoint else leaf
            need(actual in nodes and nodes[actual]['type'] != 'directory', 'owned persistent payload absent')
            owners[name] = package['name']
    return len(owners)


def _mount600(original):
    import ctypes
    import errno
    import os
    import sys
    # Linux statx UAPI: mask offset0, mnt_id offset144, fixed256-byte record.
    # Request ordinary STATX_MNT_ID, never the distinct MNT_ID_UNIQUE namespace.
    class Statx600(ctypes.Structure):
        _fields_=[('mask',ctypes.c_uint32),('prefix',ctypes.c_ubyte*140),
                  ('mnt_id',ctypes.c_uint64),('reserved',ctypes.c_ubyte*104)]
    supported=(sys.platform=='linux' and sys.byteorder=='little' and ctypes.sizeof(ctypes.c_void_p)==8 and
               os.uname().machine in ('aarch64','x86_64') and ctypes.sizeof(Statx600)==256 and Statx600.mnt_id.offset==144)
    libc=ctypes.CDLL(None,use_errno=True) if supported else None
    call=getattr(libc,'statx',None)
    if call is not None:
        call.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_uint,ctypes.POINTER(Statx600))
        call.restype=ctypes.c_int
    checked=False
    def query(descriptor,limits):
        nonlocal call,checked
        limits.tick()
        if call is None:return original(descriptor,limits)
        result=Statx600()
        if call(descriptor,b'',0x1000,0x1000,ctypes.byref(result))!=0:
            error=ctypes.get_errno()
            if error in (errno.ENOSYS,errno.EINVAL,errno.EOPNOTSUPP,errno.EPERM):
                call=None;return original(descriptor,limits)
            raise OSError(error,'descriptor statx mount query failed')
        if not result.mask&0x1000:
            call=None;return original(descriptor,limits)
        if not result.mnt_id:raise ValueError('descriptor statx mount identity unavailable')
        if not checked:
            if result.mnt_id!=original(descriptor,limits):raise ValueError('descriptor mount identity APIs differ')
            checked=True
        return result.mnt_id
    return query

def persistent_apis(roots,copier,resolver,driver):
    """Private APIs only; held walkers/copy/hash/check code and fresh FDs remain."""
    import types
    def held(module,size,digest):
        raw=Path(module.__file__).read_bytes()
        if module is roots and b'max_packages: int = 607' in raw:
            # Current604's exact selected source changes this sole typed default.
            # Reverse it before the existing whole original source proof; every
            # observation/copy/security predicate remains byte held.
            selected=b'max_packages: int = 607'
            need(raw.count(selected)==1,'one selected604 root package limit')
            raw=raw.replace(selected,b'max_packages: int = 587',1)
        need(len(raw)==size and hashlib.sha256(raw).hexdigest()==digest,'whole persistent observation API source')
    held(roots,35970,'cece1c597b2e2eb98b0e3087cc7e7c148b54332f8a1c4f18e04e4552a71fb51d')
    held(copier,25734,'e582245bd114b0b9d83f2de4fdc81a35d2f48493ba6147879871af794476813b')
    def clone(function,namespace):
        result=types.FunctionType(function.__code__,namespace,function.__name__,function.__defaults__,function.__closure__)
        result.__kwdefaults__=function.__kwdefaults__
        return result
    def relative_api(module,digest):
        import ast,os
        text=Path(module.__file__).read_text()
        nodes=[n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name=='relative']
        need(len(nodes)==1 and hashlib.sha256(ast.get_source_segment(text,nodes[0]).encode()).hexdigest()==digest,'whole original relative validator source')
        original=module.relative
        if os.name!='posix':return original
        def relative(value):
            # No filesystem/graph results or strings are retained. Canonical
            # positive POSIX components need no pathlib normalization; every
            # uncertain operand takes the entire unchanged original validator.
            if type(value)is str and value and '\0'not in value and all(p not in('','.','..')for p in value.split('/')):return value
            return original(value)
        return relative
    private_installer=types.SimpleNamespace(**vars(roots.installer))
    private_installer.relative=relative_api(roots.installer,'486c47ebbe2e6cfc392bde908003baf7559fd70d2f6ed17684f2ba34340fac41')
    private_roots=types.SimpleNamespace(**vars(roots))
    private_roots._mount_id=_mount600(roots._mount_id)
    private_roots.installer=private_installer
    private_roots.observe=clone(roots.observe,dict(roots.observe.__globals__,_mount_id=private_roots._mount_id,installer=private_installer))
    from contextlib import contextmanager
    copy_scope=dict(copier.copy_data.__globals__,roots=private_roots)
    for name in ('_parent','_root_check','_source_alias','_copy_internal','copy_data'):
        original=getattr(copier,name)
        copy_scope[name]=(contextmanager(clone(original.__wrapped__,copy_scope))
                          if name=='_parent' else clone(original,copy_scope))
    private_copier=types.SimpleNamespace(**copy_scope)
    private_driver=driver
    if driver is not None:
        private_driver=types.SimpleNamespace(**vars(driver))
        private_driver.relative=relative_api(driver,'382ec23738149e6f6ebb9a35d399f9a7e1366f6352ab7a2a64d734e3244f9ead')
        private_driver.database=clone(driver.database,dict(driver.database.__globals__,relative=private_driver.relative))
    return private_roots,private_copier,resolver,private_driver


def persistent_stage_failure(before, staged, limits):
    """Existing map DATA only. Equality and incomplete observation still refuse."""
    try:
        import math, time
        actual = staged['nodes']
        need(type(before) is dict and type(actual) is dict and max(len(before), len(actual)) <= 200000, 'bounded original stage maps')
        need(all(type(n) is str and type(v) is dict for rows in (before,actual) for n,v in rows.items()), 'typed original node maps')
        need(type(staged['complete']) is bool and not (staged['complete'] is True and actual == before), 'failed stage predicate only')
        common = before.keys() & actual.keys()
        changed = {n for n in common if before[n] != actual[n]}
        missing, extra = before.keys() - actual.keys(), actual.keys() - before.keys()
        examples = []
        def node_pin(value):
            raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
            need(len(raw) <= 32768, 'bounded original node metadata')
            return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        for name in sorted(changed | missing | extra)[:5]:
            old, new = before.get(name), actual.get(name)
            fields = sorted(k for k in (old or {}).keys() | (new or {}).keys() if (old or {}).get(k) != (new or {}).get(k))
            examples.append(dict(path=name[:256], path_truncated=len(name)>256, path_sha256=hashlib.sha256(name.encode()).hexdigest(), kind='changed' if name in changed else 'missing' if name in missing else 'extra', fields=[n[:64] for n in fields[:16]], fields_truncated=len(fields)>16, before=None if old is None else node_pin(old), after=None if new is None else node_pin(new)))
        reasons = staged['unsupported_counts']
        need(type(reasons) is dict and len(reasons) <= 64 and all(type(k) is str and type(v) is int and 0 < v <= 200000 for k,v in reasons.items()), 'bounded original observation reasons')
        remaining = limits.deadline - time.monotonic()
        need(math.isfinite(remaining), 'finite original stage clock')
        value = dict(schema_version=1, status='PERSISTENT_STAGE_FAILURE_DATA_NOT_ACCEPTANCE', observation_complete=staged['complete'], node_maps_equal=actual==before, comparison_scope='COMPLETE_MAPS' if staged['complete'] else 'PARTIAL_OBSERVATION_NOT_EVIDENCE_OF_SOURCE_DRIFT', expected_nodes=len(before), observed_nodes=len(actual), missing_nodes=len(missing), extra_nodes=len(extra), changed_nodes=len(changed), examples=examples, omitted_examples=max(0,len(changed|missing|extra)-len(examples)), unsupported_counts={k[:96]:v for k,v in sorted(reasons.items())[:8]}, unsupported_reasons_omitted=max(0,len(reasons)-8), stage_remaining_seconds=remaining, stage_deadline_exhausted=remaining<=0, cleanup_authority=False, acceptance_authority=False)
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)
        need(len(raw.encode()) <= 6144, 'bounded persistent stage diagnostic')
        print('APPS6_PERSISTENT_STAGE_FAILURE '+raw, file=sys.stderr, flush=True)
    except Exception:
        pass  # Diagnostic loss never replaces the unchanged original refusal.


_UPDATER_PHASE_BYTES = 4096
_UPDATER_PHASE_LABELS = ('PATHS', 'APIS', 'PARENT', 'MOUNTS', 'SOURCE_BEFORE', 'SOURCE_DB', 'SELECTION', 'OWN_BEFORE', 'COPY', 'RESTORE', 'STAGED_OBSERVE', 'STAGED_EQUALITY', 'STAGED_DB', 'OWN_AFTER', 'SOURCE_AFTER', 'SOURCE_EQUALITY', 'MOUNT_EQUALITY', 'MANIFEST', 'SOURCE_WALK', 'SOURCE_HARDLINKS')

def _updater_phase_write(state, label):
    global _UPDATER_PHASE_BYTES
    if state not in ('BEGIN','END','FAIL') or label not in _UPDATER_PHASE_LABELS:
        return
    raw = ('UPDATER489_STAGE_PHASE '+state+' '+label+'\n').encode('ascii')
    if len(raw) > _UPDATER_PHASE_BYTES:
        return
    _UPDATER_PHASE_BYTES -= len(raw)
    try:
        os.write(2, raw)
    except OSError:
        pass

@contextmanager
def _updater_phase(label):
    _updater_phase_write('BEGIN', label)
    try:
        yield
    except BaseException:
        _updater_phase_write('FAIL', label)
        raise
    else:
        _updater_phase_write('END', label)


def materialize(source: Path, target: Path, code: Path, limits):
    """Return PASS only for complete persistent coverage, before any update actor."""
    with _updater_phase('PATHS'):
        source, target, code = Path(source), Path(target), Path(code)
        need(source.is_absolute() and target.is_absolute() and code.is_absolute()
             and '..' not in source.parts + target.parts + code.parts, 'absolute canonical scope paths required')
        need(not source.is_relative_to(target) and not target.exists() and not target.is_symlink(), 'fresh disjoint stage required')
        need(not limits.allow_cross_device, 'single-mount staged copy required')
        parent = target.parent.stat()
        need(parent.st_uid == os.geteuid() and not stat.S_IMODE(parent.st_mode) & 0o077,
             'owned private staging parent required')
    with _updater_phase('APIS'):
        roots, copier, resolver, driver = _apis(code)
    with _updater_phase('PARENT'):
        fd = roots._open_root(target.parent)
        try:
            need(roots._identity(os.fstat(fd)) == roots._identity(parent), 'stage parent changed or aliased')
        finally: os.close(fd)
    with _updater_phase('MOUNTS'):
        raw = _mount_table()
        policy = mount_policy(source, target, mounts(raw))
    with _updater_phase('SOURCE_BEFORE'):
        before, excluded = source_manifest(source, limits, roots, policy)
    with _updater_phase('SOURCE_DB'):
        packages = driver.database(source, max_packages=limits.max_packages, max_files=limits.max_package_files,
                                   max_nodes=limits.max_nodes, observed=before)
    with _updater_phase('SELECTION'):
        expected, _ = driver.selection(code)
        need({p['name']: p['version'] for p in packages} == expected, 'initial signed587 source inventory differs')
    with _updater_phase('OWN_BEFORE'):
        owned = owned_coverage(packages, before, resolver, limits)
    with _updater_phase('COPY'):
        report = copier.copy_data(source, target, limits=limits,
            excluded=RUNTIME | (INFRASTRUCTURE & set(policy['observed_mounts'])) | MOUNT_FILES, absolute_paths=True)
        need(not report['unsupported_counts'], 'persistent copy skipped special nodes')
    with _updater_phase('RESTORE'):
        _restore_boundaries(source, target, before, roots, copier, limits)
    with _updater_phase('STAGED_OBSERVE'):
        staged = roots.observe(target, limits=limits, hardlinks='generic-development-internal', absolute_paths=True)
    with _updater_phase('STAGED_EQUALITY'):
        try:
            need(staged['complete'] is True and staged['nodes'] == before, 'complete persistent stage differs')
        except ValueError:
            persistent_stage_failure(before, staged, limits)
            raise
    with _updater_phase('STAGED_DB'):
        need(driver.database(target, max_packages=limits.max_packages, max_files=limits.max_package_files,
                             max_nodes=limits.max_nodes, observed=staged['nodes']) == packages, 'staged package records differ')
    with _updater_phase('OWN_AFTER'):
        need(owned_coverage(packages, staged['nodes'], resolver, limits) == owned, 'staged ownership coverage differs')
    with _updater_phase('SOURCE_AFTER'):
        after, final_excluded = source_manifest(source, limits, roots, policy)
    with _updater_phase('SOURCE_EQUALITY'):
        need(after == before and final_excluded == excluded, 'persistent source changed during materialization')
    with _updater_phase('MOUNT_EQUALITY'):
        need(mounts(_mount_table()) == mounts(raw), 'source mount table changed')
    with _updater_phase('MANIFEST'):
        digest = hashlib.sha256(json.dumps(before, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        return dict(status='PASS', scope='complete-persistent-data-materialization',
            whole_container_root=False, whole_root_copy=False, excluded=excluded,
            runtime_directories='PRESERVED_EMPTY', ordinary_mount_files=sorted(MOUNT_FILES & before.keys()),
            source_nodes=len(before), source_manifest_sha256=digest, source_inventory_count=len(packages),
            package_owned_nondirectory_paths=owned, source_preserved=True, persistent_nodes_identical=True,
            staged_single_mount=True, stage_ready_for_selected_copy=True,
            copy=report, mount_scope=policy, update_eligibility='NOT ESTABLISHED',
            copied_metadata='contents, modes, UID/GID, literal symlinks, closed internal hardlinks; xattrs/timestamps omitted',
            consistency='bounded per-file identity and before/after node equality; not an atomic snapshot',
            transaction_acceptance='NOT ESTABLISHED', hardware='NOT RUN')


def verify(source: Path, stage: Path, code: Path, limits):
    """Reobserve both unchanged baselines; caller must also match initial digest."""
    source, stage, code = Path(source), Path(stage), Path(code)
    need(source.is_absolute() and stage.is_absolute() and code.is_absolute()
         and '..' not in source.parts + stage.parts + code.parts and not limits.allow_cross_device,
         'canonical single-mount verification required')
    roots, _copier, resolver, driver = _apis(code)
    raw = _mount_table()
    policy = mount_policy(source, stage, mounts(raw))
    before, excluded = source_manifest(source, limits, roots, policy)
    observation = roots.observe(stage, limits=limits, hardlinks='generic-development-internal', absolute_paths=True)
    need(observation['complete'] is True and observation['nodes'] == before, 'persistent verification stage differs')
    packages = driver.database(source, max_packages=limits.max_packages, max_files=limits.max_package_files,
                               max_nodes=limits.max_nodes, observed=before)
    expected, _ = driver.selection(code)
    need({p['name']: p['version'] for p in packages} == expected, 'verified initial587 inventory differs')
    need(driver.database(stage, max_packages=limits.max_packages, max_files=limits.max_package_files,
                         max_nodes=limits.max_nodes, observed=observation['nodes']) == packages,
         'verified staged database differs')
    owned = owned_coverage(packages, before, resolver, limits)
    after, final_excluded = source_manifest(source, limits, roots, policy)
    need(after == before and final_excluded == excluded, 'persistent source changed during verification')
    need(mounts(_mount_table()) == mounts(raw), 'verification mount table changed')
    digest = hashlib.sha256(json.dumps(before, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return dict(status='PASS', whole_container_root=False, source_preserved=True,
        persistent_nodes_identical=True, source_manifest_sha256=digest, excluded=excluded,
        source_nodes=len(before), source_inventory_count=len(packages), package_owned_nondirectory_paths=owned,
        initial_digest_match='CALLER MUST CHECK', transaction_acceptance='NOT ESTABLISHED', hardware='NOT RUN')
