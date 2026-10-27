# SPDX-License-Identifier: MIT
"""Compile in the original root_upgrade globals; full copy only, no update API."""
import ast as _capacity_ast
import contextlib as _capacity_contextlib
import hashlib as _capacity_hashlib
import os as _capacity_os
from pathlib import Path as _CapacityPath
import stat as _capacity_stat
import sys as _capacity_sys
import time as _capacity_time
import types as _capacity_types

_CAPACITY_FIXED = dict(copy=3600, copy_workspace_cleanup=900, control_lease_cleanup=300, driver=4800)
_CAPACITY_LEASE = 'capacity-control.lease'


def _capacity_need(ok, reason):
    if not ok:
        raise ValueError(reason)


def _capacity_budgets(value):
    _capacity_need(type(value) is dict and all(type(value.get(k)) is int and value[k] == v
                   for k, v in _CAPACITY_FIXED.items()), 'fixed finite capacity-only budgets required')
    return dict(_CAPACITY_FIXED)


def _capacity_digest(value):
    def data(v):
        if type(v) is bytes:
            return dict(bytes=len(v), sha256=_capacity_hashlib.sha256(v).hexdigest())
        if type(v) in (tuple, list):
            return [data(x) for x in v]
        if type(v) is dict:
            _capacity_need(all(type(k) is str for k in v), 'typed private receipt keys')
            return {k: data(x) for k, x in v.items()}
        _capacity_need(v is None or type(v) in (str, int, bool), 'finite private receipt values')
        return v
    import json
    return _capacity_hashlib.sha256((json.dumps(data(value), sort_keys=True,
               separators=(',', ':'), allow_nan=False) + '\n').encode()).hexdigest()


def _capacity_clone(function, namespace):
    value = _capacity_types.FunctionType(function.__code__, namespace, function.__name__,
                                         function.__defaults__, function.__closure__)
    value.__kwdefaults__ = function.__kwdefaults__
    return value


def _capacity_lifetime(module, source, expected, proof, emit=None):
    """Only this freshly pinned private lifetime permits cleanup900; whole inverse."""
    fd = _capacity_os.open(source, _capacity_os.O_RDONLY | _capacity_os.O_NOFOLLOW |
                           _capacity_os.O_NONBLOCK | _capacity_os.O_CLOEXEC)
    try:
        before = _capacity_os.fstat(fd)
        key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
                         s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        _capacity_need(_capacity_stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                       0 < before.st_size <= 512 * 1024, 'private lifetime source shape')
        raw = bytearray()
        while chunk := _capacity_os.read(fd, min(65536, before.st_size - len(raw) + 1)):
            raw.extend(chunk)
            _capacity_need(len(raw) <= before.st_size, 'private lifetime source growth')
        _capacity_need(len(raw) == before.st_size and key(before) == key(_capacity_os.fstat(fd)) ==
                       key(_capacity_os.stat(source, follow_symlinks=False)) and
                       _capacity_hashlib.sha256(raw).hexdigest() == expected,
                       'whole stable private lifetime source pin')
    finally:
        _capacity_os.close(fd)
    tree = _capacity_ast.parse(raw)
    nodes = [n for n in tree.body if isinstance(n, _capacity_ast.FunctionDef) and n.name == 'copied_root']
    _capacity_need(len(nodes) == 1, 'one complete original lifetime body')
    original = _capacity_ast.get_source_segment(raw.decode(), nodes[0])
    old, new = '0 < cleanup_seconds <= 120', '0 < cleanup_seconds <= 900'
    _capacity_need(original.count(old) == 1, 'one private cleanup ceiling operand')
    changed = original.replace(old, new, 1)
    additions = (
        ('        cleanup_error = None',
         "        _capacity_emit('WORKSPACE_CLEANUP', 'BEGIN')", True),
        ('            if failed:',
         "            _capacity_emit('WORKSPACE_CLEANUP', 'FAIL' if failed or cleanup_error is not None or report['cleanup'] != 'PASS-owned-workspace-removed' else 'END', details=dict(status='FAIL-owned-descriptor-cleanup' if failed else report['cleanup']))", False))
    for anchor, addition, after in additions:
        _capacity_need(changed.count(anchor) == 1, 'one complete private cleanup telemetry anchor')
        changed = changed.replace(anchor, anchor + '\n' + addition if after else addition + '\n' + anchor, 1)
    restored = '\n'.join(line for line in changed.split('\n')
                         if not line.lstrip().startswith('_capacity_emit('))
    _capacity_need(changed.count(new) == 1 and restored.replace(new, old, 1) == original,
                   'whole private lifetime cleanup inverse')
    module._capacity_emit = emit if emit is not None else lambda *args, **kwargs: None
    exec(compile(changed, str(source), 'exec'), module.__dict__)
    module.copied_root = _capacity_contextlib.contextmanager(module.copied_root)
    proof.update(source_sha256=expected, before_sha256=_capacity_hashlib.sha256(original.encode()).hexdigest(),
                 after_sha256=_capacity_hashlib.sha256(changed.encode()).hexdigest(),
                 whole_inverse=True, original_ceiling=120, capacity_ceiling=900,
                 cleanup_telemetry_seams=2)
    return module


def bind(copy_module, trace, budgets, validate_observation=None):
    """Clone the real private globals; keep all observations/checkpoints fresh."""
    _capacity_budgets(budgets)
    _capacity_need(callable(validate_observation), 'explicit capacity observation validator required')
    space = dict(copy_module.copied_root.__globals__)
    _capacity_need(all(k in space for k in ('_isolated', '_copy_binding', 'copy_data', 'copied_root',
                   'aux', 'roots', 'links', 'measure_copy', 'disposable_copy', 'LIFETIME_SHA256', '_updater_copy_cost')),
                   'complete original private copied-root globals required')
    helper = space['_updater_copy_cost']
    telemetry_errors = []
    def raw_stats():
        value = helper._stats[:]
        _capacity_need(type(value) is list and len(value) == 7 and
                       all(type(v) is int and 0 <= v < 2**63 for v in value),
                       'fresh bounded original copy counters')
        return value
    initial = raw_stats()
    _capacity_need(initial[:3] == [0] * 3, 'fresh complete-copy work counters required')
    offset, last = [-v for v in initial], [0] * 7
    copy_started = False
    def stats():
        value = [base + raw for base, raw in zip(offset, raw_stats())]
        _capacity_need(all(type(v) is int and 0 <= v < 2**63 and v >= previous
                       for v, previous in zip(value, last)),
                       'cumulative capacity counters regressed or overflowed')
        last[:] = value
        return value
    def emit(phase, event, *, stats_value=None, **kwargs):
        # Diagnostic failure invalidates the probe; never masks a primary error.
        try:
            trace.event(phase, event, stats=stats() if stats_value is None else stats_value, **kwargs)
        except BaseException as error:
            if len(telemetry_errors) < 16:
                telemetry_errors.append(dict(phase=phase, event=event, error_type=type(error).__name__))
    auxiliary = space['aux']
    proxy = _capacity_types.SimpleNamespace(**vars(auxiliary))
    def checkpoint(root, observation, limits):
        value = auxiliary.checkpoint(root, observation, limits)
        validate_observation(root, observation, limits, value)
        return value
    proxy.checkpoint = checkpoint
    space['aux'] = proxy
    original_isolated = space['_isolated']
    lifetime_proof = {}
    def isolated(source, expected):
        module = original_isolated(source, expected)
        if _CapacityPath(source) == _CapacityPath(space['disposable_copy'].__file__):
            _capacity_need(expected == space['LIFETIME_SHA256'], 'original lifetime selection held')
            module = _capacity_lifetime(module, source, expected, lifetime_proof, emit)
        if _CapacityPath(source) == _CapacityPath(space['measure_copy'].__file__):
            original_cost = module._updater_cost.cost
            cost_proxy = _capacity_types.SimpleNamespace(**vars(module._updater_cost))
            def cost(stage, event):
                original_cost(stage, event)
                emit(stage, event)
            cost_proxy.cost = cost
            module._updater_cost = cost_proxy
            original_copy = module._copy_internal
            def copy(*args, **kwargs):
                nonlocal copy_started
                _capacity_need(not copy_started and original_copy.__globals__ is vars(helper),
                               'one source-pinned original copy counter reset required')
                copy_started = True
                before_reset = stats()
                original_helper_cost, reset_seen = helper.cost, False
                def reset_cost(stage, event):
                    nonlocal reset_seen
                    if (stage, event) == ('COPY', 'BEGIN'):
                        _capacity_need(not reset_seen and raw_stats() == [0] * 7,
                                       'one exact raw-zero original copy reset witness required')
                        offset[:] = before_reset
                        reset_seen = True
                        emit('COPY', 'BEGIN')
                    else:
                        _capacity_need(reset_seen, 'original copy reset witness required before cost')
                    return original_helper_cost(stage, event)
                helper.cost = reset_cost
                try:
                    value = original_copy(*args, **kwargs)
                    _capacity_need(reset_seen, 'original copy returned without reset witness')
                except BaseException:
                    emit('COPY', 'FAIL')
                    raise
                finally:
                    changed_cost = helper.cost is not reset_cost
                    helper.cost = original_helper_cost
                    _capacity_need(not changed_cost, 'private scalar reset witness rebound')
                emit('COPY', 'END')
                return value
            copy.__wrapped__ = original_copy
            module._copy_internal = copy
        return module
    space['_isolated'] = isolated
    for name in ('_copy_binding', 'copy_data', 'copied_root'):
        space[name] = _capacity_clone(space[name], space)
    result = _capacity_types.SimpleNamespace(**space)
    result.capacity_lifetime_inverse = lifetime_proof
    result.capacity_checkpoint = auxiliary.checkpoint
    result.capacity_compare = auxiliary.compare
    result.capacity_stats = stats
    result.capacity_event = emit
    result.capacity_telemetry_errors = telemetry_errors
    return result


class _CapacityObservation:
    def __init__(self, args, before, config, copy_module, trace):
        self.args, self.before, self.config = args, before, config
        self.copy_module, self.trace = copy_module, trace
        self.receipts, self.nodes, self.groups, self.state = [], None, None, None

    def __call__(self, root, observation, limits, checkpoint):
        index = len(self.receipts)
        phases = ('SOURCE_BEFORE', 'DESTINATION', 'SOURCE_AFTER')
        expected = (_CapacityPath(self.args.source), _CapacityPath(self.args.workspace) / 'root',
                    _CapacityPath(self.args.source))
        _capacity_need(index < 3 and _CapacityPath(root) == expected[index] and
                       observation.get('complete') is True, 'exact three original copier observations')
        limits.tick()
        rows = database(root, max_packages=607, max_files=self.config['limits']['package_files'],
                        max_nodes=self.config['limits']['root_nodes'], observed=observation['nodes'])
        actual = {row['name']: row['version'] for row in rows}
        _capacity_need(len(rows) == len(actual) == 607 and actual == self.before,
                       'capacity requires exact unchanged607 Apps6 database')
        resolver = _capacity_types.SimpleNamespace(resolve_nodes=lambda nodes, path:
                    self.copy_module.links.protection_endpoint(nodes, path, limits))
        protected, kernels = ownership(rows, observation['nodes'], resolver)
        _capacity_need(any((n.startswith('home/') or n.startswith('root/')) and v['type'] == 'file'
                       for n, v in observation['nodes'].items()), 'actual user-file baseline required')
        if index == 0:
            self.nodes, self.groups, self.state = observation['nodes'], observation.get('hardlink_groups', {}), checkpoint
        else:
            _capacity_need(observation['nodes'] == self.nodes and
                           observation.get('hardlink_groups', {}) == self.groups,
                           'complete source/destination byte/metadata/hardlink preservation')
            _capacity_need(checkpoint['main_bytes'] == self.state['main_bytes'] and
                           checkpoint['aux_bytes'] == self.state['aux_bytes'],
                           'capacity never initializes or changes cache bytes')
            if index == 2:
                self.copy_module.aux.compare(self.state, checkpoint, None, committed=False)
        receipt = dict(phase=phases[index], package_count=607, inventory_sha256=inventory_sha(actual),
                       database_sha256=_capacity_digest(rows), nodes_sha256=_capacity_digest(observation['nodes']),
                       hardlink_graph_sha256=_capacity_digest(observation.get('hardlink_groups', {})),
                       ownership_sha256=_capacity_digest(dict(protected=sorted(protected), kernels=kernels)),
                       checkpoint_sha256=_capacity_digest(checkpoint),
                       main_cache_sha256=_capacity_hashlib.sha256(checkpoint['main_bytes']).hexdigest(),
                       auxiliary_cache_sha256=_capacity_hashlib.sha256(checkpoint['aux_bytes']).hexdigest())
        self.receipts.append(receipt)
        event = getattr(self, 'emit', self.trace.event)
        event(phases[index], 'END', totals=self.trace.totals(observation), details=receipt)
        limits.tick()


class _CapacityLease:
    def __init__(self, data, workspace, roots, root_check):
        self.data, self.workspace, self.roots, self.root_check = data, workspace, roots, root_check
        self.directory = self.parent = self.file = None
        self.created = False

    def _core(self, info):
        return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid

    def _key(self, info):
        return self._core(info) + (info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def _directories(self, limits):
        for path, fd, key, mount in ((self.data, self.directory, self.data_key, self.data_mount),
                                    (self.workspace.parent, self.parent, self.parent_key, self.parent_mount)):
            current = _capacity_os.fstat(fd)
            _capacity_need(self._core(current) == key, 'capacity control directory rebound')
            self.root_check(path, fd, self.roots._identity(current), mount, limits)

    def check(self, limits):
        self._directories(limits)
        current = _capacity_os.fstat(self.file)
        _capacity_need(self._key(current) == self.file_key == self._key(_capacity_os.stat(
                       _CAPACITY_LEASE, dir_fd=self.directory, follow_symlinks=False)) and
                       self.roots._mount_id(self.file, limits) == self.data_mount,
                       'capacity control lease FD/path/mount/ownership drift')

    def open(self, limits):
        self.directory = self.roots._open_root(self.data)
        self.parent = self.roots._open_root(self.workspace.parent)
        a, b = _capacity_os.fstat(self.directory), _capacity_os.fstat(self.parent)
        for info in (a, b):
            _capacity_need(info.st_uid == _capacity_os.geteuid() and not
                           _capacity_stat.S_IMODE(info.st_mode) & 0o022, 'owned private capacity control directory')
        self.data_key, self.parent_key = self._core(a), self._core(b)
        self.data_mount = self.roots._mount_id(self.directory, limits)
        self.parent_mount = self.roots._mount_id(self.parent, limits)
        self.file = _capacity_os.open(_CAPACITY_LEASE, _capacity_os.O_RDWR | _capacity_os.O_CREAT |
                  _capacity_os.O_EXCL | _capacity_os.O_NOFOLLOW | _capacity_os.O_CLOEXEC, 0o600,
                  dir_fd=self.directory)
        self.created = True
        info = _capacity_os.fstat(self.file)
        _capacity_need(_capacity_stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == 0 and
                       info.st_uid == _capacity_os.geteuid() and info.st_gid == _capacity_os.getegid() and
                       _capacity_stat.S_IMODE(info.st_mode) == 0o600, 'exclusive empty owned capacity control lease')
        self.file_key = self._key(info)
        self.check(limits)

    def workspace_absent(self, limits):
        self._directories(limits)
        try:
            _capacity_os.stat(self.workspace.name, dir_fd=self.parent, follow_symlinks=False)
        except FileNotFoundError:
            return True
        return False

    def retire(self, limits, workspace_cleanup):
        receipt = dict(role='control_lease', status='NOT_CREATED')
        try:
            if self.created:
                _capacity_need(workspace_cleanup and self.workspace_absent(limits),
                               'capacity workspace absence unknown; retain control lease')
                self.check(limits)
                _capacity_os.unlink(_CAPACITY_LEASE, dir_fd=self.directory)
                try:
                    _capacity_os.stat(_CAPACITY_LEASE, dir_fd=self.directory, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise ValueError('capacity control lease remains')
                _capacity_need(_capacity_os.fstat(self.file).st_nlink == 0,
                               'capacity control lease unlink not observed')
                self._directories(limits)
                receipt['status'] = 'PASS_OWNED_CONTROL_LEASE_REMOVED'
        except BaseException as error:
            receipt.update(status='RETAINED_OR_UNCERTAIN', error_type=type(error).__name__)
        finally:
            for field in ('file', 'parent', 'directory'):
                fd = getattr(self, field)
                if fd is not None:
                    setattr(self, field, None)
                    try:
                        _capacity_os.close(fd)
                    except OSError:
                        receipt['status'] = 'FAIL_DESCRIPTOR_RETIREMENT'
        return receipt


def run(args, *, runtime_module, copy_module, constructor=None, prepare_copy=None):
    """Actual copy capacity only; initializer/repository/apply are unreachable."""
    result = dict(status='FAIL', phase='selection', scope='FULL_COPY_CAPACITY_DATA_NOT_ACCEPTANCE',
                  acceptance=False, normal_updater_acceptance=False, committed_transactions=0,
                  commit_started=False, packages_committed=False, checkpoint_changed=False,
                  initialization_started=False, init_started=False, root_initialized=False, hardware='NOT_RUN',
                  release='NOT_ADMITTED', copy_cleanup='NOT_CREATED', cleanup_order=[],
                  capacity_telemetry=dict(status='NOT_STARTED', source_totals=None, closed=False))
    trace = lease = selected = observer = None
    report = {}
    workspace_cleanup = False
    deadline = _capacity_time.monotonic() + _CAPACITY_FIXED['driver']
    try:
        import capacity_trace
        budgets = _capacity_budgets(capacity_trace.BUDGETS)
        _capacity_need(not _capacity_sys.flags.optimize and type(args.copy_seconds) is int and
                       args.copy_seconds == budgets['copy'] and type(args.seconds) is int and
                       args.seconds == budgets['driver'], 'explicit capacity-only finite copy/driver selection')
        before, after = selection(args.source_root)
        scale, bound = runtime_module.scale, runtime_module.scale.bound
        config = scale.configuration(args.scale, args.scale_sha256)
        need(config['platform_mode'] == 'generic-development' and config['before_lock_sha256'] == BEFORE and
             config['after_lock_sha256'] == AFTER and len(before) == len(after) == 607,
             'exact generic607 source configuration required')
        data = bound.install.private(_CapacityPath(args.data), _capacity_os.geteuid())
        need(not any(data.iterdir()), 'fresh driver data directory required')
        workspace, source = _CapacityPath(args.workspace), _CapacityPath(args.source)
        need(source.is_absolute() and workspace.is_absolute() and '..' not in source.parts + workspace.parts and
             not data.is_relative_to(workspace) and not workspace.is_relative_to(data) and
             not data.is_relative_to(source) and not source.is_relative_to(data), 'driver data/copy/source overlap refused')
        trace = capacity_trace.from_args(args)
        observer = _CapacityObservation(args, before, config, copy_module, trace)
        selected = bind(copy_module, trace, budgets, observer)
        observer.emit = selected.capacity_event
        limits = config['limits']
        copy_limits = selected.roots.Limits(deadline=min(deadline, _capacity_time.monotonic() + budgets['copy']),
              max_nodes=limits['root_nodes'], max_bytes=limits['root_bytes'], max_file_bytes=limits['file_bytes'],
              max_package_files=limits['package_files'])
        lease = _CapacityLease(data, workspace, selected.roots,
                               selected._copy_binding(copy_limits)._root_check)
        lease.open(copy_limits)
        result['phase'] = 'copy'
        result['copy_cleanup'] = 'UNKNOWN'
        selected.capacity_event('COPY_CONTEXT', 'BEGIN')
        with selected.copied_root(source, workspace, limits=copy_limits,
                                  cleanup_seconds=budgets['copy_workspace_cleanup']) as (root, report):
            need(report['copy']['copy_complete'] is True and report['copy']['excluded'] == [] and
                 report['copy'].get('copy_byte_identical_before_initialization') is True,
                 'complete byte-identical supplied-source copy required')
            result['initial_copy_byte_identical'] = True
            args.root = str(root)
            bound.guard(root, workspace)
            lease.check(copy_limits)
            need(len(observer.receipts) == 3, 'all three fresh guarded copy observations required')
            need(not _capacity_os.path.lexists(workspace / 'aux-initialization-started'),
                 'capacity must stop before initialization')
            result['observations'] = observer.receipts
            result['lifetime_inverse'] = dict(selected.capacity_lifetime_inverse)
            need(result['lifetime_inverse'].get('whole_inverse') is True,
                 'complete private cleanup-only lifetime inverse required')
            copy_limits.tick()
            result['phase'] = 'copy-cleanup'
        result['copy_cleanup'] = report.get('cleanup', 'UNKNOWN')
        workspace_cleanup = result['copy_cleanup'] == 'PASS-owned-workspace-removed'
        need(workspace_cleanup, 'owned copy disposal not confirmed')
        result['copy_report_sha256'] = _capacity_digest(report)
        result['copy'] = {k: report['copy'][k] for k in ('source_nodes', 'copied_nodes', 'logical_bytes',
                        'source_hardlink_entries', 'source_allocated_bytes', 'copy_complete')}
        selected.capacity_event('COPY_CONTEXT', 'END', details=dict(cleanup=result['copy_cleanup']))
    except BaseException as error:
        result.update(status='FAIL', error_type=type(error).__name__, error='CAPACITY_GUARD_REFUSED',
                      copy_cleanup=report.get('cleanup', result['copy_cleanup']))
    finally:
        result['cleanup_order'].append(dict(role='copy_workspace', status=result['copy_cleanup']))
        lease_receipt = dict(role='control_lease', status='NOT_CREATED')
        if lease is not None:
            try:
                selected.capacity_event('CONTROL_LEASE_CLEANUP', 'BEGIN')
                roots = selected.roots
                cleanup = roots.Limits(deadline=min(deadline, _capacity_time.monotonic() + budgets['control_lease_cleanup']))
                # Only a successful real lifetime permits release of the control marker.
                lease_receipt = lease.retire(cleanup, workspace_cleanup)
            except BaseException as error:
                lease_receipt.update(status='RETAINED_OR_UNCERTAIN', error_type=type(error).__name__)
            selected.capacity_event('CONTROL_LEASE_CLEANUP',
                      'END' if lease_receipt['status'] == 'PASS_OWNED_CONTROL_LEASE_REMOVED' else 'FAIL',
                      details=dict(status=lease_receipt['status']))
        result['cleanup_order'].append(lease_receipt)
        complete = workspace_cleanup and lease_receipt['status'] == 'PASS_OWNED_CONTROL_LEASE_REMOVED'
        result['capacity_cleanup'] = dict(scope='OWNED_COPY_WORKSPACE_THEN_CONTROL_LEASE',
                  status='PASS' if complete else 'NOT_VERIFIED', ordered=result['cleanup_order'],
                  workspace_absence_verified=complete)
        if complete and 'error_type' not in result and _capacity_time.monotonic() < deadline:
            result.update(status='PASS', phase='completed')
        if selected is not None and selected.capacity_telemetry_errors:
            result.update(status='FAIL', trace_error_type='CapacityTelemetryFailure')
        if trace is not None:
            try:
                details = dict(status=result['status'], cleanup=result['cleanup_order'])
                if selected is None:
                    trace.event('COMPLETE', 'FAIL', details=details)
                else:
                    selected.capacity_event('COMPLETE', 'END' if result['status'] == 'PASS' else 'FAIL',
                                            details=details)
                    result['capacity_telemetry_errors'] = list(selected.capacity_telemetry_errors)
                    if result['capacity_telemetry_errors']:
                        result.update(status='FAIL', trace_error_type='CapacityTelemetryFailure')
            except BaseException as error:
                result.update(status='FAIL', trace_error_type=type(error).__name__)
            finally:
                try:
                    trace.close()
                except BaseException as error:
                    result.update(status='FAIL', trace_error_type=type(error).__name__)
                try:
                    result['capacity_telemetry'] = trace.summary()
                    if result['status'] == 'PASS':
                        _capacity_need(result['capacity_telemetry'].get('closed') is True and
                                       result['capacity_telemetry'].get('source_totals') is not None,
                                       'closed capacity telemetry with actual source totals required')
                except BaseException as error:
                    result.update(status='FAIL', trace_error_type=type(error).__name__)
        if result['status'] == 'PASS' and _capacity_time.monotonic() >= deadline:
            result.update(status='FAIL', error_type='TimeoutError', error='CAPACITY_DRIVER_DEADLINE')
    return result
