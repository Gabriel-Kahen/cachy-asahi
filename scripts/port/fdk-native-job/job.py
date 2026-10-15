#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 cachy-asahi contributors
"""Separate finite same-job original producer and reviewed FDK native stage."""
import argparse
import builtins
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import math
import os
import json
from pathlib import Path
import platform
import re
import secrets
import shutil
import signal
import stat
import sys
import time
import types

sys.path.insert(0, str(Path(__file__).resolve().parent))
import job_runtime as jr
import packet
import evidence
from base_broker import broker_class
import current_cache

HERE = Path(__file__).resolve().parent
ENV_FIELDS = ('GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_REPOSITORY', 'RUNNER_ARCH', 'RUNNER_OS', 'ImageVersion', 'ImageOS')
FDK_KEYS = {'schema_version', 'stage', 'status', 'phase', 'error_code', 'cancelled',
            'owned_container_absence', 'native_build', 'hardware', 'installation',
            'selected_for_release', 'binary_publication', 'worker_diagnostics', 'accepted_outputs'}
FDK_ACTIONS = ('build-1', 'build-2', 'compare')
FROZEN_VIM_FILES = (
    ('vim-9.2.1164-2-aarch64.pkg.tar.xz', 2086796, 'd4f857559e5f0af1cd5a9603d31437ddc8fe35957c11bc6b8670b9a58a80ea73'),
    ('vim-9.2.1164-2-aarch64.pkg.tar.xz.sig', 565, '38e920e436994e6516752f2057974ecd3d284b4be5887a183714175be9169524'),
    ('vim-runtime-9.2.1164-2-aarch64.pkg.tar.xz', 7702256, 'def07038ac8bde14c3c875ea2f37adc199e21bb237d357b1b2f00eb401d4add6'),
    ('vim-runtime-9.2.1164-2-aarch64.pkg.tar.xz.sig', 566, '7481985526069c20b81762bbb308a0df61acf07d316f557d60e330a22627e5e3'),
)


@dataclass(frozen=True)
class FrozenVimInputs:
    inputs_sha256: str
    files: tuple

    def manifest_sha256(self):
        raw = json.dumps({'inputs_sha256':self.inputs_sha256,
            'files':[{'filename':name, 'size':size, 'sha256':pin} for name, size, pin in self.files]},
            sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        return packet.sha(raw)


def frozen_live(deadline):
    try:valid = type(deadline) in (int, float) and math.isfinite(deadline) and time.monotonic() < deadline
    except (OverflowError, TypeError):valid = False
    packet.need(valid, 'frozen-vim-carrier-deadline')


def frozen_stamp(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def frozen_cleanup_note(first, later, note='frozen-vim-owned-fd-cleanup-outcome-unknown'):
    first.add_note(note)
    if isinstance(later, jr.Cancelled):first.frozen_vim_cancelled = True


@contextmanager
def frozen_critical():
    """Block owned job signals through returned-FD registration and restoration.

    This protects legitimate pending signals, not an arbitrary replacement open
    that allocates a descriptor and raises without returning it to this owner.
    """
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, jr.SIGNALS)
    first = None
    try:
        yield
    except BaseException as error:
        first = error
        raise
    finally:
        try:signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        except BaseException as later:
            if first is None:raise
            frozen_cleanup_note(first, later, 'frozen-vim-signal-restoration-outcome-unknown')


@contextmanager
def frozen_defer():
    """Use the existing handler API without letting restoration replace body cause."""
    manager = jr.defer_signals(); events = manager.__enter__(); first = None
    try:
        yield events
    except BaseException as error:
        first = error
    finally:
        try:manager.__exit__(None, None, None)
        except BaseException as later:
            if first is None:first = later
            frozen_cleanup_note(first, later, 'frozen-vim-signal-restoration-outcome-unknown')
    if first is not None:
        if events:first.frozen_vim_cancelled = True
        raise first


@contextmanager
def frozen_fds():
    """Attempt each registered FD close once; preserve the exact first cause."""
    descriptors = []; first = None
    try:
        yield descriptors
    except BaseException as error:
        first = error
    finally:
        try:
            with frozen_critical():
                for fd in reversed(descriptors):
                    try:os.close(fd)
                    except BaseException as later:
                        if first is None:first = later
                        frozen_cleanup_note(first, later)
        except BaseException as later:
            if first is None:first = later
            frozen_cleanup_note(first, later)
        # Never retry an ambiguous close: the integer may now name another FD.
        descriptors.clear()
    if first is not None:raise first


def frozen_names(directory, deadline=None):
    names = set()
    with frozen_fds() as descriptors:
        with frozen_critical():
            fd = os.open('.', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            descriptors.append(fd)
            packet.need(frozen_stamp(os.fstat(fd)) == frozen_stamp(os.fstat(directory)), 'frozen-vim-carrier-directory-drift')
        with os.scandir(fd) as entries:
            for entry in entries:
                if deadline is not None:frozen_live(deadline)
                packet.need(len(names) < 4, 'frozen-vim-carrier-membership')
                names.add(entry.name)
    if deadline is not None:frozen_live(deadline)
    return names


@contextmanager
def frozen_directory(path, deadline):
    """Hold every real parent open; lexical paths must retain the same custody."""
    packet.need(type(path) is type(HERE) and path.is_absolute() and '..' not in path.parts,
                'frozen-vim-carrier-path')
    opened = []
    identity = lambda s:(s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode)
    with frozen_fds() as descriptors:
        for current in (*reversed(path.parents), path):
            frozen_live(deadline)
            before = current.lstat()
            packet.need(stat.S_ISDIR(before.st_mode), 'frozen-vim-carrier-parent')
            with frozen_critical():
                fd = os.open(current.name if opened else str(current),
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    **({'dir_fd':opened[-1][1]} if opened else {}))
                descriptors.append(fd)
                opened.append((current, fd, identity(before)))
                packet.need(identity(os.fstat(fd)) == identity(before), 'frozen-vim-carrier-parent-drift')
        def guard():
            for current, fd, expected in opened:
                frozen_live(deadline)
                packet.need(identity(os.fstat(fd)) == expected == identity(current.lstat()),
                            'frozen-vim-carrier-parent-drift')
        guard()
        yield opened[-1][1], guard


def frozen_read(directory, name, deadline, *, size=None, pin=None, limit=8 * 1024**2):
    frozen_live(deadline)
    before = os.stat(name, dir_fd=directory, follow_symlinks=False)
    packet.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) in (0o400, 0o444, 0o600, 0o644) and
                0 <= before.st_size <= limit and (size is None or before.st_size == size),
                'frozen-vim-carrier-file')
    with frozen_fds() as descriptors:
        with frozen_critical():
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
            descriptors.append(fd)
            packet.need(frozen_stamp(os.fstat(fd)) == frozen_stamp(before), 'frozen-vim-carrier-file-drift')
        chunks = []; total = 0; digest = hashlib.sha256()
        while True:
            frozen_live(deadline)
            block = os.read(fd, min(65536, limit + 1 - total))
            frozen_live(deadline)
            if not block:break
            total += len(block);packet.need(total <= before.st_size, 'frozen-vim-carrier-size')
            digest.update(block);chunks.append(block)
        packet.need(total == before.st_size and (pin is None or digest.hexdigest() == pin) and
                    frozen_stamp(os.fstat(fd)) == frozen_stamp(before) ==
                    frozen_stamp(os.stat(name, dir_fd=directory, follow_symlinks=False)),
                    'frozen-vim-carrier-pin-drift')
        frozen_live(deadline)
        return b''.join(chunks), frozen_stamp(before)


def frozen_vim_inputs(snapshot, deadline):
    with frozen_directory(snapshot / 'scripts/ci', deadline) as (directory, guard):
        raw, _ = frozen_read(directory, 'inputs.lock.json', deadline, pin=packet.INPUTS_SHA)
        guard()
    value = packet.decode(raw); files = []; packages = value.get('packages')
    packet.need(type(packages) is list, 'frozen-vim-carrier-inputs')
    for row in packages:
        frozen_live(deadline)
        packet.need(type(row) is dict, 'frozen-vim-carrier-inputs')
        if row.get('name') not in ('vim', 'vim-runtime'):continue
        packet.need(row.get('version') == '9.2.1164-2' and row.get('arch') == 'aarch64',
                    'frozen-vim-carrier-version')
        packet.need(type(row.get('filename')) is str, 'frozen-vim-carrier-inputs')
        files.extend(((row.get('filename'), row.get('size'), row.get('sha256')),
            (row.get('filename') + '.sig', row.get('signature_size'), row.get('signature_sha256'))))
    packet.need(all(type(name) is str and type(size) is int and 0 < size <= 8 * 1024**2 and
                    type(pin) is str and re.fullmatch('[0-9a-f]{64}', pin) for name, size, pin in files) and
                sorted(files) == sorted(FROZEN_VIM_FILES), 'frozen-vim-carrier-contract')
    return FrozenVimInputs(packet.INPUTS_SHA, tuple(sorted(files)))


def frozen_carrier_options(args, root):
    carrier = getattr(args, 'frozen_vim_carrier', None)
    pin = getattr(args, 'frozen_vim_manifest_sha256', None)
    packet.need(pin is None or type(pin) is str and re.fullmatch('[0-9a-f]{64}', pin), 'frozen-vim-carrier-manifest-pin')
    if carrier is None:
        packet.need(pin is None, 'frozen-vim-carrier-missing')
        return None, None
    packet.need(type(carrier) is type(HERE), 'frozen-vim-carrier-path')
    carrier = carrier.absolute(); out = args.output.absolute()
    packet.need('..' not in carrier.parts and all(not carrier.is_relative_to(other) and
                not other.is_relative_to(carrier) for other in (root, out)), 'frozen-vim-carrier-overlap')
    return carrier, pin


def seed_frozen_vim(snapshot, private, carrier, deadline, manifest_sha256=None):
    """Copy only source-derived original bytes; crypto and producer gates still follow."""
    packet.need(type(carrier) is type(private) is type(snapshot) is type(HERE) and
                carrier.is_absolute() and all(not carrier.is_relative_to(other) and
                not other.is_relative_to(carrier) for other in (snapshot, private.parent, HERE.parents[2])),
                'frozen-vim-carrier-overlap')
    contract = frozen_vim_inputs(snapshot, deadline)
    packet.need(manifest_sha256 is None or type(manifest_sha256) is str and
                manifest_sha256 == contract.manifest_sha256(), 'frozen-vim-carrier-manifest-pin')
    with frozen_directory(carrier, deadline) as (source, source_guard), \
            frozen_directory(private, deadline) as (parent, parent_guard):
        directory = os.fstat(source); owned = os.fstat(parent)
        packet.need(directory.st_uid == owned.st_uid == os.getuid() and
                    stat.S_IMODE(directory.st_mode) in (0o500, 0o700) and
                    stat.S_IMODE(owned.st_mode) == 0o700, 'frozen-vim-carrier-directory')
        source_stamp = frozen_stamp(directory)
        packet.need(frozen_names(source, deadline) == {name for name, _, _ in contract.files}, 'frozen-vim-carrier-membership')
        captured = []
        for name, size, pin in contract.files:
            source_guard(); data, stamp = frozen_read(source, name, deadline, size=size, pin=pin)
            captured.append((name, data, stamp, pin))
        def guard():
            source_guard(); parent_guard(); frozen_live(deadline)
            packet.need(frozen_stamp(os.fstat(source)) == source_stamp and
                        frozen_names(source, deadline) == {name for name, _, _ in contract.files}, 'frozen-vim-carrier-directory-drift')
            for name, _, stamp, _ in captured:
                frozen_live(deadline)
                packet.need(frozen_stamp(os.stat(name, dir_fd=source, follow_symlinks=False)) == stamp,
                            'frozen-vim-carrier-file-drift')
        guard(); cache = None; cache_stamp = None; created = {}; retained = {}
        with frozen_fds() as cache_descriptors:
            try:
                with frozen_critical():
                    with frozen_defer() as pending:
                        os.mkdir('cache', mode=0o700, dir_fd=parent)
                        cache_stamp = os.stat('cache', dir_fd=parent, follow_symlinks=False)
                        cache = os.open('cache', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                        cache_descriptors.append(cache)
                        packet.need(frozen_stamp(os.fstat(cache)) == frozen_stamp(cache_stamp), 'frozen-vim-carrier-cache-drift')
                if pending:raise jr.Cancelled(pending[0])
                def cache_guard():
                    guard();current = os.stat('cache', dir_fd=parent, follow_symlinks=False)
                    packet.need(stat.S_ISDIR(current.st_mode) and current.st_uid == os.getuid() and
                        stat.S_IMODE(current.st_mode) == 0o700 and
                        (current.st_dev, current.st_ino) == (cache_stamp.st_dev, cache_stamp.st_ino) ==
                        (os.fstat(cache).st_dev, os.fstat(cache).st_ino), 'frozen-vim-carrier-cache-drift')
                    for name, stamp in retained.items():
                        frozen_live(deadline)
                        packet.need(frozen_stamp(os.stat(name, dir_fd=cache, follow_symlinks=False)) == stamp,
                                    'frozen-vim-carrier-copy-drift')
                for name, data, _, pin in captured:
                    cache_guard()
                    with frozen_fds() as copy_descriptors:
                        with frozen_critical():
                            with frozen_defer() as pending:
                                fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=cache)
                                copy_descriptors.append(fd)
                                created[name] = os.fstat(fd)
                        if pending:raise jr.Cancelled(pending[0])
                        for offset in range(0, len(data), 65536):
                            cache_guard();block = data[offset:offset + 65536]
                            packet.need(os.write(fd, block) == len(block), 'frozen-vim-carrier-copy-write')
                            cache_guard()
                        os.fsync(fd);frozen_live(deadline)
                    copied, stamp = frozen_read(cache, name, deadline, size=len(data), pin=pin)
                    packet.need(copied == data and stamp[:6] == frozen_stamp(created[name])[:6],
                                'frozen-vim-carrier-copy-pin')
                    retained[name] = stamp;cache_guard()
                cache_guard()
                packet.need(frozen_names(cache, deadline) == set(created) and
                            (cache_stamp.st_dev, cache_stamp.st_ino) ==
                            (os.stat('cache', dir_fd=parent, follow_symlinks=False).st_dev,
                             os.stat('cache', dir_fd=parent, follow_symlinks=False).st_ino), 'frozen-vim-carrier-cache-drift')
                frozen_live(deadline)
            except BaseException as error:
                # Fixed four-file bookkeeping only; no new timer or producer allowance.
                events = []
                try:
                    with frozen_critical(), frozen_defer() as events:
                        if cache_stamp is not None:
                            current = os.stat('cache', dir_fd=parent, follow_symlinks=False)
                            packet.need(stat.S_ISDIR(current.st_mode) and current.st_uid == os.getuid() and
                                (current.st_dev, current.st_ino) == (cache_stamp.st_dev, cache_stamp.st_ino),
                                'frozen-vim-carrier-cache-disposal-custody')
                            packet.need(cache is not None and frozen_names(cache) == set(created), 'frozen-vim-carrier-cache-disposal-membership')
                            for name, before in created.items():
                                info = os.stat(name, dir_fd=cache, follow_symlinks=False)
                                packet.need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and
                                    (info.st_dev, info.st_ino) == (before.st_dev, before.st_ino), 'frozen-vim-carrier-cache-disposal-file')
                            for name in created:os.unlink(name, dir_fd=cache)
                            os.rmdir('cache', dir_fd=parent)
                except BaseException as disposal:
                    error.add_note('frozen-vim-owned-cache-disposal-failed')
                    if isinstance(disposal, jr.Cancelled):error.frozen_vim_cancelled = True
                if events:error.frozen_vim_cancelled = True
                raise
    return contract


def cleanup_observation(value, phases, reasons, refusals):
    keys = {'schema_version', 'scope', 'phase', 'call', 'journal', 'reason', 'boundary_error',
            'observation_error', 'status', 'absence_verified', 'cancelled'}
    if type(value) is not dict or set(value) != keys:
        return None
    if type(value['schema_version']) is not int or value['schema_version'] != 1 or \
            type(value['scope']) is not str or value['scope'] != 'producer-containers':
        return None
    enums = {'phase': phases | {'UNOBSERVED'},
             'call': {'UNOBSERVED', 'not-run', 'started', 'returned', 'raised'},
             'journal': {'UNOBSERVED', 'ABSENT', 'REGULAR', 'OTHER'},
             'reason': reasons | refusals | {'none', 'docker-cleanup-cancellation-uncertain',
                                            'returned-failure', 'malformed-result'},
             'boundary_error': refusals | {'none'}, 'observation_error': refusals | {'none'},
             'status': {'UNOBSERVED', 'PASS', 'FAIL'}}
    if any(type(value[name]) is not str or value[name] not in allowed for name, allowed in enums.items()):
        return None
    if any(type(value[name]) is not bool and not (type(value[name]) is str and value[name] == 'UNOBSERVED')
           for name in ('absence_verified', 'cancelled')):
        return None
    return dict(value)


def producer_cleanup(value, phases, reasons, refusals):
    if type(value) is not dict or set(value) != {'availability', 'observation'} or \
            type(value['availability']) is not str:
        return None
    if value['availability'] == 'UNOBSERVED' and value['observation'] is None:
        return {'availability': 'UNOBSERVED', 'observation': None}
    if value['availability'] != 'OBSERVED':
        return None
    observation = cleanup_observation(value['observation'], phases, reasons, refusals)
    return {'availability': 'OBSERVED', 'observation': observation} if observation is not None else None


def capture_producer_cleanup(private, state):
    """Capture one optional observation; it grants no worker/cleanup admission."""
    if not state.get('producer_cleanup_capture_attempted'):
        state['producer_cleanup_capture_attempted'] = True
        state['producer_cleanup_capture'] = {'availability': 'UNOBSERVED', 'observation': None}
        if state.get('producer_cleanup_allowed') is True:
            try:
                path = private / 'producer-worker.json'
                before = path.lstat()
                packet.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
                            before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o600,
                            'producer-cleanup-capture-owner')
                raw = packet.read(path, 65536)
                after = path.lstat()
                identity = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
                                      s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                packet.need(identity(before) == identity(after), 'producer-cleanup-capture-custody')
                observation = cleanup_observation(packet.decode(raw).get('cleanup_diagnostic'),
                    evidence.PRODUCER_PHASES, evidence.BASE_PROBE_POLICY_CODES, evidence.BASE_PROBE_REFUSALS)
                if observation is not None:
                    state['producer_cleanup_capture'] = {'availability': 'OBSERVED', 'observation': observation}
                    state['producer_cleanup_capture_sha256'] = packet.sha(raw)
            except Exception:
                pass
    captured = state['producer_cleanup_capture']
    return {'availability': captured['availability'],
            'observation': dict(captured['observation']) if captured['observation'] is not None else None}


def validator_from_bytes(captured):
    """Execute authenticated pure bytes with a private, explicit import binding."""
    if type(captured) is not dict or set(captured) != {'evidence.py', 'worker_evidence.py'} or \
            any(type(value) is not bytes or len(value) > 8 * 1024**2 for value in captured.values()):
        raise ValueError('FDK-validator-bytes')
    modules = {name: types.ModuleType('captured_fdk_' + name) for name in ('evidence', 'worker_evidence')}
    def private_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in modules:
            return modules[name]
        return builtins.__import__(name, globals, locals, fromlist, level)
    for name, module in modules.items():
        module.__dict__.update(__file__='captured-fdk-stage/' + name + '.py',
            __builtins__=dict(vars(builtins), __import__=private_import))
        exec(compile(captured[name + '.py'], module.__file__, 'exec'), module.__dict__)
    return modules['worker_evidence']


def authenticated_worker_validator(snapshot, manifest_path, manifest_sha):
    manifest = packet.load(manifest_path, manifest_sha)
    packet.need(type(manifest.get('files')) is dict, 'FDK-validator-manifest')
    captured = {}
    for name in ('stage.lock.json', 'evidence.py', 'worker_evidence.py'):
        relative = packet.ADAPTER + name
        row = manifest['files'][relative]; path = snapshot / relative
        packet.need(type(row) is dict and set(row) == {'sha256', 'mode', 'bytes'} and
                    type(row['mode']) is int and row['mode'] == 0o644 and type(row['bytes']) is int and
                    0 <= row['bytes'] <= 8 * 1024**2, 'FDK-validator-row')
        before = path.lstat(); data = packet.read(path); after = path.lstat()
        identity = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
                              s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        packet.need(before.st_uid == os.getuid() and identity(before) == identity(after) and
                    stat.S_IMODE(before.st_mode) == row['mode'] and len(data) == row['bytes'] and
                    packet.sha(data) == row['sha256'], 'FDK-validator-binding')
        captured[name] = data
    stage_bytes = captured.pop('stage.lock.json')
    packet.need(packet.sha(stage_bytes) == packet.ADAPTER_SHA, 'FDK-validator-stage-pin')
    # The complete packet/source/Git gate ran before this capture. Additionally
    # bind this exact dependency pair to the independently pinned stage lock.
    adapter = packet.decode(stage_bytes)
    for name, data in captured.items():
        packet.need(adapter['files'][packet.ADAPTER + name] == {'sha256': packet.sha(data), 'mode': 0o644},
                    'FDK-validator-stage-row')
    return validator_from_bytes(captured)


def ordinary():
    packet.need(os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid() != 0 and
                platform.system() == 'Linux' and platform.machine() in ('aarch64', 'arm64'), 'native-ordinary-user')
    packet.need(os.environ.get('RUNNER_ARCH') == 'ARM64' and os.environ.get('RUNNER_OS') == 'Linux', 'hosted-ARM-runner')
    with open('/proc/self/status', encoding='ascii') as stream:
        fields = stream.read(65536)
    for name in ('CapEff', 'CapPrm'):
        value = re.search(r'^' + name + r':\s+([0-9a-fA-F]+)$', fields, re.M)
        packet.need(value is not None and int(value[1], 16) == 0, 'ordinary-capabilities')


def output(path, root):
    path = Path(path).absolute()
    packet.need('..' not in path.parts and not path.exists() and not path.is_symlink() and
                not path.is_relative_to(root) and all(stat.S_ISDIR(p.lstat().st_mode) for p in path.parents), 'new-external-job-output')
    path.mkdir(mode=0o700)
    for name in ('private', 'public'):
        (path / name).mkdir(mode=0o700)
    return path


def validate_fdk_record(record, validator):
    packet.need(validator is not None and type(record) is dict and set(record) == FDK_KEYS and
                record['stage'] == 'fdk-native-development' and type(record['schema_version']) is int and
                record['schema_version'] == 3 and record['hardware'] == record['installation'] ==
                record['binary_publication'] == 'NOT RUN' and record['selected_for_release'] is False,
                'FDK-public-schema')
    packet.need(record['status'] in ('PASS', 'FAIL') and
                record['native_build'] == ('PASS' if record['status'] == 'PASS' else 'NOT ACCEPTED') and
                record['phase'] in ('preflight', 'base-probe', 'source', 'build-1', 'build-2', 'compare', 'complete') and
                record['error_code'] == (None if record['status'] == 'PASS' else 'fdk-stage-failed') and
                type(record['cancelled']) is type(record['owned_container_absence']) is bool, 'FDK-public-fields')
    record = packet.decode(json.dumps(record, allow_nan=False).encode())
    record['worker_diagnostics'] = validator.validate_workers(record['worker_diagnostics'],
                                                            require_complete=record['status'] == 'PASS')
    packet.need(record['status'] != 'PASS' or record['phase'] == 'complete' and
                record['cancelled'] is False and record['owned_container_absence'] is True, 'FDK-public-acceptance')
    if record['status'] == 'PASS':
        record['accepted_outputs'] = validator.validate_accepted_outputs(record['accepted_outputs'])
    else:
        packet.need(record['accepted_outputs'] is None, 'FDK-failed-output-provenance')
    return record


def capture_fdk(private, state):
    if not state.get('fdk_capture_attempted'):
        state['fdk_capture_attempted'] = True
        state['fdk_capture'] = None
        try:
            path = private / 'fdk/public/status.json'
            before = path.lstat(); raw = packet.read(path, 65536); after = path.lstat()
            identity = lambda s: (s.st_dev, s.st_ino, s.st_uid, s.st_gid, s.st_mode, s.st_nlink,
                                  s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            packet.need(before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o600 and
                        identity(before) == identity(after), 'FDK-public-owner')
            state['fdk_capture'] = validate_fdk_record(packet.decode(raw), state.get('worker_validator'))
            state['fdk_capture_sha256'] = packet.sha(raw)
        except Exception:
            pass
    return state.get('fdk_capture')


def fdk_public(private, report, state):
    try:
        captured = capture_fdk(private, state)
        packet.need(captured is not None, 'FDK-public-unverified')
        record = packet.decode(json.dumps(captured).encode())
    except Exception:
        kind = 'UNAVAILABLE' if state.get('fdk_attempted') else 'NOT_RUN'
        record = {'schema_version': 3, 'stage': 'fdk-native-development', 'status': 'FAIL', 'phase': 'preflight',
                  'error_code': 'fdk-stage-failed', 'cancelled': False, 'owned_container_absence': False,
                  'native_build': 'NOT ACCEPTED', 'hardware': 'NOT RUN', 'installation': 'NOT RUN',
                  'selected_for_release': False, 'binary_publication': 'NOT RUN', 'accepted_outputs': None,
                  'worker_diagnostics': {name: {'availability': kind,
                      'exit': {'kind': 'UNOBSERVED' if kind == 'UNAVAILABLE' else 'NOT_RUN', 'code': None},
                      'observation': None} for name in FDK_ACTIONS}}
    if evidence.public_status(report)['status'] != 'PASS':
        record.update(status='FAIL', native_build='NOT ACCEPTED', error_code='fdk-stage-failed',
                      cancelled=record['cancelled'] or report['cancelled'], accepted_outputs=None)
    return record


def retire_exports(public):
    producer = public / 'producer'
    if producer.exists():
        packet.need(producer.is_dir() and not producer.is_symlink(), 'public-producer-directory')
        for path in producer.iterdir():
            packet.need(path.name in evidence.PUBLIC_FILES and path.is_file() and not path.is_symlink() and
                        path.lstat().st_uid == os.getuid() and path.lstat().st_nlink == 1, 'public-owned-export')
            path.unlink()
        producer.rmdir()


def write_exports(out, report, state):
    child = fdk_public(out / 'private', report, state)
    if report['status'] == 'PASS' and child['status'] != 'PASS':
        report.update(status='FAIL', fdk={'status': 'FAIL'})
    retire_exports(out / 'public')
    manifest = evidence.publish(out / 'private/producer', out / 'public/producer',
        state.get('image', ''), state.get('native_sha', ''), state['recipes'], report)
    if manifest['status'] != 'PASS':
        report['status'] = 'FAIL'
    fdk = out / 'public/fdk'
    fdk.mkdir(mode=0o700, exist_ok=True)
    packet.save(fdk / 'status.json', fdk_public(out / 'private', report, state))
    packet.save(out / 'private/job-result.json', report)
    status = evidence.public_status(report)
    status['producer_cleanup'] = capture_producer_cleanup(out / 'private', state)
    packet.save(out / 'public/status.json', status)


def retain_producer_diagnostic(private, report):
    # Recover the last durable fixed state even if the outer worker call raised.
    try:
        worker = packet.decode(packet.read(private / 'producer-worker.json', 65536))
        diagnostic = evidence.producer_diagnostic(worker.get('diagnostic'))
    except Exception:
        diagnostic = None
    if diagnostic is not None:
        report['producer_diagnostic'] = diagnostic


def retain_producer_boundary(private, report):
    """Retain only the bounded worker-owned fields, never parent gate claims."""
    try:
        worker = packet.decode(packet.read(private / 'producer-worker.json', 65536))
        boundary = evidence.producer_boundary(worker.get('boundary'), worker=True)
        if boundary is None:
            raise ValueError('boundary-invalid')
        cleanup = worker.get('cleanup')
        cleanup = cleanup if type(cleanup) is dict else {}
        known = {'worker_status': worker.get('status'), 'worker_cancelled': worker.get('cancelled'),
                 'worker_cleanup_status': cleanup.get('status'),
                 'worker_cleanup_absence': cleanup.get('absence_verified'),
                 'worker_cleanup_cancelled': cleanup.get('cancelled')}
        packet.need(all(type(boundary[key]) is str and boundary[key] == 'UNOBSERVED' or
                        type(boundary[key]) is type(actual) and boundary[key] == actual
                        for key, actual in known.items()), 'boundary-invalid')
    except Exception:
        report['producer_boundary'].update(evidence.new_boundary(worker=True))
        if report['producer_boundary']['outer_outcome'] != 'FAIL':
            report['producer_boundary'].update(outer_gate='worker-receipt', outer_outcome='FAIL',
                                               outer_reason='boundary-invalid')
        return None
    report['producer_boundary'].update(boundary)
    return worker


def boundary_save(private, report, gate, outcome, reason='none'):
    report['producer_boundary'].update(outer_gate=gate, outer_outcome=outcome, outer_reason=reason)
    packet.save(private / 'job-result.json', report)


def boundary_failure(private, report, gate, error):
    report['producer_boundary'].update(outer_gate=gate, outer_outcome='FAIL',
                                       outer_reason=evidence.boundary_reason(error))
    try:
        packet.save(private / 'job-result.json', report)
    except BaseException as retry:
        if isinstance(retry, jr.Cancelled):
            report['cancelled'] = True


@contextmanager
def producer_gate(private, report, gate):
    try:
        boundary_save(private, report, gate, 'STARTED')
        yield
        boundary_save(private, report, gate, 'PASS')
    except BaseException as error:
        boundary_failure(private, report, gate, error)
        raise


def finish(out, report, state):
    with jr.defer_signals() as events:
        write_exports(out, report, state)
    if events:
        report.update(status='FAIL', cancelled=True)
        with jr.defer_signals():
            write_exports(out, report, state)
        raise jr.Cancelled(events[0])


def execute(args, state):
    root = args.source_root.absolute()
    packet.need(root == HERE.parents[2] and root == root.resolve(), 'job-source-location')
    carrier, carrier_pin = frozen_carrier_options(args, root)
    packet.need(carrier is None, 'current-seed-separate-carrier-refused')
    out = output(args.output, root)
    private = out / 'private'
    report = {'status': 'FAIL', 'phase': 'preflight', 'cancelled': False,
              'producer': {'status': 'NOT RUN'}, 'fdk': {'status': 'NOT RUN'},
              'cleanup': {'status': 'FAIL', 'owned_image_absence': False}}
    state.update(out=out, report=report, recipes=root / 'scripts/ci/recipes.lock.json')
    broker = None
    try:
        ordinary()
        packet.need(args.execute_native and 1800 <= args.producer_timeout <= 4200 and
                    1800 <= args.fdk_timeout <= 3600 and 5400 <= args.deadline <= 9000 and
                    args.deadline >= args.producer_timeout + args.fdk_timeout + 300, 'job-time-budget')
        packet.need(args.docker_endpoint in ('unix:///run/docker.sock', 'unix:///var/run/docker.sock'), 'original-local-endpoint')
        packet.need(re.fullmatch('[0-9a-f]{40}', args.source_commit or '') and
                    os.environ.get('GITHUB_SHA') == args.source_commit, 'hosted-source-commit')
        packet.need(shutil.disk_usage(private).free >= 8 * 1024**3, 'job-disk-reserve')
        config = private / 'docker-config'
        config.mkdir(mode=0o700)
        env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C', 'HOME': str(private), 'DOCKER_CONFIG': str(config)}
        worker_env = {**env, **{k: os.environ[k] for k in ENV_FIELDS if k in os.environ}}
        runner = jr.Runner(args.deadline, worker_env, private / 'logs')
        git = runner.run(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
                          '--no-optional-locks', '-C', str(root), 'rev-parse', 'HEAD'], timeout=15, limit=4096)
        packet.need(git.returncode == 0 and git.stdout.decode('ascii').strip() == args.source_commit, 'job-Git-commit')
        report['phase'] = 'source'
        report['source'] = packet.verify(root, args.packet, args.packet_sha256, args.source_commit,
                                          runner, private / 'source')
        snapshot = private / 'source'
        state['worker_validator'] = authenticated_worker_validator(snapshot, args.packet, args.packet_sha256)
        packet.save(private / 'source-receipt.json', report['source'])
        state['recipes'] = snapshot / 'scripts/ci/recipes.lock.json'
        state['native_sha'] = packet.sha(packet.read(snapshot / 'scripts/ci/native_arm.py'))
        # Source-owned seed transport spends the original runner endpoint only.
        state['current_cache_runner'] = runner
        try:
            current_cache.seed(snapshot, private, runner, runner.deadline - args.deadline,
                               report['source']['files_map'])
        except BaseException as error:
            state['current_cache_first'] = error
            raise
        finally:
            observed = getattr(runner, 'current_cache_observation', None)
            if type(observed) is dict:
                report['cache_seed'] = dict(observed) # Private record only, no bodies.
                if observed['cancelled']: report['cancelled'] = True
        if carrier is not None:
            packet.need(all(re.fullmatch(expression, os.environ.get(name, '')) for name, expression in
                (('GITHUB_RUN_ID', '[1-9][0-9]{0,19}'), ('GITHUB_RUN_ATTEMPT', '[1-9][0-9]{0,9}'))), 'frozen-vim-carrier-job-identity')
            contract = seed_frozen_vim(snapshot, private, carrier, runner.deadline, carrier_pin)
            frozen_live(runner.deadline)
            packet.save(private / 'frozen-vim-carrier.json', {'inputs_sha256':contract.inputs_sha256,
                'manifest_sha256':contract.manifest_sha256(), 'source_commit':args.source_commit,
                'run_id':os.environ['GITHUB_RUN_ID'], 'run_attempt':os.environ['GITHUB_RUN_ATTEMPT']})
            frozen_live(runner.deadline)
        cls = broker_class(snapshot / packet.ADAPTER)
        jr.Cancelled = cls.runtime.Cancelled
        nonce = secrets.token_hex(16)
        seconds = runner.deadline - time.monotonic()
        cli = cls.runtime.Runner(seconds, {**env, 'DOCKER_BUILDKIT': '0'}, private / 'docker-logs')
        cleanup = cls.runtime.Runner(180, env, private / 'cleanup-logs')
        broker = cls(cli, cleanup, args.docker_binary, args.docker_sha256, args.docker_endpoint,
                     os.getuid(), os.getgid(), private / 'base-image.json', nonce, jobroot=private,
                     context=private / 'producer/context', iidfile=private / 'producer/image-id')
        daemon = broker.initialize()
        cfg = {'snapshot': str(snapshot), 'adapter': str(snapshot / packet.ADAPTER), 'jobroot': str(private),
               'docker_binary': args.docker_binary, 'docker_sha256': args.docker_sha256, 'endpoint': args.docker_endpoint,
               'nonce': nonce, 'daemon': daemon, 'producer_timeout': args.producer_timeout}
        packet.save(private / 'producer-config.json', cfg)
        python = str(Path(sys.executable).resolve())
        report['phase'] = 'producer'
        report['producer_boundary'] = evidence.new_boundary()
        with producer_gate(private, report, 'worker-exit'):
            state['producer_cleanup_allowed'] = True
            produced = runner.run([python, '-I', '-B', str(snapshot / (packet.PREFIX + 'producer.py')),
                '--config', str(private / 'producer-config.json'), '--config-sha256', packet.sha(packet.read(private / 'producer-config.json'))],
                timeout=args.producer_timeout + 30, log='producer.log')
            report['producer_boundary']['worker_return_zero'] = produced.returncode == 0 if type(produced.returncode) is int else 'UNOBSERVED'
            packet.need(type(produced.returncode) is int, 'worker-return-invalid')
            packet.need(report['producer_boundary']['worker_return_zero'], 'worker-exit-nonzero')
        with producer_gate(private, report, 'worker-receipt'):
            worker = retain_producer_boundary(private, report)
            packet.need(worker is not None, 'boundary-invalid')
        retain_producer_diagnostic(private, report)
        for gate, valid, reason in (
                ('worker-status', lambda: worker.get('status') == 'PASS', 'worker-status-not-pass'),
                ('worker-cancelled', lambda: worker.get('cancelled') is False, 'worker-cancelled'),
                ('worker-cleanup-status', lambda: worker.get('cleanup', {}).get('status') == 'PASS', 'worker-cleanup-not-pass'),
                ('worker-cleanup-absence', lambda: worker.get('cleanup', {}).get('absence_verified') is True, 'worker-cleanup-absence-unverified')):
            with producer_gate(private, report, gate):
                packet.need(valid(), reason)
        with producer_gate(private, report, 'producer-receipts'):
            state['image'] = worker['image_id']
            report['producer'] = evidence.validate_producer(private / 'producer', state['image'], state['native_sha'], state['recipes'])
        # Preserve the unchanged four-package result before entering the FDK stage.
        with producer_gate(private, report, 'original-result-retention'):
            original = packet.read(private / 'producer/result.json')
            (private / 'original-result.json').write_bytes(original)
            report['original_result_sha256'] = packet.sha(original)
            packet.save(private / 'producer-acceptance.json', report['producer'])
            accepted = dict(report['producer_boundary'], outer_gate='accepted', outer_outcome='PASS')
            packet.need(evidence.producer_boundary(accepted) is not None, 'boundary-invalid')
        try:
            boundary_save(private, report, 'accepted', 'PASS')
        except BaseException as error:
            boundary_failure(private, report, 'original-result-retention', error)
            raise
        report['phase'] = 'fdk'
        state['fdk_attempted'] = True
        child = runner.run([python, '-I', '-B', str(root / (packet.ADAPTER + 'stage.py')), '--execute-native',
            '--source-root', str(root), '--source-commit', args.source_commit,
            '--lock', str(root / (packet.ADAPTER + 'stage.lock.json')), '--lock-sha256', packet.ADAPTER_SHA,
            '--accepted-result', str(private / 'original-result.json'), '--accepted-result-sha256', packet.sha(original),
            '--bootstrap', str(private / 'producer/bootstrap.json'), '--bootstrap-sha256', packet.sha(packet.read(private / 'producer/bootstrap.json')),
            '--packages', str(private / 'producer/packages.lock'), '--inputs', str(private / 'producer/inputs.lock.json'),
            '--image', state['image'], '--docker-endpoint', args.docker_endpoint, '--docker-binary', args.docker_binary,
            '--docker-sha256', args.docker_sha256, '--output', str(private / 'fdk'), '--deadline', str(args.fdk_timeout),
            '--build-timeout', str((args.fdk_timeout - 300) // 2)], timeout=args.fdk_timeout + 30, log='fdk.log')
        fdk = capture_fdk(private, state)
        packet.need(type(child.returncode) is int and child.returncode == 0 and fdk is not None and
                    fdk.get('status') == 'PASS' and fdk.get('cancelled') is False,
                    'FDK-stage-failed')
        report['fdk'] = {'status': 'PASS', 'receipt_sha256': state['fdk_capture_sha256']}
        report['status'] = 'PASS'
    except jr.Cancelled:
        report.update(status='FAIL', cancelled=True)
    except Exception as error:
        report['error_code'] = 'fdk-native-job-failed'
        if getattr(error, 'frozen_vim_cancelled', False) is True:report['cancelled'] = True
        if report['phase'] in ('producer', 'fdk'):
            report[report['phase']]['status'] = 'FAIL'
    finally:
        with jr.defer_signals() as events:
            report['work_phase'] = report['phase']
            if report['work_phase'] == 'producer':
                retain_producer_diagnostic(private, report)
                if 'producer_boundary' in report:
                    retain_producer_boundary(private, report)
            report['phase'] = 'cleanup'
            if broker is not None:
                journals = [private / 'fdk/private/containers.json'] if (private / 'fdk/private/containers.json').exists() else []
                try:
                    report['cleanup'] = broker.cleanup(remove_image=True, container_journals=journals)
                    report['cancelled'] |= report['cleanup'].get('cancelled') is True
                except BaseException:
                    report['cleanup'] = {'status': 'FAIL', 'owned_image_absence': False}
            if events or report['cancelled'] or report['cleanup'].get('status') != 'PASS' or report['cleanup'].get('owned_image_absence') is not True:
                report.update(status='FAIL', cancelled=report['cancelled'] or bool(events))
            report['phase'] = 'complete'
            finish(out, report, state)
        if events:
            report.update(status='FAIL', cancelled=True)
            with jr.defer_signals():
                finish(out, report, state)
    return int(evidence.public_status(report)['status'] != 'PASS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-native', action='store_true')
    for name in ('source-root', 'packet', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('source-commit', 'packet-sha256', 'docker-endpoint', 'docker-binary', 'docker-sha256'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--deadline', type=int, default=7200)
    parser.add_argument('--producer-timeout', type=int, default=3300)
    parser.add_argument('--fdk-timeout', type=int, default=3000)
    parser.add_argument('--frozen-vim-carrier', type=Path)
    parser.add_argument('--frozen-vim-manifest-sha256')
    args = parser.parse_args()
    state = {}
    try:
        with jr.cancellation_handlers():
            return execute(args, state)
    except (Exception, jr.Cancelled) as error:
        if state:
            state['report'].update(status='FAIL', cancelled=state['report']['cancelled'] or isinstance(error, jr.Cancelled))
            with jr.defer_signals():
                try:
                    finish(state['out'], state['report'], state)
                except BaseException:
                    for path in (state['out'] / 'public/status.json', state['out'] / 'public/fdk/status.json', state['out'] / 'private/job-result.json'):
                        path.unlink(missing_ok=True)
                    retire_exports(state['out'] / 'public')
        print('fdk-native-job-failed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
