# SPDX-License-Identifier: MIT
"""Single private capture of source-issued FDK inner observations; no admission gate."""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading

from evidence import ENTRY_SHA, need, sha

LIMIT = 4096
SOURCE_LIMIT = 128 * 1024
BINDINGS = frozenset(('entry_sha256', 'recipe_sha256', 'observer_sha256', 'selected_sha256', 'layout_sha256'))
GRANT = ('argparse', 'contextlib', 'fcntl', 'hashlib', 'json', 'os', 'pathlib', 're', 'stat', 'sys', 'threading')


def unknown(reason='NOT_OBSERVED', raw_sha256=None):
    return {'availability': 'UNKNOWN', 'reason': reason, 'raw_sha256': raw_sha256, 'observation': None}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def descriptor_identity(info):
    # Inode/type/device identify the opened object; content/permission drift does
    # not transfer this reader's ownership of its existing descriptor.
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode), info.st_rdev


def close_failure(first, later):
    return later if first is None or isinstance(first, Exception) and not isinstance(later, Exception) else first


# Private process-lifetime ownership: ambiguous entries are never auto-cleared.
_UNCERTAIN = {}


def retained_failure(row, failure):
    if row['error'] is None:
        row['error'] = failure
    if not isinstance(failure, Exception) and row['control'] is None:
        row['control'] = failure


def refuse_uncertain():
    if _UNCERTAIN:
        rows = list(_UNCERTAIN.values())
        control = next((row['control'] for row in rows if row['control'] is not None), None)
        raise control if control is not None else ValueError('inner-descriptor-retained')


def release_owned(handle, expected):
    """Three query/close slots; unresolved ownership remains a sticky refusal."""
    row = _UNCERTAIN.setdefault(handle, {'identity': expected, 'error': None, 'control': None})
    if row['identity'] is None or row['identity'] != expected:
        retained_failure(row, ValueError('inner-descriptor-unknown'))
        return row['control'] if row['control'] is not None else row['error']
    for _ in range(3):
        try:
            current = descriptor_identity(os.fstat(handle))
        except BaseException as failure:
            # Linux EBADF alone proves this descriptor is no longer open.
            if isinstance(failure, OSError) and failure.errno == 9:
                del _UNCERTAIN[handle]
                return row['control'] if row['control'] is not None else row['error']
            retained_failure(row, failure)
            continue
        if current != row['identity']:
            retained_failure(row, ValueError('inner-descriptor-drift'))
            return row['control'] if row['control'] is not None else row['error']
        try:
            os.close(handle)
        except BaseException as failure:
            retained_failure(row, failure)
        else:
            del _UNCERTAIN[handle]
            return row['control'] if row['control'] is not None else row['error']
    return row['control'] if row['control'] is not None else row['error']


class RecordUnavailable(ValueError):
    def __init__(self, raw):
        self.raw = raw
        super().__init__('inner-unavailable')


def capture_file(root, name, limit, *, private=False, with_lock=False):
    """Retain every nofollow ancestor and match owned/named descriptors after one read."""
    refuse_uncertain()
    root = Path(root).absolute()
    need('..' not in root.parts and type(name) is str and '/' not in name and name not in ('', '.', '..'),
         'inner-path')
    owned, chain, fd = [], [], None
    def retain(handle):
        owned.append((handle, None))
        try:
            observed = descriptor_identity(os.fstat(handle))
        except BaseException as failure:
            row = _UNCERTAIN.setdefault(handle, {'identity': None, 'error': None, 'control': None})
            retained_failure(row, failure)
            raise
        owned[-1] = (handle, observed)
        return handle
    try:
        directory = retain(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK))
        for part in root.parts[1:]:
            child = retain(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory))
            info = os.fstat(child)
            chain.append((directory, part, child, (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)))
            directory = child
        parent = os.fstat(directory)
        need(parent.st_uid == os.getuid() and parent.st_gid == os.getgid() and
             not stat.S_IMODE(parent.st_mode) & 0o022 and
             (not private or stat.S_IMODE(parent.st_mode) == 0o700), 'inner-directory')
        fd = retain(os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory))
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit and
             before.st_uid == os.getuid() and before.st_gid == os.getgid() and
             (stat.S_IMODE(before.st_mode) == 0o600 if private else not stat.S_IMODE(before.st_mode) & 0o022),
             'inner-file')
        data = bytearray()
        while len(data) <= limit:
            piece = os.read(fd, min(65536, limit + 1 - len(data)))
            if not piece: break
            data.extend(piece)
        need(len(data) == before.st_size and identity(before) == identity(os.fstat(fd)) ==
             identity(os.stat(name, dir_fd=directory, follow_symlinks=False)), 'inner-file-drift')
        healthy = True
        if with_lock:
            try:
                lock = retain(os.open('.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory))
                lock_info = os.fstat(lock)
                need(stat.S_ISREG(lock_info.st_mode) and lock_info.st_nlink == 1 and
                     lock_info.st_uid == os.getuid() and lock_info.st_gid == os.getgid() and
                     stat.S_IMODE(lock_info.st_mode) == 0o600 and lock_info.st_size <= 2048,
                     'inner-lock')
                healthy = lock_info.st_size == 0
                need(identity(lock_info) == identity(os.fstat(lock)) ==
                     identity(os.stat('.lock', dir_fd=directory, follow_symlinks=False)), 'inner-lock-drift')
                need(identity(before) == identity(os.fstat(fd)) ==
                     identity(os.stat(name, dir_fd=directory, follow_symlinks=False)), 'inner-file-drift')
            except Exception as error:
                raise RecordUnavailable(bytes(data)) from error
        for parent_fd, part, child_fd, expected in chain:
            for info in (os.fstat(child_fd), os.stat(part, dir_fd=parent_fd, follow_symlinks=False)):
                need((info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid) == expected,
                     'inner-directory-drift')
        return (bytes(data), healthy) if with_lock else bytes(data)
    finally:
        original, close_error = sys.exc_info()[1], None
        for handle, expected in reversed(owned):
            error = release_owned(handle, expected)
            if error is not None:
                close_error = close_failure(close_error, error)
        if original is None and close_error is not None: raise close_error
        if original is not None and close_error is not None and not isinstance(close_error, Exception) and isinstance(original, Exception):
            raise close_error


def captured_observer(source_root, reviewed):
    raw = capture_file(source_root, 'inner_observation.py', SOURCE_LIMIT)
    need(type(reviewed) is dict and type(reviewed.get('inner_observation.py')) is str and
         re.fullmatch('[0-9a-f]{64}', reviewed['inner_observation.py']) and
         sha(raw) == reviewed['inner_observation.py'], 'inner-source-pin')
    modules = {name: sys.modules[name] for name in GRANT}
    def allowed_import(name, globals=None, locals=None, fromlist=(), level=0):
        need(level == 0 and name in modules and (not fromlist or name == 'pathlib' and tuple(fromlist) == ('Path',)), 'inner-import')
        return modules[name]
    builtins = __builtins__ if type(__builtins__) is dict else vars(__builtins__)
    namespace = {'__name__': 'captured_fdk_inner_observer', '__file__': str(Path(source_root) / 'inner_observation.py'),
                 '__builtins__': dict(builtins, __import__=allowed_import)}
    exec(compile(raw, namespace['__file__'], 'exec'), namespace)
    need(all(callable(namespace.get(name)) for name in ('loads', 'validate', 'binding_values')), 'inner-source-interface')
    return namespace


def source_bindings(reviewed):
    result = {'entry_sha256': ENTRY_SHA, 'recipe_sha256': reviewed.get('PKGBUILD'),
              'observer_sha256': reviewed.get('inner_observation.py'),
              'selected_sha256': reviewed.get('fdk-aac-3.0.0-selected-source.tar'),
              'layout_sha256': reviewed.get('build-layout.json')}
    need(all(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) for value in result.values()), 'inner-source-bindings')
    return result


CONTEXT = frozenset(('schema_version', 'worker_binding', 'source_bindings', 'container_id', 'container_name',
                     'image', 'nonce', 'status', 'running', 'exit_code', 'inspect_sha256'))
STATE = CONTEXT - {'schema_version', 'worker_binding', 'source_bindings'}


def binding_context(config, config_sha, reviewed, observed_state):
    from worker_evidence import binding
    need(type(observed_state) is dict and set(observed_state) == STATE, 'inner-state-shape')
    result = {'schema_version': 1, 'worker_binding': binding(config, config_sha),
              'source_bindings': source_bindings(reviewed), **observed_state}
    validate_context(result, config, config_sha, reviewed)
    return json.loads(canonical(result))


def validate_context(context, config, config_sha, reviewed):
    from worker_evidence import binding
    need(type(context) is dict and set(context) == CONTEXT and
         type(context['schema_version']) is int and context['schema_version'] == 1 and
         context['worker_binding'] == binding(config, config_sha) and
         context['source_bindings'] == source_bindings(reviewed), 'inner-context')
    need(config['action'] in ('build-1', 'build-2') and type(config_sha) is str and
         re.fullmatch('[0-9a-f]{64}', config_sha), 'inner-worker-binding')
    for key in ('container_id', 'inspect_sha256'):
        need(type(context[key]) is str and re.fullmatch('[0-9a-f]{64}', context[key]), 'inner-state-identity')
    need(type(context['container_name']) is str and re.fullmatch('cachy-asahi-[a-z0-9-]{8,96}', context['container_name']) and
         context['image'] == config['image'] and type(context['image']) is str and
         re.fullmatch('sha256:[0-9a-f]{64}', context['image']) and
         context['nonce'] == config['nonce'] and type(context['nonce']) is str and
         re.fullmatch('[0-9a-f]{32}', context['nonce']), 'inner-state-identity')
    need(type(context['status']) is str and context['status'] in ('exited', 'dead') and
         context['running'] is False and type(context['exit_code']) is int and
         0 <= context['exit_code'] <= 255, 'inner-stopped-state')


def check_context(context, group, config, config_sha, reviewed, commands=None, provenance=None):
    from worker_evidence import exit_record
    if group['availability'] != 'BOUND':
        need(context is None, 'inner-context-unavailable')
        return
    validate_context(context, config, config_sha, reviewed)
    need(group['observation']['binding_sha256'] == sha(canonical(context)), 'inner-context-digest')
    if commands is not None:
        expected = exit_record(context['exit_code'])
        need(commands['container'] == commands['attach'] == expected and commands['create'] == exit_record(0),
             'inner-command-binding')
    if provenance is not None:
        need(type(provenance) is dict and provenance.get('clean_environment_id') == context['container_name'] and
             provenance.get('image') == provenance.get('image_id') == context['image'] and
             provenance.get('entry_script_sha256') == ENTRY_SHA and provenance.get('recipe_inputs') == reviewed,
             'inner-provenance-binding')


def capture_inner(directory, source_root, reviewed, config, config_sha, observed_state):
    """Capture once; missing/invalid/unbound evidence never promotes a worker result."""
    try:
        refuse_uncertain()
    except Exception:
        return unknown('UNAVAILABLE')
    try:
        observer = captured_observer(source_root, reviewed)
    except Exception:
        return unknown('SOURCE_INVALID')
    raw = None
    try:
        raw, healthy = capture_file(Path(directory) / 'fdk-inner', 'observation.json', LIMIT,
                                    private=True, with_lock=True)
    except FileNotFoundError:
        return unknown('MISSING')
    except RecordUnavailable as error:
        return unknown('UNAVAILABLE', sha(error.raw))
    except Exception:
        return unknown('UNAVAILABLE')
    stamp = sha(raw)
    if not healthy:
        return unknown('UNAVAILABLE', stamp)
    try:
        value = observer['loads'](raw)
        checked = observer['validate'](value)
        need(type(value) is dict and type(checked) is dict and checked == value and
             set(value) == {'schema_version', 'bindings', 'phase', 'first_failure', 'cancelled', 'write_failed',
               'compiler_attempted', 'compiler_attempt_count', 'compiler_natural_count', 'first_compiler_attempt',
               'first_compiler_natural', 'publication'} and type(value['write_failed']) is bool,
             'inner-validator-result')
    except Exception:
        return unknown('INVALID', stamp)
    if value['write_failed']:
        return unknown('UNAVAILABLE', stamp)
    try:
        context = binding_context(config, config_sha, reviewed, observed_state)
        need(value['bindings'] == context['source_bindings'], 'inner-record-binding')
    except Exception:
        return unknown('UNBOUND', stamp)
    projected = {key: item for key, item in value.items() if key != 'bindings'}
    projected['binding_sha256'] = sha(canonical(context))
    return {'availability': 'BOUND', 'reason': 'OBSERVED', 'raw_sha256': stamp, 'observation': projected}
