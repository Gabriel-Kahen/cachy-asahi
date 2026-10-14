"""Proposed pre-checkout clock issuer; no project imports or actor dispatch."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
from contextlib import contextmanager


def need(value, code):
    if not value:
        raise ValueError(code)


def node(info):
    return tuple(getattr(info, field) for field in ('st_dev', 'st_ino', 'st_mode',
        'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def absolute(value):
    path = Path(value)
    need(path.is_absolute() and '..' not in path.parts, 'absolute-path-required')
    return path


def close_owned(descriptor):
    cause = sys.exc_info()[1]
    try:
        os.close(descriptor)
    except BaseException:
        if cause is None:
            raise


@contextmanager
def directory(path):
    path = absolute(path)
    descriptors = [os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)]
    seen = []
    current = Path('/')
    cause = None
    try:
        for part in path.parts[1:]:
            descriptors.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY |
                os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptors[-1]))
            current /= part
            info = os.fstat(descriptors[-1])
            seen.append((current, node(info)[:5]))
        yield descriptors[-1]
        need(all(node(path.lstat())[:5] == before for path, before in seen),
             'ancestor-identity-drift')
    except BaseException as error:
        cause = error
        raise
    finally:
        first = None
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except BaseException as error:
                first = first or error
        if first is not None and cause is None:
            raise first


def domain():
    info = time.get_clock_info('monotonic')
    need(info.monotonic and not info.adjustable and type(info.resolution) is float
         and 0 < info.resolution <= 1 and 'CLOCK_MONOTONIC' in info.implementation,
         'clock-domain-refused')
    with open('/proc/sys/kernel/random/boot_id', 'rb') as stream:
        boot = stream.read(128).strip().decode('ascii')
    need(re.fullmatch('[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot),
         'clock-domain-refused')
    before = os.stat('/proc/self/ns/time')
    fd = os.open('/proc/self/ns/time', os.O_RDONLY | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
    finally:
        close_owned(fd)
    after = os.stat('/proc/self/ns/time')
    need((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino) ==
         (after.st_dev, after.st_ino) and opened.st_dev >= 0 and opened.st_ino > 0,
         'clock-domain-refused')
    with open('/proc/self/timens_offsets', 'rb') as stream:
        offsets = stream.read(1024)
    need(len(offsets) < 1024 and {tuple(line.split()) for line in offsets.splitlines()} ==
         {(b'monotonic', b'0', b'0'), (b'boottime', b'0', b'0')}, 'clock-domain-refused')
    return {'clock_id': 'CLOCK_MONOTONIC', 'boot_id': boot,
            'time_namespace_device': opened.st_dev, 'time_namespace_inode': opened.st_ino}


def alive(end):
    now = time.monotonic()
    need(type(now) in (int, float) and math.isfinite(now) and now > 0 and now < end,
         'issuer-deadline-exceeded')


def private_reference(reference, checkout, limit, end):
    path, pin = reference
    path = absolute(path)
    need(not path.is_relative_to(checkout) and '\n' not in str(path) and
         '\r' not in str(path) and re.fullmatch('[0-9a-f]{64}', pin), 'reference-refused')
    alive(end)
    with directory(path.parent) as parent:
        owner = os.fstat(parent)
        need(stat.S_IMODE(owner.st_mode) == 0o700 and owner.st_uid == os.geteuid(),
             'private-parent-required')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                     os.O_CLOEXEC, dir_fd=parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and stat.S_IMODE(before.st_mode) == 0o600
                 and before.st_nlink == 1 and before.st_uid == os.geteuid()
                 and 0 < before.st_size <= limit, 'private-file-required')
            size = 0
            sha = hashlib.sha256()
            while True:
                alive(end)
                chunk = os.read(fd, min(65536, limit + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                need(size <= limit, 'reference-byte-bound')
                sha.update(chunk)
            need(node(before) == node(os.fstat(fd)) ==
                 node(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) and
                 size == before.st_size and sha.hexdigest() == pin, 'reference-drift')
        finally:
            close_owned(fd)
    alive(end)
    return str(path), pin


def project_library_runtime_check(grant_path, grant_pin, deadline):
    """Observe the bootstrap-selected tool under the original clock, no execution."""
    alive(deadline)
    grant_fd = os.open(grant_path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        info = os.fstat(grant_fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid() and
             stat.S_IMODE(info.st_mode) == 0o600 and 0 < info.st_size <= 8*1024**2,'project-grant-custody')
        body = bytearray()
        while True:
            alive(deadline);chunk = os.read(grant_fd,65536);alive(deadline)
            if not chunk:break
            body.extend(chunk);need(len(body) <= 8*1024**2,'project-grant-bound')
        need(len(body) == info.st_size and hashlib.sha256(body).hexdigest() == grant_pin,'project-grant-pin')
        grant = json.loads(body)
    finally:
        close_owned(grant_fd)
    row = grant.get('project_library_runtime')
    if row is None:return
    need(type(row) is dict and set(row) == {'gpgv','docker'},'project-tool-binding')
    for name,path in (('gpgv','/usr/bin/gpgv'),('docker','/usr/bin/docker')):
        tool = row[name]
        expected = {'path','sha256','identity'} | ({'endpoint_identity'} if name == 'docker' else set())
        need(type(tool) is dict and set(tool) == expected and tool['path'] == path and
             type(tool['sha256']) is str and re.fullmatch('[0-9a-f]{64}',tool['sha256']) and
             type(tool['identity']) is list and len(tool['identity']) == 9 and
             all(type(x) is int for x in tool['identity']),'project-tool-binding')
        limit = (128 if name == 'docker' else 8)*1024**2
        fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            fields = ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
            identity = lambda info:[getattr(info,key) for key in fields]
            need(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and stat.S_IMODE(before.st_mode) == 0o755
                 and before.st_nlink == 1 and 0 < before.st_size <= limit and identity(before) == tool['identity'],
                 'project-tool-custody')
            proof = hashlib.sha256();size = 0
            while True:
                alive(deadline);body = os.read(fd,65536);alive(deadline)
                if not body:break
                size += len(body);need(size <= limit,'project-tool-bound');proof.update(body)
            need(size == before.st_size and proof.hexdigest() == tool['sha256'] and
                 identity(os.fstat(fd)) == identity(Path(path).lstat()) == tool['identity'],'project-tool-drift')
        finally:
            close_owned(fd)
    endpoint = Path('/run/docker.sock').lstat()
    expected = row['docker']['endpoint_identity']
    need(type(expected) is list and len(expected) == 6 and all(type(x) is int for x in expected) and
         stat.S_ISSOCK(endpoint.st_mode) and endpoint.st_uid == 0 and expected == [endpoint.st_dev,
             endpoint.st_ino,endpoint.st_mode,endpoint.st_uid,endpoint.st_gid,endpoint.st_nlink],'project-socket-binding')
    alive(deadline)


def issue(environment, source_sha256, execution_grant, runtime_contract):
    """References are selected externally; this function creates only the clock."""
    issued = time.monotonic()
    need(type(issued) in (int, float) and math.isfinite(issued) and issued > 0,
         'clock-unavailable')
    end = issued + 10800
    need(math.isfinite(end) and end > issued, 'clock-unavailable')
    need(type(source_sha256) is str and re.fullmatch('[0-9a-f]{64}', source_sha256),
         'issuer-source-refused')
    values = {}
    for name, expression in (('GITHUB_SHA', '[0-9a-f]{40}'),
            ('GITHUB_WORKFLOW_SHA', '[0-9a-f]{40}'), ('GITHUB_RUN_ID', '[1-9][0-9]{0,19}'),
            ('GITHUB_RUN_ATTEMPT', '[1-9][0-9]{0,9}')):
        value = environment.get(name)
        need(type(value) is str and re.fullmatch(expression, value), 'workflow-identity-refused')
        values[name] = value
    need(values['GITHUB_SHA'] == values['GITHUB_WORKFLOW_SHA'], 'workflow-identity-refused')
    checkout = absolute(environment['GITHUB_WORKSPACE'])
    temporary = absolute(environment['RUNNER_TEMP'])
    env_file = absolute(environment['GITHUB_ENV'])
    need(not temporary.is_relative_to(checkout) and not env_file.is_relative_to(checkout),
         'outside-checkout-required')
    clock_domain = domain()
    grant_path, grant_pin = private_reference(execution_grant, checkout, 8 * 1024**2, end)
    runtime_path, runtime_pin = private_reference(runtime_contract, checkout, 16 * 1024, end)
    project_library_runtime_check(grant_path,grant_pin,end)
    value = {'schema_version': 1, 'purpose': 'development-workflow-clock',
        'source_commit': values['GITHUB_SHA'], 'run_id': values['GITHUB_RUN_ID'],
        'run_attempt': values['GITHUB_RUN_ATTEMPT'], 'nonce': os.urandom(16).hex(),
        'issued_monotonic': issued, 'deadline_monotonic': end, 'allowance_seconds': 10800,
        'clock_domain': clock_domain, 'issuer_source_sha256': source_sha256,
        'issuer_workflow_commit': values['GITHUB_WORKFLOW_SHA']}
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    need(0 < len(raw) <= 16 * 1024, 'clock-byte-bound')
    alive(end)
    private = clock = owned_clock = private_node = None
    try:
        with directory(temporary):
            private = Path(tempfile.mkdtemp(prefix='development-clock-', dir=temporary))
            private_node = node(private.lstat())[:5]
        clock = private / 'clock.json'
        with directory(private) as parent:
            fd = os.open(clock.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
            try:
                owned_clock = node(os.fstat(fd))[:2]
                offset = 0
                while offset < len(raw):
                    alive(end)
                    count = os.write(fd, raw[offset:])
                    need(count > 0, 'clock-write-failed')
                    offset += count
                os.fsync(fd)
                before = os.fstat(fd)
                need(stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1 and
                     before.st_size == len(raw) and node(before) ==
                     node(os.stat(clock.name, dir_fd=parent, follow_symlinks=False)), 'clock-file-drift')
            finally:
                close_owned(fd)
        bindings = {'DEVELOPMENT_CLOCK_PATH': str(clock),
            'DEVELOPMENT_CLOCK_SHA256': hashlib.sha256(raw).hexdigest(),
            'DEVELOPMENT_EXECUTION_GRANT_PATH': grant_path,
            'DEVELOPMENT_EXECUTION_GRANT_SHA256': grant_pin,
            'DEVELOPMENT_RUNTIME_CONTRACT_PATH': runtime_path,
            'DEVELOPMENT_RUNTIME_CONTRACT_SHA256': runtime_pin}
        block = ''.join(name + '=' + item + '\n' for name, item in bindings.items()).encode()
        need(len(block) <= 4096 and '\n' not in str(clock) and '\r' not in str(clock), 'env-bound')
        alive(end)
        need(domain() == clock_domain, 'clock-domain-drift')
        with directory(env_file.parent) as parent:
            fd = os.open(env_file.name, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW |
                         os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
            try:
                info = os.fstat(fd)
                need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                     info.st_uid == os.geteuid() and info.st_size <= 65536 and
                     node(info) == node(os.stat(env_file.name, dir_fd=parent, follow_symlinks=False)),
                     'workflow-env-file-refused')
                alive(end)
                need(os.write(fd, block) == len(block), 'workflow-env-short-write')
                os.fsync(fd)
                after = os.fstat(fd)
                need(node(info)[:6] == node(after)[:6] and
                     after.st_size == info.st_size + len(block) and node(after) ==
                     node(os.stat(env_file.name, dir_fd=parent, follow_symlinks=False)),
                     'workflow-env-file-drift')
            finally:
                close_owned(fd)
        alive(end)
        return bindings
    except BaseException:
        # No authority is claimed after partial publication; retain first cause.
        if clock is not None:
            try:
                with directory(clock.parent) as parent:
                    if node(os.stat(clock.name, dir_fd=parent, follow_symlinks=False))[:2] == owned_clock:
                        os.unlink(clock.name, dir_fd=parent)
            except BaseException:
                pass
        if private is not None:
            try:
                with directory(private.parent) as parent:
                    if node(os.stat(private.name, dir_fd=parent, follow_symlinks=False))[:5] == private_node:
                        os.rmdir(private.name, dir_fd=parent)
            except BaseException:
                pass
        raise


if __name__ == '__main__':
    issue(os.environ, ISSUER_SOURCE_SHA256, EXECUTION_GRANT, RUNTIME_CONTRACT)
