#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""One exact-commit Git DATA delivery, without checkout or fetched execution.

Adapted from Batch129 owner.transport and legacy_prefill.prove. See the companion
documentation for exact source hashes, deltas and acceptance boundaries.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import resource
import stat
import subprocess
import sys
import time
import urllib.parse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'virtual'))
import owned_process as op

MAX_PROFILE = 2 * 1024**2
MAX_FILE, MAX_TOTAL, MAX_FILES = 128 * 1024**2, 2 * 1024**3, 4096
MAX_LOG = 4 * 1024**2
GIT = '/usr/bin/git'
SHA1 = re.compile(r'[0-9a-f]{40}\Z')
SHA256 = re.compile(r'[0-9a-f]{64}\Z')


class Error(ValueError):
    pass


def need(ok, why):
    if not ok:
        raise Error(why)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def write_at(parent, name, raw):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    try:
        view = memoryview(raw)
        while view:
            n = os.write(fd, view); need(n > 0, 'short receipt/log write'); view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)


def reference_policy():
    return dict(fetch_seconds=400, transport_seconds=480, outer_seconds=500,
                reason='Explicit one-fetch allocation for full retained DATA; no measured latency guarantee')


def policy_check(policy):
    need(type(policy) is dict and set(policy) == {'fetch_seconds', 'transport_seconds', 'outer_seconds', 'reason'},
         'explicit finite operator policy required')
    for key in ('fetch_seconds', 'transport_seconds', 'outer_seconds'):
        value = policy[key]
        need(type(value) in (int, float) and math.isfinite(value) and value > 0, 'finite positive policy seconds')
    need(policy['fetch_seconds'] < policy['transport_seconds'] < policy['outer_seconds'] <= 3600,
         'fetch < transport < caller outer <= 3600 seconds required')
    need(type(policy['reason']) is str and 0 < len(policy['reason']) <= 4096 and
         all(ord(c) >= 32 for c in policy['reason']), 'operator budget reason required')


def absolute(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and not str(path).startswith('//'),
         'absolute path without aliases required')
    return path


def directory(path):
    path = absolute(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def relative(name):
    need(type(name) is str and 0 < len(name) <= 1024 and
         re.fullmatch(r'[A-Za-z0-9_@+.,:/=\-]+', name), 'bounded ASCII material path required')
    path = PurePosixPath(name)
    need(not path.is_absolute() and path.as_posix() == name and
         all(p not in ('.', '..') and p.lower() != '.git' for p in path.parts), 'unsafe material path')
    return path


def profile_check(raw, checksum, source):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_PROFILE and type(checksum) is str and
         SHA256.fullmatch(checksum) and pin(raw)['sha256'] == checksum, 'whole immutable profile SHA256 required')
    need(type(source) is str and SHA1.fullmatch(source), 'exact 40-hex expected source required')
    def pairs(items):
        value = {}
        for key, item in items:
            need(key not in value, 'duplicate profile JSON key'); value[key] = item
        return value
    def invalid(value):
        raise Error('profile floating/nonfinite number refused')
    try:
        profile = json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    except (ValueError, UnicodeError) as error:
        raise Error('invalid immutable profile') from error
    need(type(profile) is dict and set(profile) in
         ({'schema', 'actual', 'source', 'ref', 'files'}, {'schema', 'actual', 'source', 'ref', 'files', 'modes'}),
         'existing retained carrier profile fields required')
    need(type(profile['schema']) is int and profile['schema'] == 1 and profile['actual'] is None and
         profile['source'] == source, 'source-only profile/expected commit mismatch')
    need(type(profile['ref']) is str and 0 < len(profile['ref']) <= 512 and
         all(32 <= ord(c) < 127 for c in profile['ref']), 'retained descriptive ref required')
    files = profile['files']
    need(type(files) is dict and 0 < len(files) <= MAX_FILES, 'finite whole profile file map required')
    total = 0
    for name, row in files.items():
        relative(name)
        need(type(row) is dict and set(row) == {'bytes', 'sha256'} and type(row['bytes']) is int and
             0 <= row['bytes'] <= MAX_FILE and type(row['sha256']) is str and SHA256.fullmatch(row['sha256']),
             'exact bounded material size/SHA256 required')
        need(not any(p.as_posix() in files for p in relative(name).parents if p != PurePosixPath('.')),
             'profile file/directory collision')
        total += row['bytes']
    need(total <= MAX_TOTAL, 'whole material byte cap exceeded')
    if 'modes' in profile:
        need(type(profile['modes']) is dict and len(profile['modes']) <= 16 and
             all(type(k) is str and 0 < len(k) <= 128 and type(v) is int and 0 <= v <= MAX_FILES
                 for k, v in profile['modes'].items()), 'descriptive profile modes invalid')
    return profile


def source_url(url, fixture):
    need(type(fixture) is bool and type(url) is str and 0 < len(url) <= 4096 and
         all(32 < ord(c) < 127 for c in url) and '\\' not in url, 'explicit safe source URL required')
    parsed = urllib.parse.urlsplit(url)
    need(not parsed.query and not parsed.fragment and not parsed.username and not parsed.password and
         '?' not in url and '#' not in url and '@' not in parsed.netloc, 'credential/query/fragment refused')
    if fixture:
        need(parsed.scheme == 'file' and not parsed.netloc and '%' not in parsed.path,
             'fixture requires explicit local file URL')
        path = absolute(parsed.path); fd = directory(path)
        try:
            info = os.fstat(fd)
            need(info.st_uid == os.getuid() and not info.st_mode & 0o022, 'owned private local Git fixture required')
        finally:
            os.close(fd)
    else:
        need(parsed.scheme == 'https' and parsed.hostname and parsed.port in (None, 443) and '%' not in parsed.netloc,
             'public standard-port HTTPS source required')
    return url


class Delivery:
    def __init__(self, destination, deadline, policy):
        self.path = destination; self.deadline = deadline; self.policy = policy
        self.fd = directory(destination); self.info = os.fstat(self.fd); self.rows = []

    def tick(self):
        need(time.monotonic() < self.deadline, 'aggregate transport deadline exhausted')
        check = directory(self.path)
        try:
            current = os.fstat(check)
            need((current.st_dev, current.st_ino) == (self.info.st_dev, self.info.st_ino) and
                 current.st_uid == os.getuid() and stat.S_IMODE(current.st_mode) == 0o700,
                 'delivery directory ownership/identity lost')
        finally:
            os.close(check)

    def write(self, name, raw):
        self.tick()
        parent = directory((self.path/name).parent)
        try:
            write_at(parent, Path(name).name, raw)
        finally:
            os.close(parent)

    def command(self, argv, *, seconds=30, stdout_limit=None, material=None):
        if stdout_limit is None: stdout_limit = MAX_LOG
        self.tick(); number = len(self.rows); stem = f'logs/{number:04d}'
        row = dict(number=number, argv=list(map(str, argv)), raw_stdout=stem+'.stdout',
                   raw_stderr=stem+'.stderr', passed=False)
        self.rows.append(row)
        logs = directory(self.path/'logs')
        stdout = os.open(f'{number:04d}.stdout', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=logs)
        try:
            cap = min(seconds, self.deadline - time.monotonic())
            need(cap > .02, 'insufficient bounded child budget')
            retirement = min(1, cap / 4); grace = min(.2, retirement / 4)
            def limits():
                # Metadata diagnostics are pipe-bounded separately. A fetch
                # writes packfiles too: never cap those at the tiny log limit.
                maximum = max(1, stdout_limit) if material is not None else MAX_TOTAL+MAX_FILE
                resource.setrlimit(resource.RLIMIT_FSIZE, (maximum, maximum))
            env = dict(PATH=os.defpath, LANG='C', LC_ALL='C', HOME=str(self.path/'empty-home'),
                       GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_SYSTEM='/dev/null',
                       GIT_NO_REPLACE_OBJECTS='1', GIT_OPTIONAL_LOCKS='0', GIT_NO_LAZY_FETCH='1',
                       GIT_TERMINAL_PROMPT='0', GIT_ATTR_NOSYSTEM='1')
            op.prepare()
            child = subprocess.Popen(row['argv'], cwd=self.path, env=env, stdin=subprocess.DEVNULL,
                                     stdout=stdout if material is not None else subprocess.PIPE,
                                     stderr=subprocess.PIPE if material is not None else subprocess.STDOUT,
                                     start_new_session=True, preexec_fn=limits)
            outcome = op.supervise(child, cap=cap, retirement=retirement, grace=grace,
                                   streams=(child.stderr if material is not None else child.stdout,),
                                   max_output=MAX_LOG if material is not None else stdout_limit)
            output = outcome.pop('output'); row['supervision'] = outcome
            stderr = output if material is not None else b''
            if material is None:
                view = memoryview(output)
                while view:
                    n = os.write(stdout, view); need(n > 0, 'short raw output write'); view = view[n:]
                os.fsync(stdout)
                row['stdout_streams'] = 'STDOUT_AND_STDERR_MERGED_AT_SPAWN'
            else:
                row['stdout_streams'] = 'BLOB_STDOUT; SEPARATE_STDERR'
            # No wait, poll, numeric signal or probe follows custody transfer.
            write_at(logs, f'{number:04d}.stderr', stderr)
            row['stderr_pin'] = pin(stderr)
            need(outcome['passed'], 'owned child failed; consult numbered raw logs and supervision receipt')
            self.tick()
        finally:
            os.close(stdout)
            os.close(logs)
        body = self.path/(stem+'.stdout')
        if material is not None:
            expected, oid, mode, name = material
            value = self.file_pin(body, stdout_limit, blob=True)
            need(value['sha256'] == expected['sha256'] and value['bytes'] == expected['bytes'] and
                 value['git_blob'] == oid, 'full Git/blob/profile SHA256 mismatch')
            target = self.path/'data'/name
            need(not os.path.lexists(target), 'fresh DATA material required')
            source_parent = directory(body.parent); target_parent = directory(target.parent)
            try:
                fd = os.open(body.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=source_parent)
                try: os.fchmod(fd, mode)
                finally: os.close(fd)
                os.link(body.name, target.name, src_dir_fd=source_parent, dst_dir_fd=target_parent,
                        follow_symlinks=False)
                os.unlink(body.name, dir_fd=source_parent)
                os.fsync(target_parent)
            finally:
                os.close(source_parent); os.close(target_parent)
            row['raw_stdout'] = 'data/'+name
            row['stdout_material'] = dict(**value, mode=mode); row['passed'] = True
            return None
        raw = self.read(body, stdout_limit)
        row['stdout_pin'] = pin(raw); row['passed'] = True
        return raw

    def read(self, path, limit):
        value, raw = self.file_pin(path, limit, contents=True)
        need(pin(raw) == value, 'raw log bytes differ')
        return raw

    def file_pin(self, path, limit, *, blob=False, contents=False):
        self.tick(); path = absolute(path); parent = directory(path.parent)
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        finally:
            os.close(parent)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid() and
                 0 <= before.st_size <= limit, 'ordinary bounded single-link DATA/log file required')
            sha256 = hashlib.sha256(); sha1 = hashlib.sha1(b'blob '+str(before.st_size).encode()+b'\0'); count = 0
            chunks = [] if contents else None
            while True:
                self.tick(); chunk = os.read(fd, min(1024**2, limit-count+1))
                if not chunk: break
                count += len(chunk); need(count <= limit, 'DATA byte cap'); sha256.update(chunk); sha1.update(chunk)
                if contents: chunks.append(chunk)
            need(count == before.st_size and identity(before) == identity(os.fstat(fd)), 'DATA/log file changed')
            value = dict(bytes=count, sha256=sha256.hexdigest())
            if blob: value['git_blob'] = sha1.hexdigest()
            return (value, b''.join(chunks)) if contents else value
        finally:
            os.close(fd)

    def receipt(self, report):
        # After a timeout retain evidence through the held directory descriptor;
        # never write a guessed/replaced path or launch another actor.
        write_at(self.fd, 'receipt.json', encoded(dict(report, commands=self.rows)))
        os.fsync(self.fd)


def tree_oid(table):
    """Reconstruct Git's complete recursive tree (Batch129 legacy_prefill proof)."""
    root = {}
    for name, row in table.items():
        node = root; parts = name.split('/')
        for part in parts[:-1]: node = node.setdefault(part, {})
        node[parts[-1]] = (row['mode'], row['oid'])
    def digest(node):
        raw = bytearray()
        for name, value in sorted(node.items(), key=lambda item: (item[0]+('/' if type(item[1]) is dict else '')).encode()):
            mode, oid = ('40000', digest(value)) if type(value) is dict else value
            raw.extend(mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(oid))
        return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    return digest(root)


def namespace(delivery, files, table):
    actual = set(); dirs = set(); root = delivery.path/'data'
    expected_dirs = {p.as_posix() for name in files for p in relative(name).parents if p != PurePosixPath('.')}
    for base, directories, names in os.walk(root, followlinks=False):
        delivery.tick()
        for name in tuple(directories):
            path = Path(base)/name; info = path.lstat()
            need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o022,
                 'ordinary owned DATA directory required')
            rel = path.relative_to(root).as_posix()
            if rel == '.git': directories.remove(name)
            else: dirs.add(rel)
        for name in names:
            path = Path(base)/name; rel = path.relative_to(root).as_posix()
            need(rel in files, 'unexpected DATA file')
            need(delivery.file_pin(path, files[rel]['bytes']) == files[rel] and
                 stat.S_IMODE(path.stat().st_mode) == (0o755 if table[rel]['mode'] == '100755' else 0o644),
                 'final DATA hash/size/mode differs')
            actual.add(rel)
    need(actual == set(files) and dirs == expected_dirs, 'full DATA filesystem namespace differs')
    git = root/'.git'
    need(not any(os.path.lexists(git/p) for p in ('objects/info/alternates', 'commondir', 'info/grafts')),
         'Git external object/replace ancestry refused')
    metadata_bytes = 0
    for path in git.rglob('*'):
        delivery.tick(); info = path.lstat()
        need(info.st_uid == os.getuid() and not info.st_mode & 0o022 and
             (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_nlink == 1),
             'ordinary owned unaliased Git metadata required')
        if stat.S_ISREG(info.st_mode): metadata_bytes += info.st_size
        need(metadata_bytes <= MAX_TOTAL+MAX_FILE, 'Git metadata aggregate byte cap')


def _deliver(*, url, expected_source, profile_raw, profile_sha256, destination, executable_root,
            policy, fixture_local=False):
    started = time.monotonic()
    need(type(policy) is dict, 'explicit policy object required')
    policy = dict(policy); policy_check(policy)
    profile = profile_check(profile_raw, profile_sha256, expected_source)
    source_url(url, fixture_local)
    destination, executable_root = absolute(destination), absolute(executable_root)
    code = directory(executable_root); os.close(code)
    need(Path(__file__).resolve().is_relative_to(executable_root), 'executable root must contain this source-owned API')
    need(not destination.is_relative_to(executable_root) and not executable_root.is_relative_to(destination),
         'fresh DATA destination must be disjoint from executable tree')
    need(destination.name not in ('', '.', '..'), 'fresh explicit DATA destination required')
    parent = directory(destination.parent)
    try:
        info = os.fstat(parent)
        need(info.st_uid == os.getuid() and not info.st_mode & 0o022, 'owned non-writable DATA parent required')
        os.mkdir(destination.name, 0o700, dir_fd=parent)
    finally:
        os.close(parent)
    delivery = Delivery(destination, started+policy['transport_seconds'], policy)
    report = dict(schema_version=1, status='FAIL_RETAINED_GIT_DATA', fixture=fixture_local,
                  source=expected_source, url=url, profile_sha256=profile_sha256, policy=policy,
                  file_count=len(profile['files']), material_bytes=sum(v['bytes'] for v in profile['files'].values()),
                  destination=str(destination), retry=False, partial_data_retained=True,
                  signature_authentication='NOT_RUN', native_build='NOT_RUN', trust_admission=False,
                  release_acceptance=False, source_code_execution='NOT_RUN', fetch_attempts=0)
    try:
        for name in ('data', 'logs', 'empty-home'):
            os.mkdir(name, 0o700, dir_fd=delivery.fd)
        delivery.write('expected-profile.json', profile_raw)
        git = [GIT, '-c', 'credential.helper=', '-c', 'http.extraHeader=', '-c', 'http.sslVerify=true',
               '-c', 'http.followRedirects=false', '-c', 'http.proxy=', '-c', 'core.hooksPath=/dev/null',
               '-c', 'core.attributesFile=/dev/null', '-c', 'core.fsmonitor=false', '-c', 'gc.auto=0',
               '-c', 'maintenance.auto=false', '-c', 'fetch.writeCommitGraph=false',
               '-c', 'protocol.allow=never', '-c', 'protocol.'+('file' if fixture_local else 'https')+'.allow=always']
        git_dir = destination/'data/.git'
        delivery.command([*git, 'init', '--bare', '--object-format=sha1', '--template=', str(git_dir)], seconds=10)
        git += ['--git-dir='+str(git_dir)]
        report['fetch_attempts'] = 1
        delivery.command([*git, '-c', 'http.lowSpeedLimit=65536', '-c', 'http.lowSpeedTime=60',
                          '-c', 'fetch.fsckObjects=true', 'fetch', '--depth=1', '--no-tags',
                          '--no-recurse-submodules', url, expected_source], seconds=policy['fetch_seconds'])
        fetched = delivery.command([*git, 'rev-parse', '--verify', 'FETCH_HEAD']).strip()
        need(fetched == expected_source.encode(), 'fetched source differs from exact expected commit')
        commit = delivery.command([*git, 'cat-file', 'commit', expected_source], stdout_limit=65536)
        need(hashlib.sha1(b'commit '+str(len(commit)).encode()+b'\0'+commit).hexdigest() == expected_source,
             'full immutable Git commit hash differs')
        first = commit.split(b'\n', 1)[0]
        need(first.startswith(b'tree ') and SHA1.fullmatch(first[5:].decode('ascii')), 'exact Git commit root tree required')
        tree = first[5:].decode('ascii')
        raw_tree = delivery.command([*git, 'ls-tree', '-rz', '--full-tree', expected_source])
        table = {}
        for raw in raw_tree.split(b'\0'):
            if not raw: continue
            header, name = raw.split(b'\t', 1); mode, kind, oid = header.decode('ascii').split(); name = name.decode('ascii')
            relative(name)
            need(kind == 'blob' and mode in ('100644', '100755') and SHA1.fullmatch(oid) and
                 name in profile['files'] and name not in table, 'whole ordinary Git tree membership differs')
            table[name] = dict(mode=mode, oid=oid)
        need(set(table) == set(profile['files']) and tree_oid(table) == tree, 'complete Git tree/manifest closure differs')
        directories = sorted({p.as_posix() for name in table for p in relative(name).parents
                              if p != PurePosixPath('.')}, key=lambda s: (s.count('/'), s))
        for name in directories:
            delivery.tick(); target = destination/'data'/name; parent = directory(target.parent)
            try: os.mkdir(target.name, 0o700, dir_fd=parent)
            finally: os.close(parent)
        for name, row in sorted(table.items()):
            want = profile['files'][name]
            delivery.command([*git, 'cat-file', 'blob', row['oid']], stdout_limit=want['bytes'],
                             material=(want, row['oid'], 0o755 if row['mode'] == '100755' else 0o644, name))
        delivery.command([*git, 'update-ref', '--no-deref', 'HEAD', expected_source])
        head = delivery.command([*git, 'rev-parse', '--verify', 'HEAD']).strip()
        need(head == expected_source.encode(), 'DATA HEAD differs')
        namespace(delivery, profile['files'], table); delivery.tick()
        report.update(status='PASS_EXACT_RETAINED_GIT_DATA_ONLY', tree=tree,
                      blob_joins=len(table), full_namespace=True, data_path=str(destination/'data'))
        return report
    except BaseException as error:
        report['error'] = type(error).__name__+': '+str(error)[:2048]
        raise Error(report['error']) from error
    finally:
        report['elapsed_seconds'] = time.monotonic()-started
        try: delivery.receipt(report)
        finally: os.close(delivery.fd)


def deliver(*, url, expected_source, profile_raw, profile_sha256, destination, executable_root,
            policy, fixture_local=False):
    """Source-owned one-shot API. Refusals raise Error; created DATA is retained."""
    try:
        return _deliver(url=url, expected_source=expected_source, profile_raw=profile_raw,
                        profile_sha256=profile_sha256, destination=destination,
                        executable_root=executable_root, policy=policy, fixture_local=fixture_local)
    except Error:
        raise
    except (OSError, ValueError) as error:
        raise Error(type(error).__name__+': '+str(error)[:2048]) from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('url', 'expected-source', 'profile', 'profile-sha256', 'destination', 'executable-root', 'policy'):
        parser.add_argument('--'+name, required=True)
    args = parser.parse_args(argv)
    try:
        profile_path = absolute(args.profile); parent = directory(profile_path.parent)
        try:
            fd = os.open(profile_path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            try:
                before = os.fstat(fd)
                need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= MAX_PROFILE,
                     'bounded ordinary profile file required')
                raw = os.read(fd, MAX_PROFILE+1)
                need(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd)), 'profile changed while reading')
            finally: os.close(fd)
        finally: os.close(parent)
        result = deliver(url=args.url, expected_source=args.expected_source, profile_raw=raw,
                         profile_sha256=args.profile_sha256, destination=args.destination,
                         executable_root=args.executable_root, policy=json.loads(args.policy))
        print(encoded(result).decode(), end=''); return 0
    except (Error, OSError, ValueError):
        print('retained-git-transport: refused; retain DATA and inspect receipt/raw logs', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
