#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preview or explicitly prune an owned package cache; never install packages."""
import argparse
from contextlib import contextmanager
from functools import cmp_to_key
import hashlib
import gzip
import json
import lzma
import os
from pathlib import Path
import re
import signal
import secrets
import stat
import subprocess
import sys
import tarfile
import time
import zlib
try:
    from compression import zstd
except ImportError:
    zstd = None
COMPRESSION_ERRORS = (OSError, lzma.LZMAError, zlib.error) + ((zstd.ZstdError,) if zstd else ())

NAME = re.compile(r"[A-Za-z0-9@._+-]+\Z")
ARCHIVE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:-]*\.pkg\.tar\.(?:gz|xz|zst)\Z")
SHA = re.compile(r"[0-9a-f]{64}\Z")
MAX_FILES, MAX_ARCHIVE = 4096, 2 * 1024**3


class Error(ValueError):
    pass


class ApplyError(Error):
    def __init__(self, cause, deleted, quarantine):
        super().__init__(str(cause) or type(cause).__name__)
        self.deleted, self.quarantine = deleted, quarantine
        self.cancelled = isinstance(cause, KeyboardInterrupt)
        self.cleanup_notes = getattr(cause, '__notes__', [])


def need(ok, message):
    if not ok:raise Error(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    need(len(raw) <= 8 * 1024**2, 'JSON input exceeds bound')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key');result[key] = value
        return result
    def invalid(value):raise Error('noninteger JSON number')
    return json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)


def identity(info):
    return {key: getattr(info, 'st_' + key) for key in ('dev', 'ino', 'uid', 'mode', 'nlink', 'size', 'mtime_ns', 'ctime_ns')}


@contextmanager
def roots(cache, database):
    paths, fds = [], []
    try:
        for value in (cache, database):
            path = Path(value).absolute()
            need(not str(path).startswith('//') and '..' not in path.parts and
                 not any(p.is_symlink() for p in (path, *path.parents)), 'directory aliases/symlinks forbidden')
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW);fds.append(fd)
            info = os.fstat(fd)
            need(info.st_uid == os.geteuid() and not info.st_mode & 0o022, 'directories must be owned and not group/other writable')
            need((info.st_dev, info.st_ino) == (path.stat().st_dev, path.stat().st_ino), 'directory changed')
            paths.append(path)
        need(not paths[0].is_relative_to(paths[1]) and not paths[1].is_relative_to(paths[0]), 'cache and database must not overlap')
        yield paths, fds
    finally:
        for fd in fds:os.close(fd)


def guard(paths, fds):
    for path, fd in zip(paths, fds):
        current = path.stat(follow_symlinks=False);held = os.fstat(fd)
        need(stat.S_ISDIR(current.st_mode) and (current.st_dev, current.st_ino) == (held.st_dev, held.st_ino), 'directory replaced')


def exists(fd, name):
    try:os.stat(name, dir_fd=fd, follow_symlinks=False);return True
    except FileNotFoundError:return False


def policy_check(policy):
    need(type(policy) is dict and set(policy) == {'schema_version', 'retain_versions', 'known_packages', 'protected'}, 'policy schema')
    need(type(policy['schema_version']) is int and policy['schema_version'] == 1 and
         type(policy['retain_versions']) is int and 3 <= policy['retain_versions'] <= MAX_FILES, 'retain at least three versions')
    known = set()
    for row in policy['known_packages']:
        need(type(row) is dict and set(row) == {'name', 'arch'} and NAME.fullmatch(row['name']) and
             row['arch'] in ('any', 'aarch64'), 'known package identity')
        known.add((row['name'], row['arch']))
    need(known and len(known) == len(policy['known_packages']) <= MAX_FILES, 'finite unique known packages')
    protected = policy['protected']
    need(type(protected) is list and 0 < len(protected) <= MAX_FILES, 'explicit rollback archives required')
    for row in protected:
        need(type(row) is dict and set(row) == {'filename', 'name', 'version', 'arch', 'sha256'} and
             ARCHIVE.fullmatch(row['filename']) and (row['name'], row['arch']) in known and SHA.fullmatch(row['sha256']) and
             type(row['version']) is str and 0 < len(row['version']) <= 256 and not re.search(r'[\s\x00]', row['version']), 'protected archive identity')
    need(len({r['filename'] for r in protected}) == len(protected), 'duplicate protected filename')
    return known


def archive_metadata(stream, filename):
    # Drain the decompressor through EOF as well as reading tar members: tar's
    # end marker alone does not establish the compression trailer's integrity.
    if filename.endswith('.gz'):decoder = gzip.GzipFile(fileobj=stream)
    elif filename.endswith('.xz'):decoder = lzma.LZMAFile(stream)
    else:
        need(zstd is not None, 'zstd reader unavailable; archive retained')
        decoder = zstd.ZstdFile(stream)
    with decoder:
        return tar_metadata(decoder)


def tar_metadata(stream):
    deadline, total, names, found = time.monotonic() + 30, 0, set(), None
    with tarfile.open(fileobj=stream, mode='r|') as archive:
        for member in archive:
            name = member.name.removeprefix('./').rstrip('/')
            if name in ('', '.') and member.isdir():continue
            need(name and not name.startswith('/') and '..' not in Path(name).parts and name not in names, 'unsafe/duplicate archive member')
            names.add(name);total += member.size
            need(len(names) <= 65536 and total <= 8 * 1024**3 and time.monotonic() < deadline, 'archive inspection bound')
            if member.isfile():
                need(name != '.PKGINFO' or member.size <= 1024**2, 'package metadata exceeds bound')
                source = archive.extractfile(member);data = bytearray() if name == '.PKGINFO' else None
                while block := source.read(1024**2):
                    need(time.monotonic() < deadline, 'archive inspection deadline')
                    if data is not None:data.extend(block)
                if data is not None:found = bytes(data)
    while block := stream.read(1024**2):
        total += len(block)
        need(total <= 8 * 1024**3 and time.monotonic() < deadline, 'compression trailer bound')
    need(found is not None, 'package metadata missing')
    fields = {}
    for line in found.decode().splitlines():
        if line and not line.startswith('#'):
            key, value = line.split(' = ', 1);fields.setdefault(key, []).append(value)
    need(all(len(fields.get(k, [])) == 1 for k in ('pkgname', 'pkgver', 'arch')), 'package metadata identity')
    name, version, arch = (fields[k][0] for k in ('pkgname', 'pkgver', 'arch'))
    need(NAME.fullmatch(name) and arch in ('any', 'aarch64') and 0 < len(version) <= 256 and
         not re.search(r'[\s\x00]', version) and fields.get('license'), 'unsupported package metadata')
    return {'name': name, 'version': version, 'arch': arch}


def record(fd, name):
    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
    result = {'filename': name, 'identity': identity(info), 'action': 'unknown'}
    if not ARCHIVE.fullmatch(name) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or \
       info.st_uid != os.geteuid() or info.st_mode & 0o022 or not 0 < info.st_size <= MAX_ARCHIVE:
        return result
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    with os.fdopen(descriptor, 'rb') as stream:
        need(identity(os.fstat(stream.fileno())) == result['identity'], 'archive replaced while opening')
        try:
            package = archive_metadata(stream, name)
        except (Error, tarfile.TarError, UnicodeError, ValueError, EOFError) + COMPRESSION_ERRORS:
            return result  # Corrupt/unsupported objects remain untouched, never deletion candidates.
        stream.seek(0);checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
        need(identity(os.fstat(stream.fileno())) == result['identity'], 'archive changed while inspecting')
    result.update(package=package, sha256=checksum)
    return result


def version_compare(left, right):
    process = subprocess.run(['vercmp', left, right], capture_output=True, timeout=10, check=True)
    return int(process.stdout.strip())


def plan_for(paths, fds, policy):
    known = policy_check(policy);guard(paths, fds)
    names = sorted(os.listdir(fds[0]));need(len(names) <= MAX_FILES, 'cache member bound')
    entries = [record(fds[0], name) for name in names]
    by_name = {row['filename']: row for row in entries}
    for pin in policy['protected']:
        row = by_name.get(pin['filename'], {})
        need(row.get('package') == {k: pin[k] for k in ('name', 'version', 'arch')} and row.get('sha256') == pin['sha256'], 'protected rollback archive missing/changed: ' + pin['filename'])
    for package, arch in sorted(known):
        rows = [row for row in entries if row.get('package', {}).get('name') == package and row['package']['arch'] == arch]
        versions = sorted({row['package']['version'] for row in rows}, key=cmp_to_key(version_compare), reverse=True)
        retained = []
        for version in versions:
            if not any(version_compare(version, kept) == 0 for kept in retained):retained.append(version)
            if len(retained) == policy['retain_versions']:break
        protected = [p['version'] for p in policy['protected'] if (p['name'], p['arch']) == (package, arch)]
        for row in rows:
            version = row['package']['version']
            row['action'] = 'protected' if any(version_compare(version, p) == 0 for p in protected) else \
                'retained' if any(version_compare(version, p) == 0 for p in retained) else 'candidate'
    guard(paths, fds)
    return {'schema_version': 1, 'purpose': 'package-cache-preview', 'cache': str(paths[0]), 'database': str(paths[1]),
            'directory_ids': [{'dev': os.fstat(fd).st_dev, 'ino': os.fstat(fd).st_ino} for fd in fds],
            'policy_sha256': digest(encoded(policy)), 'entries': entries}


def preview(cache, database, policy):
    with roots(cache, database) as (paths, fds):
        need(not exists(fds[1], 'db.lck'), 'ALPM lock exists; active or stale transactions require separate diagnosis')
        return plan_for(paths, fds, policy)


@contextmanager
def transaction_lock(paths, fds):
    fd, held = None, None
    blocked = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
    try:
        fd = os.open('db.lck', os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=fds[1])
        held = os.fstat(fd);os.write(fd, (str(os.getpid()) + '\n').encode());held = os.fstat(fd)
        signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
        yield lambda: need(identity(os.stat('db.lck', dir_fd=fds[1], follow_symlinks=False)) == identity(held), 'owned ALPM lock replaced')
    finally:
        active, failures = sys.exc_info()[1], []
        try:
            signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
            if fd is not None:
                need(held is not None, 'ALPM lock identity unavailable; retained without unlink')
                current = os.stat('db.lck', dir_fd=fds[1], follow_symlinks=False)
                need((current.st_dev, current.st_ino) == (held.st_dev, held.st_ino), 'ALPM lock cleanup uncertain; replacement retained')
                os.unlink('db.lck', dir_fd=fds[1])
        except (OSError, Error, ValueError, KeyboardInterrupt) as error:
            failures.append(('ALPM lock cleanup uncertain', error))
        finally:
            try:
                if fd is not None:os.close(fd)
            except OSError as error:
                failures.append(('ALPM descriptor closure uncertain', error))
            finally:
                try:signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
                except (OSError, ValueError, KeyboardInterrupt) as error:
                    failures.append(('caller signal-mask restoration uncertain', error))
        if failures:
            first = active if active is not None else failures[0][1]
            for label, error in failures:first.add_note(label + ': ' + str(error))
            if active is None:raise first


def same_archive(observed, expected, moved=False):
    left, right = dict(observed), dict(expected)
    left.pop('action', None);right.pop('action', None)
    if moved:
        left['identity'] = {k: v for k, v in left['identity'].items() if k != 'ctime_ns'}
        right['identity'] = {k: v for k, v in right['identity'].items() if k != 'ctime_ns'}
    return left == right


def apply(cache, database, policy, plan, plan_sha256, selected):
    deleted, quarantine = [], None
    try:
        need(SHA.fullmatch(plan_sha256) and digest(encoded(plan)) == plan_sha256, 'preview digest mismatch')
        need(selected and len(set(selected)) == len(selected) and all(type(n) is str and ARCHIVE.fullmatch(n) for n in selected), 'explicit unique archive basenames required')
        with roots(cache, database) as (paths, fds), transaction_lock(paths, fds) as lock_guard:
            need(encoded(plan_for(paths, fds, policy)) == encoded(plan), 'cache, policy or directory identity changed since preview')
            candidates = {r['filename']: r for r in plan['entries'] if r['action'] == 'candidate'}
            need(set(selected) <= candidates.keys(), 'selection contains protected, retained or unknown entries')
            qname = '.package-cache-' + secrets.token_hex(12);quarantine = str(paths[0] / qname)
            os.mkdir(qname, 0o700, dir_fd=fds[0])
            qfd = os.open(qname, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fds[0]);held = os.fstat(qfd)
            try:
                for name in selected:
                    guard(paths, fds);lock_guard()
                    need(same_archive(record(fds[0], name), candidates[name]), 'selected archive changed: ' + name)
                    os.rename(name, name, src_dir_fd=fds[0], dst_dir_fd=qfd)
                    need(same_archive(record(qfd, name), candidates[name], moved=True), 'claimed archive replaced/changed: ' + name)
                    guard(paths, fds);lock_guard()
                    current = os.stat(qname, dir_fd=fds[0], follow_symlinks=False);held = os.fstat(qfd)
                    need((current.st_dev, current.st_ino) == (held.st_dev, held.st_ino), 'quarantine replaced')
                    mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})
                    try:os.unlink(name, dir_fd=qfd);deleted.append(name)
                    finally:signal.pthread_sigmask(signal.SIG_SETMASK, mask)
            finally:
                # Restore without overwriting a concurrent replacement; uncertain
                # bytes stay in the private quarantine for explicit inspection.
                active = sys.exc_info()[1]
                try:
                    for name in os.listdir(qfd):
                        try:
                            os.link(name, name, src_dir_fd=qfd, dst_dir_fd=fds[0], follow_symlinks=False)
                            os.unlink(name, dir_fd=qfd)
                        except OSError:pass
                    if not os.listdir(qfd):
                        current = os.stat(qname, dir_fd=fds[0], follow_symlinks=False)
                        need((current.st_dev, current.st_ino) == (held.st_dev, held.st_ino), 'quarantine cleanup uncertain; replacement retained')
                        os.rmdir(qname, dir_fd=fds[0]);quarantine = None
                except (OSError, Error) as error:
                    if active is not None:active.add_note(str(error))
                    else:raise
                finally:os.close(qfd)
        return {'status': 'applied', 'deleted': deleted, 'retained_quarantine': quarantine}
    except (OSError, Error, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        raise ApplyError(error, deleted, quarantine) from error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('cache', 'db-path', 'policy'):parser.add_argument('--' + name, required=True)
    parser.add_argument('--apply', action='store_true');parser.add_argument('--plan');parser.add_argument('--plan-sha256')
    parser.add_argument('--select', action='append', default=[])
    args = parser.parse_args(argv);policy = decode(Path(args.policy).read_bytes())
    if args.apply:
        need(args.plan and args.plan_sha256, 'apply requires a reviewed preview and its digest')
        raw = Path(args.plan).read_bytes();plan = decode(raw)
        need(raw == encoded(plan) and digest(raw) == args.plan_sha256, 'exact preview bytes/digest required')
        result = apply(args.cache, args.db_path, policy, plan, args.plan_sha256, args.select)
    else:
        need(not (args.plan or args.plan_sha256 or args.select), 'selection requires explicit --apply')
        result = preview(args.cache, args.db_path, policy)
    print(encoded(result).decode(), end='');return 0


def cancelled(signum, frame):
    raise KeyboardInterrupt('cancelled')


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, cancelled)
    try:sys.exit(main())
    except ApplyError as error:
        print(json.dumps({'status': 'stopped', 'error': str(error), 'deleted': error.deleted,
              'retained_quarantine': error.quarantine, 'cleanup_notes': error.cleanup_notes}), file=sys.stderr)
        sys.exit(130 if error.cancelled else 1)
    except KeyboardInterrupt:
        print('package cache preview cancelled', file=sys.stderr);sys.exit(130)
    except (Error, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        print('package cache error: ' + str(error), file=sys.stderr);sys.exit(1)
