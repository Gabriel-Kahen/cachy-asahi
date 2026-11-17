#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Strict finite held-entry public output snapshot; never reads private trees."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

PACKAGE = 'cachy-asahi-llhttp-reference-9.3.1-1-aarch64'
ROOT_FILES = ('report.json', 'cleanup.json', 'comparison.json', 'pair.json')
BOOTSTRAP = ('bootstrap.json', 'acquisition.json', 'signatures.json', 'package-audit.json',
             'rootfs-inventory.json', 'rootfs-hooks.json', 'cache-checksums.json',
             'packages.lock', 'inputs.lock.json', 'bootstrap.log')
BUILD_FILES = ('provenance.json', 'validation.json', 'expected-packages.lock', 'build.log')
# environment.txt is the fixed uname/pagesize/makepkg-version/package inventory
# output of the pinned builder, never an os.environ/env dump.
ARTIFACTS = ('environment.txt', 'packages.lock', 'config.sha256', 'makepkg.conf', 'pacman.conf',
             'generated.SRCINFO', PACKAGE+'.pkg.tar.xz',
             *(PACKAGE+'-'+phase+'.log' for phase in ('prepare', 'pkgver', 'build', 'check', 'package')))
PUBLIC_LEAVES = ROOT_FILES + tuple('bootstrap/'+n for n in BOOTSTRAP) + tuple(
    'commands/'+f'{index:03d}.'+suffix for index in range(512) for suffix in ('json', 'stdout', 'stderr')) + tuple(
    'build-'+str(build)+'/'+n for build in (1, 2) for n in (*BUILD_FILES, *('artifacts/'+n for n in ARTIFACTS)))
SUCCESS_REQUIRED = ROOT_FILES + tuple('build-'+str(build)+'/'+name for build in (1, 2) for name in
    (*BUILD_FILES, *('artifacts/'+n for n in ('environment.txt', 'packages.lock', 'config.sha256', 'makepkg.conf',
                                          'pacman.conf', 'generated.SRCINFO', PACKAGE+'.pkg.tar.xz', PACKAGE+'-check.log'))))
MAX_BYTES = 16*1024**2
REPORT_FIELDS = {'status', 'natural_outcome', 'cleanup', 'actual_host', 'source', 'source_map_sha256',
                 'canonical_admission', 'canonical_runtime', 'ref', 'run', 'attempt', 'job', 'nonce', 'image',
                 'Root_acceptance', 'hardware', 'release', 'failure', 'packages_lock', 'pair', 'commands', 'retention_failure'}
DECLARATION = dict(kind='STRICT_HELD_ENTRY_PUBLIC_SNAPSHOT_V6', when='finally before existing cleanup',
    input='exact volume/work/llhttp-reference-native only', report_context='same Source/ref/map/run/attempt/job/nonce',
    public_leaves=list(PUBLIC_LEAVES), success_required=list(SUCCESS_REQUIRED),
    max_files=len(PUBLIC_LEAVES)+1, max_bytes=MAX_BYTES,
    private_trees_read=False, recursive_discovery=False, truncate=False,
    missing_or_unstable='nonaccepting; preserve payload failure and always attempt original cleanup',
    acceptance=False, resources_changed=False)


def need(ok, guard):
    if not ok:
        raise ValueError(guard)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def decode(raw):
    def pairs(rows):
        result = {}
        for name, value in rows:
            need(name not in result, 'public-json-duplicate')
            result[name] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False, 'public-json-nonfinite'))


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_uid,
            value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def directory(fd, owner, device):
    value = os.fstat(fd)
    need(stat.S_ISDIR(value.st_mode) and value.st_uid == owner and not value.st_mode & 0o022
         and value.st_dev == device, 'public-directory-identity')


def leaf(root_fd, name, owner, device, remaining):
    """Only literal catalog paths; capability-relative nofollow bounded reads."""
    need(name in PUBLIC_LEAVES, 'public-leaf-not-allowed')
    parts = name.split('/')
    descriptors = [os.dup(root_fd)]
    try:
        for part in parts[:-1]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptors[-1])
            except FileNotFoundError:
                return None
            descriptors.append(child)
            directory(child, owner, device)
        parent = descriptors[-1]
        try:
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        except FileNotFoundError:
            return None
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == owner
                 and before.st_dev == device and not before.st_mode & 0o022
                 and 0 <= before.st_size <= min(MAX_BYTES, remaining), 'public-file-identity-or-budget')
            chunks = []
            left = before.st_size
            while left:
                raw = os.read(fd, min(left, 65536))
                need(bool(raw), 'public-file-short-read')
                chunks.append(raw)
                left -= len(raw)
            need(not os.read(fd, 1), 'public-file-grew')
            need(identity(before) == identity(os.fstat(fd)) == identity(os.stat(parts[-1], dir_fd=parent, follow_symlinks=False)), 'public-file-changed')
            return b''.join(chunks)
        finally:
            os.close(fd)
    finally:
        for fd in reversed(descriptors):
            os.close(fd)


def export(inner, public, expected, owner):
    inner, public = Path(inner), Path(public)
    need(type(owner) is int and owner > 0 and set(expected) == {'source', 'ref', 'source_map_sha256', 'run', 'attempt', 'job', 'nonce'}, 'public-explicit-context')
    need(re.fullmatch('[0-9a-f]{40}', expected['source'] or '') and re.fullmatch('[0-9a-f]{64}', expected['source_map_sha256'] or '')
         and re.fullmatch('[0-9a-f]{32}', expected['nonce'] or '') and expected['attempt'] == 1
         and re.fullmatch(r'refs/heads/codex/[A-Za-z0-9._/-]+', expected['ref'] or '')
         and re.fullmatch('[1-9][0-9]{1,19}', expected['run'] or '') and expected['job'] == 'pair', 'public-context-identity')
    need(inner.is_absolute() and inner == inner.resolve() and not any(p.is_symlink() for p in (inner, *inner.parents))
         and inner.parts[-3:] == ('volume', 'work', 'llhttp-reference-native')
         and public == inner.parents[2]/'evidence' and not public.exists() and not public.is_symlink(), 'public-exact-owned-paths')
    try:
        root = os.open(inner, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return dict(status='NOT_CREATED', accepting=False, files=0, bytes=0)
    rows = {}
    try:
        original = os.fstat(root)
        directory(root, owner, original.st_dev)
        total = 0
        for name in PUBLIC_LEAVES:
            raw = leaf(root, name, owner, original.st_dev, MAX_BYTES-total)
            if raw is not None:
                rows[name] = raw
                total += len(raw)
        need(identity(original) == identity(os.fstat(root)) == identity(inner.lstat()), 'public-root-changed')
    finally:
        os.close(root)
    missing = [n for n in ('report.json', 'cleanup.json') if n not in rows]
    status = None
    if 'report.json' in rows:
        need(len(rows['report.json']) <= 2*1024**2, 'public-report-budget')
        report = decode(rows['report.json'])
        need(set(report) <= REPORT_FIELDS and report['Root_acceptance'] is None
             and report['hardware'] == 'NOT RUN' and report['release'] == 'NOT ADMITTED', 'public-report-schema')
        need(all(report[k] == value for k, value in expected.items()), 'public-report-context')
        status = report['status']
        need(status in ('HOLD', 'HOLD_CLEANUP_OR_CANCELLED', 'HOLD_RETENTION', 'PASS_CURRENT_LLHTTP_REFERENCE_NATIVE_PAIR_ONLY'), 'public-report-status')
        if status == 'PASS_CURRENT_LLHTTP_REFERENCE_NATIVE_PAIR_ONLY':
            missing = [n for n in SUCCESS_REQUIRED if n not in rows]
    record = dict(kind='STRICT_HELD_ENTRY_PUBLIC_SNAPSHOT_V6', status='EXPORTED' if not missing else 'INCOMPLETE',
                  accepting=False, payload_status=status, missing_required=missing, files={n: pin(raw) for n, raw in sorted(rows.items())},
                  source=expected['source'], source_map_sha256=expected['source_map_sha256'], truncation=False,
                  private_trees_read=False, recursive_discovery=False)
    manifest = encode(record)
    need(len(rows)+1 < 4096 and sum(map(len, rows.values()))+len(manifest) <= MAX_BYTES, 'public-whole-budget')
    # Root-owned destination is exclusive and contains only validated public data.
    public.mkdir(mode=0o700)
    for name, raw in (*rows.items(), ('inner-public-manifest.json', manifest)):
        target = public/name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
    return dict(status=record['status'], payload_status=status, accepting=False, files=len(rows)+1,
                bytes=sum(map(len, rows.values()))+len(manifest), manifest=pin(manifest), missing_required=missing)


def refusal(error):
    raw = str(error).encode('utf-8', errors='replace')
    return dict(status='REFUSED', accepting=False, error_class=type(error).__name__ if type(error).__name__ in
                ('ValueError', 'OSError', 'PermissionError', 'FileExistsError', 'FileNotFoundError', 'JSONDecodeError') else 'Exception',
                message_bytes=len(raw), message_prefix_sha256=hashlib.sha256(raw[:8192]).hexdigest(), message_truncated=len(raw) > 8192)


def preserve(report, inner, public, expected, owner):
    """Nonaccepting observation only; cleanup still executes after any refusal."""
    try:
        row = export(inner, public, expected, owner)
    except BaseException as error:
        row = refusal(error)
    report['inner_public_evidence'] = row
    if row['status'] != 'EXPORTED':
        report['status'] = 'HOLD'
    return row
