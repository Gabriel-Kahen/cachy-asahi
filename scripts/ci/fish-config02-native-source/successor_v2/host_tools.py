# SPDX-License-Identifier: MIT
"""Finite host executable observations, streamed whole pins and pre-use rejoin.

No PATH lookup, process execution, installation or privilege change occurs here.
"""
import hashlib
import os
from pathlib import Path
import re
import stat

NAMES = ('systemd-run', 'systemctl', 'dockerd', 'docker', 'fallocate', 'losetup',
         'mkfs.ext4', 'mount', 'umount', 'python3', 'gpg', 'bsdtar', 'zstd')
CANDIDATES = {name: ('/usr/bin/'+name, '/usr/sbin/'+name) for name in NAMES}
CI_CANDIDATES={name:('/usr/bin/'+name,) for name in ('apt-get','apt-cache','dpkg','dpkg-query')}
MAX_BINARY = 256*1024**2
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')


def need(ok, why):
    if not ok:
        raise ValueError(why)


def metadata(info):
    return {name: getattr(info, name) for name in FIELDS}


def _chain(path, root, uid):
    result = []
    for member in reversed((path, *path.parents)):
        if member != root and root not in member.parents:
            continue
        info = member.lstat()
        need(info.st_uid == uid, 'root-owned executable path chain')
        row = dict(path=str(member), metadata=metadata(info))
        if stat.S_ISLNK(info.st_mode):
            row['link'] = os.readlink(member)
        else:
            need(not info.st_mode & 0o022, 'non-writable executable path chain')
        result.append(row)
    return result


def inspect(candidate, *, root=Path('/'), trusted_uid=0):
    """Observe one fixed candidate; root/uid overrides are inert fixture seams.

    Operational callers use the default host root and uid 0, never input/env
    selected filesystem roots or owners.
    """
    need(candidate in {p for rows in (*CANDIDATES.values(),*CI_CANDIDATES.values()) for p in rows}, 'fixed host tool candidate')
    root = Path(root)
    need(root.is_absolute() and root == root.resolve(), 'canonical executable observation root')
    path = root/candidate.lstrip('/')
    path.lstat()  # Distinguish absent candidates from malformed/dangling aliases.
    try:
        target = path.resolve(strict=True)
    except FileNotFoundError as error:
        raise ValueError('present dangling executable alias') from error
    relative = target.relative_to(root)
    need(str(relative.parent) in ('usr/bin', 'usr/sbin'), 'canonical executable in finite host directories')
    name = Path(candidate).name
    aliases = {name}
    if name == 'mkfs.ext4':
        aliases.add('mke2fs')
    need(target.name in aliases or name == 'python3' and re.fullmatch(r'python3\.[0-9]{1,2}', target.name),
         'explicit executable alias only')
    chain = _chain(path, root, trusted_uid)
    target_chain = _chain(target, root, trusted_uid)
    fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_uid == trusted_uid and before.st_nlink >= 1
             and 0 < before.st_size <= MAX_BINARY and before.st_mode & 0o111 and not before.st_mode & 0o022
             and os.access(target, os.X_OK), 'root-owned executable non-writable bounded ordinary binary')
        digest, size = hashlib.sha256(), 0
        while block := os.read(fd, min(65536, MAX_BINARY+1-size)):
            size += len(block)
            need(size <= MAX_BINARY, 'whole executable size cap')
            digest.update(block)
        need(size == before.st_size and metadata(before) == metadata(os.fstat(fd)) == metadata(target.lstat())
             and chain == _chain(path, root, trusted_uid) and target_chain == _chain(target, root, trusted_uid)
             and target == path.resolve(strict=True), 'unchanged whole executable and alias chain')
        return dict(candidate=candidate, path=str(target), metadata=metadata(before),
                    bytes=size, sha256=digest.hexdigest(), chain=chain, target_chain=target_chain)
    finally:
        os.close(fd)


def probe_all(observer=None):
    observer = inspect if observer is None else observer
    rows = {}
    for name, candidates in CANDIDATES.items():
        attempts, accepted, invalid = [], [], False
        for candidate in candidates:
            try:
                row = observer(candidate)
                accepted.append(row)
                attempts.append(dict(candidate=candidate, status='OBSERVED', observation=row))
            except FileNotFoundError:
                attempts.append(dict(candidate=candidate, status='MISSING'))
            except (OSError, ValueError, RuntimeError) as error:
                invalid = True
                attempts.append(dict(candidate=candidate, status='INVALID', error=type(error).__name__, message=str(error)[:240]))
        selected = accepted[0] if accepted and not invalid else None
        rows[name] = dict(status='OBSERVED' if selected else 'HOLD', selected=selected, candidates=attempts)
    return dict(kind='FISH02_HOST_TOOL_OBSERVATIONS_V1', tools=rows,
                missing_or_invalid=[name for name in NAMES if rows[name]['selected'] is None])


def checked(row):
    current = inspect(row['candidate'])
    need(current == row, 'host executable/alias/metadata/body drift before use')
    return current['path']
