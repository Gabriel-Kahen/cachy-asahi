#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-only explicit local VM entry; source mode and templates never execute."""
import argparse
import fcntl
import os
from pathlib import Path
import signal
import stat
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import common as C
import controller as H
import local as L


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--execute', action='store_true')
    for name in ('selection-sha256', 'local-authority-sha256'):
        parser.add_argument('--' + name)
    for name in ('selection', 'local-authority', 'kernel', 'kernel-config', 'kernel-qualification', 'rootfs',
                 'rootfs-manifest', 'rootfs-qualification', 'qemu', 'work', 'output'):
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args()
    C.need(sys.version_info >= (3, 12), 'Python>=3.12')
    C.need(sys.flags.isolated and sys.dont_write_bytecode, 'explicit isolated -I -B local operator')
    if not args.execute:
        H.source(args.source_root)
        C.need(C.decode(C.read(H.HERE / 'local-input-policy.json')) == L.defaults(), 'unbound local template held')
        print(C.encoded(dict(status='ROOT_LOCAL_SOURCE_ONLY_NO_ACTORS', actual_run=None, local_id=None)).decode(), end='')
        return 0
    C.need(all(getattr(args, k) is not None for k in ('selection', 'selection_sha256', 'local_authority',
           'local_authority_sha256', 'kernel', 'kernel_config', 'kernel_qualification', 'rootfs',
           'rootfs_manifest', 'rootfs_qualification', 'qemu', 'work', 'output')), 'all explicit Root local operands')
    def interrupted(*_):
        raise TimeoutError('local owner interruption/deadline')
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGALRM):
        signal.signal(sig, interrupted)
    signal.alarm(C.BOUNDS['owner_seconds'])
    os.umask(0o077)
    local = L.authorize(args)
    lease = local['authority']['lease']
    C.need(set(lease) == {'path', 'device', 'inode', 'uid', 'mode'}, 'exact Root-created exclusive local lease')
    C.need(all(type(lease[k]) is int for k in ('device', 'inode', 'uid', 'mode')), 'typed actual lease identity')
    path = Path(lease['path'])
    C.need(path.is_absolute() and path == path.resolve() and path.parent.stat().st_uid == os.geteuid() and
           stat.S_IMODE(path.parent.stat().st_mode) == 0o700, 'owned0700 local lease parent')
    fd = os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        C.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
               (before.st_dev, before.st_ino, before.st_uid, stat.S_IMODE(before.st_mode)) ==
               (lease['device'], lease['inode'], lease['uid'], lease['mode']) and
               before.st_uid == os.geteuid() and lease['mode'] == 0o600, 'actual pinned local lease identity')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        local['lease_fd'] = fd
        local['lease_observation'] = dict(lease, holder_PID=os.getpid(), acquisition='EXCLUSIVE_NONBLOCKING', release='CLOSE_ONLY')
        report = H.trial(args, local)
        return int(report['status'] != 'OBSERVED_UNPRIVILEGED_BWRAP_SUCCESS')
    finally:
        os.close(fd)
        signal.alarm(0)


if __name__ == '__main__':
    raise SystemExit(main())
