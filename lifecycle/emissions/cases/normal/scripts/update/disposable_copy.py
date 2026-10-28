#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Private internal-hardlink copy lifetime for disposable development updates."""
from contextlib import contextmanager
import os
from pathlib import Path
import stat
import time

import full_root as roots
import measure_copy


def need(ok, reason):
    if not ok: raise ValueError(reason)


def _inode(info): return info.st_dev, info.st_ino


def _same(parent, name, fd, inode, mount, limits):
    limits.tick()
    need(_inode(os.fstat(fd)) == inode == _inode(os.stat(name, dir_fd=parent, follow_symlinks=False))
         and roots._mount_id(fd, limits) == mount, 'owned cleanup path or mount drift')


def _empty(fd, mount, limits, spent, depth=0):
    limits.tick(); need(depth <= limits.max_depth, 'owned cleanup depth limit')
    # A separate budget remains available after a copy/update deadline expires.
    with os.scandir(fd) as entries:
        for entry in entries:
            limits.tick(); spent[0] += 1
            need(spent[0] <= limits.max_nodes, 'owned cleanup node limit')
            name = entry.name
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            flags = os.O_CLOEXEC | os.O_NOFOLLOW
            directory = stat.S_ISDIR(info.st_mode)
            flags |= os.O_RDONLY | os.O_DIRECTORY if directory else os.O_PATH
            child = os.open(name, flags, dir_fd=fd)
            try:
                inode = _inode(info)
                _same(fd, name, child, inode, mount, limits)
                if directory:
                    os.fchmod(child, stat.S_IMODE(info.st_mode) | 0o700)
                    _empty(child, mount, limits, spent, depth + 1)
                _same(fd, name, child, inode, mount, limits)
                if directory: os.rmdir(name, dir_fd=fd)
                else: os.unlink(name, dir_fd=fd)
            finally:
                os.close(child)


@contextmanager
def copied_root(source, workspace, *, limits, cleanup_seconds=60, cleanup_extra_nodes=10000):
    """Yield (workspace/root, report); dispose only the newly created workspace.

    Uses the unchanged strict copy policy: absolute links/ldconfig remain refused.
    The owner must stop transaction actors before leaving the context. A process
    kill cannot guarantee cleanup; the outer owner must dispose its container.
    """
    source, workspace = Path(source), Path(workspace)
    need(source.is_absolute() and workspace.is_absolute() and '..' not in source.parts + workspace.parts,
         'absolute contained copy paths required')
    need(not source.is_relative_to(workspace) and not workspace.is_relative_to(source), 'overlapping copy roots')
    need(type(cleanup_seconds) is int and (0 < cleanup_seconds <= 120 or cleanup_seconds == 300)
         and type(cleanup_extra_nodes) is int and 0 <= cleanup_extra_nodes <= 10000,
         'bounded cleanup budgets required')
    parent = roots._open_root(workspace.parent)
    descriptor, created, identity, mount = None, False, None, None
    primary = None
    report = {'cleanup': 'NOT RUN', 'source_mutation': 'NONE', 'transaction_acceptance': 'NOT ESTABLISHED'}
    try:
        parent_info = os.fstat(parent)
        need(parent_info.st_uid == os.geteuid() and not stat.S_IMODE(parent_info.st_mode) & 0o022,
             'owned private copy parent required')
        mount = roots._mount_id(parent, limits)
        os.mkdir(workspace.name, 0o700, dir_fd=parent); created = True
        identity = _inode(os.stat(workspace.name, dir_fd=parent, follow_symlinks=False))
        descriptor = os.open(workspace.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        _same(parent, workspace.name, descriptor, identity, mount, limits)
        target = workspace / 'root'
        report['copy'] = measure_copy.copy_data(source, target, limits=limits,
                                               hardlinks='generic-development-internal')
        yield target, report
    except BaseException as error:
        primary = error
        raise
    finally:
        cleanup_error = None
        try:
            if created:
                need(identity is not None, 'owned workspace identity unavailable; retained')
                cleanup = roots.Limits(deadline=time.monotonic() + cleanup_seconds,
                    max_nodes=limits.max_nodes + cleanup_extra_nodes + 1, max_depth=limits.max_depth)
                if descriptor is None:
                    descriptor = os.open(workspace.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                _same(parent, workspace.name, descriptor, identity, mount, cleanup)
                _empty(descriptor, mount, cleanup, [0], depth=-1)
                _same(parent, workspace.name, descriptor, identity, mount, cleanup)
                # Also check the originally named parent has not been substituted.
                current = roots._open_root(workspace.parent)
                try:
                    need(_inode(os.fstat(current)) == _inode(parent_info)
                         and roots._mount_id(current, cleanup) == mount, 'owned cleanup parent drift')
                finally: os.close(current)
                os.rmdir(workspace.name, dir_fd=parent)
                report['cleanup'] = 'PASS-owned-workspace-removed'
        except BaseException as error:
            cleanup_error = error
            report['cleanup'] = 'FAIL-owned-workspace-retained-or-partial'
            if primary is not None: primary.add_note('owned workspace cleanup failed; dispose outer container')
            else: raise
        finally:
            failed = False
            for fd in ([descriptor] if descriptor is not None else []) + [parent]:
                try: os.close(fd)
                except OSError: failed = True
            if failed:
                report['cleanup'] = 'FAIL-owned-descriptor-cleanup'
                error = primary if primary is not None else cleanup_error
                if error is not None: error.add_note('owned copy descriptor cleanup failed')
                else: raise ValueError('owned copy descriptor cleanup failed')
