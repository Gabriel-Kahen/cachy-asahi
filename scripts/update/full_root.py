#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Per-caller bounded ALPM inventory and descriptor-relative root observations."""
import ctypes as C
from dataclasses import dataclass
import hashlib
import importlib.util
import math
import os
from pathlib import Path
import stat
import time

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location('_full_root_installer', ROOT / 'scripts/install/local_transaction.py')
installer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(installer)


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


@dataclass(frozen=True)
class Limits:
    deadline: float
    max_packages: int = 587
    max_nodes: int = 500000
    max_bytes: int = 8 * 1024**3
    max_file_bytes: int = 1024**3
    max_package_files: int = 100000
    max_depth: int = 128
    max_unsupported: int = 64
    allow_cross_device: bool = False

    def __post_init__(self):
        need(type(self.deadline) in (int, float) and math.isfinite(self.deadline), 'finite deadline required')
        for name in ('max_packages', 'max_nodes', 'max_bytes', 'max_file_bytes',
                     'max_package_files', 'max_depth', 'max_unsupported'):
            value = getattr(self, name)
            need(type(value) is int and 0 < value <= 2**63 - 1, 'finite positive limit required')
        need(self.max_packages <= 4096 and self.max_depth <= 256
             and self.max_unsupported <= 1024 and type(self.allow_cross_device) is bool,
             'bounded inventory/depth/diagnostics required')

    def tick(self):
        need(time.monotonic() < self.deadline, 'root observation deadline')


def package_map(value, *, limits):
    limits.tick()
    need(type(value) is dict and len(value) <= limits.max_packages, 'package inventory limit')
    for name, version in value.items():
        need(type(name) is str and installer.NAME.fullmatch(name) and type(version) is str
             and 0 < len(version) <= 128 and not any(c.isspace() or c == '\0' for c in version),
             'invalid package identity')
    return dict(value)


def inventory_exact(actual, expected, *, limits):
    need(package_map(actual, limits=limits) == package_map(expected, limits=limits), 'exact inventory drift')
    return dict(actual)


def check_inventory(actual, expected, label='', *, limits):
    return inventory_exact(actual, expected, limits=limits)


class Alpm(installer.Alpm):
    """Retain the pinned ABI/signatures/handle; change only observation bounds."""
    def __init__(self, root, gpgdir, log, architecture='aarch64', *, limits):
        self.limits = limits
        limits.tick()
        super().__init__(root, gpgdir, log, architecture)

    def packages(self, entries):
        result = {}
        while entries:
            self.limits.tick()
            need(len(result) < self.limits.max_packages, 'ALPM package inventory limit')
            package = entries.contents.data
            name = self.alpm_pkg_get_name(package).decode()
            need(name not in result, 'duplicate ALPM package')
            result[name] = self.alpm_pkg_get_version(package).decode()
            entries = entries.contents.next
        return package_map(result, limits=self.limits)

    def owned_files(self, names):
        need(type(names) in (list, tuple, set) and len(names) <= self.limits.max_packages,
             'bounded owned package names required')
        paths = set()
        db = self.alpm_get_localdb(self.handle)
        for name in names:
            self.limits.tick()
            need(type(name) is str and installer.NAME.fullmatch(name), 'invalid owned package name')
            package = self.alpm_db_get_pkg(db, name.encode())
            need(package, 'protected package absent')
            files = self.alpm_pkg_get_files(package).contents
            need(files.count <= self.limits.max_package_files, 'ALPM owned file count limit')
            for index in range(files.count):
                self.limits.tick()
                paths.add(installer.relative(files.files[index].name.decode().rstrip('/')))
                need(len(paths) <= self.limits.max_nodes, 'aggregate owned file count limit')
        return paths


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _file_hash(descriptor, expected, limits):
    need(_identity(os.fstat(descriptor)) == _identity(expected), 'file entry drift')
    hashed, digest = 0, hashlib.sha256()
    while True:
        limits.tick()
        data = os.read(descriptor, min(1024**2, expected.st_size - hashed + 1))
        if not data:
            break
        hashed += len(data)
        need(hashed <= expected.st_size, 'file grew during observation')
        digest.update(data)
    need(hashed == expected.st_size and _identity(os.fstat(descriptor)) == _identity(expected),
         'file content drift')
    return digest.hexdigest()


def _open_root(root):
    root = Path(root)
    need(root.is_absolute() and '..' not in root.parts, 'absolute contained root required')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open('/', flags)
    try:
        for part in root.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def node(root, relative, *, limits):
    """Observe one node through nofollow directory descriptors beneath known root."""
    limits.tick()
    installer.relative(relative)
    descriptor = _open_root(root)
    original = os.fstat(descriptor)
    try:
        parts = relative.split('/')
        need(len(parts) <= limits.max_depth + 1, 'node depth limit')
        for part in parts[:-1]:
            limits.tick()
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            need(limits.allow_cross_device or os.fstat(descriptor).st_dev == original.st_dev,
                 'cross-device node parent')
        name = parts[-1]
        before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        need(limits.allow_cross_device or before.st_dev == original.st_dev, 'cross-device node')
        common = {'mode': stat.S_IMODE(before.st_mode), 'uid': before.st_uid, 'gid': before.st_gid}
        if stat.S_ISDIR(before.st_mode):
            common['type'] = 'directory'
        elif stat.S_ISREG(before.st_mode):
            need(before.st_nlink == 1 and before.st_size <= limits.max_file_bytes
                 and before.st_size <= limits.max_bytes, 'hardlinked or oversized node')
            file = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                           dir_fd=descriptor)
            try:
                common.update(type='file', bytes=before.st_size, sha256=_file_hash(file, before, limits))
            finally:
                os.close(file)
        elif stat.S_ISLNK(before.st_mode):
            common.update(type='symlink', target=os.readlink(name, dir_fd=descriptor))
            installer.resolve_nodes({relative: common}, relative)
        else:
            raise ValueError('special node refused')
        need(_identity(os.stat(name, dir_fd=descriptor, follow_symlinks=False)) == _identity(before),
             'named node drift')
        parent = _open_root(Path(root).joinpath(*parts[:-1]))
        try:
            need(_identity(os.fstat(parent)) == _identity(os.fstat(descriptor)), 'node parent path drift')
        finally:
            os.close(parent)
        rebound = _open_root(root)
        try:
            need(_identity(os.fstat(rebound)) == _identity(original), 'root path drift')
        finally:
            os.close(rebound)
        return common
    finally:
        os.close(descriptor)


def observe(root, *, limits):
    """Measure a root without following links; incomplete/unsupported is ineligible."""
    limits.tick()
    nodes, problems, counts = {}, [], {}
    allocated_inodes, hardlinked_inodes = set(), set()
    footprint = {'nodes': 0, 'bytes': 0, 'largest_file_bytes': 0, 'hardlinks': 0,
                 'hardlink_entries': 0, 'hardlink_inodes': 0, 'hardlink_declared_links': 0,
                 'allocated_bytes': 0, 'allocated_bytes_by_entry': 0,
                 'symlinks': 0, 'database_bytes': 0, 'database_files': 0}
    report = {'nodes': nodes, 'footprint': footprint, 'unsupported': problems,
              'unsupported_counts': counts, 'complete': False, 'eligible': False}
    descriptor = _open_root(root)
    try:
        root_info = os.fstat(descriptor)
        space = os.fstatvfs(descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    inode_counts_known = space.f_files > 0 and space.f_favail >= 0
    footprint.update(filesystem_free_bytes=space.f_bavail * space.f_frsize,
                     filesystem_free_inodes=space.f_favail if inode_counts_known else None,
                     filesystem_inode_counts_known=inode_counts_known,
                     filesystem_inode_source='statvfs' if inode_counts_known else 'unknown',
                     filesystem_free_bytes_source='statvfs-f_bavail')

    def problem(reason, name):
        counts[reason] = counts.get(reason, 0) + 1
        if len(problems) < limits.max_unsupported:
            problems.append({'reason': reason, 'path': name[:4096]})

    def walk(directory, prefix='', depth=0):
        limits.tick()
        need(depth <= limits.max_depth, 'directory depth limit')
        before_directory = os.fstat(directory)
        with os.scandir(directory) as entries:
            for entry in entries:
                limits.tick()
                need(footprint['nodes'] < limits.max_nodes, 'root node limit')
                name = prefix + entry.name
                installer.relative(name)
                before = os.stat(entry.name, dir_fd=directory, follow_symlinks=False)
                footprint['nodes'] += 1
                common = {'mode': stat.S_IMODE(before.st_mode), 'uid': before.st_uid, 'gid': before.st_gid}
                nodes[name] = common
                if before.st_dev != root_info.st_dev and not limits.allow_cross_device:
                    common['type'] = 'cross-device'
                    problem('cross-device', name)
                    continue
                if stat.S_ISDIR(before.st_mode):
                    common['type'] = 'directory'
                    child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    dir_fd=directory)
                    try:
                        need(_identity(os.fstat(child)) == _identity(before), 'directory entry drift')
                        walk(child, name + '/', depth + 1)
                    finally:
                        os.close(child)
                elif stat.S_ISLNK(before.st_mode):
                    footprint['symlinks'] += 1
                    target = os.readlink(entry.name, dir_fd=directory)
                    common.update(type='symlink', target=target)
                    if target.startswith('/'):
                        problem('absolute-symlink', name)
                elif stat.S_ISREG(before.st_mode):
                    common.update(type='file', bytes=before.st_size)
                    footprint['bytes'] += before.st_size
                    inode = (before.st_dev, before.st_ino)
                    footprint['allocated_bytes_by_entry'] += before.st_blocks * 512
                    if inode not in allocated_inodes:
                        allocated_inodes.add(inode)
                        footprint['allocated_bytes'] += before.st_blocks * 512
                    footprint['largest_file_bytes'] = max(footprint['largest_file_bytes'], before.st_size)
                    if name.startswith('var/lib/pacman/'):
                        footprint['database_bytes'] += before.st_size
                        footprint['database_files'] += 1
                    need(footprint['bytes'] <= limits.max_bytes, 'root byte limit')
                    need(before.st_size <= limits.max_file_bytes, 'root file byte limit')
                    if before.st_nlink != 1:
                        footprint['hardlinks'] += 1
                        footprint['hardlink_entries'] += 1
                        if inode not in hardlinked_inodes:
                            hardlinked_inodes.add(inode)
                            footprint['hardlink_inodes'] += 1
                            footprint['hardlink_declared_links'] += before.st_nlink
                        problem('hardlink', name)
                        continue
                    file = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                   dir_fd=directory)
                    try:
                        common['sha256'] = _file_hash(file, before, limits)
                    finally:
                        os.close(file)
                else:
                    common['type'] = 'special'
                    problem('special-node', name)
                need(_identity(os.stat(entry.name, dir_fd=directory, follow_symlinks=False))
                     == _identity(before), 'named entry drift')
        need(_identity(os.fstat(directory)) == _identity(before_directory), 'directory content drift')

    try:
        walk(descriptor)
        for name, node in nodes.items():
            limits.tick()
            if node['type'] == 'symlink':
                if node['target'].startswith('/'):
                    continue  # Already explicitly counted while walking.
                try:
                    installer.resolve_nodes(nodes, name)
                except ValueError as error:
                    reason = {'escaping payload link': 'escaping-symlink',
                              'cyclic payload link': 'cyclic-symlink',
                              'absolute payload link': 'absolute-symlink'}.get(str(error), 'unsupported-symlink')
                    problem(reason, name)
        for auxiliary in ('usr/bin/ldconfig','usr/sbin/ldconfig','sbin/ldconfig'):
            limits.tick()
            try:
                resolved=installer.resolve_nodes(nodes,auxiliary)
                if auxiliary in nodes or resolved in nodes:
                    problem('auxiliary-present',auxiliary)
            except ValueError:
                pass  # Unsupported links are already recorded above.
        need(_identity(os.fstat(descriptor)) == _identity(root_info), 'root identity drift')
        rebound = _open_root(root)
        try:
            need(_identity(os.fstat(rebound)) == _identity(root_info), 'root path drift')
        finally:
            os.close(rebound)
        report['complete'] = True
    except (ValueError, OSError) as error:
        # Fixed error text only; never emit raw OS exception/path diagnostics.
        reason = str(error) if type(error) is ValueError else 'filesystem-observation-failed'
        problem(reason, '')
    finally:
        os.close(descriptor)
    report['eligible'] = report['complete'] and not counts
    footprint['complete'] = report['complete'] and 'cross-device' not in counts
    return report


def require_eligible(observation):
    need(observation.get('eligible') is True and observation.get('complete') is True
         and not observation.get('unsupported_counts'), 'unsupported or incomplete root observation')
    return observation['nodes']


def projected_paths(seed, added, *, limits):
    """The existing path/ldconfig refusals with explicit per-caller size bounds."""
    limits.tick()
    combined = dict(seed)
    combined.update(added)
    need(len(combined) <= limits.max_nodes, 'projected node limit')
    total = 0
    for name, node in combined.items():
        limits.tick()
        installer.relative(name)
        need(len(name.split('/')) <= limits.max_depth + 1, 'projected depth limit')
        need(node.get('type') in ('file', 'directory', 'symlink'), 'unsupported projected shape')
        if node['type'] == 'file':
            size = node.get('bytes')
            need(type(size) is int and 0 <= size <= limits.max_file_bytes, 'projected file byte limit')
            need(type(node.get('sha256')) is str and installer.HEX.fullmatch(node['sha256']),
                 'projected file content observation missing')
            total += size
        if node['type'] == 'symlink':
            need(type(node.get('target')) is str and 0 < len(node['target']) <= 4096,
                 'invalid projected symlink')
        installer.resolve_nodes(combined, name)
    need(total <= limits.max_bytes, 'projected byte limit')
    for name in ('usr/bin/ldconfig', 'usr/sbin/ldconfig', 'sbin/ldconfig'):
        resolved = installer.resolve_nodes(combined, name)
        need(name not in combined and resolved not in combined, 'unaudited auxiliary executable or alias refused')
    return combined
