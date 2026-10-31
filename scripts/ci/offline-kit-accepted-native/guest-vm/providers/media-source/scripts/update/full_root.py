#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Per-caller bounded ALPM inventory and descriptor-relative root observations."""
import ctypes as C
from dataclasses import dataclass
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import posixpath
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
    max_hardlink_groups: int = 4096
    max_hardlink_aliases: int = 16384
    max_hardlink_members: int = 4096

    def __post_init__(self):
        need(type(self.deadline) in (int, float) and math.isfinite(self.deadline), 'finite deadline required')
        for name in ('max_packages', 'max_nodes', 'max_bytes', 'max_file_bytes',
                     'max_package_files', 'max_depth', 'max_unsupported',
                     'max_hardlink_groups', 'max_hardlink_aliases', 'max_hardlink_members'):
            value = getattr(self, name)
            need(type(value) is int and 0 < value <= 2**63 - 1, 'finite positive limit required')
        need(self.max_packages <= 4096 and self.max_depth <= 256
             and self.max_unsupported <= 1024 and type(self.allow_cross_device) is bool
             and self.max_hardlink_groups <= 4096 and self.max_hardlink_aliases <= 16384
             and self.max_hardlink_members <= 4096,
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
            previous, descriptor = descriptor, child
            os.close(previous)
        return descriptor
    except BaseException as error:
        try:
            os.close(descriptor)
        except OSError:
            error.add_note('root descriptor cleanup failed')
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



def absolute_target_class(nodes, name, limits):
    """Trace only the observed node map for diagnostics; never authorize a path."""
    pending, parts, seen = name.split('/'), [], set()
    for _ in range(4096):
        limits.tick()
        if not pending: break
        part = pending.pop(0)
        if part in ('', '.'): continue
        if part == '..':
            if not parts: break
            parts.pop(); continue
        parts.append(part); current = '/'.join(parts)
        node = nodes.get(current, {})
        if node.get('type') != 'symlink': continue
        if current in seen or len(seen) >= 40: break
        seen.add(current); target = node['target']
        if target.startswith('/'):
            value = posixpath.normpath(target).strip('/')
            prefix = value.split('/', 1)[0]
            return {'usr': 'usr-path', 'etc': 'etc-path', 'var': 'var-path', 'opt': 'opt-path',
                    'run': 'runtime-run', 'proc': 'runtime-proc', 'sys': 'runtime-sys',
                    'dev': 'runtime-dev', 'tmp': 'runtime-tmp', 'root': 'root-home',
                    'home': 'user-home', '': 'filesystem-root'}.get(prefix, 'other-absolute')
        parts.pop(); pending = target.split('/') + pending
    return 'unclassified-chain'


def _mount_id(descriptor, limits):
    """Bounded Linux descriptor identity; same-device binds have different IDs."""
    limits.tick()
    with Path('/proc/self/fdinfo/' + str(descriptor)).open('rb') as stream:
        raw = stream.read(4097)
    need(len(raw) <= 4096, 'mount identity byte limit')
    fields = [row.split(b':', 1)[1].strip() for row in raw.splitlines()
              if row.startswith(b'mnt_id:')]
    need(len(fields) == 1 and fields[0].isdigit() and int(fields[0]) > 0,
         'mount identity unavailable')
    return int(fields[0])


ABSOLUTE_PATH_LIMIT = 4096
ABSOLUTE_PATH_BYTES = 256 * 1024


def observe(root, *, limits, shape_examples=0, hardlinks='refuse', absolute_paths=False):
    """Measure a root without following links; incomplete/unsupported is ineligible."""
    limits.tick()
    need(type(shape_examples) is int and 0 <= shape_examples <= 16, 'bounded shape samples required')
    need(type(absolute_paths) is bool, 'boolean absolute path diagnostic required')
    need(type(hardlinks) is str and hardlinks in ('refuse', 'generic-development-internal'),
         'invalid hardlink observation mode')
    internal = hardlinks == 'generic-development-internal'
    need(not internal or not limits.allow_cross_device, 'internal hardlinks require one device')
    groups, directories = {}, {}
    aliases = 0
    nodes, problems, counts = {}, [], {}
    categories, target_classes, auxiliary_paths = {}, {}, []
    absolute_entries, absolute_bytes, absolute_truncated = [], 2, False
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
        nonlocal absolute_bytes, absolute_truncated
        counts[reason] = counts.get(reason, 0) + 1
        if len(problems) < limits.max_unsupported:
            problems.append({'reason': reason, 'path': name[:4096]})
        if shape_examples:
            category = reason if reason in ('hardlink', 'absolute-symlink', 'auxiliary-present',
                'special-node', 'cross-device', 'escaping-symlink', 'cyclic-symlink', 'unsupported-symlink') else 'observation-error'
            row = categories.setdefault(category, {'count': 0, 'examples': []})
            row['count'] += 1
            target_class = None
            if reason == 'absolute-symlink':
                target_class = absolute_target_class(nodes, name, limits)
                target_classes[target_class] = target_classes.get(target_class, 0) + 1
            if reason == 'auxiliary-present': auxiliary_paths.append(name)
            if len(row['examples']) < shape_examples:
                sample = {'path': name[:1024], 'path_truncated': len(name) > 1024}
                if target_class is not None: sample['target_class'] = target_class
                row['examples'].append(sample)
        if absolute_paths and reason == 'absolute-symlink':
            if not shape_examples: target_class = absolute_target_class(nodes, name, limits)
            entry = {'path': name, 'target_class': target_class}
            size = len(json.dumps(entry, sort_keys=True, separators=(',', ':')).encode('ascii'))
            added = size + bool(absolute_entries)
            if len(absolute_entries) < ABSOLUTE_PATH_LIMIT and absolute_bytes + added <= ABSOLUTE_PATH_BYTES:
                absolute_entries.append(entry); absolute_bytes += added
            else:
                absolute_truncated = True

    def walk(directory, prefix='', depth=0):
        nonlocal aliases
        limits.tick()
        need(depth <= limits.max_depth, 'directory depth limit')
        before_directory = os.fstat(directory)
        if internal:
            need(_mount_id(directory, limits) == root_mount, 'mount crossing refused')
            directories[prefix.rstrip('/')] = _identity(before_directory)
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
                        if not internal:
                            problem('hardlink', name)
                            continue
                        aliases += 1
                        need(aliases <= limits.max_hardlink_aliases, 'hardlink alias limit')
                        need(2 <= before.st_nlink <= limits.max_hardlink_members, 'hardlink member limit')
                    file = os.open(entry.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                   dir_fd=directory)
                    try:
                        if internal:
                            need(_mount_id(file, limits) == root_mount, 'mount crossing refused')
                        if internal and before.st_nlink > 1:
                            group = groups.get(inode)
                            if group is None:
                                need(len(groups) < limits.max_hardlink_groups, 'hardlink group limit')
                                digest = _file_hash(file, before, limits)
                                group = {'fd': file, 'identity': _identity(before),
                                         'members': [], 'sha256': digest}
                                groups[inode] = group
                                file = None  # Group owns this descriptor until final validation.
                            else:
                                need(_identity(os.fstat(file)) == group['identity'] == _identity(before),
                                     'hardlink identity drift')
                            group['members'].append(name)
                            need(len(group['members']) <= limits.max_hardlink_members, 'hardlink member limit')
                        else:
                            common['sha256'] = _file_hash(file, before, limits)
                    finally:
                        if file is not None:
                            os.close(file)
                else:
                    common['type'] = 'special'
                    problem('special-node', name)
                need(_identity(os.stat(entry.name, dir_fd=directory, follow_symlinks=False))
                     == _identity(before), 'named entry drift')
        need(_identity(os.fstat(directory)) == _identity(before_directory), 'directory content drift')

    def validate_groups():
        result = {}
        for group in groups.values():
            limits.tick()
            identity, retained = group['identity'], group['fd']
            members = tuple(sorted(group['members']))
            need(len(members) == len(set(members)) == identity[5], 'hardlink group not closed')
            for name in members:
                limits.tick()
                parent = os.dup(descriptor)
                prefix = ''
                try:
                    for part in name.split('/')[:-1]:
                        limits.tick()
                        child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                        dir_fd=parent)
                        os.close(parent)
                        parent = child
                        prefix = part if not prefix else prefix + '/' + part
                        need(_identity(os.fstat(parent)) == directories.get(prefix)
                             and _mount_id(parent, limits) == root_mount, 'hardlink parent drift')
                    file = os.open(name.split('/')[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                                   dir_fd=parent)
                    try:
                        need(_mount_id(file, limits) == root_mount
                             and _identity(os.fstat(file)) == identity == _identity(os.fstat(retained))
                             and _identity(os.stat(name.split('/')[-1], dir_fd=parent, follow_symlinks=False)) == identity,
                             'hardlink named entry drift')
                    finally:
                        os.close(file)
                finally:
                    os.close(parent)
            need(_identity(os.fstat(retained)) == identity and _mount_id(retained, limits) == root_mount,
                 'hardlink retained entry drift')
            common = nodes[members[0]]
            result[members[0]] = {key: common[key] for key in ('bytes', 'mode', 'uid', 'gid')}
            result[members[0]].update(members=members, nlink=len(members), sha256=group['sha256'])
        # Publish group tags only after all groups have passed.
        for key, group in result.items():
            for name in group['members']:
                nodes[name].update(sha256=group['sha256'], hardlink_group=key)
        report['hardlink_groups'] = result

    try:
        if internal:
            root_mount = _mount_id(descriptor, limits)
        walk(descriptor)
        if internal:
            validate_groups()
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
            if internal:
                need(_mount_id(descriptor, limits) == root_mount == _mount_id(rebound, limits),
                     'root mount drift')
                for group in groups.values():
                    limits.tick()
                    need(_identity(os.fstat(group['fd'])) == group['identity'], 'hardlink final drift')
        finally:
            os.close(rebound)
        report['complete'] = True
    except (ValueError, OSError) as error:
        # Fixed error text only; never emit raw OS exception/path diagnostics.
        reason = str(error) if type(error) is ValueError else 'filesystem-observation-failed'
        problem(reason, '')
    finally:
        for closing in [group['fd'] for group in groups.values()] + [descriptor]:
            try:
                os.close(closing)
            except OSError:
                # A failed close may already have released the FD. Never retry it.
                report['complete'] = False
                problem('filesystem-cleanup-failed', '')
    if shape_examples:
        for row in categories.values():
            row['examples_complete'] = report['complete'] and len(row['examples']) == row['count'] and not any(x['path_truncated'] for x in row['examples'])
        report['shape_diagnostics'] = {'sample_limit_per_category': shape_examples, 'sample_path_char_limit': 1024,
            'categories': categories, 'absolute_target_classes': target_classes,
            'auxiliary_paths': auxiliary_paths, 'auxiliary_paths_complete': report['complete'],
            'absolute_classes_complete': report['complete'] and sum(target_classes.values()) == counts.get('absolute-symlink', 0),
            'target_values': 'OMITTED',
            'scope': 'observed node-map diagnostics only; no policy permission'}
    if absolute_paths:
        report['absolute_chain_paths'] = {
            'entries': sorted(absolute_entries, key=lambda entry: entry['path']),
            'observed_count': counts.get('absolute-symlink', 0),
            'complete': report['complete'] and not absolute_truncated and len(absolute_entries) == counts.get('absolute-symlink', 0),
            'truncated': absolute_truncated, 'observation_complete': report['complete'],
            'entry_limit': ABSOLUTE_PATH_LIMIT, 'entry_json_byte_limit': ABSOLUTE_PATH_BYTES,
            'entry_json_bytes': absolute_bytes, 'target_values': 'OMITTED',
            'scope': 'observed node-map diagnostics only; no policy permission'}
    report['eligible'] = report['complete'] and not counts
    footprint['complete'] = report['complete'] and 'cross-device' not in counts
    return report


def require_eligible(observation):
    need(observation.get('eligible') is True and observation.get('complete') is True
         and not observation.get('unsupported_counts'), 'unsupported or incomplete root observation')
    return observation['nodes']


def _projected_paths(seed, added, *, limits, internal=False):
    """The existing path/ldconfig refusals with explicit per-caller size bounds."""
    limits.tick()
    need(type(seed) is dict and type(added) is dict
         and len(seed) <= limits.max_nodes and len(added) <= limits.max_nodes, 'projected input limit')
    if not internal:
        need(all(type(value) is dict and 'hardlink_group' not in value
                 for graph in (seed, added) for value in graph.values()),
             'hardlink projection requires explicit mode')
    combined = dict(seed)
    combined.update(added)
    need(len(combined) <= limits.max_nodes, 'projected node limit')
    total = 0
    for name, node in combined.items():
        limits.tick()
        installer.relative(name)
        need(type(node) is dict and (internal or 'hardlink_group' not in node), 'hardlink projection requires explicit mode')
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


def projected_paths(seed, added, *, limits):
    return _projected_paths(seed, added, limits=limits)


def _path_set(value, limits):
    need(type(value) in (set, frozenset, tuple, list) and len(value) <= limits.max_nodes,
         'bounded path collection required')
    result = set()
    for name in value:
        limits.tick()
        installer.relative(name)
        need(len(name.split('/')) <= limits.max_depth + 1, 'path depth limit')
        result.add(name)
    return result


def _group_graph(observation, limits):
    """Validate ordinary in-memory observations, never a permission token."""
    limits.tick()
    need(type(observation) is dict, 'hardlink observation required')
    nodes = require_eligible(observation)
    groups = observation.get('hardlink_groups')
    need(type(groups) is dict and len(groups) <= limits.max_hardlink_groups,
         'bounded hardlink groups required')
    _projected_paths(nodes, {}, limits=limits, internal=True)
    members = set()
    for key, group in groups.items():
        limits.tick()
        installer.relative(key)
        need(type(group) is dict and set(group) ==
             {'members', 'nlink', 'bytes', 'mode', 'uid', 'gid', 'sha256'}, 'invalid hardlink group record')
        paths = group['members']
        need(type(paths) is tuple and 2 <= len(paths) <= limits.max_hardlink_members,
             'invalid hardlink membership')
        for name in paths:
            limits.tick()
            installer.relative(name)
        need(paths == tuple(sorted(set(paths))) and key == paths[0]
             and type(group['nlink']) is int and group['nlink'] == len(paths), 'invalid hardlink membership')
        need(type(group['bytes']) is int and 0 <= group['bytes'] <= limits.max_file_bytes
             and type(group['sha256']) is str and installer.HEX.fullmatch(group['sha256']),
             'invalid hardlink content')
        for field in ('mode', 'uid', 'gid'):
            need(type(group[field]) is int and 0 <= group[field] <= (0o7777 if field == 'mode' else 2**32 - 1),
                 'invalid hardlink metadata')
        for name in paths:
            limits.tick()
            need(name not in members, 'duplicate hardlink membership')
            members.add(name)
            need(len(members) <= limits.max_hardlink_aliases, 'hardlink alias limit')
            value = nodes.get(name)
            need(type(value) is dict and value.get('type') == 'file'
                 and value.get('hardlink_group') == key
                 and all(type(value.get(field)) is int for field in ('bytes', 'mode', 'uid', 'gid'))
                 and all(value.get(field) == group[field] for field in ('bytes', 'mode', 'uid', 'gid', 'sha256')),
                 'hardlink member differs')
            parts = name.split('/')
            for index in range(1, len(parts)):
                limits.tick()
                parent = nodes.get('/'.join(parts[:index]), {})
                need(parent.get('type') == 'directory'
                     and all(type(parent.get(field)) is int and 0 <= parent[field] <=
                             (0o7777 if field == 'mode' else 2**32 - 1) for field in ('mode', 'uid', 'gid')),
                     'hardlink parent missing or redirected')
    for name, value in nodes.items():
        limits.tick()
        need('hardlink_group' not in value or name in members, 'unknown hardlink member')
    return nodes, groups


def _same_groups(before, after, before_groups, after_groups, limits):
    need(before_groups == after_groups, 'hardlink groups changed')
    for group in before_groups.values():
        for name in group['members']:
            limits.tick()
            need(before[name] == after.get(name), 'hardlink member changed')
            parts = name.split('/')
            for index in range(1, len(parts)):
                limits.tick()
                parent = '/'.join(parts[:index])
                need(before[parent] == after.get(parent), 'hardlink parent changed')


def projected_internal_hardlinks(observation, added, *, selected_old_paths,
                                 removed_paths, protected_paths, limits):
    """Only unrelated updates: retain every existing group and its ancestors."""
    seed, groups = _group_graph(observation, limits)
    old = _path_set(selected_old_paths, limits)
    removed = _path_set(removed_paths, limits)
    _path_set(protected_paths, limits)  # Every group is preserved, including all protected aliases.
    need(type(added) is dict and len(added) <= limits.max_nodes, 'projected input limit')
    for name, value in added.items():
        limits.tick()
        installer.relative(name)
        need(type(value) is dict and 'hardlink_group' not in value, 'payload hardlink marker refused')
    need(removed <= old and removed <= seed.keys(), 'unaccounted removal')
    for name in old:
        limits.tick()
        need(name in seed, 'selected old path missing')
        need(name in added or name in removed or seed[name]['type'] == 'directory',
             'selected old removal missing')
    retained = {name: value for name, value in seed.items() if name not in removed}
    combined = _projected_paths(retained, added, limits=limits, internal=True)
    # A removed directory with retained children is an ambiguous extraction model.
    # Do not invent ALPM's rmdir decisions.
    for name in combined:
        limits.tick()
        parts = name.split('/')
        for index in range(1, len(parts)):
            limits.tick()
            parent = '/'.join(parts[:index])
            resolved = installer.resolve_nodes(combined, parent)
            need(combined.get(resolved, {}).get('type') == 'directory', 'projected parent missing or not directory')
    sensitive = set()
    for group in groups.values():
        for name in group['members']:
            parts = name.split('/')
            for index in range(1, len(parts) + 1):
                limits.tick()
                sensitive.add('/'.join(parts[:index]))
    for name in old | set(added) | removed:
        limits.tick()
        for graph in (seed, combined):
            resolved = installer.resolve_nodes(graph, name)
            if name in sensitive or resolved in sensitive:
                need(name not in removed and seed.get(name, {}).get('type') == 'directory'
                     and seed[name] == combined.get(name) and name == resolved
                     and (name not in added or seed[name] == added[name]), 'selected hardlink path touched')
    projected = dict(observation, nodes=combined)
    _, projected_groups = _group_graph(projected, limits)
    _same_groups(seed, combined, groups, projected_groups, limits)
    return combined


def check_hardlink_preservation(before_observation, after_observation, *, protected_paths, limits):
    """Pure all-group content/topology comparison; no write exclusion or rollback."""
    _path_set(protected_paths, limits)
    before, groups = _group_graph(before_observation, limits)
    after, after_groups = _group_graph(after_observation, limits)
    _same_groups(before, after, groups, after_groups, limits)
    return True
