#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Descriptor-only held ldconfig closure reads; no helper execution or writes."""
import hashlib
import os
from pathlib import Path
import re
import stat
import types

import full_root as roots
import measure_copy as copy
import root_path

COMPARATOR_SHA256 = '3e9b0f0f153a1fade1ff98606dafd93a654730eea0a8e44464415112922fc552'
HELPER = ('8794bf13f7a651963a219d8031fe04800d06ac6e44a29fbdfd81b64855b2bd98', 865664)
MAIN_CONF = '785c6c3614a27ae6115a27c1ca55bbf333654780997c4ba7e181172b021d1bf3'
HELPER_PATHS = ('usr/bin/ldconfig', 'usr/sbin/ldconfig', 'sbin/ldconfig')
HELPER_NODE = 'usr/bin/ldconfig'
SCAN_ROOTS = ('usr/lib', 'usr/lib64')
FAKE_CONF = 'usr/lib/ld.so.conf.d/fakeroot.conf'
FAKE_DIR = 'usr/lib/libfakeroot'
FAKE_HASH = '564c4c4d369d005702d825d34edc5e5568cb1ab6ee1b19fa03d0d672fb8b3aee'
TARGET_PARENTS = ('usr/lib/pkcs11', 'usr/lib/python3.14', 'usr/lib/python3.14/site-packages',
                  'usr/lib/python3.14/site-packages/vapoursynth')
TARGETS = {
    'usr/lib/pkcs11/p11-kit-trust.so': (396568, 'd945af27e9e9d9ca7b2879cbfdf0d3fe17d8b94fc61dde4408f482793c0bffa7'),
    'usr/lib/python3.14/site-packages/vapoursynth/libvapoursynth.so.4': (3284304, 'd946d71543f23536392e568268f59f5e1f83f7a2767bb2fc1bcbf7c192973111'),
    'usr/lib/python3.14/site-packages/vapoursynth/libvsscript.so': (67816, '3ba72b1bc64942269cc29de3343a6250fcfb0a1b89f9a5d615d2f78973b3e65c'),
}
MAIN_CACHE, AUX_CACHE = 'etc/ld.so.cache', 'var/cache/ldconfig/aux-cache'


def need(ok, reason):
    if not ok: raise ValueError('aux-checkpoint-' + reason)


def load_comparator(path, limits):
    """Execute exactly the pinned dependency bytes, never re-open for import."""
    path = Path(path)
    need(path.is_absolute(), 'absolute-comparator-source')
    with copy._descriptors() as held:
        parent = roots._open_root(path.parent); held.append(parent)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent); held.append(fd)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= 128*1024, 'comparator-source-shape')
        data = bytearray()
        while len(data) <= info.st_size:
            limits.tick(); block = os.read(fd, min(65536, info.st_size-len(data)+1))
            if not block: break
            data.extend(block)
        need(len(data) == info.st_size and roots._identity(info) == roots._identity(os.fstat(fd))
             == roots._identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)), 'comparator-source-drift')
        need(hashlib.sha256(data).hexdigest() == COMPARATOR_SHA256, 'comparator-source-pin')
        copy._root_check(path.parent, parent, roots._identity(os.fstat(parent)), roots._mount_id(parent, limits), limits)
    module = types.ModuleType('_held_audio_aux')
    exec(compile(bytes(data), str(path), 'exec'), module.__dict__)
    need(module.HELPER_SHA256 == HELPER[0] and module.SOURCE_REVISION == '8362e8ce10b24068bacc19552c128dd10e082fd9'
         and module.SOURCE_SHA256 == '4d8950977fbba59b0ccd479027811c6b82a31c3700d4478d04e8a4147c87bca8', 'comparator-binding')
    return module


class Reader:
    """Live reads joined to a complete observation, without granting eligibility."""
    def __init__(self, root, observation, limits):
        need(observation.get('complete') is True and type(observation.get('nodes')) is dict
             and len(observation['nodes']) <= limits.max_nodes, 'complete-observation')
        self.root, self.nodes, self.groups, self.limits = Path(root), observation['nodes'], observation.get('hardlink_groups', {}), limits
        self.children_map = {}
        for name in self.nodes:
            limits.tick(); roots.installer.relative(name)
            parent, _, _leaf = name.rpartition('/')
            self.children_map.setdefault(parent, []).append(name)

    def literal(self, name, data_limit=None):
        """Physical canonical path only; O_NOFOLLOW on every opened component."""
        expected = self.nodes.get(name)
        with copy._descriptors() as held:
            root = roots._open_root(self.root); held.append(root)
            root_id, mount = roots._identity(os.fstat(root)), roots._mount_id(root, self.limits)
            with copy._parent(root, name, mount, {}, self.limits, self.nodes) as (parent, base):
                try: info = os.stat(base, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    need(expected is None, 'observed-node-missing')
                    row = {'node': {'type': 'absent'}}
                else:
                    need(expected is not None, 'unexpected-node')
                    flags = os.O_NOFOLLOW | os.O_CLOEXEC
                    if expected['type'] == 'file': flags |= os.O_RDONLY | os.O_NONBLOCK
                    elif expected['type'] == 'directory': flags |= os.O_RDONLY | os.O_DIRECTORY
                    else: flags |= os.O_PATH
                    fd = os.open(base, flags, dir_fd=parent); held.append(fd)
                    identity = roots._identity(info)
                    need(identity == roots._identity(os.fstat(fd)) and roots._mount_id(fd, self.limits) == mount, 'node-or-mount-drift')
                    copy._metadata_equal(info, expected)
                    if expected['type'] == 'file':
                        members = self.groups[expected['hardlink_group']]['members'] if 'hardlink_group' in expected else (name,)
                        need(stat.S_ISREG(info.st_mode) and info.st_nlink == len(members)
                             and info.st_size == expected['bytes'], 'file-shape')
                        if data_limit is None:
                            digest = roots._file_hash(fd, info, self.limits)
                        else:
                            need(type(data_limit) is int and 0 < info.st_size <= data_limit, 'read-bound')
                            data = bytearray()
                            while len(data) <= info.st_size:
                                self.limits.tick(); block = os.read(fd, min(65536, info.st_size-len(data)+1))
                                if not block: break
                                data.extend(block)
                            need(len(data) == info.st_size, 'read-size')
                            digest = hashlib.sha256(data).hexdigest()
                        need(digest == expected['sha256'], 'file-content')
                        for member in members:
                            copy._source_alias(root, member, mount, {}, self.nodes, identity, self.limits)
                    elif expected['type'] == 'directory': need(stat.S_ISDIR(info.st_mode), 'directory-shape')
                    else:
                        need(expected['type'] == 'symlink' and stat.S_ISLNK(info.st_mode)
                             and os.readlink(base, dir_fd=parent) == expected['target'], 'link-target')
                    need(identity == roots._identity(os.fstat(fd)) == roots._identity(os.stat(base, dir_fd=parent, follow_symlinks=False)), 'named-node-drift')
                    row = {'node': {k:v for k,v in expected.items() if k != 'hardlink_group'}, 'identity': identity}
                    if expected['type'] == 'file' and data_limit is not None: row['data'] = bytes(data)
            copy._root_check(self.root, root, root_id, mount, self.limits)
        return row

    def resolve(self, name):
        endpoint, trace = root_path.resolve(self.nodes, name, limits=self.limits)
        for dependency in trace:
            if dependency: self.literal(dependency)
        return endpoint, trace

    def capture(self, name, *, data_limit=None):
        parent, _, leaf = name.rpartition('/')
        endpoint, trace = self.resolve(parent)
        value = self.literal(endpoint + '/' + leaf if endpoint else leaf, data_limit)
        for dependency in trace:
            if dependency: self.literal(dependency)
        return value

    def children(self, name, bound):
        endpoint, trace = self.resolve(name)
        need(self.nodes[endpoint]['type'] == 'directory', 'listing-directory')
        with copy._descriptors() as held:
            root = roots._open_root(self.root); held.append(root)
            root_id, mount = roots._identity(os.fstat(root)), roots._mount_id(root, self.limits)
            with copy._parent(root, endpoint, mount, {}, self.limits, self.nodes) as (parent, base):
                fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent); held.append(fd)
                identity = roots._identity(os.fstat(fd)); need(roots._mount_id(fd, self.limits) == mount, 'listing-mount')
                names = []
                with os.scandir(fd) as entries:
                    for entry in entries:
                        self.limits.tick(); need(len(names) < bound, 'listing-bound')
                        names.append(endpoint + '/' + entry.name)
                need(sorted(names) == sorted(self.children_map.get(endpoint, [])), 'listing-drift')
                need(identity == roots._identity(os.fstat(fd)) == roots._identity(os.stat(base, dir_fd=parent, follow_symlinks=False)), 'listing-identity')
            copy._root_check(self.root, root, root_id, mount, self.limits)
        for dependency in trace:
            if dependency: self.literal(dependency)
        return sorted(names)


def metadata(row):
    """Keep ordinary metadata and inode identity; directory times may change."""
    value = {'node': row['node']}
    if 'identity' in row: value['inode'] = row['identity'][:2]
    return value


def checkpoint(root, observation, limits):
    reader = Reader(root, observation, limits)
    state = {'helper': {}, 'configs': {}, 'aliases': {}, 'scan': {}, 'targets': {}, 'caches': {}}
    closure, scan = set(), set()
    for name in HELPER_PATHS:
        endpoint, trace = reader.resolve(name)
        need(endpoint == HELPER_NODE, 'helper-alias')
        for dependency in trace:
            if dependency: state['helper'][dependency] = metadata(reader.literal(dependency)); closure.add(dependency)
    helper = reader.capture(HELPER_NODE)
    node = helper['node']
    need(node == dict(type='file', mode=0o755, uid=0, gid=0, bytes=HELPER[1], sha256=HELPER[0]), 'helper-pin')
    need(helper['identity'][5] == 1, 'helper-hardlink')
    state['helper'][HELPER_NODE] = helper
    main = reader.capture('etc/ld.so.conf', data_limit=4096)
    need(main['node']['type'] == 'file' and main['node']['sha256'] == MAIN_CONF, 'main-config-pin')
    del main['data']; state['configs']['etc/ld.so.conf'] = main; closure.add('etc/ld.so.conf')
    for directory in ('etc/ld.so.conf.d', 'usr/lib/ld.so.conf.d'):
        row = reader.capture(directory); state['configs'][directory] = metadata(row); closure.add(directory)
        need(row['node']['type'] in ('absent', 'directory'), 'include-directory')
        if row['node']['type'] == 'absent': continue
        for name in reader.children(directory, 32):
            row = reader.capture(name); state['configs'][name] = row; closure.add(name)
            if name.rsplit('/',1)[1].startswith('.') or not name.endswith('.conf'): continue
            row = reader.capture(name, data_limit=4096)
            need(row['node']['type'] == 'file', 'include-file')
            if name == FAKE_CONF:
                need(row['node'] == dict(type='file', mode=0o644, uid=0, gid=0, bytes=21, sha256=FAKE_HASH), 'fakeroot-config')
            else:
                for line in row['data'].decode('ascii').splitlines():
                    line = line.split('#',1)[0].strip(' \t')
                    need(not line or line in ('/usr/lib', '/usr/lib64'), 'include-content')
    need(FAKE_CONF in state['configs'], 'missing-fakeroot-config')
    for row in state['configs'].values():
        node = row['node']; need(node['type'] == 'absent' or node['uid'] == node['gid'] == 0 and not node['mode'] & 0o022, 'config-metadata')
    for name in SCAN_ROOTS + (FAKE_DIR,):
        row = reader.capture(name); state['aliases'][name] = metadata(row); closure.add(name)
        if row['node']['type'] == 'absent':
            need(name != FAKE_DIR, 'missing-fakeroot-directory'); continue
        endpoint, trace = reader.resolve(name)
        need(endpoint in (SCAN_ROOTS if name != FAKE_DIR else (FAKE_DIR,)), 'scan-alias')
        need(reader.nodes[endpoint] == dict(type='directory', mode=0o755, uid=0, gid=0), 'scan-directory')
        scan.add(endpoint)
        for dependency in trace:
            if dependency: state['aliases'][dependency] = metadata(reader.literal(dependency)); closure.add(dependency)
    for directory in tuple(scan):
        hwcaps = directory + '/glibc-hwcaps'; row = reader.capture(hwcaps)
        state['aliases'][hwcaps] = metadata(row); closure.add(hwcaps)
        need(row['node']['type'] in ('absent', 'directory'), 'hwcaps-shape')
        if row['node']['type'] == 'absent': continue
        for child in reader.children(hwcaps,32):
            row = reader.capture(child); state['aliases'][child] = metadata(row); closure.add(child)
            need(re.fullmatch('[A-Za-z0-9_.-]{1,100}',child.rsplit('/',1)[1]) and row['node']['type'] == 'directory', 'hwcaps-child')
            scan.add(child)
    count, total = 0, 0
    for directory in sorted(scan):
        for name in reader.children(directory,8192):
            count += 1; need(count <= 8192, 'scan-entry-bound')
            row = reader.capture(name); state['scan'][name] = row; closure.add(name)
            total += row['node'].get('bytes',0); need(total <= 2*1024**3, 'scan-byte-bound')
    for name in TARGET_PARENTS:
        row = reader.capture(name); state['aliases'][name] = metadata(row); closure.add(name)
        need(row['node'] == dict(type='directory', mode=0o755, uid=0, gid=0), 'target-parent')
    for name,(size,digest) in TARGETS.items():
        row = reader.capture(name); state['targets'][name] = row; closure.add(name)
        need(row['node'] == dict(type='file', mode=0o755, uid=0, gid=0, bytes=size, sha256=digest), 'target-pin')
        total += size; count += 1; need(total <= 2*1024**3 and count <= 8192, 'target-budget')
    for name,row in state['scan'].items():
        if row['node']['type'] != 'symlink': continue
        endpoint, trace = reader.resolve(name)
        need(endpoint in TARGETS or endpoint.rpartition('/')[0] in scan
             and state['scan'].get(endpoint,{}).get('node',{}).get('type') == 'file', 'library-link-closure')
        for dependency in trace:
            if dependency: closure.add(dependency)
    for name, bound in ((MAIN_CACHE,16*1024**2),(AUX_CACHE,256*1024)):
        row = reader.capture(name,data_limit=bound)
        need(row['node']['type'] == 'file' and row['node']['uid'] == row['node']['gid'] == 0
             and row['identity'][5] == 1, 'cache-file')
        data = row.pop('data'); state['caches'][name] = {'node': row['node']}; closure.add(name)
        state['aux_bytes' if name == AUX_CACHE else 'main_bytes'] = data
        row = reader.capture(name+'~'); need(row['node']['type'] == 'absent','temporary-cache')
        state['caches'][name+'~'] = row; closure.add(name+'~')
    directory = 'var/cache/ldconfig'; row = reader.capture(directory)
    need(row['node']['type'] == 'directory' and row['node']['uid'] == row['node']['gid'] == 0, 'cache-parent')
    state['caches'][directory] = metadata(row); closure.add(directory)
    state['closure'], state['scan_directories'] = tuple(sorted(closure)), tuple(sorted(scan))
    return state


def compare(before, after, comparator, *, committed=False):
    need(before['closure'] == after['closure'] and before['scan_directories'] == after['scan_directories'], 'closure-changed')
    need(before['main_bytes'] == after['main_bytes'], 'main-cache-content-changed')
    transition = comparator.compare(before['aux_bytes'], after['aux_bytes']) if committed else {'kind':'RAW_EQUAL'}
    if not committed: need(before['aux_bytes'] == after['aux_bytes'], 'aux-changed-before-commit')
    for field in ('helper','configs','aliases','scan','targets','caches'):
        old, new = before[field], after[field]
        if field == 'caches' and committed:
            old = {name: {'node': {k:v for k,v in row['node'].items() if name != AUX_CACHE or k != 'sha256'}}
                   if name == AUX_CACHE else row for name,row in old.items()}
            new = {name: {'node': {k:v for k,v in row['node'].items() if name != AUX_CACHE or k != 'sha256'}}
                   if name == AUX_CACHE else row for name,row in new.items()}
        need(old == new, field+'-changed')
    return {'status':'PASS-recorded-state-preserved', 'auxiliary_exit_status':'NOT OBSERVED',
            'main_cache':'RAW_EQUAL', 'auxiliary_transition':transition,
            'scan_entries':len(after['scan']), 'explicit_targets':len(after['targets'])}


def live_keys(state, comparator):
    """Join every saved auxiliary key to a live observed library/target inode."""
    available = set()
    for row in (*state['scan'].values(), *state['targets'].values()):
        if row['node']['type'] == 'file':
            info = row['identity']
            available.add((info[1], info[8] // 10**9, info[6], info[0]))
    records = comparator.parse(state['aux_bytes'])
    need(all(key in available for key, _value in records), 'stale-or-unobserved-aux-key')
    return {'records':len(records), 'live_library_keys':len(available)}
