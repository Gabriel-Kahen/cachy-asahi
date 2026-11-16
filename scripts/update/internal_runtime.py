#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Strict internal-hardlink adapter; real-root absolute/auxiliary policy pending.

Python callers may supply args.prior_archive plus its adjacent detached .sig to
remove unmodified obsolete selected leaves. The current authenticated release's
signer/keyring must verify that archive; ownership and backup ambiguity refuse.
Old and new archives share the caller's existing aggregate inspection budgets.
Results retain prior_archive identity/signature pins and projected obsolete paths;
the enclosing transaction result alone reports whether a commit occurred.
There is no CLI, automatic recovery or supported target-update claim here.
"""
import ctypes as C
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import stat

import full_root as roots
import measure_copy as copy
import root_path
import scale_update as scale

MODE = 'generic-development-internal'
DB = 'var/lib/pacman/local'


def need(ok, reason):
    if not ok: raise ValueError(reason)


class Runtime(scale.Runtime):
    """One unrelated package update; all existing hardlink groups stay immutable.

    This adapter deliberately keeps require_eligible's absolute-link/ldconfig
    refusals. Prior archives must exactly match ALPM's complete owned path set;
    directories, backups, modified leaves and aliases remain unsupported removals.
    It is independent preparatory code, not real587 acceptance.
    """
    def __init__(self, args, config):
        super().__init__(args, config)
        need(config['platform_mode'] == 'generic-development', 'explicit generic development runtime required')
        self.observation = self.baseline = self.projected = self.alpm = None
        self.old_paths, self.database_changes = set(), ()
        self.prior = None
        factory = self.Alpm
        def opened(*args, **kwargs):
            self.alpm = factory(*args, **kwargs)
            return self.alpm
        self.Alpm = opened

    def resolve_nodes(self, nodes, path):
        return root_path.resolve(nodes, path, limits=self.root_limits)[0]

    def retained(self, nodes):
        return {name: node for name, node in nodes.items() if not any(
            name == prefix or name.startswith(prefix + '/') for prefix in self.database_changes)}

    def tree(self, root):
        need(Path(root) == self.root, 'selected root required')
        self.recheck_prior()
        observation = roots.observe(root, limits=self.root_limits, hardlinks=MODE)
        nodes = roots.require_eligible(observation)
        self.footprints.append(observation['footprint'])
        if self.baseline is None:
            self.baseline = observation
        else:
            roots.check_hardlink_preservation(self.baseline, observation, protected_paths=(), limits=self.root_limits)
            # bound_update observes immediately before and after commit. The
            # baseline remains required until its precommit hook has succeeded.
            expected = self.projected if getattr(self, 'commit_ready', False) else self.baseline['nodes']
            need(self.retained(nodes) == self.retained(expected), 'unrelated root content changed')
            if not getattr(self, 'commit_ready', False):
                need(nodes == self.baseline['nodes'], 'root changed before commit')
        self.observation = observation
        self.recheck_prior()
        return nodes

    def selection(self, snapshot, before, desired):
        super().selection(snapshot, before, desired)
        need(self.alpm is not None, 'live transaction observation required')
        self.old_paths = set(self.alpm.owned_files(set(desired)))
        self.database_changes = tuple(DB + '/' + name + '-' + version
            for name in desired for version in (before[name], desired[name]))
        if getattr(self.args, 'prior_archive', None) is not None:
            self.select_prior(snapshot, before, desired)

    def select_prior(self, snapshot, before, desired):
        """Authenticate a frozen OLD archive; local ownership is not authority."""
        client = scale.bound.client
        source = client.absolute(self.args.prior_archive)
        work = snapshot['bundle'].parent.parent / 'prior-package'
        work.mkdir(mode=0o700)
        sources, copies = [], {}
        for path, name, maximum in ((source, 'archive', self.archive_limits.compressed_bytes),
                (Path(str(source) + '.sig'), 'archive.sig', client.MAX_SIGNATURE)):
            root = client.directory(path.parent)
            try:
                with client.member(root, path.name) as fd:
                    info = os.fstat(fd)
                    need(0 < info.st_size <= maximum, 'prior archive/signature size limit')
                    identity = client.identity(info)
                target = work / name
                pin, _ = client.hash_member(root, path.name, snapshot=target)
                need(client.identity(os.stat(path.name, dir_fd=root, follow_symlinks=False)) == identity,
                     'prior input changed during snapshot')
                target.chmod(0o400)
                copies[name] = dict(sha256=pin, bytes=target.stat().st_size)
                sources.extend(((path, identity, pin), (target, client.identity(target.stat()), pin)))
            finally:
                os.close(root)
        verifier = client.Verifier(work, client.read_path(snapshot['keyring'], client.MAX_KEYRING),
                                  snapshot['metadata']['signer'], datetime.now(timezone.utc))
        signature = verifier.verify(work / 'archive', client.read_path(work / 'archive.sig', client.MAX_SIGNATURE))
        metadata, accounting = {}, {}
        payload = scale.archives.archive_payload(work / 'archive', self.archive_limits, accounting, pkginfo=metadata)
        fields = {}
        for line in metadata['raw'].decode('utf-8').splitlines():
            if not line or line.startswith('#'):
                continue
            need(' = ' in line, 'malformed prior package metadata')
            key, value = line.split(' = ', 1)
            need(re.fullmatch('[a-z][a-z0-9_]*', key) is not None, 'malformed prior package metadata key')
            fields.setdefault(key, []).append(value)
        name, = desired
        selected, = snapshot['release']['packages']
        need(fields.get('pkgname') == [name] and fields.get('pkgver') == [before[name]]
             and fields.get('arch') == [selected['arch']], 'prior package identity differs')
        need('backup' not in fields, 'prior archive backup semantics unsupported')
        package = self.alpm.alpm_db_get_pkg(self.alpm.alpm_get_localdb(self.alpm.handle), name.encode())
        need(package, 'selected installed package absent')
        need(self.alpm.alpm_pkg_get_arch(package).decode() == selected['arch'], 'installed prior architecture differs')
        backups = self.alpm.lib.alpm_pkg_get_backup
        backups.restype, backups.argtypes = roots.installer.Ptr, [C.c_void_p]
        need(not backups(package), 'installed backup semantics unsupported')
        need(set(payload) == self.old_paths, 'prior archive and selected ownership differ')
        foreign = set(self.alpm.owned_files(set(before) - set(desired)))
        evidence = dict(package=dict(name=name, version=before[name], arch=selected['arch']),
            archive=copies['archive'], signature=dict(copies['archive.sig'], **signature), projected_obsolete_paths=[])
        self.prior = dict(payload=payload, foreign=foreign, sources=sources, accounting=accounting, evidence=evidence)
        self.recheck_prior()

    def archive_payload(self, path, accounting):
        if getattr(self, 'prior', None) is not None:
            need(not any(accounting.values()), 'one new archive after prior inspection required')
            accounting.update(self.prior['accounting'])
        return super().archive_payload(path, accounting)

    def recheck_prior(self):
        if getattr(self, 'prior', None) is None:
            return
        client = scale.bound.client
        for path, identity, pin in self.prior['sources']:
            self.root_limits.tick()
            root = client.directory(path.parent)
            try:
                with client.member(root, path.name) as fd:
                    need(client.identity(os.fstat(fd)) == identity, 'prior input identity changed')
                need(client.hash_member(root, path.name)[0] == pin, 'prior input bytes changed')
                need(client.identity(os.stat(path.name, dir_fd=root, follow_symlinks=False)) == identity,
                     'prior input changed during recheck')
            finally:
                os.close(root)

    def projected_paths(self, seed, payload):
        need(self.baseline is not None and seed == self.baseline['nodes'], 'observed seed required')
        removed = self.old_paths - payload.keys()
        if removed:
            need(getattr(self, 'prior', None) is not None, 'selected payload removal unsupported without authenticated prior archive')
            self.recheck_prior()
            foreign = set(self.prior['foreign'])
            for name in self.prior['foreign']:
                parent, _, leaf = name.rpartition('/')
                parent = self.resolve_nodes(seed, parent)
                foreign.add(parent + '/' + leaf if parent else leaf)
            for name in removed:
                self.root_limits.tick()
                old = self.prior['payload'].get(name)
                need(old is not None and old['type'] in ('file', 'symlink'), 'selected directory removal unsupported')
                parent, _, _ = name.rpartition('/')
                need(self.resolve_nodes(seed, parent) == parent, 'obsolete leaf parent alias unsupported')
                need(seed.get(name) == old, 'obsolete leaf modified or hardlinked')
                need(name not in foreign, 'obsolete leaf has foreign ownership')
        self.projected = roots.projected_internal_hardlinks(self.baseline, payload,
            selected_old_paths=self.old_paths, removed_paths=removed, protected_paths=(), limits=self.root_limits)
        if getattr(self, 'prior', None) is not None:
            self.prior['evidence']['projected_obsolete_paths'] = sorted(removed)
        return self.projected

    def node(self, path):
        need(self.observation is not None, 'root observation required')
        nodes = self.observation['nodes']
        name = Path(path).relative_to(self.root).as_posix(); roots.installer.relative(name)
        parent, _, leaf = name.rpartition('/')
        parent, trace = root_path.resolve(nodes, parent, limits=self.root_limits)
        name = parent + '/' + leaf if parent else leaf
        # Resolution is pure; every dependency must also match live root data.
        for dependency in trace:
            if dependency: self._live_node(dependency)
        value = self._live_node(name)
        for dependency in trace:
            if dependency: self._live_node(dependency)
        return value

    def _live_node(self, name):
        nodes = self.observation['nodes']
        expected = nodes.get(name)
        need(expected is not None, 'observed node missing')
        with copy._descriptors() as held:
            root = roots._open_root(self.root); held.append(root)
            root_identity = roots._identity(os.fstat(root)); mount = roots._mount_id(root, self.root_limits)
            identities = {}
            with copy._parent(root, name, mount, identities, self.root_limits, nodes) as (directory, base):
                flags = os.O_CLOEXEC | os.O_NOFOLLOW
                if expected['type'] == 'file': flags |= os.O_RDONLY | os.O_NONBLOCK
                elif expected['type'] == 'directory': flags |= os.O_RDONLY | os.O_DIRECTORY
                else: flags |= os.O_PATH
                fd = os.open(base, flags, dir_fd=directory); held.append(fd)
                info = os.fstat(fd); identity = roots._identity(info)
                need(identity == roots._identity(os.stat(base, dir_fd=directory, follow_symlinks=False))
                     and roots._mount_id(fd, self.root_limits) == mount, 'observed node drift')
                copy._metadata_equal(info, expected)
                if expected['type'] == 'file':
                    members = self.observation['hardlink_groups'][expected['hardlink_group']]['members'] if 'hardlink_group' in expected else (name,)
                    need(stat.S_ISREG(info.st_mode) and info.st_size == expected['bytes'] and info.st_nlink == len(members), 'observed file differs')
                    need(roots._file_hash(fd, info, self.root_limits) == expected['sha256'], 'observed file content changed')
                    for member in members:
                        copy._source_alias(root, member, mount, identities, nodes, identity, self.root_limits)
                elif expected['type'] == 'directory':
                    need(stat.S_ISDIR(info.st_mode), 'observed directory differs')
                else:
                    need(stat.S_ISLNK(info.st_mode) and os.readlink(base, dir_fd=directory) == expected['target'], 'observed symlink differs')
                need(identity == roots._identity(os.fstat(fd)) == roots._identity(os.stat(base, dir_fd=directory, follow_symlinks=False)), 'observed node changed')
            copy._root_check(self.root, root, root_identity, mount, self.root_limits)
        # Archive payloads never carry a source hardlink-group marker.
        return {key: value for key, value in expected.items() if key != 'hardlink_group'}

    def precommit(self):
        super().precommit()
        need(self.projected is not None, 'complete projected root required')
        self.recheck_prior()
        self.commit_ready = True


def apply(args):
    """Apply to workspace/root created by disposable_copy.copied_root's owner."""
    delegated, result = False, None
    try:
        scale.bound.guard(Path(args.root), Path(args.workspace))
        config = scale.configuration(args.scale, args.scale_sha256)
        runtime = Runtime(args, config)
        delegated = True
        result = scale.bound.apply(args, adapter=runtime)
        result.update(root_footprints=runtime.footprints, scope='internal-hardlink-disposable-root',
            auxiliary_execution='REFUSED_IF_PRESENT', full587_composition='NOT ESTABLISHED',
            apple_acceptance='NOT ESTABLISHED', hardware='NOT RUN')
        if runtime.prior is not None:
            result['prior_archive'] = runtime.prior['evidence']
        return result
    except BaseException as error:
        failure = dict(result) if type(result) is dict else {}
        for field in ('commit_started', 'packages_committed', 'checkpoint_changed'):
            failure.setdefault(field, 'UNKNOWN' if delegated else False)
        failure.update(status='FAIL', phase='internal-runtime', error_type=type(error).__name__,
            error=str(error)[:256], full587_composition='NOT ESTABLISHED')
        return failure
