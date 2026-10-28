#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Owned temporary filesystem/data checks; no package or native actors."""
import copy
import errno
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MODE = 'generic-development-internal'


class InternalHardlinkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.layout = tempfile.TemporaryDirectory(prefix='hardlink-module-')
        try:
            root = Path(cls.layout.name)
            target = root / 'scripts/update/full_root.py'
            target.parent.mkdir(parents=True)
            shutil.copyfile(HERE / 'full_root.py', target)
            install = root / 'scripts/install'
            install.mkdir()
            (install / 'local_transaction.py').symlink_to(ROOT / 'scripts/install/local_transaction.py')
            spec = importlib.util.spec_from_file_location('artifact_internal_hardlinks', target)
            cls.module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = cls.module
            spec.loader.exec_module(cls.module)
        except BaseException:
            sys.modules.pop('artifact_internal_hardlinks', None)
            cls.layout.cleanup()
            raise

    @classmethod
    def tearDownClass(cls):
        sys.modules.pop('artifact_internal_hardlinks', None)
        cls.layout.cleanup()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='hardlink-data-')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.root = self.work / 'root'
        self.root.mkdir()
        self.members = ('usr/share/a', 'usr/share/b', 'usr/share/c')
        self.data = b'inert shared package data\n'

    def limits(self, **changes):
        return self.module.Limits(deadline=time.monotonic() + 20, **changes)

    def group(self, members=None):
        members = members or self.members
        first = self.root / members[0]
        first.parent.mkdir(parents=True, exist_ok=True)
        first.write_bytes(self.data)
        first.chmod(0o640)
        for name in members[1:]:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            os.link(first, path)
        return first

    def observe(self, **options):
        options.setdefault('hardlinks', MODE)
        options.setdefault('limits', self.limits())
        return self.module.observe(self.root, **options)

    def accepted(self, **options):
        report = self.observe(**options)
        self.assertTrue(report['complete'], report)
        self.assertTrue(report['eligible'], report)
        return report

    def refused_observation(self, **options):
        try:
            report = self.observe(**options)
        except (ValueError, OSError):
            return
        self.assertFalse(report['eligible'], report)

    def project(self, observation, added=None, old=(), removed=(), protected=()):
        return self.module.projected_internal_hardlinks(
            observation, added or {}, selected_old_paths=set(old), removed_paths=set(removed),
            protected_paths=set(protected), limits=self.limits())

    def preserved(self, before, after, protected=()):
        return self.module.check_hardlink_preservation(
            before, after, protected_paths=set(protected), limits=self.limits())

    def fd_count(self):
        return len(os.listdir('/proc/self/fd'))

    def test_default_schema_hash_omission_and_node_refusal_remain(self):
        self.group()
        report = self.module.observe(self.root, limits=self.limits())
        self.assertFalse(report['eligible'])
        self.assertEqual(report['unsupported_counts']['hardlink'], 3)
        self.assertNotIn('hardlink_groups', report)
        for name in self.members:
            self.assertNotIn('sha256', report['nodes'][name])
            self.assertNotIn('hardlink_group', report['nodes'][name])
        with self.assertRaises(ValueError):
            self.module.node(self.root, self.members[0], limits=self.limits())

    def test_complete_group_hashes_once_and_keeps_every_alias(self):
        first = self.group()
        original = self.module._file_hash
        calls = []
        original_open = self.module.os.open
        member_opens = {Path(name).name: 0 for name in self.members}

        def opened(*args, **kwargs):
            descriptor = original_open(*args, **kwargs)
            name = Path(os.fsdecode(args[0])).name
            if name in member_opens: member_opens[name] += 1
            return descriptor

        def hashed(fd, expected, limits):
            calls.append((os.fstat(fd).st_dev, os.fstat(fd).st_ino))
            return original(fd, expected, limits)

        baseline = self.fd_count()
        with patch.object(self.module, '_file_hash', side_effect=hashed), \
                patch.object(self.module.os, 'open', side_effect=opened):
            report = self.accepted()
        self.assertEqual(self.fd_count(), baseline)
        self.assertEqual(len(calls), 1)
        for name, count in member_opens.items():
            self.assertGreaterEqual(count, 2, 'initial and final named opens required: ' + name)
        key = self.members[0]
        self.assertEqual(set(report['hardlink_groups']), {key})
        info = first.stat()
        expected = dict(members=self.members, nlink=3, bytes=len(self.data), mode=0o640,
                        uid=info.st_uid, gid=info.st_gid, sha256=hashlib.sha256(self.data).hexdigest())
        self.assertEqual(report['hardlink_groups'][key], expected)
        for name in self.members:
            self.assertEqual(report['nodes'][name]['hardlink_group'], key)
            self.assertEqual(report['nodes'][name]['sha256'], expected['sha256'])
        self.assertEqual(report['footprint']['hardlink_entries'], 3)
        self.assertEqual(report['footprint']['hardlink_inodes'], 1)
        self.assertEqual(report['footprint']['bytes'], 3 * len(self.data))

    def test_outside_alias_cannot_be_hidden_by_aggregate_counts(self):
        first = self.group()
        os.link(first, self.work / 'outside')
        self.refused_observation()

    def test_same_device_file_and_directory_mount_crossings_refuse(self):
        self.group()
        original = self.module._mount_id
        for target in (self.root / 'usr', self.root / self.members[0]):
            with self.subTest(target=target.name):
                identity = (target.stat().st_dev, target.stat().st_ino)

                def mounted(fd, limits):
                    info = os.fstat(fd)
                    value = original(fd, limits)
                    return value + 100000 if (info.st_dev, info.st_ino) == identity else value

                with patch.object(self.module, '_mount_id', side_effect=mounted):
                    self.refused_observation()

    def test_missing_mount_identity_and_changed_final_mount_refuse(self):
        first = self.group()
        with patch.object(self.module, '_mount_id', side_effect=ValueError('missing mount identity')):
            self.refused_observation()
        original = self.module._mount_id
        identity = (first.stat().st_dev, first.stat().st_ino)
        calls = 0

        def changed(fd, limits):
            nonlocal calls
            info = os.fstat(fd)
            value = original(fd, limits)
            if (info.st_dev, info.st_ino) == identity:
                calls += 1
                if calls > len(self.members):
                    return value + 100000
            return value

        with patch.object(self.module, '_mount_id', side_effect=changed):
            self.refused_observation()
        self.assertGreater(calls, len(self.members))

    def test_hash_time_content_metadata_linkcount_and_rebind_drift_refuse(self):
        for mutation in ('content', 'mode', 'outside-link', 'split', 'rebind'):
            with self.subTest(mutation=mutation):
                case = self.root / mutation
                case.mkdir()
                members = (mutation + '/a', mutation + '/b')
                first = self.group(members)
                original = self.module._file_hash
                done = False

                def hashed(fd, expected, limits):
                    nonlocal done
                    digest = original(fd, expected, limits)
                    if not done and os.fstat(fd).st_ino == first.stat().st_ino:
                        done = True
                        if mutation == 'content': first.write_bytes(b'changed bytes\n')
                        elif mutation == 'mode': first.chmod(0o600)
                        elif mutation == 'outside-link': os.link(first, self.work / 'outside')
                        elif mutation == 'split':
                            alias = self.root / members[1]
                            alias.unlink(); alias.write_bytes(self.data)
                        else:
                            replacement = self.work / 'replacement'
                            replacement.write_bytes(self.data)
                            os.replace(replacement, first)
                    return digest

                baseline = self.fd_count()
                with patch.object(self.module, '_file_hash', side_effect=hashed):
                    self.refused_observation()
                self.assertTrue(done)
                self.assertEqual(self.fd_count(), baseline)
                shutil.rmtree(case)
                (self.work / 'outside').unlink(missing_ok=True)

    def test_group_alias_member_and_existing_resource_limits_refuse(self):
        self.group()
        self.group(('other/a', 'other/b'))
        for changes in ({'max_hardlink_groups': 1}, {'max_hardlink_aliases': 2},
                        {'max_hardlink_members': 2}, {'max_nodes': 1},
                        {'max_bytes': 1}, {'max_file_bytes': 1}, {'max_depth': 1}):
            with self.subTest(changes=changes):
                baseline = self.fd_count()
                self.refused_observation(limits=self.limits(**changes))
                self.assertEqual(self.fd_count(), baseline)
        self.refused_observation(limits=self.module.Limits(deadline=time.monotonic() - 1))

    def test_emfile_after_retaining_group_descriptor_cleans_every_fd(self):
        self.group()
        original_hash = self.module._file_hash
        original_open = self.module.os.open
        hashed = False

        def digest(*args):
            nonlocal hashed
            result = original_hash(*args)
            hashed = True
            return result

        def exhausted(*args, **kwargs):
            if hashed:
                raise OSError(errno.EMFILE, 'inert descriptor limit')
            return original_open(*args, **kwargs)

        baseline = self.fd_count()
        with patch.object(self.module, '_file_hash', side_effect=digest), \
                patch.object(self.module.os, 'open', side_effect=exhausted):
            self.refused_observation()
        self.assertTrue(hashed)
        self.assertEqual(self.fd_count(), baseline)

    def test_first_group_close_error_preserves_refusal_and_attempts_remaining_cleanup(self):
        self.group(('a1', 'a2'))
        self.group(('b1', 'b2'))
        original_hash = self.module._file_hash
        original_open, original_close = self.module.os.open, self.module.os.close
        retained, attempts, injected = [], [], []
        root_identity = (self.root.stat().st_dev, self.root.stat().st_ino)

        def hashed(fd, expected, limits):
            digest = original_hash(fd, expected, limits)
            retained.append(fd)
            return digest

        def exhausted(*args, **kwargs):
            if len(retained) == 2:
                raise OSError(errno.EMFILE, 'inert descriptor exhaustion')
            return original_open(*args, **kwargs)

        def close(fd):
            if len(retained) == 2:
                info = os.fstat(fd)
                attempts.append((fd, (info.st_dev, info.st_ino)))
            original_close(fd)
            if retained and fd == retained[0] and not injected:
                injected.append(fd)
                raise OSError(errno.EIO, 'inert close failure after release')

        baseline = self.fd_count()
        with patch.object(self.module, '_file_hash', side_effect=hashed), \
                patch.object(self.module.os, 'open', side_effect=exhausted), \
                patch.object(self.module.os, 'close', side_effect=close):
            report = self.observe()
        self.assertEqual(len(retained), 2)
        self.assertEqual(injected, [retained[0]])
        self.assertEqual([fd for fd, _ in attempts if fd in retained], retained)
        self.assertEqual(attempts[-1][1], root_identity)
        self.assertFalse(report['complete'])
        self.assertFalse(report['eligible'])
        self.assertEqual(report['unsupported_counts']['filesystem-observation-failed'], 1)
        self.assertEqual(report['unsupported_counts']['filesystem-cleanup-failed'], 1)
        self.assertEqual(report['unsupported'][0]['reason'], 'filesystem-observation-failed')
        self.assertEqual(self.fd_count(), baseline)

    def test_invalid_modes_and_cross_device_optin_refuse(self):
        self.group()
        for mode in (None, True, 1, 'allow', 'apple'):
            with self.subTest(mode=mode):
                with self.assertRaises(ValueError):
                    self.observe(hardlinks=mode)
        self.refused_observation(limits=self.limits(allow_cross_device=True))

    def test_group_limit_types_and_ceilings_are_not_coerced(self):
        for field, ceiling in (('max_hardlink_groups', 4096),
                               ('max_hardlink_aliases', 16384),
                               ('max_hardlink_members', 4096)):
            for value in (True, 0, -1, ceiling + 1, 1.5):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ValueError): self.limits(**{field: value})

    def test_mount_identity_parser_requires_one_positive_bounded_value(self):
        for raw in (b'pos: 0\n', b'mnt_id: 4\nmnt_id: 4\n', b'mnt_id: 0\n',
                    b'mnt_id: -1\n', b'mnt_id: unknown\n', b'mnt_id: 4\n' + b'x' * 4096):
            with self.subTest(raw_length=len(raw)):
                with patch.object(Path, 'open', return_value=io.BytesIO(raw)):
                    with self.assertRaises(ValueError): self.module._mount_id(99, self.limits())
        with patch.object(Path, 'open', side_effect=OSError(errno.EACCES, 'inert fdinfo refusal')):
            with self.assertRaises(OSError): self.module._mount_id(99, self.limits())
        with patch.object(Path, 'open', return_value=io.BytesIO(b'pos: 0\nmnt_id: 42\n')):
            self.assertEqual(self.module._mount_id(99, self.limits()), 42)

    def test_group_and_ancestor_numeric_metadata_reject_bool_coercion(self):
        self.group()
        report = self.accepted()
        for field in ('bytes', 'mode', 'uid', 'gid'):
            with self.subTest(field=field):
                changed = copy.deepcopy(report)
                changed['hardlink_groups'][self.members[0]][field] = False
                for name in self.members: changed['nodes'][name][field] = False
                with self.assertRaises(ValueError): self.project(changed)
        for field in ('mode', 'uid', 'gid'):
            changed = copy.deepcopy(report)
            changed['nodes']['usr'][field] = False
            with self.subTest(ancestor_field=field):
                with self.assertRaises(ValueError): self.project(changed)

    def test_default_projection_cannot_accept_group_tagged_nodes(self):
        self.group()
        report = self.accepted()
        with self.assertRaises(ValueError):
            self.module.projected_paths(report['nodes'], {}, limits=self.limits())

    def test_projection_rejects_malformed_group_maps_and_node_claims(self):
        self.group()
        report = self.accepted()
        key = self.members[0]
        mutations = {
            'missing-member': lambda x: x['nodes'].pop(self.members[1]),
            'duplicate-member': lambda x: x['hardlink_groups'][key].update(members=(key, key, self.members[2])),
            'wrong-key': lambda x: x['hardlink_groups'].update(forged=x['hardlink_groups'].pop(key)),
            'wrong-count': lambda x: x['hardlink_groups'][key].update(nlink=4),
            'wrong-hash': lambda x: x['hardlink_groups'][key].update(sha256='0' * 64),
            'wrong-mode': lambda x: x['hardlink_groups'][key].update(mode=0o600),
            'unknown-reference': lambda x: x['nodes'][key].update(hardlink_group='unknown'),
            'missing-reference': lambda x: x['nodes'][key].pop('hardlink_group'),
            'incomplete': lambda x: x.update(complete=False),
        }
        for name, mutate in mutations.items():
            with self.subTest(case=name):
                changed = copy.deepcopy(report)
                mutate(changed)
                with self.assertRaises(ValueError): self.project(changed)

    def test_payload_cannot_forge_group_membership(self):
        self.group()
        report = self.accepted()
        forged = copy.deepcopy(report['nodes'][self.members[0]])
        with self.assertRaises(ValueError):
            self.project(report, {'usr/share/new': forged})

    def test_selected_equal_byte_group_replacements_and_old_only_removal_refuse(self):
        self.group()
        report = self.accepted()
        member = self.members[0]
        ordinary = {k: v for k, v in report['nodes'][member].items() if k != 'hardlink_group'}
        for added, old, removed in (({member: ordinary}, (), ()),
                                    ({}, (member,), (member,)),
                                    ({member: ordinary}, (member,), ())):
            with self.subTest(added=bool(added), old=bool(old)):
                with self.assertRaises(ValueError): self.project(report, added, old, removed)

    def test_relative_alias_to_member_refuses_in_seed_and_projected_graph(self):
        self.group()
        (self.root / 'alias').symlink_to(self.members[0])
        report = self.accepted()
        ordinary = {k: v for k, v in report['nodes'][self.members[0]].items() if k != 'hardlink_group'}
        with self.assertRaises(ValueError): self.project(report, {'alias': ordinary})
        with self.assertRaises(ValueError): self.project(report, {}, old={'alias'}, removed={'alias'})
        with self.assertRaises(ValueError):
            self.project(report, {'fresh-alias': {'type': 'symlink', 'mode': 0o777,
                         'uid': os.getuid(), 'gid': os.getgid(), 'target': self.members[0]}})

    def test_ancestor_removal_replacement_and_redirect_refuse(self):
        self.group()
        report = self.accepted()
        for ancestor in ('usr', 'usr/share'):
            with self.subTest(ancestor=ancestor):
                with self.assertRaises(ValueError): self.project(report, {}, old={ancestor}, removed={ancestor})
                changed = dict(report['nodes'][ancestor], mode=0o700)
                with self.assertRaises(ValueError): self.project(report, {ancestor: changed})
                redirected = dict(type='symlink', mode=0o777, uid=os.getuid(), gid=os.getgid(), target='elsewhere')
                with self.assertRaises(ValueError): self.project(report, {ancestor: redirected})

    def test_unrelated_update_and_identical_shared_directories_succeed(self):
        self.group()
        old = self.root / 'usr/share/unrelated'
        old.write_bytes(b'old\n')
        report = self.accepted()
        new = dict(report['nodes']['usr/share/unrelated'], bytes=4, sha256=hashlib.sha256(b'new\n').hexdigest())
        added = {'usr': report['nodes']['usr'], 'usr/share': report['nodes']['usr/share'],
                 'usr/share/unrelated': new}
        projected = self.project(report, added, old=added.keys(), protected={self.members[0]})
        self.assertEqual(projected[self.members[1]], report['nodes'][self.members[1]])
        self.assertEqual(projected['usr/share/unrelated']['sha256'], new['sha256'])
        self.preserved(report, self.accepted(), protected={self.members[0]})

    def test_selected_old_absent_new_requires_explicit_removal_accounting(self):
        self.group()
        (self.root / 'old-file').write_bytes(b'old')
        report = self.accepted()
        with self.assertRaises(ValueError): self.project(report, old={'old-file'})
        projected = self.project(report, old={'old-file'}, removed={'old-file'})
        self.assertNotIn('old-file', projected)

    def test_every_protected_alias_is_preserved_not_only_owned_name(self):
        first = self.group()
        before = self.accepted()
        # A write through an unowned alias changes the protected member as well.
        (self.root / self.members[2]).write_bytes(b'changed through alias\n')
        after = self.accepted()
        with self.assertRaises(ValueError): self.preserved(before, after, protected={self.members[0]})
        self.assertEqual(first.read_bytes(), b'changed through alias\n')

    def test_preservation_rejects_metadata_topology_and_equal_byte_split(self):
        first = self.group()
        before = self.accepted()
        first.chmod(0o600)
        with self.assertRaises(ValueError): self.preserved(before, self.accepted())
        first.chmod(0o640)
        alias = self.root / self.members[2]
        alias.unlink(); alias.write_bytes(self.data); alias.chmod(0o640)
        after = self.accepted()
        with self.assertRaises(ValueError): self.preserved(before, after)
        changed = copy.deepcopy(before)
        changed['hardlink_groups'][self.members[0]]['uid'] += 1
        for name in self.members: changed['nodes'][name]['uid'] += 1
        with self.assertRaises(ValueError): self.preserved(before, changed)

    def test_new_group_added_after_observation_is_not_preserved(self):
        self.group()
        before = self.accepted()
        self.group(('new/a', 'new/b'))
        with self.assertRaises(ValueError): self.preserved(before, self.accepted())

    def test_independent_absolute_link_auxiliary_and_special_refusals_remain(self):
        self.group()
        cases = ('absolute', 'auxiliary', 'fifo')
        for kind in cases:
            with self.subTest(kind=kind):
                if kind == 'absolute':
                    node = self.root / 'absolute'; node.symlink_to('/etc/passwd')
                elif kind == 'auxiliary':
                    node = self.root / 'usr/bin/ldconfig'; node.parent.mkdir(parents=True); node.write_bytes(b'inert')
                else:
                    node = self.root / 'fifo'; os.mkfifo(node)
                self.refused_observation()
                node.unlink()


if __name__ == '__main__':
    unittest.main(verbosity=2)
