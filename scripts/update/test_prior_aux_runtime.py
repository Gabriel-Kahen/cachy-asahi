#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real TEST signatures/read-only host ALPM; synthetic auxiliary bytes only.

Run in an owned mapped-root network namespace. No ALPM commit/helper execution.
Filesystem edits below model observations; they are not transaction evidence.
"""
from contextlib import ExitStack
import copy
from dataclasses import replace
import io
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import aux_checkpoint as aux
import aux_runtime
import internal_runtime as strict
import linked_runtime
import prior_aux_runtime as runtime
import root_link_selection as links
import scale_update as scale
import test_auxiliary as fixtures
from test_snapshot import signing


class Cases(unittest.TestCase):
    """Every case keeps genuine signature verification and read-only ALPM."""
    limits = fixtures.Closure.limits
    mkdir = fixtures.Closure.mkdir
    write = fixtures.Closure.write
    keys = fixtures.Closure.keys

    @classmethod
    def setUpClass(cls):
        if os.getuid() != 0 or os.getgid() != 0:
            raise AssertionError('run in an owned mapped-root user/network namespace; no skips')
        cls.stack = ExitStack(); cls.addClassCleanup(cls.stack.close)
        base = Path(cls.stack.enter_context(tempfile.TemporaryDirectory(prefix='pak-')))
        cls.key_home = base/'k'
        cls.signer, cls.public, sign = cls.stack.enter_context(signing(cls.key_home))
        cls.sign = staticmethod(sign)

    def setUp(self):
        fixtures.Closure.setUp(self)  # Explicit inert helper/library selection.
        for name, value in (('CHAIN_PATHS', ()), ('LINK_NODES', {}), ('RESOLVED_ENDPOINTS', {}),
                            ('DATA_ONLY_ENDPOINTS', {}), ('MTAB_TARGETS', ())):
            selected = patch.object(links, name, value); selected.start(); self.addCleanup(selected.stop)
        self.entries = {'usr/share/selected/data': b'old data', 'usr/share/selected/retired': b'old retired',
                        'usr/share/selected/retired-link': ('data',)}
        for name, data in self.entries.items():
            if isinstance(data, tuple): (self.root/name).symlink_to(data[0])
            else: self.write(name, data)
        local = self.root/'var/lib/pacman/local'
        shutil.rmtree(local); local.mkdir()
        (local/'ALPM_DB_VERSION').write_text('9\n')
        self.before = {'selected': '1-1', **{f'held-{i}': '1-1' for i in range(586)}}
        for name in self.before:
            directory = local/(name+'-1-1'); directory.mkdir()
            (directory/'desc').write_text(f'%NAME%\n{name}\n\n%VERSION%\n1-1\n\n%ARCH%\nany\n\n')
            owned = self.entries if name == 'selected' else ()
            (directory/'files').write_text('%FILES%\n'+'\n'.join(owned)+'\n\n')
        self.args.prior_archive = str(self.base/'old.pkg.tar.gz')
        self.archive(Path(self.args.prior_archive), '1-1', self.entries)
        self.bundle = self.work/'authenticated/bundle'; self.bundle.mkdir(parents=True)
        public = self.bundle.parent/'public.gpg'; public.write_bytes(self.public)
        self.snapshot = dict(bundle=self.bundle, keyring=public, metadata=dict(signer=self.signer),
                             release=dict(packages=[dict(name='selected', version='2-1', arch='any')]))
        self.config = fixtures.Closure.config(self)
        self.config['limits']['root_nodes'] = 5000
        self.config.update(before_lock_sha256=scale.inventory_sha(self.before),
                           after_lock_sha256=scale.inventory_sha(dict(self.before, selected='2-1')))
        self.instance = runtime.Runtime(self.args, self.config, comparator_path=fixtures.COMPARATOR)
        self.seed = self.instance.tree(self.root)
        self.alpm = self.instance.Alpm(self.root, self.key_home, self.base/'alpm.log', os.uname().machine)
        self.addCleanup(self.alpm.close)
        self.assertEqual(self.alpm.inventory(), self.before)

    def archive(self, path, version, entries, *, control=None, metadata=''):
        with tarfile.open(path, 'w:gz') as stream:
            controls = f'pkgname = selected\npkgver = {version}\narch = any\nlicense = MIT\n{metadata}'.encode()
            for name, data in {'.PKGINFO': controls, **entries, **(control or {})}.items():
                node = tarfile.TarInfo(name); node.mode = 0o644
                if data is None: node.type, node.mode = tarfile.DIRTYPE, 0o755; stream.addfile(node)
                elif isinstance(data, tuple):
                    node.type, node.mode, node.linkname = tarfile.SYMTYPE, 0o777, data[0]; stream.addfile(node)
                else:
                    node.size = len(data); stream.addfile(node, io.BytesIO(data))
        self.sign(path)
        return path

    def select(self):
        self.instance.selection(self.snapshot, self.before, {'selected': '2-1'})

    def reobserve(self):
        self.instance = runtime.Runtime(self.args, self.config, comparator_path=fixtures.COMPARATOR)
        self.instance.alpm = self.alpm
        self.seed = self.instance.tree(self.root)

    def new_payload(self, entries=None, **kwargs):
        entries = {'usr/share/selected/data': b'new data', 'usr/share/selected/new': b'new leaf'} if entries is None else entries
        path = self.archive(self.base/'new.pkg.tar.gz', '2-1', entries, **kwargs)
        return self.instance.archive_payload(path, {})

    def prepared(self):
        self.select(); payload = self.new_payload()
        return self.instance.projected_paths(self.seed, payload)

    def model_precommit(self):
        # The component does not execute bound_update, its capacity actor or commit.
        with patch.object(scale.Runtime, 'precommit'):
            self.instance.precommit()

    def test_real_signed_prior_and_ALPM_project_leaf_update_addition_and_removal(self):
        projected = self.prepared()
        self.assertNotIn('usr/share/selected/retired', projected)
        self.assertNotIn('usr/share/selected/retired-link', projected)
        self.assertIn('usr/share/selected/new', projected)
        self.assertEqual(projected[aux.HELPER_NODE], self.seed[aux.HELPER_NODE])
        self.assertEqual(self.instance.prior['evidence']['signature']['hash_algorithm'], '8')
        self.assertEqual(self.instance.prior['evidence']['projected_obsolete_paths'],
                         ['usr/share/selected/retired', 'usr/share/selected/retired-link'])
        self.assertEqual(self.instance.control_accounting['compressed_bytes'],
                         self.instance.prior['accounting']['compressed_bytes']+(self.base/'new.pkg.tar.gz').stat().st_size)
        self.assertEqual(self.instance.control_limits.deadline, self.instance.archive_limits.deadline)
        self.assertEqual(self.instance.tree(self.root), self.seed)  # Projection never mutates root.

    def test_prior_signature_tamper_refused(self):
        signature = Path(self.args.prior_archive+'.sig'); signature.write_bytes(b'invalid')
        with self.assertRaisesRegex(scale.bound.client.Error, 'GPG rejected'): self.select()
        self.assertFalse(getattr(self.instance, 'commit_ready', False))
        self.assertEqual(self.instance.tree(self.root), self.seed)

    def test_wrong_old_version_refused_after_real_signature_verification(self):
        self.archive(Path(self.args.prior_archive), '0-1', self.entries)
        with self.assertRaisesRegex(ValueError, 'identity differs'): self.select()

    def test_backup_semantics_refused(self):
        self.archive(Path(self.args.prior_archive), '1-1', self.entries,
                     metadata='backup = usr/share/selected/data\n')
        with self.assertRaisesRegex(ValueError, 'backup semantics'): self.select()

    def test_modified_updated_leaf_refused_at_selection(self):
        (self.root/'usr/share/selected/data').write_bytes(b'local ed')  # Same size; hash must catch the edit.
        with self.assertRaisesRegex(ValueError, 'root-content-changed'):
            self.instance.tree(self.root)  # Baseline drift refuses before selection.
        with self.assertRaisesRegex(ValueError, 'observed file content changed'):
            self.select()

    def test_modified_prior_input_refused_at_tree_and_precommit(self):
        self.prepared()
        path = Path(self.args.prior_archive); path.write_bytes(path.read_bytes()+b'changed')
        with self.assertRaisesRegex(ValueError, 'prior input'): self.instance.tree(self.root)
        with self.assertRaisesRegex(ValueError, 'prior input'): self.model_precommit()
        self.assertFalse(getattr(self.instance, 'commit_ready', False))

    def test_prior_copy_changed_after_selection_refused_before_projection(self):
        self.select()
        copied = self.bundle.parent.parent/'prior-package/archive'
        copied.chmod(0o600); copied.write_bytes(copied.read_bytes()+b'changed')
        with self.assertRaisesRegex(ValueError, 'prior input'): self.instance.projected_paths(self.seed, {})

    def test_old_install_control_and_native_prefix_refused_without_changing_old_parser(self):
        self.archive(Path(self.args.prior_archive), '1-1', self.entries, control={'.INSTALL': b'echo unsafe\n'})
        with self.assertRaisesRegex(ValueError, 'control member'): self.select()
        self.assertIn('.INSTALL', scale.archives.CONTROLS)
        self.assertNotIn('.INSTALL', runtime.archives.CONTROLS)

    def test_old_native_bytes_refused_after_signature_verification(self):
        entries = dict(self.entries, **{'usr/share/selected/data': b'\x7fELFnative bytes'})
        self.archive(Path(self.args.prior_archive), '1-1', entries)
        with self.assertRaisesRegex(ValueError, 'native ELF or script'): self.select()

    def test_new_install_control_refused(self):
        self.select()
        with self.assertRaisesRegex(ValueError, 'control member'):
            self.new_payload(control={'.INSTALL': b'echo unsafe\n'})

    def test_new_native_or_script_bytes_refused_even_without_execute_mode(self):
        self.select()
        for data in (b'\x7fELFnot an accepted native binary', b'#!/bin/sh\necho unsafe\n'):
            with self.subTest(data=data), self.assertRaisesRegex(ValueError, 'native ELF or script'):
                # Separate counter snapshot for independent failed decoder cases.
                saved = dict(self.instance.control_accounting)
                try: self.new_payload({'usr/share/selected/data': data})
                finally: self.instance.control_accounting = saved

    def test_auxiliary_selected_link_and_executable_paths_refused(self):
        self.select()
        payload = self.new_payload()
        node = payload['usr/share/selected/data']
        for name in (aux.HELPER_NODE, 'usr/lib/libfixture-a.so', 'usr/share/selected/action.hook'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.instance.projected_paths(self.seed, {name: node})
        with self.assertRaisesRegex(ValueError, 'executable'):
            self.instance.projected_paths(self.seed, {'usr/share/selected/data': dict(node, mode=0o755)})
        self.assertIs(self.instance.baseline['nodes'], self.seed)

    def test_foreign_updated_and_new_leaves_refused(self):
        held = self.root/'var/lib/pacman/local/held-0-1-1/files'
        held.write_text('%FILES%\nusr/share/selected/data\n\n')
        self.reobserve()
        with self.assertRaisesRegex(ValueError, 'foreign ownership'): self.select()

    def test_new_foreign_owned_leaf_is_not_adopted_even_when_absent(self):
        held = self.root/'var/lib/pacman/local/held-0-1-1/files'
        held.write_text('%FILES%\nusr/share/selected/new\n\n')
        self.reobserve()
        self.select()
        with self.assertRaisesRegex(ValueError, 'foreign ownership'):
            self.instance.projected_paths(self.seed, self.new_payload())

    def test_selected_leaf_hardlink_refused_before_projection(self):
        os.link(self.root/'usr/share/selected/data', self.base/'outside-hardlink')
        with self.assertRaisesRegex(ValueError, 'observed file differs'): self.select()

    def test_old_and_new_archives_share_original_aggregate_budget(self):
        path = self.archive(self.base/'new.pkg.tar.gz', '2-1', {'usr/share/selected/data': b'new data'})
        old_size, new_size = Path(self.args.prior_archive).stat().st_size, path.stat().st_size
        self.instance.archive_limits = replace(self.instance.archive_limits,
            total_compressed_bytes=old_size+new_size-1)
        self.instance.control_limits = replace(self.instance.control_limits,
            total_compressed_bytes=old_size+new_size-1)
        self.select()
        with self.assertRaisesRegex(ValueError, 'aggregate compressed'):
            self.instance.archive_payload(path, {})

    def test_selected_directory_cannot_be_replaced_by_leaf(self):
        self.select(); payload = self.new_payload()
        self.instance.old_paths.add('usr/share/selected')
        self.instance.prior['payload']['usr/share/selected'] = self.seed['usr/share/selected']
        with self.assertRaisesRegex(ValueError, 'directory replacement'):
            self.instance.projected_paths(self.seed, {'usr/share/selected': payload['usr/share/selected/data']})

    def test_directory_creation_and_parent_alias_refused(self):
        self.select(); payload = self.new_payload()
        with self.assertRaisesRegex(ValueError, 'directory creation'):
            self.instance.projected_paths(self.seed, {'usr/share/selected/new-dir': dict(type='directory', mode=0o755, uid=0, gid=0)})
        with self.assertRaises(ValueError):
            self.instance.projected_paths(self.seed, {'usr/share/selected/link': dict(type='symlink', mode=0o777, uid=0, gid=0, target='../../user/config')})

    def test_selected_absolute_and_data_only_literals_survive_projection(self):
        absolute, mask = 'usr/share/held-absolute', 'builder-disabled-hooks/test.hook'
        (self.root/absolute).symlink_to('/usr/lib/libfixture-a.so')
        (self.root/'builder-disabled-hooks').mkdir()
        (self.root/mask).symlink_to('/dev/null')
        observation = strict.roots.observe(self.root, limits=self.instance.root_limits, hardlinks=strict.MODE)
        changes = {'CHAIN_PATHS': tuple(sorted((absolute, mask))),
                   'LINK_NODES': {name: observation['nodes'][name] for name in (absolute, mask)},
                   'RESOLVED_ENDPOINTS': {absolute: 'usr/lib/libfixture-a.so'},
                   'DATA_ONLY_ENDPOINTS': {mask: 'dev/null'}}
        with ExitStack() as selected:
            for name, value in changes.items(): selected.enter_context(patch.object(links, name, value))
            self.instance = runtime.Runtime(self.args, self.config, comparator_path=fixtures.COMPARATOR)
            self.instance.alpm = self.alpm
            self.seed = self.instance.tree(self.root)
            projected = self.prepared()
            for name in (absolute, mask): self.assertEqual(projected[name], self.seed[name])
            self.assertEqual(self.instance.tree(self.root), self.seed)

    def test_prior_changed_during_observation_is_refused_after_observation(self):
        self.prepared()
        original = linked_runtime.Runtime.tree
        def observed(instance, root):
            nodes = original(instance, root)
            path = Path(self.args.prior_archive); path.write_bytes(path.read_bytes()+b'drift')
            return nodes
        with patch.object(linked_runtime.Runtime, 'tree', observed):
            with self.assertRaisesRegex(ValueError, 'prior input'): self.instance.tree(self.root)

    def test_auxiliary_drift_after_modeled_commit_refused_and_no_rollback_claim(self):
        self.prepared(); self.model_precommit()
        self.write(aux.HELPER_NODE, b'changed helper', 0o755)
        with self.assertRaisesRegex(ValueError, 'helper-pin'): self.instance.tree(self.root)

    def test_modeled_postcommit_leaf_map_preserves_auxiliary_and_all_unrelated_nodes(self):
        projected = self.prepared(); self.model_precommit()
        self.write('usr/share/selected/data', b'new data'); self.write('usr/share/selected/new', b'new leaf')
        (self.root/'usr/share/selected/retired').unlink(); (self.root/'usr/share/selected/retired-link').unlink()
        self.assertEqual(self.instance.tree(self.root), projected)
        self.assertEqual(self.instance.auxiliary_checks[-1]['auxiliary_transition']['kind'], 'RAW_EQUAL')

    def test_exact_release_selection_and_missing_prior_refused(self):
        bad = copy.deepcopy(self.snapshot)
        bad['release']['packages'].append(dict(name='other', version='2-1', arch='any'))
        with self.assertRaisesRegex(ValueError, 'one exact'):
            self.instance.selection(bad, self.before, {'selected': '2-1'})
        args = SimpleNamespace(root=str(self.root))
        with self.assertRaisesRegex(ValueError, 'prior archive required'):
            runtime.Runtime(args, self.config, comparator_path=fixtures.COMPARATOR)

    def test_old_setup_only_selection_remains_refusal(self):
        for adapter in (aux_runtime.Runtime, linked_runtime.Runtime):
            instance = adapter(self.args, self.config, comparator_path=fixtures.COMPARATOR)
            with self.assertRaisesRegex(ValueError, 'exact-setup-transition'):
                instance.selection(self.snapshot, self.before, {'selected': '2-1'})

    def test_apply_preserves_known_commit_failure_and_prior_evidence(self):
        self.prepared()
        failure = dict(status='FAIL', phase='observe-after', commit_started=True,
                       packages_committed=True, checkpoint_changed=False)
        with patch.object(scale.bound, 'guard'), patch.object(scale, 'configuration', return_value=self.config), \
                patch.object(runtime, 'Runtime', return_value=self.instance), \
                patch.object(scale.bound, 'apply', return_value=failure):
            row = runtime.apply(self.args, comparator_path=fixtures.COMPARATOR)
        self.assertTrue(row['packages_committed']); self.assertTrue(row['commit_started'])
        self.assertFalse(row['checkpoint_changed']); self.assertEqual(row['phase'], 'observe-after')
        self.assertEqual(row['rollback'], 'NOT IMPLEMENTED')
        self.assertEqual(row['prior_archive'], self.instance.prior['evidence'])


if __name__ == '__main__':
    unittest.main()
