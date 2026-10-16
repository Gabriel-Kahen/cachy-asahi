#!/usr/bin/env python3
"""Inert full node-map and descriptor checks; no package transaction actors."""
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import internal_runtime as internal

class Tests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='runtime-data-'); self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)/'root'; self.root.mkdir()
        for name in ('home/user/config','usr/share/a','usr/share/selected',
                     'var/lib/pacman/local/selected-1-1/desc','var/lib/pacman/local/held-1-1/desc'):
            path=self.root/name; path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(b'inert data\n')
        os.link(self.root/'usr/share/a',self.root/'usr/share/b')
        (self.root/'usr/alias').symlink_to('share')
        self.runtime=internal.Runtime.__new__(internal.Runtime)
        self.runtime.root=self.root
        self.runtime.root_limits=internal.roots.Limits(deadline=time.monotonic()+20,max_nodes=100,max_bytes=1024**2,max_file_bytes=1024**2)
        self.runtime.footprints=[]
        self.runtime.observation=self.runtime.baseline=self.runtime.projected=self.runtime.alpm=None
        self.runtime.old_paths=set(); self.runtime.database_changes=()
        self.seed=self.runtime.tree(self.root)

    def project(self,payload):
        self.runtime.old_paths={'usr/share/selected'}
        return self.runtime.projected_paths(self.seed,payload)

    def file(self,data):
        import hashlib
        return dict(type='file',bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),mode=0o644,uid=os.getuid(),gid=os.getgid())

    def test_live_group_node_reads_and_parent_alias_resolution(self):
        row=self.runtime.node(self.root/'usr/alias/a')
        self.assertEqual(row,self.file(b'inert data\n')); self.assertNotIn('hardlink_group',row)
        self.assertEqual(self.runtime.resolve_nodes(self.seed,'usr/alias/a'),'usr/share/a')

    def test_live_parent_alias_drift_is_not_hidden_by_cached_resolution(self):
        alias=self.root/'usr/alias'; alias.unlink(); alias.symlink_to('../home/user')
        with self.assertRaisesRegex(ValueError,'observed symlink differs'):
            self.runtime.node(self.root/'usr/alias/a')

    def test_selected_directory_removal_refused_before_commit(self):
        (self.root/'usr/share/retired').mkdir()
        self.runtime.baseline=self.runtime.observation=None
        self.seed=self.runtime.tree(self.root)
        self.runtime.old_paths={'usr/share/retired'}
        with self.assertRaisesRegex(ValueError,'removal unsupported'):
            self.runtime.projected_paths(self.seed,{})
        self.assertIsNone(self.runtime.projected)

    def test_group_content_topology_and_metadata_drift_refused(self):
        for kind in ('content','outside-alias','mode'):
            with self.subTest(kind=kind):
                path=self.root/'usr/share/a'
                if kind=='content': path.write_bytes(b'changed')
                elif kind=='outside-alias': os.link(path,self.root.parent/'outside')
                else: path.chmod(0o600)
                with self.assertRaises(ValueError): self.runtime.node(path)
                if kind=='content': path.write_bytes(b'inert data\n')
                elif kind=='outside-alias': (self.root.parent/'outside').unlink()
                else: path.chmod(0o644)

    def test_symlink_node_is_literal_and_leaf_type_drift_refused(self):
        self.assertEqual(self.runtime.node(self.root/'usr/alias')['target'],'share')
        (self.root/'home/user/config').unlink(); (self.root/'home/user/config').symlink_to('/outside')
        with self.assertRaises((ValueError,OSError)): self.runtime.node(self.root/'home/user/config')

    def test_projection_preserves_all_unrelated_nodes_and_groups(self):
        payload={'usr/share/selected':self.file(b'new')}
        projected=self.project(payload)
        self.assertEqual(projected['home/user/config'],self.seed['home/user/config'])
        self.assertEqual(projected['usr/share/a'],self.seed['usr/share/a'])
        self.runtime.tree(self.root) # prepare must retain original bytes
        (self.root/'usr/share/selected').write_bytes(b'new')
        self.runtime.commit_ready=True
        self.assertEqual(self.runtime.tree(self.root),projected)

    def test_group_touch_or_payload_removal_refused(self):
        self.runtime.old_paths={'usr/share/a'}
        with self.assertRaisesRegex(ValueError,'hardlink path touched'):
            self.runtime.projected_paths(self.seed,{'usr/share/a':self.file(b'new')})
        self.runtime.old_paths={'usr/share/selected'}
        with self.assertRaisesRegex(ValueError,'removal unsupported'):
            self.runtime.projected_paths(self.seed,{})

    def test_unrelated_user_change_before_and_after_commit_refused(self):
        self.project({'usr/share/selected':self.file(b'inert data\n')})
        for committed in (False,True):
            self.runtime.commit_ready=committed
            (self.root/'home/user/config').write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError,'unrelated root content changed'): self.runtime.tree(self.root)
            (self.root/'home/user/config').write_bytes(b'inert data\n')

    def test_only_selected_database_entries_may_change_after_commit(self):
        self.project({'usr/share/selected':self.file(b'inert data\n')})
        self.runtime.database_changes=('var/lib/pacman/local/selected-1-1','var/lib/pacman/local/selected-2-1')
        self.runtime.commit_ready=True
        (self.root/'var/lib/pacman/local/selected-1-1/desc').write_bytes(b'selected DB change')
        self.runtime.tree(self.root)
        (self.root/'var/lib/pacman/local/held-1-1/desc').write_bytes(b'held DB change')
        with self.assertRaisesRegex(ValueError,'unrelated root content changed'): self.runtime.tree(self.root)

    def test_selected_database_cannot_change_before_commit(self):
        self.project({'usr/share/selected':self.file(b'inert data\n')})
        self.runtime.database_changes=('var/lib/pacman/local/selected-1-1',)
        (self.root/'var/lib/pacman/local/selected-1-1/desc').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'root changed before commit'): self.runtime.tree(self.root)

    def test_absolute_auxiliary_and_external_hardlink_still_refused(self):
        (self.root/'absolute').symlink_to('/usr/share/a')
        with self.assertRaisesRegex(ValueError,'unsupported or incomplete'): self.runtime.tree(self.root)
        (self.root/'absolute').unlink()
        (self.root/'usr/bin').mkdir(); (self.root/'usr/bin/ldconfig').write_bytes(b'inert auxiliary')
        with self.assertRaisesRegex(ValueError,'unsupported or incomplete'): self.runtime.tree(self.root)
        (self.root/'usr/bin/ldconfig').unlink()
        os.link(self.root/'usr/share/a',self.root.parent/'outside')
        with self.assertRaisesRegex(ValueError,'unsupported or incomplete'): self.runtime.tree(self.root)

    def config(self):
        return dict(platform_mode='generic-development', limits=dict(root_nodes=100,root_bytes=1024**2,
            file_bytes=1024**2,package_files=100,archive_bytes=1024**2,archive_total_bytes=2*1024**2,
            decoded_bytes=4*1024**2,archive_members=100,window_bytes=1024**2,seconds=20))

    def test_real_constructor_and_exact_selection_capture_database_scope(self):
        config=self.config(); args=SimpleNamespace(root=str(self.root))
        runtime=internal.Runtime(args,config)
        before={'selected':'1-1',**{f'held-{i}':'1-1' for i in range(586)}}
        config.update(before_lock_sha256=internal.scale.inventory_sha(before),
            after_lock_sha256=internal.scale.inventory_sha(dict(before,selected='2-1')))
        runtime.alpm=SimpleNamespace(owned_files=lambda names: {'usr/share/selected'})
        runtime.selection({},before,{'selected':'2-1'})
        self.assertEqual(runtime.old_paths,{'usr/share/selected'})
        self.assertEqual(runtime.database_changes,('var/lib/pacman/local/selected-1-1','var/lib/pacman/local/selected-2-1'))
        config['platform_mode']='apple'
        with self.assertRaisesRegex(ValueError,'generic development runtime'):
            internal.Runtime(args,config)

    def test_apply_preserves_known_commit_failure_truth(self):
        args=SimpleNamespace(root=str(self.root),workspace=str(self.root.parent),scale='inert',scale_sha256='0'*64)
        failure=dict(status='FAIL',phase='observe-after',commit_started=True,packages_committed=True,checkpoint_changed=False)
        with patch.object(internal.scale.bound,'guard'), patch.object(internal.scale,'configuration',return_value=self.config()), \
             patch.object(internal.scale.bound,'apply',return_value=failure) as apply:
            row=internal.apply(args)
        self.assertTrue(row['packages_committed']); self.assertFalse(row['checkpoint_changed'])
        self.assertEqual(row['phase'],'observe-after'); self.assertIsInstance(apply.call_args.kwargs['adapter'],internal.Runtime)
        self.assertEqual(row['full587_composition'],'NOT ESTABLISHED')

    def test_precommit_flag_set_only_after_existing_checks(self):
        self.runtime.projected=self.seed
        with patch.object(internal.scale.Runtime,'precommit',side_effect=ValueError('configuration drift')):
            with self.assertRaisesRegex(ValueError,'configuration drift'): self.runtime.precommit()
        self.assertFalse(getattr(self.runtime,'commit_ready',False))
        with patch.object(internal.scale.Runtime,'precommit'): self.runtime.precommit()
        self.assertTrue(self.runtime.commit_ready)

if __name__=='__main__': unittest.main()
