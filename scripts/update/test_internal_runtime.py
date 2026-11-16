#!/usr/bin/env python3
"""Inert full node-map and descriptor checks; no package transaction actors."""
import os
from contextlib import ExitStack, contextmanager
from dataclasses import replace
import hashlib
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
import tarfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import internal_runtime as internal

# TEST ONLY: independently read from the whole-pinned official image layers,
# including pacman's files/mtree; never accept a digest derived from this host.
CI_ALPM_PROFILE = 'archlinux-base-fcee73ea-pacman-7.1.0.r9.g54d9411-3'
CI_ALPM_IMAGE = 'sha256:fcee73ea1b96e236248f53a213f71276cc9072d9025b58bce9915e32f19963ae'
CI_ALPM_PATH = Path('/usr/lib/libalpm.so.16.0.1')
CI_ALPM_SHA = '1bc59ef4cee493246db69c9466970de01d24fdc32a4a4c18c77063af66705e90'
CACHY_ALPM_SHA = 'da30edd45277cf4b1000485658976042f8106fe0b97378d1e6c4e81a9d7c4888'
CI_PACMAN_DESC = Path('/var/lib/pacman/local/pacman-7.1.0.r9.g54d9411-3/desc')
CI_PACMAN_DESC_SHA = '0ee6e4c981f717be73dea1a9311ad7a947a2a6929060b2250a0f70342d093c58'


def profile_file(path, size, expected):
    node = path.lstat()
    internal.need(stat.S_ISREG(node.st_mode) and node.st_size == size,
                  'TEST libalpm profile file identity changed')
    internal.need(hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                  'TEST libalpm profile bytes changed')


def ci_alpm_identity():
    installer = internal.roots.installer
    internal.need(os.uname().machine == 'x86_64', 'TEST libalpm profile architecture changed')
    internal.need(installer.LIBRARY == CI_ALPM_PATH and installer.LIBRARY_SHA == CACHY_ALPM_SHA,
                  'TEST libalpm default binding changed')
    profile_file(CI_PACMAN_DESC, 719, CI_PACMAN_DESC_SHA)
    profile_file(CI_ALPM_PATH, 281240, CI_ALPM_SHA)


@contextmanager
def alpm_test_profile(name):
    if name is None:
        yield None
        return
    internal.need(name == CI_ALPM_PROFILE, 'unknown TEST libalpm profile')
    ci_alpm_identity()  # Refuse before changing the fixture module or creating keys.
    with patch.object(internal.roots.installer, 'LIBRARY_SHA', CI_ALPM_SHA):
        yield dict(scope='TEST read-only host-x86_64 prior archives', profile=name,
                   image_manifest=CI_ALPM_IMAGE, package='pacman 7.1.0.r9.g54d9411-3',
                   library=str(CI_ALPM_PATH), library_bytes=281240, library_sha256=CI_ALPM_SHA,
                   expected_abi='16.0.1', native_ARM='NOT RUN', hardware='NOT RUN')


class AlpmProfileTests(unittest.TestCase):
    """Finite profile controls; no library load, GPG or package actor."""
    def test_default_keeps_original_pin_without_probing_ci_identity(self):
        with patch(__name__ + '.ci_alpm_identity') as identity, alpm_test_profile(None) as row:
            self.assertIsNone(row)
            self.assertEqual(internal.roots.installer.LIBRARY_SHA, CACHY_ALPM_SHA)
        identity.assert_not_called()

    def test_explicit_profile_binding_and_diagnostic_restore_on_success_and_error(self):
        for fail in (False, True):
            with self.subTest(fail=fail), patch(__name__ + '.ci_alpm_identity') as identity:
                try:
                    with alpm_test_profile(CI_ALPM_PROFILE) as row:
                        self.assertEqual(internal.roots.installer.LIBRARY_SHA, CI_ALPM_SHA)
                        self.assertEqual(row['image_manifest'], CI_ALPM_IMAGE)
                        self.assertEqual(row['library_sha256'], CI_ALPM_SHA)
                        if fail: raise RuntimeError('fixture setup failed')
                except RuntimeError as error:
                    self.assertTrue(fail)
                    self.assertEqual(str(error), 'fixture setup failed')
                identity.assert_called_once_with()
                self.assertEqual(internal.roots.installer.LIBRARY_SHA, CACHY_ALPM_SHA)

    def test_unknown_profile_refused_before_identity_or_library_load(self):
        with patch(__name__ + '.ci_alpm_identity') as identity, \
                patch.object(internal.roots.installer.C, 'CDLL') as load:
            with self.assertRaisesRegex(ValueError, 'unknown TEST'):
                with alpm_test_profile(CI_ALPM_PROFILE + '-changed'): self.fail('accepted')
        identity.assert_not_called(); load.assert_not_called()

    def test_failed_class_setup_restores_profile_through_unittest_cleanup(self):
        class Refused(PriorArchives):
            def runTest(self): self.fail('setup failure must prevent the case')
        with patch.dict(os.environ, CACHY_ASAHI_TEST_ALPM_PROFILE=CI_ALPM_PROFILE), \
                patch(__name__ + '.ci_alpm_identity'), patch.object(os, 'getuid', return_value=0), \
                patch.object(os, 'getgid', return_value=0), patch('test_snapshot.signing',
                side_effect=RuntimeError('fixture setup failed')), patch('sys.stdout', new=io.StringIO()):
            result = unittest.TestResult()
            unittest.TestSuite([Refused()]).run(result)
        self.assertEqual(result.testsRun, 0)
        self.assertEqual(len(result.errors), 1)
        self.assertIn('fixture setup failed', result.errors[0][1])
        self.assertEqual(result.skipped, [])
        self.assertEqual(internal.roots.installer.LIBRARY_SHA, CACHY_ALPM_SHA)

    def test_wrong_architecture_and_default_binding_refused_before_file_reads(self):
        installer = internal.roots.installer
        cases = ((patch.object(os, 'uname', return_value=SimpleNamespace(machine='aarch64')), 'architecture'),
                 (patch.object(installer, 'LIBRARY_SHA', '0'*64), 'binding'),
                 (patch.object(installer, 'LIBRARY', Path('/other/libalpm.so.16.0.1')), 'binding'))
        for change, reason in cases:
            with self.subTest(reason=reason), change, patch(__name__ + '.profile_file') as read:
                with self.assertRaisesRegex(ValueError, reason): ci_alpm_identity()
                read.assert_not_called()

    def test_changed_package_or_library_identity_cannot_bind_or_load(self):
        for rejected in (CI_PACMAN_DESC, CI_ALPM_PATH):
            def refuse(path, size, expected):
                if path == rejected: raise ValueError('changed identity')
            with self.subTest(path=rejected), patch(__name__ + '.profile_file', side_effect=refuse), \
                    patch.object(internal.roots.installer.C, 'CDLL') as load:
                with self.assertRaisesRegex(ValueError, 'changed identity'):
                    with alpm_test_profile(CI_ALPM_PROFILE): self.fail('accepted')
                self.assertEqual(internal.roots.installer.LIBRARY_SHA, CACHY_ALPM_SHA)
                load.assert_not_called()

    def test_actual_altered_bytes_size_and_symlink_refused_without_library_load(self):
        with tempfile.TemporaryDirectory(prefix='alpm-profile-data-') as directory, \
                patch.object(internal.roots.installer.C, 'CDLL') as load:
            path = Path(directory) / 'library'; path.write_bytes(b'\0' * 281240)
            with self.assertRaisesRegex(ValueError, 'bytes changed'): profile_file(path, 281240, CI_ALPM_SHA)
            with self.assertRaisesRegex(ValueError, 'identity changed'): profile_file(path, 281241, CI_ALPM_SHA)
            alias = path.with_name('alias'); alias.symlink_to(path)
            with self.assertRaisesRegex(ValueError, 'identity changed'): profile_file(alias, 281240, CI_ALPM_SHA)
        load.assert_not_called()

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
        self.assertNotIn('prior_archive', row)
        self.assertEqual(row['phase'],'observe-after'); self.assertIsInstance(apply.call_args.kwargs['adapter'],internal.Runtime)
        self.assertEqual(row['full587_composition'],'NOT ESTABLISHED')

    def test_precommit_flag_set_only_after_existing_checks(self):
        self.runtime.projected=self.seed
        with patch.object(internal.scale.Runtime,'precommit',side_effect=ValueError('configuration drift')):
            with self.assertRaisesRegex(ValueError,'configuration drift'): self.runtime.precommit()
        self.assertFalse(getattr(self.runtime,'commit_ready',False))
        with patch.object(internal.scale.Runtime,'precommit'): self.runtime.precommit()
        self.assertTrue(self.runtime.commit_ready)

class PriorArchives(unittest.TestCase):
    """Real TEST signatures and read-only ALPM in an owned fixture database.

    Run in `unshare --user --map-root-user` so archive UID/GID zero has its real
    installed meaning without changing host ownership or installing anything.
    """
    file = Tests.file
    config = Tests.config

    @classmethod
    def setUpClass(cls):
        cls.stack = ExitStack()
        cls.addClassCleanup(cls.stack.close)
        profile = cls.stack.enter_context(alpm_test_profile(os.environ.get('CACHY_ASAHI_TEST_ALPM_PROFILE')))
        if os.getuid() != 0 or os.getgid() != 0:
            if profile is not None: raise AssertionError('selected TEST libalpm profile requires UID/GID zero')
            raise unittest.SkipTest('run in a private mapped-root user namespace for exact archive ownership')
        if profile is not None: print(json.dumps(profile, sort_keys=True), flush=True)
        from test_snapshot import signing
        cls.keys = Path(cls.stack.enter_context(tempfile.TemporaryDirectory(prefix='prior-keys-')))
        cls.signer, cls.public, sign = cls.stack.enter_context(signing(cls.keys / 'keys'))
        cls.sign = staticmethod(sign)

    def setUp(self):
        Tests.setUp(self)
        self.case = self.root.parent
        self.args = SimpleNamespace(root=str(self.root), prior_archive=str(self.case / 'old.pkg.tar.gz'))
        self.runtime = internal.Runtime(self.args, self.config())
        self.seed = self.runtime.tree(self.root)
        self.archive = Path(self.args.prior_archive)
        self.work = self.case / 'work'
        (self.work / 'authenticated/bundle').mkdir(parents=True)
        keyring = self.work / 'authenticated/public.gpg'
        keyring.write_bytes(self.public)
        self.snapshot = dict(bundle=self.work / 'authenticated/bundle', keyring=keyring,
            metadata=dict(signer=self.signer), release=dict(packages=[dict(arch='any')]))
        self.before = {'selected': '1-1', 'held': '1-1'}
        self.entries = {'usr/share/selected': b'inert data\n'}
        self.alpm = None

    def prepare(self, *, metadata='', backups='', foreign=()):
        local = self.root / 'var/lib/pacman/local'
        (local / 'ALPM_DB_VERSION').write_text('9\n')
        for package in self.before:
            directory = local / (package + '-1-1')
            (directory / 'desc').write_text(f'%NAME%\n{package}\n\n%VERSION%\n1-1\n\n%ARCH%\nany\n\n')
            owned = self.entries if package == 'selected' else foreign
            suffix = '%BACKUP%\n' + backups + '\n\n' if package == 'selected' and backups else ''
            (directory / 'files').write_text('%FILES%\n' + '\n'.join(owned) + '\n\n' + suffix)
        with tarfile.open(self.archive, 'w:gz') as archive:
            controls = f'pkgname = selected\npkgver = 1-1\narch = any\nlicense = MIT\n{metadata}'.encode()
            for name, data in {'.PKGINFO': controls, **self.entries}.items():
                node = tarfile.TarInfo(name)
                node.mode = 0o644
                if data is None:
                    node.type, node.mode = tarfile.DIRTYPE, 0o755
                    archive.addfile(node)
                elif isinstance(data, tuple):
                    node.type, node.linkname, node.mode = tarfile.SYMTYPE, data[0], 0o777
                    archive.addfile(node)
                else:
                    node.size = len(data)
                    archive.addfile(node, io.BytesIO(data))
        self.sign(self.archive)
        self.alpm = internal.roots.Alpm(self.root, self.keys / 'keys', self.case / 'read-only-alpm.log',
                                        os.uname().machine, limits=self.runtime.root_limits)
        self.addCleanup(self.alpm.close)
        self.runtime.alpm = self.alpm
        self.runtime.old_paths = self.alpm.owned_files({'selected'})
        self.runtime.baseline = self.runtime.observation = None
        self.seed = self.runtime.tree(self.root)

    def authenticate(self):
        self.runtime.select_prior(self.snapshot, self.before, {'selected': '2-1'})

    def test_signed_old_regular_and_symlink_leaves_remove_only_obsolete_nodes(self):
        link = self.root / 'usr/share/retired-link'
        link.symlink_to('selected')
        self.entries['usr/share/retired-link'] = ('selected',)
        self.runtime.baseline = self.runtime.observation = None
        self.seed = self.runtime.tree(self.root)
        self.prepare()
        self.authenticate()
        projected = self.runtime.projected_paths(self.seed, {})
        self.assertEqual(projected, {path: node for path, node in self.seed.items() if path not in self.entries})
        self.runtime.tree(self.root)  # Original leaves must remain until commit.
        for name in self.entries:
            (self.root / name).unlink()
        self.runtime.commit_ready = True
        self.assertEqual(self.runtime.tree(self.root), projected)
        self.assertEqual((self.root / 'home/user/config').read_bytes(), b'inert data\n')

    def test_modified_leaf_refuses_and_preserves_user_content(self):
        self.prepare()
        (self.root / 'usr/share/selected').write_bytes(b'user edit')
        self.runtime.baseline = self.runtime.observation = None
        self.seed = self.runtime.tree(self.root)
        self.authenticate()
        with self.assertRaisesRegex(ValueError, 'modified or hardlinked'):
            self.runtime.projected_paths(self.seed, {})
        self.assertEqual((self.root / 'usr/share/selected').read_bytes(), b'user edit')

    def test_signed_old_bytes_or_signature_tamper_never_authorizes_removal(self):
        self.prepare()
        self.archive.write_bytes(self.archive.read_bytes() + b'changed')
        with self.assertRaisesRegex(internal.scale.bound.client.Error, 'GPG rejected'):
            self.authenticate()
        self.assertIsNone(self.runtime.prior)

    def test_wrong_installed_version_in_signed_old_archive_refuses(self):
        self.prepare(metadata='pkgver = 0-1\n')
        with self.assertRaisesRegex(ValueError, 'prior package identity'):
            self.authenticate()

    def test_signed_archive_backup_semantics_refuse(self):
        self.prepare(metadata='backup = usr/share/selected\n')
        with self.assertRaisesRegex(ValueError, 'archive backup semantics'):
            self.authenticate()

    def test_actual_installed_backup_semantics_refuse(self):
        self.prepare(backups='usr/share/selected\t0123456789abcdef0123456789abcdef')
        with self.assertRaisesRegex(ValueError, 'installed backup semantics'):
            self.authenticate()

    def test_shared_local_ownership_refuses_obsolete_removal(self):
        self.prepare(foreign=('usr/share/selected',))
        self.authenticate()
        with self.assertRaisesRegex(ValueError, 'foreign ownership'):
            self.runtime.projected_paths(self.seed, {})

    def test_complete_old_ownership_is_required(self):
        self.entries['usr/share/extra'] = b'not installed'
        self.prepare()
        self.runtime.old_paths.remove('usr/share/extra')
        with self.assertRaisesRegex(ValueError, 'selected ownership differ'):
            self.authenticate()

    def test_prior_source_drift_refuses_before_commit_and_after_observation(self):
        self.prepare()
        self.authenticate()
        self.runtime.projected_paths(self.seed, {})
        self.archive.write_bytes(self.archive.read_bytes() + b'drift')
        for committed in (False, True):
            self.runtime.commit_ready = committed
            with self.assertRaisesRegex(ValueError, 'prior input identity changed'):
                self.runtime.tree(self.root)

    def test_signed_symlink_drift_preserves_obsolete_leaf(self):
        path = self.root / 'usr/share/selected'
        path.unlink()
        path.symlink_to('a')
        self.entries['usr/share/selected'] = ('a',)
        self.prepare()
        self.authenticate()
        path.unlink()
        path.symlink_to('b')
        self.runtime.baseline = self.runtime.observation = None
        self.seed = self.runtime.tree(self.root)
        with self.assertRaisesRegex(ValueError, 'modified or hardlinked'):
            self.runtime.projected_paths(self.seed, {})
        self.assertEqual(os.readlink(path), 'b')

    def test_obsolete_directory_still_refuses_with_authenticated_prior(self):
        path = self.root / 'usr/share/retired'
        path.mkdir()
        self.entries['usr/share/retired'] = None
        self.prepare()
        self.authenticate()
        with self.assertRaisesRegex(ValueError, 'directory removal unsupported'):
            self.runtime.projected_paths(self.seed, {'usr/share/selected': self.file(b'new')})
        self.assertTrue(path.is_dir())

    def test_obsolete_hardlink_still_refuses_with_authenticated_prior(self):
        path = self.root / 'usr/share/selected'
        os.link(path, self.root / 'usr/share/held-alias')
        self.prepare()
        self.authenticate()
        with self.assertRaisesRegex(ValueError, 'modified or hardlinked'):
            self.runtime.projected_paths(self.seed, {})
        self.assertEqual(path.stat().st_nlink, 2)

    def test_obsolete_leaf_under_parent_alias_refuses(self):
        self.entries = {'usr/alias/selected': b'inert data\n'}
        self.prepare()
        self.authenticate()
        with self.assertRaisesRegex(ValueError, 'parent alias unsupported'):
            self.runtime.projected_paths(self.seed, {})
        self.assertTrue((self.root / 'usr/share/selected').is_file())

    def test_signature_from_a_distinct_primary_is_refused(self):
        from test_snapshot import signing
        self.prepare()
        with signing(self.case / 'foreign-keys') as (_, _, sign):
            sign(self.archive)
        with self.assertRaisesRegex(internal.scale.bound.client.Error, 'GPG rejected'):
            self.authenticate()
        self.assertIsNone(self.runtime.prior)

    def test_frozen_prior_copy_drift_prevents_precommit_flag(self):
        self.prepare()
        self.authenticate()
        self.runtime.projected_paths(self.seed, {})
        copied = self.work / 'prior-package/archive'
        copied.chmod(0o600)
        copied.write_bytes(copied.read_bytes() + b'drift')
        with patch.object(internal.scale.Runtime, 'precommit'):
            with self.assertRaisesRegex(ValueError, 'prior input identity changed'):
                self.runtime.precommit()
        self.assertFalse(getattr(self.runtime, 'commit_ready', False))

    def test_old_and_new_archives_share_existing_aggregate_limits(self):
        self.prepare()
        self.authenticate()
        self.runtime.archive_limits = replace(self.runtime.archive_limits,
            total_compressed_bytes=self.archive.stat().st_size)
        with self.assertRaisesRegex(internal.scale.archives.Invalid, 'aggregate compressed'):
            self.runtime.archive_payload(self.archive, {'bytes': 0, 'nodes': 0})

    def test_result_retains_exact_authenticated_prior_evidence_without_commit_claim(self):
        self.prepare()
        self.authenticate()
        self.runtime.projected_paths(self.seed, {})
        client = internal.scale.bound.client
        expected = dict(package=dict(name='selected', version='1-1', arch='any'),
            archive=dict(sha256=client.digest(self.archive.read_bytes()), bytes=self.archive.stat().st_size),
            signature=dict(sha256=client.digest(Path(str(self.archive) + '.sig').read_bytes()),
                bytes=Path(str(self.archive) + '.sig').stat().st_size,
                primary_fingerprint=self.signer, signing_fingerprint=self.signer, hash_algorithm='8'),
            projected_obsolete_paths=['usr/share/selected'])
        args = SimpleNamespace(root=str(self.root), workspace=str(self.case), scale='unused', scale_sha256='0'*64)
        for status in ('PASS', 'FAIL'):
            with self.subTest(status=status), patch.object(internal.scale.bound, 'guard'), \
                    patch.object(internal.scale, 'configuration', return_value=self.config()), \
                    patch.object(internal, 'Runtime', return_value=self.runtime), \
                    patch.object(internal.scale.bound, 'apply', return_value=dict(status=status, packages_committed=False)):
                result = internal.apply(args)
            self.assertEqual(result['prior_archive'], expected)
            self.assertEqual(result['status'], status)
            self.assertFalse(result['packages_committed'])

if __name__=='__main__': unittest.main()
