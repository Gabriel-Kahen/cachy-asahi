"""Inert filesystem controls: no native composition, signer or package actor."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'manifests/packages.toml').is_file())
sys.path.insert(0, str(ROOT / 'scripts/update'))
import full_root as roots
import measure_copy as copier
import root_path as resolver
sys.path.pop(0)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


scope = load('persistent_scope_fixture', HERE / 'persistent_scope.py')
driver = load('scope_driver_fixture', ROOT / 'scripts/ci/full-root-upgrade/root_upgrade.py')


def limits(): return roots.Limits(deadline=time.monotonic() + 30, max_nodes=1000, max_bytes=1024**2, max_file_bytes=65536)


class MountPolicy(unittest.TestCase):
    def rows(self):
        return [dict(id=1, path='/', fs='overlay'), dict(id=2, path='/measurement', fs='ext4'),
                dict(id=3, path='/etc/hosts', fs='ext4'), dict(id=4, path='/dev/pts', fs='devpts'),
                dict(id=5, path='/upgrade-signing', fs='ext4')]

    def test_literal_mounts_retained_data_and_private_signer_exclusion(self):
        row = scope.mount_policy(Path('/'), Path('/measurement/run/source'), self.rows())
        self.assertEqual(row['observed_mounts'], ['dev/pts', 'etc/hosts', 'measurement', 'upgrade-signing'])
        self.assertIn('upgrade-signing', scope.INFRASTRUCTURE)
        self.assertNotIn('etc', scope.INFRASTRUCTURE | scope.RUNTIME)
        self.assertEqual(scope.MOUNT_FILES, {'etc/hosts', 'etc/hostname', 'etc/resolv.conf'})

    def test_unexpected_persistent_mount_and_memory_backed_destination_refuse(self):
        for path in ['/home', '/boot', '/etc/unknown', '/upgrade-signing/nested', '/measurement/nested']:
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, 'unrecognized'):
                scope.mount_policy(Path('/'), Path('/measurement/run/source'), self.rows() + [dict(id=6, path=path, fs='ext4')])
        rows = self.rows(); rows[1]['fs'] = 'tmpfs'
        with self.assertRaisesRegex(ValueError, 'disk-backed'):
            scope.mount_policy(Path('/'), Path('/measurement/run/source'), rows)
        with self.assertRaisesRegex(ValueError, 'outside persistent'):
            scope.mount_policy(Path('/'), Path('/home/stage'), self.rows())

    def test_mount_parser_bounds_aliases_and_escaped_names(self):
        raw = '20 1 0:1 / / rw - overlay overlay rw\n21 20 0:2 / /measurement rw - ext4 /dev/x rw\n'
        self.assertEqual(len(scope.mounts(raw)), 2)
        for value in [raw + raw.splitlines()[0] + '\n', raw.replace('/measurement', '/space\\040name'), '']:
            with self.subTest(value=value), self.assertRaises(ValueError): scope.mounts(value)


class Filesystem(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name); self.base.chmod(0o700)
        self.source, self.target = self.base / 'source', self.base / 'stage'
        self.source.mkdir()
        for path, data in {'home/person/notes': b'user', 'root/settings': b'root', 'etc/setting': b'config',
                           'etc/hosts': b'hosts', 'etc/hostname': b'name', 'etc/resolv.conf': b'resolver',
                           'boot/kernel': b'boot', 'usr/lib/modules/fixture.ko': b'module',
                           'usr/share/payload': b'owned', 'tmp/private': b'volatile',
                           'upgrade-signing/secret': b'excluded TEST secret'}.items():
            file = self.source / path; file.parent.mkdir(parents=True, exist_ok=True); file.write_bytes(data)
        (self.source / 'lib').symlink_to('/usr/lib')
        os.link(self.source / 'usr/share/payload', self.source / 'usr/share/alias')
        local = self.source / driver.DB; local.mkdir(parents=True)
        (local / 'ALPM_DB_VERSION').write_bytes(b'9\n')
        package = local / 'fixture-1-1'; package.mkdir()
        (package / 'desc').write_text('%NAME%\nfixture\n\n%VERSION%\n1-1\n\n%ARCH%\nany\n\n')
        (package / 'files').write_text('%FILES%\nlib/modules/fixture.ko\nusr/share/payload\netc/hosts\n\n')
        fd = roots._open_root(self.source)
        try: self.policy = dict(source_mount=roots._mount_id(fd, limits()), target_mount=0, observed_mounts=['upgrade-signing'])
        finally: os.close(fd)

    def manifest(self): return scope.source_manifest(self.source, limits(), roots, self.policy)

    def run_materialize(self):
        api = SimpleNamespace(database=driver.database, selection=lambda code: ({'fixture': '1-1'}, {}))
        with patch.object(scope, '_apis', return_value=(roots, copier, resolver, api)), \
             patch.object(scope, 'mount_policy', return_value=self.policy), patch.object(scope, 'mounts', return_value=[]):
            return scope.materialize(self.source, self.target, ROOT, limits())

    def verify(self):
        api = SimpleNamespace(database=driver.database, selection=lambda code: ({'fixture': '1-1'}, {}))
        with patch.object(scope, '_apis', return_value=(roots, copier, resolver, api)), \
             patch.object(scope, 'mount_policy', return_value=self.policy), patch.object(scope, 'mounts', return_value=[]):
            return scope.verify(self.source, self.target, ROOT, limits())

    def test_manifest_retains_config_boot_user_links_and_closed_hardlinks(self):
        nodes, excluded = self.manifest()
        self.assertEqual(excluded, ['tmp/*', 'upgrade-signing'])
        self.assertNotIn('tmp/private', nodes); self.assertIn('tmp', nodes)
        self.assertNotIn('upgrade-signing/secret', nodes)
        self.assertEqual(nodes['lib']['target'], '/usr/lib')
        self.assertEqual(nodes['usr/share/payload']['hardlink_group'], 'usr/share/alias')
        self.assertTrue({'boot/kernel', 'etc/setting', 'home/person/notes', 'root/settings'} <= nodes.keys())

    def test_scoped_materialization_restores_mount_files_and_proves_all_nodes(self):
        before, _ = self.manifest(); result = self.run_materialize()
        self.assertEqual(result['status'], 'PASS')
        self.assertFalse(result['whole_container_root']); self.assertFalse(result['whole_root_copy'])
        self.assertEqual(result['transaction_acceptance'], 'NOT ESTABLISHED')
        self.assertEqual(result['package_owned_nondirectory_paths'], 3)
        self.assertEqual(sorted(p.name for p in (self.target / 'tmp').iterdir()), [])
        self.assertEqual((self.target / 'etc/hosts').read_bytes(), b'hosts')
        self.assertEqual((self.target / 'lib').readlink().as_posix(), '/usr/lib')
        self.assertEqual((self.target / 'usr/share/payload').stat().st_ino, (self.target / 'usr/share/alias').stat().st_ino)
        self.assertEqual(roots.observe(self.target, limits=limits(), hardlinks='generic-development-internal')['nodes'], before)

    def test_excluded_owned_file_refuses_before_copy(self):
        files = self.source / driver.DB / 'fixture-1-1/files'
        files.write_text(files.read_text().replace('etc/hosts', 'tmp/private'))
        with self.assertRaisesRegex(ValueError, 'owned persistent payload absent'): self.run_materialize()
        self.assertFalse(self.target.exists())

    def test_parent_link_resolution_checks_leaf_as_data(self):
        nodes, _ = self.manifest()
        packages = [dict(name='fixture', files=['lib/modules/fixture.ko', 'lib'])]
        self.assertEqual(scope.owned_coverage(packages, nodes, resolver, limits()), 2)
        nodes.pop('usr/lib/modules/fixture.ko')
        with self.assertRaisesRegex(ValueError, 'owned persistent payload absent'):
            scope.owned_coverage(packages, nodes, resolver, limits())

    def test_special_unclosed_hardlink_runtime_alias_and_mount_file_alias_refuse(self):
        fifo = self.source / 'home/person/fifo'; os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, 'special'): self.manifest()
        fifo.unlink()
        os.link(self.source / 'usr/share/payload', self.base / 'outside')
        with self.assertRaisesRegex(ValueError, 'not closed'): self.manifest()
        (self.base / 'outside').unlink()
        for name in ['etc/hosts', 'tmp']:
            path = self.source / name
            if path.is_dir(): (path / 'private').unlink(); path.rmdir()
            else: path.unlink()
            path.symlink_to('/run')
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'alias refused'): self.manifest()
            path.unlink(); path.mkdir() if name == 'tmp' else path.write_bytes(b'hosts')

    def test_source_drift_or_stage_corruption_cannot_pass(self):
        real = scope._restore_boundaries
        def corrupt(*args):
            real(*args); (self.target / 'home/person/notes').write_bytes(b'changed')
        with patch.object(scope, '_restore_boundaries', side_effect=corrupt), self.assertRaisesRegex(ValueError, 'stage differs'):
            self.run_materialize()

    def test_stage_does_not_follow_aliased_parent(self):
        alias = self.base / 'alias'; alias.symlink_to(self.base, target_is_directory=True)
        self.target = alias / 'stage'
        with self.assertRaises(OSError): self.run_materialize()

    def test_postdriver_verification_requires_original_source_and_stage(self):
        initial = self.run_materialize(); checked = self.verify()
        self.assertEqual(checked['status'], 'PASS')
        self.assertEqual(checked['source_manifest_sha256'], initial['source_manifest_sha256'])
        (self.source / 'home/person/notes').write_bytes(b'changed source')
        with self.assertRaisesRegex(ValueError, 'verification stage differs'): self.verify()
        (self.target / 'home/person/notes').write_bytes(b'changed source')
        self.assertNotEqual(self.verify()['source_manifest_sha256'], initial['source_manifest_sha256'])

    def test_source_drift_after_copy_refuses(self):
        real = scope.source_manifest
        calls = []
        def drifting(*args):
            calls.append(None)
            if len(calls) == 2: (self.source / 'home/person/new').write_bytes(b'new')
            return real(*args)
        with patch.object(scope, 'source_manifest', side_effect=drifting), self.assertRaisesRegex(ValueError, 'source changed'):
            self.run_materialize()

    def test_unmounted_infrastructure_names_are_preserved(self):
        self.policy['observed_mounts'] = []
        nodes, excluded = self.manifest()
        self.assertIn('upgrade-signing/secret', nodes)
        self.assertEqual(excluded, ['tmp/*'])


if __name__ == '__main__': unittest.main()
