#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

from test_verify import HERE, fixtures, load

preflight = load('install_preflight', HERE / 'preflight.py')


class BaseLockTests(unittest.TestCase):
    def setUp(self):
        self.archive = {
            'name': 'archive', 'version': '1:2-3', 'arch': 'aarch64',
            'filename': 'archive-1:2-3-aarch64.pkg.tar.xz', 'depends': ['runtime>=2'],
            'provides': [], 'conflicts': [], 'replaces': [], 'size': 100,
            'sha256': 'a' * 64, 'signature_size': 100, 'signature_sha256': 'b' * 64,
        }
        self.lock = {
            'schema_version': 1, 'snapshot_id': 'base-test', 'packages': [self.archive],
            'rootfs': {**self.archive, 'filename': 'ArchLinuxARM-test.tar.gz'},
        }
        self.base = {
            'snapshot_id': 'base-test',
            'packages': [dict(self.archive, depend=self.archive['depends'], conflict=[])],
        }

    def test_exact_base_archive_record(self):
        rows, size = preflight.base_rows(self.lock, self.base)
        self.assertEqual(rows, [self.archive])
        self.assertEqual(size, 200)

    def test_version_relation_architecture_and_snapshot_drift_refused(self):
        for key, value in [('version', '2-3'), ('depend', []), ('arch', 'any')]:
            with self.subTest(key=key):
                base = copy.deepcopy(self.base)
                base['packages'][0][key] = value
                with self.assertRaisesRegex(preflight.client.Error, 'differs from the signed kit declaration'):
                    preflight.base_rows(self.lock, base)
        self.base['snapshot_id'] = 'foreign-base'
        with self.assertRaisesRegex(preflight.client.Error, 'snapshot differs from the kit'):
            preflight.base_rows(self.lock, self.base)

    def test_unsafe_archive_and_rootfs_names_are_refused(self):
        self.archive['filename'] = '../escape.pkg.tar.xz'
        with self.assertRaisesRegex(preflight.client.Error, 'unsafe or duplicate'):
            preflight.base_rows(self.lock, self.base)
        self.archive['filename'] = 'archive-1:2-3-aarch64.pkg.tar.xz'
        self.lock['rootfs']['filename'] = '../escape.tar.gz'
        with self.assertRaisesRegex(preflight.client.Error, 'must be a basename'):
            preflight.base_rows(self.lock, self.base)


class SignedIndexesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.KitTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        fixtures.KitTests.tearDownClass()

    def test_overlay_inventory_uses_the_authenticated_archive_and_signature(self):
        fixture = fixtures.KitTests(methodName='runTest')
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        fixture.assemble()
        checked = preflight.inventory.kit.inspect(fixture.inspect_args)
        checked['base_sha256'] = fixture.f.release_spec['base']['sha256']
        work = fixture.f.base / 'overlay-indexes'
        work.mkdir(mode=0o700)
        (repo, _, _), _, rows = preflight.inspect_overlay(fixture.inspect_args, checked, work, datetime.now(timezone.utc))
        signature = fixture.bundle / 'repo' / (fixture.f.archive.name + '.sig')
        self.assertEqual(repo, fixture.f.release_spec['repo_name'])
        self.assertEqual([(row['name'], row['sha256'], row['signature_sha256']) for row in rows],
                         [('fixture', fixture.f.digest, preflight.client.digest(signature.read_bytes()))])

    def test_pinned_wrong_signature_still_fails(self):
        fixture = fixtures.KitTests(methodName='runTest')
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        repo = fixture.bundle / 'repo'
        release = json.loads((fixture.bundle / 'release.json').read_bytes())
        name = fixture.f.release_spec['repo_name']
        paths = {key.removeprefix('repo/'): pin for key, pin in release['files'].items() if key.startswith('repo/')}
        for tamper in (False, True):
            work = fixture.f.base / ('tampered' if tamper else 'original')
            work.mkdir(mode=0o700)
            verifier = preflight.client.Verifier(work, fixture.public.read_bytes(), fixture.f.key, datetime.now(timezone.utc))
            with preflight.directory(repo) as root:
                if not tamper:
                    preflight.certified_indexes(root, name, paths, work, verifier)
                    continue
                signature = f'{name}.db.tar.gz.sig'
                raw = (repo / signature).read_bytes()
                changed = raw[:-1] + bytes([raw[-1] ^ 1])
                (repo / signature).write_bytes(changed)
                paths[signature] = preflight.client.digest(changed)
                with self.assertRaisesRegex(preflight.client.Error, 'GPG rejected detached signature'):
                    preflight.certified_indexes(root, name, paths, work, verifier)


class PackageInventoryTests(unittest.TestCase):
    @staticmethod
    def archive(name, version, arch, digest, signature):
        return dict(name=name, version=version, arch=arch, filename=f'{name}-{version}-{arch}.pkg.tar.xz',
                    sha256=digest * 64, signature_sha256=signature * 64)

    def test_opt_in_reports_only_archives_from_the_resolved_repositories(self):
        inherited = self.archive('kernel', '1-1', 'aarch64', 'a', 'b')
        replaced = self.archive('editor', '1-1', 'aarch64', 'c', 'd')
        selected = self.archive('editor', '1-1', 'any', 'e', 'f')
        args = SimpleNamespace(signer='A' * 40, base_signer='B' * 40, target_lock='target', target_lock_sha256='lock',
                               base_lock='base', base_lock_sha256='base-pin', base_receipt_sha256='receipt-pin')
        expected = {'kernel': '1-1', 'editor': '1-1'}
        captured = dict(base_sha256='declared', release_sha256='release')
        overlay = ('overlay', Path('overlay'), b'overlay')
        base = ('alarm', Path('alarm'), b'alarm')
        with (mock.patch.object(preflight.inventory, 'verify', return_value=captured),
              mock.patch.object(preflight.inventory, 'target_lock', return_value=expected),
              mock.patch.object(preflight, 'pinned_read', return_value={'signer_fingerprint': 'C' * 40}),
              mock.patch.object(preflight, 'inspect_overlay', return_value=(overlay, {}, [selected])),
              mock.patch.object(preflight, 'inspect_base', return_value=(base, [inherited, replaced])),
              mock.patch.object(preflight, 'command'),
              mock.patch.object(preflight, 'resolve', return_value='plan') as resolved):
            default = preflight.preflight(args)
            args.include_package_inventory = True
            report = preflight.preflight(args)
            self.assertEqual(resolved.call_args.args[-2:], (expected, {'kernel': 'alarm', 'editor': 'overlay'}))
            resolved.side_effect = preflight.client.Error('resolution refused')
            with self.assertRaisesRegex(preflight.client.Error, 'resolution refused'):
                preflight.preflight(args)
        self.assertNotIn('package_inventory', default)
        self.assertEqual(report.pop('package_inventory'), [
            dict(name='editor', version='1-1', arch='any', repository='overlay', filename=selected['filename'],
                 archive_sha256='e' * 64, signature_sha256='f' * 64),
            dict(name='kernel', version='1-1', arch='aarch64', repository='alarm', filename=inherited['filename'],
                 archive_sha256='a' * 64, signature_sha256='b' * 64),
        ])
        self.assertEqual(report, default)


if __name__ == '__main__':
    unittest.main()
