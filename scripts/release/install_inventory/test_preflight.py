#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest

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


if __name__ == '__main__':
    unittest.main()
