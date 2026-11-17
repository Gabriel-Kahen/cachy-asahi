# SPDX-License-Identifier: MIT
"""Genuine Source78 DATA controls; no source body or operational role executes.

An explicit --source78 files-only fixture is required. Its original bytes and
modes are checked before and after; all mutations affect one private copy.
"""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest

ACTORS = []


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'ctypes.', 'os.exec',
                         'os.spawn', 'os.posix_spawn', 'os.fork')) or event in (
            'os.system', 'fcntl.flock'):
        ACTORS.append(event)
        raise AssertionError('SOURCE_DATA_NO_OPERATIONAL_ROLE: ' + event)


sys.addaudithook(fence)
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('audio_source_reader_controls', HERE / 'reader.py')
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)
SOURCE78 = None
MAP = dict(bytes=15363, sha256='dc3197203a91bdcd98cdd98f4f672d05abbc6865e26f2b744c3646c1b4d761eb')
OLD_MAP = dict(bytes=14203, sha256='5643afddb02e2d4d29f1215f44b8409599d9b17dd3849699e8fd6897eb6c40b8')


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def snapshot(root):
    rows = {}
    for path in root.rglob('*'):
        info = path.lstat()
        name = path.relative_to(root).as_posix()
        if stat.S_ISDIR(info.st_mode):
            rows[name + '/'] = dict(mode=stat.S_IMODE(info.st_mode))
        else:
            if not stat.S_ISREG(info.st_mode):
                raise AssertionError('original fixture must contain ordinary files only')
            rows[name] = dict(pin(path.read_bytes()), mode=stat.S_IMODE(info.st_mode),
                              links=info.st_nlink)
    return rows


class GenuineSource78(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SOURCE78 is None:
            raise RuntimeError('genuine Source78 controls require explicit --source78 PATH; no skipped PASS')
        cls.original = SOURCE78.resolve()
        cls.before = snapshot(cls.original)
        cls.tmp = tempfile.TemporaryDirectory(prefix='audio-source78-DATA-')
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.root = Path(cls.tmp.name) / 'relocated-source78'
        shutil.copytree(cls.original, cls.root)
        cls.mapping = json.loads((cls.root / 'source-map.json').read_bytes())

    @classmethod
    def tearDownClass(cls):
        if snapshot(cls.original) != cls.before:
            raise AssertionError('original Source78 DATA fixture changed')
        if ACTORS:
            raise AssertionError('operational attempt observed: ' + repr(ACTORS))

    @contextmanager
    def changed(self, name, *, body=None, mode=None, symlink=False):
        path = self.root / name
        old, old_mode = path.read_bytes(), stat.S_IMODE(path.lstat().st_mode)
        try:
            if symlink:
                path.unlink()
                path.symlink_to(self.original / name)
            else:
                if body is not None:
                    path.write_bytes(body)
                if mode is not None:
                    path.chmod(mode)
            yield
        finally:
            if path.is_symlink():
                path.unlink()
            path.write_bytes(old)
            path.chmod(old_mode)

    def check(self):
        return R.source_readiness(self.root)

    def test_genuine_fixed_tuple_relocation_and_all_actuals_unissued(self):
        result = self.check()
        self.assertNotEqual(self.original, self.root)
        self.assertEqual(result['status'], 'PASS_SOURCE78_DATA_ONLY')
        self.assertEqual((result['files'], result['bytes']), (78, 35742081))
        self.assertEqual(result['source_map'], MAP)
        self.assertEqual(len(self.mapping['files']), 76)
        files = {n: r for n, r in snapshot(self.root).items() if not n.endswith('/')}
        self.assertEqual(len(files), 78)
        self.assertEqual(sum(r['bytes'] for r in files.values()), 35742081)
        self.assertTrue(all(v is None for v in result['actual'].values()))
        self.assertIsNone(result['Root_acceptance'])
        for key in ('native_acceptance', 'hardware_acceptance', 'release_acceptance'):
            self.assertIs(result[key], False)
        for key in ('source', 'legal', 'key_freshness', 'exact_Qt_recipe_correspondence'):
            self.assertEqual(result[key], 'HELD')
        self.assertEqual(result['platform'], 'NOT_RUN')
        self.assertEqual(result['M2'], 'NOT_RUN')

    def test_all_seventy_source72_members_preserve_actual_bytes_and_modes(self):
        member = R.HOSTED + 'source72-map.DATA.json'
        raw = (self.root / member).read_bytes()
        self.assertEqual(pin(raw), OLD_MAP)
        previous = json.loads(raw)
        self.assertEqual(len(previous['files']), 70)
        self.assertTrue(all(v is None for v in previous['actual'].values()))
        for name, row in previous['files'].items():
            with self.subTest(member=name):
                self.assertEqual(self.mapping['files'][name], row)
                path = self.root / name
                self.assertEqual(dict(pin(path.read_bytes()), mode=stat.S_IMODE(path.lstat().st_mode)), row)
        self.assertEqual(set(self.mapping['files']) - set(previous['files']),
                         {R.HOSTED + n for n in R.P.RUNTIME})
        self.assertEqual(self.check()['preserved_Source72_members'], 70)

    def test_prospective477_protected349_and_catalog333_joins(self):
        joins = self.check()['prospective_inventory_joins']
        self.assertEqual((joins['inventory_count'], joins['protected_count'],
                          joins['catalog_count'], joins['addition_count']), (477, 349, 333, 128))
        self.assertEqual(joins['inventory'], R.H.EXPECTED477)
        self.assertEqual(joins['protected'], R.H.PROTECTED349)
        self.assertEqual(joins['catalog'], pin((self.root / 'inputs/catalog333.DATA.json').read_bytes()))
        self.assertIsNone(joins['Root_acceptance'])
        self.assertIs(joins['native_acceptance'], False)

    def test_source_data_pass_does_not_hide_missing_dispatch_workflow(self):
        self.assertFalse((self.root / '.github').exists())
        self.assertFalse(any(n.startswith('.github/') for n in self.mapping['files']))
        previous = json.loads((self.root / (R.HOSTED + 'source72-map.DATA.json')).read_bytes())
        self.assertFalse(any(n.startswith('.github/') for n in previous['files']))
        result = self.check()
        self.assertEqual(result['hosted_dispatch'], 'HELD_SOURCE78_OMITS_WORKFLOW')
        self.assertEqual(result['hosted_workflow_member'], R.WORKFLOW)
        self.assertIs(result['dispatch_ready'], False)

    def test_altered_runtime_preserved_member_and_inventory_refuse(self):
        names = (R.HOSTED + 'hosted.py', R.AUDIO + 'owner.py',
                 R.HOSTED + 'source72-map.DATA.json',
                 'inputs/prospective477.expected.DATA.lock', 'inputs/catalog333.DATA.json')
        for name in names:
            with self.subTest(member=name), self.changed(name, body=(self.root / name).read_bytes() + b'\n'):
                with self.assertRaises(ValueError):
                    self.check()

    def test_map_alias_body_and_exact_modes_refuse(self):
        with self.changed('source.lock.json', body=(self.root / 'source.lock.json').read_bytes() + b'\n'):
            with self.assertRaises(ValueError):
                self.check()
        for name in ('source-map.json', 'source.lock.json', R.AUDIO + 'owner.py'):
            with self.subTest(member=name), self.changed(name, mode=0o600):
                with self.assertRaises(ValueError):
                    self.check()

    def test_foreign_empty_directory_and_foreign_file_refuse(self):
        extra = self.root / 'FOREIGN_EMPTY_DIRECTORY'
        extra.mkdir()
        try:
            with self.assertRaises(ValueError):
                self.check()
        finally:
            extra.rmdir()
        extra = self.root / 'FOREIGN.DATA'
        extra.write_bytes(b'foreign DATA\n')
        try:
            with self.assertRaises(ValueError):
                self.check()
        finally:
            extra.unlink()

    def test_expected_leaf_symlink_refuses_without_following_fixture_mutation(self):
        for name in (R.AUDIO + 'owner.py', 'source.lock.json'):
            with self.subTest(member=name), self.changed(name, symlink=True):
                with self.assertRaises(ValueError):
                    self.check()

    def test_old_source72_and_onboarding_source188_shape_cannot_select_source78(self):
        old = (self.root / (R.HOSTED + 'source72-map.DATA.json')).read_bytes()
        wrong = dict(self.mapping, schema=5, kind='CURRENT_ONBOARDING_CLOSED_SOURCE_V3',
                     operation='first-login-enrollment-ui-current-v2')
        # This schema5 case is explicit MODEL DATA, never a claimed genuine188 fixture.
        for body in (old, R.encoded(wrong)):
            with self.subTest(map=pin(body)), self.changed('source-map.json', body=body), \
                    self.changed('source.lock.json', body=body):
                with self.assertRaises(ValueError):
                    self.check()

    def test_no_operational_attempt_and_original_fixture_unchanged(self):
        self.assertEqual(ACTORS, [])
        self.assertEqual(snapshot(self.original), self.before)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source78', type=Path, required=True)
    options, remaining = parser.parse_known_args()
    SOURCE78 = options.source78
    unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)
