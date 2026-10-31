#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Finite synthetic exporter controls; selected source is never interpreted."""
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

PATH = Path(__file__).with_name('export_image_tools_source.py')
SPEC = importlib.util.spec_from_file_location('_image_tools_exporter', PATH)
EXPORTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPORTER)


class ExportSource(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='image-source-export-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root/'source'
        self.source.mkdir()
        self.raws = {'scripts/trap.py': b'raise AssertionError("TRANSPORTED SOURCE EXECUTED")\n',
                     'packages/fixture/data.txt': b'owned synthetic data\n'}
        for name, raw in self.raws.items():
            path = self.source/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        self.profile = dict(schema_version=1, kind='cachy-asahi-image-tools-finite-source-v1', epoch=1700000000,
                            original_source_revision='a'*40,
                            files={name: dict(bytes=len(raw), sha256=EXPORTER.sha(raw), mode=0o755 if name.endswith('.py') else 0o644)
                                   for name, raw in self.raws.items()})
        self.profile_path = self.root/'profile.json'
        self.output = self.root/'source.tar.gz'
        self.save()

    def save(self, raw=None):
        raw = raw if raw is not None else (json.dumps(self.profile, sort_keys=True, separators=(',', ':')) + '\n').encode()
        self.profile_path.write_bytes(raw)
        self.profile_hash = EXPORTER.sha(raw)

    def export(self, output=None, overlay=None, profile_hash=None):
        return EXPORTER.export(self.source, self.profile_path, profile_hash or self.profile_hash,
                               output or self.output, overlay)

    def refuse(self, expected, **kwargs):
        with self.assertRaisesRegex((ValueError, OSError), expected):
            self.export(**kwargs)
        self.assertFalse(self.output.exists())

    def test_deterministic_finite_raw_data_archive(self):
        first = self.export()
        second_path = self.root/'second.tar.gz'
        second = self.export(second_path)
        self.assertEqual(self.output.read_bytes(), second_path.read_bytes())
        self.assertEqual(first, second)
        self.assertEqual(first['files'], 3)
        self.assertEqual(first['source_bytes'], sum(map(len, self.raws.values())))
        self.assertEqual(first['source_execution'], 'NOT_RUN')
        with tarfile.open(fileobj=io.BytesIO(self.output.read_bytes()), mode='r:gz') as archive:
            members = archive.getmembers()
            self.assertEqual([member.name for member in members], sorted([*self.raws, 'IMAGE_TOOLS_SOURCE_PROFILE.json']))
            for member in members:
                self.assertTrue(member.isfile())
                self.assertEqual((member.uid, member.gid, member.mtime), (0, 0, 1700000000))
                self.assertEqual(member.pax_headers, {})
                expected = self.profile_path.read_bytes() if member.name == 'IMAGE_TOOLS_SOURCE_PROFILE.json' else self.raws[member.name]
                self.assertEqual(archive.extractfile(member).read(), expected)
                self.assertEqual(member.mode, 0o755 if member.name.endswith('.py') else 0o644)

    def test_profile_digest_mismatch_refused(self):
        self.refuse('profile-pin', profile_hash='0'*64)

    def test_invalid_profile_digest_refused(self):
        self.refuse('profile-sha256-required', profile_hash='invalid')

    def test_source_tamper_refused_without_output(self):
        (self.source/'scripts/trap.py').write_bytes(b'x'*len(self.raws['scripts/trap.py']))
        self.refuse('finite-source-pin')

    def test_source_missing_refused_without_output(self):
        (self.source/'scripts/trap.py').unlink()
        self.refuse('No such file')

    def test_source_symlink_refused_without_output(self):
        target = self.source/'scripts/trap.py'
        moved = self.root/'external.py'
        target.rename(moved)
        target.symlink_to(moved)
        self.refuse('source-path-symlink')

    def test_source_hardlink_refused_without_output(self):
        os.link(self.source/'scripts/trap.py', self.root/'second-link.py')
        self.refuse('bounded-single-link-source')

    def test_unsafe_relative_names_refused(self):
        row = next(iter(self.profile['files'].values()))
        for name in ('../outside', '/absolute', 'a/../b', './relative', 'a//b', 'a/', '', 'a\\b', 'a b'):
            with self.subTest(name=name):
                self.profile['files'] = {name: row}
                self.save()
                self.refuse('source-relative-path')

    def test_preexisting_output_preserves_bytes(self):
        before = b'EXISTING OPERATOR OUTPUT\n'
        self.output.write_bytes(before)
        with self.assertRaises(FileExistsError):
            self.export()
        self.assertEqual(self.output.read_bytes(), before)

    def test_reserved_profile_member_collision_refused(self):
        row = next(iter(self.profile['files'].values()))
        self.profile['files']['IMAGE_TOOLS_SOURCE_PROFILE.json'] = row
        self.save()
        self.refuse('reserved-profile-member')

    def test_duplicate_json_key_refused(self):
        raw = self.profile_path.read_bytes().replace(b'"schema_version":1', b'"schema_version":1,"schema_version":1')
        self.save(raw)
        self.refuse('duplicate-json-key')

    def test_duplicate_nested_file_key_refused(self):
        raw = self.profile_path.read_bytes().replace(b'"bytes":', b'"bytes":1,"bytes":', 1)
        self.save(raw)
        self.refuse('duplicate-json-key')

    def test_overlay_exact_pinned_path_and_unlisted_data_ignored(self):
        overlay = self.root/'overlay'
        (overlay/'scripts').mkdir(parents=True)
        (overlay/'scripts/trap.py').write_bytes(self.raws['scripts/trap.py'])
        (overlay/'unlisted.py').write_bytes(b'raise AssertionError("UNLISTED EXECUTED")\n')
        (self.source/'scripts/trap.py').unlink()
        result = self.export(overlay=overlay)
        self.assertEqual(result['files'], 3)
        with tarfile.open(self.output, 'r:gz') as archive:
            self.assertNotIn('unlisted.py', archive.getnames())
            self.assertEqual(archive.extractfile('scripts/trap.py').read(), self.raws['scripts/trap.py'])

    def test_overlay_cannot_shadow_pin_with_changed_bytes(self):
        overlay = self.root/'overlay'
        (overlay/'scripts').mkdir(parents=True)
        (overlay/'scripts/trap.py').write_bytes(b'x'*len(self.raws['scripts/trap.py']))
        self.refuse('finite-source-pin', overlay=overlay)

    def test_overlay_symlink_refused(self):
        overlay = self.root/'overlay'
        (overlay/'scripts').mkdir(parents=True)
        (overlay/'scripts/trap.py').symlink_to(self.source/'scripts/trap.py')
        self.refuse('source-path-symlink', overlay=overlay)


if __name__ == '__main__':
    unittest.main(verbosity=2)
