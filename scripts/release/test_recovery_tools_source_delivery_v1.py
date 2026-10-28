#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Original inert recursive recipe fixtures; no recipe code is executed."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import tarfile
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('recovery_delivery', Path(__file__).with_name('recovery_tools_source_delivery_v1.py'))
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)


class SourceDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='original-recovery-source-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.recipe = self.root / 'original-recipe'
        self.recipe.mkdir()
        self.originals = {'PKGBUILD': ('touch "' + str(self.root/'SHOULD_NEVER_EXIST') + '"\n').encode(),
                          '.SRCINFO': b'pkgbase = original-inert-fixture\n',
                          'private/scripts/recovery.py': b'# Original inert fixture\n',
                          'private/LICENSE': b'Original MIT fixture notice\n',
                          'empty': b''}
        for name, raw in self.originals.items():
            path = self.recipe / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            path.chmod(0o644)
        self.value = dict(schema_version=1, purpose='recovery-tools-recipe-source',
            package='cachy-asahi-recovery-tools', version='0.1.0-1', files={name:
                dict(sha256=D.sha(raw), bytes=len(raw), mode=0o644) for name, raw in self.originals.items()})
        self.profile = self.root / D.PROFILE_NAME
        self.save_profile()
        self.output = self.root / 'export'
        self.unpacked = self.root / 'unpacked'
        self.common = lambda: ['--profile', str(self.profile), '--profile-sha256', D.sha(self.profile.read_bytes())]

    def save_profile(self):
        self.profile.write_bytes(D.encoded(self.value))
        self.profile.chmod(0o644)

    def cli(self, argv, expected=0):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertEqual(D.main(argv), expected, err.getvalue())
        return json.loads(out.getvalue()) if expected == 0 else err.getvalue()

    def pack(self, expected=0, output=None):
        return self.cli(['pack', '--recipe', str(self.recipe), '--output', str(output or self.output), *self.common()], expected)

    def unpack(self, raw=None, expected=0):
        path = self.output / 'source.tar'
        if raw is not None:
            path.write_bytes(raw)
        return self.cli(['unpack', '--bundle', str(path), '--sha256', D.sha(path.read_bytes()),
                         '--output', str(self.unpacked), *self.common()], expected)

    def test_complete_deterministic_roundtrip_and_no_execution(self):
        result = self.pack()
        self.assertEqual(result['recipe_files'], len(self.originals))
        other = self.root / 'export-again'
        self.pack(output=other)
        self.assertEqual((self.output/'source.tar').read_bytes(), (other/'source.tar').read_bytes())
        self.unpack()
        for name, raw in self.originals.items():
            self.assertEqual((self.unpacked/'recipe'/name).read_bytes(), raw)
        self.assertEqual((self.unpacked/'delivery'/D.PROFILE_NAME).read_bytes(), self.profile.read_bytes())
        self.assertEqual((self.unpacked/'delivery'/D.ADAPTER_NAME).read_bytes(), Path(D.__file__).read_bytes())
        self.assertFalse(any(self.root.rglob('SHOULD_NEVER_EXIST')))

    def test_verify_and_profile_pin_refuse_changed_profile(self):
        result = self.pack()
        args = ['verify', '--bundle', str(self.output/'source.tar'), '--sha256', result['source_sha256'], *self.common()]
        self.cli(args)
        self.profile.write_bytes(self.profile.read_bytes()+b' ')
        self.assertIn('profile checksum mismatch', self.cli(args, 1))

    def test_mutation_missing_and_extra_members_refuse_before_output(self):
        target = self.recipe/'private/scripts/recovery.py'
        raw = target.read_bytes()
        target.write_bytes(b'changed')
        self.assertIn('recipe input mismatch', self.pack(1))
        self.assertFalse(self.output.exists())
        target.unlink()
        self.assertIn('empty or unrecorded', self.pack(1))
        target.write_bytes(raw); target.chmod(0o644)
        (self.recipe/'extra').write_bytes(b'extra')
        self.assertIn('file set differs', self.pack(1))
        self.assertFalse(self.output.exists())

    def test_modes_are_bound(self):
        (self.recipe/'PKGBUILD').chmod(0o755)
        self.assertIn('recipe input mismatch', self.pack(1))

    def test_symlink_hardlink_fifo_and_empty_directory_refuse(self):
        target = self.recipe/'PKGBUILD'
        saved = target.read_bytes()
        target.unlink(); target.symlink_to('.SRCINFO')
        self.assertIn('regular single-link', self.pack(1))
        target.unlink(); os.link(self.recipe/'.SRCINFO', target)
        self.assertIn('regular single-link', self.pack(1))
        target.unlink(); os.mkfifo(target)
        self.assertIn('regular single-link', self.pack(1))
        target.unlink(); target.write_bytes(saved); target.chmod(0o644)
        (self.recipe/'unrecorded').mkdir()
        self.assertIn('empty or unrecorded', self.pack(1))

    def test_symlink_ancestor_refuses(self):
        moved = self.root/'actual-tree'
        self.recipe.rename(moved)
        self.recipe.symlink_to(moved, target_is_directory=True)
        self.pack(1)
        self.assertFalse(self.output.exists())

    def test_existing_output_and_foreign_content_preserved(self):
        self.output.mkdir()
        marker = self.output/'foreign'
        marker.write_bytes(b'caller-owned')
        self.pack(1)
        self.assertEqual(marker.read_bytes(), b'caller-owned')
        self.assertEqual(list(self.output.iterdir()), [marker])
        shutil.rmtree(self.output)
        self.pack()
        self.unpacked.mkdir()
        marker = self.unpacked/'foreign'; marker.write_bytes(b'owned')
        self.unpack(expected=1)
        self.assertEqual(marker.read_bytes(), b'owned')

    def test_symlink_destination_preserved(self):
        foreign = self.root/'foreign'; foreign.mkdir()
        marker = foreign/'data'; marker.write_bytes(b'owned')
        self.output.symlink_to(foreign, target_is_directory=True)
        self.pack(1)
        self.assertTrue(self.output.is_symlink())
        self.assertEqual(marker.read_bytes(), b'owned')

    def test_unsafe_duplicate_hardlink_and_noncanonical_archives_refuse(self):
        self.pack()
        raw = (self.output/'source.tar').read_bytes()
        bodies = D.verified(raw, D.sha(raw), self.value, self.profile.read_bytes(), Path(D.__file__).read_bytes())
        for name, kind in (('../escape', tarfile.REGTYPE), ('recipe/PKGBUILD', tarfile.LNKTYPE)):
            stream = io.BytesIO()
            with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                member = tarfile.TarInfo(name); member.type = kind
                member.linkname = 'recipe/.SRCINFO' if kind == tarfile.LNKTYPE else ''
                archive.addfile(member)
            self.unpack(stream.getvalue(), 1)
            self.assertFalse(self.unpacked.exists())
        self.unpack(raw + b'\0'*512, 1)
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for _ in range(2):
                name = 'recipe/PKGBUILD'; body, mode = bodies[name]
                member = tarfile.TarInfo(name); member.mode = mode; member.size = len(body)
                archive.addfile(member, io.BytesIO(body))
        self.unpack(stream.getvalue(), 1)

    def test_bundle_mutation_with_original_pin_refuses(self):
        result = self.pack()
        source = self.output/'source.tar'; source.write_bytes(source.read_bytes()+b'x')
        self.assertIn('bundle checksum mismatch', self.cli(['verify', '--bundle', str(source),
            '--sha256', result['source_sha256'], *self.common()], 1))

    def test_profile_duplicate_unsafe_paths_bad_types_and_collision_refuse(self):
        self.assertRaises(ValueError, D.profile, b'{"x":1,"x":2}', D.sha(b'{"x":1,"x":2}'))
        for name in ('../escape', '/escape', 'private/../escape', 'private//escape', 'private/./escape'):
            value = json.loads(D.encoded(self.value)); value['files'][name] = value['files']['PKGBUILD']
            raw = D.encoded(value)
            self.assertRaises(ValueError, D.profile, raw, D.sha(raw))
        for mutate in (lambda v: v.update(schema_version=True),
                       lambda v: v['files']['PKGBUILD'].update(bytes=True),
                       lambda v: v['files']['PKGBUILD'].update(mode=0o777),
                       lambda v: v['files'].update(private=v['files']['PKGBUILD'])):
            value = json.loads(D.encoded(self.value)); mutate(value); raw = D.encoded(value)
            self.assertRaises(ValueError, D.profile, raw, D.sha(raw))

    def test_interrupted_owned_staging_cleanup_and_fresh_retry(self):
        with mock.patch.object(D, 'write_file', side_effect=KeyboardInterrupt):
            self.assertRaises(KeyboardInterrupt, self.pack)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob('.recovery-source-*')), [])
        self.pack()
        self.unpack()

    def test_world_writable_parent_refused(self):
        self.root.chmod(0o777)
        self.assertIn('without group/world writes', self.pack(1))


if __name__ == '__main__':
    unittest.main()
