#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real private source/export controls; process and network creation forbidden."""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import zlib_pgo102 as P


class AdoptionControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='pgo102-source-only-')
        self.addCleanup(self.tmp.cleanup); self.base = Path(self.tmp.name)
        self.root = self.base/'source'; self.root.mkdir()
        profile, _ = P.checked()
        names = {P.PROFILE, profile['admission']['source']} | {r['source'] for r in profile['files'].values()}
        for name in names:
            target = self.root/name; target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(P.ROOT/name, target); target.chmod(0o644)
        self.profile = profile; self.output = self.base/'export'
        self.enterContext(patch.object(subprocess, 'Popen', side_effect=AssertionError('process forbidden')))
        self.enterContext(patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')))

    def test_exact_source102_recipe_pipeline_and_original_map(self):
        profile, files = P.checked(self.root)
        self.assertEqual(len(files), 39)
        pipeline = files[P.RECIPE+'/pipeline.py']
        self.assertEqual(P.digest(pipeline), '907717f2f0ecfd126f43ac55b8805bfa871922a4c8f5ee8a1d38f5412f30d2e4')
        self.assertEqual(P.digest(files['PGO-SOURCE.json']), profile['pgo_manifest_sha256'])
        policy = json.loads(files[P.RECIPE+'/recipe-policy.json'])
        self.assertNotEqual(policy['training']['sha256'], policy['validation']['sha256'])
        self.assertEqual(policy['local_files']['pipeline.py']['sha256'], profile['pipeline_sha256'])

    def test_actual_export_has_exact39_bytes_modes_and_no_extra_receipt(self):
        result = P.export(self.output, self.root)
        P.verify_export(self.output, self.profile)
        self.assertEqual(result['files'], 39)
        self.assertEqual(len([p for p in self.output.rglob('*') if p.is_file()]), 39)
        self.assertFalse(result['release_acceptance'])
        before = (self.output/'PGO-SOURCE.json').read_bytes()
        with self.assertRaises(FileExistsError): P.export(self.output, self.root)
        self.assertEqual((self.output/'PGO-SOURCE.json').read_bytes(), before)

    def test_profile_cannot_be_rewritten_to_accept_changed_source(self):
        path = self.root/P.PROFILE
        value = json.loads(path.read_bytes()); value['qualified_source'] = '0'*40
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'profile changed'): P.export(self.output, self.root)
        self.assertFalse(self.output.exists())

    def test_changed_pipeline_or_reused_builder_refuses_before_export(self):
        for name in (P.RECIPE+'/pipeline.py', 'scripts/build/build_v2.py'):
            source = self.profile['files'][name]['source']; path = self.root/source; raw = path.read_bytes()
            path.write_bytes(raw+b'\n# changed\n')
            with self.assertRaises(ValueError): P.export(self.output, self.root)
            self.assertFalse(self.output.exists()); path.write_bytes(raw)

    def test_alias_hardlink_fifo_and_mode_changes_refuse(self):
        target = self.root/P.RECIPE/'pipeline.py'; original = target.read_bytes()
        target.chmod(0o600)
        with self.assertRaises(ValueError): P.checked(self.root)
        target.chmod(0o644); origin = self.base/'origin'; origin.write_bytes(original)
        target.unlink(); target.symlink_to(origin)
        with self.assertRaises(OSError): P.checked(self.root)
        target.unlink(); os.link(origin, target)
        with self.assertRaises(ValueError): P.checked(self.root)
        target.unlink(); os.mkfifo(target)
        with self.assertRaises(ValueError): P.checked(self.root)

    def test_unsafe_or_existing_destination_never_changes_it(self):
        with self.assertRaises(ValueError): P.export(self.root/'inside', self.root)
        self.assertFalse((self.root/'inside').exists())
        self.output.mkdir(); keep = self.output/'keep'; keep.write_bytes(b'preserved')
        with self.assertRaises(FileExistsError): P.export(self.output, self.root)
        self.assertEqual(keep.read_bytes(), b'preserved')
        alias = self.base/'alias'; alias.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises(OSError): P.export(alias/'fresh', self.root)
        self.assertFalse((self.base/'fresh').exists())

    def test_export_extra_leaf_directory_and_mode_refuse(self):
        P.export(self.output, self.root)
        extra = self.output/'extra'; extra.mkdir()
        with self.assertRaises(ValueError): P.verify_export(self.output, self.profile)
        extra.rmdir(); extra.write_bytes(b'unknown')
        with self.assertRaises(ValueError): P.verify_export(self.output, self.profile)
        extra.unlink(); (self.output/'LICENSE').chmod(0o600)
        with self.assertRaises(ValueError): P.verify_export(self.output, self.profile)

    def test_original_component_record_is_byte_pinned(self):
        path = self.root/self.profile['admission']['source']; path.write_bytes(b'new acceptance claim')
        with self.assertRaisesRegex(ValueError, 'component record changed'): P.checked(self.root)

    def test_partial_write_is_retained_and_never_reused(self):
        write = os.write
        def fail(fd, data):
            write(fd, data[:3]); raise OSError('fixture interrupted write')
        with patch.object(P.os, 'write', side_effect=fail), self.assertRaises(OSError):
            P.export(self.output, self.root)
        self.assertTrue(self.output.is_dir())
        files = [p for p in self.output.rglob('*') if p.is_file()]
        self.assertEqual(len(files), 1); self.assertEqual(files[0].stat().st_size, 3)
        with self.assertRaises(ValueError): P.verify_export(self.output, self.profile)
        with self.assertRaises(FileExistsError): P.export(self.output, self.root)
        self.assertEqual(files[0].stat().st_size, 3)


if __name__ == '__main__':
    unittest.main(verbosity=2)
