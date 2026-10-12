# SPDX-License-Identifier: MIT
import argparse
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import harness


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.addCleanup(patch.stopall)
        patch.object(harness, 'ROOT', self.root).start()
        self.before = b'one\ntwo\nthree\n'
        self.after = b'one\nfixed\nthree\n'
        self.patch_bytes = b'diff --git a/block/bio.c b/block/bio.c\n--- a/block/bio.c\n+++ b/block/bio.c\n@@ -1,3 +1,3 @@\n one\n-two\n+fixed\n three\n'
        self.archive = self.root / 'source.tar.gz'
        self.config = self.root / 'config'; self.config.write_text('\n'.join(harness.GUARDS) + '\n')
        self.patch = self.root / 'change.patch'; self.patch.write_bytes(self.patch_bytes)
        self.members = {'linux-test/block/bio.c': self.before, 'linux-test/COPYING': b'license\n'}
        self.tar()
        self.lock = {'schema_version': 1, 'experiment': 'KERNEL-C01', 'selected_for_release': False,
                     'archive': {'root': 'linux-test', 'commit': 'a' * 40}, 'config': {}, 'patch': {},
                     'files': {'block/bio.c': {'before_sha256': self.sha(self.before), 'after_sha256': self.sha(self.after)}},
                     'licenses': {'COPYING': {'before_sha256': self.sha(b'license\n')}}, 'build_plan': {'status': 'NOT RUN'}}
        self.lock_path = self.root / 'candidate.json'
        self.refresh()

    @staticmethod
    def sha(data):
        return hashlib.sha256(data).hexdigest()

    def tar(self, extra=None):
        with tarfile.open(self.archive, 'w:gz') as stream:
            for name, data in self.members.items():
                row = tarfile.TarInfo(name); row.size = len(data)
                stream.addfile(row, io.BytesIO(data))
            if extra:
                stream.addfile(*extra)

    def refresh(self):
        for key, path in (('archive', self.archive), ('config', self.config), ('patch', self.patch)):
            self.lock[key].update(sha256=harness.digest(path), bytes=path.stat().st_size)
        harness.save(self.lock_path, self.lock)

    def args(self, mode='apply'):
        return argparse.Namespace(mode=mode, lock=self.lock_path, lock_sha256=harness.digest(self.lock_path),
                                  archive=self.archive, config=self.config, patch=self.patch,
                                  output=self.root / 'artifacts/kernel-candidates/trial')

    def test_actual_patch_applies_only_expected_file(self):
        args = self.args(); result = harness.run(args)
        self.assertEqual((result['status'], result['fuzz'], result['rejects']), ('PATCH_APPLIED_TO_SOURCE_SLICE', 0, 0))
        self.assertEqual((args.output / 'source-slice/block/bio.c').read_bytes(), self.after)
        self.assertEqual(result['kernel_build'], 'NOT RUN')
        self.assertEqual(len(result['commands']), 2)

    def test_plan_runs_no_commands(self):
        with patch.object(subprocess, 'run', side_effect=AssertionError('command during plan')):
            result = harness.run(self.args('plan'))
        self.assertEqual(result['status'], 'SOURCE_VALIDATED')
        self.assertEqual(result['commands'], [])

    def test_full_source_baseline_and_candidate_verify_every_member(self):
        for index, mode in enumerate(('baseline', 'apply')):
            args = self.args(mode); args.full_source = True
            args.output = args.output.with_name('full-' + str(index))
            with patch.object(harness.shutil, 'disk_usage', return_value=SimpleNamespace(free=4 * 1024**3)):
                result = harness.run(args)
            self.assertTrue(result['full_source_tree'])
            expected = ['block/bio.c'] if mode == 'apply' else []
            self.assertEqual(result['full_tree_verification']['changed_files'], expected)
            self.assertEqual(result['full_tree_verification']['regular_files_verified'], 2)

    def test_full_tree_detects_unrelated_file_drift(self):
        args = self.args('baseline'); args.full_source = True
        with patch.object(harness.shutil, 'disk_usage', return_value=SimpleNamespace(free=4 * 1024**3)):
            harness.run(args)
        source = args.output / 'source-tree/linux-test'
        (source / 'COPYING').write_bytes(b'changed license')
        with self.assertRaises(ValueError): harness.verify_full_tree(self.archive, source, self.lock, patched=False)

    def test_input_or_lock_drift_refused_before_output(self):
        for kind in ('archive', 'config', 'patch', 'lock'):
            args = self.args()
            target = {'archive': self.archive, 'config': self.config, 'patch': self.patch, 'lock': self.lock_path}[kind]
            original = target.read_bytes(); target.write_bytes(original + b'changed')
            with self.assertRaises(ValueError): harness.run(args)
            self.assertFalse(args.output.exists()); target.write_bytes(original)

    def test_expected_source_member_pin_required(self):
        self.lock['files']['block/bio.c']['before_sha256'] = '0' * 64; self.refresh()
        with self.assertRaises(ValueError): harness.run(self.args())

    def test_patched_output_pin_required_and_failure_retained(self):
        self.lock['files']['block/bio.c']['after_sha256'] = '0' * 64; self.refresh()
        args = self.args()
        with self.assertRaises(ValueError): harness.run(args)
        self.assertEqual(json.loads((args.output / 'result.json').read_text())['status'], 'FAIL')

    def test_archive_duplicate_refused(self):
        row = tarfile.TarInfo('linux-test/COPYING'); row.size = 0
        self.tar((row, io.BytesIO(b''))); self.refresh()
        with self.assertRaises(ValueError): harness.run(self.args())

    def test_archive_path_escape_and_special_member_refused(self):
        for name, kind, link in (('../escape', tarfile.REGTYPE, ''), ('linux-test/escape', tarfile.SYMTYPE, '../../escape'),
                                 ('linux-test/device', tarfile.CHRTYPE, ''), ('other-root/file', tarfile.REGTYPE, '')):
            row = tarfile.TarInfo(name); row.type = kind; row.linkname = link
            self.tar((row, None)); self.refresh()
            with self.assertRaises(ValueError): harness.run(self.args())

    def test_patch_extra_path_and_file_creation_refused(self):
        for data in (self.patch_bytes.replace(b'block/bio.c', b'../escape'),
                     self.patch_bytes + b'diff --git a/extra b/extra\n',
                     self.patch_bytes + b'--- /dev/null\n+++ c/extra\n@@ -0,0 +1 @@\n+unexpected\n',
                     b'@@ -1 +1 @@\n-old\n+new\n' + self.patch_bytes,
                     self.patch_bytes.replace(b'--- a/', b'new file mode 100644\n--- a/')):
            with self.assertRaises(ValueError): harness.patch_paths(data, {'block/bio.c'})

    def test_materialization_read_error_retains_failure(self):
        args = self.args('baseline'); args.full_source = True
        original = tarfile.open
        def open_tar(*values, **kwargs):
            if values and str(values[0]).endswith('source-snapshot.tar.gz'):
                raise tarfile.ReadError('injected extraction failure')
            return original(*values, **kwargs)
        with patch.object(harness.shutil, 'disk_usage', return_value=SimpleNamespace(free=4 * 1024**3)), patch.object(tarfile, 'open', side_effect=open_tar):
            with self.assertRaises(tarfile.ReadError): harness.run(args)
        self.assertEqual(json.loads((args.output / 'result.json').read_text())['status'], 'FAIL')

    def test_input_swap_during_snapshot_refused_before_extraction(self):
        args = self.args('baseline'); args.full_source = True
        original = self.archive.read_bytes()
        real_validate = harness.validate
        def validated(*values):
            result = real_validate(*values)
            self.members['linux-test/unexpected-large'] = b'x' * 1024
            self.tar()
            return result
        with patch.object(harness, 'validate', side_effect=validated), patch.object(harness.shutil, 'disk_usage', return_value=SimpleNamespace(free=4 * 1024**3)):
            with self.assertRaises(ValueError): harness.run(args)
        self.assertFalse((args.output / 'source-tree/linux-test/unexpected-large').exists())
        self.assertEqual(json.loads((args.output / 'result.json').read_text())['status'], 'FAIL')
        self.archive.write_bytes(original)

    def test_safe_symlink_original_spelling_preserved(self):
        row = tarfile.TarInfo('linux-test/alias'); row.type = tarfile.SYMTYPE; row.linkname = './block/../COPYING'
        self.tar((row, None)); self.refresh()
        args = self.args('baseline'); args.full_source = True
        with patch.object(harness.shutil, 'disk_usage', return_value=SimpleNamespace(free=4 * 1024**3)):
            result = harness.run(args)
        self.assertTrue(result['full_tree_verification']['all_other_members_identical'])
        self.assertEqual((args.output / 'source-tree/linux-test/alias').readlink(), Path(row.linkname))

    def test_restored_symlink_cannot_escape_through_existing_link(self):
        with tarfile.open(self.archive, 'w:gz') as stream:
            for name, data in self.members.items():
                row = tarfile.TarInfo(name); row.size = len(data); stream.addfile(row, io.BytesIO(data))
            for name in ('linux-test/g', 'linux-test/g/h'):
                row = tarfile.TarInfo(name); row.type = tarfile.DIRTYPE; stream.addfile(row)
            for name, target in (('linux-test/g/h/deep', '../..'), ('linux-test/escape', 'g/h/deep/../../../outside')):
                row = tarfile.TarInfo(name); row.type = tarfile.SYMTYPE; row.linkname = target; stream.addfile(row)
        self.refresh(); args = self.args('baseline'); args.full_source = True
        with patch.object(harness.shutil, 'disk_usage', return_value=SimpleNamespace(free=4 * 1024**3)):
            with self.assertRaises(ValueError): harness.run(args)
        self.assertEqual(json.loads((args.output / 'result.json').read_text())['status'], 'FAIL')
        self.assertFalse((args.output / 'source-tree/linux-test/escape').is_symlink())

    def test_wrong_16k_or_apple_config_refused(self):
        self.config.write_text('\n'.join(harness.GUARDS).replace('CONFIG_ARM64_16K_PAGES=y', 'CONFIG_ARM64_4K_PAGES=y'))
        self.refresh()
        with self.assertRaises(ValueError): harness.run(self.args())

    def test_existing_or_outside_or_symlink_output_refused(self):
        args = self.args(); args.output = self.root / 'outside'
        with self.assertRaises(ValueError): harness.run(args)
        args.output = self.root / 'artifacts/kernel-candidates/../../outside'
        with self.assertRaises(ValueError): harness.run(args)
        base = self.root / 'artifacts'; base.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError): harness.run(self.args())
        base.unlink(); args = self.args(); args.output.mkdir(parents=True)
        with self.assertRaises(ValueError): harness.run(args)

    def test_full_materialization_storage_guard(self):
        args = self.args('baseline'); args.full_source = True
        with patch.object(harness.shutil, 'disk_usage', return_value=SimpleNamespace(free=4 * 1024**3 - 1)):
            with self.assertRaises(ValueError): harness.run(args)
        self.assertEqual(json.loads((args.output / 'result.json').read_text())['status'], 'FAIL')

    def test_no_fuzz_allowed(self):
        # GNU patch would accept removal of the unmatched first context line at fuzz=1.
        self.members['linux-test/block/bio.c'] = b'drift\ntwo\nthree\n'; self.tar()
        self.lock['files']['block/bio.c']['before_sha256'] = self.sha(self.members['linux-test/block/bio.c']); self.refresh()
        args = self.args()
        with self.assertRaises(ValueError): harness.run(args)
        self.assertEqual(json.loads((args.output / 'result.json').read_text())['status'], 'FAIL')
        self.assertEqual((args.output / 'source-slice/block/bio.c').read_bytes(), self.members['linux-test/block/bio.c'])

    def test_command_timeout_retains_failure_receipt(self):
        args = self.args()
        with patch.object(subprocess, 'run', side_effect=subprocess.TimeoutExpired('patch', 30)):
            with self.assertRaises(subprocess.TimeoutExpired): harness.run(args)
        self.assertEqual(json.loads((args.output / 'result.json').read_text())['status'], 'FAIL')

    def test_duplicate_json_key_refused(self):
        self.lock_path.write_text('{"a":1,"a":2}')
        with self.assertRaises(ValueError): harness.read_json(self.lock_path)


if __name__ == '__main__':
    unittest.main()
