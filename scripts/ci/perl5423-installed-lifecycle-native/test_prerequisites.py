# SPDX-License-Identifier: MIT
"""Fenced passive DATA controls; never approve or parse a fixed real archive."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('lifecycle_prerequisite_data', HERE/'prerequisites.py')
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def descriptor(path):
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), mode=path.stat().st_mode & 0o777)


class PrerequisiteTests(unittest.TestCase):
    def test_template_refuses_even_with_its_exact_digest(self):
        path = HERE/'prerequisites.TEMPLATE.json'
        with self.assertRaisesRegex(ValueError, 'unreviewed'):
            p.validate(path, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_review_hash_is_external_and_exact(self):
        with self.assertRaisesRegex(ValueError, 'review changed'):
            p.validate(HERE/'prerequisites.TEMPLATE.json', 'a'*64)

    def test_absent_review_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                p.validate(Path(directory)/'missing.json', 'a'*64)

    def test_readonly_and_executable_readonly_data_modes_are_accepted_exactly(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'opaque.data'
            path.write_bytes(b'PASSIVE FIXTURE DATA ONLY\n')
            for mode in (0o444, 0o555):
                path.chmod(mode)
                found, raw = p.file_input(descriptor(path))
                self.assertEqual(found, path)
                self.assertEqual(raw, b'PASSIVE FIXTURE DATA ONLY\n')

    def test_mode_change_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'data'
            path.write_bytes(b'PASSIVE DATA')
            row = descriptor(path)
            path.chmod(0o444 if row['mode'] != 0o444 else 0o555)
            with self.assertRaisesRegex(ValueError, 'mode differ'):
                p.file_input(row)

    def test_content_change_refuses(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'data'
            path.write_bytes(b'original passive data')
            row = descriptor(path)
            path.write_bytes(b'changed passive data')
            with self.assertRaises(ValueError):
                p.file_input(row)

    def test_leaf_symlink_and_parent_alias_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ordinary = root/'ordinary'
            ordinary.mkdir()
            path = ordinary/'data'
            path.write_bytes(b'PASSIVE DATA')
            alias = root/'alias'
            alias.symlink_to(ordinary, target_is_directory=True)
            leaf = root/'leaf'
            leaf.symlink_to(path)
            for bad in (leaf, alias/'data'):
                with self.assertRaises(OSError):
                    p.read(bad, 1024)

    def test_hardlink_and_fifo_refuse_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root/'data'
            path.write_bytes(b'PASSIVE DATA')
            os.link(path, root/'second')
            os.mkfifo(root/'fifo')
            for bad in (path, root/'fifo'):
                with self.assertRaisesRegex(ValueError, 'single-link'):
                    p.read(bad, 1024)

    def test_oversized_data_refuses_before_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'data'
            path.write_bytes(b'12345')
            with self.assertRaisesRegex(ValueError, 'bounded ordinary'):
                p.read(path, 4)

    def test_small_fixture_cannot_become_the_fixed_candidate_or_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'data'
            path.write_bytes(b'NOT AN ARCHIVE')
            for fixed in (p.OLD, p.OLD_SIG, p.CANDIDATE, p.DECISION):
                with self.assertRaisesRegex(ValueError, 'fixed archive'):
                    p.file_input(descriptor(path), fixed=fixed)

    def test_nonfinite_and_duplicate_json_refuse(self):
        for raw in (b'{"x":NaN}', b'{"x":1e999}', b'{"x":1,"x":2}'):
            with self.assertRaises(ValueError):
                p.decode(raw)

    def test_missing_baseline_review_map_refuses(self):
        value = dict(status='ROOT_ARCHIVE_REVIEW_REQUIRED_BEFORE_ADMISSION', archive=p.OLD, signature=p.OLD_SIG, metadata_config_hook_paths=None)
        with self.assertRaisesRegex(ValueError, 'metadata/config/hook map'):
            p.archive_review(value)

    def test_no_image_or_runtime_qualification_is_minted(self):
        template = json.loads((HERE/'prerequisites.TEMPLATE.json').read_text())
        self.assertIsNone(template['authority'])
        self.assertIsNone(template['baseline_review']['archive_review']['path'])
        self.assertTrue(all(value['path'] is None for value in template['inputs'].values()))
        with self.assertRaisesRegex(ValueError, 'prior concrete Root'):
            p.check_capsule_review(Path('/not-opened'), template)

    def test_missing_image_hooks_and_effective_policy_remain_unreviewed(self):
        template = json.loads((HERE/'prerequisites.TEMPLATE.json').read_text())
        with self.assertRaisesRegex(ValueError, 'Root-reviewed config'):
            p.image_expectations(template['image_expectations'])
        self.assertIn('NOT_EQUIVALENT', template['effective_policy']['equivalence'])
        self.assertIn('NO_HOOKDIR', template['effective_policy']['transaction_hookdir'])


if __name__ == '__main__':
    unittest.main()
