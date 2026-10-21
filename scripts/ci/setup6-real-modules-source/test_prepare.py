#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact materialization and input/output refusal controls; no native actors."""
import argparse
import json
from pathlib import Path
import shutil
import tempfile
import unittest
import prepare

parser = argparse.ArgumentParser()
parser.add_argument('--original-checkout', type=Path, required=True)
parser.add_argument('--setup6-source', type=Path, required=True)
parser.add_argument('--expected', type=Path, required=True)
args, rest = parser.parse_known_args()
args.original_checkout, args.setup6_source, args.expected = (p.absolute() for p in (args.original_checkout, args.setup6_source, args.expected))


class Controls(unittest.TestCase):
    def test_full_exact_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'source'
            result = prepare.emit(args.original_checkout, args.setup6_source, output)
            actual = {p.relative_to(output).as_posix(): prepare.pin(prepare.regular(p)) for p in output.rglob('*') if p.is_file()}
            expected = {p.relative_to(args.expected).as_posix(): prepare.pin(prepare.regular(p)) for p in args.expected.rglob('*') if p.is_file() and '.git' not in p.relative_to(args.expected).parts}
            self.assertEqual(actual, expected)
            self.assertEqual(len(actual), 240)
            self.assertEqual(result['native'], 'NOT_RUN')

    def test_changed_source_refuses_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'setup6'
            shutil.copytree(args.setup6_source, source, ignore=shutil.ignore_patterns('.git'))
            profile = json.loads((prepare.HERE / 'profile.json').read_bytes())
            path = source / next(iter(profile['setup6_files']))
            path.write_bytes(path.read_bytes() + b'\n')
            with self.assertRaisesRegex(ValueError, 'pin differs'):
                prepare.emit(args.original_checkout, source, root / 'output')
            self.assertFalse((root / 'output').exists())

    def test_existing_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'source'
            output.mkdir()
            (output / 'keep').write_bytes(b'user-owned')
            with self.assertRaisesRegex(ValueError, 'fresh ordinary'):
                prepare.emit(args.original_checkout, args.setup6_source, output)
            self.assertEqual((output / 'keep').read_bytes(), b'user-owned')


if __name__ == '__main__':
    unittest.main(argv=[__file__, *rest])
