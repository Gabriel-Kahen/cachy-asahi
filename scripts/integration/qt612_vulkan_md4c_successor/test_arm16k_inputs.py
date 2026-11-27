#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Refusal checks for the offline Qt successor input boundary."""

import hashlib
from pathlib import Path
from runpy import run_path
from tempfile import TemporaryDirectory
import unittest


INPUTS = run_path(str(Path(__file__).resolve().with_name("arm16k_inputs.py")))


class InputTests(unittest.TestCase):
    def test_readonly_input_pin_rejects_writes_and_changed_bytes(self):
        with TemporaryDirectory() as directory:
            original = Path(directory) / "original"
            original.write_bytes(b"verified")
            expected = INPUTS["pin"](8, hashlib.sha256(b"verified").hexdigest())
            with self.assertRaisesRegex(ValueError, "file type or mode"):
                INPUTS["verify"](original, expected, readonly=True)
            original.chmod(0o400)
            self.assertEqual(INPUTS["verify"](original, expected, readonly=True), expected)
            original.chmod(0o600)
            original.write_bytes(b"tampered")
            original.chmod(0o400)
            with self.assertRaisesRegex(ValueError, "pin differs"):
                INPUTS["verify"](original, expected, readonly=True)

    def test_original_symlink_refused(self):
        with TemporaryDirectory() as directory:
            original = Path(directory) / "original"
            original.write_bytes(b"verified")
            link = original.with_name("link")
            link.symlink_to(original)
            with self.assertRaisesRegex(ValueError, "Ordinary absolute file"):
                INPUTS["verify"](link)

    def test_inventory_requires_complete_sorted_distinct_rows(self):
        parse = INPUTS["package_inventory"]
        expected = {b"md4c": b"0.6.0-2", b"vulkan-headers": b"1:1.4.363.0-1"}
        self.assertEqual(parse(b"md4c 0.6.0-2\nvulkan-headers 1:1.4.363.0-1\n", 2), expected)
        for malformed in (
            b"md4c 0.6.0-2\nmd4c 1.0-1\n",
            b"vulkan-headers 1:1.4.363.0-1\nmd4c 0.6.0-2\n",
            b"md4c 0.6.0-2\nvulkan-headers 1:1.4.363.0-1",
        ):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                parse(malformed, 2)


if __name__ == "__main__":
    unittest.main()
