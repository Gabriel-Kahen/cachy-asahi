#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""MODEL control bytes only; no actors or network."""
import importlib.util
from pathlib import Path
import os
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('bankstown_passive_tests', HERE / 'passive.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)


def fence(event, args):
    if event.startswith(('subprocess.', 'socket.', 'os.exec', 'os.spawn', 'os.system')):
        raise AssertionError('NO_ACTORS_OR_NETWORK')


sys.addaudithook(fence)


class Passive(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='bankstown-controls-MODEL-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_roundtrip_exact_pin_ref_and_private_fresh_output(self):
        p = self.root / 'MODEL.json'
        raw = P.encoded({'evidence': 'MODEL_ONLY', 'authority': None})
        P.write(p, raw)
        self.assertEqual(p.stat().st_mode & 0o777, 0o600)
        self.assertEqual(P.read_ref(P.ref(p)), raw)
        self.assertEqual(P.decoded(raw)['authority'], None)
        with self.assertRaises(ValueError): P.write(p, raw)
        with self.assertRaises(ValueError): P.read(p, expected=P.pin(b'OTHER'))

    def test_duplicate_nonfinite_and_unbounded_json_refused(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): P.decoded(raw)
        for row in ({'bytes': True, 'sha256': '0'*64}, {'bytes': 1, 'sha256': 'MODEL'},
                    {'bytes': 0, 'sha256': '0'*64}, {'bytes': 1, 'sha256': '0'*64, 'other': None}):
            with self.subTest(row=row), self.assertRaises(ValueError): P.descriptor(row)

    def test_alias_fifo_hardlink_and_oversize_control_refused(self):
        p = self.root/'data'; p.write_bytes(b'MODEL')
        alias = self.root/'alias'; alias.symlink_to(p)
        with self.assertRaises(ValueError): P.read(alias)
        fifo = self.root/'fifo'; os.mkfifo(fifo)
        with self.assertRaises(ValueError): P.read(fifo)
        with self.assertRaises(ValueError): P.read(p, cap=4)
        os.link(p, self.root/'hardlink')
        with self.assertRaises(ValueError): P.read(p)

    def test_source_loader_rejects_missing_or_changed_consumers(self):
        with self.assertRaises(OSError): P.consumers(self.root)
        relative = next(iter(P.PINS)); target=self.root/relative
        target.parent.mkdir(parents=True); target.write_bytes(b'MODEL_NOT_CONSUMER')
        with self.assertRaises(ValueError): P.consumers(self.root)


if __name__ == '__main__':
    unittest.main()
