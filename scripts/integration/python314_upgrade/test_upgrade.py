# SPDX-License-Identifier: MIT
"""Finite historical material/loader controls; no network or Docker mutation."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location('test_' + name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


acquire = load('acquire')


class HistoricalControls(unittest.TestCase):
    def test_foreign_cached_variant_cannot_substitute(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / 'python-3.14.7-2-x86_64_v3.pkg.tar.zst').write_bytes(b'foreign variant')
            with self.assertRaisesRegex(ValueError, 'exact historical baseline material missing'):
                acquire.verify(root)

    def test_same_size_changed_bytes_refused(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            for name, pin in acquire.PINS.items():
                with (root / name).open('wb') as stream:
                    stream.truncate(pin['bytes'])
            with self.assertRaisesRegex(ValueError, 'historical baseline bytes changed'):
                acquire.verify(root)

    def test_symlink_material_refused(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / 'other').write_bytes(b'foreign')
            (root / acquire.BASELINE).symlink_to('other')
            with self.assertRaisesRegex(ValueError, 'exact historical baseline material missing'):
                acquire.verify(root)

    def test_controller_loads_without_checkout_search_path(self):
        controller = load('run')
        self.assertEqual(controller.acquire.PINS, acquire.PINS)
        self.assertEqual(controller.old.BASE,
                         'archlinux@sha256:fcee73ea1b96e236248f53a213f71276cc9072d9025b58bce9915e32f19963ae')


if __name__ == '__main__':
    unittest.main()
