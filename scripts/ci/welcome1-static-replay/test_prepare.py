# SPDX-License-Identifier: MIT
"""Owned temporary source staging controls; no Git, network or native actors."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
import prepare as P


class Replay(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.current, self.old, self.output = [self.base / p for p in ('current', 'old', 'replay')]
        self.current.mkdir(); self.old.mkdir()
        self.files = {P.PREFIX + ('PKGBUILD' if n == 0 else 'source' + str(n)): b'old' + str(n).encode() for n in range(16)}
        for name, raw in self.files.items():
            target = self.old / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
        self.lock = dict(schema_version=1, source_commit=P.COMMIT, scope=P.SCOPE,
                         files={name: P.pin(raw) for name, raw in self.files.items()})
        self.entries = []
        for name, raw, mode in [('scripts/helper.py', b'current helper\n', 0o100755),
                                 (P.PREFIX + 'PKGBUILD', b'new product', 0o100644),
                                 (P.PREFIX + 'management.c', b'new helper', 0o100644),
                                 ('artifacts/large', b'not replay input', 0o100644)]:
            target = self.current / name; target.parent.mkdir(parents=True, exist_ok=True); target.write_bytes(raw)
            self.entries.append((name, mode, 'a' * 40))

    def stage(self, output=None):
        return P.stage(self.current, self.old, output or self.output, self.entries, self.lock)

    def test_current_helpers_and_only_exact_old_product_copied(self):
        receipt = self.stage()
        self.assertFalse(receipt['current_acceptance'])
        self.assertEqual(receipt['scope'], P.SCOPE)
        self.assertEqual(receipt['file_count'], 17)
        self.assertEqual((self.output / 'scripts/helper.py').read_bytes(), b'current helper\n')
        self.assertEqual((self.output / 'scripts/helper.py').stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.output / P.PREFIX / 'PKGBUILD').read_bytes(), b'old0')
        self.assertFalse((self.output / P.PREFIX / 'management.c').exists())
        self.assertFalse((self.output / 'artifacts').exists())
        self.assertEqual(json.loads((self.output / 'replay.json').read_text())['historical_files'], self.lock['files'])

    def test_changed_or_extra_historical_input_refused_before_output(self):
        path = self.old / P.PREFIX / 'PKGBUILD'; path.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'source pin differs'):
            self.stage()
        self.assertFalse(self.output.exists())
        path.write_bytes(b'old0'); extra = self.old / P.PREFIX / 'extra'; extra.write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError, 'file set differs'):
            self.stage()
        self.assertFalse(self.output.exists())

    def test_existing_overlapping_or_aliased_output_refused(self):
        self.output.mkdir()
        with self.assertRaisesRegex(ValueError, 'fresh output'):
            self.stage()
        with self.assertRaisesRegex(ValueError, 'overlapping'):
            self.stage(self.current / 'nested')
        alias = self.base / 'alias'; alias.symlink_to(self.base, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'alias'):
            self.stage(alias / 'different')

    def test_source_links_traversal_and_index_modes_refused(self):
        helper = self.current / 'scripts/helper.py'; helper.unlink(); helper.symlink_to(self.old / P.PREFIX / 'PKGBUILD')
        with self.assertRaisesRegex(ValueError, 'alias'):
            self.stage()
        helper.unlink(); helper.write_bytes(b'helper')
        for entry in [('../escape', 0o100644, 'a' * 40), ('scripts/link', 0o120000, 'a' * 40)]:
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                P.stage(self.current, self.old, self.output, [entry], self.lock)
        self.assertFalse(self.output.exists())

    def test_lock_full_fingerprint_and_duplicate_keys_are_checked(self):
        path = self.base / 'source.json'; path.write_text(json.dumps(self.lock))
        self.assertEqual(P.source_lock(path), self.lock)
        bad = copy.deepcopy(self.lock); bad['source_commit'] = 'main'; path.write_text(json.dumps(bad))
        with self.assertRaisesRegex(ValueError, 'identity'):
            P.source_lock(path)
        path.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            P.source_lock(path)


if __name__ == '__main__':
    unittest.main()
