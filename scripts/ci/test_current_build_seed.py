# SPDX-License-Identifier: MIT
"""Owned filesystem regressions; synthetic transport is not package/GPG evidence."""
import base64
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import old_four_seed as seed


class CurrentBuildSeed(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='current-seed-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cache = self.root / 'cache'
        self.rows = seed.OLD_FOUR_PRIVATE_ROWS + seed.RETAINED_BUBBLEWRAP_PRIVATE_ROWS
        # Public, deterministic synthetic bytes, at the transport's fixed sizes.
        # Only row pins are substituted; real SHA256/size/base64/readback checks run.
        self.bodies = {}
        for name, size, *_ in self.rows:
            marker = ('synthetic test bytes: ' + name + '\n').encode()
            self.bodies[name] = (marker * (size // len(marker) + 1))[:size]
        self.environment = {
            'UNRELATED_TEST_VALUE': 'preserve',
            seed.OLD_FOUR_PRIVATE_PREFIX + 'SCHEMA': '1',
            seed.OLD_FOUR_PRIVATE_PREFIX + 'SOURCE_EPOCH': '1791748800',
        }
        for prefix, rows in ((seed.OLD_FOUR_PRIVATE_PREFIX, seed.OLD_FOUR_PRIVATE_ROWS),
                             (seed.RETAINED_BUBBLEWRAP_PRIVATE_PREFIX, seed.RETAINED_BUBBLEWRAP_PRIVATE_ROWS)):
            for name, _, _, tag, *_ in rows:
                encoded = base64.b64encode(self.bodies[name]).decode('ascii')
                self.environment.update({prefix + f'{tag}_{i // 32768 + 1:02d}': encoded[i:i + 32768]
                                         for i in range(0, len(encoded), 32768)})

    @contextmanager
    def synthetic_pins(self):
        """Explicit fixture seam; never replace hashing, validation or filesystem IO."""
        def rows(values):
            return tuple((name, size, hashlib.sha256(self.bodies[name]).hexdigest(), *rest)
                         for name, size, _, *rest in values)
        with patch.object(seed, 'OLD_FOUR_PRIVATE_ROWS', rows(seed.OLD_FOUR_PRIVATE_ROWS)), \
             patch.object(seed, 'RETAINED_BUBBLEWRAP_PRIVATE_ROWS', rows(seed.RETAINED_BUBBLEWRAP_PRIVATE_ROWS)):
            yield

    def run_seed(self, binding=None):
        seed.seed_current_build_cache(self.cache, seed.RETAINED_BUBBLEWRAP_INPUT_SHA256 if binding is None else binding)

    def assert_erased(self):
        self.assertEqual(dict(os.environ), {'UNRELATED_TEST_VALUE': 'preserve'})

    def assert_no_files(self):
        self.assertFalse(self.cache.exists() and list(self.cache.iterdir()))

    def test_all_six_inputs_are_mandatory(self):
        old, retained = seed.OLD_FOUR_PRIVATE_PREFIX, seed.RETAINED_BUBBLEWRAP_PRIVATE_PREFIX
        cases = {
            'neither': {k: v for k, v in self.environment.items() if not k.startswith((old, retained))},
            'old_only': {k: v for k, v in self.environment.items() if not k.startswith(retained)},
            'retained_only': {k: v for k, v in self.environment.items() if not k.startswith(old)},
            'partial_old': {k: v for k, v in self.environment.items() if k != old + 'JBIGKIT_01'},
        }
        for name, environment in cases.items():
            with self.subTest(name=name), self.synthetic_pins(), patch.dict(os.environ, environment, clear=True):
                with self.assertRaises(ValueError):
                    self.run_seed()
                self.assert_erased()
                self.assert_no_files()

    def test_namespace_and_malformed_chunks_refuse_before_writes(self):
        old, retained = seed.OLD_FOUR_PRIVATE_PREFIX, seed.RETAINED_BUBBLEWRAP_PRIVATE_PREFIX
        cases = {
            'partial_retained': (retained + 'PACKAGE_02', None),
            'extra_retained': (retained + 'EXTRA', 'synthetic'),
            'extra_old': (old + 'EXTRA', 'synthetic'),
            'malformed_chunk': (retained + 'PACKAGE_01', '!'),
            'wrong_digest': (retained + 'SIGNATURE_01', 'A' * 756),
        }
        for name, (key, value) in cases.items():
            environment = dict(self.environment)
            if value is None:
                environment.pop(key)
            else:
                environment[key] = value
            with self.subTest(name=name), self.synthetic_pins(), patch.dict(os.environ, environment, clear=True):
                with self.assertRaises(ValueError):
                    self.run_seed()
                self.assert_erased()
                self.assert_no_files()

    def test_input_binding_and_production_hashes_are_enforced(self):
        with self.synthetic_pins(), patch.dict(os.environ, self.environment, clear=True):
            with self.assertRaisesRegex(ValueError, 'input-binding-refused'):
                self.run_seed('0' * 64)
            self.assertFalse(self.cache.exists())
            self.assert_erased()
        # Unmodified production rows must refuse these same synthetic bodies.
        with patch.dict(os.environ, self.environment, clear=True):
            with self.assertRaisesRegex(ValueError, 'retained-cache-bytes-refused'):
                self.run_seed()
            self.assert_erased()
            self.assert_no_files()

    def test_synthetic_six_readback_and_preexisting_cache_preservation(self):
        with self.synthetic_pins(), patch.dict(os.environ, self.environment, clear=True):
            self.run_seed()
            self.assert_erased()
        self.assertEqual({p.name for p in self.cache.iterdir()}, set(self.bodies))
        snapshots = {}
        for name, body in self.bodies.items():
            path = self.cache / name
            self.assertEqual(path.read_bytes(), body)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            snapshots[name] = path.stat()
        self.assertEqual(stat.S_IMODE(self.cache.stat().st_mode), 0o700)
        with self.synthetic_pins(), patch.dict(os.environ, self.environment, clear=True):
            with self.assertRaisesRegex(ValueError, 'fresh-directory-refused'):
                self.run_seed()
            self.assert_erased()
        for name, before in snapshots.items():
            self.assertEqual((self.cache / name).stat(), before)
            self.assertEqual((self.cache / name).read_bytes(), self.bodies[name])

    def test_cancellation_after_partial_write_rolls_back_and_erases_environment(self):
        cancellation = KeyboardInterrupt('synthetic seed cancellation')
        real_write = os.write
        calls = []
        def cancel_write(fd, data):
            calls.append(fd)
            if len(calls) == 1:
                return real_write(fd, data[:3])
            os.environ[seed.RETAINED_BUBBLEWRAP_PRIVATE_PREFIX + 'LATE'] = 'synthetic'
            raise cancellation
        with self.synthetic_pins(), patch.dict(os.environ, self.environment, clear=True), \
             patch.object(seed.os, 'write', side_effect=cancel_write):
            with self.assertRaises(KeyboardInterrupt) as observed:
                self.run_seed()
            self.assertIs(observed.exception, cancellation)
            self.assertEqual(len(calls), 2)
            receipt = cancellation._retained_cache_receipt
            self.assertEqual(receipt['state'], 'ROLLED_BACK')
            self.assertFalse(receipt['uncertain'])
            self.assertIsNone(receipt['directory'])
            self.assert_no_files()
            self.assert_erased()

    def test_postclose_finish_failure_retains_uncertainty_without_rollback(self):
        failure = OSError('synthetic postclose failure')
        real_finish = seed.finish_retained_private_cache
        def fail_after_close(receipt, deadline):
            real_finish(receipt, deadline)
            raise failure
        with self.synthetic_pins(), patch.dict(os.environ, self.environment, clear=True), \
             patch.object(seed, 'finish_retained_private_cache', side_effect=fail_after_close), \
             patch.object(seed, 'rollback_retained_private_cache', side_effect=AssertionError('unsafe close retry')) as rollback:
            with self.assertRaises(OSError) as observed:
                self.run_seed()
            self.assertIs(observed.exception, failure)
            rollback.assert_not_called()
            receipt = failure._retained_cache_receipt
            self.assertEqual(receipt['state'], 'FINISH_UNCERTAIN')
            self.assertTrue(receipt['uncertain'])
            self.assertIsNone(receipt['directory'])
            self.assert_erased()
        self.assertEqual({p.name for p in self.cache.iterdir()}, set(self.bodies))
        for name, body in self.bodies.items():
            self.assertEqual((self.cache / name).read_bytes(), body)


if __name__ == '__main__':
    unittest.main()
