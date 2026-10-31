#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure checkout-only staging, source refusal and cleanup controls."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import shutil
import stat
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'scripts/platform/archive_intake.py'


def loaded(path):
    module = types.ModuleType('portable_test')
    module.__file__ = str(path)
    exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
    return module


adapter = loaded(SOURCE)


class Checks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = ROOT / '.intake-portable-test-work'
        cls.work.mkdir(mode=0o700)

    @classmethod
    def tearDownClass(cls):
        cls.work.rmdir()

    def test_staged_modes_and_held_policy_guards(self):
        rows = adapter.decode((SOURCE.parent / 'archive_intake_bundle.json').read_bytes())['files']
        with tempfile.TemporaryDirectory(dir=self.work) as parent:
            with adapter.runtime(parent) as engine:
                root = Path(engine.__file__).parent
                for row in rows:
                    p = root / row['path']
                    self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(), row['sha256'])
                    self.assertEqual(stat.S_IMODE(p.stat().st_mode), row['private_mode'])
                self.assertTrue(all(stat.S_IMODE(p.stat().st_mode) == 0o700
                                    for p in root.rglob('*') if p.is_dir()))
                policy = engine.load(engine.RUNTIME / 'policy.py', engine.POLICY_SHA)
                with policy.snapshot() as (raws, check):
                    modules = policy.sources(raws)
                    self.assertEqual(modules['assembler'].readiness()['contract']['required_packages'], 261)
                    with modules['consumer'].snapshot() as (proof, proof_check):
                        consumer = modules['consumer']
                        self.assertEqual(consumer.associations(proof,
                            consumer.decode(proof['inputs/assembly-plan.json']),
                            consumer.decode(proof['inputs/package-reference-index.json'])),
                            'EXACT_TWO_RETAINED_SIGNED_DATA_ASSOCIATIONS')
                        proof_check()
                    check()
                directory = engine.RUNTIME / 'runtime'
                directory.chmod(0o755)
                with self.assertRaisesRegex(ValueError, 'policy-directory-owner-mode'):
                    with policy.snapshot():
                        self.fail('guard weakened')
                directory.chmod(0o700)
            self.assertFalse(root.exists())

    def test_source_tamper_symlink_hardlink_refusals(self):
        for kind in ('changed', 'symlink', 'hardlink'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir=self.work) as parent:
                directory = Path(parent); copied = directory / 'source'
                shutil.copytree(SOURCE.parent, copied)
                leaf = copied / 'archive_intake_bundle/engine.py'
                if kind == 'changed':
                    leaf.write_bytes(leaf.read_bytes() + b'\n')
                elif kind == 'symlink':
                    leaf.unlink(); leaf.symlink_to(SOURCE.parent / 'archive_intake_bundle/engine.py')
                else:
                    os.link(leaf, copied / 'other')
                other = loaded(copied / 'archive_intake.py')
                with self.assertRaises((ValueError, OSError)):
                    with other.runtime(directory):
                        self.fail('unverified source admitted')
                self.assertFalse(list(directory.glob('archive-intake-runtime-*')))

    def test_original_control_identity_and_cleanup(self):
        marker = KeyboardInterrupt('fixture-control')
        with tempfile.TemporaryDirectory(dir=self.work) as parent:
            with self.assertRaises(KeyboardInterrupt) as caught:
                with adapter.runtime(parent):
                    raise marker
            self.assertIs(caught.exception, marker)
            self.assertEqual(list(Path(parent).iterdir()), [])

    def test_outer_runtime_cleanup_failure_prevents_pass(self):
        @contextmanager
        def fixture(selection, authentication, output, seconds):
            with adapter.runtime(output):
                yield {'packages': []}
        result = dict(bundle={}, manifest_sha256='fixture', io={},
                      manifest={'archive_authentication': {}, 'inert_separation': {}})
        with tempfile.TemporaryDirectory(dir=self.work) as parent:
            output = Path(parent) / 'out'
            with patch.object(adapter, 'prepared', fixture), patch.object(adapter, 'assemble', return_value=result),\
                 patch.object(adapter.shutil, 'rmtree', side_effect=OSError('fixture-cleanup-failure')):
                with self.assertRaisesRegex(OSError, 'fixture-cleanup-failure'):
                    adapter.run({}, {}, output)
            self.assertTrue((output / 'INCOMPLETE.json').exists())
            self.assertFalse((output / 'receipt.json').exists())

    def test_close_failure_promotes_control_and_attempts_every_close(self):
        real_close = os.close
        closed = []
        marker = KeyboardInterrupt('close-control')
        def failing_close(fd):
            real_close(fd)
            closed.append(fd)
            if len(closed) == 1:
                raise OSError('ordinary-close')
            if len(closed) == 2:
                raise marker
        with patch.object(adapter.os, 'close', failing_close):
            with self.assertRaises(KeyboardInterrupt) as caught:
                adapter.read_pinned(SOURCE.parent, 'archive_intake_bundle/engine.py', '0'*64, 1024**2)
        self.assertIs(caught.exception, marker)
        self.assertEqual(len(closed), 3)


if __name__ == '__main__':
    unittest.main(verbosity=2)
