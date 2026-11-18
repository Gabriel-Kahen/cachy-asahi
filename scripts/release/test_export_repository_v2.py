#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real TEST signature and copy fixtures. Stable hardware gates are modeled."""
import argparse
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


v2 = load('export_repository_v2')
legacy = load('test_export_repository')


class ExportV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        legacy.ExportTests.setUpClass()

    @classmethod
    def tearDownClass(cls):
        legacy.ExportTests.tearDownClass()

    def setUp(self):
        self.fixture = legacy.ExportTests(methodName='runTest')
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.fixture.add_sources()
        self.fixture.promote()
        self.args = self.fixture.root, self.fixture.endpoint, self.fixture.home, self.fixture.key

    def export(self, apply=False):
        with mock.patch.object(v2.R, 'gates_check', side_effect=lambda *args: v2.R.load(args[-1])):
            return v2.export(*self.args, apply=apply)

    def test_signed_release_exports_the_legacy_generation_with_one_lineage_check_per_source_decision(self):
        before = self.fixture.snapshot(self.fixture.root)
        old = self.fixture.export(False)
        self.assertEqual(self.export(), old)
        self.assertEqual(list(self.fixture.endpoint.iterdir()), [])
        with mock.patch.object(v2.C.r, 'verify_release', wraps=v2.C.r.verify_release) as verify:
            actual = self.export(True)
        source = self.fixture.root / 'stable/fixture-1'
        self.assertEqual([call.args[0] for call in verify.call_args_list], [source] * 3)
        self.assertEqual(actual['generation'], old['generation'])
        self.assertEqual(self.fixture.snapshot(self.fixture.endpoint / 'current/release'), self.fixture.snapshot(source))
        self.assertEqual(self.fixture.snapshot(self.fixture.root), before)

    def test_unmodeled_gate_refuses_the_synthetic_fixture(self):
        promotion = self.fixture.root / 'promotions/fixture-1.json'
        record = v2.R.load(promotion)
        record['gates'].update(release_id=record['release_id'], release_sha256=record['release_sha256'])
        v2.R.write(promotion, record)
        promotion.with_suffix('.json.sig').unlink()
        v2.R.sign(promotion, self.fixture.key, self.fixture.env)
        with self.assertRaisesRegex(v2.R.Error, 'synthetic fixtures cannot enter stable'):
            v2.export(*self.args, apply=True)
        self.assertEqual(list(self.fixture.endpoint.iterdir()), [])

    def test_signed_archive_record_mismatch_refuses_before_materialization(self):
        release = self.fixture.root / 'stable/fixture-1/release.json'
        changed = v2.R.load(release)
        changed['packages'][0]['sha256'] = '0' * 64
        v2.R.write(release, changed)
        signature = release.with_suffix('.json.sig')
        signature.unlink()
        v2.R.sign(release, self.fixture.key, self.fixture.env)

        def signed_record(directory, key, env):
            # Model the semantic verifier's return to isolate the signed-file-map join.
            # This fixture signs only the draft manifest and leaves old provenance and database bytes.
            v2.R.verify_signature(directory / 'release.json', key, env)
            return v2.R.load(directory / 'release.json'), v2.R.load(directory / 'spec.json')

        with (mock.patch.object(v2.C.r, 'verify_release', side_effect=signed_record) as verify,
              mock.patch.object(v2.E, 'materialize', side_effect=AssertionError('must refuse before materialization'))):
            with self.assertRaisesRegex(v2.C.r.Error, 'artifact digest differs from signed file map'):
                self.export(True)
        self.assertEqual(verify.call_count, 1)
        self.assertEqual(list(self.fixture.endpoint.iterdir()), [])

    def test_active_and_withdrawal_only_generation_preserve_signed_incidents(self):
        fixture = self.fixture
        reason = fixture.inputs / 'reason.txt'
        reason.write_text('Synthetic withdrawal drill.\n')
        v2.R.withdraw(argparse.Namespace(release_id='fixture-1', reason=str(reason)), fixture.root, fixture.key, fixture.env)
        self.assertEqual(self.export(), fixture.export(False))
        fixture.promote('fixture-2')
        self.assertEqual(self.export(), fixture.export(False))
        actual = self.export(True)
        self.assertEqual(actual['selected_release'], 'fixture-2')
        path = Path('withdrawals/fixture-1.json.sig')
        self.assertEqual((fixture.endpoint / 'current' / path).read_bytes(), (fixture.root / path).read_bytes())


if __name__ == '__main__':
    unittest.main()
