# SPDX-License-Identifier: MIT
"""Source-only dual-root bootstrap controls with a modeled runtime identity."""

import base64
import copy
import importlib.util
from pathlib import Path
import runpy
import tempfile
import time
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, HERE / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


legacy = load('legacy_bootstrap_fixture', 'development-bootstrap.py')
bootstrap = load('dual_root_bootstrap_fixture', 'development-bootstrap-v3.py')
PACKET = 'scripts/ci/development/packet-dual-source.lock.json'
SOURCE = 'a' * 40
PEER = b'modeled peer bytes for the source-only test'
OBSERVED = ((1, 2, 0o100755, 0, 0, 1), (2, 3, 0o140660, 0, 0, 1))


class BootstrapV3Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture = runpy.run_path(str(ROOT / 'scripts/ci/development/repository_graph_fixture.py'))
        cls.lock = fixture['original_lock'](ROOT)
        files = {}
        for name in (*cls.lock['source_files'], legacy.INITIAL):
            raw, mode = fixture['historical_input'](ROOT, name)
            files[name] = {'mode': mode, 'base64': base64.b64encode(raw).decode('ascii')}
        cls.history = {'schema_version': 1, 'source_commit': bootstrap.ORIGINAL_SOURCE['source_commit'], 'files': files}
        cls.history_raw = legacy.encoded(cls.history)
        cls.packet_raw = (ROOT / PACKET).read_bytes()
        packet = legacy.decode(cls.packet_raw)
        cls.selection = {
            'source_commit': SOURCE, 'source_files': packet['source_files'],
            'metadata_pins': packet['metadata_pins'],
            'metadata_hex': {path: (ROOT / path).read_bytes().hex() for path in legacy.METADATA},
            'maps': {role: {'path': prefix + '/source-map.json',
                           'sha256': packet['metadata_pins'][prefix + '/source-map.json']}
                     for role, prefix in legacy.PREFIXES.items()},
            'callbacks': legacy.CALLBACKS, 'peer_receipt_sha256': legacy.digest(PEER),
            'original_source': packet['original_source'], 'packet_sha256': legacy.digest(cls.packet_raw),
        }

    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.temporary = Path(scratch.name)
        self.environment = {
            'GITHUB_SHA': SOURCE, 'GITHUB_WORKFLOW_SHA': SOURCE, 'GITHUB_RUN_ID': '3', 'GITHUB_RUN_ATTEMPT': '1',
            'GITHUB_WORKSPACE': str(ROOT), 'RUNNER_TEMP': str(self.temporary),
        }
        self.deadline = time.monotonic() + 45
        self.selection_raw = legacy.encoded(self.selection)
        self.pins = {
            'selection_sha256': legacy.digest(self.selection_raw), 'peer_receipt_sha256': legacy.digest(PEER),
            'source_rows_sha256': legacy.digest(legacy.encoded(self.selection['source_files'])),
            'source_commit': SOURCE, 'cli_sha256': 'b' * 64, 'original_source_sha256': legacy.digest(self.history_raw),
        }

    def prepare(self, *, history=None, peer=PEER, selection=None):
        raw = self.history_raw if history is None else history
        selected = self.selection_raw if selection is None else selection
        return bootstrap.prepare(legacy, selected, peer, raw, self.pins, self.environment,
                                 preparation_deadline=self.deadline)

    def verify(self, prepared):
        return bootstrap.verify_checkout(legacy, prepared, self.pins, self.environment, deadline=self.deadline)

    def test_exact_history_and_candidate_construct_closed_v3_contract(self):
        with patch.object(legacy, 'observe_runtime', return_value=OBSERVED) as observation:
            prepared = self.prepare()
            self.addCleanup(prepared['owned'].dispose)
            grant = legacy.decode(Path(prepared['execution_grant'][0]).read_bytes())
            self.assertEqual(grant['schema_version'], 3)
            original = prepared['paths']['original']
            self.assertEqual(grant['original_view']['source_root'], str(original))
            self.assertEqual(grant['original_view']['schema_version'], 2)
            self.assertNotEqual(grant['original_view']['full_source_root'], str(original))
            self.assertEqual(grant['recipe_source_commit'], self.lock['recipe_source_commit'])
            self.assertEqual(legacy.digest((original / bootstrap.RUNNER).read_bytes()), bootstrap.ORIGINAL_SOURCE['runner_sha256'])
            self.assertEqual((original / 'scripts/release/release.py').stat().st_mode & 0o777, 0o755)
            empty = original / 'packages/desktop/evidence'
            for name in ('native-ci-38189058133/strict-corrected-diff.txt', 'source-check-1.txt', 'source-check-2.txt'):
                self.assertEqual((empty / name).read_bytes(), b'')
                self.assertEqual((empty / name).stat().st_mode & 0o777, 0o644)
            verified = self.verify(prepared)
            self.assertEqual(verified['selected_rows_verified'], 259)
            self.assertEqual(verified['packet_sha256'], legacy.digest(self.packet_raw))
            self.assertEqual(verified['metadata_pins'][legacy.INITIAL], legacy.INITIAL_SHA)
            self.assertNotEqual(verified['metadata_pins'][legacy.INITIAL], self.selection['metadata_pins'][legacy.INITIAL])
            self.assertEqual(observation.call_count, 3)
            self.assertFalse(prepared['paths']['output'].exists())
            self.assertFalse(prepared['paths']['cache'].exists())
            self.assertTrue(prepared['owned'].dispose())
            self.assertEqual(list(self.temporary.iterdir()), [])

    def test_wrong_peer_or_bundle_refuses_before_observation_or_staging(self):
        with patch.object(legacy, 'observe_runtime', side_effect=AssertionError('premature observation')):
            with self.assertRaisesRegex(legacy.Refused, '^external-provenance$'):
                self.prepare(peer=b'different modeled peer')
            with self.assertRaisesRegex(legacy.Refused, '^historical-bundle-pin$'):
                self.prepare(history=self.history_raw + b' ')
        self.assertEqual(list(self.temporary.iterdir()), [])

    def test_rebound_historical_identity_refuses(self):
        value = copy.deepcopy(self.selection)
        value['original_source']['runner_sha256'] = '0' * 64
        raw = legacy.encoded(value)
        self.pins['selection_sha256'] = legacy.digest(raw)
        with self.assertRaisesRegex(legacy.Refused, '^selection-provenance$'):
            self.prepare(selection=raw)
        self.assertEqual(list(self.temporary.iterdir()), [])

    def test_rebound_historical_rows_refuse_substitution_and_mode_drift(self):
        name = 'scripts/release/release.py'
        for change, reason in (('source', 'historical-source-pin'), ('mode', 'historical-source-pin'),
                               ('name', 'historical-path-set')):
            with self.subTest(change=change), patch.object(
                    legacy, 'observe_runtime', side_effect=AssertionError('premature observation')):
                bundle = copy.deepcopy(self.history)
                row = bundle['files'][name]
                if change == 'source':
                    row['base64'] = base64.b64encode((ROOT / name).read_bytes()).decode('ascii')
                elif change == 'mode':
                    row['mode'] = 0o644
                else:
                    bundle['files']['scripts/release/foreign.py'] = bundle['files'].pop(name)
                raw = legacy.encoded(bundle)
                self.pins['original_source_sha256'] = legacy.digest(raw)
                with self.assertRaisesRegex(legacy.Refused, '^' + reason + '$'):
                    self.prepare(history=raw)
                self.assertEqual(list(self.temporary.iterdir()), [])

    def test_verify_refuses_root_alias_and_in_place_historical_drift(self):
        with patch.object(legacy, 'observe_runtime', return_value=OBSERVED) as observation:
            prepared = self.prepare()
            self.addCleanup(prepared['owned'].dispose)
            original = prepared['paths']['original']
            prepared['paths']['original'] = ROOT
            with self.assertRaisesRegex(legacy.Refused, '^historical-root-binding$'):
                self.verify(prepared)
            prepared['paths']['original'] = original
            extra = original / 'foreign'
            extra.write_bytes(b'foreign')
            with self.assertRaisesRegex(legacy.Refused, '^historical-path-drift$'):
                self.verify(prepared)
            self.assertEqual(extra.read_bytes(), b'foreign')
            extra.unlink()
            path = original / 'scripts/release/release.py'
            path.write_bytes(path.read_bytes() + b' ')
            with self.assertRaisesRegex(legacy.Refused, '^historical-source-drift$'):
                self.verify(prepared)
            self.assertEqual(observation.call_count, 2)

    def test_refuses_checkout_run_rebinding(self):
        with patch.object(legacy, 'observe_runtime', return_value=OBSERVED):
            prepared = self.prepare()
            self.addCleanup(prepared['owned'].dispose)
            self.environment['GITHUB_RUN_ID'] = '4'
            with self.assertRaisesRegex(legacy.Refused, '^checkout-bindings$'):
                self.verify(prepared)

    def test_staging_failure_retires_only_owned_paths(self):
        foreign = self.temporary / 'foreign'
        foreign.write_bytes(b'untouched')
        with patch.object(legacy, 'observe_runtime', side_effect=legacy.Refused('modeled-runtime-refusal')):
            with self.assertRaisesRegex(legacy.Refused, '^modeled-runtime-refusal$') as failure:
                self.prepare()
        self.assertTrue(failure.exception.cleanup_complete)
        self.assertEqual(list(self.temporary.iterdir()), [foreign])
        self.assertEqual(foreign.read_bytes(), b'untouched')


if __name__ == '__main__':
    unittest.main()
