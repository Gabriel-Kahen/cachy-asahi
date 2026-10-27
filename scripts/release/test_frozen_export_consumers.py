#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real combined source/pin imports; no container, signer, updater or VM starts."""
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
EXPORTER = 'scripts/release/export_repository.py'
EXPORTER_SHA = '9d07089a8855a1b11ad8a8f2ef680b00aa4ea48f7f422e05ce83a279780595ea'
CONFIGS = ('scripts/ci/full-root-upgrade-caller/upgrade-config.json',
           'scripts/ci/full-root-failed-update/lane-config.json',
           'scripts/ci/full-root-postcommit-failure/lane-config.json')


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


def selection(relative):
    config = ROOT / relative
    value = json.loads(config.read_bytes())
    lane = module('export_pin_' + config.parent.name.replace('-', '_'),
                  config.parent.relative_to(ROOT).as_posix() + '/run.py')
    args = SimpleNamespace(source_root=ROOT, lane_config=config,
        lane_config_sha256=hashlib.sha256(config.read_bytes()).hexdigest(), failure_case=lane.CASE,
        auxiliary_runtime=True, runtime=ROOT / 'scripts/update/linked_runtime.py',
        runtime_sha256=value['code_pins']['scripts/update/linked_runtime.py'],
        initializer=ROOT / 'scripts/update/aux_initialize.py',
        initializer_sha256=value['code_pins']['scripts/update/aux_initialize.py'],
        comparator=ROOT / 'scripts/ci/full-development-composition/audio_aux.py')
    return lane, args


class FrozenExportConsumers(unittest.TestCase):
    def test_all_three_live_pin_closures_match_real_combined_source(self):
        self.assertEqual(hashlib.sha256((ROOT / EXPORTER).read_bytes()).hexdigest(), EXPORTER_SHA)
        for name in CONFIGS:
            value = json.loads((ROOT / name).read_bytes())
            self.assertEqual(value['code_pins'][EXPORTER], EXPORTER_SHA)
            for relative, expected in value['code_pins'].items():
                with self.subTest(config=name, source=relative):
                    self.assertEqual(hashlib.sha256((ROOT / relative).read_bytes()).hexdigest(), expected)

    def test_existing_export_and_endpoint_api_calls_still_bind(self):
        exporter = module('combined_export_api', EXPORTER)
        client = module('combined_endpoint_api', 'scripts/client/endpoint.py')
        required = dict(canonical=1, managed_directory=1, encoded=1, tree=1,
                        generation_check=2, stable=5, export=5)
        for api in (exporter, client.e):
            for name, arity in required.items():
                with self.subTest(name=name):
                    inspect.signature(getattr(api, name)).bind(*([None] * arity))
            self.assertEqual((api.MAX_FILES, api.MAX_BYTES), (16384, 8 * 1024**3))
        self.assertEqual(str(inspect.signature(exporter.export)), '(root, endpoint, home, key, apply=False)')
        inspect.signature(exporter.describe).bind(None, None, None)

    def accepted_then_drift(self, relative):
        lane, args = selection(relative)
        with patch('subprocess.Popen', side_effect=AssertionError('source selection must not start actors')):
            selected = lane.selected_api(args)
            self.assertEqual(Path(selected.driver.__file__), ROOT / lane.NORMAL)
            self.assertIsNotNone(selected.normal)
            real_read = lane.read
            def drift(path, maximum=1024**2):
                raw = real_read(path, maximum)
                return raw + b'\n' if Path(path) == ROOT / EXPORTER else raw
            with patch.object(lane, 'read', side_effect=drift):
                with self.assertRaisesRegex(ValueError, 'frozen source differs: scripts/release/export_repository.py'):
                    lane.selected_api(args)

    def test_precommit_real_selected_api_accepts_then_rejects_exporter_drift(self):
        self.accepted_then_drift(CONFIGS[1])

    def test_postcommit_real_selected_api_accepts_then_rejects_exporter_drift(self):
        self.accepted_then_drift(CONFIGS[2])

    def test_lane_configuration_byte_seals_refuse_before_api_import(self):
        for relative in CONFIGS[1:]:
            lane, args = selection(relative)
            real_read = lane.read
            def drift(path, maximum=1024**2):
                raw = real_read(path, maximum)
                return raw + b'\n' if Path(path) == args.lane_config else raw
            with self.subTest(lane=relative), patch.object(lane, 'read', side_effect=drift), \
                 patch.object(lane, 'load', side_effect=AssertionError('unsealed input reached API import')):
                with self.assertRaisesRegex(ValueError, 'lane configuration pin differs'):
                    lane.selected_api(args)

    def test_failure_policy_limits_and_expiry_are_not_rewritten_by_pin_refresh(self):
        for relative, case, exit_code in ((CONFIGS[1], 'precommit-exit86', 86),
                                          (CONFIGS[2], 'postcommit-exit87', 87)):
            value = json.loads((ROOT / relative).read_bytes())
            self.assertEqual(value['failure'], dict(case=case, exit_code=exit_code,
                                                   worker_seconds=1200, verify_seconds=600))
            self.assertEqual(value['release']['issued_utc'], '2026-10-16T00:00:00Z')
            self.assertEqual(value['release']['expires_utc'], '2026-10-18T00:00:00Z')
            for name in ('window_bytes', 'decoded_bytes'):
                self.assertEqual(value['scale']['limits'][name], 16 * 1024**2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
