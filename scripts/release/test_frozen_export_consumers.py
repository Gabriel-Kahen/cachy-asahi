#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real combined source/pin imports; no container, signer, updater or VM starts."""
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import sys
import shutil
import tempfile
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


def module(name, relative, root=ROOT):
    spec = importlib.util.spec_from_file_location(name, root / relative)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value


def selection(relative, root):
    config = root / relative
    value = json.loads(config.read_bytes())
    lane = module('export_pin_' + config.parent.name.replace('-', '_'),
                  config.parent.relative_to(root).as_posix() + '/run.py', root)
    args = SimpleNamespace(source_root=root, lane_config=config,
        lane_config_sha256=hashlib.sha256(config.read_bytes()).hexdigest(), failure_case=lane.CASE,
        auxiliary_runtime=True, runtime=root / 'scripts/update/linked_runtime.py',
        runtime_sha256=value['code_pins']['scripts/update/linked_runtime.py'],
        initializer=root / 'scripts/update/aux_initialize.py',
        initializer_sha256=value['code_pins']['scripts/update/aux_initialize.py'],
        comparator=root / 'scripts/ci/full-development-composition/audio_aux.py')
    return lane, args


class FrozenExportConsumers(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.adapter = module('frozen_export_source_view', 'scripts/ci/default-historical-build-source/prepare.py')
        cls.temporary = tempfile.TemporaryDirectory(prefix='frozen-export-views-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.scratch = Path(cls.temporary.name)
        cls.views = {}
        for relative in CONFIGS:
            profile = Path(relative).parent.name
            view = cls.scratch / profile
            with patch('subprocess.Popen', side_effect=AssertionError('source view must not start actors')):
                cls.adapter.prepare(ROOT, view, profile)
            cls.views[relative] = view

    def selected(self, relative):
        return selection(relative, self.views[relative])

    def test_all_three_frozen_pin_closures_match_real_combined_source(self):
        self.assertEqual(hashlib.sha256((ROOT / EXPORTER).read_bytes()).hexdigest(), EXPORTER_SHA)
        for name in CONFIGS:
            value = json.loads((ROOT / name).read_bytes())
            self.assertEqual(value['code_pins'][EXPORTER], EXPORTER_SHA)
            for relative, expected in value['code_pins'].items():
                with self.subTest(config=name, source=relative):
                    self.assertEqual(hashlib.sha256((self.views[name] / relative).read_bytes()).hexdigest(), expected)

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
        lane, args = self.selected(relative)
        with patch('subprocess.Popen', side_effect=AssertionError('source selection must not start actors')):
            selected = lane.selected_api(args)
            self.assertEqual(Path(selected.driver.__file__), args.source_root / lane.NORMAL)
            self.assertIsNotNone(selected.normal)
            real_read = lane.read
            def drift(path, maximum=1024**2):
                raw = real_read(path, maximum)
                return raw + b'\n' if Path(path) == args.source_root / EXPORTER else raw
            with patch.object(lane, 'read', side_effect=drift):
                with self.assertRaisesRegex(ValueError, 'frozen source differs: scripts/release/export_repository.py'):
                    lane.selected_api(args)

    def test_precommit_real_selected_api_accepts_then_rejects_exporter_drift(self):
        self.accepted_then_drift(CONFIGS[1])

    def test_postcommit_real_selected_api_accepts_then_rejects_exporter_drift(self):
        self.accepted_then_drift(CONFIGS[2])

    def test_lane_configuration_byte_seals_refuse_before_api_import(self):
        for relative in CONFIGS[1:]:
            lane, args = self.selected(relative)
            real_read = lane.read
            def drift(path, maximum=1024**2):
                raw = real_read(path, maximum)
                return raw + b'\n' if Path(path) == args.lane_config else raw
            with self.subTest(lane=relative), patch.object(lane, 'read', side_effect=drift), \
                 patch.object(lane, 'load', side_effect=AssertionError('unsealed input reached API import')):
                with self.assertRaisesRegex(ValueError, 'lane configuration pin differs'):
                    lane.selected_api(args)

    def test_direct_evolved_root_selection_still_refuses(self):
        for relative in CONFIGS[1:]:
            lane, args = selection(relative, ROOT)
            # The mixed feature checkout carries the real enhanced helpers.
            config = json.loads(args.lane_config.read_bytes())
            self.assertNotEqual(hashlib.sha256((ROOT/'scripts/build/build.py').read_bytes()).hexdigest(),
                                config['code_pins']['scripts/build/build.py'])
            with self.subTest(config=relative), patch('subprocess.Popen', side_effect=AssertionError('no actors')):
                with self.assertRaisesRegex(ValueError, 'frozen source differs: scripts/build/build.py'):
                    lane.selected_api(args)

    def refusal_source(self, label):
        source = self.scratch / label
        shutil.copytree(self.views[CONFIGS[1]], source)
        for helper in ('build.py', 'compare.py'):
            target = source / self.adapter.SHARED / helper
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / self.adapter.SHARED / helper, target)
        return source

    def test_changed_shared_snapshot_refuses_before_view_creation(self):
        source = self.refusal_source('snapshot-drift')
        helper = source/self.adapter.SHARED/'build.py'
        helper.write_bytes(helper.read_bytes()+b'\n# changed snapshot\n')
        output = self.scratch/'snapshot-refused'
        with self.assertRaisesRegex(ValueError, 'fixed shared build snapshot differs'):
            self.adapter.prepare(source, output, 'full-root-failed-update')
        self.assertFalse(output.exists())

    def test_unrelated_frozen_exporter_drift_refuses_before_view_creation(self):
        source = self.refusal_source('exporter-drift')
        exporter = source/EXPORTER; exporter.write_bytes(exporter.read_bytes()+b'\n# changed exporter\n')
        output = self.scratch/'exporter-refused'
        with self.assertRaisesRegex(ValueError, 'historical source drift outside selected helpers: '+EXPORTER):
            self.adapter.prepare(source, output, 'full-root-failed-update')
        self.assertFalse(output.exists())

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
