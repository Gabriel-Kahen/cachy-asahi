# SPDX-License-Identifier: MIT
from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import common
import stage


class StageDataTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'public').mkdir(); (self.root / 'private').mkdir()
        self.report = {'status': 'PASS', 'phase': 'complete', 'cancelled': False, 'source_commit': 'a' * 40,
            'native_kernel_compilation': 'PASS', 'kernel_execution': 'NOT RUN', 'hardware_validation': 'NOT RUN',
            'performance': 'NOT MEASURED', 'cleanup': {'status': 'PASS'}}

    def test_finish_has_explicit_public_allowlist_no_private_data(self):
        self.report['unaccepted_binary'] = 'private ELF path'
        stage.finish(self.root, self.report)
        public = json.loads((self.root / 'public/status.json').read_text())
        self.assertNotIn('unaccepted_binary', public)
        self.assertEqual(public['hardware_validation'], 'NOT RUN')

    def test_late_cancel_with_failure_export_error_cannot_retain_pass(self):
        @contextmanager
        def deferred(): yield [15]
        actual = common.save; calls = []
        def save(path, value):
            calls.append(path)
            if len(calls) == 3: raise OSError('injected failure rewrite error')
            actual(path, value)
        with patch.object(stage, 'defer_signals', deferred), patch.object(stage, 'save', side_effect=save):
            with self.assertRaises(OSError): stage.finish(self.root, self.report)
        self.assertFalse((self.root / 'public/status.json').exists())
        self.assertFalse((self.root / 'private/result.json').exists())
        self.assertEqual((self.report['status'], self.report['cancelled']), ('FAIL', True))

    def test_late_cancel_retains_authoritative_failure_receipts(self):
        @contextmanager
        def deferred(): yield [15]
        with patch.object(stage, 'defer_signals', deferred):
            with self.assertRaises(stage.Cancelled): stage.finish(self.root, self.report)
        for name in ('public/status.json', 'private/result.json'):
            receipt = json.loads((self.root / name).read_text())
            self.assertEqual((receipt['status'], receipt['cancelled']), ('FAIL', True))

    def test_config_metadata_delta_and_exact_new_lint_probe_only(self):
        policy = {'version_symbols': ['CONFIG_RUSTC_VERSION']}
        result = common.delta_config({'CONFIG_ARM64_16K_PAGES': 'y', 'CONFIG_RUSTC_VERSION': '109301'},
            {'CONFIG_ARM64_16K_PAGES': 'y', 'CONFIG_RUSTC_VERSION': '109900',
             'CONFIG_RUSTC_HAS_SUSPICIOUS_RUNTIME_SYMBOL_DEFINITIONS': 'y'}, policy)
        self.assertEqual(len(result), 2)
        with self.assertRaises(ValueError): common.delta_config({'CONFIG_HZ': '1000'}, {'CONFIG_HZ': '250'}, policy)
        with self.assertRaises(ValueError): common.delta_config({}, {'CONFIG_RUSTC_HAS_SUSPICIOUS_RUNTIME_SYMBOL_DEFINITIONS': 'n'}, policy)

    def test_json_pin_authenticates_captured_bytes(self):
        path = self.root / 'receipt.json'; common.save(path, {'status': 'UNREVIEWED'})
        pin = common.digest(path)
        with patch.object(common, 'digest', side_effect=AssertionError('second-path-read not allowed')):
            self.assertEqual(common.load(path, pin)['status'], 'UNREVIEWED')
        path.write_text('{"status":"REVIEWED"}')
        with self.assertRaises(ValueError): common.load(path, pin)

    def test_non_native_stage_rejected_before_outputs(self):
        with patch.object(stage.platform, 'machine', return_value='x86_64'):
            with self.assertRaises(ValueError): stage.ordinary()

    def test_isolated_cli_can_load_owned_helpers(self):
        result = subprocess.run([sys.executable, '-I', '-B', stage.__file__, '--help'], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'--accepted-result-sha256', result.stdout)

    def test_snapshot_failure_remains_authoritative_fail(self):
        base = self.root / 'artifacts/kernel-native-stage'; base.mkdir(parents=True)
        args = SimpleNamespace(root=self.root, output=base / 'failed-new', source_commit='a' * 40,
                               lock=self.root / 'lock', lock_sha256='b' * 64)
        lock = {'purpose': 'KERNEL-NATIVE-C01', 'base_inventory_sha256': stage.BASE_SHA}
        with (patch.object(stage, 'ordinary'), patch.object(stage, 'load', return_value=lock),
              patch.object(stage.shutil, 'disk_usage', return_value=SimpleNamespace(free=8 * 1024**3)),
              patch.dict(stage.os.environ, {'GITHUB_SHA': args.source_commit}),
              patch.object(stage, 'snapshot', side_effect=ValueError('injected source mismatch'))):
            self.assertEqual(stage.execute(args), 1)
        public = json.loads((args.output / 'public/status.json').read_text())
        self.assertEqual((public['status'], public['native_kernel_compilation']), ('FAIL', 'NOT RUN'))
        self.assertEqual(public['cleanup']['status'], 'FAIL')
        private = json.loads((args.output / 'private/result.json').read_text())
        self.assertEqual(private['error_type'], 'ValueError')


if __name__ == '__main__':
    unittest.main()
