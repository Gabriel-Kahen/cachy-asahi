"""Mocked orchestration and owned cleanup; no Docker, downloads or source builds."""
import hashlib
import json
from pathlib import Path
import tempfile
import signal
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import native_trial as trial


class NativeTrialTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.args = SimpleNamespace(output=self.root / 'output', cache=self.root / 'cache', source_commit='a' * 40)
        self.args.cache.mkdir()
        self.addCleanup(patch.stopall)
        patch.object(trial.native, 'run', side_effect=AssertionError('no real command')).start()
        patch.object(trial.native.subprocess, 'run', side_effect=AssertionError('no real subprocess')).start()

    def test_non_native_and_docker_overrides_refuse_before_commands_or_output(self):
        with patch.object(trial.platform, 'machine', return_value='x86_64'), self.assertRaises(ValueError):
            trial.preflight(self.args)
        with patch.object(trial.platform, 'machine', return_value='aarch64'), \
             patch.object(trial.os, 'getuid', return_value=1000), patch.object(trial.os, 'geteuid', return_value=1000), \
             patch.dict(trial.os.environ, {'DOCKER_CONTEXT': 'remote'}), self.assertRaisesRegex(ValueError, 'overrides'):
            trial.preflight(self.args)
        self.assertFalse(self.args.output.exists())

    def test_branch_name_refuses_before_checkout_or_docker(self):
        self.args.source_commit = 'main'
        with patch.object(trial.platform, 'machine', return_value='aarch64'), \
             patch.object(trial.os, 'getuid', return_value=1000), patch.object(trial.os, 'geteuid', return_value=1000), \
             patch.dict(trial.os.environ, {}, clear=True), self.assertRaisesRegex(ValueError, 'exact product'):
            trial.preflight(self.args)

    def owned(self):
        (self.root / 'trial/inputs').mkdir(parents=True)
        (self.root / 'trial/inputs/contract.json').write_text(json.dumps({'nonce': 'b' * 32}))
        (self.root / 'native').mkdir()
        (self.root / 'native/image-id').write_text('sha256:' + 'c' * 64)

    def test_container_query_failure_still_attempts_owned_image_removal(self):
        self.owned(); calls = []
        def run(argv, **kwargs):
            calls.append(argv)
            if 'container' in argv:
                raise ValueError('fixture query failure')
            return ''
        with patch.object(trial.native, 'run', side_effect=run):
            result = trial.cleanup(self.root, ['docker', '--host=unix:///var/run/docker.sock'])
        self.assertEqual(result['status'], 'FAIL')
        self.assertTrue(result['image']['absence_verified'])
        self.assertIn(['docker', '--host=unix:///var/run/docker.sock', 'image', 'rm', '--no-prune', 'sha256:' + 'c' * 64], calls)

    def test_container_and_image_absence_are_checked_and_remaining_image_fails(self):
        self.owned()
        for remains in (False, True):
            def run(argv, **kwargs):
                return 'sha256:' + 'c' * 64 if remains and argv[2:4] == ['image', 'ls'] else ''
            with self.subTest(remains=remains), patch.object(trial.native, 'run', side_effect=run):
                result = trial.cleanup(self.root, ['docker', '--host=unix:///run/docker.sock'])
            self.assertEqual(result['status'], 'FAIL' if remains else 'PASS')
            self.assertTrue(result['container']['absence_verified'])

    def test_started_bootstrap_without_image_id_is_uncertain_failure(self):
        result = trial.cleanup(self.root, ['docker'], bootstrap_started=True)
        self.assertEqual((result['status'], result['image']['status']), ('FAIL', 'UNKNOWN'))
        self.assertFalse(result['image']['absence_verified'])

    def orchestration(self, trial_code=0, cleanup_status='PASS', build_error=None, export_error=None, late_signal=False):
        source = self.root / 'source.tar.gz'; source.write_bytes(b'inert source fixture')
        packages = b'fixture-base 1\n'
        def build(inputs, cache, output, recipes):
            self.assertEqual(recipes, {}, 'unrelated package recipes must not be built')
            if build_error:
                raise build_error
            (output / 'packages.lock').write_bytes(packages)
            (output / 'image-id').write_text('sha256:' + 'c' * 64)
            return 'sha256:' + 'c' * 64
        def host(args):
            args.output.mkdir(); (args.output / 'inputs').mkdir()
            (args.output / 'inputs/contract.json').write_text('{}')
            return trial_code
        handlers = {}
        real_save = trial.native.save
        def remember(sig, handler):
            old = handlers.get(sig); handlers[sig] = handler; return old
        def save(path, value):
            real_save(path, value)
            if late_signal and path == self.args.output / 'summary/result.json' and value['status'] == 'PASS':
                handlers[signal.SIGTERM](signal.SIGTERM, None)
        with patch.object(trial.signal, 'signal', side_effect=remember), \
             patch.object(trial.native, 'save', side_effect=save), \
             patch.object(trial, 'preflight', return_value={}), \
             patch.object(trial, 'PACKAGES_SHA', hashlib.sha256(packages).hexdigest()), \
             patch.object(trial.native, 'probe', return_value={'docker_endpoint': 'unix:///var/run/docker.sock'}), \
             patch.object(trial.native, 'audit'), patch.object(trial.native, 'build', side_effect=build), \
             patch.object(trial.native, 'fetch', return_value=source), \
             patch.object(trial.arm, 'host', side_effect=host), \
             patch.object(trial.arm, 'verify_result', return_value={'receiver_verification': {}, 'reproducibility': {'baseline': 'PASS', 'lto': 'PASS'}}), \
             patch.object(trial.stage, 'export_artifacts', side_effect=export_error) as export, \
             patch.object(trial.stage, 'project_evidence'), \
             patch.object(trial, 'cleanup', return_value={'status': cleanup_status}) as cleanup:
            code = trial.run(self.args)
        cleanup.assert_called_once()
        return code, json.loads((self.args.output / 'summary/result.json').read_text()), export

    def test_signal_during_final_summary_save_replaces_pass_with_failure(self):
        code, result, _ = self.orchestration(late_signal=True)
        self.assertEqual((code, result['status'], result['cancelled']), (1, 'FAIL', True))

    def test_cleanup_failure_overrides_otherwise_passing_trial(self):
        code, result, export = self.orchestration(cleanup_status='FAIL')
        self.assertEqual((code, result['status']), (1, 'FAIL'))
        export.assert_called_once()

    def test_failed_trial_does_not_export_unverified_artifacts(self):
        code, result, export = self.orchestration(trial_code=1)
        self.assertEqual((code, result['status']), (1, 'FAIL'))
        export.assert_not_called()

    def test_bootstrap_cancellation_still_cleans_up_and_retains_failure(self):
        code, result, export = self.orchestration(build_error=KeyboardInterrupt())
        self.assertEqual((code, result['status'], result['cancelled']), (1, 'FAIL', True))
        export.assert_not_called()

    def test_artifact_export_failure_cannot_publish_success(self):
        code, result, _ = self.orchestration(export_error=ValueError('fixture artifact mismatch'))
        self.assertEqual((code, result['status']), (1, 'FAIL'))

    def test_complete_mocked_trial_keeps_hardware_and_performance_unaccepted(self):
        code, result, export = self.orchestration()
        self.assertEqual((code, result['status']), (0, 'PASS'))
        self.assertEqual((result['hardware_validation'], result['performance_acceptance']), ('NOT RUN', 'NOT RUN'))
        self.assertFalse(result['selected_for_release'])
        export.assert_called_once()


if __name__ == '__main__':
    unittest.main()
