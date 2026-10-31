import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('static_apt_trial', Path(__file__).with_name('static_apt_trial.py'))
trial = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trial)


class TrialControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.data = b'authenticated archive fixture'
        self.name = 'fixture_1_amd64.deb'
        self.rows = {self.name: {'size': len(self.data), 'sha256': hashlib.sha256(self.data).hexdigest()}}
        self.cold = dict(phase='cold', source='a' * 40, repository='owner/repo', ref='refs/heads/test', run_id='123', run_attempt='1', image='image1', os='Linux', arch='X64', plan_digest='b' * 64, helper_digest='c' * 64, runner_name='cold-runner', cache_hit='', archive_count=1, verified_before_install=0, packages_readback='fish\t3.7.0\n', packages_sha256='d' * 64)
        self.cold['key'] = trial.bind_key(self.cold)
        self.warm = dict(self.cold, phase='warm', runner_name='warm-runner', cache_hit='true', verified_before_install=1)

    def test_matching_pair_accepted(self):
        trial.compare_finished(self.cold, self.warm)

    def test_every_source_scope_image_plan_or_key_mismatch_refused(self):
        for field in trial.FIELDS:
            with self.subTest(field=field), self.assertRaises(ValueError):
                trial.compare_identity(self.cold, dict(self.warm, **{field: 'changed'}))

    def test_same_runner_not_cold_or_empty_predecessor_refused(self):
        for cold in (dict(self.cold, phase='warm'), dict(self.cold, cache_hit='true'), dict(self.cold, archive_count=0), dict(self.cold, verified_before_install=1), dict(self.cold, runner_name=self.warm['runner_name'])):
            with self.subTest(cold=cold), self.assertRaises(ValueError):
                trial.compare_identity(cold, self.warm)

    def test_cold_requires_no_restored_archives(self):
        self.assertEqual(trial.check_cache(self.cold, self.root, self.rows, ''), 0)
        (self.root / self.name).write_bytes(b'X' * len(self.data))
        with self.assertRaises(ValueError):
            trial.check_cache(self.cold, self.root, self.rows, 'false')

    def test_warm_miss_prefix_or_incomplete_cache_refused(self):
        (self.root / self.name).write_bytes(self.data)
        for hit in ('', 'false'):
            with self.subTest(hit=hit), self.assertRaises(ValueError):
                trial.check_cache(self.warm, self.root, self.rows, hit)
        self.assertEqual(trial.check_cache(self.warm, self.root, self.rows, 'true'), 1)
        (self.root / self.name).write_bytes(b'X' * len(self.data))
        with self.assertRaises(ValueError):
            trial.check_cache(self.warm, self.root, self.rows, 'true')
        with self.assertRaises(ValueError):
            trial.check_cache(self.warm, self.root, {}, 'true')

    def test_package_readback_mismatch_or_incomplete_warm_refused(self):
        for warm in (dict(self.warm, packages_readback='fish\tchanged\n'), dict(self.warm, packages_sha256='e' * 64), dict(self.warm, cache_hit='false'), dict(self.warm, verified_before_install=0)):
            with self.subTest(warm=warm), self.assertRaises(ValueError):
                trial.compare_finished(self.cold, warm)

    def test_measurement_namespace_separates_attempts_and_normal_cache(self):
        self.assertNotEqual(trial.bind_key(self.cold), trial.bind_key(dict(self.cold, phase='normal')))
        self.assertNotEqual(trial.bind_key(self.cold), trial.bind_key(dict(self.cold, run_attempt='2')))
        self.assertEqual(trial.bind_key(self.cold), trial.bind_key(self.warm))

    def invoke(self, mode, env, *args):
        def readback(command, **kwargs):
            return env['GITHUB_SHA'] if command[0] == 'git' else 'fish\t3.7.0\n'
        with patch.dict(os.environ, env, clear=True), patch.object(trial.sys, 'argv', ['trial', mode, *args]), patch.object(trial.subprocess, 'check_output', side_effect=readback), contextlib.redirect_stdout(io.StringIO()):
            trial.main()

    def execute_setup(self, phase, cold=None):
        root = self.root / phase
        root.mkdir()
        env = dict(RUNNER_TEMP=str(root), CAA_STATIC_PHASE=phase, CAA_COLD_RECEIPT=json.dumps(cold) if cold else '', GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_SHA='a' * 40, GITHUB_REPOSITORY='owner/repo', GITHUB_REF='refs/heads/test', GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1', ImageVersion='image1', RUNNER_OS='Linux', RUNNER_ARCH='X64', RUNNER_NAME=phase + '-runner', GITHUB_OUTPUT=str(root / 'output'), GITHUB_STEP_SUMMARY=str(root / 'summary'))
        self.invoke('begin', env)
        self.invoke('clock', env, 'plan_start_ns')
        (root / 'static-apt-uris').write_text(f"'https://mirror/fixture.deb' {self.name} {len(self.data)} SHA256:{self.rows[self.name]['sha256']}\n")
        self.invoke('clock', env, 'plan_end_ns')
        self.invoke('identity', env)
        if phase == 'warm':
            cache = root / 'static-apt-cache'
            cache.mkdir()
            (cache / self.name).write_bytes(self.data)
            env['CAA_CACHE_HIT'] = 'true'
        self.invoke('cache', env)
        self.invoke('clock', env, 'install_start_ns')
        self.invoke('clock', env, 'install_end_ns')
        self.invoke('finish', env)
        return json.loads((root / 'static-apt-setup-receipt.json').read_text()), env

    def test_complete_cold_warm_receipt_state_machine_without_apt_or_hosted_service(self):
        cold, _ = self.execute_setup('cold')
        warm, env = self.execute_setup('warm', cold)
        self.assertEqual(cold['key'], warm['key'])
        self.assertTrue(all(value >= 0 for value in warm['timing_ns'].values()))
        self.invoke('report', env)
        self.assertIn('PASS_ONE_HOSTED_SETUP_PAIR_AND_FULL_STATIC_SUITE', (self.root / 'warm/summary').read_text())

    def test_measurement_rejects_non_dispatch_and_missing_predecessor(self):
        env = dict(RUNNER_TEMP=str(self.root), CAA_STATIC_PHASE='cold', GITHUB_EVENT_NAME='pull_request')
        with self.assertRaises(ValueError):
            self.invoke('begin', env)
        with self.assertRaises(ValueError):
            self.execute_setup('warm')

    def test_normal_setup_needs_no_predecessor_or_cache_hit(self):
        receipt, _ = self.execute_setup('normal')
        self.assertEqual(receipt['phase'], 'normal')
        self.assertTrue(receipt['key'].startswith('static-apt-v1-'))


if __name__ == '__main__':
    unittest.main()
