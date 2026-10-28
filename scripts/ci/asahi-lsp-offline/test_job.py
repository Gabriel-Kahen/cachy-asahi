"""Mocked job ownership/secret-scope checks; no Docker or native actors."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('offline_job', HERE / 'job.py')
job = importlib.util.module_from_spec(spec)
spec.loader.exec_module(job)


class JobTests(unittest.TestCase):
    def setUp(self):
        tmp = HERE.parents[3] / 'tmp'
        tmp.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=tmp)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'job'
        self.root.mkdir()
        self.args = SimpleNamespace(root=self.root, source=Path('/source'), product=Path('/product'),
                                    desktop=Path('/desktop'), source_commit='a' * 40, mode='cleanup')
        self.image = 'sha256:' + 'b' * 64
        self.api = SimpleNamespace(LOCK='lock-pin', INPUTS='inputs-pin', HELPER='helper-pin', cleanup=lambda *_: None)

    def fixture(self, **changes):
        state = {'source_commit': 'a' * 40, 'before_images': [], 'seed': 'PASS', 'build': 'PASS', 'trial': 'PASS'}
        state.update(changes)
        job.save(self.root / 'state.json', state)
        base = self.root / 'base'
        base.mkdir()
        (base / 'image-id').write_text(self.image)
        (base / 'installed-packages.lock').write_text('fixture')
        job.save(base / 'report.json', {'status': 'PASS_NATIVE_OFFLINE_574_TRANSACTION', 'image': self.image,
            'native_build': 'PASS', 'build_returncode': 0, 'failures': [], 'acquired': 1153})
        public = self.root / 'public'
        public.mkdir()
        job.save(public / 'result.json', {'status': 'PASS'})

    def test_normal_cleanup_removes_only_new_image_and_private_tree(self):
        self.fixture()
        with patch.object(job, 'caller', return_value=self.api), \
             patch.object(job, 'sha', return_value='lock-pin'), \
             patch.object(job, 'capture', side_effect=['', '']) as capture, \
             patch.object(job.subprocess, 'run') as run:
            self.assertEqual(job.cleanup(self.args, []), 0)
        self.assertEqual(run.call_args.args[0], ['docker', 'image', 'rm', '--no-prune', self.image])
        self.assertEqual(len(capture.call_args_list), 2)
        self.assertEqual(set(p.name for p in self.root.iterdir()), {'public'})
        result = json.loads((self.root / 'public/result.json').read_text())
        self.assertEqual(result['owner_cleanup']['bootstrap_retirement'], 'PASS-normal-completion')

    def test_preexisting_image_is_preserved_and_result_fails(self):
        self.fixture(before_images=[self.image])
        with patch.object(job, 'caller', return_value=self.api), patch.object(job, 'sha', return_value='lock-pin'), \
             patch.object(job, 'capture') as capture, patch.object(job.subprocess, 'run') as run:
            self.assertEqual(job.cleanup(self.args, []), 1)
        capture.assert_not_called()
        run.assert_not_called()
        self.assertTrue((self.root / 'base').exists())

    def test_interrupted_bootstrap_is_unknown_without_daemon_hunt(self):
        self.fixture(build='STARTED', trial='NOT STARTED')
        with patch.object(job, 'caller', return_value=self.api), patch.object(job, 'capture') as capture, \
             patch.object(job.subprocess, 'run') as run:
            self.assertEqual(job.cleanup(self.args, []), 1)
        report = json.loads((self.root / 'public/result.json').read_text())['owner_cleanup']
        self.assertEqual(report['bootstrap_retirement'], 'UNKNOWN')
        self.assertFalse(report['private_removed'])
        run.assert_not_called()
        capture.assert_not_called()

    def test_uncertain_trial_does_not_delete_a_live_controllers_private_inputs(self):
        self.fixture(trial='FAIL', failure={'phase': 'trial', 'kind': 'TimeoutExpired'})
        private = self.root / 'private'
        private.mkdir()
        (private / 'source.tar.gz').write_bytes(b'private')
        with patch.object(job, 'caller', return_value=self.api), patch.object(job, 'sha', return_value='lock-pin'), \
             patch.object(job, 'capture') as capture, patch.object(job.subprocess, 'run') as run:
            self.assertEqual(job.cleanup(self.args, []), 1)
        self.assertTrue((private / 'source.tar.gz').exists())
        capture.assert_not_called()
        run.assert_not_called()

    def test_seed_receives_only_exact_secret_names_and_clean_environment(self):
        job.save(self.root / 'state.json', {'seed': 'NOT STARTED', 'build': 'NOT STARTED', 'trial': 'NOT STARTED'})
        self.args.mode = 'seed'
        environment = {key: 'PRIVATE_SECRET_VALUE' for key in job.SECRET_NAMES}
        environment.update(GITHUB_TOKEN='MUST_NOT_INHERIT', UNRELATED='MUST_NOT_INHERIT')
        with patch.dict(job.os.environ, environment, clear=True), patch.object(job, 'command') as command:
            job.phase(self.args)
        env = command.call_args.args[2]
        self.assertEqual(len(job.SECRET_NAMES), 22)
        self.assertNotIn('GITHUB_TOKEN', env)
        self.assertNotIn('UNRELATED', env)
        self.assertEqual(set(env), set(job.ENV) | {'HOME', 'TMPDIR', 'CACHY_OLD_FOUR_SCHEMA',
                                                   'CACHY_OLD_FOUR_SOURCE_EPOCH'} | set(job.SECRET_NAMES))
        self.assertNotIn('PRIVATE_SECRET_VALUE', (self.root / 'state.json').read_text())

    def test_trial_uses_only_new_caller_one_fixed_timeout_and_no_secrets(self):
        job.save(self.root / 'state.json', {'seed': 'PASS', 'build': 'PASS', 'trial': 'NOT STARTED'})
        self.args.mode = 'trial'
        with patch.dict(job.os.environ, {key: 'PRIVATE_SECRET' for key in job.SECRET_NAMES}, clear=True), \
             patch.object(job, 'command') as command:
            job.phase(self.args)
        argv, _, env, limit = command.call_args.args
        self.assertEqual(argv[3], HERE / 'run.py')
        self.assertEqual(limit, 3500)
        self.assertFalse(set(job.SECRET_NAMES) & set(env))
        self.assertEqual(len(command.call_args_list), 1)


if __name__ == '__main__':
    unittest.main()
