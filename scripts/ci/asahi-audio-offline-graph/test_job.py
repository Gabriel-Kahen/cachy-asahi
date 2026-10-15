"""Inert tests for the narrow adapter around the hash-held job owner."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
ROOT = next(p for p in HERE.parents if (p / 'scripts/ci/asahi-lsp-offline/job.py').is_file())
spec = importlib.util.spec_from_file_location('graph_job_test', HERE / 'job.py')
job = importlib.util.module_from_spec(spec); spec.loader.exec_module(job)
TMP = HERE / 'tmp'; TMP.mkdir(exist_ok=True)


class JobTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=TMP); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'job'; self.root.mkdir()
        self.args = SimpleNamespace(root=self.root, source=HERE.parents[2], product=Path('/product'),
                                    desktop=Path('/desktop'), source_commit='a' * 40, mode='trial')
        self.owner = job.s.held('job', ROOT / 'scripts/ci/asahi-lsp-offline')
        # Load a new module per test because bind intentionally replaces only its callbacks.
        self.owner = job.s.load('graph_owner_fixture', ROOT / 'scripts/ci/asahi-lsp-offline/job.py', job.s.HELD_PINS['job'])
        self.owner.command = Mock()
        self.original_phase = self.owner.phase
        job.s.save(self.root / 'state.json', {'seed': 'PASS', 'build': 'PASS', 'trial': 'NOT STARTED'})

    def state(self): return json.loads((self.root / 'state.json').read_text())

    def test_seed_and_base_dispatch_use_the_original_owner(self):
        seen = []; old = Mock(side_effect=lambda args: seen.append(args.mode)); self.owner.phase = old
        owner = job.bind(self.owner)
        for mode in ('seed', 'build'):
            self.args.mode = mode; owner.phase(self.args)
        self.assertEqual(seen, ['seed', 'build'])
        self.assertEqual(old.call_count, 2)
        self.owner.command.assert_not_called()

    def test_retrieval_receives_only_its_token_and_clean_environment(self):
        pins = job.s.inputs(); owner = job.bind(self.owner, retrieval=True)
        captured = []; owner.command.side_effect = lambda argv, log, env, limit: captured.append(dict(env))
        with patch.dict(os.environ, {'GH_TOKEN': 'PRIVATE_TOKEN', 'UNRELATED': 'NO',
                                     'CACHY_OLD_FOUR_JBIGKIT_01': 'SEED_MUST_NOT_LEAK'}, clear=True), \
             patch.object(job.s, 'sha', return_value=pins['retrieval_sha256']):
            owner.phase(self.args)
            self.assertNotIn('GH_TOKEN', os.environ)
        argv, log, env, limit = owner.command.call_args.args
        self.assertEqual(captured[0]['GH_TOKEN'], 'PRIVATE_TOKEN')
        self.assertEqual(limit, 650); self.assertEqual(argv[-1], self.root / 'incoming/audio-archives')
        # The token is removed from the captured dictionary after command retirement.
        self.assertNotIn('GH_TOKEN', env); self.assertNotIn('UNRELATED', env)
        self.assertNotIn('CACHY_OLD_FOUR_JBIGKIT_01', env)
        self.assertEqual(env['RUNNER_TEMP'], str(self.root / 'incoming'))
        self.assertEqual(self.state()['retrieval'], 'PASS'); self.assertEqual(self.state()['trial'], 'NOT STARTED')
        self.assertNotIn('PRIVATE_TOKEN', (self.root / 'state.json').read_text())

    def test_unreviewed_or_changed_retrieval_pin_blocks_before_any_child(self):
        for change in ('pending', 'hash'):
            with self.subTest(change=change):
                owner = job.s.load('graph_owner_block_' + change, ROOT / 'scripts/ci/asahi-lsp-offline/job.py')
                owner.command = Mock(); job.bind(owner, retrieval=True)
                pins = job.s.inputs()
                if change == 'pending': pins['retrieval_status'] = 'PENDING_ROOT_INTEGRATION'
                with patch.object(job.s, 'inputs', return_value=pins), \
                     patch.object(job.s, 'sha', return_value='0' * 64), patch.dict(os.environ, GH_TOKEN='TOKEN'):
                    with self.assertRaises(ValueError): owner.phase(self.args)
                owner.command.assert_not_called(); self.assertEqual(self.state()['trial'], 'NOT STARTED')
                self.assertEqual(self.state()['retrieval'], 'BLOCKED-ROOT-PIN-OR-TOKEN')

    def test_graph_trial_has_no_token_or_seed_secrets_and_no_build_argument(self):
        state = self.state(); state['retrieval'] = 'PASS'; job.s.save(self.root / 'state.json', state)
        owner = job.bind(self.owner)
        with patch.dict(os.environ, GH_TOKEN='NO_TOKEN_IN_RUNTIME', CACHY_OLD_FOUR_JBIGKIT_01='NO_SEED'):
            owner.phase(self.args)
        argv, _, env, limit = owner.command.call_args.args
        self.assertEqual(limit, 550); self.assertEqual(argv[3], HERE / 'run.py')
        self.assertNotIn('GH_TOKEN', env); self.assertNotIn('CACHY_OLD_FOUR_JBIGKIT_01', env)
        self.assertNotIn('build.py', str(argv)); self.assertNotIn('compare.py', str(argv))
        self.assertEqual(self.state()['trial'], 'PASS')

    def test_interrupted_retrieval_uses_existing_uncertain_trial_preservation(self):
        owner = job.bind(self.owner, retrieval=True); owner.command.side_effect = KeyboardInterrupt()
        pins = job.s.inputs()
        with patch.object(job.s, 'sha', return_value=pins['retrieval_sha256']), patch.dict(os.environ, GH_TOKEN='TOKEN'):
            with self.assertRaises(KeyboardInterrupt): owner.phase(self.args)
        state = self.state(); self.assertEqual(state['trial'], 'FAIL')
        self.assertEqual(state['failure'], {'phase': 'trial', 'kind': 'KeyboardInterrupt'})
        (self.root / 'private').mkdir(); (self.root / 'private/retained').write_bytes(b'owned')
        # Exercise the retained owner cleanup; no daemon queries permitted here.
        with patch.object(owner, 'caller', return_value=SimpleNamespace()), patch.object(owner, 'capture') as capture:
            self.assertEqual(owner.cleanup(self.args, []), 1)
        capture.assert_not_called(); self.assertTrue((self.root / 'private/retained').exists())
        report = json.loads((self.root / 'public/result.json').read_text())
        self.assertEqual(report['owner_cleanup']['trial_controller_retirement'], 'UNKNOWN')
        self.assertEqual(report['scope'], 'PRIVATE-ASAHI-AUDIO-GRAPH-LOADABILITY')

    def test_late_signal_during_added_cleanup_metadata_cannot_leave_pass(self):
        public = self.root / 'public'; public.mkdir()
        job.s.save(public / 'result.json', {'status': 'PASS'})
        self.owner.cleanup = lambda args, interrupted: 0
        owner = job.bind(self.owner)
        interrupted = []; original = job.s.save; injected = False
        def save(path, value):
            nonlocal injected
            original(path, value)
            if path.name == 'result.json' and not injected:
                injected = True; interrupted.append(15)
        with patch.object(job.s, 'save', side_effect=save): self.assertEqual(owner.cleanup(self.args, interrupted), 1)
        value = json.loads((public / 'result.json').read_text())
        self.assertEqual(value['status'], 'FAIL'); self.assertTrue(value['cancelled'])

    def test_successful_trial_cannot_be_repeated(self):
        state = self.state(); state.update(trial='PASS', retrieval='PASS'); job.s.save(self.root / 'state.json', state)
        owner = job.bind(self.owner)
        with self.assertRaises(ValueError): owner.phase(self.args)
        owner.command.assert_not_called()


if __name__ == '__main__': unittest.main()
