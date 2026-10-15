"""Focused host-boundary/cleanup tests; no Docker, package or network actors."""
import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('runtime_trial', Path(__file__).with_name('run-native.py'))
trial = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trial)


class RuntimeTrialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'trial'
        self.root.mkdir()

    def owned(self):
        raw = self.root / 'private'
        (raw / 'native/gpg').mkdir(parents=True)
        (self.root / 'cache').mkdir()
        image = 'sha256:' + 'b' * 64
        (raw / 'native/image-id').write_text(image)
        name = 'cachy-asahi-updater-runtime-' + 'a' * 32
        (self.root / 'owned.json').write_text(json.dumps({'container': name}))
        return raw, image, name

    def test_cleanup_removes_only_named_trial_resources_and_verifies_absence(self):
        raw, image, name = self.owned()
        foreign = Path(self.temp.name) / 'foreign'
        foreign.write_text('preserved')
        state = {'container': True, 'image': True}
        commands = []
        def query(argv):
            commands.append(argv)
            if argv[:3] == ['docker', 'container', 'ls']:
                self.assertIn('name=^/' + name + '$', argv)
                return (name + '\n').encode() if state['container'] else b''
            if argv[:3] == ['docker', 'rm', '-f']:
                self.assertEqual(argv[3], name)
                state['container'] = False
                return name.encode()
            if argv[:3] == ['docker', 'image', 'ls']:
                return (image + '\n').encode() if state['image'] else b''
            self.assertEqual(argv, ['docker', 'image', 'rm', '--no-prune', image])
            state['image'] = False
            return image.encode()
        with patch.object(trial, 'query', side_effect=query), patch.object(trial.subprocess, 'run') as gpg:
            result = trial.cleanup(self.root)
        self.assertEqual(result['status'], 'PASS')
        self.assertTrue(result['private_data_removed'])
        self.assertFalse(raw.exists())
        self.assertEqual(foreign.read_text(), 'preserved')
        self.assertEqual(len(commands), 6)
        gpg.assert_called_once()

    def test_failed_daemon_query_never_proves_image_absence_or_private_cleanup(self):
        raw, _, _ = self.owned()
        with patch.object(trial, 'query', side_effect=ValueError('daemon unavailable')), \
                patch.object(trial.subprocess, 'run'):
            result = trial.cleanup(self.root)
        self.assertEqual(result['status'], 'FAIL')
        self.assertFalse(result['private_data_removed'])
        self.assertTrue(raw.exists())
        self.assertTrue((self.root / 'cache').exists())

    def test_command_timeout_signals_owned_group_and_preserves_original_error(self):
        failure = subprocess.TimeoutExpired(['fixture'], 1)
        process = Mock(pid=12345)
        process.wait.side_effect = [failure, 0]
        with patch.object(trial.subprocess, 'Popen', return_value=process) as spawn, \
                patch.object(trial.os, 'killpg') as kill, self.assertRaises(subprocess.TimeoutExpired) as raised:
            trial.command(['fixture'], self.root / 'command.log', 1)
        self.assertIs(raised.exception, failure)
        self.assertTrue(spawn.call_args.kwargs['start_new_session'])
        kill.assert_called_once_with(12345, signal.SIGTERM)

    def test_nonzero_command_cannot_be_reported_successful(self):
        process = Mock()
        process.wait.return_value = 4
        with patch.object(trial.subprocess, 'Popen', return_value=process), \
                self.assertRaisesRegex(ValueError, 'command failed: package'):
            trial.command(['fixture'], self.root / 'package.log', 1)

    def test_explicit_source_commit_must_be_full_and_equal_checkout(self):
        source = self.root / 'source'
        source.mkdir()
        for commit in ('not-a-commit', 'a' * 40):
            with self.subTest(commit=commit), \
                    patch.object(trial.sys, 'argv', ['run-native.py', '--source', str(source),
                                                   '--output', str(self.root), '--source-commit', commit]), \
                    patch.object(trial.platform, 'machine', return_value='aarch64'), \
                    patch.object(trial.os, 'getuid', return_value=1000), \
                    patch.dict(trial.os.environ, {}, clear=True), \
                    patch.object(trial.subprocess, 'check_output', return_value='b' * 40) as checkout, \
                    patch.object(trial, 'trial') as actor, \
                    self.assertRaisesRegex(ValueError, 'exact reviewed product checkout'):
                trial.main()
            actor.assert_not_called()
            self.assertEqual(checkout.call_count, int(len(commit) == 40))

    def test_inside_entry_refuses_nonroot_before_any_command_or_private_write(self):
        spec = importlib.util.spec_from_file_location('runtime_inside', Path(__file__).with_name('inside.py'))
        inside = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(inside)
        with patch.object(inside.platform, 'machine', return_value='aarch64'), \
                patch.object(inside.os, 'getuid', return_value=1000), \
                patch.object(inside.subprocess, 'run') as actor, \
                patch.object(inside.tempfile, 'mkdtemp') as private, \
                self.assertRaisesRegex(ValueError, 'explicit disposable'):
            inside.main()
        actor.assert_not_called()
        private.assert_not_called()


if __name__ == '__main__':
    unittest.main()
