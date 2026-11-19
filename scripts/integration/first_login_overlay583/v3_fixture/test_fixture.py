"""Exercise the seed and executable poison without signing or booting a guest."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


I, P = load('isolation'), load('project')


class FixtureTests(unittest.TestCase):
    def test_seed_denies_noexec_and_poison_really_runs(self):
        def local(label, argv, cwd):
            self.assertEqual(label, I.LABEL + 'seed')
            self.assertEqual(argv[0], '/usr/bin/runuser')
            command = argv[argv.index(I.PYTHON):]
            return subprocess.run(command, cwd=cwd, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'},
                                  capture_output=True, check=True, timeout=5).stdout

        with tempfile.TemporaryDirectory(prefix='overlay583-isolation-') as temporary:
            root = Path(temporary)
            blocked = root / 'noexec model'
            blocked.mkdir()
            with patch.object(I.os, 'access', return_value=False):
                with self.assertRaisesRegex(I.IsolationRefusal, 'POISON_EXECUTION_ACCESS_REFUSED'):
                    I.seed(blocked, 'local test user', local)
            self.assertEqual(I.configs(blocked), I.PREEXISTING)
            executable = root / 'exec fixture'
            executable.mkdir()
            self.assertEqual(I.seed(executable, 'local test user', local), I.pins(I.PREEXISTING))
            result = subprocess.run([str(I.check_poison(executable) / 'python3')],
                                    capture_output=True, check=False, timeout=5)
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (97, b'', b'unexpected ambient interpreter\n'))

    def test_scope_owned_path_and_frozen_followup(self):
        nonce = 'a' * 32
        home = I.fixture_home(nonce)
        self.assertEqual(home.parent.parent, Path('/var/tmp'))
        self.assertIn(nonce, home.parent.name)
        self.assertNotEqual(home, I.fixture_home('b' * 32))
        with self.assertRaisesRegex(I.IsolationRefusal, 'FIXTURE_NONCE_REFUSED'):
            I.fixture_home('../foreign')
        preview = I.isolated_argv(home, False)
        self.assertEqual(preview[:3], ['/usr/bin/python3', '-I', '-B'])
        self.assertEqual(preview[preview.index('--home') + 1], str(home))
        self.assertEqual(I.isolated_argv(home, True), preview + ['--apply'])

    def test_source_drift_refuses_before_output(self):
        with tempfile.TemporaryDirectory(prefix='overlay583-projection-') as temporary:
            root = Path(temporary)
            source, handoff, reader, output = (root / leaf for leaf in ('source', 'handoff', 'reader', 'output'))
            expected = {name: P.pin(b'original body') for name in P.FIXED}
            for name in P.FIXED:
                leaf = source / name
                leaf.parent.mkdir(parents=True, exist_ok=True)
                leaf.write_bytes(b'changed body')
            raw = json.dumps(dict(kind=P.BEFORE, source=expected)).encode()
            handoff.write_bytes(raw)
            reader.write_bytes(b'exact reader fixture')
            with self.assertRaisesRegex(ValueError, 'v3 worker source changed'):
                P.stage(source, handoff, P.pin(raw)['sha256'], reader, P.pin(reader.read_bytes())['sha256'], output)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
