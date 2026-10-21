"""Exercise exact public inputs, isolated CLI, and before-output refusal boundaries."""
import argparse, importlib.util, json, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--original-source', type=Path, required=True)
parser.add_argument('--setup-source', type=Path, required=True)
parser.add_argument('--expected', type=Path, required=True)
args, rest = parser.parse_known_args()
OLD, SETUP, EXPECTED = map(lambda p: p.absolute(), (args.original_source, args.setup_source, args.expected))
spec = importlib.util.spec_from_file_location('_setup606_factory', HERE / 'prepare.py')
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)

def cli(factory, original, out, auth):
    return subprocess.run([sys.executable, '-I', '-B', str(factory / 'prepare.py'),
        '--original-source', str(original), '--setup-source', str(SETUP),
        '--output', str(out), '--authorization', str(auth)], capture_output=True, timeout=60, cwd='/tmp')

class Factory(unittest.TestCase):
    def test_exact608_and_unchanged_inputs(self):
        before = F.files(OLD), F.files(SETUP)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'source'
            value = F.emit(OLD, SETUP, out)
            self.assertEqual(value['files'], F.files(EXPECTED))
            self.assertEqual(F.files(out), F.files(EXPECTED))
        self.assertEqual((F.files(OLD), F.files(SETUP)), before)

    def test_actual_isolated_cli_and_source_preflight(self):
        with tempfile.TemporaryDirectory() as tmp:
            out, auth = Path(tmp) / 'source', Path(tmp) / 'auth.json'
            result = cli(HERE, OLD, out, auth)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(json.loads(auth.read_bytes())['files']), 608)
            result = subprocess.run([sys.executable, '-I', '-B', str(out / 'scripts/ci/current606-doctor2-closed-owner/owner.py'),
                '--source-preflight'], capture_output=True, timeout=60, cwd='/tmp')
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_changed_original_refuses_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = root / 'original'
            shutil.copytree(OLD, original)
            (original / 'LICENSE').write_bytes(b'drift')
            out = root / 'output'
            with self.assertRaisesRegex(ValueError, 'whole immutable353 and240'):
                F.emit(original, SETUP, out)
            self.assertFalse(out.exists())

    def test_existing_output_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / 'output'
            out.mkdir()
            (out / 'sentinel').write_bytes(b'keep')
            with self.assertRaisesRegex(ValueError, 'fresh disjoint output'):
                F.emit(OLD, SETUP, out)
            self.assertEqual((out / 'sentinel').read_bytes(), b'keep')

    def test_payload_drift_refuses_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            factory = root / 'factory'
            shutil.copytree(HERE, factory)
            payload = next(p for p in (factory / 'payload').rglob('*') if p.is_file())
            payload.write_bytes(payload.read_bytes() + b'\n# drift\n')
            out, auth = root / 'output', root / 'auth'
            result = cli(factory, OLD, out, auth)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'whole readable payload before output', result.stderr)
            self.assertFalse(out.exists())
            self.assertFalse(auth.exists())

if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *rest])
