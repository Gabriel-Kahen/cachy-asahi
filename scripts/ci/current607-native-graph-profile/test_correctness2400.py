"""Exact public-source emission and real isolated CLI, without native actors."""
import argparse, importlib.util, json, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', type=Path, required=True)
parser.add_argument('--expected', type=Path, required=True)
args, remaining = parser.parse_known_args()
SOURCE, EXPECTED = args.source.absolute(), args.expected.absolute()
spec = importlib.util.spec_from_file_location('_correctness_factory', HERE / 'prepare.py')
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)

class CorrectnessFactory(unittest.TestCase):
    def test_all_three_exact_outputs(self):
        _, _, expected563, _, _, _, final563, _ = F.inputs()
        _, expected566, _ = F.ancestry_inputs()
        _, expected568, _ = F.correctness_inputs()
        self.assertEqual(expected568, F.files(EXPECTED))
        with tempfile.TemporaryDirectory() as tmp:
            for index, (profile, expected) in enumerate([
                ('fresh_descriptor563', final563), ('fresh_ancestry566', expected566),
                ('correctness2400', expected568)]):
                out = Path(tmp) / str(index)
                result = F.emit(SOURCE, out, profile)
                self.assertEqual(F.files(out), expected)
                self.assertEqual(result['files'], expected)
                self.assertEqual(result['consumer_seconds'], 2400 if index == 2 else 1800)

    def test_actual_isolated_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            out, auth = Path(tmp) / 'source', Path(tmp) / 'authorization.json'
            result = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'prepare.py'),
                '--source', str(SOURCE), '--output', str(out), '--authorization', str(auth),
                '--profile', 'correctness2400'], capture_output=True, timeout=60, cwd='/tmp')
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = json.loads(auth.read_bytes())
            self.assertEqual(F.files(out), F.files(EXPECTED))
            self.assertEqual(receipt['original1800_fit'], 'FAILED_NOT_RECLASSIFIED')
            self.assertEqual(receipt['performance'], 'NOT_CLAIMED')

    def test_support_drift_refuses_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            copy = root / 'factory'
            shutil.copytree(HERE, copy)
            dependency = copy / 'correctness2400/budget_successor.py'
            dependency.write_bytes(dependency.read_bytes() + b'\n# drift\n')
            out = root / 'source'
            result = subprocess.run([sys.executable, '-I', '-B', str(copy / 'prepare.py'),
                '--source', str(SOURCE), '--output', str(out), '--authorization', str(root / 'auth'),
                '--profile', 'correctness2400'], capture_output=True, timeout=60)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'whole correctness support before output', result.stderr)
            self.assertFalse(out.exists())

if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *remaining])
