"""Exercise exact public inputs, isolated CLI, and before-output refusal boundaries."""
import argparse, importlib.util, json, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--original-source', type=Path, required=True)
parser.add_argument('--setup-source', type=Path, required=True)
parser.add_argument('--expected', type=Path, required=True)
parser.add_argument('--real-expected', type=Path, required=True)
args, rest = parser.parse_known_args()
OLD, SETUP, EXPECTED = map(lambda p: p.absolute(), (args.original_source, args.setup_source, args.expected))
spec = importlib.util.spec_from_file_location('_setup606_factory', HERE / 'prepare.py')
REAL_EXPECTED = args.real_expected.absolute()
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)

def cli(factory, original, out, auth, mode='copied-root'):
    return subprocess.run([sys.executable, '-I', '-B', str(factory / 'prepare.py'),
        '--original-source', str(original), '--setup-source', str(SETUP),
        '--output', str(out), '--authorization', str(auth), '--mode', mode], capture_output=True, timeout=60, cwd='/tmp')

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

    def test_real636_exact_input_isolated_cli_and_source_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out, auth = root / 'source', root / 'auth.json'
            result = cli(HERE, OLD, out, auth, 'real-modules')
            self.assertEqual(result.returncode, 0, result.stderr)
            value = json.loads(auth.read_bytes())
            self.assertEqual(value['files'], F.files(REAL_EXPECTED))
            self.assertEqual(F.files(out), F.files(REAL_EXPECTED))
            self.assertEqual(len(value['files']), 636)
            self.assertEqual(value['full606_real_shell'], 'NOT_RUN_BY_FACTORY_REAL_DOCKER_PROFILE')
            for entry, argument in (('run.py', '--source-preflight'), ('test_source.py', None)):
                cmd = [sys.executable, '-I', '-B', '-Werror', str(out / 'real606' / entry)]
                if argument is not None:
                    cmd.append(argument)
                result = subprocess.run(cmd, cwd='/tmp', capture_output=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_both_profiles_have_matching_source_owned_transport_context(self):
        import os
        for mode in ('copied-root', 'real-modules'):
            with tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / 'source'
                F.emit(OLD, SETUP, out, mode)
                policy = json.loads((out / 'scripts/ci/native-evidence-transport/doctor-policy.json').read_bytes())
                name = (out / '.github/workflows/native-arm-build.yml').read_text().splitlines()[0].removeprefix('name: ')
                spec = importlib.util.spec_from_file_location('_real_transport', out / 'scripts/ci/native-evidence-transport/transport.py')
                transport = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(transport)
                env = dict(GITHUB_ACTIONS='true', GITHUB_REPOSITORY=policy['repository'], GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_JOB='native', GITHUB_WORKFLOW=name, RUNNER_ARCH='ARM64', GITHUB_SHA='a'*40, CAA_EVIDENCE_SOURCE_SHA='a'*40, CAA_EVIDENCE_WORKFLOW_SHA='a'*40, GITHUB_RUN_ID='123', GITHUB_RUN_ATTEMPT='1')
                self.assertEqual(transport.context(policy, env)['workflow_name'], name)
                with self.assertRaises(ValueError):
                    transport.context(policy, dict(env, GITHUB_RUN_ATTEMPT='2'))

    def test_real_source_owned_nonce_projection_is_exported_without_authority(self):
        import os
        saved, paths = dict(sys.modules), sys.path[:]
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source = root / 'source'
                F.emit(OLD, SETUP, source, 'real-modules')
                home = source / 'real606'
                sys.path.insert(0, str(home))
                for name in ('guard', 'integration', 'latest_plan'):
                    sys.modules.pop(name, None)
                import guard as G
                import integration as I
                anchor = G.anchor()
                context = anchor.source_context(G.ROOT)
                obj = I.Integration(G, anchor, context, Path('/inert-runtime'), Path('/inert-setup'))
                out = root / 'owned-output'
                out.mkdir()
                obj.prepare_nonce(out)
                original = (out / 'setup6-selection.json').read_bytes()
                self.assertEqual((out / 'plan/bridge-selection.json').read_bytes(), original)
                value = json.loads(original)
                self.assertEqual(value['purpose'], 'FULL606_SETUP6_REAL_MODULES_NATIVE_CORRECTNESS')
                self.assertEqual(value['authority'], 'SOURCE_OWNED_NOT_INDEPENDENT_ROOT_OBSERVATION')
                self.assertIsNone(value['actual_source'])
                names = obj.export_names(out)
                self.assertEqual(set(names), {'setup6-selection.json', 'plan/bridge-selection.json'})
                (out / 'plan/bridge-selection.json').write_bytes(b'{}')
                with self.assertRaisesRegex(ValueError, 'genuine normal606 nonce transport projection'):
                    obj.export_names(out)
        finally:
            sys.path[:] = paths
            for name in set(sys.modules) - set(saved):
                sys.modules.pop(name, None)
            sys.modules.update(saved)

    def test_real_profile_drift_refuses_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            factory = root / 'factory'
            shutil.copytree(HERE, factory)
            leaf = factory / 'real-modules/real606/integration.py'
            leaf.write_bytes(leaf.read_bytes() + b'\n# drift\n')
            out, auth = root / 'output', root / 'auth'
            result = cli(factory, OLD, out, auth, 'real-modules')
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'whole real-module payload before output', result.stderr)
            self.assertFalse(out.exists())
            self.assertFalse(auth.exists())

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
