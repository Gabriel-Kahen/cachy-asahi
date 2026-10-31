#!/usr/bin/env python3
"""New DATA regressions; read the actual production guard and actual Source Git.

No native runtime, fixture, inline workflow Python, package or control executes.
"""
import argparse
import importlib.util
import json
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

parser = argparse.ArgumentParser()
parser.add_argument('--checker', type=Path, required=True)
parser.add_argument('--repository', type=Path, required=True)
parser.add_argument('--workflow', type=Path, required=True)
parser.add_argument('--checkout-only', action='store_true', help='run only the four new checkout regressions')
parser.add_argument('--fixture-root', type=Path, required=True, help='existing private directory for tiny local-only Git DATA')
args = parser.parse_args()
spec = importlib.util.spec_from_file_location('source_guard_checker', args.checker)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)  # Only this maintained passive checker; never Source code.
body = args.workflow.read_bytes()
guard = checker.contract(body)


def changed_guard(old, new):
    workflow = json.loads(body)
    step = next(s for s in workflow['jobs']['adopted-zero-control']['steps'] if s.get('id') == 'source_guard')
    assert old in step['run']
    step['run'] = step['run'].replace(old, new)
    return json.dumps(workflow).encode()


class SourceData(unittest.TestCase):
    def test_real_git_source_positive(self):
        proof = checker.git_source(args.repository, guard)
        self.assertEqual(proof['git_mode'], '100755')

    def test_observed_old_0644_guard_refused_by_actual_git(self):
        workflow = json.loads(body)
        step = next(s for s in workflow['jobs']['adopted-zero-control']['steps'] if s.get('id') == 'source_guard')
        old_call = "sha256='" + guard['sha256'] + "'),0o755)"
        self.assertIn(old_call, step['run'])
        step['run'] = step['run'].replace(old_call, "sha256='" + guard['sha256'] + "'),0o644)")
        with self.assertRaisesRegex(ValueError, 'real Source Git mode'):
            checker.git_source(args.repository, checker.contract(json.dumps(workflow).encode()))

    def test_wrong_hash_refused_by_actual_git(self):
        bad = dict(guard, sha256='0' * 64)
        with self.assertRaisesRegex(ValueError, 'body pin'):
            checker.git_source(args.repository, bad)

    def test_wrong_size_refused_by_actual_git(self):
        with self.assertRaisesRegex(ValueError, 'blob size'):
            checker.git_source(args.repository, dict(guard, bytes=guard['bytes'] + 1))

    def test_checkout_and_provenance_disagreement(self):
        workflow = json.loads(body)
        next(s for s in workflow['jobs']['adopted-zero-control']['steps'] if s.get('with', {}).get('path') == guard['checkout'])['with']['ref'] = '0' * 40
        with self.assertRaisesRegex(ValueError, 'Source disagree'):
            checker.contract(json.dumps(workflow).encode())

    def test_missing_mode_predicate(self):
        with self.assertRaisesRegex(ValueError, 'physical file predicate'):
            checker.contract(changed_guard('stat.S_IMODE(s.st_mode)==mode', 'True'))

    def test_missing_source_head_guard(self):
        with self.assertRaisesRegex(ValueError, 'HEAD guard missing'):
            checker.contract(changed_guard("assert git(data,'rev-parse','HEAD')==value['runtime_source']", 'assert True'))

    def test_physical_checkout_data_positive_and_refusals(self):
        row = checker.git(args.repository, 'ls-tree', '-z', guard['source'], '--', guard['path'])
        blob = row.split(b'\t')[0].split()[2].decode()
        data = checker.git(args.repository, 'cat-file', 'blob', blob)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / guard['path']
            path.parent.mkdir(parents=True)
            path.write_bytes(data)
            path.chmod(guard['mode'])
            checker.physical_file(root, guard)
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'physical checkout metadata'):
                checker.physical_file(root, guard)
            path.chmod(guard['mode'])
            path.write_bytes(b'X' + data[1:])
            with self.assertRaisesRegex(ValueError, 'physical checkout body'):
                checker.physical_file(root, guard)
            path.unlink()
            (root / 'body').write_bytes(data)
            path.symlink_to(root / 'body')
            with self.assertRaisesRegex(ValueError, 'ordinary unaliased'):
                checker.physical_file(root, guard)


class CheckoutData(unittest.TestCase):
    def test_inherited_denial_is_rejected_for_each_checkout(self):
        for index in (0, 1):
            workflow = json.loads(body)
            steps = [s for s in workflow['jobs']['adopted-zero-control']['steps'] if s.get('uses', '').startswith('actions/checkout@')]
            steps[index].pop('env', None)
            with self.assertRaisesRegex(ValueError, 'both checkout steps'):
                checker.contract(json.dumps(workflow).encode())

    def test_global_denial_remains_held(self):
        workflow = json.loads(body)
        workflow['jobs']['adopted-zero-control']['env']['GIT_NO_LAZY_FETCH'] = '0'
        with self.assertRaisesRegex(ValueError, 'global lazy-fetch denial'):
            checker.contract(json.dumps(workflow).encode())

    def test_passive_git_cannot_enable_lazy_fetch(self):
        with self.assertRaisesRegex(ValueError, 'Git reads must explicitly disable'):
            checker.contract(changed_guard("env=dict(os.environ,GIT_NO_LAZY_FETCH='1'", "env=dict(os.environ,GIT_NO_LAZY_FETCH='0'"))

    def test_real_partial_fetch_materialization(self):
        # This fixture alone may write Git objects/refs, only under the requested private root.
        # No project clone, network protocol, runtime, hook or fixture Python is executed.
        transcript = []
        args.fixture_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='partial-data-', dir=args.fixture_root) as temporary:
            root = Path(temporary).resolve()
            env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
            env.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1', GIT_ALLOW_PROTOCOL='file',
                       GIT_TERMINAL_PROMPT='0', GIT_NO_LAZY_FETCH='1', GIT_OPTIONAL_LOCKS='0')

            def command(folder, *argv, lazy='1', success=True):
                assert folder == root or root in folder.parents
                full = ['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', '-c', 'gc.auto=0', *argv]
                result = subprocess.run(full, cwd=folder, env=dict(env, GIT_NO_LAZY_FETCH=lazy),
                                        capture_output=True, timeout=10)
                assert len(result.stdout) + len(result.stderr) <= 65536
                transcript.append(dict(directory=folder.name, argv=argv, GIT_NO_LAZY_FETCH=lazy,
                                       exit=result.returncode, stdout=result.stdout.decode(), stderr=result.stderr.decode()))
                if success:
                    result.check_returncode()
                return result

            seed = root / 'seed'
            command(root, 'init', '--initial-branch=main', str(seed))
            command(seed, 'config', 'user.name', 'Source DATA fixture')
            command(seed, 'config', 'user.email', 'data-fixture@example.invalid')
            leaf = seed / 'scripts/runtime.py'
            leaf.parent.mkdir()
            expected = b'PASSIVE_SOURCE_DATA_NEVER_EXECUTED\n'
            leaf.write_bytes(expected)
            leaf.chmod(0o755)
            (seed / 'excluded.data').write_bytes(b'EXCLUDED\n' * 64)
            command(seed, 'add', '--', 'scripts/runtime.py', 'excluded.data')
            command(seed, 'commit', '-m', 'Tiny passive Git DATA fixture')
            source = command(seed, 'rev-parse', 'HEAD').stdout.decode().strip()
            blob = command(seed, 'rev-parse', source + ':scripts/runtime.py').stdout.decode().strip()
            origin = root / 'origin.git'
            command(root, 'clone', '--bare', '--no-hardlinks', seed.as_uri(), str(origin))
            command(origin, 'config', 'uploadpack.allowFilter', 'true')
            command(origin, 'config', 'uploadpack.allowAnySHA1InWant', 'true')
            outcomes = {}
            for lazy in ('1', '0'):
                checkout = root / ('checkout-' + lazy)
                command(root, 'init', str(checkout))
                command(checkout, 'remote', 'add', 'origin', origin.as_uri())
                command(checkout, '-c', 'protocol.version=2', 'fetch', '--no-tags', '--prune',
                        '--no-recurse-submodules', '--filter=blob:none', '--depth=1', 'origin', source, lazy=lazy)
                missing = command(checkout, 'cat-file', '-e', blob, success=False)
                self.assertNotEqual(missing.returncode, 0, 'filtered fetch must actually omit the blob')
                self.assertTrue(list((checkout / '.git/objects/pack').glob('*.promisor')))
                command(checkout, 'config', 'core.sparseCheckout', 'true')
                (checkout / '.git/info/sparse-checkout').write_text('/scripts/runtime.py\n')
                result = command(checkout, 'checkout', '--progress', '--force', source, lazy=lazy, success=False)
                outcomes[lazy] = result.returncode
                if lazy == '1':
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(b'could not fetch', result.stderr)
                    self.assertIn(b'promisor remote', result.stderr)
                    self.assertFalse((checkout / 'scripts/runtime.py').exists())
                else:
                    self.assertEqual(result.returncode, 0)
                    actual = checkout / 'scripts/runtime.py'
                    self.assertEqual(actual.read_bytes(), expected)
                    self.assertEqual(stat.S_IMODE(actual.stat().st_mode), 0o755)
                    self.assertEqual(command(checkout, 'rev-parse', 'HEAD').stdout.decode().strip(), source)
                    self.assertEqual(command(checkout, 'cat-file', 'blob', blob).stdout, expected)
            total = sum(p.stat().st_size for p in root.rglob('*') if p.is_file())
            self.assertLess(total, 1024**2)
        print(json.dumps(dict(private_partial_clone_proof=dict(source=source, blob=blob,
                         blob_sha256=hashlib.sha256(expected).hexdigest(), mode='100755',
                         checkout_exit_by_effective_GIT_NO_LAZY_FETCH=outcomes,
                         fixture_total_bytes=total, transport='file-only', commands=transcript)), sort_keys=True))


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(CheckoutData)
    if not args.checkout_only:
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(SourceData))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps(dict(status='PASS_NEW_SOURCE_DATA_CONTROLS' if result.wasSuccessful() else 'FAIL',
                         tests=result.testsRun, failures=len(result.failures), errors=len(result.errors),
                         skips=len(result.skipped), source=checker.git_source(args.repository, guard),
                         local_physical_evidence='MATERIALIZED_GIT_BLOB_DATA_NOT_A_REAL_CHECKOUT',
                         actual_CI_checkout_join='PENDING_CI', native_runtime_executed=False), sort_keys=True))
    sys.exit(not result.wasSuccessful())
