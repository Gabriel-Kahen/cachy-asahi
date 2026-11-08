#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real TEST-GPG/filesystem copy tests; stable hardware admission alone is modeled."""
import contextlib
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest import mock

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


m = module('endpoint_copy_under_test', HERE / 'copy_endpoint.py')
fixture = module('endpoint_copy_fixture', HERE.parents[1] / 'client/test_endpoint.py')


class CopyTests(unittest.TestCase):
    # Reuse fixture construction, not the recipient suite's test methods. Keys,
    # archives, database and signatures are real; no package code is executed.
    @classmethod
    def setUpClass(cls):
        fixture.EndpointTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        fixture.EndpointTests.tearDownClass.__func__(cls)

    def setUp(self):
        fixture.EndpointTests.setUp(self)
        self.output = self.base / 'received'

    put = fixture.EndpointTests.put
    ref = fixture.EndpointTests.ref
    save_spec = fixture.EndpointTests.save_spec
    stage = fixture.EndpointTests.stage
    promote = fixture.EndpointTests.promote
    export = fixture.EndpointTests.export
    snapshot = fixture.EndpointTests.snapshot
    add_sources = fixture.EndpointTests.add_sources
    generation = fixture.EndpointTests.generation
    edit = fixture.EndpointTests.edit
    rehash = fixture.EndpointTests.rehash
    withdraw = fixture.EndpointTests.withdraw

    def gates(self, modeled):
        # This is the same sole positive-admission seam as test_endpoint.py.
        # Verification, GPG, release semantics and source checks remain real.
        return (mock.patch.object(m.e.r, 'gates_check', side_effect=lambda *a: m.e.r.load(a[-1]))
                if modeled else contextlib.nullcontext())

    def copy(self, *, modeled=True, apply=True, **changes):
        args = dict(generation=self.gen, expected_generation=self.ident,
                    public_keyring=self.keyring, signer=self.key, output=self.output)
        args.update(changes)
        with self.gates(modeled):
            return m.copy_generation(**args, apply=apply)

    def refused(self, **changes):
        before, children = self.snapshot(self.endpoint), set(self.base.iterdir())
        key = self.keyring.read_bytes()
        with self.assertRaises((m.c.Error, m.e.r.Error, m.k.c.Error, OSError, ValueError)):
            self.copy(**changes)
        self.assertEqual(self.snapshot(self.endpoint), before)
        self.assertEqual(set(self.base.iterdir()), children)
        self.assertEqual(self.keyring.read_bytes(), key)

    def cli(self, *extra):
        return subprocess.run([sys.executable, '-B', HERE / 'copy_endpoint.py',
            '--generation', self.gen, '--expected-generation', self.ident,
            '--public-keyring', self.keyring, '--signer', self.key,
            '--output', self.output, *extra], capture_output=True, timeout=45)

    def assert_flags(self, result):
        for flag in ('freshness_established', 'installation_authorized', 'production_accepted',
                     'trust_changed', 'state_changed', 'network_used'):
            self.assertIs(result[flag], False)

    def test_feature_directory_preserves_stdlib_copy_import(self):
        completed = subprocess.run([sys.executable, '-B', '-c',
            'import tarfile; assert tarfile.copy.copy([1, 2]) == [1, 2]'],
            cwd=HERE, capture_output=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, b'')
        self.assertEqual(completed.stderr, b'')

    def test_default_dry_run_creates_nothing_and_counts_complete_plan(self):
        self.generation(sources=True)
        before = self.snapshot(self.endpoint)
        files, links = m.e.tree(self.gen)
        with mock.patch.object(m.e, 'copy_file', side_effect=AssertionError('dry run copied')), \
             mock.patch.object(m.k, 'publish', side_effect=AssertionError('dry run published')):
            result = self.copy(apply=False)
        self.assertEqual(result['status'], 'planned-local-endpoint-copy')
        self.assertIs(result['output_created'], False)
        self.assertEqual(result['output'], str(self.output))
        self.assertEqual(result['files'], len(files))
        self.assertEqual(result['bytes'], sum((self.gen / name).stat().st_size for name in files))
        self.assertEqual(result['symlinks'], len(links))
        self.assertFalse(self.output.exists())
        self.assertEqual(self.snapshot(self.endpoint), before)
        self.assert_flags(result)

    def test_complete_stable_copy_aliases_modes_and_relocation(self):
        self.generation(sources=True)
        before, key = self.snapshot(self.endpoint), self.keyring.read_bytes()
        result = self.copy()
        self.assertEqual(result['status'], 'copied-local-endpoint')
        self.assertIs(result['output_created'], True)
        self.assertEqual(result['selected_release'], 'fixture-1')
        self.assertEqual(result['repository_relative_path'], 'release/repo/fixture.db')
        self.assertTrue(result['stable_contract_checked'])
        self.assertEqual(self.snapshot(self.output), self.snapshot(self.gen))
        files, links = m.e.tree(self.output)
        self.assertGreater(len(links), 0)
        self.assertEqual(result['files'], len(files))
        self.assertEqual(result['symlinks'], len(links))
        self.assertEqual(result['bytes'], sum((self.output / name).stat().st_size for name in files))
        for path in (self.output, *self.output.rglob('*')):
            if not path.is_symlink():
                self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o444)
        moved = self.base / 'relocated'
        shutil.copytree(self.output, moved, symlinks=True)
        with self.gates(True):
            checked = m.p.verify(moved, self.ident, self.keyring, self.key)
        for name, value in checked.items():
            if name != 'status':
                self.assertEqual(result[name], value)
        self.assertEqual(self.snapshot(self.endpoint), before)
        self.assertEqual(self.keyring.read_bytes(), key)
        self.assert_flags(result)

    def test_real_cli_withdrawal_preview_and_copy_retain_signed_notice(self):
        self.generation(); self.withdraw()
        before = self.snapshot(self.endpoint)
        planned = self.cli()
        self.assertEqual(planned.returncode, 0, planned.stderr)
        self.assertEqual(planned.stderr, b'')
        self.assertEqual(json.loads(planned.stdout)['status'], 'planned-local-endpoint-copy')
        self.assertFalse(self.output.exists())
        completed = self.cli('--apply')
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, b'')
        result = json.loads(completed.stdout)
        self.assertEqual(result['status'], 'copied-local-endpoint')
        self.assertEqual(result['withdrawn_releases'], ['fixture-1'])
        self.assertIsNone(result['selected_release'])
        self.assertIsNone(result['repository_relative_path'])
        self.assertFalse(result['stable_contract_checked'])
        self.assertEqual(self.snapshot(self.output), self.snapshot(self.gen))
        self.assertEqual(m.p.verify(self.output, self.ident, self.keyring, self.key)['withdrawn_releases'], ['fixture-1'])
        self.assertEqual(self.snapshot(self.endpoint), before)
        self.assert_flags(result)

    def test_real_cli_synthetic_stable_refused_without_success_stdout(self):
        self.generation()
        before = self.snapshot(self.endpoint)
        completed = self.cli('--apply')
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, b'')
        refusal = json.loads(completed.stderr)
        self.assertEqual(refusal['status'], 'endpoint-copy-refused')
        self.assertTrue(refusal['errors'])
        self.assertFalse(self.output.exists())
        self.assertEqual(self.snapshot(self.endpoint), before)

    def test_wrong_generation_and_signer_refused(self):
        self.generation()
        for pin in ('f' * 64, 'a' * 63, 'A' * 64):
            with self.subTest(pin=pin):
                self.refused(expected_generation=pin)
        self.refused(signer='F' * 40)

    def test_wrong_public_keyring_refused_by_real_gpg(self):
        self.generation()
        wrong = self.inputs / 'wrong.gpg'
        uid = 'Wrong copy key <wrong-copy@invalid>'
        fixture.fixture.e.r.run(['gpg', '--batch', '--pinentry-mode', 'loopback',
            '--passphrase', '', '--quick-generate-key', uid, 'ed25519', 'sign', '1d'], env=self.env)
        fixture.fixture.e.r.run(['gpg', '--batch', '--export', '--output', wrong, uid], env=self.env)
        self.assertGreater(wrong.stat().st_size, 0)
        self.refused(public_keyring=wrong)

    def test_package_tamper_with_rehashed_inventory_refused(self):
        self.generation()
        path = self.gen / 'release/repo' / self.archive.name
        self.edit(path, path.read_bytes() + b'tamper')
        self.rehash()
        self.refused()

    def test_source_tamper_with_rehashed_inventory_refused(self):
        self.generation(sources=True)
        self.edit(self.gen / 'release/evidence/source.tar', b'foreign source\n')
        self.rehash()
        self.refused()

    def test_signature_tamper_refused(self):
        self.generation()
        self.edit(self.gen / 'promotion.json.sig', b'not a signature\n')
        self.rehash()
        self.refused()

    def test_unknown_members_even_rehashed_refused(self):
        self.generation()
        self.edit(self.gen / 'extra', b'unlisted product\n')
        self.rehash()
        self.refused()

    def test_escaping_alias_refused(self):
        self.generation()
        plan = m.c.decode((self.gen / 'export.json').read_bytes())
        alias = self.gen / next(iter(plan['symlinks']))
        alias.unlink(); alias.symlink_to('../../outside')
        self.refused()

    def test_preexisting_file_directory_and_symlink_never_overwritten(self):
        self.generation()
        for kind in ('file', 'directory', 'symlink'):
            with self.subTest(kind=kind):
                if kind == 'file':
                    self.output.write_bytes(b'caller data')
                elif kind == 'directory':
                    self.output.mkdir(); (self.output / 'held').write_bytes(b'caller data')
                else:
                    self.output.symlink_to(self.inputs)
                before = self.snapshot(self.base)
                self.refused()
                self.assertEqual(self.snapshot(self.base), before)
                if kind == 'directory':
                    shutil.rmtree(self.output)
                else:
                    self.output.unlink()

    def test_nested_source_and_noncanonical_paths_refused(self):
        self.generation()
        for output in (self.gen, self.gen / 'child', self.endpoint,
                       str(self.base) + '/../received', '//' + str(self.output).lstrip('/')):
            with self.subTest(output=str(output)):
                self.refused(output=output)
        alias = self.base / 'source-alias'; alias.symlink_to(self.gen, target_is_directory=True)
        self.refused(generation=alias)

    def test_symlink_parent_and_writable_parent_refused(self):
        self.generation()
        alias = self.base / 'parent-alias'; alias.symlink_to(self.inputs, target_is_directory=True)
        self.refused(output=alias / 'copy')
        parent = self.base / 'writable'; parent.mkdir()
        for mode in (0o775, 0o777):
            parent.chmod(mode)
            with self.subTest(mode=oct(mode)):
                self.refused(output=parent / 'copy')
        parent.chmod(0o700)

    def test_exclusive_source_writer_lock_refuses_copy(self):
        self.generation()
        fd = os.open(self.gen, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.refused()
        finally:
            os.close(fd)

    def test_source_shared_lock_is_held_during_every_stream_copy(self):
        self.generation()
        original, calls = m.e.copy_file, []
        def check(*args):
            fd = os.open(self.gen, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
            calls.append(args[0]); return original(*args)
        with mock.patch.object(m.e, 'copy_file', side_effect=check):
            result = self.copy()
        self.assertEqual(len(calls), result['files'])

    def test_stream_copy_fault_cleans_partial_staging(self):
        self.generation()
        original, calls = m.e.copy_file, []
        def fail(*args):
            calls.append(args[0])
            if len(calls) == 2:
                raise OSError('injected stream fault')
            return original(*args)
        with mock.patch.object(m.e, 'copy_file', side_effect=fail):
            self.refused()
        self.assertEqual(len(calls), 2)
        self.assertFalse(self.output.exists())

    def test_noncooperative_source_change_is_rechecked_before_publish(self):
        self.generation()
        original, copied = m.e.copy_file, []
        file_count = len(m.e.tree(self.gen)[0])
        def change(*args):
            result = original(*args)
            copied.append(args[0])
            if len(copied) == file_count:
                self.edit(self.gen / 'promotion.json.sig', b'changed after final copy\n')
            return result
        children = set(self.base.iterdir())
        with mock.patch.object(m.e, 'copy_file', side_effect=change), \
             mock.patch.object(m.k, 'publish', side_effect=AssertionError('published changed source')):
            with self.assertRaises((m.c.Error, m.e.r.Error, OSError, ValueError)):
                self.copy()
        self.assertEqual(len(copied), file_count)
        self.assertFalse(self.output.exists())
        self.assertEqual(set(self.base.iterdir()), children)

    def test_noreplace_publication_race_preserves_other_writer(self):
        self.generation()
        original, before = m.k.publish, self.snapshot(self.endpoint)
        def race(*args):
            self.output.mkdir(); (self.output / 'held').write_bytes(b'other writer')
            return original(*args)
        with mock.patch.object(m.k, 'publish', side_effect=race):
            with self.assertRaises(OSError):
                self.copy()
        self.assertEqual(self.snapshot(self.output), {'held': ('file', b'other writer')})
        self.assertFalse(list(self.base.glob('.endpoint-copy-*')))
        self.assertEqual(self.snapshot(self.endpoint), before)

    def test_tampered_retained_withdrawal_refuses_real_copy(self):
        self.generation(); self.withdraw()
        notice = next((self.gen / 'withdrawals').glob('*.json'))
        self.edit(notice, notice.read_bytes() + b' ')
        self.rehash()
        self.refused(modeled=False)

    def test_publication_helper_refusal_is_json_without_success_stdout(self):
        self.generation(); self.withdraw()
        original = m.k.publish
        def swap(staging, parent, output, inspected):
            staging.rename(staging.with_name('retained-staging'))
            staging.mkdir(mode=0o700)
            return original(staging, parent, output, inspected)
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(m.k, 'publish', side_effect=swap), \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = m.main(['--generation', str(self.gen), '--expected-generation', self.ident,
                '--public-keyring', str(self.keyring), '--signer', self.key,
                '--output', str(self.output), '--apply'])
        self.assertEqual(code, 1)
        self.assertEqual(stdout.getvalue(), '')
        refused = json.loads(stderr.getvalue())
        self.assertEqual(refused['status'], 'endpoint-copy-refused')
        self.assertIn('identity changed', refused['errors'][0])
        self.assertFalse(self.output.exists())
        self.assertFalse(list(self.base.glob('.endpoint-copy-*')))

    def test_staging_identity_swap_refuses_publication(self):
        self.generation()
        original, moved = m.k.publish, []
        def swap(staging, parent, output, inspected):
            retained = staging.with_name('retained-staging')
            staging.rename(retained); moved.append(retained)
            staging.mkdir(mode=0o700)
            return original(staging, parent, output, inspected)
        with mock.patch.object(m.k, 'publish', side_effect=swap):
            self.refused()
        self.assertTrue(moved)
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main()
