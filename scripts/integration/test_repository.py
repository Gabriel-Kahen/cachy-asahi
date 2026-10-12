#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Portable boundary tests; no actual host key imports, installs or trust mutation."""
import argparse
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.dont_write_bytecode = True
loader = importlib.util.spec_from_file_location('repository', Path(__file__).with_name('repository.py'))
r = importlib.util.module_from_spec(loader)
loader.loader.exec_module(r)


class RepositoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='repository-portable-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.runner = r.Integration({'source_commit': 'a' * 40})
        self.runner.out = self.base / 'out'
        self.runner.out.mkdir()
        self.runner.home = self.base / 'private'
        self.runner.home.mkdir()
        self.runner.scratch = self.base / 'scratch'
        self.runner.scratch.mkdir()
        self.runner.query_config = self.runner.scratch / 'query-pacman.conf'

    def mount_contract(self):
        def row(fs, mode, root='/'):return {'fs': fs, 'options': {mode}, 'root': root}
        return {'/': row('overlay', 'ro'), '/inputs': row('ext4', 'ro', '/bound-inputs'), '/runner': row('ext4', 'ro', '/bound-runner'),
                '/scratch': {'fs': 'tmpfs', 'options': {'rw', 'nosuid', 'nodev'}, 'root': '/'},
                '/test-home': {'fs': 'tmpfs', 'options': {'rw', 'nosuid', 'nodev'}, 'root': '/'}, '/out': row('ext4', 'rw', '/bound-output'),
                **{p: row('ext4', 'rw', '/Docker/' + Path(p).name) for p in r.RUNTIME_FILES},
                **{p: {'fs': fs, 'options': set(flags), 'root': '/null' if p in r.MASKED_NULL else
                        p.removeprefix('/proc') if fs == 'proc' and p != '/proc' else '/'}
                   for p, (fs, flags) in r.STANDARD_MOUNTS.items()}}

    def test_host_invocation_refuses_before_mutation(self):
        env = dict(os.environ, CACHY_ASAHI_REPOSITORY_CONTAINER='1',
                   CACHY_ASAHI_DISPOSABLE_REPOSITORY='a' * 32, CACHY_ASAHI_IMAGE_ID='sha256:' + 'b' * 64)
        p = subprocess.run([sys.executable, str(Path(__file__).with_name('repository.py')),
                            '--inputs', '/inputs/manifest.json', '--inputs-sha256', 'c' * 64,
                            '--allow-disposable-repository-test'], env=env, capture_output=True, text=True)
        self.assertEqual(p.returncode, 1)
        self.assertIn('refused/failed', p.stderr)

    def test_missing_explicit_execution_flag(self):
        with mock.patch.object(r.subprocess, 'run') as commands:
            with self.assertRaisesRegex(r.Refused, 'explicit disposable'):
                r.guard(argparse.Namespace(allow_disposable_repository_test=False))
            commands.assert_not_called()

    def test_mounts_parse(self):
        parsed = r.mounts('21 1 0:1 / / ro - overlay overlay rw\n22 21 0:2 / /scratch rw - tmpfs tmpfs rw\n')
        self.assertEqual(parsed['/']['options'], {'ro'})
        self.assertEqual(parsed['/scratch']['fs'], 'tmpfs')

    def test_readonly_container_mount_contract(self):
        r.validate_mounts(self.mount_contract())
        bad = self.mount_contract()
        bad['/']['options'] = {'rw'}
        with self.assertRaisesRegex(r.Refused, 'read-only'):
            r.validate_mounts(bad)

    def test_host_mutation_paths_rejected_even_readonly(self):
        for path in ('/usr', '/var/lib/pacman', '/etc/pacman.d/gnupg', '/home/gabe', '/root', '/tmp'):
            with self.subTest(path=path):
                bad = self.mount_contract()
                bad[path] = {'fs': 'ext4', 'options': {'ro'}, 'root': '/host-subtree'}
                with self.assertRaisesRegex(r.Refused, 'host/system-path'):
                    r.validate_mounts(bad)

    def test_unknown_nested_and_arbitrary_runtime_mounts_refused(self):
        for path in ('/inputs/writablechild', '/runner/writablechild', '/out/child', '/scratch/child', '/test-home/child',
                     '/proc/self/status', '/proc/self/mountinfo', '/run/hostsock', '/custom-runtime', '/dev/dri'):
            with self.subTest(path=path):
                bad = self.mount_contract()
                bad[path] = {'fs': 'ext4', 'options': {'rw'}, 'root': '/host'}
                with self.assertRaisesRegex(r.Refused, 'unexpected/nested'):
                    r.validate_mounts(bad)

    def test_standard_mount_filesystem_flags_and_subtree_are_exact(self):
        for path, (fs, flags) in r.STANDARD_MOUNTS.items():
            with self.subTest(path=path, field='fs'):
                bad = self.mount_contract(); bad[path]['fs'] = 'ext4'
                with self.assertRaises(r.Refused):r.validate_mounts(bad)
            for flag in flags:
                with self.subTest(path=path, flag=flag):
                    bad = self.mount_contract(); bad[path]['options'].remove(flag)
                    with self.assertRaises(r.Refused):r.validate_mounts(bad)
            with self.subTest(path=path, field='root'):
                bad = self.mount_contract(); bad[path]['root'] = '/host-private'
                with self.assertRaises(r.Refused):r.validate_mounts(bad)
        bad = self.mount_contract(); del bad['/proc']
        with self.assertRaises(r.Refused):r.validate_mounts(bad)

    def test_private_tmpfs_nodev_nosuid_and_root_required(self):
        for path in ('/scratch', '/test-home'):
            for flag in ('nodev', 'nosuid'):
                bad = self.mount_contract(); bad[path]['options'].remove(flag)
                with self.subTest(path=path, flag=flag), self.assertRaisesRegex(r.Refused, 'tmpfs'):
                    r.validate_mounts(bad)
            bad = self.mount_contract(); bad[path]['root'] = '/host-subtree'
            with self.assertRaises(r.Refused):r.validate_mounts(bad)

    def test_readonly_kernel_proc_protections_cannot_be_omitted(self):
        for path in r.PROTECTED_PROC:
            bad = self.mount_contract()
            del bad[path]
            with self.subTest(path=path), self.assertRaisesRegex(r.Refused, 'complete standard Docker'):
                r.validate_mounts(bad)
        bad = self.mount_contract()
        for path in r.PROTECTED_PROC:del bad[path]
        with self.assertRaises(r.Refused):r.validate_mounts(bad)

    def test_duplicate_conflicting_and_invalid_mount_records_refused(self):
        row = '21 1 0:1 / / ro - overlay overlay rw\n'
        with self.assertRaisesRegex(r.Refused, 'duplicate'):
            r.mounts(row + row)
        with self.assertRaisesRegex(r.Refused, 'duplicate'):
            r.mounts(row.replace(' ro ', ' ro,ro '))
        for path, extra in (('/', 'rw'), ('/scratch', 'suid'), ('/test-home', 'dev'), ('/proc', 'exec')):
            bad = self.mount_contract(); bad[path]['options'].add(extra)
            with self.subTest(path=path), self.assertRaises(r.Refused):r.validate_mounts(bad)

    def test_all_actual_capability_sets_and_no_new_privileges_required(self):
        good = '\n'.join(f'{name}:\t{r.SAFE_CAPS if name in {"CapEff", "CapPrm", "CapBnd"} else 0:x}' for name in r.CAP_FIELDS) + '\nNoNewPrivs:\t1\n'
        self.assertEqual(r.privileges(good)['CapEff'], r.SAFE_CAPS)
        for field in r.CAP_FIELDS:
            value = r.SAFE_CAPS if field in {'CapEff', 'CapPrm', 'CapBnd'} else 0
            for forbidden in (1 << 5, 1 << 21, 1 << 27, 1 << 31):
                bad = good.replace(f'{field}:\t{value:x}', f'{field}:\t{value | forbidden:x}')
                with self.subTest(field=field, bit=forbidden), self.assertRaisesRegex(r.Refused, 'six-cap'):
                    r.privileges(bad)
            with self.assertRaises(r.Refused):r.privileges(good.replace(f'{field}:\t{value:x}', ''))
        with self.assertRaisesRegex(r.Refused, 'no-new-privileges'):r.privileges(good.replace('NoNewPrivs:\t1', 'NoNewPrivs:\t0'))

    def test_sys_chroot_is_required_only_in_exact_repository_effective_permitted_bounding_mask(self):
        self.assertEqual(r.SAFE_CAPS, 0x400cb)
        good = '\n'.join(f'{name}:\t{r.SAFE_CAPS if name in {"CapEff", "CapPrm", "CapBnd"} else 0:x}' for name in r.CAP_FIELDS) + '\nNoNewPrivs:\t1\n'
        for field in ('CapEff', 'CapPrm', 'CapBnd'):
            with self.subTest(field=field), self.assertRaisesRegex(r.Refused, 'six-cap'):
                r.privileges(good.replace(f'{field}:\t{r.SAFE_CAPS:x}', f'{field}:\tcb'))
        for field in ('CapInh', 'CapAmb'):
            with self.subTest(field=field), self.assertRaisesRegex(r.Refused, 'six-cap'):
                r.privileges(good.replace(f'{field}:\t0', f'{field}:\t40000'))

    def test_zero_exit_native_ancillary_errors_cannot_pass_positive_pacman(self):
        self.runner.keys['verifier'] = {'home': self.runner.home / 'verifier'}
        actual = b'installing cachy-asahi-setup...\ncould not change the root directory (Operation not permitted)\nerror: command failed to execute correctly\n'
        for output in (actual, b'upgrading fixture...\nerror: command failed to execute correctly\n',
                       b'upgrading fixture...\ncould not change the root directory (Operation not permitted)\n'):
            result = subprocess.CompletedProcess([], 0, output)
            with self.subTest(output=output), mock.patch.object(r.subprocess, 'run', return_value=result):
                with self.assertRaisesRegex(r.Refused, 'ancillary execution diagnostic'):
                    self.runner.pacman('trusted-full-install', ['-Syyu', '--noscriptlet'])
            self.assertEqual((self.runner.out / self.runner.receipts[-1]['log']).read_bytes(), output)

    def test_positive_diagnostics_checks_query_stderr_without_filtering_inventory(self):
        self.runner.keys['verifier'] = {'home': self.runner.home / 'verifier'}
        result = subprocess.CompletedProcess([], 0, b'runtime 1-1\n', b'error: command failed to execute correctly\n')
        with mock.patch.object(r.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(r.Refused, 'ancillary execution diagnostic'):
                self.runner.pacman('query', ['-Q'])
        result.stderr = b'warning: optional TEST fixture notice\n'
        with mock.patch.object(r.subprocess, 'run', return_value=result):
            self.assertEqual(self.runner.pacman('query', ['-Q']), 'runtime 1-1\n')
        self.assertEqual(self.runner.receipts[-1]['positive_diagnostics'], 'PASS')

    def test_device_socket_and_standard_identity_exposure_refused(self):
        good = {'devices': {path: {'kind': 'char', 'major': major, 'minor': minor}
                            for path, (major, minor) in r.STANDARD_DEVICES.items()}, 'sockets': []}
        r.validate_exposure(good)
        bad = copy.deepcopy(good); bad['sockets'] = ['/run/host-service.sock']
        with self.assertRaisesRegex(r.Refused, 'socket'):r.validate_exposure(bad)
        for path, kind in (('/dev/dri/card0', 'char'), ('/inputs/device', 'block'), ('/runner/device', 'char'), ('/out/device', 'block')):
            bad = copy.deepcopy(good); bad['devices'][path] = {'kind': kind, 'major': 8, 'minor': 0}
            with self.subTest(path=path), self.assertRaisesRegex(r.Refused, 'device'):r.validate_exposure(bad)
        bad = copy.deepcopy(good); bad['devices']['/dev/null']['major'] = 8
        with self.assertRaises(r.Refused):r.validate_exposure(bad)
        bad = copy.deepcopy(good); del bad['devices']['/dev/null']
        with self.assertRaises(r.Refused):r.validate_exposure(bad)

    def test_exposure_observer_collects_actual_lstat_nodes_without_host_mutation(self):
        walks = iter([('/dev', [], ['gpu', 'sock'])])
        def status(path):
            return SimpleNamespace(st_mode=stat.S_IFCHR if path.name == 'gpu' else stat.S_IFSOCK, st_rdev=os.makedev(226, 0))
        with mock.patch.object(r.os, 'walk', side_effect=lambda *a, **k: walks if a[0] == '/dev' else []), \
             mock.patch.object(Path, 'lstat', status):
            observed = r.exposed_nodes()
        self.assertEqual(observed['devices'], {'/dev/gpu': {'kind': 'char', 'major': 226, 'minor': 0}})
        self.assertEqual(observed['sockets'], ['/dev/sock'])

    def test_full_guard_bad_mount_caps_and_devices_refuse_before_input_or_commands(self):
        good_status = '\n'.join(f'{name}:\t{r.SAFE_CAPS if name in {"CapEff", "CapPrm", "CapBnd"} else 0:x}' for name in r.CAP_FIELDS) + '\nNoNewPrivs:\t1\n'
        good_exposure = {'devices': {p: {'kind': 'char', 'major': major, 'minor': minor}
                                    for p, (major, minor) in r.STANDARD_DEVICES.items()}, 'sockets': []}
        bad_mount = self.mount_contract()
        bad_mount['/inputs/writablechild'] = {'fs': 'ext4', 'options': {'rw'}, 'root': '/host'}
        bad_exposure = copy.deepcopy(good_exposure)
        bad_exposure['devices']['/dev/gpu'] = {'kind': 'char', 'major': 226, 'minor': 0}
        cases = ((bad_mount, good_status, good_exposure, 'unexpected/nested'),
                 (self.mount_contract(), good_status.replace(f'CapBnd:\t{r.SAFE_CAPS:x}', 'CapBnd:\t200000'), good_exposure, 'six-cap'),
                 (self.mount_contract(), good_status, bad_exposure, 'device'))
        args = argparse.Namespace(allow_disposable_repository_test=True, inputs='/inputs/manifest.json')
        env = {'CACHY_ASAHI_REPOSITORY_CONTAINER': '1', 'CACHY_ASAHI_DISPOSABLE_REPOSITORY': 'a' * 32,
               'CACHY_ASAHI_IMAGE_ID': 'sha256:' + 'b' * 64}
        for observed, status, exposure, reason in cases:
            with self.subTest(reason=reason), mock.patch.dict(r.os.environ, env), \
                 mock.patch.object(r.platform, 'machine', return_value='aarch64'), mock.patch.object(r.os, 'geteuid', return_value=0), \
                 mock.patch.object(Path, 'is_file', return_value=True), mock.patch.object(Path, 'is_symlink', return_value=False), \
                 mock.patch.object(Path, 'stat', return_value=SimpleNamespace(st_uid=0)), mock.patch.object(Path, 'exists', return_value=False), \
                 mock.patch.object(Path, 'read_text', autospec=True, side_effect=lambda p: status if str(p) == '/proc/self/status' else ''), \
                 mock.patch.object(r, 'mounts', return_value=observed), mock.patch.object(r, 'exposed_nodes', return_value=exposure), \
                 mock.patch.object(r.subprocess, 'run') as commands, mock.patch.object(r, 'input_file') as inputs, \
                 mock.patch.object(r, 'write') as output:
                with self.assertRaisesRegex(r.Refused, reason):r.guard(args)
                commands.assert_not_called()
                inputs.assert_not_called()
                output.assert_not_called()

    def test_scratch_private_home_cannot_be_host_bind(self):
        for path in ('/scratch', '/test-home'):
            with self.subTest(path=path):
                bad = self.mount_contract()
                bad[path]['fs'] = 'ext4'
                with self.assertRaisesRegex(r.Refused, 'tmpfs'):
                    r.validate_mounts(bad)

    def test_signature_identity_and_invalid_key_status(self):
        key = 'A' * 40
        valid = f'[GNUPG:] VALIDSIG {key} 2026-10-11 1791748800 0 4 0 22 8 00 {key}\n'
        r.signature_status(valid, key)
        for status in ('EXPKEYSIG', 'REVKEYSIG', 'BADSIG', 'NO_PUBKEY', 'KEYEXPIRED'):
            with self.subTest(status=status):
                with self.assertRaises(r.Refused):
                    r.signature_status(valid + f'[GNUPG:] {status} {key}\n', key)
        with self.assertRaises(r.Refused):
            r.signature_status(valid, 'B' * 40)
        with self.assertRaises(r.Refused):
            r.signature_status(valid.replace('22 8 00', '22 2 00'), key)

    def test_fixture_is_changed_data_without_hooks(self):
        first, second = self.base / 'one.pkg.tar.xz', self.base / 'two.pkg.tar.xz'
        r.fixture(first, '1-1', 'TEST version 1\n')
        r.fixture(second, '2-1', 'TEST version 2\n')
        self.assertNotEqual(r.sha(first), r.sha(second))
        with tarfile.open(second) as package:
            self.assertEqual(package.getnames(), ['.PKGINFO', r.PAYLOAD])
            self.assertIn(b'pkgver = 2-1', package.extractfile('.PKGINFO').read())
            self.assertEqual(package.extractfile(r.PAYLOAD).read(), b'TEST version 2\n')

    def test_archive_member_listings_must_agree(self):
        with mock.patch.object(self.runner, 'command', side_effect=['.PKGINFO\nusr/share/cachy-asahi/file\n', '- metadata\n']):
            with self.assertRaisesRegex(r.Refused, 'inconsistent package member'):
                self.runner.metadata(self.base / 'unused.pkg.tar.xz')

    def test_receipts_capture_bytes_without_shell(self):
        result = subprocess.CompletedProcess(['mock'], 0, b'fixture\xff\n')
        with mock.patch.object(r.subprocess, 'run', return_value=result) as call:
            output = self.runner.command('binary', ['mock', 'literal;$()'], binary=True)
        self.assertEqual(output, b'fixture\xff\n')
        self.assertNotIn('shell', call.call_args.kwargs)
        receipt = self.runner.receipts[0]
        self.assertEqual(receipt['argv'], ['mock', 'literal;$()'])
        self.assertEqual(r.sha(self.runner.out / receipt['log']), receipt['sha256'])

    def test_negative_tests_need_signature_diagnostic(self):
        result = subprocess.CompletedProcess([], 1, b'missing dependency\n')
        with mock.patch.object(r.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(r.Refused, 'signature/trust'):
                self.runner.command('wrong-failure', ['mock'], expected=1, signature_failure=True)
        result.stdout = b'invalid PGP signature\n'
        with mock.patch.object(r.subprocess, 'run', return_value=result):
            self.runner.command('right-failure', ['mock'], expected=1, signature_failure=True)

    def missing_database_fixture(self):
        self.runner.config = self.runner.scratch / 'pacman.conf'
        self.runner.target = self.runner.scratch / 'system'
        reference = self.runner.scratch / 'repos/updated-B'
        reference.mkdir(parents=True)
        for name in ('integration.db.tar.gz', 'integration.files.tar.gz', 'original.pkg.tar.xz', 'probe.pkg.tar.xz'):
            (reference / name).write_bytes(b'SYNTHETIC TEST ' + name.encode())
            (reference / (name + '.sig')).write_bytes(b'SYNTHETIC TEST signature ' + name.encode())
        for alias, target in (('integration.db', 'integration.db.tar.gz'), ('integration.db.sig', 'integration.db.tar.gz.sig'),
                              ('integration.files', 'integration.files.tar.gz'), ('integration.files.sig', 'integration.files.tar.gz.sig')):
            (reference / alias).symlink_to(target)
        repository = reference.parent / 'missing-database-signature-B'
        shutil.copytree(reference, repository, symlinks=True)
        for name in ('integration.db.sig', 'integration.db.tar.gz.sig'):
            (repository / name).unlink()
        self.runner.config.write_text(r.STRICT_OPTIONS + r.STRICT_REPOSITORY)
        self.runner.keys['verifier'] = {'home': self.runner.home / 'verifier'}
        self.runner.select(repository)
        return repository, reference, self.runner.missing_database_inputs(repository, reference)

    def missing_database_output(self):
        return (":: Synchronizing package databases...\n integration downloading...\n"
                "error: failed retrieving file 'integration.db.sig' from disk : Could not open file "
                + str(self.runner.scratch / 'repos/active/integration.db.sig')
                + '\nerror: failed to synchronize all databases (download library error)\n')

    def test_native_missing_database_signature_diagnostic_is_exact(self):
        # Verbatim four-line diagnostic from native38214941784, with no execution.
        actual = (":: Synchronizing package databases...\n integration downloading...\n"
                  "error: failed retrieving file 'integration.db.sig' from disk : Could not open file /scratch/repos/active/integration.db.sig\n"
                  "error: failed to synchronize all databases (download library error)\n")
        with mock.patch.object(self.runner, 'scratch', Path('/scratch')):
            self.runner.missing_database_diagnostic(actual)
            for bad in (actual.replace('integration.db.sig', 'integration.db'),
                        actual.replace('integration.db.sig', 'original.pkg.tar.xz.sig'),
                        actual.replace('/scratch/repos/active/', '/scratch/repos/other/'),
                        actual.replace('from disk', 'from example.invalid'),
                        actual.replace('Could not open file', 'Connection refused'),
                        'error: failed to synchronize all databases (download library error)\n',
                        actual + 'error: missing dependency\n'):
                with self.subTest(output=bad), self.assertRaisesRegex(r.Refused, 'exact selected local'):
                    self.runner.missing_database_diagnostic(bad)

    def test_typed_missing_database_rejection_retains_after_invariants_and_raw_log(self):
        repository, _, proof = self.missing_database_fixture()
        before = ({'runtime': '1-1'}, {'owned': {'type': 'regular', 'sha256': 'a' * 64}})
        result = subprocess.CompletedProcess([], 1, self.missing_database_output().encode())
        with mock.patch.object(self.runner, 'snapshot', side_effect=[before, before]) as snapshot, \
                mock.patch.object(r.subprocess, 'run', return_value=result):
            self.runner.transaction(r.MISSING_DATABASE_CASE, repository, reject=True, missing_database=proof)
        self.assertEqual(snapshot.call_args_list[-1].args, (r.MISSING_DATABASE_CASE + '-after',))
        self.assertEqual(self.runner.cases[-1]['rejection_contract'], proof)
        receipt = self.runner.receipts[-1]
        self.assertEqual(receipt['signature_rejection_kind'], 'missing-required-local-database-signature')
        self.assertEqual((self.runner.out / receipt['log']).read_bytes(), result.stdout)
        self.assertEqual(r.sha(self.runner.out / receipt['log']), receipt['sha256'])

    def test_missing_database_case_rejects_mutation_of_any_other_bytes(self):
        repository, reference, proof = self.missing_database_fixture()
        for path in (repository / 'integration.db.tar.gz', repository / 'original.pkg.tar.xz',
                     repository / 'original.pkg.tar.xz.sig', reference / 'integration.files.tar.gz'):
            old = path.read_bytes()
            path.write_bytes(old + b'changed')
            with self.subTest(path=path), self.assertRaises(r.Refused):
                self.runner.validate_missing_database(proof)
            path.write_bytes(old)
        (repository / 'integration.db').unlink()
        (repository / 'integration.db').symlink_to('integration.files.tar.gz')
        with self.assertRaises(r.Refused):self.runner.validate_missing_database(proof)

    def test_missing_database_requires_strict_config_selected_endpoint_and_absent_signatures(self):
        repository, _, proof = self.missing_database_fixture()
        self.runner.config.write_text((r.STRICT_OPTIONS + r.STRICT_REPOSITORY).replace('Required', 'Optional'))
        with self.assertRaisesRegex(r.Refused, 'strict local'):self.runner.validate_missing_database(proof)
        self.runner.config.write_text(r.STRICT_OPTIONS + r.STRICT_REPOSITORY)
        active = repository.parent / 'active'
        active.unlink()
        active.symlink_to('updated-B')
        with self.assertRaisesRegex(r.Refused, 'selected'):self.runner.validate_missing_database(proof)
        active.unlink()
        active.symlink_to(repository.name)
        (repository / 'integration.db.sig').symlink_to('missing-target')
        with self.assertRaises(r.Refused):self.runner.validate_missing_database(proof)

    def test_typed_rejection_is_not_available_to_other_cases_or_operations(self):
        _, _, proof = self.missing_database_fixture()
        for label, options, reject in (('missing-package-signature-rejected', ['-Syyu', '--noscriptlet'], True),
                                       (r.MISSING_DATABASE_CASE, ['-Q'], True),
                                       (r.MISSING_DATABASE_CASE, ['-Syyu', '--noscriptlet'], False)):
            with mock.patch.object(r.subprocess, 'run') as command:
                with self.assertRaisesRegex(r.Refused, 'case-specific'):
                    self.runner.pacman(label, options, reject=reject, missing_database=proof)
                command.assert_not_called()

    def test_wrong_negative_diagnostic_still_records_after_snapshot(self):
        repository, _, proof = self.missing_database_fixture()
        before = ({'runtime': '1-1'}, {})
        result = subprocess.CompletedProcess([], 1, b'error: missing dependency\n')
        with mock.patch.object(self.runner, 'snapshot', side_effect=[before, before]) as snapshot, \
                mock.patch.object(r.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(r.Refused, 'exact selected local'):
                self.runner.transaction(r.MISSING_DATABASE_CASE, repository, reject=True, missing_database=proof)
        self.assertEqual(snapshot.call_count, 2)
        self.assertEqual(self.runner.cases, [])

    def test_database_bytes_must_remain_bound_after_failed_command(self):
        repository, _, proof = self.missing_database_fixture()
        result = subprocess.CompletedProcess([], 1, self.missing_database_output().encode())
        def mutate(*args, **kwargs):
            (repository / 'integration.db.tar.gz').write_bytes(b'changed during negative transaction')
            return result
        with mock.patch.object(r.subprocess, 'run', side_effect=mutate):
            with self.assertRaises(r.Refused):
                self.runner.pacman(r.MISSING_DATABASE_CASE, ['-Syyu', '--noscriptlet'], reject=True, missing_database=proof)

    def test_missing_database_diagnostic_cannot_replace_nonzero_exit_requirement(self):
        _, _, proof = self.missing_database_fixture()
        result = subprocess.CompletedProcess([], 0, self.missing_database_output().encode())
        with mock.patch.object(r.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(r.Refused, 'unexpected exit 0'):
                self.runner.pacman(r.MISSING_DATABASE_CASE, ['-Syyu', '--noscriptlet'], reject=True, missing_database=proof)

    def test_typed_missing_database_negative_still_rejects_inventory_or_payload_mutation(self):
        repository, _, proof = self.missing_database_fixture()
        before = ({'runtime': '1-1'}, {'owned': {'type': 'regular', 'sha256': 'a' * 64}})
        after = ({'runtime': '2-1'}, {'owned': {'type': 'regular', 'sha256': 'b' * 64}})
        result = subprocess.CompletedProcess([], 1, self.missing_database_output().encode())
        with mock.patch.object(self.runner, 'snapshot', side_effect=[before, after]), \
                mock.patch.object(r.subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(r.Refused, 'changed inventory/payload'):
                self.runner.transaction(r.MISSING_DATABASE_CASE, repository, reject=True, missing_database=proof)
        self.assertEqual(self.runner.cases, [])

    def test_negative_transaction_cannot_change_installed_state(self):
        before = ('fixture 1-1\n', {'path': {'sha256': 'a' * 64}})
        after = ('fixture 2-1\n', {'path': {'sha256': 'b' * 64}})
        with mock.patch.object(self.runner, 'snapshot', side_effect=[before, after]), \
             mock.patch.object(self.runner, 'select'), mock.patch.object(self.runner, 'pacman'):
            with self.assertRaisesRegex(r.Refused, 'changed inventory/payload'):
                self.runner.transaction('rejected', Path('/unused'), reject=True)

    def test_pacman_targets_only_copied_root_private_config_and_keyring(self):
        self.runner.target = self.base / 'scratch/system'
        self.runner.config = self.base / 'scratch/pacman.conf'
        self.runner.keys['verifier'] = {'home': self.runner.home / 'verifier'}
        with mock.patch.object(self.runner, 'command', return_value='') as call:
            self.runner.pacman('install', ['-Syyu', '--noscriptlet', 'fixture'])
        argv = [str(x) for x in call.call_args.args[1]]
        self.assertEqual(argv[argv.index('--root') + 1], str(self.runner.target))
        self.assertEqual(argv[argv.index('--gpgdir') + 1], str(self.runner.home / 'verifier'))
        self.assertFalse(any(x in argv for x in ('--nodeps', '--overwrite', '--dbonly', '/etc/pacman.conf')))

    def test_copied_base_inventory_has_cache_before_repository_selection(self):
        # Real read-only pacman query against a tiny private copied-root fixture.
        # Before the fix, copy_base left --cachedir absent and this query failed.
        if not shutil.which('pacman'):
            self.skipTest('read-only copied-root query requires installed pacman')
        self.runner.target = self.runner.scratch / 'system'
        self.runner.config = self.runner.scratch / 'pacman.conf'
        verifier = self.runner.home / 'verifier'
        verifier.mkdir()
        self.runner.keys['verifier'] = {'home': verifier}
        calls = []
        def copied(source, target, **options):
            calls.append(source)
            target.mkdir()
            if source == '/var/lib/pacman/local':
                (target / 'ALPM_DB_VERSION').write_bytes(Path('/var/lib/pacman/local/ALPM_DB_VERSION').read_bytes())
                package = target / 'runtime-1-1'
                package.mkdir()
                (package / 'desc').write_text('%NAME%\nruntime\n\n%VERSION%\n1-1\n\n%ARCH%\nany\n\n')
        with mock.patch.object(r.os, 'walk', return_value=[]), mock.patch.object(r.shutil, 'copytree', side_effect=copied):
            self.runner.copy_base()
        self.assertEqual(calls, ['/usr', '/etc', '/var/lib/pacman/local'])
        self.assertFalse((self.runner.scratch / 'repos').exists())
        self.assertEqual(self.runner.pacman('copied-base-inventory', ['-Q']), 'runtime 1-1\n')
        self.assertEqual((self.runner.out / self.runner.receipts[-1]['log']).read_text(), 'runtime 1-1\n')
        self.assertEqual((self.runner.out / self.runner.receipts[-1]['stderr_log']).read_text(), '')
        self.assertNotIn('[integration]', self.runner.query_config.read_text())
        self.assertIn('Required TrustedOnly', self.runner.query_config.read_text())
        self.assertTrue((self.runner.scratch / 'cache').is_dir())
        self.assertEqual(list((self.runner.scratch / 'cache').iterdir()), [])
        config = self.runner.config.read_text()
        self.assertIn('SigLevel = Required TrustedOnly', config)
        self.assertIn('LocalFileSigLevel = Required TrustedOnly', config)
        argv = self.runner.receipts[-1]['argv']
        self.assertEqual(argv[argv.index('--cachedir') + 1], str(self.runner.scratch / 'cache'))
        self.assertEqual(argv[argv.index('--dbpath') + 1], str(self.runner.target / 'var/lib/pacman'))

    def test_exit_zero_unchanged_upgrade_cannot_pass(self):
        self.runner.base_versions = {'runtime': '1'}
        self.runner.owned = {r.PAYLOAD}
        expected = {name: {'name': name, 'version': '2-1', 'payload_sha256': {}} for name in r.ORIGINALS}
        old = '\n'.join(['runtime 1', f'{r.FIXTURE} 1-1', *[f'{name} 1-1' for name in sorted(r.ORIGINALS)]]) + '\n'
        unchanged = (old, {r.PAYLOAD: {'sha256': 'a' * 64}})
        with mock.patch.object(self.runner, 'snapshot', side_effect=[unchanged, unchanged]), \
             mock.patch.object(self.runner, 'select'), mock.patch.object(self.runner, 'pacman', return_value=old):
            with self.assertRaisesRegex(r.Refused, 'installed package versions'):
                self.runner.transaction('trusted-original-upgrade', Path('/unused'),
                                        expected_packages=expected, fixture_version='2-1')
        self.assertEqual(self.runner.cases, [])

    def test_original_payload_and_base_inventory_must_match(self):
        self.runner.base_versions = {'runtime': '1'}
        self.runner.target = self.base / 'target'
        self.runner.target.mkdir()
        expected = {name: {'name': name, 'version': '2-1', 'payload_sha256': {f'usr/share/{name}.txt': '0' * 64},
                          'payload_metadata': {f'usr/share/{name}.txt': {'mode': 0o644, 'uid': os.geteuid(), 'gid': os.getegid()}}}
                    for name in r.ORIGINALS}
        self.runner.owned = {r.PAYLOAD, *[f'usr/share/{name}.txt' for name in r.ORIGINALS]}
        inventory = '\n'.join(['runtime 1', f'{r.FIXTURE} 2-1', *[f'{name} 2-1' for name in sorted(r.ORIGINALS)]]) + '\n'
        def query(label, options, **kwargs):
            if options == ['-Q']:return inventory
            return f'{options[1]} {self.runner.target}/usr/share/{options[1]}.txt\n'
        with mock.patch.object(self.runner, 'pacman', side_effect=query):
            with self.assertRaisesRegex(r.Refused, 'installed payload differs'):
                self.runner.installed(expected, '2-1')
        with mock.patch.object(self.runner, 'pacman', return_value=inventory.replace('runtime 1', 'runtime 2')):
            with self.assertRaisesRegex(r.Refused, 'complete (reviewed transaction|accepted baseline)'):
                self.runner.installed(expected, '2-1')

    def test_root_prefixed_owned_payloads_are_verified(self):
        self.runner.base_versions = {'runtime': '1'}
        self.runner.target = self.base / 'target'
        self.runner.target.mkdir()
        expected = {}
        for name in r.ORIGINALS:
            rel = f'usr/share/{name}.txt'
            path = self.runner.target / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('TEST payload')
            info = path.lstat()
            expected[name] = {'name': name, 'version': '2-1', 'payload_sha256': {rel: r.sha(path)},
                              'payload_metadata': {rel: {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}}}
        self.runner.owned = {r.PAYLOAD, *[f'usr/share/{name}.txt' for name in r.ORIGINALS]}
        inventory = '\n'.join(['runtime 1', f'{r.FIXTURE} 2-1', *[f'{name} 2-1' for name in sorted(r.ORIGINALS)]]) + '\n'
        def query(label, options, **kwargs):
            if options == ['-Q']:return inventory
            return f'{options[1]} {self.runner.target}/usr/share/{options[1]}.txt\n'
        with mock.patch.object(self.runner, 'pacman', side_effect=query):
            self.runner.installed(expected, '2-1')
        share = self.runner.target / 'usr/share'
        outside = self.base / 'outside-payload'
        share.rename(outside)
        share.symlink_to(outside, target_is_directory=True)
        with mock.patch.object(self.runner, 'pacman', side_effect=query):
            with self.assertRaisesRegex(r.Refused, 'installed payload differs'):
                self.runner.installed(expected, '2-1')
        with mock.patch.object(self.runner, 'pacman', side_effect=lambda label, opts: inventory if opts == ['-Q'] else f'{opts[1]} /usr/share/escape.txt\n'):
            with self.assertRaisesRegex(r.Refused, 'ownership path escapes'):
                self.runner.installed(expected, '2-1')

    def test_rejected_transaction_detects_identical_symlink_target(self):
        self.runner.target = self.base / 'target'
        payload = self.runner.target / 'usr/share/cachy-asahi/probe'
        payload.parent.mkdir(parents=True)
        payload.write_text('same TEST bytes')
        alternate = self.base / 'alternate'
        alternate.write_bytes(payload.read_bytes())
        alternate.chmod(stat.S_IMODE(payload.stat().st_mode))
        self.runner.owned = {'usr/share/cachy-asahi/probe'}
        def pacman(label, options, **kwargs):
            if label == 'rejected-type-change':
                payload.unlink()
                payload.symlink_to(alternate)
            return 'runtime 1\n'
        with mock.patch.object(self.runner, 'pacman', side_effect=pacman), mock.patch.object(self.runner, 'select'):
            with self.assertRaisesRegex(r.Refused, 'changed inventory/payload'):
                self.runner.transaction('rejected-type-change', Path('/unused'), reject=True)
        self.assertTrue(payload.is_symlink())
        self.assertEqual(self.runner.cases, [])
        before = json.loads((self.runner.out / 'rejected-type-change-before-snapshot.json').read_text())
        after = json.loads((self.runner.out / 'rejected-type-change-after-snapshot.json').read_text())
        self.assertEqual(before['files']['usr/share/cachy-asahi/probe']['type'], 'regular')
        self.assertEqual(after['files']['usr/share/cachy-asahi/probe']['type'], 'symlink')

    def test_owned_states_distinguish_missing_directory_and_symlink_parent(self):
        target = self.base / 'target'
        target.mkdir()
        self.assertEqual(r.owned_state(target, 'probe'), {'type': 'missing'})
        (target / 'probe').mkdir()
        self.assertEqual(r.owned_state(target, 'probe')['type'], 'directory')
        (target / 'probe').rmdir()
        (target / 'probe').symlink_to('missing')
        self.assertEqual(r.owned_state(target, 'probe')['type'], 'symlink')
        self.assertEqual(r.owned_state(target, 'probe/child')['type'], 'blocked-parent')

    def test_archive_metadata_preserves_special_permissions_and_numeric_owners(self):
        self.assertEqual(r.archive_metadata('-rwxr-xr-x  0 123 456 9 Oct 11 2026 payload'),
                         {'mode': 0o755, 'uid': 123, 'gid': 456})
        self.assertEqual(r.archive_metadata('-rwSr-Sr-T  0 0 0 9 Oct 11 2026 payload')['mode'], 0o7644)
        with self.assertRaises(r.Refused):r.archive_metadata('-rw-r--r--  0 root root 9 Oct 11 2026 payload')

    def test_actual_archive_header_modes_and_owners_are_retained(self):
        if not shutil.which('bsdtar'):
            self.skipTest('preinstalled bsdtar required for read-only archive-header case')
        path = self.base / 'cachy-asahi-setup-2-1-any.pkg.tar.gz'
        with tarfile.open(path, 'w:gz') as package:
            for name, data, mode in (('.PKGINFO', b'pkgname = cachy-asahi-setup\npkgver = 2-1\narch = any\nlicense = MIT\n', 0o644),
                                     ('usr/bin/cachy-asahi-setup', b'#!/bin/sh\n# TEST ONLY\n', 0o755)):
                member = tarfile.TarInfo(name)
                member.size, member.mode, member.uid, member.gid = len(data), mode, 123, 456
                package.addfile(member, io.BytesIO(data))
        inspected = self.runner.metadata(path)
        self.assertEqual(inspected['payload_metadata']['usr/bin/cachy-asahi-setup'], {'mode': 0o755, 'uid': 123, 'gid': 456})
        self.assertEqual(inspected['payload_sha256']['usr/bin/cachy-asahi-setup'], hashlib.sha256(b'#!/bin/sh\n# TEST ONLY\n').hexdigest())

    def test_successful_setup_payload_rejects_mode_and_owner_changes(self):
        self.runner.target = self.base / 'target'
        self.runner.base_versions = {'runtime': '1'}
        packages = {}
        for name in r.ORIGINALS:
            relative = 'usr/bin/cachy-asahi-setup' if name == 'cachy-asahi-setup' else f'usr/share/{name}/config'
            path = self.runner.target / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('reviewed TEST bytes')
            path.chmod(0o755 if name == 'cachy-asahi-setup' else 0o644)
            info = path.lstat()
            packages[name] = {'name': name, 'version': '2-1', 'payload_sha256': {relative: r.sha(path)},
                'payload_metadata': {relative: {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}}}
        self.runner.owned = {r.PAYLOAD, *[next(iter(p['payload_sha256'])) for p in packages.values()]}
        probe = self.runner.target / r.PAYLOAD
        probe.parent.mkdir(parents=True)
        probe.write_text('SYNTHETIC TEST fixture version 2\n')
        inventory = '\n'.join(['runtime 1', f'{r.FIXTURE} 2-1', *[f'{name} 2-1' for name in sorted(r.ORIGINALS)]]) + '\n'
        def pacman(label, options, **kwargs):
            if options == ['-Q']:return inventory
            if options[0] == '-Ql':
                return ''.join(f'{options[1]} {self.runner.target / path}\n' for path in packages[options[1]]['payload_sha256'])
            return ''
        helper = self.runner.target / 'usr/bin/cachy-asahi-setup'
        with mock.patch.object(self.runner, 'pacman', side_effect=pacman), mock.patch.object(self.runner, 'select'):
            self.runner.installed(packages, '2-1')
            for mode in (0o600, 0o644):
                helper.chmod(mode)
                with self.subTest(mode=mode), self.assertRaisesRegex(r.Refused, 'mode/uid/gid'):
                    self.runner.transaction('bad-setup-permission', Path('/unused'), expected_packages=packages, fixture_version='2-1')
                self.assertEqual(self.runner.cases, [])
            helper.chmod(0o755)
            original = r.owned_state(self.runner.target, 'usr/bin/cachy-asahi-setup')
            for field in ('uid', 'gid'):
                # Mock observed lstat owner only: no privileged host chown is performed.
                def changed_owner(target, name):
                    value = dict(original, **{field: original[field] + 1}) if name == 'usr/bin/cachy-asahi-setup' else original_state(target, name)
                    return value
                original_state = r.owned_state
                with self.subTest(field=field), mock.patch.object(r, 'owned_state', side_effect=changed_owner):
                    with self.assertRaisesRegex(r.Refused, 'mode/uid/gid'):
                        self.runner.transaction('bad-setup-owner', Path('/unused'), expected_packages=packages, fixture_version='2-1')
                self.assertEqual(self.runner.cases, [])

    def test_public_repository_export_has_no_symlinks(self):
        repo = self.runner.scratch / 'repos/baseline-A'
        repo.mkdir(parents=True)
        (repo / 'integration.db.tar.gz').write_bytes(b'TEST public database')
        (repo / 'integration.db').symlink_to('integration.db.tar.gz')
        (repo.parent / 'active').symlink_to('baseline-A')
        with mock.patch.object(self.runner, 'sign'):
            self.runner.export_public_repositories()
        export = self.runner.out / 'TEST-repositories'
        self.assertFalse(any(p.is_symlink() for p in export.rglob('*')))
        self.assertEqual((export / 'baseline-A/integration.db').read_bytes(), b'TEST public database')
        aliases = json.loads((self.runner.out / 'TEST-repository-aliases.json').read_text())
        self.assertEqual(aliases['active']['kind'], 'directory')
        self.assertEqual(aliases['baseline-A/integration.db']['regular_copy_sha256'], r.sha(export / 'baseline-A/integration.db'))

    def test_unsigned_probe_keeps_database_and_original_signature_requirements(self):
        package, probe = self.base / 'original.pkg.tar.xz', self.base / 'probe.pkg.tar.xz'
        package.write_bytes(b'original TEST bytes')
        probe.write_bytes(b'probe TEST bytes')
        key = 'B' * 40
        self.runner.keys['signer-B'] = {'home': self.runner.home / 'signer-B', 'fingerprint': key}
        valid = f'[GNUPG:] VALIDSIG {key} 2026-10-11 1791748800 0 4 0 22 8 00 {key}\n'
        def command(label, argv, **kwargs):
            if label.startswith('repo-add-'):
                for name in ('integration.db.tar.gz', 'integration.files.tar.gz'):
                    (Path(argv[5]).parent / name).write_bytes(b'public TEST database')
            return valid
        def sign(path, signer):
            Path(str(path) + '.sig').write_bytes(b'public TEST signature')
        with mock.patch.object(self.runner, 'command', side_effect=command), \
             mock.patch.object(self.runner, 'sign', side_effect=sign):
            repo = self.runner.repository('missing-probe', {'original': {'path': package}}, probe, 'signer-B',
                                          omit_fixture_signature=True)
        self.assertFalse(Path(str(repo / probe.name) + '.sig').exists())
        for path in (repo / package.name, repo / 'integration.db.tar.gz', repo / 'integration.files.tar.gz'):
            self.assertTrue(Path(str(path) + '.sig').is_file())

    def test_strict_inventory_rejects_prompt_duplicate_diagnostic_and_malformed_rows(self):
        self.assertEqual(r.package_inventory('runtime 1-1\nlibsecret 1:0.21-1\n'), {'runtime': '1-1', 'libsecret': '1:0.21-1'})
        for value in ('runtime 1-1', '', 'runtime 1-1\n\n', 'runtime 1-1\r\n', 'runtime\t1-1\n',
                      'runtime 1-1\nruntime 1-1\n', ':: Import PGP key TEST? [Y/n]\nruntime 1-1\n',
                      'runtime 1-1\nwarning: integration is unavailable\n', 'runtime 1-1 extra\n'):
            with self.subTest(value=value), self.assertRaises(r.Refused):r.package_inventory(value)
        with self.assertRaises(r.Refused):r.package_inventory(''.join(f'pkg{i} 1-1\n' for i in range(2049)))

    def test_inventory_stdout_and_raw_stderr_are_separate_hash_bound_receipts(self):
        stdout = b'runtime 1-1\n'
        stderr = b'warning: database unavailable\nunknown-key diagnostic\xff\n'
        result = subprocess.CompletedProcess(['mock'], 0, stdout, stderr)
        with mock.patch.object(r.subprocess, 'run', return_value=result) as call:
            actual = self.runner.command('local-inventory', ['pacman', '-Q'], stdout_only=True)
        self.assertEqual(actual, stdout.decode())
        self.assertEqual(call.call_args.kwargs['stderr'], subprocess.PIPE)
        receipt = self.runner.receipts[-1]
        self.assertEqual((self.runner.out / receipt['log']).read_bytes(), stdout)
        self.assertEqual((self.runner.out / receipt['stderr_log']).read_bytes(), stderr)
        self.assertEqual(receipt['stderr_sha256'], r.sha(self.runner.out / receipt['stderr_log']))

    def test_local_queries_never_load_sync_config_and_transactions_keep_it(self):
        self.runner.target = self.runner.scratch / 'system'
        self.runner.keys['verifier'] = {'home': self.runner.home / 'verifier'}
        for operation in ('-Q', '-Ql', '-Qk', '-Dk', '-Syyu', '-Syyuu'):
            with mock.patch.object(self.runner, 'command', return_value='') as call:
                self.runner.pacman('config-test', [operation])
            argv = call.call_args.args[1]
            local = operation in {'-Q', '-Ql', '-Qk', '-Dk'}
            self.assertEqual(argv[argv.index('--config') + 1], self.runner.query_config if local else self.runner.config)
            self.assertEqual(call.call_args.kwargs['stdout_only'], local)

    def test_rejected_transaction_unchanged_inventory_maps_with_changing_stderr(self):
        self.runner.base_versions = {'runtime': '1-1'}
        self.runner.owned = set()
        self.runner.target = self.runner.scratch / 'system'
        self.runner.keys['verifier'] = {'home': self.runner.home / 'verifier'}
        results = [subprocess.CompletedProcess(['mock'], 0, b'runtime 1-1\n', b'missing-db warning\n'),
                   subprocess.CompletedProcess(['mock'], 0, b'runtime 1-1\n', b'unknown PGP key diagnostic\n')]
        original = self.runner.pacman
        def query_only(label, options, **kwargs):
            if options == ['-Q']:return original(label, options, **kwargs)
            return 'invalid PGP signature (TEST rejection)'
        with mock.patch.object(r.subprocess, 'run', side_effect=results), \
                mock.patch.object(self.runner, 'pacman', side_effect=query_only), mock.patch.object(self.runner, 'select'):
            self.runner.transaction('unchanged-negative', Path('/unused'), reject=True)
        self.assertEqual(self.runner.cases[-1]['result'], 'PASS')
        diagnostics = [(self.runner.out / row['stderr_log']).read_bytes() for row in self.runner.receipts]
        self.assertNotEqual(diagnostics[0], diagnostics[1])
        self.assertEqual(json.loads((self.runner.out / 'unchanged-negative-after-snapshot.json').read_text())['inventory'], 'runtime 1-1\n')

    def test_negative_inventory_rejects_package_change_and_valid_extra_package(self):
        self.runner.base_versions = {'runtime': '1-1'}
        for text in ('runtime 2-1\n', 'runtime 1-1\ninjected 1-1\n', 'other 1-1\n'):
            with mock.patch.object(self.runner, 'pacman', return_value=text):
                with self.assertRaisesRegex(r.Refused, 'complete accepted baseline'):self.runner.inventory('negative')

    def test_gpg_exit_two_is_explicit_nonzero_rejection_with_diagnostic_retained(self):
        result = subprocess.CompletedProcess(['gpg'], 2, b'[GNUPG:] NO_PUBKEY TEST\ngpg: no public key\n')
        with mock.patch.object(r.subprocess, 'run', return_value=result):
            self.runner.command('unknown-key', ['gpg'], expected='nonzero', signature_failure=True)
        self.assertEqual(self.runner.receipts[-1]['expected'], 'nonzero')
        self.assertEqual(self.runner.receipts[-1]['exit_code'], 2)
        result.returncode = 0
        with mock.patch.object(r.subprocess, 'run', return_value=result):
            with self.assertRaises(r.Refused):self.runner.command('unexpected-success', ['gpg'], expected='nonzero')

    def test_real_signed_repo_add_uses_private_scratch_tmp_and_cleans_it(self):
        if not all(shutil.which(tool) for tool in ('gpg', 'gpgconf', 'repo-add')):
            self.skipTest('real signed repository fixture requires preinstalled GPG/repo-add')
        key = self.runner.key('signer-A', 'sign')
        self.addCleanup(self.runner.cleanup)
        (key['home'] / 'gpg.conf').write_text(f"no-default-keyring\nkeyring {key['home']}/pubring.gpg\nno-auto-key-retrieve\nauto-key-locate clear\n")
        original = self.base / 'cachy-asahi-setup-1-1-any.pkg.tar.gz'
        with tarfile.open(original, 'w:gz') as archive:
            for name, data in (('.PKGINFO', b'pkgname = cachy-asahi-setup\npkgver = 1-1\narch = any\nlicense = MIT\n'),
                               ('usr/bin/cachy-asahi-setup', b'#!/bin/sh\n# TEST ONLY\n')):
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        probe = self.base / f'{r.FIXTURE}-1-1-any.pkg.tar.xz'
        r.fixture(probe, '1-1', 'SYNTHETIC TEST ONLY\n')
        execute, temps = self.runner.command, []
        def observe(label, argv, **options):
            if label.startswith('repo-add-'):
                directory = Path(options['env']['TMPDIR'])
                self.assertTrue(directory.is_dir())
                self.assertEqual(directory.parent, self.runner.scratch)
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
                self.assertEqual(options['env']['GNUPGHOME'], str(key['home']))
                temps.append(directory)
            return execute(label, argv, **options)
        with mock.patch.dict(os.environ, {'TMPDIR': str(self.base / 'unavailable-global-tmp')}), \
                mock.patch.object(self.runner, 'command', side_effect=observe):
            repo = self.runner.repository('real-temp-fixture', {'original': {'path': original}}, probe, 'signer-A')
        self.assertEqual(len(temps), 1)
        self.assertFalse(temps[0].exists())
        for name in ('integration.db.tar.gz', 'integration.files.tar.gz'):
            self.assertTrue((repo / name).is_file())
            self.assertTrue(Path(str(repo / name) + '.sig').is_file())
        self.assertTrue((repo / 'integration.db').is_symlink())
        self.assertEqual([x['exit_code'] for x in self.runner.receipts if x['label'].startswith('verify-database-')], [0, 0])

    def test_repo_add_failure_removes_its_private_scratch_tmp(self):
        package = self.base / 'fixture.pkg.tar.xz'
        package.write_bytes(b'TEST-only archive bytes')
        self.runner.keys['signer-A'] = {'home': self.runner.home / 'signer-A', 'fingerprint': 'A' * 40}
        temps = []
        def fail(label, argv, **options):
            self.assertTrue(label.startswith('repo-add-'))
            directory = Path(options['env']['TMPDIR'])
            self.assertEqual(directory.parent, self.runner.scratch)
            (directory / 'partial').write_text('TEST temporary state')
            temps.append(directory)
            raise r.Refused('TEST repo-add failure')
        with mock.patch.object(self.runner, 'sign'), mock.patch.object(self.runner, 'command', side_effect=fail):
            with self.assertRaisesRegex(r.Refused, 'TEST repo-add failure'):
                self.runner.repository('failed-temp-fixture', {}, package, 'signer-A')
        self.assertEqual(len(temps), 1)
        self.assertFalse(temps[0].exists())

    def test_private_state_cleanup_including_partial_revocation(self):
        home = self.runner.home / 'signer-A'
        (home / 'private-keys-v1.d').mkdir(parents=True)
        (home / 'private-keys-v1.d/TEST.key').write_bytes(b'private fixture bytes')
        (self.runner.home / 'TEST-revocation.asc').write_bytes(b'private revocation fixture')
        with mock.patch.object(r.subprocess, 'run', side_effect=subprocess.TimeoutExpired('gpgconf', 30)):
            self.runner.cleanup()
        self.assertEqual(list(self.runner.home.iterdir()), [])
        self.assertTrue(self.runner.result['test_private_state_removed'])
        self.assertEqual(list(self.runner.out.iterdir()), [])

    def test_cleanup_failure_cannot_record_pass(self):
        home = self.runner.home / 'signer-A'
        home.mkdir()
        with mock.patch.object(r.subprocess, 'run'), mock.patch.object(r.shutil, 'rmtree', side_effect=PermissionError('TEST cleanup denied')):
            with self.assertRaisesRegex(r.Refused, 'private TEST state cleanup failed'):
                self.runner.cleanup()
        self.assertFalse(self.runner.result['test_private_state_removed'])
        with mock.patch.object(self.runner, 'inputs', side_effect=r.Refused('TEST input failure')), \
             mock.patch.object(self.runner, 'cleanup', side_effect=PermissionError('TEST cleanup denied')):
            with self.assertRaisesRegex(r.Refused, 'private TEST state cleanup failed'):
                self.runner.execute()
        result = json.loads((self.runner.out / 'result.json').read_text())
        self.assertEqual(result['status'], 'FAIL')
        self.assertFalse(result['test_private_state_removed'])
        self.assertIn('TEST cleanup denied', result['cleanup_error'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
