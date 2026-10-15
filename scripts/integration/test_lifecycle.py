# SPDX-License-Identifier: MIT
"""Trust/failure fixtures only; never run pacman, useradd or a real lifecycle locally."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import time
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('virtual_lifecycle', Path(__file__).with_name('lifecycle.py'))
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)


def probe():
    return {'uid': 0, 'arch': 'aarch64', 'caps': lifecycle.SAFE_CAPS, 'privileges': {name: lifecycle.SAFE_CAPS for name in ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb')} | {'NoNewPrivs': 1}, 'device_exposure': False, 'docker_marker': True, 'interfaces': ['lo'], 'docker_socket': False,
            'nonce': 'a' * 32, 'image_id': 'sha256:' + 'b' * 64,
            'mask_nodes': {}, 'mounts': {'/': {'fs': 'overlay', 'options': ['rw']},
                       '/inputs': {'fs': 'ext4', 'options': ['ro']},
                       '/out': {'fs': 'ext4', 'options': ['rw']},
                       '/runner': {'fs': 'ext4', 'options': ['ro']},
                       '/etc/hosts': {'fs': 'ext4', 'options': ['rw']},
                       '/proc': {'fs': 'proc', 'options': ['rw', 'nosuid', 'nodev', 'noexec']},
                       '/sys': {'fs': 'sysfs', 'options': ['ro', 'nosuid', 'nodev', 'noexec']},
                       '/dev': {'fs': 'tmpfs', 'options': ['rw', 'nosuid']}}}


def contract():
    result = {'schema_version': 1, 'execution': 'native-aarch64-disposable-docker', 'allow_system_mutation': True,
              'daemon_arch': 'aarch64', 'nonce': 'a' * 32, 'image_id': 'sha256:' + 'b' * 64,
              'source_commit': 'c' * 40, 'signing_key_fingerprint': 'D' * 40,
              'pacman_conf': 'pacman.conf', 'pacman_conf_sha256': 'e' * 64, 'public_cert': 'signing/test-key.asc',
              'public_cert_sha256': '2' * 64, 'baseline_handoff': False, 'baseline': [], 'upgrade': []}
    for stage, version, byte in (('baseline', '1-1', 'f'), ('upgrade', '1-2', 'a')):
        for name, component in lifecycle.PACKAGES.items():
            path = lifecycle.PRIMARY_FILES[name]
            result[stage].append({'name': name, 'version': version,
                'archive': stage + '/' + name + '.pkg.tar.gz', 'sha256': byte * 64,
                'signature_sha256': '1' * 64, 'payload_sha256': {path: byte * 64}})
    next(r for r in result['baseline'] if r['name'] == 'cachy-asahi-setup')['payload_sha256']['usr/bin/cachy-asahi-setup'] = lifecycle.BASELINE_HELPER_SHA256
    return result


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='lifecycle-safety-fixture-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_valid_disposable_contract_and_probe(self):
        lifecycle.validate_contract(contract())
        lifecycle.environment_guard(probe(), 'a' * 32, 'sha256:' + 'b' * 64)

    def test_host_marker_uid_arch_network_socket_and_identity_failures(self):
        invalid = {'docker_marker': False, 'uid': 1000, 'arch': 'x86_64', 'interfaces': ['eth0', 'lo'],
                   'docker_socket': True, 'caps': 1 << 21, 'device_exposure': True, 'nonce': None, 'image_id': 'latest'}
        for key, value in invalid.items():
            p = probe()
            p[key] = value
            with self.subTest(key=key), self.assertRaises(lifecycle.Error):
                lifecycle.environment_guard(p)
        with self.assertRaises(lifecycle.Error):
            lifecycle.environment_guard(probe(), '0' * 32, 'sha256:' + 'b' * 64)

    def test_sensitive_system_mounts_block_before_mutation(self):
        for path in ('/etc', '/etc/passwd', '/usr', '/usr/bin', '/var/lib/pacman', '/home', '/tmp', '/tmp/user', '/root'):
            p = probe()
            p['mounts'][path] = {'fs': 'ext4', 'options': ['rw']}
            with self.subTest(path=path), self.assertRaisesRegex(lifecycle.Error, 'system-path mount'):
                lifecycle.environment_guard(p)
        p = probe()
        p['mounts']['/tmp'] = {'fs': 'tmpfs', 'options': ['rw', 'nosuid', 'nodev']}
        lifecycle.environment_guard(p)

    def test_overlay_and_fixed_mount_flags_required(self):
        for path, field, value in (('/', 'fs', 'ext4'), ('/', 'options', ['ro']),
                                   ('/inputs', 'options', ['rw']), ('/runner', 'options', ['rw']),
                                   ('/out', 'options', ['ro'])):
            p = probe()
            p['mounts'][path][field] = value
            with self.assertRaises(lifecycle.Error):
                lifecycle.environment_guard(p)
        p = probe()
        del p['mounts']['/inputs']
        with self.assertRaises(lifecycle.Error):
            lifecycle.environment_guard(p)

    def test_mount_parser_decodes_escaped_paths(self):
        data = '31 22 0:2 / / rw,relatime - overlay overlay rw\n32 31 0:3 / /home/user\\040files rw - ext4 /dev/fixture rw\n'
        parsed = lifecycle.mounts(data)
        self.assertIn('/home/user files', parsed)
        self.assertEqual(parsed['/']['fs'], 'overlay')
        with self.assertRaises(lifecycle.Error):
            lifecycle.mounts('not mountinfo')

    def test_contract_requires_exact_real_package_set_and_changed_upgrade(self):
        for mutation in ('missing', 'duplicate', 'same-archive', 'same-version', 'same-payload', 'no-mutation', 'not-native'):
            value = contract()
            if mutation == 'missing': value['baseline'].pop()
            if mutation == 'duplicate': value['baseline'][-1] = value['baseline'][0]
            if mutation == 'same-archive': value['upgrade'][0]['sha256'] = value['baseline'][0]['sha256']
            if mutation == 'same-version': value['upgrade'][0]['version'] = value['baseline'][0]['version']
            if mutation == 'same-payload': value['upgrade'][0]['payload_sha256'] = value['baseline'][0]['payload_sha256']
            if mutation == 'no-mutation': value['allow_system_mutation'] = False
            if mutation == 'not-native': value['daemon_arch'] = 'x86_64'
            with self.subTest(mutation=mutation), self.assertRaises(lifecycle.Error):
                lifecycle.validate_contract(value)

    def test_contract_rejects_escaping_paths_payloads_and_bad_pins(self):
        for path in ('../archive.pkg.tar.gz', '/archive.pkg.tar.gz', 'baseline/../archive.pkg.tar.gz', 'baseline//archive.pkg.tar.gz', 'baseline/archive.pkg.tar.bz2'):
            value = contract()
            value['baseline'][0]['archive'] = path
            with self.assertRaises(lifecycle.Error):
                lifecycle.validate_contract(value)
        value = contract()
        value['baseline'][0]['payload_sha256'] = {'etc/pacman.conf': '1' * 64}
        with self.assertRaises(lifecycle.Error):
            lifecycle.validate_contract(value)
        value = contract()
        value['baseline'][0]['signature_sha256'] = 'short'
        with self.assertRaises(lifecycle.Error):
            lifecycle.validate_contract(value)

    def test_pins_reject_tampered_symlink_and_hardlink_inputs(self):
        path = self.root / 'input'
        path.write_bytes(b'original')
        digest = lifecycle.sha(path)
        self.assertEqual(lifecycle.pinned(self.root, 'input', digest), path)
        path.write_bytes(b'changed')
        with self.assertRaises(lifecycle.Error): lifecycle.pinned(self.root, 'input', digest)
        path.unlink()
        outside = self.root / 'outside'
        outside.write_bytes(b'original')
        path.symlink_to(outside)
        with self.assertRaises(lifecycle.Error): lifecycle.pinned(self.root, 'input', digest)
        path.unlink()
        os.link(outside, path)
        with self.assertRaises(lifecycle.Error): lifecycle.pinned(self.root, 'input', digest)

    def test_pacman_config_requires_signatures_masks_and_no_include_repo(self):
        valid = '[options]\nArchitecture = aarch64\nSigLevel = Required\nLocalFileSigLevel = Required\nHookDir = /builder-disabled-hooks\nGPGDir = /tmp/cachy-asahi-lifecycle-keyring-' + 'a' * 32 + '\n'
        lifecycle.validate_pacman_conf(valid, 'a' * 32)
        for text in (valid.replace('LocalFileSigLevel = Required', 'LocalFileSigLevel = Optional'),
                     valid.replace('SigLevel = Required', 'SigLevel = Never'),
                     valid.replace('HookDir = /builder-disabled-hooks\nGPGDir = /tmp/cachy-asahi-lifecycle-keyring-' + 'a' * 32 + '\n', ''),
                     valid + 'Include = /etc/pacman.conf\n', valid + '[core]\n',
                     valid + 'GPGDir = /home/user/.gnupg\n', valid + 'SigLevel = Required\n'):
            with self.assertRaises(lifecycle.Error): lifecycle.validate_pacman_conf(text, 'a' * 32)

    def archive(self, extra=None, mode=0o644, owner=0):
        row = contract()['baseline'][0]
        payload = next(iter(row['payload_sha256']))
        contents = {'.PKGINFO': f"pkgname = {row['name']}\npkgver = {row['version']}\narch = any\nlicense = MIT\n".encode(),
                    '.BUILDINFO': b'format = 2\n', '.MTREE': b'mtree fixture', payload: b'payload'}
        contents.update(extra or {})
        row['payload_sha256'] = {payload: hashlib.sha256(b'payload').hexdigest()}
        path = self.root / 'fixture.pkg.tar.gz'
        with tarfile.open(path, 'w:gz') as archive:
            for name, data in contents.items():
                member = tarfile.TarInfo(name)
                member.size, member.mode, member.uid = len(data), mode, owner
                archive.addfile(member, io.BytesIO(data))
        return path, row

    def test_streaming_archive_binds_payload_name_version_and_scope(self):
        path, row = self.archive()
        audit = lifecycle.inspect_archive(path, row)
        self.assertEqual(set(audit['files']), set(row['payload_sha256']))
        self.assertFalse((self.root / 'usr').exists())
        for key, value in (('version', 'wrong-version'), ('payload_sha256', {next(iter(row['payload_sha256'])): '0' * 64})):
            changed = dict(row, **{key: value})
            with self.assertRaises(lifecycle.Error): lifecycle.inspect_archive(path, changed)
        for extra in ({'.INSTALL': b'commands'}, {'etc/pacman.conf': b'override'}, {'../outside': b'escape'}):
            path, row = self.archive(extra)
            with self.assertRaises(lifecycle.Error): lifecycle.inspect_archive(path, row)

    def test_archive_ownership_modes_elf_special_and_platform_directories(self):
        for mode, owner in ((0o4755, 0), (0o666, 0), (0o644, 1000)):
            path, row = self.archive(mode=mode, owner=owner)
            with self.assertRaises(lifecycle.Error): lifecycle.inspect_archive(path, row)
        path, row = self.archive()
        payload = next(iter(row['payload_sha256']))
        path, row = self.archive({payload: b'\x7fELFfake'})
        with self.assertRaises(lifecycle.Error): lifecycle.inspect_archive(path, row)
        for kind, name in ((tarfile.SYMTYPE, payload), (tarfile.DIRTYPE, 'usr/lib/modules')):
            path, row = self.archive()
            raw = self.root / 'special.pkg.tar'
            with tarfile.open(path) as source, tarfile.open(raw, 'w') as target:
                for member in source:
                    target.addfile(member, source.extractfile(member))
                member = tarfile.TarInfo(name)
                member.type = kind
                member.mode = 0o755
                member.linkname = '/etc'
                target.addfile(member)
            with self.assertRaises(lifecycle.Error): lifecycle.inspect_archive(raw, row)

    def test_no_execution_switch_means_no_probe_commands_or_output(self):
        argv = ['lifecycle.py', '--contract', '/inputs/lifecycle.json', '--contract-sha256', 'a' * 64, '--output', '/out/lifecycle']
        with patch.object(lifecycle.sys, 'argv', argv), patch.object(lifecycle, 'actual_environment') as observed, \
             patch.object(lifecycle.subprocess, 'run') as execute, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(lifecycle.main(), 1)
            observed.assert_not_called()
            execute.assert_not_called()

    def test_host_refusal_happens_before_input_reads_output_and_commands(self):
        argv = ['lifecycle.py', '--execute-disposable-container', '--contract', '/inputs/lifecycle.json',
                '--contract-sha256', 'a' * 64, '--output', '/out/lifecycle']
        invalid = dict(probe(), docker_marker=False)
        with patch.object(lifecycle.sys, 'argv', argv), patch.object(lifecycle, 'actual_environment', return_value=invalid), \
             patch.object(lifecycle, 'pinned') as read, patch.object(lifecycle.subprocess, 'run') as execute, \
             patch.object(lifecycle.Path, 'mkdir') as create, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(lifecycle.main(), 1)
            read.assert_not_called(); execute.assert_not_called(); create.assert_not_called()

    def test_cached_or_claimed_probe_cannot_arm_host_command(self):
        runner = lifecycle.Lifecycle(contract(), self.root, probe())
        with patch.object(lifecycle, 'actual_environment', return_value=dict(probe(), docker_marker=False)), \
             patch.object(lifecycle.subprocess, 'run') as execute:
            with self.assertRaises(lifecycle.Error): runner.command(['pacman', '-U', 'not-real'])
            execute.assert_not_called()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_failed_package_command_retains_exit_and_log_not_success(self):
        runner = lifecycle.Lifecycle(contract(), self.root, probe())
        result = {'reason': 'exit', 'returncode': 7, 'stdout': b'fixture stdout', 'stderr': b'fixture transaction failed', 'cleanup': {'reaped': True}}
        with patch.object(lifecycle, 'actual_environment', return_value=probe()), \
             patch.object(lifecycle, 'bounded_process', return_value=result) as execute:
            with self.assertRaisesRegex(lifecycle.Error, 'command exit / exit 7'):
                runner.command(['pacman', '-U', '/inputs/not-executed.pkg.tar.gz'])
        self.assertEqual(execute.call_count, 1)
        self.assertEqual(runner.report['commands'][0]['exit_code'], 7)
        self.assertIn('fixture transaction failed', (self.root / '001.log').read_text())
        self.assertNotEqual(runner.report['status'], 'PASS')

    def test_failure_check_is_visible_and_aborts(self):
        runner = lifecycle.Lifecycle(contract(), self.root, probe())
        with self.assertRaisesRegex(lifecycle.Error, 'integration check failed'):
            runner.check('fixture-failure', False)
        self.assertEqual(runner.report['checks'], [{'check': 'fixture-failure', 'status': 'FAIL'}])

    def test_duplicate_and_nonfinite_contract_json_refused(self):
        for text in ('{"allow_system_mutation": false, "allow_system_mutation": true}', '{"value": NaN}'):
            with self.assertRaises(lifecycle.Error): lifecycle.strict_json(text)

    def test_pinned_public_certificate_and_original_helper_are_required(self):
        for key, value in (('public_cert', '/home/user/secret'), ('public_cert_sha256', 'bad'), ('baseline_handoff', 'yes')):
            changed = contract()
            changed[key] = value
            with self.assertRaises(lifecycle.Error): lifecycle.validate_contract(changed)
        changed = contract()
        row = next(r for r in changed['baseline'] if r['name'] == 'cachy-asahi-setup')
        row['payload_sha256']['usr/bin/cachy-asahi-setup'] = '0' * 64
        with self.assertRaisesRegex(lifecycle.Error, r'^reviewed strict setup 0\.1\.0-3 baseline required$'): lifecycle.validate_contract(changed)

    def test_public_cert_retarget_rejected_before_import(self):
        inputs = self.root / 'inputs'
        certificate = inputs / 'signing/test-key.asc'
        certificate.parent.mkdir(parents=True)
        certificate.write_text('-----BEGIN PGP PUBLIC KEY BLOCK-----\nfixture\n-----END PGP PUBLIC KEY BLOCK-----\n')
        value = contract()
        value['public_cert_sha256'] = lifecycle.sha(certificate)
        runner = lifecycle.Lifecycle(value, self.root, probe())
        runner.keyring = self.root / 'fixture-keyring'
        commands = []
        def fake_command(argv, **kwargs):
            commands.append([str(v) for v in argv])
            return 'pub:-:256:22:fixture:0:0::::::\nfpr:::::::::' + 'E' * 40 + ':\n'
        with patch.object(lifecycle, 'INPUT_ROOT', inputs), patch.object(runner, 'guard'), \
             patch.object(runner, 'command', side_effect=fake_command):
            with self.assertRaisesRegex(lifecycle.Error, 'fingerprint'):
                runner.prepare_keyring()
        self.assertFalse(any('--import' in argv for argv in commands))

    def test_private_certificate_refused_before_gpg_command_or_keyring_creation(self):
        inputs = self.root / 'inputs'
        certificate = inputs / 'signing/test-key.asc'
        certificate.parent.mkdir(parents=True)
        certificate.write_text('-----BEGIN PGP PRIVATE KEY BLOCK-----\nfixture\n-----END PGP PRIVATE KEY BLOCK-----\n')
        value = contract()
        value['public_cert_sha256'] = lifecycle.sha(certificate)
        runner = lifecycle.Lifecycle(value, self.root, probe())
        runner.keyring = self.root / 'fixture-keyring'
        with patch.object(lifecycle, 'INPUT_ROOT', inputs), patch.object(runner, 'guard'), \
             patch.object(runner, 'command') as commands:
            with self.assertRaisesRegex(lifecycle.Error, 'public certificate'):
                runner.prepare_keyring()
            commands.assert_not_called()
        self.assertFalse(runner.keyring.exists())

    def test_public_import_and_ownertrust_use_only_dedicated_fixture_keyring(self):
        inputs = self.root / 'inputs'
        certificate = inputs / 'signing/test-key.asc'
        certificate.parent.mkdir(parents=True)
        certificate.write_text('-----BEGIN PGP PUBLIC KEY BLOCK-----\nfixture\n-----END PGP PUBLIC KEY BLOCK-----\n')
        value = contract()
        value['public_cert_sha256'] = lifecycle.sha(certificate)
        runner = lifecycle.Lifecycle(value, self.root, probe())
        runner.keyring = self.root / 'fixture-keyring'
        commands = []
        def fake_command(argv, **kwargs):
            commands.append(([str(v) for v in argv], kwargs))
            return 'pub:-:256:22:fixture:0:0::::::\nfpr:::::::::' + 'D' * 40 + ':\n'
        with patch.object(lifecycle, 'INPUT_ROOT', inputs), patch.object(runner, 'guard'), \
             patch.object(runner, 'command', side_effect=fake_command):
            runner.prepare_keyring()
        self.assertEqual(len(commands), 4)
        for argv, kwargs in commands:
            self.assertIn(str(runner.keyring), argv)
            self.assertNotIn('/etc/pacman.d/gnupg', argv)
        self.assertEqual(next(kwargs['stdin'] for argv, kwargs in commands if '--import-ownertrust' in argv), 'D' * 40 + ':6:\n')

    def test_handoff_requires_original_install_verification_and_successful_cleanup(self):
        value = contract()
        value['baseline_handoff'] = True
        runner = lifecycle.Lifecycle(value, self.root, probe())
        order = []
        runner.results.extend({'check': name, 'status': 'PASS'} for name in lifecycle.LIFECYCLE_GATES)
        with patch.object(runner, 'guard'), \
             patch.object(runner, 'transaction', side_effect=lambda stage, remove=False: order.append(('transaction', stage, remove))), \
             patch.object(runner, 'installed', side_effect=lambda stage, label: order.append(('installed', stage, label))), \
             patch.object(runner, 'removed', side_effect=lambda stage, label: order.append(('removed', stage, label))), \
             patch.object(runner, 'cleanup', side_effect=lambda: order.append(('cleanup',))), \
             patch.object(lifecycle, 'sha', return_value=lifecycle.BASELINE_HELPER_SHA256):
            runner.finish()
        self.assertEqual(order, [('transaction', 'upgrade', True), ('removed', 'upgrade', 'final'),
                                 ('transaction', 'baseline', False), ('installed', 'baseline', 'baseline-handoff'),
                                 ('cleanup',), ('installed', 'baseline', 'clean-baseline-handoff')])
        self.assertTrue(runner.report['baseline_handoff_ready'])
        self.assertEqual(runner.report['status'], 'PASS')
        self.assertEqual(runner.report['handoff_package_versions'], {r['name']: r['version'] for r in value['baseline']})
        failed = lifecycle.Lifecycle(value, self.root, probe())
        failed.results.extend({'check': name, 'status': 'PASS'} for name in lifecycle.LIFECYCLE_GATES)
        with patch.object(failed, 'guard'), patch.object(failed, 'transaction'), patch.object(failed, 'installed'), \
             patch.object(failed, 'removed'), patch.object(failed, 'cleanup', side_effect=lifecycle.Error('fixture cleanup failed')), \
             patch.object(lifecycle, 'sha', return_value=lifecycle.BASELINE_HELPER_SHA256):
            with self.assertRaisesRegex(lifecycle.Error, 'cleanup failed'): failed.finish()
        self.assertFalse(failed.report['baseline_handoff_ready'])
        self.assertNotEqual(failed.report['status'], 'PASS')

    def test_unrun_lifecycle_cannot_publish_handoff_ready(self):
        value = contract()
        value['baseline_handoff'] = True
        runner = lifecycle.Lifecycle(value, self.root, probe())
        with patch.object(runner, 'guard'), patch.object(runner, 'transaction') as transactions:
            with self.assertRaisesRegex(lifecycle.Error, 'gates incomplete'):
                runner.finish()
            transactions.assert_not_called()
        self.assertFalse(runner.report['baseline_handoff_ready'])

    def test_account_backups_restore_without_exporting_contents_or_deleting_base_owned_files(self):
        runner = lifecycle.Lifecycle(contract(), self.root, probe())
        account = self.root / 'passwd'
        backup = self.root / 'passwd-'
        original = b'PRIVATE_BASE_ACCOUNT_DATA_DO_NOT_LOG'
        account.write_bytes(original)
        account.chmod(0o640)
        runner.account_files = (account, backup)
        with patch.object(runner, 'guard'):
            runner.snapshot_accounts()
        account.write_bytes(b'changed fixture accounts')
        backup.write_bytes(b'temporary fixture backup')
        with patch.object(runner, 'guard'), patch.object(runner, 'command', return_value='') as command:
            runner.restore_accounts()
        self.assertEqual(account.read_bytes(), original)
        self.assertEqual(account.stat().st_mode & 0o777, 0o640)
        self.assertFalse(backup.exists())
        self.assertEqual(command.call_args.kwargs['allowed'], (1,))
        self.assertNotIn(original.decode(), json.dumps(runner.report))
        backup.write_bytes(b'base-owned fixture')
        with patch.object(runner, 'guard'), patch.object(runner, 'command', side_effect=lifecycle.Error('base package owns file')):
            with self.assertRaises(lifecycle.Error): runner.restore_accounts()
        self.assertEqual(backup.read_bytes(), b'base-owned fixture')

    def test_unrelated_external_mount_and_notice_only_upgrade_refused(self):
        observed = probe()
        observed['mounts']['/mnt/host-home'] = {'fs': 'ext4', 'options': ['rw']}
        with self.assertRaisesRegex(lifecycle.Error, 'unexpected external mount'):
            lifecycle.environment_guard(observed)
        value = contract()
        value['upgrade'][0]['payload_sha256'] = dict(value['baseline'][0]['payload_sha256'])
        value['upgrade'][0]['payload_sha256']['usr/share/doc/cachy-asahi-hyprland-settings/NOTICE'] = '3' * 64
        with self.assertRaisesRegex(lifecycle.Error, 'changed primary template'):
            lifecycle.validate_contract(value)

    def test_all_privilege_sets_and_nnp_are_observed_and_limited(self):
        for name in ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb'):
            for value in (1 << 21, -1, 'safe', None, True):
                observed = probe()
                observed['privileges'][name] = value
                with self.subTest(name=name, value=value), self.assertRaises(lifecycle.Error):
                    lifecycle.environment_guard(observed)
            observed = probe()
            del observed['privileges'][name]
            with self.assertRaises(lifecycle.Error): lifecycle.environment_guard(observed)
        for value in (0, '0', '1', None, True):
            observed = probe()
            observed['privileges']['NoNewPrivs'] = value
            with self.assertRaises(lifecycle.Error): lifecycle.environment_guard(observed)
        observed = probe()
        del observed['privileges']
        with self.assertRaises(lifecycle.Error): lifecycle.environment_guard(observed)
        observed = probe()
        observed['caps'] &= ~(1 << 5)
        observed['privileges']['CapEff'] = observed['caps']
        with self.assertRaisesRegex(lifecycle.Error, 'CAP_KILL'):
            lifecycle.environment_guard(observed)

    def test_process_status_parser_refuses_missing_malformed_privilege_observations(self):
        text = ''.join(f'{name}:\t00000000000000eb\n' for name in ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb')) + 'NoNewPrivs:\t1\n'
        self.assertEqual(lifecycle.privilege_status(text)['NoNewPrivs'], 1)
        self.assertEqual(lifecycle.privilege_status(text)['CapBnd'], lifecycle.SAFE_CAPS)
        for changed in (text.replace('CapPrm:', 'Missing:'), text.replace('00000000000000eb', 'zz'), text.replace('NoNewPrivs:\t1', 'NoNewPrivs:\tmaybe')):
            with self.assertRaises(lifecycle.Error): lifecycle.privilege_status(changed)

    def test_nested_mounts_and_unexpected_proc_run_mounts_refused_regardless_flags(self):
        for path in ('/inputs/baseline', '/runner/lifecycle.py', '/out/lifecycle', '/proc/self/status', '/run/host-user.sock'):
            for flags in (['rw'], ['ro']):
                observed = probe()
                observed['mounts'][path] = {'fs': 'tmpfs', 'options': flags}
                with self.subTest(path=path, flags=flags), self.assertRaises(lifecycle.Error):
                    lifecycle.environment_guard(observed)
        observed = probe()
        observed['mounts'].update({'/proc': {'fs': 'proc', 'options': ['rw', 'nosuid', 'nodev', 'noexec']},
            '/proc/sys': {'fs': 'proc', 'options': ['ro', 'nosuid', 'nodev', 'noexec']}, '/proc/kcore': {'fs': 'tmpfs', 'options': ['rw']},
            '/sys': {'fs': 'sysfs', 'options': ['ro', 'nosuid', 'nodev', 'noexec']}, '/sys/fs/cgroup': {'fs': 'cgroup2', 'options': ['ro', 'nosuid', 'nodev', 'noexec']},
            '/dev': {'fs': 'tmpfs', 'options': ['rw', 'nosuid']}, '/dev/pts': {'fs': 'devpts', 'options': ['rw', 'nosuid', 'noexec']}})
        observed['mask_nodes']['/proc/kcore'] = {'symlink': False, 'kind': 'char', 'device': [1, 3]}
        lifecycle.environment_guard(observed)

    def process(self, code, timeout=0.15, limit=16384):
        return lifecycle.bounded_process([lifecycle.sys.executable, '-c', code], timeout=timeout,
                                         stdout_limit=limit, stderr_limit=limit)

    def test_real_stalled_process_retains_partial_output_and_is_reaped(self):
        started = time.monotonic()
        result = self.process("import time; print('fixture partial stdout', flush=True); time.sleep(30)")
        self.assertEqual(result['reason'], 'timeout')
        self.assertIn(b'fixture partial stdout', result['stdout'])
        self.assertTrue(result['cleanup']['reaped'])
        self.assertTrue(result['cleanup']['term_sent'])
        self.assertLess(time.monotonic() - started, 2)

    def test_real_term_ignoring_descendant_group_is_killed_without_other_processes(self):
        code = "import os, signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); child=os.fork(); print('owned-pid', os.getpid(), flush=True); time.sleep(30)"
        result = self.process(code)
        self.assertEqual(result['reason'], 'timeout')
        self.assertTrue(result['cleanup']['kill_sent'])
        self.assertTrue(result['cleanup']['reaped'])
        for row in result['stdout'].decode().splitlines():
            if row.startswith('owned-pid '):
                path = Path('/proc') / row.split()[1] / 'stat'
                self.assertTrue(not path.exists() or path.read_text().split()[2] == 'Z')

    def test_real_stdout_and_stderr_saturation_are_bounded_and_reaped(self):
        for stream in ('stdout', 'stderr'):
            result = self.process(f"import sys, time; sys.{stream}.write('x'*1000000); sys.{stream}.flush(); time.sleep(30)", timeout=1, limit=8192)
            self.assertEqual(result['reason'], 'output-limit')
            self.assertLessEqual(len(result[stream]), 8192)
            self.assertGreater(result[stream + '_seen'], 8192)
            self.assertTrue(result['cleanup']['reaped'])

    def test_timeout_receipt_exists_before_execution_and_partial_logs_survive(self):
        runner = lifecycle.Lifecycle(contract(), self.root, probe())
        def expired(*args, **kwargs):
            self.assertEqual(json.loads((self.root / '001.json').read_text())['status'], 'starting')
            raise subprocess.TimeoutExpired(args[0], 1, output=b'fixture partial stdout', stderr=b'fixture partial stderr')
        with patch.object(runner, 'guard'), patch.object(lifecycle, 'bounded_process', side_effect=expired):
            with self.assertRaisesRegex(lifecycle.Error, 'timeout'):
                runner.command(['not-executed-fixture'])
        receipt = json.loads((self.root / '001.json').read_text())
        self.assertEqual(receipt['status'], 'timeout')
        self.assertIn('fixture partial stdout', (self.root / '001.log').read_text())
        self.assertIn('fixture partial stderr', (self.root / '001.log').read_text())
        self.assertEqual(runner.report['status'], 'FAIL')

    def test_archive_many_empty_members_and_metadata_stream_bound(self):
        path = self.root / 'many.pkg.tar'
        with tarfile.open(path, 'w') as archive:
            for i in range(9):
                member = tarfile.TarInfo(f'usr/share/empty-{i}')
                member.type = tarfile.DIRTYPE
                member.mode = 0o755
                archive.addfile(member)
        with patch.object(lifecycle, 'ARCHIVE_MEMBERS', 8):
            with self.assertRaisesRegex(lifecycle.Error, 'member count'):
                lifecycle.inspect_archive(path, contract()['baseline'][0])
        with patch.object(lifecycle, 'ARCHIVE_STREAM', 1024):
            with self.assertRaisesRegex(lifecycle.Error, 'stream exceeds'):
                lifecycle.inspect_archive(path, contract()['baseline'][0])
        header = tarfile.TarInfo('PaxHeader')
        header.type, header.size = tarfile.XHDTYPE, 65537
        data = header.tobuf() + b'x' * (65536 + 512) + b'\0' * 1024
        with self.assertRaisesRegex(lifecycle.Error, 'extension metadata'):
            lifecycle.tar_stream_guard(data, time.monotonic() + 1)

    def test_stalled_archive_decoder_and_saturated_diagnostics_cannot_hang(self):
        path = self.root / 'fixture.pkg.tar.zst'
        path.write_bytes(b'owned fixture input')
        original = lifecycle.bounded_process
        for code, expected in (("import time; time.sleep(30)", 'timeout'),
                               ("import sys,time; sys.stderr.write('x'*1000000); sys.stderr.flush(); time.sleep(30)", 'output-limit')):
            def fake_decoder(argv, **kwargs):
                return original([lifecycle.sys.executable, '-c', code], **kwargs)
            started = time.monotonic()
            with patch.object(lifecycle, 'ARCHIVE_TIMEOUT', 0.15), patch.object(lifecycle, 'COMMAND_STDERR', 8192), \
                 patch.object(lifecycle, 'bounded_process', side_effect=fake_decoder):
                with self.assertRaisesRegex(lifecycle.Error, expected):
                    lifecycle.inspect_archive(path, contract()['baseline'][0])
            self.assertLess(time.monotonic() - started, 2)

    def test_malformed_decoded_tar_error_is_not_replaced_by_cleanup(self):
        path = self.root / 'fixture.pkg.tar.zst'
        path.write_bytes(b'owned fixture input')
        # Physical bounds pass; bad tar checksum must remain the parser's error.
        header = bytearray(tarfile.TarInfo('file').tobuf())
        header[0] ^= 1
        decoded = bytes(header) + b'\0' * 1024
        original = lifecycle.bounded_process
        def fake_decoder(argv, **kwargs):
            code = 'import sys; sys.stdout.buffer.write(' + repr(decoded) + ')'
            result = original([lifecycle.sys.executable, '-c', code], **kwargs)
            self.assertTrue(result['cleanup']['reaped'])
            self.assertEqual(result['cleanup']['errors'], [])
            return result
        with patch.object(lifecycle, 'bounded_process', side_effect=fake_decoder):
            with self.assertRaises(tarfile.ReadError):
                lifecycle.inspect_archive(path, contract()['baseline'][0])

    def test_exact_default_docker_masks_with_null_identity_are_accepted(self):
        observed = probe()
        for path in lifecycle.NULL_MASKS:
            observed['mounts'][path] = {'fs': 'tmpfs', 'options': ['rw']}
            observed['mask_nodes'][path] = {'kind': 'char', 'device': [1, 3], 'symlink': False}
        for path in lifecycle.DIRECTORY_MASKS:
            observed['mounts'][path] = {'fs': 'tmpfs', 'options': ['ro']}
            observed['mask_nodes'][path] = {'kind': 'directory', 'device': None, 'symlink': False}
        for path in lifecycle.PROC_READONLY:
            observed['mounts'][path] = {'fs': 'proc', 'options': ['ro', 'nosuid', 'nodev', 'noexec']}
        lifecycle.environment_guard(observed)
        for path in lifecycle.NULL_MASKS | lifecycle.DIRECTORY_MASKS:
            changed = json.loads(json.dumps(observed))
            changed['mounts'][path]['fs'] = 'ext4'
            with self.subTest(path=path), self.assertRaises(lifecycle.Error):
                lifecycle.environment_guard(changed)
        for invalid in ({'kind': 'regular', 'device': None, 'symlink': False},
                        {'kind': 'char', 'device': [1, 1], 'symlink': False},
                        {'kind': 'char', 'device': [1, 3], 'symlink': True}, {}):
            changed = json.loads(json.dumps(observed))
            changed['mask_nodes']['/proc/interrupts'] = invalid
            with self.assertRaises(lifecycle.Error): lifecycle.environment_guard(changed)

    def test_known_mount_roles_require_exact_filesystems_security_and_access(self):
        observed = probe()
        observed['mounts']['/sys/fs/cgroup'] = {'fs': 'cgroup2', 'options': ['ro', 'nosuid', 'nodev', 'noexec']}
        observed['mounts']['/dev/pts'] = {'fs': 'devpts', 'options': ['rw', 'nosuid', 'noexec']}
        observed['mounts']['/dev/mqueue'] = {'fs': 'mqueue', 'options': ['rw', 'nosuid', 'nodev', 'noexec']}
        observed['mounts']['/dev/shm'] = {'fs': 'tmpfs', 'options': ['rw', 'nosuid', 'nodev', 'noexec']}
        lifecycle.environment_guard(observed)
        for path, entry in (('/sys', {'fs': 'sysfs', 'options': ['rw', 'nosuid', 'nodev', 'noexec']}),
                            ('/sys', {'fs': 'cgroup2', 'options': ['ro', 'nosuid', 'nodev', 'noexec']}),
                            ('/sys/fs/cgroup', {'fs': 'sysfs', 'options': ['ro', 'nosuid', 'nodev', 'noexec']}),
                            ('/sys/fs/cgroup', {'fs': 'cgroup2', 'options': ['rw', 'nosuid', 'nodev', 'noexec']}),
                            ('/dev/pts', {'fs': 'tmpfs', 'options': ['rw', 'nosuid', 'noexec']}),
                            ('/dev/mqueue', {'fs': 'mqueue', 'options': ['rw']}),
                            ('/dev/shm', {'fs': 'tmpfs', 'options': ['rw']}),
                            ('/proc', {'fs': 'proc', 'options': ['ro', 'nosuid', 'nodev', 'noexec']}),
                            ('/proc', {'fs': 'proc', 'options': ['rw', 'nodev', 'noexec']}),
                            ('/inputs', {'fs': 'ext4', 'options': ['ro', 'rw']})):
            changed = json.loads(json.dumps(observed))
            changed['mounts'][path] = entry
            with self.subTest(path=path, entry=entry), self.assertRaises(lifecycle.Error):
                lifecycle.environment_guard(changed)


class HandoffDiagnosticTests(unittest.TestCase):
    def setUp(self):
        lifecycle.handoff_diagnostic_start()

    def test_first_refusal_and_later_cancellation_are_closed(self):
        lifecycle.handoff_diagnostic_site('COMMIT')
        with self.assertRaises(lifecycle.Error):
            lifecycle.require(False, 'private fixture input', diagnostic='LOAD_01')
        lifecycle.handoff_diagnostic_site('OUTPUT')
        lifecycle.handoff_diagnostic_failure('HANDOFF_INIT_10')
        lifecycle.handoff_diagnostic_cancel()
        stream = io.StringIO()
        with contextlib.redirect_stderr(stream):
            lifecycle.handoff_diagnostic_emit()
            lifecycle.handoff_diagnostic_emit()
        lines = stream.getvalue().splitlines()
        self.assertEqual(len(lines), 1)
        value = json.loads(lines[0][len(lifecycle.HANDOFF_DIAGNOSTIC_PREFIX):])
        self.assertEqual(value, {'schema_version': 1, 'operation': 'COMMIT',
                                'refusal': 'LOAD_01', 'cancelled': True})
        self.assertNotIn('private fixture', stream.getvalue())

    def test_refusal_recorder_baseexceptions_preserve_original_guard(self):
        for secondary in (RuntimeError('recorder'), KeyboardInterrupt(), SystemExit(), BaseException()):
            lifecycle.handoff_diagnostic_start()
            with self.subTest(kind=type(secondary)), patch.object(lifecycle, 'handoff_diagnostic_failure', side_effect=secondary):
                with self.assertRaises(lifecycle.Error) as raised:
                    lifecycle.require(False, 'original guard', diagnostic='LOAD_01')
                self.assertEqual(raised.exception.args, ('original guard',))
            if type(secondary) is KeyboardInterrupt:
                self.assertTrue(lifecycle._HANDOFF_DIAGNOSTIC['cancelled'])

    def test_unknown_labels_are_projected_and_malformed_state_not_emitted(self):
        lifecycle.handoff_diagnostic_site('private arbitrary text')
        lifecycle.handoff_diagnostic_failure('private arbitrary text')
        self.assertEqual(lifecycle._HANDOFF_DIAGNOSTIC['first']['operation'], 'UNKNOWN')
        self.assertEqual(lifecycle._HANDOFF_DIAGNOSTIC['first']['refusal'], 'UNKNOWN')
        lifecycle._HANDOFF_DIAGNOSTIC['first']['path'] = '/private'
        stream = io.StringIO()
        with contextlib.redirect_stderr(stream):
            lifecycle.handoff_diagnostic_emit()
        self.assertEqual(stream.getvalue(), '')

    def test_successful_require_never_calls_optional_recorder(self):
        with patch.object(lifecycle, 'handoff_diagnostic_failure', side_effect=KeyboardInterrupt()) as observer:
            lifecycle.require(True, 'held guard', diagnostic='LOAD_01')
        observer.assert_not_called()


if __name__ == '__main__':
    unittest.main()
