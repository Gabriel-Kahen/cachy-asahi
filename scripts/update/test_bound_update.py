#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actual signed x86_64 tiny-root commits in an owned private namespace only."""
import argparse
from contextlib import ExitStack
import json
import os
import shutil
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_snapshot import module, encoded, digest, signing, make_bundle, make_envelope

ROOT = Path(__file__).resolve().parents[2]
bound = module('bound_under_test', Path(__file__).with_name('bound_update.py'))
fixtures = module('bound_policy_fixtures', ROOT / 'packages/tools/cachy-asahi-update/test-asahi-policy.py')


class ActualTransactions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stack = ExitStack()
        cls.addClassCleanup(cls.stack.close)
        cls.directory = Path(cls.stack.enter_context(tempfile.TemporaryDirectory(prefix='bound-tests-')))
        cls.signer, cls.public, sign = cls.stack.enter_context(signing(cls.directory / 'keys'))
        cls.sign = staticmethod(sign)

    def setUp(self):
        case = tempfile.TemporaryDirectory(prefix='case-', dir=self.directory)
        self.addCleanup(case.cleanup)
        self.case = Path(case.name)
        self.workspace = self.case / 'workspace'
        self.workspace.mkdir(mode=0o700)
        self.root = self.workspace / 'root'
        self.root.mkdir()
        self.policy, self.observed = fixtures.fixture(phase='pre-transaction')
        self.policy['release_id'] = 'fixture-1'
        self.versions = dict(self.observed['before_versions'], fixture='0-1')
        self.owned = {name: [f'usr/share/protected/{name}'] for name in self.versions}
        self.owned['fixture-asahi-kernel'] = [self.observed['before_kernel_files']['fixture-asahi-kernel'][0].lstrip('/')]
        self.owned['fixture'] = ['usr/share/fixture/config']
        local = self.root / 'var/lib/pacman/local'
        local.mkdir(parents=True)
        (local / 'ALPM_DB_VERSION').write_text('9\n')
        for name, version in self.versions.items():
            db = local / f'{name}-{version}'
            db.mkdir()
            (db / 'desc').write_text(f'%NAME%\n{name}\n\n%VERSION%\n{version}\n\n%ARCH%\nany\n\n')
            (db / 'files').write_text('%FILES%\n' + '\n'.join(self.owned[name]) + '\n\n')
            for path in self.owned[name]:
                file = self.root / path
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_bytes(b'BASE TEST ONLY\n')
                file.chmod(0o644)
        (self.root / 'etc/pacman.d').mkdir(parents=True)
        (self.root / 'etc/pacman.conf').write_text('# BASE TEST ONLY\n')
        (self.root / 'etc/pacman.d/base-public').write_bytes(b'preserve base public trust\n')
        self.base = [dict(name=name, version=version, arch='any', depend=[], provides=[], conflict=[], files=self.owned[name])
                for name, version in self.versions.items()]
        self.bundle = make_bundle(self.case, self.signer, self.sign, base_packages=self.base)
        # External policy binds this authenticated release and an existing signed file digest.
        release = json.loads((self.bundle / 'release.json').read_text())
        self.policy['transitions'][0]['evidence_sha256'] = dict(
            release_manifest=digest(self.bundle / 'release.json'), transition_validation=release['files']['base.json'])
        self.policy_path = self.case / 'policy.json'
        self.policy_path.write_bytes(encoded(self.policy))
        self.keyring = self.case / 'public.gpg'
        self.keyring.write_bytes(self.public)
        self.state = self.case / 'state'
        self.state.mkdir(mode=0o700)
        self.metadata = self.case / 'metadata.json'
        make_envelope(self.case, self.bundle, self.signer, self.public, self.sign)
        self.settings = dict(schema_version=1, purpose='disposable-generic-bound-update', namespace='dev.fixture',
            signer=self.signer, minimum_sequence=1, release_id='fixture-1', repo_name='fixture',
            metadata_sha256=digest(self.metadata), release_sha256=digest(self.bundle / 'release.json'),
            public_keyring_sha256=digest(self.keyring), base_trust_sha256=bound.trust_digest(bound.install.tree(self.root)),
            model=self.observed['model'], running_kernel_release=self.observed['running_kernel_release'],
            operations=['repository-update'])
        self.settings_path = self.case / 'settings.json'
        self.settings_path.write_bytes(encoded(self.settings))
        self.args = argparse.Namespace(root=str(self.root), workspace=str(self.workspace), settings=str(self.settings_path),
            settings_sha256=digest(self.settings_path), policy=str(self.policy_path), policy_sha256=digest(self.policy_path),
            bundle=str(self.bundle), metadata=str(self.metadata), signature=str(self.metadata)+'.sig',
            public_keyring=str(self.keyring), state_dir=str(self.state), operation='repository-update')
        self.trust = bound.trust_rows(bound.install.tree(self.root))

    def invoke(self):
        # libalpm retains a process-global GPGME context; CLI calls are separate workers.
        read, write = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read)
            try:
                data = encoded(bound.apply(self.args))
                with os.fdopen(write, 'wb') as stream:
                    stream.write(data)
            finally:
                os._exit(0)
        os.close(write)
        with os.fdopen(read, 'rb') as stream:
            data = stream.read(65537)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(status, 0)
        self.assertLessEqual(len(data), 65536)
        return json.loads(data)

    def run_update(self):
        value = self.invoke()
        self.assertEqual(bound.trust_rows(bound.install.tree(self.root)), self.trust)
        self.assertFalse((self.root / 'var/lib/pacman/db.lck').exists())
        self.assertEqual(list(self.workspace.iterdir()), [self.root])
        return value

    def assert_refused(self, value, contains=None):
        self.assertEqual(value['status'], 'FAIL', value)
        self.assertFalse(value['commit_started'], value)
        self.assertFalse(value['checkpoint_changed'], value)
        self.assertEqual((self.root / self.owned['fixture'][0]).read_bytes(), b'BASE TEST ONLY\n')
        self.assertEqual(list(self.state.iterdir()), [])
        if contains:
            self.assertIn(contains, value.get('error', ''))

    def test_real_signed_upgrade_and_repeat_noop(self):
        result = self.run_update()
        self.assertEqual(result['status'], 'PASS', result)
        self.assertTrue(result['packages_committed'])
        self.assertEqual(result['before']['fixture'], '0-1')
        self.assertEqual(result['after']['fixture'], '1-1')
        self.assertEqual((self.root / self.owned['fixture'][0]).read_bytes(), b'TEST ONLY\n')
        self.assertEqual(result['prepared_add'], {'fixture': '1-1'})
        again = self.run_update()
        self.assertEqual(again['status'], 'PASS', again)
        self.assertFalse(again['commit_started'])
        self.assertEqual(again['prepared_add'], {})

    def test_modified_archive_refused(self):
        with (self.bundle / 'repo/fixture-1-1-any.pkg.tar.gz').open('ab') as stream:
            stream.write(b'tamper')
        self.assert_refused(self.run_update())

    def test_invalid_metadata_signature_refused(self):
        Path(self.args.signature).write_bytes(b'INVALID TEST SIGNATURE')
        self.assert_refused(self.run_update())

    def test_existing_package_lock_refused_before_observation(self):
        lock = self.root / 'var/lib/pacman/db.lck'
        lock.write_bytes(b'owned test contention\n')
        try:
            result = self.invoke()
            self.assert_refused(result, 'transaction lock')
            self.assertEqual(result['phase'], 'package-manager-lock')
            self.assertEqual(lock.read_bytes(), b'owned test contention\n')
        finally:
            lock.unlink()

    def test_real_dependency_prepare_failure(self):
        path = self.root / 'var/lib/pacman/local/fixture-graphics-1-1/desc'
        with path.open('a') as stream:
            stream.write('%DEPENDS%\nfixture=0-1\n\n')
        self.assert_refused(self.run_update(), 'prepare immutable transaction')

    def test_configuration_input_drift_after_prepare_refused(self):
        original = bound.configuration
        calls = []
        def change(path, pin):
            calls.append(1)
            if len(calls) == 2:
                self.settings_path.write_bytes(self.settings_path.read_bytes() + b' ')
            return original(path, pin)
        with mock.patch.object(bound, 'configuration', change):
            self.assert_refused(self.run_update(), 'configuration changed')

    def test_missing_release_configuration_and_policy_refused(self):
        self.settings_path.unlink()
        self.assert_refused(self.run_update())
        self.settings_path.write_bytes(encoded(self.settings))
        self.policy_path.unlink()
        self.assert_refused(self.run_update())

    def test_auxiliary_ldconfig_refused_without_execution(self):
        path = self.root / 'usr/bin/ldconfig'
        path.parent.mkdir(parents=True)
        path.write_bytes(b'#!/bin/sh\nexit 99\n')
        path.chmod(0o755)
        self.assert_refused(self.run_update(), 'auxiliary executable')

    def test_checkpoint_failure_reports_actual_commit(self):
        with mock.patch.object(bound.client, 'commit', side_effect=OSError('TEST checkpoint failure')):
            result = self.run_update()
        self.assertEqual(result['status'], 'FAIL', result)
        self.assertTrue(result['packages_committed'], result)
        self.assertFalse(result['checkpoint_changed'])
        self.assertEqual(result['phase'], 'checkpoint')
        self.assertEqual((self.root / self.owned['fixture'][0]).read_bytes(), b'TEST ONLY\n')

    def test_checkpoint_failure_after_replacement_reports_changed(self):
        commit = bound.client.commit
        def replace_then_fail(fd, value):
            self.assertTrue((self.root / 'var/lib/pacman/db.lck').exists())
            commit(fd, value)
            raise OSError('TEST failure after checkpoint replacement')
        with mock.patch.object(bound.client, 'commit', replace_then_fail):
            result = self.run_update()
        self.assertEqual(result['status'], 'FAIL', result)
        self.assertTrue(result['packages_committed'])
        self.assertIs(result['checkpoint_changed'], True)

    def test_lock_release_failure_is_not_reported_as_pass(self):
        actual = bound.install.Alpm
        class ReportReleaseFailure(actual):
            def __init__(instance, *args, **kwargs):
                super().__init__(*args, **kwargs)
                release = instance.alpm_trans_release
                def fail(handle):
                    release(handle)  # Retire real test lock; model failed return status.
                    return -1
                instance.alpm_trans_release = fail
        with mock.patch.object(bound.install, 'Alpm', ReportReleaseFailure):
            result = self.run_update()
        self.assertEqual(result['status'], 'FAIL', result)
        self.assertTrue(result['packages_committed'])
        self.assertTrue(result['checkpoint_changed'])
        self.assertIn('lock release failed', result['error'])

    def replace_payload(self, payload, version="1-1"):
        shutil.rmtree(self.bundle)
        self.bundle = make_bundle(self.case, self.signer, self.sign, base_packages=self.base, payload=payload, version=version)
        self.metadata.unlink()
        make_envelope(self.case, self.bundle, self.signer, self.public, self.sign)
        release = json.loads((self.bundle / 'release.json').read_text())
        self.policy['transitions'][0]['evidence_sha256'] = dict(
            release_manifest=digest(self.bundle / 'release.json'), transition_validation=release['files']['base.json'])
        self.policy_path.write_bytes(encoded(self.policy))
        self.args.policy_sha256 = digest(self.policy_path)
        self.settings.update(metadata_sha256=digest(self.metadata), release_sha256=digest(self.bundle / 'release.json'))
        self.settings_path.write_bytes(encoded(self.settings))
        self.args.settings_sha256 = digest(self.settings_path)

    def test_signed_new_protected_payload_refused(self):
        self.replace_payload({'boot/TEST-unauthorized': b'never install\n'})
        self.assert_refused(self.run_update(), 'protected platform/trust path')
        self.assertFalse((self.root / 'boot/TEST-unauthorized').exists())

    def test_signed_payload_through_existing_alias_to_protected_path_refused(self):
        (self.root / 'boot').mkdir()
        (self.root / 'usr/share/route').symlink_to('../../boot')
        self.replace_payload({'usr/share/route/TEST-unauthorized': b'never install\n'})
        self.assert_refused(self.run_update(), 'protected platform/trust path')
        self.assertFalse((self.root / 'boot/TEST-unauthorized').exists())

    def test_old_selected_protected_owned_path_refused_before_removal(self):
        path = self.root / 'var/lib/pacman/local/fixture-0-1/files'
        path.write_text(path.read_text().rstrip() + '\netc/pacman.conf\n\n')
        self.assert_refused(self.run_update(), 'protected platform/trust path')

    def test_old_selected_alias_to_base_trust_refused_before_removal(self):
        (self.root / 'alias').symlink_to('etc/pacman.d')
        path = self.root / 'var/lib/pacman/local/fixture-0-1/files'
        path.write_text(path.read_text().rstrip() + '\nalias/base-public\n\n')
        self.assert_refused(self.run_update(), 'protected platform/trust path')

    def test_signed_package_downgrade_refused(self):
        self.replace_payload({'usr/share/fixture/config': b'old candidate\n'}, version='0-0')
        self.assert_refused(self.run_update(), 'downgrade')

    def test_actual_protected_ownership_outside_platform_prefix_refused(self):
        path = self.root / 'var/lib/pacman/local/fixture-graphics-1-1/files'
        path.write_text(path.read_text().rstrip() + '\nusr/share/fixture/config\n\n')
        self.assert_refused(self.run_update(), 'actual protected ownership')

    def test_original_archive_drift_after_prepare_refused(self):
        original = bound.configuration
        calls = []
        def change(path, pin):
            calls.append(1)
            if len(calls) == 2:
                with (self.bundle / 'repo/fixture-1-1-any.pkg.tar.gz').open('ab') as stream:
                    stream.write(b'changed after actual prepare')
            return original(path, pin)
        with mock.patch.object(bound, 'configuration', change):
            self.assert_refused(self.run_update(), 'drifted')

    def test_other_operations_refused(self):
        for operation in ('aur-update', 'flatpak-update', 'orphan-removal', 'restart', 'platform-update'):
            self.args.operation = operation
            self.assert_refused(self.run_update(), 'unsupported update operation')


if __name__ == '__main__':
    unittest.main()
