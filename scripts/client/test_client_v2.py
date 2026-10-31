#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Portable and real ephemeral-GPG DEVELOPMENT fixtures; no host package/trust mutation."""
import argparse
import copy
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
loader = importlib.util.spec_from_file_location('client', Path(__file__).with_name('client_v2.py'))
c = importlib.util.module_from_spec(loader)
loader.loader.exec_module(c)


class PortableTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='client-boundary-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.state = self.base / 'state'
        self.state.mkdir(mode=0o700)
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.key = 'A' * 40
        self.value = {'schema_version': 1, 'scope': 'development', 'namespace': 'dev.example', 'signer': self.key,
                      'sequence': 2, 'metadata_sha256': 'a' * 64, 'release_sha256': 'b' * 64,
                      'issued_utc': c.utc(self.now - timedelta(seconds=60)), 'verified_utc': c.utc(self.now)}
        self.metadata = dict(type=c.TYPE, expires_utc=c.utc(self.now + timedelta(hours=1)), synthetic=True,
                             release_id='fixture', repo_name='fixture', targets={},
                             **{k: self.value[k] for k in ('schema_version', 'scope', 'namespace', 'signer', 'sequence', 'issued_utc')})

    def test_source_helper_loads_exact_sibling_bytes_ignoring_cwd_module(self):
        from types import SimpleNamespace
        fake=SimpleNamespace(verify_associations=lambda *args: 'FOREIGN')
        with mock.patch.dict(sys.modules,{'source_delivery':fake}):
            helper=c.source_delivery_helper()
        self.assertNotEqual(helper,fake)
        self.assertEqual(Path(helper.__file__).absolute(),Path(c.__file__).absolute().parents[1]/'release/source_delivery.py')
        self.assertIsNone(helper.verify_associations({},[],lambda *args:b'',lambda *args:{}))

    def test_sources_primary_survives_owned_root_close_uncertainty(self):
        raw=c.encoded({});release={'files':{'spec.json':c.digest(raw)}}
        args=argparse.Namespace(package='fixture',version='1-1',arch='any',artifact_sha256='a'*64,
            output=None,bundle=str(self.base),state_dir=str(self.state),apply=True)
        fd=os.open(self.base,os.O_RDONLY|os.O_DIRECTORY);close=os.close
        primary=c.Error('FIRST ASSOCIATION REFUSAL')
        def uncertain(number):close(number);raise OSError('SECOND CLOSE UNCERTAINTY')
        with mock.patch.object(c,'verify',return_value={'release_sha256':c.digest(raw)}) as verify, \
             mock.patch.object(c,'directory',return_value=fd),mock.patch.object(c,'describe',return_value=({},release,raw)), \
             mock.patch.object(c,'read_member',return_value=raw),mock.patch.object(c,'source_associations',side_effect=primary), \
             mock.patch.object(c.os,'close',side_effect=uncertain):
            with self.assertRaises(c.Error) as caught:c.sources(args)
        self.assertIs(caught.exception,primary)
        self.assertEqual(primary.__notes__,['source bundle close uncertainty: OSError'])
        self.assertIs(verify.call_args.args[0].apply,False)
        self.assertIs(args.apply,True)

    def test_json_rejects_duplicate_float_nonfinite_and_nonobject(self):
        for data in (b'{"sequence":1,"sequence":2}', b'{"v":1.0}', b'{"v":NaN}', b'[]'):
            with self.subTest(data=data), self.assertRaises(c.Error):
                c.decode(data)

    def test_paths_reject_traversal_empty_and_noncanonical(self):
        for value in ('', '.', '../x', 'x/../y', '/x', 'x//y', 'x/./y', 'x/', 'x\\y', 'x\x00'):
            with self.subTest(value=value), self.assertRaises(c.Error):
                c.relative(value)
        for value in ('relative', '/tmp/../x', '//tmp/x', '/tmp//x', '/tmp/./x'):
            with self.subTest(value=value), self.assertRaises(c.Error):
                c.absolute(value)

    def test_input_symlink_components_hardlinks_and_fifo_refused(self):
        directory = self.base / 'real'
        directory.mkdir()
        (directory / 'data').write_bytes(b'TEST')
        (self.base / 'alias').symlink_to(directory, target_is_directory=True)
        with self.assertRaises(OSError):
            c.read_path(self.base / 'alias/data', 100)
        (directory / 'alias').symlink_to('data')
        with self.assertRaises(OSError):
            c.read_path(directory / 'alias', 100)
        os.link(directory / 'data', directory / 'hardlink')
        with self.assertRaisesRegex(c.Error, 'non-hardlinked'):
            c.read_path(directory / 'data', 100)
        os.mkfifo(directory / 'pipe')
        with self.assertRaisesRegex(c.Error, 'regular'):
            c.read_path(directory / 'pipe', 100)

    def test_read_bounds(self):
        path = self.base / 'data'
        path.write_bytes(b'12345')
        with self.assertRaisesRegex(c.Error, 'bounded size'):
            c.read_path(path, 4)

    def test_sequence_rejects_bool_zero_negative_large_and_float(self):
        for value in (True, 0, -1, 2**63, 1.0, '1'):
            with self.subTest(value=value), self.assertRaises(c.Error):
                c.sequence(value)

    def test_envelope_rejects_stable_unknown_fields_and_schema_bool(self):
        c.validate_envelope(self.metadata, self.now)
        for field, value in (('scope', 'stable'), ('extra', True), ('schema_version', True), ('signer', 'A' * 16)):
            changed = dict(self.metadata, **{field: value})
            with self.subTest(field=field), self.assertRaises(c.Error):
                c.validate_envelope(changed, self.now)

    def test_freshness_future_expiry_and_maximum_lifetime(self):
        variants = ({'issued_utc': c.utc(self.now + timedelta(seconds=1))},
                    {'expires_utc': c.utc(self.now)}, {'expires_utc': self.metadata['issued_utc']},
                    {'expires_utc': c.utc(self.now + timedelta(days=8))}, {'issued_utc': '2026-10-11T00:00:00+00:00'})
        for variant in variants:
            with self.subTest(variant=variant), self.assertRaises(c.Error):
                c.validate_envelope(dict(self.metadata, **variant), self.now)

    def good_status(self):
        timestamp = int(self.now.timestamp())
        return f'[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG 0123456789ABCDEF TEST ONLY\n[GNUPG:] VALIDSIG {self.key} {self.now:%Y-%m-%d} {timestamp} 0 4 0 22 8 00 {self.key}\n'.encode()

    def test_full_status_identity_subkey_and_weak_digest(self):
        status = self.good_status()
        c.signature_status(status, self.key, self.now)
        subkey = 'B' * 40
        receipt = c.signature_status(status.replace(b'VALIDSIG ' + self.key.encode(), b'VALIDSIG ' + subkey.encode()), self.key, self.now)
        self.assertEqual(receipt['signing_fingerprint'], subkey)
        for data in (status.replace(b'22 8 00', b'22 2 00'), status.replace(b'22 8 00', b'22 11 00'),
                     status.replace(b'22 8 00', b'22 8 01'), status.replace(self.key.encode(), b'A' * 16)):
            with self.subTest(data=data), self.assertRaises(c.Error):
                c.signature_status(data, self.key, self.now)
        with self.assertRaises(c.Error):
            c.signature_status(status, 'C' * 40, self.now)

    def test_bad_expired_revoked_and_multiple_statuses(self):
        good = self.good_status()
        for tag in ('BADSIG', 'KEYEXPIRED', 'EXPKEYSIG', 'EXPSIG', 'REVKEYSIG', 'KEYREVOKED', 'SIGEXPIRED',
                    'ERRSIG', 'NO_PUBKEY', 'NODATA', 'FAILURE', 'ERROR', 'BADARMOR'):
            with self.subTest(tag=tag), self.assertRaises(c.Error):
                c.signature_status(good + f'[GNUPG:] {tag} TEST\n'.encode(), self.key, self.now)
        for value in (good + good, good.replace(b'[GNUPG:] NEWSIG\n', b''), b'[GNUPG:] VALIDSIG truncated\n',
                      good.replace(b' 0 4 0 22', f' {int(self.now.timestamp())} 4 0 22'.encode())):
            with self.subTest(value=value), self.assertRaises(c.Error):
                c.signature_status(value, self.key, self.now)
        with self.assertRaises(c.Error):
            c.signature_status(good, self.key, self.now - timedelta(seconds=1))

    def test_rollback_same_sequence_changes_namespace_signer_and_clock(self):
        c.against_state(self.value, self.metadata, 'a' * 64, self.now, 1)
        variants = ({'sequence': 1}, {'namespace': 'other.example'}, {'signer': 'B' * 40}, {'scope': 'stable'},
                    {'sequence': 3, 'issued_utc': c.utc(self.now - timedelta(seconds=120))})
        for variant in variants:
            with self.subTest(variant=variant), self.assertRaises(c.Error):
                c.against_state(self.value, dict(self.metadata, **variant), 'a' * 64, self.now, 1)
        with self.assertRaisesRegex(c.Error, 'altered metadata'):
            c.against_state(self.value, self.metadata, 'c' * 64, self.now, 1)
        with self.assertRaisesRegex(c.Error, 'clock moved'):
            c.against_state(self.value, self.metadata, 'a' * 64, self.now - timedelta(seconds=1), 1)
        with self.assertRaisesRegex(c.Error, 'supplied floor'):
            c.against_state(None, self.metadata, 'a' * 64, self.now, 3)

    def test_state_private_permissions_owner_symlink_and_missing(self):
        self.state.chmod(0o755)
        with self.assertRaisesRegex(c.Error, 'private 0700'):
            with c.state_directory(self.state, False):pass
        self.state.chmod(0o700)
        alias = self.base / 'state-alias'
        alias.symlink_to(self.state, target_is_directory=True)
        with self.assertRaises(OSError):
            with c.state_directory(alias, False):pass
        with self.assertRaises(FileNotFoundError):
            with c.state_directory(self.base / 'missing', True):pass
        with c.state_directory(self.state, False) as fd:
            self.assertIsNone(c.checkpoint(fd))
        self.assertEqual(list(self.state.iterdir()), [])

    def test_checkpoint_private_mode_symlink_and_malformed(self):
        path = self.state / c.CHECKPOINT
        path.write_bytes(c.encoded(self.value))
        path.chmod(0o644)  # Explicitly unsafe, including under the native worker's 077 umask.
        with c.state_directory(self.state, False) as fd:
            with self.assertRaisesRegex(c.Error, 'private 0600'):
                c.checkpoint(fd)
            path.chmod(0o600)
            self.assertEqual(c.checkpoint(fd), self.value)
            path.write_bytes(c.encoded(dict(self.value, sequence=True)))
            with self.assertRaises(c.Error):
                c.checkpoint(fd)
            path.unlink()
            path.symlink_to(self.base / 'outside')
            with self.assertRaises(OSError):
                c.checkpoint(fd)

    def test_checkpoint_read_does_not_modify_bytes_or_mtime(self):
        path = self.state / c.CHECKPOINT
        path.write_bytes(c.encoded(self.value))
        path.chmod(0o600)
        before = path.read_bytes(), path.stat().st_mtime_ns
        with c.state_directory(self.state, False) as fd:
            c.checkpoint(fd)
        self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), before)

    def test_lock_excludes_other_apply_and_readonly_checks(self):
        with c.state_directory(self.state, True):
            for apply in (True, False):
                with self.subTest(apply=apply), self.assertRaisesRegex(c.Error, 'locked'):
                    with c.state_directory(self.state, apply):pass
        with c.state_directory(self.state, False):
            with c.state_directory(self.state, False):pass

    def test_atomic_checkpoint_mode_and_precommit_failure(self):
        with c.state_directory(self.state, True) as fd:
            self.assertTrue(c.commit(fd, self.value))
            original = (self.state / c.CHECKPOINT).read_bytes()
            changed = dict(self.value, sequence=3)
            with mock.patch.object(c.os, 'replace', side_effect=OSError('TEST replace failure')):
                with self.assertRaises(OSError):c.commit(fd, changed)
            self.assertEqual((self.state / c.CHECKPOINT).read_bytes(), original)
        self.assertEqual([p.name for p in self.state.iterdir()], [c.CHECKPOINT])
        self.assertEqual((self.state / c.CHECKPOINT).stat().st_mode & 0o777, 0o600)

    def test_sync_failure_before_and_after_commit_has_distinct_outcome(self):
        with c.state_directory(self.state, True) as fd:
            with mock.patch.object(c.os, 'fsync', side_effect=OSError('TEST unsupported sync')):
                with self.assertRaises(OSError):c.commit(fd, self.value)
            self.assertEqual(list(self.state.iterdir()), [])
            with mock.patch.object(c.os, 'fsync', side_effect=[None, None, OSError('TEST final sync failure')]):
                self.assertFalse(c.commit(fd, self.value))
            self.assertEqual(c.checkpoint(fd), self.value)

    def test_gpg_exit_zero_is_not_enough_and_isolation_is_explicit(self):
        temp = self.base / 'verifier'
        temp.mkdir()
        verifier = c.Verifier(temp, b'public TEST ring', self.key, self.now)
        data = temp / 'data'
        data.write_bytes(b'TEST data')
        proc = subprocess.CompletedProcess([], 0, b'no valid status', b'')
        with mock.patch.object(c.subprocess, 'run', return_value=proc) as call:
            with self.assertRaises(c.Error):verifier.verify(data, b'TEST signature')
        argv = call.call_args.args[0]
        for option in ('--no-options', '--no-default-keyring', '--no-auto-key-retrieve', '--no-auto-key-import', '--disable-dirmngr', '--no-autostart'):
            self.assertIn(option, argv)
        self.assertNotIn('shell', call.call_args.kwargs)
        self.assertNotIn('--trust-model', argv)
        self.assertNotIn('--import', argv)
        self.assertEqual(argv[argv.index('--homedir') + 1], str(temp / 'gpg-home'))


class GPGTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(shutil.which(x) for x in ('gpg', 'gpgconf')):
            raise unittest.SkipTest('real ephemeral-GPG cases require preinstalled gpg/gpgconf')
        cls.temp = tempfile.TemporaryDirectory(prefix='TEST-only-client-keys-')
        cls.base = Path(cls.temp.name)
        cls.homes = []
        def cleanup():
            for home in cls.homes:
                subprocess.run(['gpgconf', '--homedir', str(home), '--kill', 'all'], capture_output=True, timeout=30)
            cls.temp.cleanup()
        cls.addClassCleanup(cleanup)
        cls.home = cls.base / 'external-TEST-signer'
        cls.home.mkdir(mode=0o700)
        cls.homes.append(cls.home)
        cls.gpg(['--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key',
                 'TEST ONLY offline client <fixture@test.invalid>', 'ed25519', 'cert', '1d'])
        listing = cls.gpg(['--with-colons', '--list-keys']).decode()
        cls.key = next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
        cls.gpg(['--pinentry-mode', 'loopback', '--passphrase', '', '--quick-add-key', cls.key, 'ed25519', 'sign', '1d'])
        cls.public = cls.gpg(['--export', cls.key])
        cls.bundle = cls.base / 'bundle'
        (cls.bundle / 'repo').mkdir(parents=True)
        package = cls.bundle / 'repo/fixture-1-1-any.pkg.tar.gz'
        with tarfile.open(package, 'w:gz') as archive:
            for name, data in (('.PKGINFO', b'pkgname = fixture\npkgver = 1-1\narch = any\nlicense = MIT\n'),
                               ('usr/share/fixture/config', b'SYNTHETIC TEST ONLY\n')):
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
        for suffix in ('db', 'files'):
            path = cls.bundle / f'repo/fixture.{suffix}.tar.gz'
            with tarfile.open(path, 'w:gz') as archive:
                data = b'SYNTHETIC TEST ONLY database bytes\n'
                entry = tarfile.TarInfo('fixture-1-1/desc')
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
            cls.sign(path)
            (path.parent / f'fixture.{suffix}').symlink_to(path.name)
        cls.sign(package)
        spec = {'schema_version': 1, 'release_id': 'fixture-1', 'repo_name': 'fixture', 'target_arch': 'aarch64', 'synthetic': True}
        (cls.bundle / 'spec.json').write_bytes(c.encoded(spec))
        files = {p.relative_to(cls.bundle).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in cls.bundle.rglob('*') if p.is_file() and not p.is_symlink()}
        release = {'schema_version': 1, 'release_id': 'fixture-1', 'signer': cls.key,
                   'created_utc': c.utc(datetime.now(timezone.utc)), 'files': files,
                   'packages': [{'name': 'fixture', 'version': '1-1', 'arch': 'any', 'filename': package.name,
                                 'sha256': files['repo/' + package.name]}],
                   'symlinks': {p.relative_to(cls.bundle).as_posix(): os.readlink(p)
                                for p in cls.bundle.rglob('*') if p.is_symlink()}}
        (cls.bundle / 'release.json').write_bytes(c.encoded(release))
        cls.sign(cls.bundle / 'release.json')

    @classmethod
    def gpg(cls, options, home=None):
        home = home or cls.home
        result = subprocess.run(['gpg', '--batch', '--no-options', '--homedir', str(home), *map(str, options)],
                                env=dict(os.environ, GNUPGHOME=str(home)), capture_output=True, timeout=30)
        if result.returncode:
            raise AssertionError(result.stderr.decode(errors='replace'))
        return result.stdout

    @classmethod
    def sign(cls, path, *, digest='SHA256', home=None, key=None):
        sig = Path(str(path) + '.sig')
        sig.unlink(missing_ok=True)
        cls.gpg(['--pinentry-mode', 'loopback', '--passphrase', '', '--local-user', key or cls.key,
                 '--digest-algo', digest, '--detach-sign', '--output', sig, path], home=home)

    def setUp(self):
        self.case = tempfile.TemporaryDirectory(prefix='client-real-GPG-case-')
        self.addCleanup(self.case.cleanup)
        self.directory = Path(self.case.name)
        self.local_bundle = self.directory / 'bundle'
        shutil.copytree(self.bundle, self.local_bundle, symlinks=True)
        self.state = self.directory / 'state'
        self.state.mkdir(mode=0o700)
        self.metadata = self.directory / 'metadata.json'
        self.keyring = self.directory / 'public.gpg'
        self.keyring.write_bytes(self.public)
        self.initial_keyring = self.keyring.read_bytes(), self.keyring.stat().st_mtime_ns
        now = datetime.now(timezone.utc)
        self.build_args = argparse.Namespace(bundle=str(self.local_bundle), output=str(self.metadata), namespace='dev.example',
            sequence=1, issued_utc=c.utc(now - timedelta(seconds=60)), expires_utc=c.utc(now + timedelta(hours=1)), signer=self.key)
        c.build(self.build_args)
        self.sign(self.metadata)
        self.args = argparse.Namespace(bundle=str(self.local_bundle), metadata=str(self.metadata), signature=str(self.metadata) + '.sig',
            public_keyring=str(self.keyring), signer=self.key, namespace='dev.example', state_dir=str(self.state), apply=False, minimum_sequence=1)

    def changed_metadata(self, **changes):
        value = c.decode(self.metadata.read_bytes())
        value.update(changes)
        self.metadata.write_bytes(c.encoded(value))
        self.sign(self.metadata)
        return value

    def apply(self):
        self.args.apply = True
        return c.verify(self.args)

    def checkpoint_bytes(self):
        return (self.state / c.CHECKPOINT).read_bytes()

    def test_real_subkey_verification_and_no_default_or_external_keyring_mutation(self):
        result = c.verify(self.args)
        self.assertEqual(result['status'], 'verified-development')
        self.assertTrue(result['cold_start'])
        self.assertFalse(result['state_changed'])
        self.assertNotEqual(result['signer']['signing_fingerprint'], self.key)
        self.assertEqual(result['signer']['primary_fingerprint'], self.key)
        self.assertEqual(list(self.state.iterdir()), [])
        self.assertEqual((self.keyring.read_bytes(), self.keyring.stat().st_mtime_ns), self.initial_keyring)
        self.assertEqual(sorted(p.name for p in self.directory.iterdir()), ['bundle', 'metadata.json', 'metadata.json.sig', 'public.gpg', 'state'])

    def test_apply_then_readonly_and_idempotent_verification(self):
        result = self.apply()
        self.assertEqual(result['status'], 'applied-development')
        self.assertTrue(result['checkpoint_directory_synced'])
        original = self.checkpoint_bytes()
        self.args.apply = False
        result = c.verify(self.args)
        self.assertFalse(result['cold_start'])
        self.assertEqual(self.checkpoint_bytes(), original)
        self.assertFalse(result['stable_accepted'])

    def test_envelope_signature_tamper_missing_and_wrong_signer(self):
        self.apply()
        original = self.checkpoint_bytes()
        self.metadata.write_bytes(self.metadata.read_bytes() + b' ')
        with self.assertRaises(c.Error):c.verify(self.args)
        self.assertEqual(self.checkpoint_bytes(), original)
        Path(self.args.signature).unlink()
        with self.assertRaises((c.Error, OSError)):c.verify(self.args)
        self.args.signer = 'B' * 40
        with self.assertRaises(c.Error):c.verify(self.args)
        self.assertEqual(self.checkpoint_bytes(), original)

    def test_invalid_metadata_signature_on_fresh_higher_sequence(self):
        self.apply()
        original = self.checkpoint_bytes()
        value = c.decode(self.metadata.read_bytes())
        value['sequence'] = 2
        self.metadata.write_bytes(c.encoded(value))
        with self.assertRaisesRegex(c.Error, 'GPG rejected'):c.verify(self.args)
        self.assertEqual(self.checkpoint_bytes(), original)

    def test_expired_future_namespace_and_stable_fail_without_state_change(self):
        self.apply()
        original = self.checkpoint_bytes()
        original_metadata = c.decode(self.metadata.read_bytes())
        now = datetime.now(timezone.utc)
        for change in ({'expires_utc': c.utc(now - timedelta(seconds=1))},
                       {'issued_utc': c.utc(now + timedelta(seconds=120))}, {'namespace': 'other.example'}, {'scope': 'stable'}):
            self.metadata.write_bytes(c.encoded(dict(original_metadata, **change)))
            self.sign(self.metadata)
            with self.subTest(change=change), self.assertRaises(c.Error):c.verify(self.args)
            self.assertEqual(self.checkpoint_bytes(), original)

    def test_higher_sequence_then_replay_and_same_sequence_altered_bytes(self):
        self.apply()
        first = self.metadata.read_bytes()
        self.changed_metadata(sequence=2)
        self.apply()
        original = self.checkpoint_bytes()
        self.metadata.write_bytes(first)
        self.sign(self.metadata)
        with self.assertRaisesRegex(c.Error, 'sequence rollback'):c.verify(self.args)
        self.assertEqual(self.checkpoint_bytes(), original)
        self.changed_metadata(sequence=2, expires_utc=c.utc(datetime.now(timezone.utc) + timedelta(hours=2)))
        with self.assertRaisesRegex(c.Error, 'altered metadata bytes'):c.verify(self.args)
        self.assertEqual(self.checkpoint_bytes(), original)

    def test_payload_tamper_and_bundle_mix_do_not_advance(self):
        self.apply()
        original = self.checkpoint_bytes()
        self.changed_metadata(sequence=2)
        path = self.local_bundle / 'repo/fixture-1-1-any.pkg.tar.gz'
        path.write_bytes(path.read_bytes() + b'UNSIGNED TEST TAMPER')
        with self.assertRaisesRegex(c.Error, 'payload checksum'):c.verify(self.args)
        self.assertEqual(self.checkpoint_bytes(), original)

    def test_signed_envelope_targets_must_match_actual_bytes(self):
        self.apply()
        original = self.checkpoint_bytes()
        value = self.changed_metadata(sequence=2)
        value['targets']['databases'][0]['sha256'] = '0' * 64
        self.metadata.write_bytes(c.encoded(value))
        self.sign(self.metadata)
        with self.assertRaisesRegex(c.Error, 'does not bind actual'):c.verify(self.args)
        self.assertEqual(self.checkpoint_bytes(), original)

    def test_release_record_signature_failure_prevents_apply(self):
        path = self.local_bundle / 'release.json.sig'
        path.write_bytes(b'unsigned TEST signature')
        self.args.apply = True
        with self.assertRaisesRegex(c.Error, 'GPG rejected'):c.verify(self.args)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_bad_package_signature_even_with_resigned_manifest_and_envelope(self):
        path = self.local_bundle / 'repo/fixture-1-1-any.pkg.tar.gz.sig'
        path.write_bytes(b'unsigned TEST signature')
        release_path = self.local_bundle / 'release.json'
        release = c.decode(release_path.read_bytes())
        release['files'][path.relative_to(self.local_bundle).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        release_path.write_bytes(c.encoded(release))
        self.sign(release_path)
        self.metadata.unlink()
        c.build(self.build_args)
        self.sign(self.metadata)
        self.args.apply = True
        with self.assertRaisesRegex(c.Error, 'GPG rejected'):c.verify(self.args)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_valid_resign_race_cannot_change_consumed_signature_bytes(self):
        self.apply()
        original = self.checkpoint_bytes()
        self.changed_metadata(sequence=2)
        describe = c.describe
        path = self.local_bundle / 'repo/fixture-1-1-any.pkg.tar.gz'
        def changed_signature(root):
            result = describe(root)
            self.sign(path, digest='SHA512')
            return result
        with mock.patch.object(c, 'describe', side_effect=changed_signature):
            with self.assertRaisesRegex(c.Error, 'signature bytes changed'):
                c.verify(self.args)
        self.assertEqual(self.checkpoint_bytes(), original)

    def test_bad_database_signature_with_resigned_manifest_and_envelope(self):
        path = self.local_bundle / 'repo/fixture.db.tar.gz.sig'
        path.write_bytes(b'unsigned TEST signature')
        release_path = self.local_bundle / 'release.json'
        release = c.decode(release_path.read_bytes())
        release['files'][path.relative_to(self.local_bundle).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
        release_path.write_bytes(c.encoded(release))
        self.sign(release_path)
        self.metadata.unlink()
        c.build(self.build_args)
        self.sign(self.metadata)
        self.args.apply = True
        with self.assertRaisesRegex(c.Error, 'GPG rejected'):c.verify(self.args)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_full_apply_precommit_cleanup_and_sync_failures_preserve_existing_checkpoint(self):
        self.apply()
        original = self.checkpoint_bytes()
        self.changed_metadata(sequence=2)
        cleanup = c.tempfile.TemporaryDirectory.cleanup
        def cleanup_failure(instance):
            cleanup(instance)
            raise OSError('TEST cleanup failure')
        for failure in ('cleanup', 'sync', 'replace'):
            if failure == 'cleanup':
                patched = mock.patch.object(c.tempfile.TemporaryDirectory, 'cleanup', cleanup_failure)
            elif failure == 'sync':
                patched = mock.patch.object(c.os, 'fsync', side_effect=OSError('TEST precommit sync failure'))
            else:
                patched = mock.patch.object(c.os, 'replace', side_effect=OSError('TEST precommit replace failure'))
            with self.subTest(failure=failure), patched:
                with self.assertRaises(OSError):c.verify(self.args)
            self.assertEqual(self.checkpoint_bytes(), original)
            self.assertEqual([p.name for p in self.state.iterdir()], [c.CHECKPOINT])

    def test_real_sha1_signature_rejected(self):
        self.sign(self.metadata, digest='SHA1')
        self.args.apply = True
        with self.assertRaises(c.Error):c.verify(self.args)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_real_wrong_primary_in_mixed_keyring_is_rejected(self):
        home = self.directory / 'TEST-other-primary'
        home.mkdir(mode=0o700)
        self.addCleanup(lambda: subprocess.run(['gpgconf', '--homedir', str(home), '--kill', 'all'], capture_output=True, timeout=30))
        self.gpg(['--pinentry-mode', 'loopback', '--passphrase', '', '--quick-generate-key',
                  'TEST ONLY other client <other@test.invalid>', 'ed25519', 'sign', '1d'], home=home)
        listing = self.gpg(['--with-colons', '--list-keys'], home=home).decode()
        key = next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
        self.keyring.write_bytes(self.public + self.gpg(['--export', key], home=home))
        self.sign(self.metadata, home=home, key=key)
        self.args.apply = True
        with self.assertRaisesRegex(c.Error, 'full pinned primary'):
            c.verify(self.args)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_real_revoked_public_certificate_rejected(self):
        home = self.directory / 'TEST-revocation-home'
        home.mkdir(mode=0o700)
        self.homes.append(home)
        public = self.directory / 'TEST-public.gpg'
        public.write_bytes(self.public)
        self.gpg(['--import', public], home=home)
        data = (self.home / 'openpgp-revocs.d' / (self.key + '.rev')).read_text()
        marker = ':-----BEGIN PGP PUBLIC KEY BLOCK-----'
        revocation = self.directory / 'TEST-revocation.asc'
        revocation.write_text(data[data.index(marker):].replace(marker, marker[1:], 1))
        self.gpg(['--import', revocation], home=home)
        self.keyring.write_bytes(self.gpg(['--export', self.key], home=home))
        self.args.apply = True
        with self.assertRaises(c.Error):c.verify(self.args)
        self.assertEqual(list(self.state.iterdir()), [])
        subprocess.run(['gpgconf', '--homedir', str(home), '--kill', 'all'], capture_output=True, timeout=30)
        self.homes.remove(home)

    def test_real_expired_key_rejected_without_checkpoint(self):
        home = self.directory / 'TEST-expired-signing-home'
        home.mkdir(mode=0o700)
        self.addCleanup(lambda: subprocess.run(['gpgconf', '--homedir', str(home), '--kill', 'all'], capture_output=True, timeout=30))
        past = int((datetime.now(timezone.utc) - timedelta(days=2)).timestamp())
        self.gpg(['--faked-system-time', str(past) + '!', '--pinentry-mode', 'loopback', '--passphrase', '',
                  '--quick-generate-key', 'TEST ONLY expired client <expired@test.invalid>', 'ed25519', 'sign', '1d'], home=home)
        listing = self.gpg(['--with-colons', '--list-keys'], home=home).decode()
        key = next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
        self.changed_metadata(signer=key)
        Path(self.args.signature).unlink()
        self.gpg(['--faked-system-time', str(past + 1) + '!', '--pinentry-mode', 'loopback', '--passphrase', '',
                  '--local-user', key, '--digest-algo', 'SHA256', '--detach-sign', '--output', self.args.signature,
                  self.metadata], home=home)
        self.keyring.write_bytes(self.gpg(['--export', key], home=home))
        self.args.signer, self.args.apply = key, True
        with self.assertRaises(c.Error):c.verify(self.args)
        self.assertEqual(list(self.state.iterdir()), [])

    def test_existing_release_stage_bundle_is_consumed_without_interface_changes(self):
        missing = [tool for tool in ('repo-add', 'bsdtar', 'vercmp') if not shutil.which(tool)]
        if missing:
            self.skipTest('actual release-stage adapter tools unavailable: ' + ', '.join(missing))
        path = Path(__file__).parents[1] / 'release/test_release.py'
        loader = importlib.util.spec_from_file_location('existing_release_tests', path)
        module = importlib.util.module_from_spec(loader)
        loader.loader.exec_module(module)
        module.ReleaseTests.setUpClass()
        self.addCleanup(module.ReleaseTests.tearDownClass)
        fixture = module.ReleaseTests(methodName='test_signed_stage_and_verify')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.source_delivery_fixture()
        fixture.stage()  # Real existing stage/signature actors, synthetic source-delivery materials and retained review bytes.
        metadata = self.directory / 'actual-stage-envelope.json'
        args = copy.copy(self.build_args)
        args.bundle, args.output, args.signer = str(fixture.directory), str(metadata), fixture.key
        c.build(args)
        fixture.r = module.r
        module.r.sign(metadata, fixture.key, fixture.env)
        public = self.directory / 'actual-stage-TEST-public.gpg'
        public.write_bytes(module.r.run(['gpg', '--batch', '--homedir', fixture.home, '--export', fixture.key], env=fixture.env))
        check = copy.copy(self.args)
        check.bundle, check.metadata, check.signature = str(fixture.directory), str(metadata), str(metadata) + '.sig'
        check.signer, check.public_keyring, check.apply = fixture.key, str(public), True
        result = c.verify(check)
        self.assertEqual(result['status'], 'applied-development')
        self.assertFalse(result['stable_accepted'])
        self.assertEqual(result['signer']['signing_fingerprint'], fixture.key)
        self.assertEqual(result['release_sha256'], module.r.sha(fixture.directory / 'release.json'))
        source_args=copy.copy(check)
        selected=fixture.source_record['package']
        source_args.package,source_args.version,source_args.arch=(selected[key] for key in ('name','version','arch'))
        source_args.artifact_sha256=selected['sha256'];source_args.output=str(self.directory/'real-stage-source-export')
        before=(self.state/c.CHECKPOINT).read_bytes()
        result=c.sources(source_args)
        self.assertEqual(result['status'],'source-delivery-export-development')
        self.assertEqual(result['source_delivery'],fixture.source_record)
        self.assertEqual(result['release_sha256'],module.r.sha(fixture.directory/'release.json'))
        self.assertEqual((self.state/c.CHECKPOINT).read_bytes(),before)
        self.assertFalse(result['source_completeness_accepted'])

    def source_fixture(self, version=None):
        """Opted-in opaque source bytes with an opaque retained review and supplied status label."""
        release = c.decode((self.local_bundle / 'release.json').read_bytes())
        package = release['packages'][0]
        if version is not None:
            old = self.local_bundle / 'repo' / package['filename']
            archive = old.with_name('fixture-' + version + '-any.pkg.tar.gz')
            with tarfile.open(old, 'r:gz') as source, tarfile.open(archive, 'w:gz') as destination:
                for member in source.getmembers():
                    data = source.extractfile(member).read()
                    if member.name == '.PKGINFO':
                        data = data.replace(b'pkgver = 1-1\n', ('pkgver = ' + version + '\n').encode())
                    member.size = len(data); destination.addfile(member, io.BytesIO(data))
            old.unlink(); Path(str(old) + '.sig').unlink(); self.sign(archive)
            package.update(version=version, filename=archive.name, sha256=c.digest(archive.read_bytes()))
        identity = {key: package[key] for key in ('name', 'version', 'arch', 'sha256')}
        materials = {}
        def material(identifier, raw):
            materials[identifier] = raw
            return dict(id=identifier, path='publisher-inputs/' + identifier,
                        sha256=c.digest(raw), bytes=len(raw))
        recipe = material('fixture-recipe.txt', b'# INERT TEST RECIPE; NEVER EXECUTE\n')
        record = dict(package=identity, bundle=material('fixture-source.tar.gz', b'OPAQUE INERT SOURCE BUNDLE\n'),
            notices=[material('fixture-notice.txt', b'TEST ONLY permission attestation; no real source grant\n')],
            source_map=material('fixture-source-map.json', c.encoded({'PKGBUILD': recipe['sha256']})),
            recipe=recipe, recipe_key='PKGBUILD',review_status='REVIEWED_SOURCE_ONLY')
        record['authorization'] = material('fixture-existing-review.txt',
            b'OPAQUE RETAINED TEST REVIEW; source preparation only, no delivery/completeness assertion\n')
        index = dict(schema_version=1,purpose='release-source-delivery',synthetic=True,packages=[record])
        index_descriptor = material('fixture-source-index.json',c.encoded(index))
        spec = c.decode((self.local_bundle / 'spec.json').read_bytes())
        spec.update(policy=dict(selected_packages=['fixture']), evidence=[
            {key:row[key] for key in ('id','path','sha256')} for row in [index_descriptor,record['bundle'],
             *record['notices'],record['source_map'],record['recipe'],record['authorization']]],
            source_delivery=dict(schema_version=1,index={key:index_descriptor[key] for key in ('id','path','sha256')}))
        evidence = self.local_bundle / 'evidence'; evidence.mkdir()
        for identifier, raw in materials.items(): (evidence / identifier).write_bytes(raw)
        (self.local_bundle / 'spec.json').write_bytes(c.encoded(spec))
        provenance = self.local_bundle / 'provenance'; provenance.mkdir()
        (provenance / 'fixture.json').write_bytes(c.encoded(dict(package={k:identity[k] for k in ('name','version','arch')},
            artifact_sha256=identity['sha256'],recipe_sha256=recipe['sha256'])))
        package['provenance']='provenance/fixture.json'
        (self.local_bundle / 'release.json').write_bytes(c.encoded(release))
        self.source_reseal()
        self.source_record=record
        self.source_args=copy.copy(self.args)
        self.source_args.package,self.source_args.version,self.source_args.arch='fixture',package['version'],'any'
        self.source_args.artifact_sha256=identity['sha256']; self.source_args.output=None
        return spec, index

    def source_reseal(self):
        release_path=self.local_bundle/'release.json';release=c.decode(release_path.read_bytes())
        release['files']={path.relative_to(self.local_bundle).as_posix():c.digest(path.read_bytes())
            for path in self.local_bundle.rglob('*') if path.is_file() and not path.is_symlink()
            and path.relative_to(self.local_bundle).as_posix() not in ('release.json','release.json.sig')}
        release_path.write_bytes(c.encoded(release)); self.sign(release_path)
        # A fixture publisher can sign malformed source associations. This does
        # not bypass the actual client verifier or source association validator.
        value=c.decode(self.metadata.read_bytes())
        value['targets']['release_record']['sha256']=c.digest(release_path.read_bytes())
        value['targets']['spec']['sha256']=release['files']['spec.json']
        self.metadata.write_bytes(c.encoded(value)); self.sign(self.metadata)

    def test_sources_tilde_version_real_signed_lookup_export_and_tamper_refusal(self):
        version = '1.0~rc1-1'
        self.source_fixture(version)
        # Real tar metadata, package/release signatures, envelope and source map;
        # all under temporary TEST key homes with no installed package/trust writes.
        fresh = copy.copy(self.build_args); fresh.output = str(self.directory / 'tilde-envelope.json')
        c.build(fresh); self.sign(Path(fresh.output))
        self.source_args.metadata = fresh.output
        self.source_args.signature = fresh.output + '.sig'
        before = list(self.state.iterdir())
        looked = c.sources(self.source_args)
        self.assertEqual(looked['package']['version'], version)
        self.assertFalse(looked['state_changed'])
        self.source_args.output = str(self.directory / 'tilde-sources')
        exported = c.sources(self.source_args)
        self.assertEqual(exported['export']['package']['version'], version)
        self.assertFalse(exported['export']['source_completeness_accepted'])
        self.assertEqual(list(self.state.iterdir()), before)
        with tarfile.open(self.local_bundle / 'repo' / ('fixture-' + version + '-any.pkg.tar.gz')) as archive:
            self.assertIn(('pkgver = ' + version + '\n').encode(), archive.extractfile('.PKGINFO').read())
        target = self.local_bundle / 'evidence/fixture-notice.txt'
        target.write_bytes(target.read_bytes() + b'TAMPER')
        self.source_args.output = str(self.directory / 'never-export')
        with self.assertRaisesRegex(c.Error, 'payload checksum'): c.sources(self.source_args)
        self.assertFalse(Path(self.source_args.output).exists())
        self.assertEqual(list(self.state.iterdir()), before)

    def test_sources_actual_signed_lookup_export_and_unchanged_envelope_checkpoint(self):
        self.apply(); before=self.checkpoint_bytes(); original_keys=set(c.decode(self.metadata.read_bytes()))
        self.source_fixture()
        # The real unsigned builder also accepts the opted-in index, with exact
        # old envelope-v1 targets. Verification/export cannot apply a checkpoint.
        other=copy.copy(self.build_args);other.output=str(self.directory/'opted-envelope.json')
        c.build(other)
        fresh=c.decode(Path(other.output).read_bytes())
        self.assertEqual(set(fresh),original_keys)
        self.assertEqual(set(fresh['targets']),{'release_record','spec','databases','packages'})
        # A higher signed sequence is needed after the old checkpoint, even for lookup.
        self.changed_metadata(sequence=2)
        self.source_args.apply=True
        result=c.sources(self.source_args)
        self.assertEqual(result['status'],'source-delivery-lookup-development')
        self.assertEqual(result['source_delivery'],self.source_record)
        self.assertEqual(result['review_status'],'REVIEWED_SOURCE_ONLY')
        for name in ('stable_accepted','state_changed','source_completeness_accepted','legal_acceptance',
                     'native_validation','hardware_validation','public_delivery_accepted'):
            self.assertIs(result[name],False)
        self.assertEqual(self.checkpoint_bytes(),before)
        self.assertFalse((self.directory/'export').exists())
        self.source_args.output=str(self.directory/'export')
        exported=c.sources(self.source_args)
        self.assertEqual(exported['status'],'source-delivery-export-development')
        self.assertEqual(exported['export']['package'],result['package'])
        self.assertEqual(exported['export']['review_status'],'REVIEWED_SOURCE_ONLY')
        self.assertFalse(exported['export']['source_completeness_accepted'])
        self.assertFalse(exported['export']['legal_acceptance'])
        self.assertEqual(exported['export']['release_sha256'],result['release_sha256'])
        expected=c.source_delivery_helper().materials(self.source_record)
        self.assertEqual(set(path.name for path in Path(self.source_args.output).iterdir()),
            {row['id'] for row in expected}|{'source-delivery-receipt.json'})
        for row in expected:
            actual=Path(self.source_args.output)/row['id']
            self.assertEqual(c.digest(actual.read_bytes()),row['sha256'])
            self.assertEqual(actual.stat().st_mode&0o777,0o600)
        self.assertEqual(Path(self.source_args.output).stat().st_mode&0o777,0o700)
        self.assertEqual(self.checkpoint_bytes(),before)

    def test_sources_generic_bundle_not_declared_never_exports(self):
        args=copy.copy(self.args);args.package,args.version,args.arch='fixture','1-1','any'
        args.artifact_sha256=c.decode((self.local_bundle/'release.json').read_bytes())['packages'][0]['sha256']
        args.output=str(self.directory/'absent-export');args.apply=True
        self.assertEqual(c.verify(self.args)['status'],'verified-development')
        with self.assertRaisesRegex(c.Error,'not declared'):c.sources(args)
        self.assertFalse(Path(args.output).exists());self.assertEqual(list(self.state.iterdir()),[])

    def test_sources_exact_requested_identity_and_unsafe_output(self):
        self.source_fixture()
        for key,value in (('package','other'),('version','2-1'),('arch','aarch64'),('artifact_sha256','a'*64)):
            args=copy.copy(self.source_args);setattr(args,key,value)
            with self.subTest(key=key),self.assertRaisesRegex(c.Error,'identity absent'):c.sources(args)
        alias=self.directory/'export-alias';alias.symlink_to(self.local_bundle,target_is_directory=True)
        for output in (str(self.local_bundle),str(alias),str(self.directory/'new/../escape'),
                       str(self.local_bundle/'new-export'),str(self.state/'new-export'),
                       str(self.directory)+'//noncanonical-export','relative-export'):
            args=copy.copy(self.source_args);args.output=output
            with self.subTest(output=output),self.assertRaises((c.Error,ValueError,OSError)):c.sources(args)
        self.assertEqual(list(self.state.iterdir()),[])

    def test_sources_reject_material_tamper_missing_and_spec_signed_map_disagreement(self):
        self.source_fixture();target=self.local_bundle/'evidence/fixture-notice.txt';raw=target.read_bytes()
        target.write_bytes(b'TAMPER')
        with self.assertRaisesRegex(c.Error,'payload checksum'):c.sources(self.source_args)
        target.unlink()
        with self.assertRaises(OSError):c.sources(self.source_args)
        target.write_bytes(raw)
        spec=c.decode((self.local_bundle/'spec.json').read_bytes())
        spec['source_delivery']['index']['sha256']='a'*64
        next(row for row in spec['evidence'] if row['id']=='fixture-source-index.json')['sha256']='a'*64
        (self.local_bundle/'spec.json').write_bytes(c.encoded(spec));self.source_reseal()
        with self.assertRaisesRegex(c.Error,'signed release/spec'):c.sources(self.source_args)
        self.assertEqual(list(self.state.iterdir()),[])

    def test_sources_provenance_and_index_coverage_cannot_be_foreign_even_resigned(self):
        self.source_fixture();path=self.local_bundle/'provenance/fixture.json';raw=path.read_bytes()
        value=c.decode(raw);value['artifact_sha256']='a'*64;path.write_bytes(c.encoded(value));self.source_reseal()
        with self.assertRaisesRegex(c.Error,'provenance artifact identity'):c.sources(self.source_args)
        path.write_bytes(raw)
        spec_path=self.local_bundle/'spec.json';spec=c.decode(spec_path.read_bytes())
        spec['policy']['selected_packages']=['other'];spec_path.write_bytes(c.encoded(spec));self.source_reseal()
        with self.assertRaisesRegex(ValueError,'selected release package set'):c.sources(self.source_args)

    def test_sources_reopen_substitution_refused_without_export(self):
        self.source_fixture();self.source_args.output=str(self.directory/'never-export')
        actual_verify=c.verify
        def substituted(args,**kwargs):
            result=actual_verify(args,**kwargs)
            release_path=self.local_bundle/'release.json';release=c.decode(release_path.read_bytes())
            release['created_utc']='2099-01-01T00:00:00Z';release_path.write_bytes(c.encoded(release))
            return result
        with mock.patch.object(c,'verify',side_effect=substituted):
            with self.assertRaisesRegex(c.Error,'changed after verification'):c.sources(self.source_args)
        self.assertFalse(Path(self.source_args.output).exists());self.assertEqual(list(self.state.iterdir()),[])

    def test_sources_material_changes_after_describe_refused_before_lookup_and_export(self):
        self.source_fixture();actual=c.describe;calls=[]
        def changed(root):
            result=actual(root);calls.append(1)
            if len(calls)==2:(self.local_bundle/'evidence/fixture-notice.txt').write_bytes(b'REOPEN TAMPER')
            return result
        with mock.patch.object(c,'describe',side_effect=changed):
            with self.assertRaisesRegex(c.Error,'source evidence bytes changed'):c.sources(self.source_args)
        self.assertEqual(len(calls),2);self.assertEqual(list(self.state.iterdir()),[])

    def test_sources_export_rechecks_material_after_last_association(self):
        self.source_fixture();self.source_args.output=str(self.directory/'never-export')
        load=c.source_delivery_helper;calls=[]
        def changed():
            helper=load();calls.append(1)
            if len(calls)==4:
                (self.local_bundle/'evidence/fixture-notice.txt').write_bytes(b'LAST READ TAMPER')
            return helper
        with mock.patch.object(c,'source_delivery_helper',side_effect=changed):
            with self.assertRaisesRegex(c.Error,'source evidence bytes changed'):c.sources(self.source_args)
        self.assertEqual(len(calls),4)
        self.assertFalse(Path(self.source_args.output).exists());self.assertEqual(list(self.state.iterdir()),[])

    def test_sources_cli_readonly_lookup_and_apply_flag_refused(self):
        self.source_fixture()
        argv=[sys.executable,'-B',str(Path(__file__).with_name('client_v2.py')),'sources']
        for key in ('bundle','metadata','signature','public_keyring','signer','namespace','state_dir',
                    'package','version','arch','artifact_sha256'):
            argv+=['--'+key.replace('_','-'),str(getattr(self.source_args,key))]
        result=subprocess.run(argv,capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'],'source-delivery-lookup-development')
        result=subprocess.run(argv+['--apply'],capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,2);self.assertEqual(list(self.state.iterdir()),[])

    def test_builder_refuses_overwrite_and_output_inside_bundle(self):
        original = self.metadata.read_bytes()
        with self.assertRaises(FileExistsError):c.build(self.build_args)
        self.assertEqual(self.metadata.read_bytes(), original)
        self.build_args.output = str(self.local_bundle / 'metadata.json')
        with self.assertRaisesRegex(c.Error, 'outside'):c.build(self.build_args)
        self.assertFalse((self.local_bundle / 'metadata.json').exists())

    def test_cli_default_is_readonly_and_failure_is_nonzero(self):
        argv = [sys.executable, '-B', str(Path(__file__).with_name('client_v2.py')), 'verify']
        for name in ('bundle', 'metadata', 'signature', 'public_keyring', 'signer', 'namespace', 'state_dir'):
            argv += ['--' + name.replace('_', '-'), str(getattr(self.args, name))]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'verified-development')
        self.assertEqual(list(self.state.iterdir()), [])
        result = subprocess.run(argv + ['--minimum-sequence', '2', '--apply'], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 1)
        self.assertIn('supplied floor', result.stderr)
        self.assertEqual(list(self.state.iterdir()), [])



class SourceVersionTests(unittest.TestCase):
    """Real filesystem/association/export; signature verification is an explicit boundary."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='source-version-control-');self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name);self.bundle=self.base/'bundle';self.bundle.mkdir();self.state=self.base/'state';self.state.mkdir(mode=0o700)
        self.version='1.0~rc1-1';repo=self.bundle/'repo';repo.mkdir();self.filename='fixture-'+self.version+'-any.pkg.tar.gz';package=repo/self.filename
        with tarfile.open(package,'w:gz')as archive:
            raw=('pkgname = fixture\npkgver = '+self.version+'\narch = any\n').encode();m=tarfile.TarInfo('.PKGINFO');m.size=len(raw);archive.addfile(m,io.BytesIO(raw))
        for name in ('fixture.db.tar.gz','fixture.files.tar.gz',self.filename):
            if name!=self.filename:(repo/name).write_bytes(b'INERT DATABASE UNIT FIXTURE NOT REPOSITORY ACCEPTANCE')
            (repo/(name+'.sig')).write_bytes(b'INERT SIGNATURE BOUNDARY NOT CRYPTO ACCEPTANCE')
        evidence=self.bundle/'evidence';evidence.mkdir();record=dict(package=dict(name='fixture',version=self.version,arch='any',sha256=c.digest(package.read_bytes())),recipe_key='PKGBUILD',review_status='INCOMPLETE UNIT SOURCE DATA ONLY')
        def material(eid,raw):
            (evidence/eid).write_bytes(raw);return dict(id=eid,path=eid,bytes=len(raw),sha256=c.digest(raw))
        record.update(bundle=material('source.tar',b'OPAQUE UNIT SOURCE'),recipe=material('recipe.txt',b'INERT RECIPE NEVER EXECUTE'),notices=[material('NOTICE',b'UNIT NOTICE')],authorization=material('review.txt',b'INCOMPLETE UNIT REVIEW'))
        record['source_map']=material('map.json',c.encoded({'PKGBUILD':record['recipe']['sha256']}));index=material('index.json',c.encoded(dict(schema_version=1,purpose='release-source-delivery',synthetic=True,packages=[record])))
        helper=c.source_delivery_helper();evidence_rows=[{k:r[k]for k in ('id','path','sha256')}for r in [index,*helper.materials(record)]]
        spec=dict(schema_version=1,release_id='fixture',repo_name='fixture',target_arch='aarch64',synthetic=True,policy=dict(selected_packages=['fixture']),evidence=evidence_rows,source_delivery=dict(schema_version=1,index=evidence_rows[0]));(self.bundle/'spec.json').write_bytes(c.encoded(spec))
        provenance=self.bundle/'provenance';provenance.mkdir();(provenance/'fixture.json').write_bytes(c.encoded(dict(package={k:record['package'][k]for k in ('name','version','arch')},artifact_sha256=record['package']['sha256'],recipe_sha256=record['recipe']['sha256'])))
        files={p.relative_to(self.bundle).as_posix():c.digest(p.read_bytes())for p in self.bundle.rglob('*')if p.is_file()};release=dict(schema_version=1,release_id='fixture',signer='A'*40,files=files,packages=[dict(record['package'],filename=self.filename,provenance='provenance/fixture.json')]);(self.bundle/'release.json').write_bytes(c.encoded(release))
        self.args=argparse.Namespace(package='fixture',version=self.version,arch='any',artifact_sha256=record['package']['sha256'],bundle=str(self.bundle),state_dir=str(self.state),output=None,apply=True)
    def test_tilde_version_description_lookup_export_and_tamper_refusal(self):
        root=c.directory(self.bundle)
        try:actual,release,raw=c.describe(root)
        finally:os.close(root)
        self.assertEqual(actual['targets']['packages'][0]['version'],self.version)
        # Only the enclosing authentication result is stubbed. All actual source
        # map/provenance/material/output-path/receipt checks execute unchanged.
        with mock.patch.object(c,'verify',return_value={'release_sha256':c.digest(raw)})as verified:
            result=c.sources(self.args);self.assertEqual(result['package']['version'],self.version);self.assertFalse(verified.call_args.args[0].apply)
            self.args.output=str(self.base/'export');exported=c.sources(self.args);self.assertEqual(exported['export']['package']['version'],self.version);self.assertFalse(exported['state_changed']);self.assertFalse(exported['export']['source_completeness_accepted'])
            self.assertEqual(list(self.state.iterdir()),[]);self.assertEqual((self.base/'export').stat().st_mode&0o777,0o700)
            target=self.bundle/'evidence/NOTICE';target.write_bytes(target.read_bytes()+b'TAMPER');self.args.output=str(self.base/'never-export')
            with self.assertRaisesRegex(c.Error,'payload checksum'):c.sources(self.args)
            self.assertFalse((self.base/'never-export').exists());self.assertEqual(list(self.state.iterdir()),[])
    def test_version_path_controls_remain_refused_before_verification(self):
        for value in ('1 2','../1','1/2','1\x00x','1\\2','1\n2',''):
            args=copy.copy(self.args);args.version=value
            with mock.patch.object(c,'verify',side_effect=AssertionError('unsafe identity before verification')),self.assertRaises(c.Error):c.sources(args)

if __name__ == '__main__':
    unittest.main(verbosity=2)
