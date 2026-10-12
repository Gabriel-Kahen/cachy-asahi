#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real temporary TEST GPG/repo-add; synthetic repository, never native evidence."""
import gzip
import io
import lzma
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

import crypto
from common import digest, encoded


def tar_bytes(rows, mode='w:xz'):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode=mode) as archive:
        for name, data in rows.items():
            member = tarfile.TarInfo(name); member.mode = 0o644; member.size = len(data)
            archive.addfile(member, io.BytesIO(data))
    return buffer.getvalue()


class RealFixture:
    def __init__(self, root):
        self.root = root; self.private = root / 'private'; self.private.mkdir(mode=0o700)
        self.inputs = root / 'inputs'; self.inputs.mkdir()
        self.environment = dict(os.environ, LC_ALL='C', TZ='UTC')
        self.keys, self.objects, self.observations = {}, [], []
        self.native_index = 0
        for role, usage in (('signer-A', 'sign'), ('signer-B', 'sign'), ('verifier', 'cert')):
            home = self.private / role; home.mkdir(mode=0o700)
            self.run(['gpg', '--batch', '--no-options', '--homedir', str(home), '--pinentry-mode', 'loopback',
                      '--passphrase', '', '--quick-generate-key', 'TEST ONLY synthetic crypto ' + role + ' <' + role + '@test.invalid>',
                      'ed25519', usage, '1d'])
            listing = self.run(['gpg', '--batch', '--no-options', '--homedir', str(home), '--with-colons', '--list-keys'])[0]
            fingerprint = next(line.split(':')[9] for line in listing.decode().splitlines() if line.startswith('fpr:'))
            certificate = 'TEST-' + role + '-public.asc'
            self.put(certificate, self.run(['gpg', '--batch', '--no-options', '--homedir', str(home), '--armor', '--export', fingerprint])[0])
            self.keys[role] = {'fingerprint': fingerprint, 'certificate': certificate}
        for label, version, role in (('baseline-A', '1-1', 'signer-A'), ('updated-B', '2-1', 'signer-B'),
                                     ('tampered-package-B', '2-1', 'signer-B'), ('missing-package-signature-B', '2-1', 'signer-B')):
            folder = self.inputs / 'TEST-repositories' / label; folder.mkdir(parents=True)
            packages = []
            for name in sorted(crypto.ORIGINALS | {crypto.PROBE}):
                value = ('SYNTHETIC TEST fixture version ' + version[0] + '\n').encode() if name == crypto.PROBE else ('SYNTHETIC TEST ' + name + version).encode()
                if name == crypto.PROBE and label == 'tampered-package-B':
                    value = b'SYNTHETIC TEST tampered version 2\n'
                info = (f'pkgname = {name}\npkgbase = {name}\npkgver = {version}\narch = any\nlicense = MIT\n'
                        f'pkgdesc = TEST ONLY synthetic fixture\nsize = {len(value)}\nbuilddate = 1791748800\npackager = TEST ONLY\n').encode()
                filename = name + '-' + version + '-any.pkg.tar.xz'
                path = folder / filename
                path.write_bytes(tar_bytes({'.PKGINFO': info, 'usr/share/' + name + '/fixture.txt': value}))
                packages.append(path)
                if name == crypto.PROBE and label == 'missing-package-signature-B':
                    continue
                if name == crypto.PROBE and label == 'tampered-package-B':
                    shutil.copyfile(self.inputs / 'TEST-repositories/updated-B' / (filename + '.sig'), folder / (filename + '.sig'))
                else:
                    self.sign(path, role)
            self.run(['repo-add', '--include-sigs', '--sign', '--key', self.keys[role]['fingerprint'],
                      str(folder / 'integration.db.tar.gz'), *map(str, packages)], role=role)
            for kind in ('db', 'files'):
                path = folder / ('integration.' + kind + '.tar.gz')
                if not Path(str(path) + '.sig').exists():
                    self.sign(path, role)
                for suffix in ('', '.sig'):
                    alias = folder / ('integration.' + kind + suffix)
                    if alias.is_symlink():
                        data = alias.read_bytes(); alias.unlink(); alias.write_bytes(data)
            if label in ('baseline-A', 'updated-B'):
                for path in packages + [folder / 'integration.db.tar.gz', folder / 'integration.files.tar.gz']:
                    self.observe(path, role)
        healthy = self.inputs / 'TEST-repositories/updated-B'
        for label in ('tampered-database-B', 'missing-database-signature-B'):
            folder = self.inputs / 'TEST-repositories' / label
            shutil.copytree(healthy, folder)
            if label == 'tampered-database-B':
                for name in ('integration.db', 'integration.db.tar.gz'):
                    with (folder / name).open('ab') as stream:
                        stream.write(b'UNSIGNED TEST DATABASE TAMPER')
            else:
                for name in ('integration.db.sig', 'integration.db.tar.gz.sig'):
                    (folder / name).unlink()
        # Revoke A at the real clock, retaining actual earlier successful status logs.
        home = self.private / 'signer-A'
        text = (home / 'openpgp-revocs.d' / (self.keys['signer-A']['fingerprint'] + '.rev')).read_text()
        marker = ':-----BEGIN PGP PUBLIC KEY BLOCK-----'
        revoked = self.private / 'revocation.asc'; revoked.write_text(text[text.index(marker):].replace(marker, marker[1:], 1))
        self.run(['gpg', '--batch', '--no-options', '--homedir', str(home), '--import', str(revoked)])
        self.keys['signer-A']['revoked_certificate'] = 'TEST-signer-A-revoked-public.asc'
        self.put('TEST-signer-A-revoked-public.asc', self.run(['gpg', '--batch', '--no-options', '--homedir', str(home),
                                                          '--armor', '--export', self.keys['signer-A']['fingerprint']])[0])
        path = self.inputs / 'TEST-repositories/baseline-A/integration.db.tar.gz'
        out, _, code = self.run(['gpg', '--batch', '--no-options', '--homedir', str(home), '--status-fd', '1', '--verify',
                                str(path) + '.sig', str(path)], any_exit=True)
        self.put('native/revoked-status.txt', out)
        self.revocation = {'status_log': 'native/revoked-status.txt', 'exit_code': code, 'command_index': self.native_index}
        self.native_index += 1
        aliases = {'active': {'target': 'updated-B', 'kind': 'directory'}}
        for label in crypto.LABELS:
            folder = self.inputs / 'TEST-repositories' / label
            for kind in ('db', 'files'):
                for suffix in ('', '.sig'):
                    name = 'integration.' + kind + suffix
                    if (folder / name).exists():
                        aliases[label + '/' + name] = {'target': label + '/integration.' + kind + '.tar.gz' + suffix,
                                                      'kind': 'file', 'regular_copy_sha256': digest((folder / name).read_bytes())}
        self.put('TEST-repository-aliases.json', encoded(aliases))
        self.put('TEST-pacman.conf', crypto.STRICT_CONFIG)
        self.sign(self.inputs / 'TEST-repository-aliases.json', 'signer-B')
        self.observe(self.inputs / 'TEST-repository-aliases.json', 'signer-B')
        self.request = {'schema_version': 2, 'purpose': 'repository-cryptographic-phases', 'source_commit': 'a' * 40,
                        'run_id': '123', 'nonce': 'b' * 32, 'image_id': 'sha256:' + 'c' * 64, 'public_prefix': '',
                        'files': self.mapping(), 'signers': self.keys, 'signed_objects': sorted(self.objects, key=lambda row: row['path']),
                        'native_verifications': self.observations, 'native_revocation': self.revocation}

    def run(self, argv, role=None, any_exit=False):
        environment = dict(self.environment)
        if role:
            environment['GNUPGHOME'] = str(self.private / role)
        process = subprocess.run(argv, env=environment, capture_output=True, timeout=45)
        if not any_exit and process.returncode:
            raise AssertionError(process.stderr.decode(errors='replace'))
        return process.stdout, process.stderr, process.returncode

    def sign(self, path, role):
        self.run(['gpg', '--batch', '--no-options', '--homedir', str(self.private / role), '--local-user', self.keys[role]['fingerprint'],
                  '--digest-algo', 'SHA256', '--detach-sign', '--output', str(path) + '.sig', str(path)])

    def observe(self, path, role):
        out, _, code = self.run(['gpg', '--batch', '--no-options', '--homedir', str(self.private / role), '--status-fd', '1',
                                '--verify', str(path) + '.sig', str(path)])
        name = path.relative_to(self.inputs).as_posix()
        log = 'native/' + str(self.native_index) + '.txt'; self.put(log, out)
        self.objects.append({'path': name, 'signature': name + '.sig', 'signer': role})
        self.observations.append({'path': name, 'status_log': log, 'exit_code': code, 'command_index': self.native_index,
                                  'native_phase': 'pre-A-revocation' if role == 'signer-A' else 'unrevoked-B'})
        self.native_index += 1

    def put(self, name, data):
        path = self.inputs / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)

    def mapping(self):
        return {path.relative_to(self.inputs).as_posix(): {'sha256': digest(path.read_bytes()), 'bytes': path.stat().st_size}
                for path in self.inputs.rglob('*') if path.is_file()}

    def close(self):
        for role in ('signer-A', 'signer-B', 'verifier'):
            self.run(['gpgconf', '--homedir', str(self.private / role), '--kill', 'all'])


class CryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='TEST-only-real-repository-crypto-')
        cls.fixture = RealFixture(Path(cls.temporary.name))

    @classmethod
    def tearDownClass(cls):
        cls.fixture.close(); cls.temporary.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='TEST-only-crypto-case-'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.inputs = self.root / 'inputs'
        shutil.copytree(self.fixture.inputs, self.inputs)
        self.request = crypto.decode(encoded(self.fixture.request))

    def attest(self):
        raw = encoded(self.request)
        return crypto.attest(self.inputs, raw, digest(raw), self.root / 'output')

    def rebind(self, name, data):
        (self.inputs / name).write_bytes(data)
        self.request['files'][name] = {'sha256': digest(data), 'bytes': len(data)}

    def test_real_complete_snapshot_and_terminal_authorization(self):
        result = self.attest()
        self.assertEqual(result['status'], 'PASS', result)
        self.assertEqual(result['private_work_cleanup'], 'PASS')
        self.assertEqual(result['current_A_authorization'], 'REVOKED')
        self.assertEqual(result['native_observation_boundary'], 'retained-native-observations-only')
        self.assertEqual(len(result['snapshot_integrity']), 15)
        self.assertTrue(all(row['authorization'] == 'SNAPSHOT_ONLY' for row in result['snapshot_integrity']))
        for row in result['snapshot_integrity'] + result['terminal_authorization'] + result['negative_verifications']:
            raw = row['machine_status'].encode()
            self.assertEqual(digest(raw), row['status_sha256'])
            self.assertEqual(len(raw), row['status_bytes'])
            self.assertRegex(row['stderr_sha256'], r'^[0-9a-f]{64}$')
        self.assertEqual([row['authorization'] for row in result['negative_verifications']].count('REJECTED'), 2)
        self.assertTrue(result['public_only_agent_sockets_absent'])
        self.assertTrue(all('--no-autostart' in row['argv'] for row in result['commands'] if Path(row['argv'][0]).name == 'gpg'))
        self.assertEqual(result['actual_software_environment']['execution'], 'local-bounded-private-processes')
        self.assertEqual(set(result['source_sha256']), {'common.py', 'crypto.py'})
        for role, expiry in result['certificate_expiry'].items():
            self.assertLess(result['observed_at'], expiry)
            self.assertLess(result['completed_at'], expiry)
            row = result['signer_certificates'][role]
            self.assertEqual(row['fingerprint'], self.request['signers'][role]['fingerprint'])
            self.assertEqual(row['certificate_sha256'], self.request['files'][row['certificate']]['sha256'])
            self.assertEqual(row['expires_at'], expiry)
        self.assertEqual([row['authorization'] for row in result['terminal_authorization']].count('REVOKED'), 7)
        self.assertEqual([row['authorization'] for row in result['terminal_authorization']].count('VALID_AT_OBSERVATION'), 8)
        self.assertTrue((self.root / 'output/result.json').is_file())
        self.assertFalse(list(self.root.glob('repository-crypto-*')))

    def test_real_revocation_status_accepts_exit_zero_semantics(self):
        raw = (self.inputs / self.request['native_revocation']['status_log']).read_bytes()
        result = crypto.verify_phase(raw, self.request['signers']['signer-A']['fingerprint'], 'revoked', 0)
        self.assertEqual(result['authorization'], 'REVOKED')
        with self.assertRaises(ValueError):
            crypto.verify_phase(raw, self.request['signers']['signer-A']['fingerprint'])

    def test_wrong_full_identity_fails_real_status(self):
        row = self.request['native_verifications'][0]
        raw = (self.inputs / row['status_log']).read_bytes()
        with self.assertRaises(ValueError):
            crypto.verify_phase(raw, self.request['signers']['signer-B']['fingerprint'])

    def test_all_forbidden_positive_statuses_refused(self):
        row = self.request['native_verifications'][0]; raw = (self.inputs / row['status_log']).read_bytes()
        for status in crypto.BAD:
            with self.subTest(status=status), self.assertRaises(ValueError):
                crypto.verify_phase(raw + ('\n[GNUPG:] ' + status + '\n').encode(), self.request['signers']['signer-A']['fingerprint'])

    def test_v1_and_wrong_external_pin_refused_before_tools(self):
        with mock.patch.object(crypto, 'Commands', side_effect=AssertionError('tools must not execute')):
            raw = encoded(self.request)
            self.assertEqual(crypto.attest(self.inputs, raw, '0' * 64, self.root / 'output')['status'], 'FAIL')
            self.request['schema_version'] = 1
            self.assertEqual(self.attest()['status'], 'FAIL')

    def test_coherently_rebound_native_revocation_as_positive_refused(self):
        row = next(row for row in self.request['native_verifications'] if row['native_phase'] == 'pre-A-revocation')
        self.rebind(row['status_log'], (self.inputs / self.request['native_revocation']['status_log']).read_bytes())
        result = self.attest(); self.assertEqual(result['status'], 'FAIL')
        self.assertIn('forbidden-signature', result['error'])

    def test_native_A_after_revocation_order_refused(self):
        self.request['native_verifications'][0]['command_index'] = 999
        self.assertEqual(self.attest()['status'], 'FAIL')

    def test_rebound_embedded_signature_mismatch_refused(self):
        name = 'TEST-repositories/updated-B/integration.db.tar.gz'
        rows = {name: value for name, value in crypto.members((self.inputs / name).read_bytes()).items() if value is not None}
        first = next(name for name in rows if name.endswith('/desc'))
        text = rows[first].decode(); lines = text.splitlines(); index = lines.index('%PGPSIG%')
        lines[index + 1] = 'VU5TSUdORUQ='; rows[first] = ('\n'.join(lines) + '\n').encode()
        self.rebind(name, tar_bytes(rows, 'w:gz'))
        self.rebind('TEST-repositories/updated-B/integration.db', (self.inputs / name).read_bytes())
        self.assertEqual(self.attest()['status'], 'FAIL')

    def test_private_certificate_refused(self):
        cert = self.request['signers']['signer-B']['certificate']
        raw = self.fixture.run(['gpg', '--batch', '--homedir', str(self.fixture.private / 'signer-B'), '--armor', '--export-secret-keys',
                                self.request['signers']['signer-B']['fingerprint']])[0]
        self.rebind(cert, raw)
        result = self.attest(); self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['private_work_cleanup'], 'PASS')
        self.assertFalse((self.root / 'output').exists())

    def test_real_wrong_signature_rebound_refused(self):
        path = next(row['path'] for row in self.request['signed_objects'] if row['signer'] == 'signer-B' and '.pkg.' in row['path'])
        # Preserve package/DB records: signed alias is a separate mandatory object.
        self.rebind('TEST-repository-aliases.json.sig', (self.inputs / (path + '.sig')).read_bytes())
        result = self.attest(); self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['private_work_cleanup'], 'PASS')

    def test_alias_and_negative_exact_differences_refused(self):
        path = 'TEST-repositories/missing-database-signature-B/integration.files'
        self.rebind(path, (self.inputs / path).read_bytes() + b'UNEXPECTED')
        self.assertEqual(self.attest()['status'], 'FAIL')

    def test_package_tar_links_refused(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:xz') as archive:
            row = tarfile.TarInfo('evil'); row.type = tarfile.SYMTYPE; row.linkname = '/etc/passwd'; archive.addfile(row)
        with self.assertRaises(ValueError):
            crypto.members(buffer.getvalue())

    def test_real_signal_after_receipt_write_invalidates_pass(self):
        original = crypto.Publication.write
        def interrupt(publication, raw):
            value = original(publication, raw)
            os.kill(os.getpid(), signal.SIGTERM)
            return value
        with mock.patch.object(crypto.Publication, 'write', new=interrupt):
            result = self.attest()
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['private_work_cleanup'], 'PASS')
        self.assertFalse((self.root / 'output/result.json').exists())

    def test_expiry_control_refuses_without_gpg_faketime(self):
        # Explicit unit control over admission's clock; no altered-clock GPG execution.
        with mock.patch.object(crypto.time, 'time', return_value=2**40):
            result = self.attest()
        self.assertEqual(result['status'], 'FAIL')
        self.assertIn('current-expiry', result['error'])
        self.assertFalse(any('--faked-system-time' in row['argv'] for row in result['commands']))

    def test_real_signal_during_work_assignment_cleans_created_directory(self):
        original = crypto.tempfile.mkdtemp
        def interrupt(*args, **kwargs):
            path = original(*args, **kwargs)
            os.kill(os.getpid(), signal.SIGTERM)
            return path
        with mock.patch.object(crypto.tempfile, 'mkdtemp', side_effect=interrupt):
            result = self.attest()
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['private_work_cleanup'], 'PASS')
        self.assertFalse(list(self.root.glob('repository-crypto-*')))
        self.assertFalse((self.root / 'output').exists())

    def test_real_signal_in_teardown_finishes_cleanup_then_fails(self):
        original = crypto.Commands.run
        injected = []
        def interrupt(commands, argv, expected=0):
            value = original(commands, argv, expected)
            if str(argv[0]) == 'gpgconf' and not injected:
                injected.append(True); os.kill(os.getpid(), signal.SIGINT)
            return value
        with mock.patch.object(crypto.Commands, 'run', new=interrupt):
            result = self.attest()
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['private_work_cleanup'], 'PASS')
        self.assertTrue(injected)
        self.assertFalse(list(self.root.glob('repository-crypto-*')))
        self.assertFalse((self.root / 'output').exists())

    def test_unmapped_input_and_symlink_refused_before_tools(self):
        (self.inputs / 'unexpected.txt').write_bytes(b'UNMAPPED')
        with mock.patch.object(crypto, 'Commands', side_effect=AssertionError('tools must not execute')):
            self.assertEqual(self.attest()['status'], 'FAIL')
        (self.inputs / 'unexpected.txt').unlink()
        name = self.request['native_revocation']['status_log']
        source = self.inputs / name; raw = source.read_bytes(); source.unlink()
        target = self.root / 'outside.txt'; target.write_bytes(raw); source.symlink_to(target)
        with mock.patch.object(crypto, 'Commands', side_effect=AssertionError('tools must not execute')):
            self.assertEqual(self.attest()['status'], 'FAIL')

    def test_real_signal_after_terminal_close_invalidates_pass(self):
        original = crypto.Publication.close; injected = []
        def interrupt(publication):
            was_open = publication.fd is not None
            original(publication)
            if was_open and (self.root / 'output/result.json').exists() and not injected:
                injected.append(True); os.kill(os.getpid(), signal.SIGINT)
        with mock.patch.object(crypto.Publication, 'close', new=interrupt):
            result = self.attest()
        self.assertEqual(result['status'], 'FAIL')
        self.assertEqual(result['private_work_cleanup'], 'PASS')
        self.assertTrue(injected)
        self.assertFalse((self.root / 'output/result.json').exists())

    def test_real_rename_before_and_after_terminal_close_preserves_foreign_receipt(self):
        for timing, sig in (('before', signal.SIGTERM), ('after', signal.SIGINT)):
            with self.subTest(timing=timing):
                output = self.root / ('output-' + timing); retired = self.root / ('renamed-' + timing)
                original = crypto.Publication.close; injected = []
                def replace():
                    output.rename(retired); output.mkdir()
                    (output / 'result.json').write_bytes(b'FOREIGN USER RECEIPT')
                    injected.append(True); os.kill(os.getpid(), sig)
                def close(publication):
                    target = publication.fd is not None and publication.output == output and not injected
                    if target and timing == 'before':
                        replace()
                    original(publication)
                    if target and timing == 'after':
                        replace()
                raw = encoded(self.request)
                with mock.patch.object(crypto.Publication, 'close', new=close):
                    result = crypto.attest(self.inputs, raw, digest(raw), output)
                self.assertEqual(result['status'], 'FAIL')
                self.assertEqual(result['private_work_cleanup'], 'PASS')
                self.assertTrue(result['publication']['receipt_absence_verified'])
                self.assertFalse((retired / 'result.json').exists())
                self.assertEqual((output / 'result.json').read_bytes(), b'FOREIGN USER RECEIPT')

    def test_rename_without_signal_refuses_and_invalidates_original_receipt(self):
        output = self.root / 'output'; retired = self.root / 'renamed'; original = crypto.Publication.write
        def replace(publication, raw):
            original(publication, raw)
            output.rename(retired); output.mkdir()
            (output / 'result.json').write_bytes(b'FOREIGN USER RECEIPT')
        with mock.patch.object(crypto.Publication, 'write', new=replace):
            result = self.attest()
        self.assertEqual(result['status'], 'FAIL')
        self.assertTrue(result['publication']['receipt_absence_verified'])
        self.assertFalse((retired / 'result.json').exists())
        self.assertEqual((output / 'result.json').read_bytes(), b'FOREIGN USER RECEIPT')

    def test_compressed_expansion_bombs_refused_before_tar_parsing(self):
        payload = b'\0' * (32 * 1024**2 + 1)
        for name, data in (('gzip', gzip.compress(payload)), ('xz', lzma.compress(payload))):
            with self.subTest(format=name), mock.patch.object(crypto.tarfile, 'open', side_effect=AssertionError('tar must not parse bomb')):
                with self.assertRaises(ValueError):
                    crypto.members(data)

    def test_pax_headers_refused_before_tarfile_consumes_body(self):
        for kind in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE):
            row = tarfile.TarInfo('PaxHeader'); row.type = kind; row.size = 2**31
            raw = row.tobuf(format=tarfile.USTAR_FORMAT) + b'\0' * 1024
            with self.subTest(kind=kind), mock.patch.object(crypto.tarfile, 'open', side_effect=AssertionError('tar must not parse PAX')):
                with self.assertRaisesRegex(ValueError, 'pax-header-refused'):
                    crypto.members(raw)

    def test_normal_tar_root_directory_is_allowed(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:gz', format=tarfile.USTAR_FORMAT) as archive:
            row = tarfile.TarInfo('./'); row.type = tarfile.DIRTYPE; archive.addfile(row)
            row = tarfile.TarInfo('./payload'); row.size = 1; archive.addfile(row, io.BytesIO(b'x'))
        self.assertEqual(crypto.members(buffer.getvalue()), {'payload': b'x'})

    def test_trailing_compressed_and_raw_data_refused(self):
        raw = tar_bytes({'payload': b'x'}, 'w:')
        for data in (gzip.compress(raw) + b'extra', lzma.compress(raw) + b'extra', raw + b'extra'):
            with self.subTest(prefix=data[:6]), self.assertRaises(ValueError):
                crypto.members(data)


if __name__ == '__main__':
    unittest.main()
