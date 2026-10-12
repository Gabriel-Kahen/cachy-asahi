#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real temporary TEST GPG/repo-add; synthetic repository, never native evidence."""
import base64
import copy
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


def section_bytes(values):
    return ''.join('%' + key + '%\n' + '\n'.join(rows) + '\n\n' for key, rows in values.items()).encode()


def structure_public():
    """In-memory unsigned structure only; these bytes never receive GPG acceptance."""
    names = sorted(crypto.ORIGINALS | {crypto.PROBE})
    repos = {}
    def build(label, version, *, tampered=False, unsigned=False):
        repo, packs = {}, {}
        for name in names:
            payload = (f'SYNTHETIC TEST fixture version {version[0]}\n'.encode() if name == crypto.PROBE
                       else ('UNSIGNED STRUCTURE ' + name + version).encode())
            if tampered and name == crypto.PROBE:
                payload = b'SYNTHETIC TEST tampered version 2\n'
            fields = {'pkgname': name, 'pkgbase': name, 'pkgver': version, 'arch': 'any', 'license': 'MIT',
                      'pkgdesc': 'UNSIGNED structure fixture', 'size': str(len(payload)), 'builddate': '1791748800',
                      'packager': 'TEST ONLY STRUCTURAL'}
            if name in ('cachy-asahi-fish-config', 'cachy-asahi-zsh-config'):
                fields['url'] = ''
            metadata = ''.join(f'{key} = {value}\n' for key, value in fields.items()).encode()
            raw = tar_bytes({'.PKGINFO': metadata, f'usr/share/{name}/fixture.txt': payload})
            filename = f'{name}-{version}-any.pkg.tar.xz'; repo[filename] = raw
            if not (unsigned and name == crypto.PROBE):
                repo[filename + '.sig'] = (repos['updated-B'][filename + '.sig'] if tampered and name == crypto.PROBE
                                          else ('UNVERIFIED STRUCTURAL SIGNATURE ' + label + name).encode())
            info, members = crypto.package(raw); packs[name] = filename, raw, info, members
        desc, files = {}, {}
        for name, (filename, raw, info, members) in packs.items():
            values = {'NAME': [name], 'VERSION': info['pkgver'], 'ARCH': info['arch'], 'FILENAME': [filename],
                      'CSIZE': [str(len(raw))], 'SHA256SUM': [digest(raw)]}
            for source, target in (('pkgbase', 'BASE'), ('pkgdesc', 'DESC'), ('size', 'ISIZE'), ('license', 'LICENSE'),
                                   ('builddate', 'BUILDDATE'), ('packager', 'PACKAGER')):
                values[target] = info[source]
            if filename + '.sig' in repo:
                values['PGPSIG'] = [base64.b64encode(repo[filename + '.sig']).decode()]
            folder = name + '-' + info['pkgver'][0]
            desc[folder + '/desc'] = section_bytes(values)
            files[folder + '/desc'] = desc[folder + '/desc']
            files[folder + '/files'] = section_bytes({'FILES': sorted(path for path in members if not path.startswith('.'))})
        for kind, rows in (('db', desc), ('files', files)):
            raw = tar_bytes(rows, 'w:gz'); signature = ('UNVERIFIED STRUCTURAL DB ' + label + kind).encode()
            for suffix in ('', '.tar.gz'):
                repo['integration.' + kind + suffix] = raw
                repo['integration.' + kind + suffix + '.sig'] = signature
        return repo
    repos['baseline-A'] = build('baseline-A', '1-1')
    repos['updated-B'] = build('updated-B', '2-1')
    repos['tampered-package-B'] = build('tampered-package-B', '2-1', tampered=True)
    repos['missing-package-signature-B'] = build('missing-package-signature-B', '2-1', unsigned=True)
    repos['tampered-database-B'] = dict(repos['updated-B'])
    for name in ('integration.db', 'integration.db.tar.gz'):
        repos['tampered-database-B'][name] += b'UNSIGNED TEST DATABASE TAMPER'
    repos['missing-database-signature-B'] = {name: raw for name, raw in repos['updated-B'].items()
                                           if name not in ('integration.db.sig', 'integration.db.tar.gz.sig')}
    public = {'TEST-repositories/' + label + '/' + name: raw for label, repo in repos.items() for name, raw in repo.items()}
    aliases = {'active': {'target': 'updated-B', 'kind': 'directory'}}
    for label, repo in repos.items():
        for kind in ('db', 'files'):
            for suffix in ('', '.sig'):
                name = 'integration.' + kind + suffix
                if name in repo:
                    aliases[label + '/' + name] = {'target': label + '/integration.' + kind + '.tar.gz' + suffix,
                                                  'kind': 'file', 'regular_copy_sha256': digest(repo[name])}
    public['TEST-repository-aliases.json'] = encoded(aliases)
    public['TEST-repository-aliases.json.sig'] = b'UNVERIFIED STRUCTURAL ALIAS SIGNATURE'
    public['TEST-pacman.conf'] = crypto.STRICT_CONFIG
    for role in ('signer-A', 'signer-B', 'verifier', 'signer-A-revoked'):
        public['TEST-' + role + '-public.asc'] = b'UNVERIFIED STRUCTURAL CERTIFICATE'
    return public


def structure_packset(public, label='baseline-A'):
    prefix = 'TEST-repositories/' + label + '/'; packs, signatures = {}, {}
    for path, raw in public.items():
        if path.startswith(prefix) and path.endswith('.pkg.tar.xz'):
            info, payload = crypto.package(raw); name = info['pkgname'][0]
            packs[name] = path[len(prefix):], raw, info, payload
            signatures[name] = public[path + '.sig']
    return packs, signatures


def url_relation(package_lines, database_lines):
    raw = ('pkgname = cachy-asahi-fish-config\npkgver = 1-1\narch = any\n' + package_lines).encode()
    info, _ = crypto.package(tar_bytes({'.PKGINFO': raw}))
    desc = database_lines.encode()
    return crypto.url_values(raw, info, package_metadata=True), crypto.url_values(desc, crypto.sections(desc))


class RealFixture:
    def __init__(self, root, url=None):
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
                if url is not None:
                    info += ('url = ' + url + '\n').encode()
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


class URLTests(unittest.TestCase):
    def test_exact_empty_and_absence_equal_omission(self):
        for raw in ('', 'url = \n'):
            self.assertEqual(url_relation(raw, ''), ([], []))

    def test_nonempty_singleton_preserved_exactly(self):
        value = 'https://example.test/project'
        self.assertEqual(url_relation('url = ' + value + '\n', '%URL%\n' + value + '\n\n'), ([value], [value]))

    def test_nonempty_contradictions_and_asymmetric_omission_do_not_equal(self):
        value = 'https://example.test/project'
        for left, right in ((value, ''), ('', value), (value, value + '/'), (value, value.upper()),
                            (value, value.replace('project', '%70roject'))):
            p, d = url_relation('url = ' + left + '\n', '%URL%\n' + right + '\n\n' if right else '')
            self.assertNotEqual(p, d)

    def test_package_scalar_duplicates_refused(self):
        for values in (['', ''], ['x', 'x'], ['', 'x'], ['x', 'y']):
            with self.subTest(values=values), self.assertRaisesRegex(ValueError, 'duplicate-url-field'):
                url_relation(''.join('url = ' + value + '\n' for value in values), '')

    def test_database_multiple_values_refused(self):
        with self.assertRaisesRegex(ValueError, 'duplicate-url-field'):
            url_relation('url = x\n', '%URL%\nx\nx\n\n')

    def test_duplicate_database_sections_refused(self):
        with self.assertRaisesRegex(ValueError, 'duplicate-db-section'):
            url_relation('url = x\n', '%URL%\nx\n\n%URL%\nx\n\n')

    def test_present_empty_database_url_is_not_omission(self):
        with self.assertRaisesRegex(ValueError, 'malformed-db-url'):
            url_relation('url = \n', '%URL%\n\n')

    def test_whitespace_padding_and_controls_refused(self):
        value = 'https://example.test/project'
        for item in (' ', '\t', ' ' + value, value + ' ', *(value + char for char in
                     ('\r', '\v', '\f', '\u0085', '\u2028', '\x00', '\x7f', '\x80', '\u200b', '\u202e', '\u2066'))):
            with self.subTest(value=repr(item)), self.assertRaises(ValueError):
                url_relation('url = ' + item + '\n', '')
        for char in ('\u200b', '\u202e', '\u2066'):
            raw = ('%URL%\n' + value + char + '\n\n').encode()
            with self.assertRaisesRegex(ValueError, 'malformed-url-value'):
                crypto.url_values(raw, crypto.sections(raw))

    def test_raw_cr_erased_by_parser_still_refused(self):
        raw = b'url = https://example.test/project\r\n'
        with self.assertRaisesRegex(ValueError, 'malformed-package-url'):
            crypto.url_values(raw, {'url': ['https://example.test/project']}, package_metadata=True)

    def test_non_url_opaque_header_lookalike_preserved(self):
        for field in ('DESC', 'PACKAGER'):
            for suffix in ('', '%URL%\nx\n\n'):
                raw = ('%' + field + '%\n %URL% \n\n' + suffix).encode()
                self.assertEqual(crypto.url_values(raw, crypto.sections(raw)), ['x'] if suffix else [])

    def test_malformed_package_delimiters_and_keys_refused(self):
        for raw in ('url=x\n', 'url = x\n url = x\n', 'url\t = x\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                url_relation(raw, '')

    def test_malformed_db_header_value_and_terminator_refused(self):
        for raw in ('%URL%\r\nx\n\n', '%URL%\nx\r\n\n', '%URL%\nx\n%LICENSE%\nMIT\n\n', '%URL%\n \n\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                url_relation('url = x\n', raw)


class URLStructureTests(unittest.TestCase):
    """Unsigned in-memory metadata counterexamples; no crypto acceptance claims."""
    @classmethod
    def setUpClass(cls):
        cls.public = structure_public()

    def case(self, change, kind='db'):
        packs, sigs = structure_packset(self.public)
        rows = crypto.members(self.public['TEST-repositories/baseline-A/integration.' + kind + '.tar.gz'])
        path = next(name for name in rows if name.startswith('cachy-asahi-fish-config-') and name.endswith('/desc'))
        change(rows, path)
        return crypto.database(tar_bytes(rows, 'w:gz'), packs, sigs, files_database=kind == 'files')

    def test_full_six_repository_structure_causal_url_comparison(self):
        before = {name: digest(raw) for name, raw in self.public.items()}
        # Control reproduces only the predecessor's exact URL list comparison.
        def predecessor_url(_data, parsed, *, package_metadata=False):
            return parsed.get('url' if package_metadata else 'URL', [])
        with mock.patch.object(crypto, 'url_values', side_effect=predecessor_url):
            with self.assertRaisesRegex(ValueError, 'db-package-relation-mismatch'):
                crypto.audit_repositories(self.public)
        self.assertEqual(set(crypto.audit_repositories(self.public)), set(crypto.LABELS))
        self.assertEqual(before, {name: digest(raw) for name, raw in self.public.items()})

    def test_both_healthy_database_types_complete_five_packages(self):
        for label in ('baseline-A', 'updated-B'):
            packs, sigs = structure_packset(self.public, label)
            for kind in ('db', 'files'):
                raw = self.public['TEST-repositories/' + label + '/integration.' + kind + '.tar.gz']
                self.assertEqual(len(crypto.database(raw, packs, sigs, files_database=kind == 'files')), 5)

    def test_empty_package_url_cannot_match_nonempty_database_url(self):
        for kind in ('db', 'files'):
            with self.assertRaisesRegex(ValueError, 'db-package-relation-mismatch'):
                self.case(lambda rows, path: rows.update({path: rows[path] + b'%URL%\nx\n\n'}), kind)

    def test_archive_checksum_and_size_bindings_required(self):
        for field in ('SHA256SUM', 'CSIZE'):
            def poison(rows, path):
                values = crypto.sections(rows[path]); values[field] = ['0' * 64 if field == 'SHA256SUM' else '1']
                rows[path] = section_bytes(values)
            with self.assertRaisesRegex(ValueError, 'db-package-byte-or-identity-mismatch'):
                self.case(poison)

    def test_embedded_signature_bytes_required(self):
        def poison(rows, path):
            values = crypto.sections(rows[path]); values['PGPSIG'] = [base64.b64encode(b'WRONG UNVERIFIED SIGNATURE').decode()]
            rows[path] = section_bytes(values)
        with self.assertRaisesRegex(ValueError, 'embedded-signature-byte-mismatch'):
            self.case(poison)

    def test_dependency_and_license_relations_exact(self):
        for field in ('DEPENDS', 'LICENSE'):
            def poison(rows, path):
                values = crypto.sections(rows[path]); values[field] = ['contradiction']; rows[path] = section_bytes(values)
            with self.assertRaisesRegex(ValueError, 'db-package-relation-mismatch'):
                self.case(poison)

    def test_files_database_payload_inventory_exact(self):
        def poison(rows, path):
            name = path[:-4] + 'files'; values = crypto.sections(rows[name]); values['FILES'].append('unexpected/file')
            rows[name] = section_bytes(values)
        with self.assertRaisesRegex(ValueError, 'files-database-payload-mismatch'):
            self.case(poison, 'files')

    def test_unknown_desc_fields_and_duplicate_sections_refused(self):
        for suffix in (b'%UNKNOWN%\nx\n\n', b'%NAME%\ncachy-asahi-fish-config\n\n'):
            with self.assertRaises(ValueError):
                self.case(lambda rows, path: rows.update({path: rows[path] + suffix}))

    def test_alias_maps_and_exact_negative_differences_required(self):
        for path, raw in (('TEST-repositories/baseline-A/integration.db', b'wrong alias'),
                          ('TEST-repositories/tampered-database-B/integration.db.tar.gz', b'wrong tamper'),
                          ('TEST-repository-aliases.json', b'{}\n')):
            changed = dict(self.public); changed[path] = raw
            with self.assertRaises(ValueError): crypto.audit_repositories(changed)
        changed = dict(self.public)
        omitted = next(path for path in changed if path.startswith('TEST-repositories/updated-B/') and path.endswith('.pkg.tar.xz.sig'))
        changed.pop(omitted)
        with self.assertRaisesRegex(ValueError, 'package-signature-missing'): crypto.audit_repositories(changed)

    def test_coherent_duplicate_package_and_db_urls_refused(self):
        packs, sigs = structure_packset(self.public); packs = copy.deepcopy(packs)
        rows = crypto.members(self.public['TEST-repositories/baseline-A/integration.db.tar.gz'])
        name = 'cachy-asahi-fish-config'; filename, raw, info, payload = packs[name]
        payload['.PKGINFO'] = payload['.PKGINFO'].replace(b'url = \n', b'url = x\nurl = x\n')
        raw = tar_bytes(payload); info, payload = crypto.package(raw); packs[name] = filename, raw, info, payload
        path = name + '-' + info['pkgver'][0] + '/desc'; values = crypto.sections(rows[path])
        values.update(CSIZE=[str(len(raw))], SHA256SUM=[digest(raw)], URL=['x', 'x']); rows[path] = section_bytes(values)
        with self.assertRaisesRegex(ValueError, 'duplicate-url-field'):
            crypto.database(tar_bytes(rows, 'w:gz'), packs, sigs)

    def test_db_empty_url_and_non_url_opaque_values_remain_distinct(self):
        def opaque(rows, path):
            # Test URL helper against a real descriptor containing unrelated bytes.
            values = crypto.sections(rows[path]); values['PACKAGER'] = [' %URL% ']
            data = section_bytes(values)
            self.assertEqual(crypto.url_values(data, crypto.sections(data)), [])
        self.case(opaque)
        with self.assertRaisesRegex(ValueError, 'malformed-db-url'):
            self.case(lambda rows, path: rows.update({path: rows[path] + b'%URL%\n\n'}))


if __name__ == '__main__':
    unittest.main()
