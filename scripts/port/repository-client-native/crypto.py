#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Real-clock public-only crypto checks; snapshot integrity is not authorization."""
import base64
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import tarfile
import tempfile
import time

from common import Commands, Refused, bounded_tar_payload, cancellation_handlers, decode, defer_cancellation, digest, directory, encoded, need, read, write_new

ORIGINALS = frozenset(('cachy-asahi-hyprland-settings', 'cachy-asahi-fish-config',
                      'cachy-asahi-zsh-config', 'cachy-asahi-setup'))
PROBE = 'cachy-asahi-repository-test-fixture'
LABELS = ('baseline-A', 'updated-B', 'tampered-package-B', 'tampered-database-B',
          'missing-database-signature-B', 'missing-package-signature-B')
LIMIT, TOTAL = 8 * 1024**2, 64 * 1024**2
HASH = re.compile(r'[0-9a-f]{64}\Z')
FINGERPRINT = re.compile(r'[0-9A-F]{40}\Z')
BAD = frozenset(('EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'BADSIG', 'ERRSIG', 'NO_PUBKEY',
                 'KEYEXPIRED', 'SIGEXPIRED', 'KEYREVOKED', 'FAILURE', 'ERROR', 'NODATA',
                 'BADARMOR', 'UNEXPECTED', 'INV_SGNR', 'NO_SECKEY'))
FIELDS = frozenset(('schema_version', 'purpose', 'source_commit', 'run_id', 'nonce', 'image_id',
                   'files', 'signers', 'signed_objects', 'native_verifications', 'native_revocation', 'public_prefix'))
STRICT_CONFIG = ('[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\n'
                 'LocalFileSigLevel = Required TrustedOnly\nParallelDownloads = 1\n'
                 '[integration]\nSigLevel = Required TrustedOnly\nServer = file:///scratch/repos/active\n').encode()


def relative(value):
    need(isinstance(value, str) and value and '\\' not in value and '\x00' not in value,
         'invalid-relative-path')
    path = PurePosixPath(value)
    need(not path.is_absolute() and path.as_posix() == value and '..' not in path.parts
         and all(part not in ('', '.') for part in value.split('/')), 'unsafe-relative-path')
    return path


def verify_phase(stdout, fingerprint, phase='positive', exit_code=0):
    """Validate actual machine status, including revoked signatures with exit zero."""
    need(isinstance(fingerprint, str) and FINGERPRINT.fullmatch(fingerprint), 'invalid-fingerprint')
    if isinstance(stdout, bytes):
        stdout = stdout.decode('utf-8', errors='strict')
    need(isinstance(stdout, str) and phase in ('positive', 'revoked'), 'invalid-verification-phase')
    need(type(exit_code) is int and (exit_code == 0 if phase == 'positive' else exit_code in (0, 1)),
         'verification-exit-policy')
    rows = [line.split()[1:] for line in stdout.splitlines() if line.startswith('[GNUPG:] ')]
    forbidden = BAD if phase == 'positive' else BAD - {'REVKEYSIG', 'KEYREVOKED'}
    need(rows and not any(row and row[0] in forbidden for row in rows), 'forbidden-signature-status')
    valid = [row for row in rows if row and row[0] == 'VALIDSIG']
    need(len(valid) == 1 and len(valid[0]) == 11 and valid[0][1] == valid[0][-1] == fingerprint
         and valid[0][8] in ('8', '9', '10', '11'), 'full-fingerprint-sha2-required')
    marker = 'GOODSIG' if phase == 'positive' else 'REVKEYSIG'
    signs = [row for row in rows if row and row[0] in ('GOODSIG', 'REVKEYSIG')]
    need(len(signs) == 1 and len(signs[0]) >= 2 and signs[0][0] == marker
         and signs[0][1] == fingerprint[-16:], 'signature-phase-marker-required')
    return {'phase': phase, 'fingerprint': fingerprint, 'digest_algorithm': int(valid[0][8]),
            'integrity': 'VALID', 'authorization': 'REVOKED' if phase == 'revoked' else 'SNAPSHOT_ONLY'}


def members(data):
    """Read bounded gzip/xz tar data without extraction or symlink following."""
    payload = bounded_tar_payload(data, limit=32 * 1024**2)
    # tarfile consumes PAX headers internally before yielding a member. Check the
    # fixed-size headers first, before it can allocate or apply those bodies.
    offset, headers = 0, 0
    while offset + 512 <= len(payload):
        header = payload[offset:offset + 512]
        if header == b'\0' * 512:
            need(not any(payload[offset:]), 'tar-trailing-nonzero-data')
            break
        row = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
        need(row.type not in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE), 'pax-header-refused')
        need(0 <= row.size <= LIMIT and headers < 4096, 'tar-header-bound')
        offset += 512 + ((row.size + 511) // 512) * 512
        headers += 1
        need(offset <= len(payload), 'truncated-tar-body')
    else:
        raise Refused('tar-end-marker-required')
    result, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(payload), mode='r:') as archive:
        for row in archive:
            need(not row.pax_headers, 'pax-member-refused')
            if row.name in ('.', './') and row.isdir():
                continue
            name = row.name.removeprefix('./').rstrip('/')
            need(name and not name.startswith('/') and '..' not in PurePosixPath(name).parts
                 and PurePosixPath(name).as_posix() == name, 'unsafe-tar-member')
            need(row.isdir() or row.isfile(), 'nonregular-tar-member')
            need(name not in result, 'duplicate-tar-member')
            need(0 <= row.size <= LIMIT and len(result) < 4096, 'tar-member-bound')
            if row.isdir():
                result[name] = None
                continue
            total += row.size
            need(total <= 32 * 1024**2 and len(result) < 4096, 'expanded-tar-bound')
            source = archive.extractfile(row)
            need(source is not None, 'missing-tar-member')
            value = source.read(row.size + 1)
            need(len(value) == row.size, 'truncated-tar-member')
            result[name] = value
    return result


class Publication:
    """Publish through an owned FD; invalidate that inode after replacement."""
    def __init__(self, output):
        self.output, self.fd, self.root_identity = output, None, None
        self.ancestors = [(path, self.identity(path.lstat())) for path in reversed(output.parents)]
        self.proof = {'status': 'NOT RUN', 'receipt_absence_verified': False}

    @staticmethod
    def identity(info):
        return info.st_dev, info.st_ino, info.st_mode

    def current(self):
        for path, before in self.ancestors:
            need(self.identity(path.lstat()) == before, 'publication-ancestor-replaced')
        need(self.identity(self.output.lstat()) == self.root_identity, 'publication-output-replaced')

    def create(self):
        with defer_cancellation():
            with directory(self.output.parent) as parent:
                os.mkdir(self.output.name, 0o700, dir_fd=parent)
                self.fd = os.open(self.output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                self.root_identity = self.identity(os.fstat(self.fd))
            self.current()

    def write(self, raw):
        need(isinstance(raw, bytes) and 0 < len(raw) <= 16 * 1024**2, 'crypto-receipt-byte-bound')
        need(self.fd is not None and self.identity(os.fstat(self.fd)) == self.root_identity,
             'publication-held-inode-changed')
        descriptor = os.open('result.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.fd)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        os.fsync(self.fd)

    def close(self):
        if self.fd is not None:
            descriptor, self.fd = self.fd, None
            os.close(descriptor)

    def invalidate(self):
        temporary = None
        if self.root_identity is None:
            self.proof = {'status': 'PASS', 'receipt_absence_verified': True, 'output_created': False}
            return
        try:
            if self.fd is not None:
                descriptor = self.fd
                need(self.identity(os.fstat(descriptor)) == self.root_identity, 'publication-held-inode-changed')
            else:
                for path, before in self.ancestors:
                    need(self.identity(path.lstat()) == before, 'publication-recovery-ancestor-replaced')
                with directory(self.output.parent) as parent:
                    names = os.listdir(parent)
                    need(len(names) <= 1024, 'publication-recovery-directory-bound')
                    matches = [name for name in names if self.identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == self.root_identity]
                    need(len(matches) == 1, 'publication-original-inode-unavailable')
                    temporary = os.open(matches[0], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                    need(self.identity(os.fstat(temporary)) == self.root_identity, 'publication-recovery-inode-changed')
                descriptor = temporary
            try:
                os.unlink('result.json', dir_fd=descriptor); os.fsync(descriptor)
            except FileNotFoundError:
                pass
            try:
                os.stat('result.json', dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                self.proof = {'status': 'PASS', 'receipt_absence_verified': True, 'output_created': True}
            else:
                raise Refused('authoritative-crypto-receipt-remains')
        except BaseException as error:
            self.proof = {'status': 'FAIL', 'receipt_absence_verified': False, 'error_type': type(error).__name__}
            raise
        finally:
            if temporary is not None:
                os.close(temporary)

    def publish(self, raw):
        try:
            self.create()
            with defer_cancellation():
                self.current(); self.write(raw); self.current(); self.close(); self.current()
            self.proof = {'status': 'PASS', 'receipt_published': True}
        except BaseException:
            with defer_cancellation():
                try:
                    self.invalidate()
                finally:
                    self.close()
            raise


def package(data):
    rows = members(data)
    need(isinstance(rows.get('.PKGINFO'), bytes), 'package-metadata-required')
    info = {}
    for line in rows['.PKGINFO'].decode().splitlines():
        if not line or line.startswith('#'):
            continue
        need(' = ' in line, 'malformed-pkginfo')
        key, value = line.split(' = ', 1)
        info.setdefault(key, []).append(value)
    need(all(len(info.get(key, [])) == 1 for key in ('pkgname', 'pkgver', 'arch'))
         and info['pkgname'][0] in ORIGINALS | {PROBE} and info['arch'][0] == 'any', 'package-identity-required')
    return info, rows


def sections(data):
    result, key = {}, None
    for line in data.decode().splitlines():
        if not line:
            key = None
        elif line.startswith('%') and line.endswith('%'):
            key = line[1:-1]
            need(key and key not in result, 'duplicate-db-section')
            result[key] = []
        else:
            need(key is not None, 'malformed-db-section')
            result[key].append(line)
    return result


def database(data, packages, signatures, *, files_database=False, unsigned=frozenset()):
    rows, found = members(data), {}
    allowed = {'FILENAME', 'NAME', 'BASE', 'VERSION', 'DESC', 'GROUPS', 'CSIZE', 'ISIZE', 'MD5SUM',
               'SHA256SUM', 'PGPSIG', 'URL', 'LICENSE', 'ARCH', 'BUILDDATE', 'PACKAGER', 'REPLACES',
               'CONFLICTS', 'PROVIDES', 'DEPENDS', 'OPTDEPENDS', 'MAKEDEPENDS', 'CHECKDEPENDS'}
    for path, value in rows.items():
        if value is None:
            continue
        parts = PurePosixPath(path).parts
        need(len(parts) == 2 and parts[1] in ('desc', 'files'), 'unexpected-db-member')
        need(files_database or parts[1] == 'desc', 'files-in-desc-database')
        if parts[1] != 'desc':
            continue
        desc = sections(value)
        need(set(desc) <= allowed and len(desc.get('NAME', [])) == 1, 'unexpected-db-record')
        name = desc['NAME'][0]
        need(name in packages and name not in found, 'unexpected-or-duplicate-db-package')
        filename, raw, info, package_rows = packages[name]
        need(parts[0] == name + '-' + info['pkgver'][0], 'db-directory-identity')
        expected = {'NAME': [name], 'VERSION': info['pkgver'], 'ARCH': info['arch'], 'FILENAME': [filename],
                    'CSIZE': [str(len(raw))], 'SHA256SUM': [digest(raw)]}
        if 'MD5SUM' in desc:
            expected['MD5SUM'] = [hashlib.md5(raw, usedforsecurity=False).hexdigest()]
        need(all(desc.get(key) == value for key, value in expected.items()), 'db-package-byte-or-identity-mismatch')
        for source, target in (('depend', 'DEPENDS'), ('optdepend', 'OPTDEPENDS'), ('provides', 'PROVIDES'),
                               ('conflict', 'CONFLICTS'), ('replaces', 'REPLACES'), ('license', 'LICENSE'),
                               ('pkgbase', 'BASE'), ('pkgdesc', 'DESC'), ('size', 'ISIZE'), ('url', 'URL'),
                               ('group', 'GROUPS'), ('builddate', 'BUILDDATE'), ('packager', 'PACKAGER'),
                               ('makedepend', 'MAKEDEPENDS'), ('checkdepend', 'CHECKDEPENDS')):
            need(desc.get(target, []) == info.get(source, []), 'db-package-relation-mismatch')
        if name in unsigned:
            need('PGPSIG' not in desc and name not in signatures, 'unsigned-probe-signature-present')
        else:
            need(len(desc.get('PGPSIG', [])) == 1
                 and base64.b64decode(desc['PGPSIG'][0], validate=True) == signatures[name], 'embedded-signature-byte-mismatch')
        if files_database:
            file_rows = sections(rows.get(parts[0] + '/files', b''))
            expected_files = sorted(path + ('/' if payload is None else '') for path, payload in package_rows.items()
                                    if not path.startswith('.'))
            need(set(file_rows) == {'FILES'} and file_rows['FILES'] == expected_files, 'files-database-payload-mismatch')
        found[name] = desc
    need(set(found) == ORIGINALS | {PROBE}, 'complete-five-package-database-required')
    need(len([name for name, value in rows.items() if value is not None]) == len(found) * (2 if files_database else 1),
         'extra-database-record')
    return found


def audit_repositories(public):
    """Check the six exact producer repositories, metadata and negative deltas."""
    repos = {label: {name.split('/', 2)[2]: data for name, data in public.items()
                     if name.startswith('TEST-repositories/' + label + '/')} for label in LABELS}
    expected_names = {'TEST-' + role + '-public.asc' for role in ('signer-A', 'signer-B', 'verifier')}
    expected_names |= {'TEST-signer-A-revoked-public.asc', 'TEST-repository-aliases.json', 'TEST-repository-aliases.json.sig', 'TEST-pacman.conf'}
    expected_names |= {'TEST-repositories/' + label + '/' + name for label, repo in repos.items() for name in repo}
    need(set(public) == expected_names and public['TEST-pacman.conf'] == STRICT_CONFIG, 'exact-public-artifacts-and-strict-config-required')
    parsed = {}
    for label in ('baseline-A', 'updated-B'):
        repo, packs, sigs = repos[label], {}, {}
        for name, raw in repo.items():
            if re.search(r'\.pkg\.tar\.(xz|gz)$', name):
                info, payload = package(raw)
                key = info['pkgname'][0]
                need(key not in packs and name == key + '-' + info['pkgver'][0] + '-any.pkg.tar.' + name.rsplit('.', 1)[1],
                     'package-filename-mismatch')
                need(name + '.sig' in repo, 'package-signature-missing')
                packs[key] = name, raw, info, payload
                sigs[key] = repo[name + '.sig']
        need(set(packs) == ORIGINALS | {PROBE}, 'five-public-packages-required')
        for kind in ('db', 'files'):
            name = 'integration.' + kind + '.tar.gz'
            need(name in repo and name + '.sig' in repo
                 and repo.get('integration.' + kind) == repo[name]
                 and repo.get('integration.' + kind + '.sig') == repo[name + '.sig'], 'database-alias-mismatch')
            database(repo[name], packs, sigs, files_database=kind == 'files')
        need(set(repo) == {name for filename, *_ in packs.values() for name in (filename, filename + '.sig')}
             | {f'integration.{kind}{suffix}' for kind in ('db', 'files') for suffix in ('', '.sig', '.tar.gz', '.tar.gz.sig')},
             'unexpected-healthy-repository-file')
        parsed[label] = packs
    a, b = parsed['baseline-A'], parsed['updated-B']
    for name in ORIGINALS | {PROBE}:
        need(a[name][2]['pkgver'] != b[name][2]['pkgver'] and a[name][1] != b[name][1], 'unchanged-upgrade-package')
        for key in ('depend', 'provides', 'conflict', 'replaces'):
            need(a[name][2].get(key, []) == b[name][2].get(key, []), 'changed-fixture-relations')
    healthy = repos['updated-B']
    for label, omitted in (('missing-package-signature-B', {b[PROBE][0] + '.sig'}),
                           ('missing-database-signature-B', {'integration.db.sig', 'integration.db.tar.gz.sig'})):
        other = repos[label]
        need(set(other) == set(healthy) - omitted, 'negative-omission-set-mismatch')
        if label == 'missing-database-signature-B':
            need(all(value == healthy[name] for name, value in other.items()), 'missing-db-unexpected-difference')
        else:
            permitted = {'integration.' + kind + suffix for kind in ('db', 'files')
                         for suffix in ('', '.sig', '.tar.gz', '.tar.gz.sig')} | {b[name][0] + '.sig' for name in ORIGINALS}
            need(all(value == healthy[name] for name, value in other.items() if name not in permitted),
                 'missing-package-unexpected-difference')
    tamper = repos['tampered-database-B']
    need(set(tamper) == set(healthy) and all(value == healthy[name] + b'UNSIGNED TEST DATABASE TAMPER'
         if name in {'integration.db', 'integration.db.tar.gz'} else value == healthy[name]
         for name, value in tamper.items()), 'tampered-database-difference-mismatch')
    tamper = repos['tampered-package-B']
    need(set(tamper) == set(healthy), 'tampered-package-file-set')
    permitted = {b[PROBE][0]} | {'integration.' + kind + suffix for kind in ('db', 'files')
                               for suffix in ('', '.sig', '.tar.gz', '.tar.gz.sig')} | {b[name][0] + '.sig' for name in ORIGINALS}
    need(all(value == healthy[name] for name, value in tamper.items() if name not in permitted),
         'tampered-package-unexpected-difference')
    info, altered = package(tamper[b[PROBE][0]])
    original = b[PROBE][3]
    # The native producer's single synthetic payload is the only permitted tamper.
    candidates = [key for key, value in original.items() if value == b'SYNTHETIC TEST fixture version 2\n']
    need(len(candidates) == 1, 'synthetic-probe-payload-required')
    path = candidates[0]
    expected_info = dict(b[PROBE][2]); expected_info['size'] = [str(len(b'SYNTHETIC TEST tampered version 2\n'))]
    expected_pkginfo = original['.PKGINFO'].replace(('size = ' + str(len(original[path])) + '\n').encode(),
                                                   ('size = ' + expected_info['size'][0] + '\n').encode())
    need(info == expected_info and altered.get('.PKGINFO') == expected_pkginfo
         and set(altered) == set(original) and altered[path] == b'SYNTHETIC TEST tampered version 2\n'
         and all(value == original[key] for key, value in altered.items() if key not in (path, '.PKGINFO')),
         'tampered-package-payload-difference')
    for label in ('missing-package-signature-B', 'tampered-package-B'):
        repo = repos[label]
        packs = dict(b)
        if label == 'tampered-package-B':
            packs[PROBE] = b[PROBE][0], repo[b[PROBE][0]], info, altered
        sigs = {name: repo[row[0] + '.sig'] for name, row in packs.items() if row[0] + '.sig' in repo}
        for kind in ('db', 'files'):
            if label == 'missing-package-signature-B':
                database(repo['integration.' + kind + '.tar.gz'], packs, sigs, files_database=kind == 'files', unsigned={PROBE})
            else:
                database(repo['integration.' + kind + '.tar.gz'], packs, sigs, files_database=kind == 'files')
            need(repo['integration.' + kind] == repo['integration.' + kind + '.tar.gz']
                 and repo['integration.' + kind + '.sig'] == repo['integration.' + kind + '.tar.gz.sig'], 'negative-db-alias-mismatch')
    aliases = decode(public['TEST-repository-aliases.json'])
    expected = {'active': {'target': 'updated-B', 'kind': 'directory'}}
    for label, repo in repos.items():
        for kind in ('db', 'files'):
            for suffix in ('', '.sig'):
                alias, target = 'integration.' + kind + suffix, 'integration.' + kind + '.tar.gz' + suffix
                if alias in repo:
                    expected[label + '/' + alias] = {'target': label + '/' + target, 'kind': 'file',
                                                     'regular_copy_sha256': digest(repo[alias])}
    need(aliases == expected, 'exact-alias-map-required')
    return repos


def attest(input_root, request_raw, request_sha256, output):
    with cancellation_handlers():
        return _attest(input_root, request_raw, request_sha256, output)


def _attest(input_root, request_raw, request_sha256, output):
    result = {'schema_version': 2, 'purpose': 'repository-cryptographic-phases', 'status': 'FAIL',
              'current_A_authorization': 'NOT ACCEPTED', 'original_local_certification': 'native-receipts-only',
              'hardware_validation': 'NOT RUN', 'production_trust': 'NOT RUN', 'commands': []}
    work = None
    commands = None
    source_pins = None
    try:
        source_paths = {name: Path(__file__).absolute().with_name(name) for name in ('common.py', 'crypto.py')}
        source_pins = {name: digest(read(path, LIMIT)) for name, path in source_paths.items()}
        need(isinstance(request_raw, bytes) and digest(request_raw) == request_sha256, 'request-sha256-mismatch')
        request = decode(request_raw)
        need(isinstance(request, dict) and set(request) == FIELDS and type(request['schema_version']) is int
             and request['schema_version'] == 2 and request['purpose'] == 'repository-cryptographic-phases', 'version2-request-required')
        for key, pattern in (('source_commit', r'[0-9a-f]{40}'), ('run_id', r'[1-9][0-9]{0,19}'),
                             ('nonce', r'[0-9a-f]{32}'), ('image_id', r'sha256:[0-9a-f]{64}')):
            need(isinstance(request[key], str) and re.fullmatch(pattern, request[key]), 'request-identity-invalid')
        root = Path(input_root).absolute()
        need(root.is_dir() and not root.is_symlink(), 'input-root-invalid')
        mapping = request['files']
        need(isinstance(mapping, dict) and 0 < len(mapping) <= 1024, 'input-map-bound')
        loaded, total = {}, 0
        for name, row in mapping.items():
            relative(name)
            need(isinstance(row, dict) and set(row) == {'sha256', 'bytes'} and isinstance(row['sha256'], str)
                 and HASH.fullmatch(row['sha256']) and type(row['bytes']) is int and 0 <= row['bytes'] <= LIMIT, 'invalid-input-map')
            path = root
            for part in PurePosixPath(name).parts:
                path /= part
                need(not path.is_symlink(), 'input-symlink-refused')
            data = read(path, LIMIT)
            need(len(data) == row['bytes'] and digest(data) == row['sha256'], 'input-map-byte-drift')
            loaded[name] = data; total += len(data)
            need(total <= TOTAL, 'input-total-bound')
        def check_tree():
            found, directories = set(), 0
            for current, dirs, names in os.walk(root, followlinks=False):
                directories += len(dirs)
                need(directories <= 4096 and not any((Path(current) / name).is_symlink() for name in dirs), 'input-directory-bound-or-link')
                found.update((Path(current) / name).relative_to(root).as_posix() for name in names)
                need(len(found) <= 1024, 'input-file-count-bound')
            need(found == set(mapping), 'complete-input-map-required')
        check_tree()
        prefix = request['public_prefix']
        need(isinstance(prefix, str), 'invalid-public-prefix')
        if prefix:
            relative(prefix)
            prefix += '/'
        public = {name[len(prefix):]: data for name, data in loaded.items() if name.startswith(prefix)
                  and (name[len(prefix):].startswith('TEST-repositories/') or name[len(prefix):].startswith('TEST-'))}
        signers = request['signers']
        need(isinstance(signers, dict) and set(signers) == {'signer-A', 'signer-B', 'verifier'}, 'three-signer-roles-required')
        for role, row in signers.items():
            keys = {'fingerprint', 'certificate'} | ({'revoked_certificate'} if role == 'signer-A' else set())
            need(isinstance(row, dict) and set(row) == keys and FINGERPRINT.fullmatch(row.get('fingerprint', ''))
                 and row['certificate'] == prefix + 'TEST-' + role + '-public.asc' and row['certificate'] in loaded,
                 'signer-certificate-binding')
        need(len({row['fingerprint'] for row in signers.values()}) == 3
             and signers['signer-A']['revoked_certificate'] == prefix + 'TEST-signer-A-revoked-public.asc'
             and signers['signer-A']['revoked_certificate'] in loaded, 'revoked-certificate-binding')
        repos = audit_repositories(public)
        expected = []
        for label, role in (('baseline-A', 'signer-A'), ('updated-B', 'signer-B')):
            for name in repos[label]:
                if re.search(r'\.pkg\.tar\.(xz|gz)$', name) or name in ('integration.db.tar.gz', 'integration.files.tar.gz'):
                    path = prefix + 'TEST-repositories/' + label + '/' + name
                    expected.append({'path': path, 'signature': path + '.sig', 'signer': role})
        expected.append({'path': prefix + 'TEST-repository-aliases.json', 'signature': prefix + 'TEST-repository-aliases.json.sig', 'signer': 'signer-B'})
        expected.sort(key=lambda row: row['path'])
        need(len(expected) == 15 and request['signed_objects'] == expected, 'exact15-signed-objects-required')
        native = request['native_verifications']; revoked = request['native_revocation']
        need(isinstance(native, list) and len(native) == 15 and isinstance(revoked, dict)
             and set(revoked) == {'status_log', 'exit_code', 'command_index'}
             and type(revoked['command_index']) is int and revoked['command_index'] >= 0, 'native-phase-observations-required')
        paths, indices, logs = set(), set(), set()
        for row in native:
            need(isinstance(row, dict) and set(row) == {'path', 'status_log', 'exit_code', 'command_index', 'native_phase'}
                 and row['path'] not in paths and type(row['command_index']) is int and row['command_index'] >= 0
                 and row['command_index'] not in indices and row['status_log'] in loaded
                 and row['status_log'] not in logs, 'native-verification-binding')
            obj = next((value for value in expected if value['path'] == row['path']), None)
            need(obj is not None, 'native-object-not-in-signed-set')
            role = obj['signer']
            need(row['native_phase'] == ('pre-A-revocation' if role == 'signer-A' else 'unrevoked-B')
                 and (role != 'signer-A' or row['command_index'] < revoked['command_index']), 'native-phase-order')
            verify_phase(loaded[row['status_log']], signers[role]['fingerprint'], exit_code=row['exit_code'])
            paths.add(row['path']); indices.add(row['command_index']); logs.add(row['status_log'])
        need(paths == {row['path'] for row in expected} and revoked['status_log'] in loaded
             and revoked['command_index'] not in indices and revoked['status_log'] not in logs, 'complete-native-phases-required')
        verify_phase(loaded[revoked['status_log']], signers['signer-A']['fingerprint'], 'revoked', revoked['exit_code'])
        output = Path(output).absolute()
        need(not output.exists() and not output.is_symlink() and output.parent.is_dir(), 'new-output-required')
        with defer_cancellation():
            work = Path(tempfile.mkdtemp(prefix='repository-crypto-', dir=output.parent)); os.chmod(work, 0o700)
        commands = Commands(work, allowed=('gpg', 'gpgconf', 'gpg-connect-agent'))
        result['commands'] = commands.records
        homes, expires = {}, {}
        captured = work / 'captured'; captured.mkdir(mode=0o700)
        for name, data in loaded.items():
            path = captured / name; path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            write_new(path, data)
        now = int(time.time())
        def run(argv, expected_exit=0):
            return commands.run([str(value) for value in argv], expected=expected_exit)
        def gpg(home):
            return ['gpg', '--batch', '--no-options', '--no-autostart', '--homedir', home,
                    '--no-auto-key-retrieve', '--auto-key-locate', 'clear']
        for role, row in signers.items():
            home = work / role; home.mkdir(mode=0o700); homes[role] = home
            data = loaded[row['certificate']]
            need(b'PRIVATE KEY' not in data and b'SECRET KEY' not in data, 'private-certificate-refused')
            cert = work / (role + '.asc'); cert.write_bytes(data); os.chmod(cert, 0o600)
            out, _ = run(gpg(home) + ['--with-colons', '--import-options', 'show-only', '--dry-run', '--import', cert])
            listing = [line.split(':') for line in out.decode().splitlines()]
            need(not any(line[0] in ('sec', 'ssb') for line in listing), 'private-key-packet-refused')
            pubs = [line for line in listing if line[0] == 'pub']
            need(len(pubs) == 1 and pubs[0][1] != 'r' and int(pubs[0][5]) <= now
                 and pubs[0][6].isdigit() and int(pubs[0][6]) > now
                 and [line[9] for line in listing if line[0] == 'fpr'] == [row['fingerprint']], 'snapshot-identity-or-current-expiry')
            expires[role] = int(pubs[0][6])
            run(gpg(home) + ['--import', cert])
            out, _ = run(gpg(home) + ['--with-colons', '--check-sigs', row['fingerprint']])
            checks = [line.split(':') for line in out.decode().splitlines() if line.startswith('sig:')]
            need(checks and all(line[1] == '!' and line[4] == row['fingerprint'][-16:] for line in checks), 'certificate-self-signature-invalid')
        verified = []
        def verify(path, signature, role, phase='positive'):
            need(int(time.time()) < expires[role], 'certificate-expired-during-verification')
            out, err = run(gpg(homes[role]) + ['--status-fd', '1', '--verify', captured / signature, captured / path],
                           None if phase == 'revoked' else 0)
            record = verify_phase(out, signers[role]['fingerprint'], phase, commands.records[-1]['exit_code'])
            return {'path': path, 'signature': signature, 'signer': role, 'data_sha256': digest(loaded[path]),
                    'signature_sha256': digest(loaded[signature]), 'status_sha256': digest(out),
                    'machine_status': out.decode('utf-8', errors='strict'), 'status_bytes': len(out),
                    'stderr_sha256': digest(err), 'stderr_bytes': len(err), **record}
        for row in expected:
            verified.append(verify(row['path'], row['signature'], row['signer']))
        # Independently check regenerated negative DB signatures and stale probe rejection.
        negative_verified = []
        for label in ('missing-package-signature-B', 'tampered-package-B'):
            for filename in repos[label]:
                if re.search(r'\.pkg\.tar\.(xz|gz)$', filename) and not filename.startswith(PROBE + '-'):
                    path = prefix + 'TEST-repositories/' + label + '/' + filename
                    negative_verified.append(verify(path, path + '.sig', 'signer-B'))
            for kind in ('db', 'files'):
                path = prefix + 'TEST-repositories/' + label + '/integration.' + kind + '.tar.gz'
                negative_verified.append(verify(path, path + '.sig', 'signer-B'))
        for label, filename in (('tampered-package-B', next(name for name in repos['updated-B'] if name.startswith(PROBE + '-') and not name.endswith('.sig'))),
                                ('tampered-database-B', 'integration.db.tar.gz')):
            path = prefix + 'TEST-repositories/' + label + '/' + filename
            out, err = run(gpg(homes['signer-B']) + ['--status-fd', '1', '--verify', captured / (path + '.sig'), captured / path], None)
            rows = [line.split()[1:] for line in out.decode().splitlines() if line.startswith('[GNUPG:] ')]
            need(commands.records[-1]['exit_code'] != 0 and len([row for row in rows if row and row[0] == 'BADSIG'
                 and row[1] == signers['signer-B']['fingerprint'][-16:]]) == 1
                 and not any(row and row[0] in {'VALIDSIG', 'ERRSIG', 'NO_PUBKEY'} for row in rows), 'expected-tamper-badsig-required')
            negative_verified.append({'path': path, 'signature': path + '.sig', 'signer': 'signer-B',
                                      'phase': 'expected-tamper', 'integrity': 'INVALID', 'authorization': 'REJECTED',
                                      'expected_fingerprint': signers['signer-B']['fingerprint'],
                                      'data_sha256': digest(loaded[path]), 'signature_sha256': digest(loaded[path + '.sig']),
                                      'machine_status': out.decode('utf-8', errors='strict'), 'status_sha256': digest(out),
                                      'status_bytes': len(out), 'stderr_sha256': digest(err), 'stderr_bytes': len(err)})
        revoked_cert = work / 'revoked-A.asc'; revoked_cert.write_bytes(loaded[signers['signer-A']['revoked_certificate']]); os.chmod(revoked_cert, 0o600)
        need(b'PRIVATE KEY' not in revoked_cert.read_bytes() and b'SECRET KEY' not in revoked_cert.read_bytes(), 'private-revocation-input')
        out, _ = run(gpg(homes['signer-A']) + ['--with-colons', '--import-options', 'show-only', '--dry-run', '--import', revoked_cert])
        rows = [line.split(':') for line in out.decode().splitlines()]
        need(not any(row[0] in ('sec', 'ssb') for row in rows) and len([row for row in rows if row[0] == 'pub']) == 1
             and [row[9] for row in rows if row[0] == 'fpr'] == [signers['signer-A']['fingerprint']], 'revocation-public-identity-required')
        run(gpg(homes['signer-A']) + ['--import', revoked_cert])
        out, _ = run(gpg(homes['signer-A']) + ['--with-colons', '--list-keys'])
        rows = [line.split(':') for line in out.decode().splitlines()]
        need([row[9] for row in rows if row[0] == 'fpr'] == [signers['signer-A']['fingerprint']]
             and [row[1] for row in rows if row[0] == 'pub'] == ['r'], 'terminal-revocation-required')
        out, _ = run(gpg(homes['signer-A']) + ['--with-colons', '--check-sigs', signers['signer-A']['fingerprint']])
        revocations = [line.split(':') for line in out.decode().splitlines() if line.startswith('rev:')]
        need(revocations and all(row[1] == '!' and row[4] == signers['signer-A']['fingerprint'][-16:]
                                 for row in revocations), 'revocation-self-signature-invalid')
        terminal = []
        for row in expected:
            terminal.append(verify(row['path'], row['signature'], row['signer'], 'revoked' if row['signer'] == 'signer-A' else 'positive'))
            terminal[-1]['authorization'] = 'REVOKED' if row['signer'] == 'signer-A' else 'VALID_AT_OBSERVATION'
        need(int(time.time()) >= now, 'real-clock-regression')
        need(not any(path.name.startswith('S.gpg-agent') for home in homes.values() for path in home.iterdir()),
             'public-only-agent-socket-refused')
        for name, row in mapping.items():
            need(read(root / name, LIMIT) == loaded[name], 'input-drift-after-crypto')
        check_tree()
        result.update(source_commit=request['source_commit'], run_id=request['run_id'], nonce=request['nonce'], image_id=request['image_id'],
                      request_sha256=request_sha256, artifact_map_sha256=digest(encoded(mapping)),
                      public_artifact_map_sha256=digest(encoded({name: {'sha256': digest(data), 'bytes': len(data)}
                                                                for name, data in public.items()})),
                      current_A_authorization='REVOKED', tool_sha256=commands.pins,
                      certificate_expiry=expires,
                      signer_certificates={role: {'fingerprint': row['fingerprint'], 'certificate': row['certificate'],
                                                  'certificate_sha256': digest(loaded[row['certificate']]),
                                                  'expires_at': expires[role],
                                                  **({'revoked_certificate': row['revoked_certificate'],
                                                      'revoked_certificate_sha256': digest(loaded[row['revoked_certificate']])}
                                                     if role == 'signer-A' else {})} for role, row in signers.items()},
                      source_sha256=source_pins, source_authentication='caller-authenticated-snapshot-required',
                      actual_software_environment={'architecture': platform.machine(), 'page_size': os.sysconf('SC_PAGE_SIZE'),
                                                   'execution': 'local-bounded-private-processes'},
                      public_only_agent_sockets_absent=True,
                      observed_at=now, completed_at=int(time.time()), snapshot_integrity=verified,
                      terminal_authorization=terminal, negative_verifications=negative_verified,
                      native_verifications=request['native_verifications'],
                      native_revocation=request['native_revocation'], native_observation_boundary='retained-native-observations-only', status='PASS')
    except BaseException as error:
        reason = str(error) if isinstance(error, Refused) and re.fullmatch(r'[a-z0-9 -]{1,120}', str(error)) else 'cryptographic-acceptance-refused'
        result.update(status='FAIL', error_type=type(error).__name__, error=reason)
    finally:
        if work is not None:
            try:
                with defer_cancellation():
                    if commands is not None:
                        commands.teardown()
                        for home in (path for path in work.iterdir() if path.is_dir() and path.name in ('signer-A', 'signer-B', 'verifier')):
                            commands.run(['gpgconf', '--homedir', str(home), '--kill', 'all'])
                        need(all(digest(read(path)) == commands.pins[name] for name, path in commands.paths.items()),
                             'tool-drift-after-teardown')
                    need(source_pins is not None and all(digest(read(path, LIMIT)) == source_pins[name]
                                                        for name, path in source_paths.items()), 'source-drift-after-teardown')
                    shutil.rmtree(work)
                    need(not work.exists(), 'public-home-cleanup-absence')
                    result['private_work_cleanup'] = 'PASS'
                    for name, data in loaded.items():
                        need(read(root / name, LIMIT) == data, 'input-drift-after-teardown')
                    check_tree()
            except BaseException as error:
                result.update(status='FAIL', cleanup_error_type=type(error).__name__)
                result.setdefault('private_work_cleanup', 'FAIL')
    if result['status'] == 'PASS':
        publication = None
        try:
            completed = int(time.time())
            need(result['observed_at'] <= completed and all(completed < expiry for expiry in result['certificate_expiry'].values()),
                 'certificate-expired-before-publication')
            result['completed_at'] = completed
            publication = Publication(output)
            publication.publish(encoded(result))
        except BaseException as error:
            result.update(status='FAIL', error_type=type(error).__name__, error='crypto-receipt-publication-failed')
            result['publication'] = publication.proof if publication is not None else {'status': 'NOT RUN'}
    return result
