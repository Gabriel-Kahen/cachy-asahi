#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Offline DEVELOPMENT metadata checks; no installation, fetching or key/trust creation."""
import argparse
import contextlib
import copy
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile

TYPE = 'cachy-asahi-offline-development-envelope'
SCOPE = 'development'
CHECKPOINT = 'checkpoint.json'
MAX_JSON, MAX_SIGNATURE, MAX_KEYRING = 4 * 1024**2, 64 * 1024, 4 * 1024**2
MAX_FILE, MAX_TOTAL, MAX_FILES = 512 * 1024**2, 2 * 1024**3, 4096
MAX_SEQUENCE, MAX_LIFETIME = 2**63 - 1, 7 * 86400
HEX = re.compile(r'[0-9a-f]{64}\Z')
FINGERPRINT = re.compile(r'(?:[0-9A-F]{40}|[0-9A-F]{64})\Z')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}\Z')
PACKAGE_VERSION = re.compile(r'[A-Za-z0-9][A-Za-z0-9._+~:-]{0,127}\Z')
NAMESPACE = re.compile(r'[a-z0-9][a-z0-9._-]{0,127}\Z')
ENVELOPE_FIELDS = {'schema_version', 'type', 'scope', 'namespace', 'sequence', 'issued_utc',
                   'expires_utc', 'signer', 'synthetic', 'release_id', 'repo_name', 'targets'}
STATE_FIELDS = {'schema_version', 'scope', 'namespace', 'signer', 'sequence', 'metadata_sha256',
                'release_sha256', 'issued_utc', 'verified_utc'}


class Error(Exception):
    pass


def need(condition, message):
    if not condition:
        raise Error(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + '\n').encode()


def decode(data):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def invalid(value):
        raise Error('JSON floats/nonfinite constants are not allowed')
    value = json.loads(data.decode('utf-8'), object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    need(isinstance(value, dict), 'JSON object required')
    return value


def stamp(value):
    need(isinstance(value, str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value), 'exact UTC timestamp required')
    return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)


def utc(value):
    return value.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def sequence(value):
    need(type(value) is int and 1 <= value <= MAX_SEQUENCE, 'positive 63-bit sequence required')
    return value


def fingerprint(value):
    need(isinstance(value, str) and FINGERPRINT.fullmatch(value.upper()), 'full primary fingerprint required')
    return value.upper()


def relative(value):
    need(isinstance(value, str) and value and '\x00' not in value and '\\' not in value, 'unsafe relative path')
    path = PurePosixPath(value)
    need(path.parts and not path.is_absolute() and path.as_posix() == value and all(p not in {'.', '..'} for p in path.parts),
         'canonical contained relative path required')
    return path.parts


def absolute(value):
    path = Path(value)
    need(path.is_absolute() and path.anchor == '/' and str(path) == str(value) and '..' not in path.parts and '\x00' not in str(value),
         'canonical absolute path required')
    return path


def directory(path):
    """Open every component without following symlinks, retaining the final inode."""
    path = absolute(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


@contextlib.contextmanager
def member(root, name, *, private=False):
    parts = relative(name)
    parent = os.dup(root)
    fd = None
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'regular non-hardlinked input required')
        if private:
            need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o600, 'checkpoint owner/mode must be private 0600')
        yield fd
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent)


def identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def read_member(root, name, limit=MAX_JSON, *, private=False):
    with member(root, name, private=private) as fd:
        before = os.fstat(fd)
        need(before.st_size <= limit, 'input exceeds bounded size')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            data = stream.read(limit + 1)
        need(len(data) <= limit and len(data) == before.st_size and identity(os.fstat(fd)) == identity(before),
             'input changed while reading or exceeds bounded size')
        return data


def read_path(path, limit):
    path = absolute(path)
    root = directory(path.parent)
    try:
        return read_member(root, path.name, limit)
    finally:
        os.close(root)


def hash_member(root, name, *, snapshot=None):
    with member(root, name) as fd:
        before = os.fstat(fd)
        need(before.st_size <= MAX_FILE, 'bundle file exceeds bounded size')
        h, count = hashlib.sha256(), 0
        with os.fdopen(os.dup(fd), 'rb') as stream, contextlib.ExitStack() as stack:
            dest = stack.enter_context(Path(snapshot).open('xb')) if snapshot else None
            for block in iter(lambda: stream.read(1024**2), b''):
                count += len(block)
                need(count <= MAX_FILE, 'bundle file exceeds bounded size')
                h.update(block)
                if dest:
                    dest.write(block)
        need(count == before.st_size and identity(os.fstat(fd)) == identity(before), 'bundle file changed while reading')
        return h.hexdigest(), count


def reference(path, value):
    relative(path)
    need(isinstance(value, str) and HEX.fullmatch(value), 'SHA-256 required')
    return {'path': path, 'sha256': value}



def source_delivery_helper():
    """Load only our explicit sibling Source bytes, never CWD/sys.path or pyc."""
    path = Path(__file__).absolute().parents[1] / 'release/source_delivery.py'
    raw = read_path(path, MAX_JSON)
    spec = importlib.util.spec_from_file_location('cachy_asahi_client_source_delivery', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def source_readers(root, spec, release):
    """Every callback rechecks actual bytes against both enclosing selections."""
    def read_evidence(identifier, limit):
        need(type(identifier) is str and NAME.fullmatch(identifier), 'source evidence ID invalid')
        need(type(limit) is int and 0 < limit <= MAX_FILE, 'source evidence bound invalid')
        rows = [row for row in spec.get('evidence', [])
                if isinstance(row, dict) and row.get('id') == identifier]
        need(len(rows) == 1, 'source evidence missing/duplicated in spec')
        expected = rows[0].get('sha256')
        path = 'evidence/' + identifier
        need(isinstance(expected, str) and HEX.fullmatch(expected) and
             release['files'].get(path) == expected, 'source evidence differs from signed release/spec')
        raw = read_member(root, path, limit)
        need(digest(raw) == expected, 'source evidence bytes changed')
        return raw

    def read_provenance(package):
        identity = {key: package[key] for key in ('name', 'version', 'arch', 'sha256')}
        rows = [row for row in release['packages'] if all(row.get(k) == v for k, v in identity.items())]
        need(len(rows) == 1, 'source provenance package differs from release')
        path = rows[0].get('provenance')
        relative(path)
        need(path.startswith('provenance/') and path in release['files'], 'source provenance not in signed payload')
        raw = read_member(root, path)
        need(digest(raw) == release['files'][path], 'source provenance bytes changed')
        provenance = decode(raw)
        need(provenance.get('artifact_sha256') == identity['sha256'] and
             provenance.get('package') == {key: identity[key] for key in ('name', 'version', 'arch')},
             'source provenance artifact identity differs')
        return provenance
    return read_evidence, read_provenance


def source_associations(root, spec, release):
    if 'source_delivery' not in spec:
        return None
    readers = source_readers(root, spec, release)
    return source_delivery_helper().verify_associations(spec, release['packages'], *readers)


def describe(root):
    raw = read_member(root, 'release.json')
    release = decode(raw)
    need(release.get('schema_version') == 1 and type(release['schema_version']) is int, 'release schema unsupported')
    need(NAME.fullmatch(release.get('release_id', '')), 'release ID invalid')
    fingerprint(release.get('signer'))
    files = release.get('files')
    need(isinstance(files, dict) and 0 < len(files) <= MAX_FILES, 'complete bounded release payload map required')
    total = 0
    for path, expected in files.items():
        reference(path, expected)
        need(path not in {'release.json', 'release.json.sig'}, 'release payload cannot hash itself')
        actual, size = hash_member(root, path)
        total += size
        need(total <= MAX_TOTAL, 'bundle exceeds total byte bound')
        need(actual == expected, 'release payload checksum mismatch: ' + path)
    need('spec.json' in files, 'release spec binding missing')
    spec_raw = read_member(root, 'spec.json')
    need(digest(spec_raw) == files['spec.json'], 'spec changed after payload verification')
    spec = decode(spec_raw)
    need(spec.get('schema_version') == 1 and type(spec['schema_version']) is int and spec.get('target_arch') == 'aarch64',
         'release spec schema/architecture unsupported')
    need(spec.get('release_id') == release['release_id'] and NAME.fullmatch(spec.get('repo_name', '')), 'release/spec identity mismatch')
    need(type(spec.get('synthetic')) is bool, 'explicit release synthetic label required')
    repo = spec['repo_name']
    database_paths = [f'repo/{repo}.db.tar.gz', f'repo/{repo}.files.tar.gz']
    packages = release.get('packages')
    need(isinstance(packages, list) and 0 < len(packages) <= 256, 'nonempty bounded release packages required')
    result, names, filenames = [], set(), set()
    for p in packages:
        need(isinstance(p, dict) and NAME.fullmatch(p.get('name', '')) and p['name'] not in names, 'package name missing/duplicated')
        need(isinstance(p.get('version'), str) and PACKAGE_VERSION.fullmatch(p['version']) and p.get('arch') in {'any', 'aarch64'}, 'package identity invalid')
        filename = p.get('filename', '')
        need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+~:-]*\.pkg\.tar\.(gz|xz|zst)', filename) and filename not in filenames,
             'package filename invalid/duplicated')
        path = 'repo/' + filename
        need(path in files and files[path] == p.get('sha256'), 'package bytes differ from release payload map')
        result.append(dict(reference(path, p['sha256']), name=p['name'], version=p['version'], arch=p['arch']))
        names.add(p['name'])
        filenames.add(filename)
    signed_targets = database_paths + [p['path'] for p in result]
    need(all(path in files and path + '.sig' in files for path in signed_targets), 'database/package checksum or signature binding missing')
    source_associations(root, spec, release)  # Opt-in association; envelope v1 targets stay exact.
    # Only regular target paths are consumed; repo-add's basename aliases are unused.
    targets = {'release_record': reference('release.json', digest(raw)), 'spec': reference('spec.json', files['spec.json']),
               'databases': [reference(path, files[path]) for path in database_paths],
               'packages': sorted(result, key=lambda p: p['name'])}
    return {'synthetic': spec['synthetic'], 'release_id': release['release_id'], 'repo_name': repo, 'targets': targets}, release, raw


def validate_envelope(value, now):
    need(set(value) == ENVELOPE_FIELDS and type(value['schema_version']) is int and value['schema_version'] == 1,
         'exact metadata schema 1 required')
    need(value['type'] == TYPE and value['scope'] == SCOPE, 'only DEVELOPMENT scope is supported; stable is blocked')
    need(isinstance(value['namespace'], str) and NAMESPACE.fullmatch(value['namespace']), 'canonical repository namespace required')
    sequence(value['sequence'])
    need(fingerprint(value['signer']) == value['signer'], 'metadata signer must be a full uppercase primary fingerprint')
    issued, expires = stamp(value['issued_utc']), stamp(value['expires_utc'])
    need(issued <= now < expires, 'metadata is expired or issued in the future')
    need(0 < (expires - issued).total_seconds() <= MAX_LIFETIME, 'metadata lifetime must be positive and at most seven days')
    need(type(value['synthetic']) is bool, 'metadata synthetic label required')


def signature_status(data, signer, now):
    records = [line.split()[1:] for line in data.decode('utf-8').splitlines() if line.startswith('[GNUPG:] ')]
    rejected = {'KEYEXPIRED', 'SIGEXPIRED', 'EXPKEYSIG', 'EXPSIG', 'REVKEYSIG', 'KEYREVOKED', 'BADSIG',
                'ERRSIG', 'NO_PUBKEY', 'NODATA', 'FAILURE', 'ERROR', 'BADARMOR'}
    need(not any(r and r[0] in rejected for r in records), 'invalid/expired/revoked/missing signature or key')
    valid = [r for r in records if r and r[0] == 'VALIDSIG']
    need(sum(r[0] == 'NEWSIG' for r in records if r) == 1 and sum(r[0] == 'GOODSIG' for r in records if r) == 1 and
         len(valid) == 1 and len(valid[0]) == 11, 'one complete detached signature required')
    row = valid[0]
    need(FINGERPRINT.fullmatch(row[1]) and row[-1] == signer and row[8] in {'8', '9', '10'} and
         row[9] == '00' and row[5] in {'4', '5'}, 'full pinned primary/SHA-256+ binary signature required')
    created, expires = int(row[3]), int(row[4])
    need(0 < created <= now.timestamp() and (expires == 0 or expires > now.timestamp()), 'signature time invalid/future/expired')
    return {'primary_fingerprint': row[-1], 'signing_fingerprint': row[1], 'hash_algorithm': row[8]}


class Verifier:
    def __init__(self, temp, keyring, signer, now):
        self.temp, self.signer, self.now = Path(temp), signer, now
        self.home = self.temp / 'gpg-home'
        self.home.mkdir(mode=0o700)
        self.keyring = self.temp / 'external-public.gpg'
        self.keyring.write_bytes(keyring)
        self.count = 0
        need(shutil.which('gpg'), 'preinstalled GPG required')

    def verify(self, data_path, signature):
        self.count += 1
        path = self.temp / f'signature-{self.count}'
        path.write_bytes(signature)
        argv = ['gpg', '--batch', '--no-tty', '--no-options', '--homedir', str(self.home), '--no-default-keyring',
                '--keyring', str(self.keyring), '--no-auto-key-retrieve', '--no-auto-key-import',
                '--auto-key-locate', 'clear', '--disable-dirmngr', '--no-autostart', '--no-auto-check-trustdb',
                '--status-fd', '1', '--verify', str(path), str(data_path)]
        env = {'PATH': os.environ.get('PATH', os.defpath), 'HOME': str(self.home), 'GNUPGHOME': str(self.home), 'LC_ALL': 'C'}
        result = subprocess.run(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        need(result.returncode == 0 and len(result.stdout) + len(result.stderr) <= MAX_JSON, 'GPG rejected detached signature')
        return signature_status(result.stdout, self.signer, self.now)

    def bundle(self, root, ref, signature_sha256):
        path = self.temp / f'target-{self.count + 1}'
        actual, _ = hash_member(root, ref['path'], snapshot=path)
        need(actual == ref['sha256'], 'signed target changed after bundle inspection')
        signature = read_member(root, ref['path'] + '.sig', MAX_SIGNATURE)
        need(digest(signature) == signature_sha256, 'signature bytes changed after release payload inspection')
        return self.verify(path, signature)


@contextlib.contextmanager
def state_directory(path, apply):
    fd = directory(path)
    try:
        info = os.fstat(fd)
        need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700, 'state directory owner/mode must be private 0700')
        try:
            fcntl.flock(fd, (fcntl.LOCK_EX if apply else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise Error('state directory is locked by another client') from error
        yield fd
    finally:
        os.close(fd)


def checkpoint(root):
    try:
        value = decode(read_member(root, CHECKPOINT, private=True))
    except FileNotFoundError:
        return None
    need(set(value) == STATE_FIELDS and type(value['schema_version']) is int and value['schema_version'] == 1 and
         value['scope'] == SCOPE, 'checkpoint schema/scope invalid')
    need(isinstance(value['namespace'], str) and NAMESPACE.fullmatch(value['namespace']), 'checkpoint namespace invalid')
    need(fingerprint(value['signer']) == value['signer'], 'checkpoint signer invalid')
    sequence(value['sequence'])
    need(HEX.fullmatch(value['metadata_sha256']) and HEX.fullmatch(value['release_sha256']), 'checkpoint checksum invalid')
    need(stamp(value['issued_utc']) <= stamp(value['verified_utc']), 'checkpoint time invalid')
    return value


def against_state(old, metadata, metadata_sha, now, floor):
    need(metadata['sequence'] >= sequence(floor), 'metadata sequence below independently supplied floor')
    if old is None:
        return
    need(all(old[k] == metadata[k] for k in ('namespace', 'scope', 'signer')), 'checkpoint namespace/scope/signer replay')
    need(now >= stamp(old['verified_utc']), 'local clock moved behind applied checkpoint')
    need(metadata['sequence'] >= old['sequence'], 'metadata sequence rollback')
    if metadata['sequence'] == old['sequence']:
        need(metadata_sha == old['metadata_sha256'], 'same sequence has altered metadata bytes')
    need(stamp(metadata['issued_utc']) >= stamp(old['issued_utc']), 'higher sequence moved issuance backwards')


def commit(root, value):
    temporary = '.checkpoint-' + secrets.token_hex(16)
    fd, replaced = None, False
    try:
        # Detect a directory that cannot sync before the visibility commit point.
        os.fsync(root)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=root)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            fd = None
            stream.write(encoded(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, CHECKPOINT, src_dir_fd=root, dst_dir_fd=root)
        replaced = True
        try:
            os.fsync(root)
            return True
        except OSError:
            return False  # Already committed: report applied, with durability uncertainty.
    finally:
        if fd is not None:
            os.close(fd)
        if not replaced:
            try:
                os.unlink(temporary, dir_fd=root)
            except FileNotFoundError:
                pass


def verify(args, *, now=None):
    now = now or datetime.now(timezone.utc)
    signer = fingerprint(args.signer)
    need(isinstance(args.namespace, str) and NAMESPACE.fullmatch(args.namespace), 'canonical repository namespace required')
    with state_directory(args.state_dir, args.apply) as state, contextlib.ExitStack() as stack:
        old = checkpoint(state)
        metadata_raw = read_path(args.metadata, MAX_JSON)
        metadata = decode(metadata_raw)
        validate_envelope(metadata, now)
        need(metadata['namespace'] == args.namespace and metadata['signer'] == signer, 'metadata namespace/signer differs from external pin')
        metadata_sha = digest(metadata_raw)
        against_state(old, metadata, metadata_sha, now, args.minimum_sequence)
        signature = read_path(args.signature, MAX_SIGNATURE)
        keyring = read_path(args.public_keyring, MAX_KEYRING)
        temp = stack.enter_context(tempfile.TemporaryDirectory(prefix='cachy-asahi-client-verify-', dir='/tmp'))
        verifier = Verifier(temp, keyring, signer, now)
        snapshot = Path(temp) / 'metadata.json'
        snapshot.write_bytes(metadata_raw)
        receipt = verifier.verify(snapshot, signature)
        root = directory(args.bundle)
        stack.callback(os.close, root)
        actual, release, release_raw = describe(root)
        need(all(metadata[k] == actual[k] for k in actual), 'envelope does not bind actual release/database/package bytes')
        need(release['signer'] == signer, 'release signer differs from envelope/external pin')
        release_snapshot = Path(temp) / 'release.json'
        release_snapshot.write_bytes(release_raw)
        verifier.verify(release_snapshot, read_member(root, 'release.json.sig', MAX_SIGNATURE))
        for ref in actual['targets']['databases'] + actual['targets']['packages']:
            verifier.bundle(root, ref, release['files'][ref['path'] + '.sig'])
        value = {k: metadata[k] for k in ('scope', 'namespace', 'signer', 'sequence', 'issued_utc')}
        value.update(schema_version=1, metadata_sha256=metadata_sha,
                     release_sha256=actual['targets']['release_record']['sha256'], verified_utc=utc(now))
        result = {'status': 'verified-development', 'scope': SCOPE, 'stable_accepted': False,
                  'cold_start': old is None, 'state_changed': False, 'metadata_sha256': metadata_sha,
                  'sequence': metadata['sequence'], 'namespace': args.namespace, 'signer': receipt,
                  'release_sha256': value['release_sha256'], 'checked_utc': utc(now)}
        if args.apply:
            # Every verification/cleanup operation precedes checkpoint mutation.
            stack.close()
            durable = commit(state, value)
            result.update(status='applied-development', state_changed=True, checkpoint_directory_synced=durable)
        return result



def sources(args, *, now=None):
    """Authenticated DEVELOPMENT lookup/export; never advance a checkpoint."""
    selected = dict(name=args.package, version=args.version, arch=args.arch, sha256=args.artifact_sha256)
    need(NAME.fullmatch(selected['name']) and PACKAGE_VERSION.fullmatch(selected['version']) and
         selected['arch'] in {'aarch64', 'any'} and HEX.fullmatch(selected['sha256']),
         'exact source package/version/arch/artifact identity required')
    output = absolute(args.output) if args.output is not None else None
    if output is not None:
        need(not output.is_relative_to(absolute(args.bundle)) and
             not output.is_relative_to(absolute(args.state_dir)),
             'source export must stay outside bundle and checkpoint directory')
    readonly = copy.copy(args)
    readonly.apply = False
    verified = verify(readonly, now=now)
    root = directory(args.bundle)
    try:
        _, release, raw = describe(root)
        need(digest(raw) == verified['release_sha256'], 'source bundle changed after verification')
        spec_raw = read_member(root, 'spec.json')
        need(digest(spec_raw) == release['files']['spec.json'], 'source spec changed after verification')
        spec = decode(spec_raw)
        index = source_associations(root, spec, release)
        need(index is not None, 'source delivery not declared by this development bundle')
        rows = [row for row in index['packages'] if row['package'] == selected]
        need(len(rows) == 1, 'requested source package identity absent')
        record = rows[0]
        result = dict(status='source-delivery-lookup-development', scope=SCOPE, stable_accepted=False,
            state_changed=False, release_sha256=verified['release_sha256'], package=selected,
            source_delivery=record, review_status=record['review_status'], source_completeness_accepted=False, legal_acceptance=False,
            native_validation=False, hardware_validation=False, public_delivery_accepted=False)
        if output is not None:
            read_evidence, _ = source_readers(root, spec, release)
            receipt = source_delivery_helper().export_package(record, read_evidence, output,
                                                              verified['release_sha256'])
            result.update(status='source-delivery-export-development', export=receipt)
        return result
    finally:
        primary = sys.exception()
        try:
            os.close(root)
        except BaseException as error:
            if primary is None:
                raise
            primary.add_note('source bundle close uncertainty: ' + type(error).__name__)


def build(args):
    now = datetime.now(timezone.utc)
    root = directory(args.bundle)
    try:
        actual, release, _ = describe(root)
    finally:
        os.close(root)
    value = dict(actual, schema_version=1, type=TYPE, scope=SCOPE, namespace=args.namespace,
                 sequence=sequence(args.sequence), issued_utc=args.issued_utc, expires_utc=args.expires_utc,
                 signer=fingerprint(args.signer))
    validate_envelope(value, now)
    need(value['signer'] == release['signer'], 'builder signer differs from release record')
    output, bundle = absolute(args.output), absolute(args.bundle)
    need(not output.is_relative_to(bundle), 'envelope output must be outside the unchanged release bundle')
    parent = directory(output.parent)
    created = False
    try:
        info = os.fstat(parent)
        need(info.st_uid == os.geteuid() and not (stat.S_IMODE(info.st_mode) & 0o022), 'output parent must be caller-owned and not group/world writable')
        fd = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        created = True
        with os.fdopen(fd, 'wb') as stream:
            stream.write(encoded(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
    except BaseException:
        if created:
            os.unlink(output.name, dir_fd=parent)
        raise
    finally:
        os.close(parent)
    return {'status': 'unsigned-development-envelope', 'signature_created': False, 'path': str(output), 'sha256': digest(encoded(value))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    draft = commands.add_parser('build', help='write new unsigned development envelope; caller signs separately')
    check = commands.add_parser('verify', help='offline development verification; checkpoint changes only with --apply')
    lookup = commands.add_parser('sources', help='readonly development source lookup or fresh private export')
    for command in (draft, check, lookup):
        command.add_argument('--bundle', required=True)
        command.add_argument('--namespace', required=True)
        command.add_argument('--signer', required=True)
    draft.add_argument('--output', required=True)
    draft.add_argument('--sequence', type=int, required=True)
    draft.add_argument('--issued-utc', required=True)
    draft.add_argument('--expires-utc', required=True)
    for command in (check, lookup):
        for name in ('metadata', 'signature', 'public-keyring', 'state-dir'):
            command.add_argument('--' + name, required=True)
        command.add_argument('--minimum-sequence', type=int, default=1)
    check.add_argument('--apply', action='store_true')
    for name in ('package', 'version', 'arch', 'artifact-sha256'):
        lookup.add_argument('--' + name, required=True)
    lookup.add_argument('--output')
    args = parser.parse_args()
    operation = {'build': build, 'verify': verify, 'sources': sources}[args.command]
    print(json.dumps(operation(args), sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (Error, OSError, ValueError, TypeError, KeyError, OverflowError, subprocess.SubprocessError) as error:
        print('offline development client refused: ' + str(error), file=sys.stderr)
        sys.exit(1)
