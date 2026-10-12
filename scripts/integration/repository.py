#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Strict local repository transactions ONLY inside an explicit disposable ARM container."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time

ORIGINALS = {'cachy-asahi-hyprland-settings', 'cachy-asahi-fish-config',
             'cachy-asahi-zsh-config', 'cachy-asahi-setup'}
FIXTURE = 'cachy-asahi-repository-test-fixture'
PAYLOAD = 'usr/share/cachy-asahi-repository-TEST/fixture.txt'
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
SAFE_CAPS = sum(1 << bit for bit in (0, 1, 3, 6, 7))  # CHOWN/DAC_OVERRIDE/FOWNER/SETGID/SETUID only.
CAP_FIELDS = ('CapEff', 'CapPrm', 'CapBnd', 'CapInh', 'CapAmb')
BIND_FILESYSTEMS = {'ext4', 'xfs', 'btrfs', 'tmpfs', 'overlay', 'fuse-overlayfs'}
RUNTIME_FILES = {'/etc/hosts', '/etc/hostname', '/etc/resolv.conf'}
PROTECTED_PROC = {'/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger'}
MASKED_NULL = set('/proc/interrupts /proc/kcore /proc/keys /proc/latency_stats /proc/timer_list /proc/timer_stats /proc/sched_debug'.split())
STANDARD_MOUNTS = {
    '/proc': ('proc', {'rw', 'nosuid', 'nodev', 'noexec'}),
    '/dev': ('tmpfs', {'rw', 'nosuid'}),
    '/dev/pts': ('devpts', {'rw', 'nosuid', 'noexec'}),
    '/dev/mqueue': ('mqueue', {'rw', 'nosuid', 'nodev', 'noexec'}),
    '/dev/shm': ('tmpfs', {'rw', 'nosuid', 'nodev', 'noexec'}),
    '/sys': ('sysfs', {'ro', 'nosuid', 'nodev', 'noexec'}),
    '/sys/fs/cgroup': ('cgroup2', {'ro', 'nosuid', 'nodev', 'noexec'}),
    **{p: ('proc', {'ro', 'nosuid', 'nodev', 'noexec'}) for p in PROTECTED_PROC},
    **{p: ('tmpfs', {'ro'}) for p in
       ('/proc/acpi', '/proc/asound', '/proc/scsi', '/sys/firmware', '/sys/devices/virtual/powercap')},
    **{p: ('tmpfs', {'rw', 'nosuid'}) for p in MASKED_NULL},
}
STANDARD_DEVICES = {'/dev/null': (1, 3), '/dev/zero': (1, 5), '/dev/full': (1, 7),
                    '/dev/random': (1, 8), '/dev/urandom': (1, 9), '/dev/tty': (5, 0), '/dev/pts/ptmx': (5, 2)}


class Refused(Exception):
    pass


def need(condition, message):
    if not condition:
        raise Refused(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def mounts(text):
    result = {}
    for line in text.splitlines():
        before, after = line.split(' - ', 1)
        fields, tail = before.split(), after.split()
        unescape = lambda value: re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), value)
        path = unescape(fields[4])
        options = fields[5].split(',')
        need(path not in result and len(set(options)) == len(options), 'duplicate mount destination/options refused')
        result[path] = {'options': set(options), 'fs': tail[0], 'root': unescape(fields[3])}
    return result


def validate_mounts(observed):
    for path, row in observed.items():
        need(set(row) == {'fs', 'options', 'root'} and isinstance(row['options'], set) and
             ('ro' in row['options']) != ('rw' in row['options']), 'invalid mount record/options')
        need(isinstance(row['root'], str) and row['root'].startswith('/') and not any(c in row['root'] for c in ('\n', '\0')),
             'invalid mount root')
        need(not any(a in row['options'] and b in row['options'] for a, b in
                     (('nosuid', 'suid'), ('nodev', 'dev'), ('noexec', 'exec'))), 'conflicting mount security flags')
    need('/' in observed and observed['/']['fs'] in {'overlay', 'fuse-overlayfs'} and
         observed['/']['root'] == '/' and 'ro' in observed['/']['options'],
         'disposable overlay container root must be read-only')
    approved = {'/', '/inputs', '/runner', '/scratch', '/test-home', '/out'} | RUNTIME_FILES | set(STANDARD_MOUNTS)
    for path in set(observed) - approved:
        if any(path == prefix or path.startswith(prefix + '/') for prefix in ('/etc', '/usr', '/var', '/home', '/tmp', '/root')):
            raise Refused('host/system-path mount refused')
        raise Refused('unexpected/nested repository mount refused: ' + path)
    for path in ('/inputs', '/runner'):
        need(path in observed and observed[path]['fs'] in BIND_FILESYSTEMS and 'ro' in observed[path]['options'],
             f'{path} must be an explicit read-only mount')
    for path in ('/scratch', '/test-home'):
        need(path in observed and observed[path]['fs'] == 'tmpfs' and observed[path]['root'] == '/' and
             {'rw', 'nodev', 'nosuid'} <= observed[path]['options'], f'{path} must be a dedicated writable nodev/nosuid tmpfs')
    need('/out' in observed and observed['/out']['fs'] in BIND_FILESYSTEMS and 'rw' in observed['/out']['options'],
         'dedicated writable output mount required')
    need({'/proc', '/dev', '/dev/pts', '/dev/shm', '/dev/mqueue', '/sys', '/sys/fs/cgroup'} | RUNTIME_FILES | PROTECTED_PROC <= set(observed),
         'complete standard Docker runtime mount set required')
    for path in RUNTIME_FILES:
        need(observed[path]['fs'] in BIND_FILESYSTEMS, 'unexpected Docker metadata mount filesystem')
    for path in set(STANDARD_MOUNTS) & set(observed):
        fs, flags = STANDARD_MOUNTS[path]
        root = '/null' if path in MASKED_NULL else path.removeprefix('/proc') if fs == 'proc' and path != '/proc' else '/'
        need(observed[path]['fs'] == fs and flags <= observed[path]['options'] and observed[path]['root'] == root,
             'standard Docker runtime mount identity/options differ: ' + path)


def privileges(text):
    rows = dict(line.split(':', 1) for line in text.splitlines() if ':' in line)
    need(all(re.fullmatch(r'[0-9a-fA-F]+', rows.get(name, '').strip()) for name in CAP_FIELDS), 'all five actual capability observations required')
    need(rows.get('NoNewPrivs', '').strip() == '1', 'actual no-new-privileges required')
    result = {name: int(rows[name].strip(), 16) for name in CAP_FIELDS}
    need(all(not value & ~SAFE_CAPS for value in result.values()), 'capabilities exceed five-cap repository mask')
    result['NoNewPrivs'] = 1
    return result


def exposed_nodes():
    devices, sockets, count = {}, [], 0
    for root in ('/dev', '/run', '/tmp', '/inputs', '/runner', '/scratch', '/test-home', '/out'):
        for directory, dirs, files in os.walk(root, followlinks=False):
            for name in dirs + files:
                path = Path(directory) / name
                info = path.lstat()
                count += 1
                need(count <= 4096, 'exposed-node inspection exceeds bound')
                if stat.S_ISSOCK(info.st_mode):
                    sockets.append(str(path))
                if stat.S_ISCHR(info.st_mode) or stat.S_ISBLK(info.st_mode):
                    devices[str(path)] = {'kind': 'char' if stat.S_ISCHR(info.st_mode) else 'block',
                                          'major': os.major(info.st_rdev), 'minor': os.minor(info.st_rdev)}
                if stat.S_ISLNK(info.st_mode) and root == '/dev':
                    aliases = {'/dev/fd': '/proc/self/fd', '/dev/stdin': '/proc/self/fd/0', '/dev/stdout': '/proc/self/fd/1',
                               '/dev/stderr': '/proc/self/fd/2', '/dev/core': '/proc/kcore', '/dev/ptmx': 'pts/ptmx'}
                    need(str(path) in aliases and os.readlink(path) == aliases[str(path)], 'unexpected device alias')
    return {'devices': devices, 'sockets': sorted(sockets)}


def validate_exposure(value):
    need(value['sockets'] == [], 'runtime/input/output socket exposure refused')
    expected = {path: {'kind': 'char', 'major': major, 'minor': minor} for path, (major, minor) in STANDARD_DEVICES.items()}
    need(value['devices'] == expected, 'unexpected/missing hardware device identity')


def guard(args):
    need(args.allow_disposable_repository_test and os.environ.get('CACHY_ASAHI_REPOSITORY_CONTAINER') == '1',
         'explicit disposable repository-test contract required')
    need(platform.machine() == 'aarch64' and os.geteuid() == 0, 'native aarch64 container root required')
    marker = Path('/.dockerenv')
    need(marker.is_file() and not marker.is_symlink() and marker.stat().st_uid == 0, 'actual root-owned Docker marker missing')
    need(not any(Path(p).exists() for p in ('/run/docker.sock', '/var/run/docker.sock')), 'Docker socket exposure refused')
    need(re.fullmatch(r'[0-9a-f]{32}', os.environ.get('CACHY_ASAHI_DISPOSABLE_REPOSITORY', '')) and
         re.fullmatch(r'sha256:[0-9a-f]{64}', os.environ.get('CACHY_ASAHI_IMAGE_ID', '')), 'explicit nonce/image identity required')
    observed = mounts(Path('/proc/self/mountinfo').read_text())
    validate_mounts(observed)
    actual_privileges = privileges(Path('/proc/self/status').read_text())
    exposure = exposed_nodes()
    validate_exposure(exposure)
    need(not any(Path(p).exists() or Path(p).is_symlink() for p in
                 ('/dev/dri', '/dev/snd', '/dev/input', '/dev/mem', '/dev/kvm', '/dev/fuse', '/dev/vfio', '/dev/net')),
         'hardware device path exposure refused')
    for path in RUNTIME_FILES:
        info = Path(path).lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not stat.S_IMODE(info.st_mode) & 0o022,
             'Docker metadata must be root-owned regular and not group/world writable')
    for path in MASKED_NULL & set(observed):
        info = Path(path).lstat()
        need(stat.S_ISCHR(info.st_mode) and (os.major(info.st_rdev), os.minor(info.st_rdev)) == (1, 3),
             'Docker protected kernel path must be the actual null device')
    for path in ('/inputs', '/runner'):
        need(path in observed and 'ro' in observed[path]['options'], f'{path} must be an explicit read-only mount')
    for path in ('/scratch', '/test-home'):
        need(path in observed and observed[path]['fs'] == 'tmpfs' and 'rw' in observed[path]['options'],
             f'{path} must be a dedicated writable tmpfs')
        need(Path(path).is_dir() and not Path(path).is_symlink() and not any(Path(path).iterdir()), f'{path} must start empty')
    need('/out' in observed and 'rw' in observed['/out']['options'] and Path('/out').is_dir() and
         not Path('/out').is_symlink() and not any(Path('/out').iterdir()), '/out must be an empty dedicated writable mount')
    need(set(p.name for p in Path('/sys/class/net').iterdir()) == {'lo'}, 'container must use an isolated no-network namespace')
    need(Path(__file__).resolve() == Path('/runner/repository.py'), 'runner must be mounted at /runner/repository.py')
    need(Path(args.inputs) == Path('/inputs/manifest.json') and not Path(args.inputs).is_symlink(), 'fixed read-only manifest path required')
    for tool in ('pacman', 'repo-add', 'gpg', 'gpgconf', 'bsdtar', 'vercmp'):
        need(shutil.which(tool), f'preinstalled tool required: {tool}')
    return {'mounts': {path: dict(row, options=sorted(row['options'])) for path, row in observed.items()},
            'privileges': actual_privileges, 'exposure': exposure, 'interfaces': ['lo'], 'docker_marker': True}


def input_file(ref):
    need(isinstance(ref, dict) and DIGEST.fullmatch(ref.get('sha256', '')), 'input SHA-256 required')
    rel = Path(ref['path'])
    need(not rel.is_absolute() and rel.as_posix() == ref['path'] and '..' not in rel.parts, 'unsafe input filename')
    path = Path('/inputs') / rel
    need(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to('/inputs'), 'input must be a regular contained file')
    need(sha(path) == ref['sha256'], f'input checksum mismatch: {rel}')
    return path


def signature_status(text, fingerprint):
    records = [line.split()[1:] for line in text.splitlines() if line.startswith('[GNUPG:] ')]
    bad = {'EXPSIG', 'EXPKEYSIG', 'REVKEYSIG', 'BADSIG', 'ERRSIG', 'NO_PUBKEY', 'KEYEXPIRED',
           'SIGEXPIRED', 'KEYREVOKED', 'FAILURE', 'ERROR', 'NODATA'}
    need(not any(r and r[0] in bad for r in records), 'signature/key invalid, expired, revoked or missing')
    valid = [r for r in records if r and r[0] == 'VALIDSIG']
    need(len(valid) == 1 and len(valid[0]) == 11 and valid[0][1] == fingerprint and valid[0][-1] == fingerprint and
         valid[0][8] in {'8', '9', '10', '11'}, 'expected full TEST fingerprint/SHA-2 signature missing')


def fixture(path, version, value):
    metadata = '\n'.join((f'pkgname = {FIXTURE}', f'pkgbase = {FIXTURE}', f'pkgver = {version}',
        'pkgdesc = SYNTHETIC TEST ONLY repository transaction fixture', 'arch = any', 'license = MIT',
        'builddate = 1791748800', 'packager = TEST ONLY disposable repository integration', f'size = {len(value)}')) + '\n'
    with tarfile.open(path, 'w:xz') as archive:
        for name, data in (('.PKGINFO', metadata.encode()), (PAYLOAD, value.encode())):
            member = tarfile.TarInfo(name)
            member.size, member.mode, member.mtime = len(data), 0o644, 1791748800
            archive.addfile(member, io.BytesIO(data))


def archive_metadata(description):
    match = re.match(r'([-d][rwxstST-]{9})\s+\d+\s+(\d+)\s+(\d+)\s+\d+\s+', description)
    need(match, 'numeric archive ownership/mode listing required')
    text, uid, gid = match.groups()
    mode = 0
    for i, bit in enumerate((0o400, 0o200, 0o100, 0o40, 0o20, 0o10, 0o4, 0o2, 0o1), 1):
        allowed = {'r', '-'} if i % 3 == 1 else {'w', '-'} if i % 3 == 2 else {'x', 's', 'S', '-'} if i < 9 else {'x', 't', 'T', '-'}
        need(text[i] in allowed, 'invalid archive permission bits')
        if text[i] in {'r', 'w', 'x', 's', 't'}:
            mode |= bit
    for i, flag in ((3, 0o4000), (6, 0o2000), (9, 0o1000)):
        if text[i] in {'s', 'S', 't', 'T'}:
            mode |= flag
    return {'mode': mode, 'uid': int(uid), 'gid': int(gid)}


def owned_state(target, name):
    """Describe lstat types; never hash through a payload or parent symlink."""
    path = target / name
    need(path.is_relative_to(target) and '..' not in Path(name).parts, 'owned path escapes copied root')
    for parent in reversed(path.parents):
        if parent == target or parent.is_relative_to(target):
            try:
                info = parent.lstat()
            except FileNotFoundError:
                return {'type': 'missing', 'missing_parent': str(parent.relative_to(target))}
            if not stat.S_ISDIR(info.st_mode):
                value = {'type': 'blocked-parent', 'parent': str(parent.relative_to(target)),
                         'parent_type': stat.S_IFMT(info.st_mode), 'mode': stat.S_IMODE(info.st_mode),
                         'uid': info.st_uid, 'gid': info.st_gid}
                if stat.S_ISLNK(info.st_mode):
                    value['target'] = os.readlink(parent)
                return value
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {'type': 'missing'}
    kind = 'regular' if stat.S_ISREG(info.st_mode) else 'symlink' if stat.S_ISLNK(info.st_mode) else 'directory' if stat.S_ISDIR(info.st_mode) else 'special'
    value = {'type': kind, 'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
    if kind == 'regular':
        value['sha256'] = sha(path)
    elif kind == 'symlink':
        value['target'] = os.readlink(path)
    return value


class Integration:
    def __init__(self, spec, observed=None):
        self.spec = spec
        self.scratch, self.home, self.out = Path('/scratch'), Path('/test-home'), Path('/out')
        self.target = self.scratch / 'system'
        self.config = self.scratch / 'pacman.conf'
        self.receipts, self.cases, self.keys = [], [], {}
        self.result = {'schema_version': 1, 'purpose': 'disposable-generic-repository-test', 'status': 'RUNNING',
                       'hardware_validation': 'NOT RUN', 'stable_promotion': 'NOT RUN', 'published': False,
                       'source_commit': spec['source_commit'], 'commands': self.receipts, 'cases': self.cases}
        self.result['input_contract'] = {k: spec[k] for k in ('nonce', 'image_id', 'daemon_arch', 'script_sha256',
                                                           'upgrade_kind') if k in spec}
        if observed is not None:
            self.result['guard'] = observed

    def command(self, label, argv, *, env=None, expected=0, signature_failure=False, binary=False):
        process = subprocess.run([str(a) for a in argv], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300)
        output = process.stdout.decode(errors='replace')
        filename = f'{len(self.receipts):03d}-{label}.txt'
        (self.out / filename).write_bytes(process.stdout)
        self.receipts.append({'label': label, 'argv': [str(a) for a in argv], 'exit_code': process.returncode,
                              'log': filename, 'sha256': sha(self.out / filename), 'expected': expected})
        need(expected is None or (process.returncode == 0 if expected == 0 else process.returncode != 0),
             f'{label}: unexpected exit {process.returncode}')
        if signature_failure:
            need(re.search(r'(signature|public key|unknown trust|untrusted|revoked)', output, re.I),
                 f'{label}: failure lacks signature/trust diagnostic')
        return process.stdout if binary else output

    def gpg(self, home):
        return ['gpg', '--batch', '--no-options', '--homedir', home, '--no-default-keyring',
                '--keyring', home / 'pubring.gpg', '--no-auto-key-retrieve']

    def key(self, role, usage):
        home = self.home / role
        home.mkdir(mode=0o700)
        identity = f'TEST ONLY disposable repository {role} <{role}@test.invalid>'
        self.command(f'generate-{role}', self.gpg(home) + ['--pinentry-mode', 'loopback', '--passphrase', '',
                     '--quick-generate-key', identity, 'ed25519', usage, '1d'])
        listing = self.command(f'fingerprint-{role}', self.gpg(home) + ['--with-colons', '--list-keys'])
        fingerprint = next(line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:'))
        need(re.fullmatch(r'[0-9A-F]{40}', fingerprint), 'unexpected TEST key fingerprint')
        self.keys[role] = {'home': home, 'fingerprint': fingerprint, 'identity': identity}
        # Public material only; never copy a home, private key, trustdb or revocation certificate.
        public = self.out / f'TEST-{role}-public.asc'
        self.command(f'export-public-{role}', self.gpg(home) + ['--armor', '--output', public, '--export', fingerprint])
        public_listing = self.command(f'confirm-public-{role}', self.gpg(home) + ['--with-colons', '--show-keys', public])
        need([line.split(':')[9] for line in public_listing.splitlines() if line.startswith('fpr:')] == [fingerprint],
             'exported public certificate differs from explicit TEST fingerprint')
        self.keys[role]['public_sha256'] = sha(public)
        return self.keys[role]

    def trust(self, signer):
        verifier = self.keys['verifier']
        self.command(f'import-{signer}', self.gpg(verifier['home']) + ['--import', self.out / f'TEST-{signer}-public.asc'])
        self.command(f'local-certify-{signer}', self.gpg(verifier['home']) + ['--local-user', verifier['fingerprint'],
                     '--quick-lsign-key', self.keys[signer]['fingerprint']])
        self.command(f'update-trust-{signer}', self.gpg(verifier['home']) + ['--check-trustdb'])

    def sign(self, path, signer):
        key = self.keys[signer]
        self.command('sign-' + signer, self.gpg(key['home']) + ['--local-user', key['fingerprint'], '--digest-algo', 'SHA256',
                     '--detach-sign', '--output', str(path) + '.sig', path])
        status = self.command('verify-' + signer, self.gpg(key['home']) + ['--status-fd', '1', '--verify', str(path) + '.sig', path])
        signature_status(status, key['fingerprint'])

    def metadata(self, path):
        entries = self.command('archive-names', ['bsdtar', '-tf', path]).splitlines()
        listing = self.command('archive-types', ['bsdtar', '--numeric-owner', '-tvf', path]).splitlines()
        need(len(entries) == len(listing) == len(set(entries)) and all(x[:1] in {'-', 'd'} for x in listing),
             'nonregular/duplicate or inconsistent package member listings')
        for name in entries:
            normalized = name.removeprefix('./').rstrip('/')
            need(normalized and not normalized.startswith('/') and '..' not in Path(normalized).parts and
                 Path(normalized).as_posix() == normalized, 'unsafe archive path')
            need(normalized in {'.PKGINFO', '.BUILDINFO', '.MTREE'} or normalized in {'usr', 'usr/bin', 'usr/share',
                 'usr/share/doc', 'usr/share/licenses'} or normalized.startswith(('usr/share/cachy-asahi',
                 'usr/share/doc/cachy-asahi', 'usr/share/licenses/cachy-asahi')) or normalized == 'usr/bin/cachy-asahi-setup',
                 'package writes outside reviewed original/TEST data scope or includes a hook')
        info = {}
        member = next((x for x in entries if x.removeprefix('./') == '.PKGINFO'), None)
        need(member, '.PKGINFO missing')
        for line in self.command('pkginfo', ['bsdtar', '-xOf', path, member]).splitlines():
            if line and not line.startswith('#'):
                k, v = line.split(' = ', 1)
                info.setdefault(k, []).append(v)
        need(all(len(info.get(k, [])) == 1 for k in ('pkgname', 'pkgver', 'arch')), 'package identity missing/duplicated')
        need(info['arch'][0] in {'any', 'aarch64'} and info.get('license') == ['MIT'], 'unexpected package architecture/license')
        payload, attributes = {}, {}
        for name, description in zip(entries, listing):
            normalized = name.removeprefix('./')
            if description.startswith('-') and not normalized.startswith('.'):
                data = self.command('payload-read', ['bsdtar', '-xOf', path, name], binary=True)
                payload[normalized] = hashlib.sha256(data).hexdigest()
                attributes[normalized] = archive_metadata(description)
        return {'name': info['pkgname'][0], 'version': info['pkgver'][0], 'sha256': sha(path), 'path': path,
                'payload_sha256': payload, 'payload_metadata': attributes,
                'relations': {k: info.get(k, []) for k in ('depend', 'provides', 'conflict', 'replaces')}}

    def inputs(self, field):
        packages = {}
        for item in self.spec[field]:
            path = input_file(dict(item, path=item.get('archive', item.get('path'))))
            need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+:-]*\.pkg\.tar\.(xz|zst|gz)', path.name), 'unsafe package filename')
            info = self.metadata(path)
            need(item.get('name') == info['name'] and item.get('version') == info['version'] and
                 item.get('payload_sha256') == info['payload_sha256'], 'archive identity/full payload map differs from reviewed input')
            need(info['name'] in ORIGINALS and info['name'] not in packages, 'only one archive for each actual original is allowed')
            packages[info['name']] = info
        need(set(packages) == ORIGINALS, 'all four actual original archives required')
        return packages

    def repository(self, label, packages, fixture_path, signer, *, preserve_fixture_signature=None,
                   omit_fixture_signature=False):
        directory = self.scratch / 'repos' / label
        directory.mkdir(parents=True)
        paths = []
        for package in [p['path'] for p in packages.values()] + [fixture_path]:
            dest = directory / package.name
            shutil.copyfile(package, dest)
            need(sha(dest) == sha(package), 'repository copy changed approved bytes')
            if package == fixture_path and preserve_fixture_signature:
                shutil.copyfile(preserve_fixture_signature, Path(str(dest) + '.sig'))
            elif package == fixture_path and omit_fixture_signature:
                pass  # Explicit unsigned TEST negative case; signed database still required.
            else:
                self.sign(dest, signer)
            paths.append(dest)
        key = self.keys[signer]
        # repo-add does not accept --homedir; a private TEST gpg.conf binds its explicit keyring.
        env = dict(os.environ, GNUPGHOME=str(key['home']))
        self.command('repo-add-' + label, ['repo-add', '--include-sigs', '--sign', '--key', key['fingerprint'],
                     directory / 'integration.db.tar.gz', *paths], env=env)
        for name in ('integration.db.tar.gz', 'integration.files.tar.gz'):
            path = directory / name
            if not Path(str(path) + '.sig').exists():
                self.sign(path, signer)
            status = self.command('verify-database-' + label, self.gpg(key['home']) + ['--status-fd', '1', '--verify', str(path) + '.sig', path])
            signature_status(status, key['fingerprint'])
        return directory

    def select(self, repository):
        active = self.scratch / 'repos' / 'active'
        if active.is_symlink():
            active.unlink()
        need(not active.exists(), 'unexpected active repository path')
        active.symlink_to(repository.name)
        cache = self.scratch / 'cache'
        if cache.exists():
            shutil.rmtree(cache)
        cache.mkdir()

    def pacman(self, label, options, *, reject=False):
        argv = ['pacman', '--config', self.config, '--root', self.target,
                '--dbpath', self.target / 'var/lib/pacman', '--cachedir', self.scratch / 'cache',
                '--gpgdir', self.keys['verifier']['home'], '--hookdir', self.scratch / 'masked-hooks',
                '--logfile', self.out / 'pacman.log', '--noconfirm', '--color', 'never', *options]
        return self.command(label, argv, expected=1 if reject else 0, signature_failure=reject)

    def snapshot(self, label):
        inventory = self.pacman('inventory-' + label, ['-Q'])
        files = {}
        for name in self.owned:
            if name.endswith('/'):
                continue
            files[name] = owned_state(self.target, name)
        write(self.out / f'{label}-snapshot.json', {'inventory': inventory, 'files': files})
        return inventory, files

    def installed(self, packages, fixture_version):
        inventory = self.pacman('verify-installed-versions', ['-Q'])
        need(dict(line.split() for line in inventory.splitlines()) ==
             dict(self.base_versions, **{name: p['version'] for name, p in packages.items()}, **{FIXTURE: fixture_version}),
             'installed package versions differ from complete reviewed transaction')
        expected_paths = {PAYLOAD}
        for p in packages.values():
            listing = self.pacman('verify-package-ownership', ['-Ql', p['name']])
            owned = set()
            for line in listing.splitlines():
                identity, filename = line.split(maxsplit=1)
                path = Path(filename)
                need(identity == p['name'] and path.is_relative_to(self.target), 'package ownership path escapes copied root')
                owned.add(path.relative_to(self.target).as_posix())
            need(set(p['payload_sha256']) <= owned, 'installed payload ownership differs from package identity')
            need(set(p.get('payload_metadata', {})) == set(p['payload_sha256']), 'complete archive file metadata required')
            for filename, digest in p['payload_sha256'].items():
                expected_paths.add(filename)
                actual = owned_state(self.target, filename)
                need(actual.get('type') == 'regular' and actual.get('sha256') == digest, 'installed payload differs from reviewed archive')
                need(all(actual[k] == value for k, value in p['payload_metadata'][filename].items()) and
                     set(p['payload_metadata'][filename]) == {'mode', 'uid', 'gid'}, 'installed mode/uid/gid differs from reviewed archive')
        for filename in self.owned - expected_paths:
            path = self.target / filename
            need(not path.exists() and not path.is_symlink(), 'obsolete installed fixture payload was not removed')

    def transaction(self, label, repository, *, downgrade=False, reject=False, explicit=False,
                    expected_packages=None, fixture_version=None):
        need(reject or (expected_packages is not None and set(expected_packages) == ORIGINALS and fixture_version in {'1-1', '2-1'}),
             'successful transaction requires all four expected original versions/payloads')
        before = self.snapshot(label + '-before')
        self.select(repository)
        opts = ['-Syyuu' if downgrade else '-Syyu', '--noscriptlet']
        if explicit:
            opts += sorted(ORIGINALS | {FIXTURE})
        self.pacman(label, opts, reject=reject)
        after = self.snapshot(label + '-after')
        if reject:
            need(before == after, label + ': rejected transaction changed inventory/payload')
        else:
            self.installed(expected_packages, fixture_version)
            need((self.target / PAYLOAD).read_text() == f'SYNTHETIC TEST fixture version {fixture_version[0]}\n',
                 'changed/rolled-back TEST fixture content differs')
        self.cases.append({'name': label, 'result': 'PASS', 'expected_signature_rejection': reject})

    def copy_base(self):
        source_bytes = 0
        for source in ('/usr', '/etc', '/var/lib/pacman/local'):
            for directory, dirs, files in os.walk(source, followlinks=False):
                dirs[:] = [name for name in dirs if name != 'gnupg']
                for name in files:
                    path = Path(directory) / name
                    if not path.is_symlink():
                        source_bytes += path.stat().st_size
        capacity = shutil.disk_usage(self.scratch)
        self.result['copy_capacity'] = {'source_regular_file_bytes': source_bytes, 'scratch_total_bytes': capacity.total,
                                        'scratch_free_bytes': capacity.free, 'reserve_bytes': 64 * 1024**2}
        need(capacity.free >= source_bytes + 64 * 1024**2, 'scratch tmpfs too small for copied base; increase bounded mount/memory allocation')
        self.target.mkdir()
        for name in ('usr', 'etc'):
            shutil.copytree('/' + name, self.target / name, symlinks=True,
                            ignore=lambda p, names: {'gnupg'} & set(names))
        database = self.target / 'var/lib/pacman'
        database.mkdir(parents=True)
        shutil.copytree('/var/lib/pacman/local', database / 'local', symlinks=True)
        (database / 'sync').mkdir()
        (self.scratch / 'masked-hooks').mkdir()
        for directory in (self.target / 'usr/share/libalpm/hooks', self.target / 'etc/pacman.d/hooks'):
            if directory.exists():
                for hook in directory.glob('*.hook'):
                    mask = self.scratch / 'masked-hooks' / hook.name
                    if not mask.exists() and not mask.is_symlink():
                        mask.symlink_to('/dev/null')
        # Explicit paths, required signatures and a single local repository; no caller pacman config.
        self.config.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\n'
                               'LocalFileSigLevel = Required TrustedOnly\nParallelDownloads = 1\n'
                               '[integration]\nSigLevel = Required TrustedOnly\nServer = file:///scratch/repos/active\n')
        shutil.copyfile(self.config, self.out / 'TEST-pacman.conf')

    def cleanup(self):
        # Always remove all ephemeral private state, including after failure.
        errors = []
        for home in self.home.iterdir():
            try:
                if home.is_dir() and not home.is_symlink():
                    try:
                        subprocess.run(['gpgconf', '--homedir', str(home), '--kill', 'gpg-agent'], capture_output=True, timeout=30)
                    except subprocess.SubprocessError:
                        pass
                    shutil.rmtree(home)
                else:
                    home.unlink()
            except OSError as error:
                errors.append(str(error))
        self.result['test_private_state_removed'] = not any(self.home.iterdir())
        need(not errors and self.result['test_private_state_removed'], 'private TEST state cleanup failed: ' + '; '.join(errors))

    def export_public_repositories(self):
        source, target = self.scratch / 'repos', self.out / 'TEST-repositories'
        target.mkdir()
        aliases = {}
        for path in source.rglob('*'):
            relative = path.relative_to(source)
            dest = target / relative
            if path.is_symlink():
                resolved = path.resolve(strict=True)
                need(resolved.is_relative_to(source), 'repository alias escapes public repository scope')
                aliases[str(relative)] = {'target': str(resolved.relative_to(source)), 'kind': 'directory' if resolved.is_dir() else 'file'}
                if resolved.is_file():
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(resolved, dest)
                    aliases[str(relative)]['regular_copy_sha256'] = sha(dest)
            elif path.is_dir():
                dest.mkdir(parents=True, exist_ok=True)
            else:
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, dest)
        record = self.out / 'TEST-repository-aliases.json'
        write(record, aliases)
        self.sign(record, 'signer-B')
        need(not any(p.is_symlink() for p in target.rglob('*')), 'evidence must not contain symlinks')

    def execute(self):
        try:
            self.result['environment'] = {'architecture': platform.machine(), 'execution': 'native-disposable-container',
                'python': sys.version, 'uid': os.geteuid(), 'page_size': os.sysconf('SC_PAGE_SIZE')}
            baseline = self.inputs('baseline')
            updated = self.inputs('upgrade')
            for name in ORIGINALS:
                cmp = int(self.command('version-compare', ['vercmp', updated[name]['version'], baseline[name]['version']]).strip())
                need(cmp > 0 and updated[name]['sha256'] != baseline[name]['sha256'] and
                     updated[name]['relations'] == baseline[name]['relations'] and
                     updated[name]['payload_sha256'] != baseline[name]['payload_sha256'],
                     'each original needs a greater-version, changed-payload fixture with unchanged dependency relations')
            self.result['original_inputs'] = {field: {k: {x: v[x] for x in ('version', 'sha256')} for k, v in packages.items()}
                                              for field, packages in (('baseline', baseline), ('upgrade', updated))}
            for role, usage in (('signer-A', 'sign'), ('signer-B', 'sign'), ('verifier', 'cert')):
                self.key(role, usage)
                home = self.keys[role]['home']
                (home / 'gpg.conf').write_text(f'no-default-keyring\nkeyring {home}/pubring.gpg\nno-auto-key-retrieve\nauto-key-locate clear\n')
            self.result['public_TEST_identities'] = {k: {x: v[x] for x in ('fingerprint', 'identity', 'public_sha256')} for k, v in self.keys.items()}
            self.copy_base()
            inventory = self.pacman('copied-base-inventory', ['-Q'])
            self.base_versions = dict(line.split() for line in inventory.splitlines())
            need(not (set(self.base_versions) & (ORIGINALS | {FIXTURE})), 'builder must not have project/test packages already installed')
            self.result['base_versions'] = self.base_versions
            first, second = self.scratch / f'{FIXTURE}-1-1-any.pkg.tar.xz', self.scratch / f'{FIXTURE}-2-1-any.pkg.tar.xz'
            fixture(first, '1-1', 'SYNTHETIC TEST fixture version 1\n')
            fixture(second, '2-1', 'SYNTHETIC TEST fixture version 2\n')
            self.owned = {PAYLOAD}
            for package in list(baseline.values()) + list(updated.values()):
                self.owned.update(package['payload_sha256'])
            a = self.repository('baseline-A', baseline, first, 'signer-A')
            b = self.repository('updated-B', updated, second, 'signer-B')
            unknown = self.command('gpg-untrusted-A-status', self.gpg(self.keys['verifier']['home']) + ['--status-fd', '1',
                                   '--verify', a / 'integration.db.tar.gz.sig', a / 'integration.db.tar.gz'], expected=1)
            need('[GNUPG:] NO_PUBKEY' in unknown, 'unknown TEST A key was unexpectedly available')
            self.transaction('untrusted-A-rejected', a, reject=True, explicit=True)
            self.trust('signer-A')
            self.transaction('trusted-baseline-full-install', a, explicit=True, expected_packages=baseline, fixture_version='1-1')
            need((self.target / PAYLOAD).read_text() == 'SYNTHETIC TEST fixture version 1\n', 'baseline fixture not installed')
            self.transaction('untrusted-rotation-B-rejected', b, reject=True)
            self.trust('signer-B')
            self.transaction('trusted-rotation-full-upgrade', b, expected_packages=updated, fixture_version='2-1')
            need((self.target / PAYLOAD).read_text() == 'SYNTHETIC TEST fixture version 2\n', 'changed fixture upgrade missing')
            self.transaction('full-rollback-to-retained-A', a, downgrade=True, expected_packages=baseline, fixture_version='1-1')
            need((self.target / PAYLOAD).read_text() == 'SYNTHETIC TEST fixture version 1\n', 'rollback fixture not restored')
            # Hash matches signed current database; stale package signature is what must fail.
            altered = self.scratch / 'tampered' / second.name
            altered.parent.mkdir()
            fixture(altered, '2-1', 'SYNTHETIC TEST tampered version 2\n')
            bad_package = self.repository('tampered-package-B', updated, altered, 'signer-B',
                                          preserve_fixture_signature=b / (second.name + '.sig'))
            bad = self.command('gpg-tampered-package-status', self.gpg(self.keys['verifier']['home']) + ['--status-fd', '1',
                               '--verify', bad_package / (second.name + '.sig'), bad_package / second.name], expected=1)
            need('[GNUPG:] BADSIG' in bad, 'tampered package did not produce a bad-signature receipt')
            self.transaction('tampered-package-signature-rejected', bad_package, reject=True)
            bad_database = self.scratch / 'repos/tampered-database-B'
            shutil.copytree(b, bad_database, symlinks=True)
            with (bad_database / 'integration.db.tar.gz').open('ab') as stream:
                stream.write(b'UNSIGNED TEST DATABASE TAMPER')
            bad = self.command('gpg-tampered-database-status', self.gpg(self.keys['verifier']['home']) + ['--status-fd', '1',
                               '--verify', bad_database / 'integration.db.tar.gz.sig', bad_database / 'integration.db.tar.gz'], expected=1)
            need('[GNUPG:] BADSIG' in bad, 'tampered database did not produce a bad-signature receipt')
            self.transaction('tampered-database-signature-rejected', bad_database, reject=True)
            missing_package = self.repository('missing-package-signature-B', updated, second, 'signer-B',
                                              omit_fixture_signature=True)
            need(not Path(str(missing_package / second.name) + '.sig').exists(), 'unsigned TEST probe unexpectedly signed')
            self.transaction('missing-package-signature-rejected', missing_package, reject=True)
            missing_database = self.scratch / 'repos/missing-database-signature-B'
            shutil.copytree(b, missing_database, symlinks=True)
            for name in ('integration.db.tar.gz.sig', 'integration.db.sig'):
                path = missing_database / name
                if path.exists() or path.is_symlink():
                    path.unlink()
            self.transaction('missing-database-signature-rejected', missing_database, reject=True)
            # Import revocation locally; never export the sensitive standalone certificate.
            old = self.keys['signer-A']
            certificate = old['home'] / 'openpgp-revocs.d' / (old['fingerprint'] + '.rev')
            data = certificate.read_text()
            marker = ':-----BEGIN PGP PUBLIC KEY BLOCK-----'
            need(marker in data, 'generated TEST revocation certificate missing')
            revocation = self.home / 'TEST-revocation.asc'
            revocation.write_text(data[data.index(marker):].replace(marker, marker[1:], 1))
            self.command('revoke-A-signing-home', self.gpg(old['home']) + ['--import', revocation])
            self.command('revoke-A-verification-home', self.gpg(self.keys['verifier']['home']) + ['--import', revocation])
            revocation.unlink()
            self.command('export-public-revoked-A', self.gpg(old['home']) + ['--armor', '--output',
                         self.out / 'TEST-signer-A-revoked-public.asc', '--export', old['fingerprint']])
            status = self.command('gpg-revoked-A-status', self.gpg(self.keys['verifier']['home']) + ['--status-fd', '1', '--verify',
                                  a / 'integration.db.tar.gz.sig', a / 'integration.db.tar.gz'], expected=None)
            need('[GNUPG:] REVKEYSIG' in status, 'GPG did not identify TEST key revocation')
            self.transaction('revoked-A-repository-rejected', a, reject=True)
            self.transaction('unrevoked-B-final-full-upgrade', b, explicit=True, expected_packages=updated, fixture_version='2-1')
            need((self.target / PAYLOAD).read_text() == 'SYNTHETIC TEST fixture version 2\n', 'safe signer final upgrade failed')
            self.pacman('dependency-consistency', ['-Dk'])
            self.pacman('installed-original-file-presence', ['-Qk', *sorted(ORIGINALS | {FIXTURE})])
            self.export_public_repositories()
            self.result['status'] = 'PASS'
            self.result['transaction_scope'] = 'complete -Syyu/-Syyuu over copied generic builder inventory; four reviewed changed-package derivatives plus a synthetic tamper probe'
        except Exception as error:
            self.result.update(status='FAIL', error=str(error))
            raise
        finally:
            try:
                self.cleanup()
            except Exception as error:
                self.result.update(status='FAIL', cleanup_error=str(error), test_private_state_removed=False)
            self.result['evidence_sha256'] = {str(p.relative_to(self.out)): sha(p) for p in self.out.rglob('*') if p.is_file() and not p.is_symlink()}
            write(self.out / 'result.json', self.result)
            need(self.result['test_private_state_removed'], 'private TEST state cleanup failed; container must be discarded')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', required=True)
    parser.add_argument('--inputs-sha256', required=True)
    parser.add_argument('--allow-disposable-repository-test', action='store_true')
    args = parser.parse_args()
    observed = guard(args)  # Must precede any key/package command, output creation or input processing.
    need(DIGEST.fullmatch(args.inputs_sha256) and sha(args.inputs) == args.inputs_sha256, 'reviewed manifest hash mismatch')
    spec = json.loads(Path(args.inputs).read_text())
    need(spec.get('schema_version') == 1 and spec.get('purpose') == 'disposable-generic-repository-test', 'invalid integration purpose/schema')
    need(spec.get('execution') == 'native-aarch64-disposable-docker' and spec.get('allow_system_mutation') is True and
         spec.get('daemon_arch') == 'aarch64' and spec.get('nonce') == os.environ['CACHY_ASAHI_DISPOSABLE_REPOSITORY'] and
         spec.get('image_id') == os.environ['CACHY_ASAHI_IMAGE_ID'], 'container nonce/image/mutation identity differs from contract')
    need(spec.get('upgrade_kind') == 'synthetic-changed-package-fixtures', 'upgrades must be explicitly labeled nonproduction fixtures')
    need(re.fullmatch(r'[0-9a-f]{40}', spec.get('source_commit', '')), 'exact project source commit required')
    need(spec.get('script_sha256') == sha(__file__), 'runner differs from reviewed source hash')
    Integration(spec, observed).execute()
    print('PASS: disposable generic repository transactions; hardware/stable gates unchanged.')


if __name__ == '__main__':
    try:
        main()
    except (Refused, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f'repository integration refused/failed: {error}', file=sys.stderr)
        sys.exit(1)
