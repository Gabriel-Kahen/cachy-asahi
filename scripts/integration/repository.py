#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Strict local repository transactions ONLY inside an explicit disposable ARM container."""
import argparse
from contextlib import contextmanager
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
import tempfile
import time

ORIGINALS = {'cachy-asahi-hyprland-settings', 'cachy-asahi-fish-config',
             'cachy-asahi-zsh-config', 'cachy-asahi-setup'}
FIXTURE = 'cachy-asahi-repository-test-fixture'
PAYLOAD = 'usr/share/cachy-asahi-repository-TEST/fixture.txt'
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
SAFE_CAPS = sum(1 << bit for bit in (0, 1, 3, 6, 7, 18))  # Also SYS_CHROOT for libalpm's copied-root ldconfig.
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
STRICT_OPTIONS = ('[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\n'
                  'LocalFileSigLevel = Required TrustedOnly\nParallelDownloads = 1\n')
STRICT_REPOSITORY = '[integration]\nSigLevel = Required TrustedOnly\nServer = file:///scratch/repos/active\n'
MISSING_DATABASE_CASE = 'missing-database-signature-rejected'
REVOKED_CASE = 'revoked-A-repository-rejected'
FINAL_CASE = 'unrevoked-B-final-full-upgrade'


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
    need(all(result[name] == SAFE_CAPS for name in ('CapEff', 'CapPrm', 'CapBnd'))
         and result['CapInh'] == result['CapAmb'] == 0, 'actual six-cap repository mask required')
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


def package_inventory(text):
    """Exact pacman -Q stdout schema; never discard prompts/diagnostic lines."""
    need(isinstance(text, str) and 0 < len(text) <= 1024**2 and text.endswith('\n')
         and text.isascii(), 'invalid package inventory text')
    rows = {}
    for line in text.split('\n')[:-1]:
        match = re.fullmatch(r'([a-z0-9][a-z0-9@._+-]{0,127}) ([A-Za-z0-9][A-Za-z0-9._+:~-]{0,255})', line)
        need(match is not None and match[1] not in rows, 'invalid/duplicate package inventory row')
        rows[match[1]] = match[2]
    need(0 < len(rows) <= 2048, 'package inventory count exceeds bound')
    return rows


def inventory_text(rows):
    return ''.join(f'{name} {rows[name]}\n' for name in sorted(rows))


class Integration:
    def __init__(self, spec, observed=None):
        self.spec = spec
        self.scratch, self.home, self.out = Path('/scratch'), Path('/test-home'), Path('/out')
        self.target = self.scratch / 'system'
        self.config = self.scratch / 'pacman.conf'
        self.query_config = self.scratch / 'query-pacman.conf'
        self.receipts, self.cases, self.keys = [], [], {}
        self.result = {'schema_version': 1, 'purpose': 'disposable-generic-repository-test', 'status': 'RUNNING',
                       'hardware_validation': 'NOT RUN', 'stable_promotion': 'NOT RUN', 'published': False,
                       'source_commit': spec['source_commit'], 'commands': self.receipts, 'cases': self.cases}
        self.result['input_contract'] = {k: spec[k] for k in ('nonce', 'image_id', 'daemon_arch', 'script_sha256',
                                                           'upgrade_kind') if k in spec}
        if observed is not None:
            self.result['guard'] = observed

    def command(self, label, argv, *, env=None, expected=0, signature_failure=False, binary=False, stdout_only=False,
                clean_diagnostics=False):
        process = subprocess.run([str(a) for a in argv], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE if stdout_only else subprocess.STDOUT, timeout=300)
        output = process.stdout.decode(errors='replace')
        filename = f'{len(self.receipts):03d}-{label}.txt'
        (self.out / filename).write_bytes(process.stdout)
        receipt = {'label': label, 'argv': [str(a) for a in argv], 'exit_code': process.returncode,
                   'log': filename, 'sha256': sha(self.out / filename), 'expected': expected}
        if stdout_only:
            diagnostic = f'{len(self.receipts):03d}-{label}-stderr.txt'
            (self.out / diagnostic).write_bytes(process.stderr)
            receipt.update(stderr_log=diagnostic, stderr_sha256=sha(self.out / diagnostic))
        self.receipts.append(receipt)
        need(expected in (None, 0, 1, 'nonzero'), 'unknown command exit policy')
        need(expected is None or (process.returncode == 0 if expected == 0 else process.returncode != 0),
             f'{label}: unexpected exit {process.returncode}')
        if signature_failure:
            need(re.search(r'(signature|public key|unknown trust|untrusted|revoked)', output, re.I),
                 f'{label}: failure lacks signature/trust diagnostic')
        if clean_diagnostics:
            diagnostics = output + (process.stderr.decode(errors='replace') if stdout_only else '')
            need(re.search(r'^(?:error\s*:|could not change (?:the root directory|directory)\b)', diagnostics, re.I | re.M) is None,
                 f'{label}: positive command has error/ancillary execution diagnostic')
            receipt['positive_diagnostics'] = 'PASS'
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
        destinations = set()
        for name in entries:
            normalized = name.removeprefix('./').rstrip('/')
            need(normalized and not normalized.startswith('/') and '..' not in Path(normalized).parts and
                 Path(normalized).as_posix() == normalized, 'unsafe archive path')
            need(normalized not in destinations, 'duplicate normalized package destination')
            destinations.add(normalized)
            need(normalized in {'.PKGINFO', '.BUILDINFO', '.MTREE'} or normalized in {'usr', 'usr/bin', 'usr/share',
                 'usr/share/doc', 'usr/share/licenses'} or normalized.startswith(('usr/share/cachy-asahi',
                 'usr/share/doc/cachy-asahi', 'usr/share/licenses/cachy-asahi')) or normalized in {'usr/bin/cachy-asahi-setup', 'usr/bin/cachy-asahi-screenshot'},
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
        screenshot = 'usr/bin/cachy-asahi-screenshot'
        if any(name.removeprefix('./').rstrip('/') == screenshot for name in entries):
            need(info['pkgname'] == ['cachy-asahi-hyprland-settings'] and info['pkgver'][0] in {'0.1.0-2', '0.1.1-1'} and
                 info['arch'] == ['any'] and
                 payload.get(screenshot) == '5a920a5dd7a40463417a9b15e64a6620acfe7b2328960bf7014c9f587c4b69a8' and
                 attributes.get(screenshot) == {'mode': 0o755, 'uid': 0, 'gid': 0},
                 'screenshot differs from reviewed desktop package identity/content/header')
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

    def add_database(self, label, database, packages, key, env):
        probe_env = dict(env, LC_ALL='C')
        version = self.command('repo-add-version-' + label, ['repo-add', '--version'],
                               env=probe_env, binary=True, stdout_only=True).splitlines()
        match = re.fullmatch(rb'repo-add \(pacman\) (\d+)\.(\d+)\.(\d+)(?:\.r\d+\.g[0-9a-f]+)?(?:-\d+)?',
                             version[0] if version else b'')
        need(match is not None, 'unrecognized repo-add version')
        family = tuple(int(value) for value in match.groups()[:2])
        # Upstream 6.0 embeds signatures by default; 6.1 introduced the opt-in.
        need(family in {(6, 0), (6, 1), (7, 0), (7, 1)}, 'unsupported repo-add version')
        help_text = self.command('repo-add-help-' + label, ['repo-add', '--help'],
                                 env=probe_env, binary=True, stdout_only=True)
        advertised = re.search(rb'(?<![\w-])--include-sigs(?![\w-])', help_text) is not None
        options = ['--include-sigs'] if family != (6, 0) or advertised else []
        # A failed database command is terminal: never retry with weaker options.
        self.command('repo-add-' + label, ['repo-add', *options, '--sign', '--key', key, database, *packages], env=env)

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
        # The root's /tmp is read-only; isolate repo-add/mktemp below scratch.
        with tempfile.TemporaryDirectory(prefix='repo-add-', dir=self.scratch) as temporary:
            env = dict(os.environ, GNUPGHOME=str(key['home']), TMPDIR=temporary)
            self.add_database(label, directory / 'integration.db.tar.gz', paths, key['fingerprint'], env)
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

    @contextmanager
    def sync_directory(self):
        """Retain the owned directory chain and rebind it to the current path."""
        need(self.target == self.scratch / 'system' and self.scratch.is_absolute(), 'private sync-cache scope required')
        scratch, target = self.scratch, self.target
        names = ('system', 'var', 'lib', 'pacman', 'sync')
        flags, fds = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, []
        identity = lambda info: tuple(getattr(info, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid'))
        try:
            fds.append(os.open(scratch, flags))
            for name in names:
                info = os.fstat(fds[-1])
                need(info.st_uid == os.geteuid() and not info.st_mode & 0o022, 'sync-cache parent ownership/mode differs')
                fds.append(os.open(name, flags, dir_fd=fds[-1]))
            info = os.fstat(fds[-1])
            need(info.st_uid == os.geteuid() and not info.st_mode & 0o022, 'sync-cache directory ownership/mode differs')
            expected = [identity(os.fstat(fd)) for fd in fds]
            def current(*, absent=False):
                need(self.scratch == scratch and self.target == target, 'sync-cache scope changed')
                opened = []
                try:
                    opened.append(os.open(scratch, flags))
                    for n, original in enumerate(fds):
                        need(identity(os.fstat(original)) == expected[n]
                             and identity(os.fstat(opened[-1])) == expected[n], 'current sync-cache directory chain changed')
                        if n < len(names):
                            opened.append(os.open(names[n], flags, dir_fd=opened[-1]))
                    if absent:
                        need(not self.sync_entries(opened[-1]), 'current private sync-cache absence unconfirmed')
                finally:
                    for opened_fd in reversed(opened):os.close(opened_fd)
            current()
            yield fds[-1], current
        finally:
            for fd in reversed(fds):os.close(fd)

    def sync_entries(self, fd):
        entries = set()
        with os.scandir(fd) as iterator:
            for entry in iterator:
                need(entry.name in {'integration.db', 'integration.db.sig'} and entry.name not in entries,
                     'unexpected private sync-cache entry')
                entries.add(entry.name)
        return entries

    @staticmethod
    def cache_identity(info):
        return tuple(getattr(info, name) for name in ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
                                                     'st_size', 'st_mtime_ns', 'st_ctime_ns'))

    def sync_bytes(self, fd, reference):
        need(reference.parent == self.scratch / 'repos' and reference.name in {'baseline-A', 'updated-B'},
             'retained sync-cache reference differs')
        expected = self.repository_bytes(reference)
        need(self.sync_entries(fd) == {'integration.db', 'integration.db.sig'}, 'complete cached database/signature required')
        result = {}
        for name, source in (('integration.db', 'integration.db.tar.gz'), ('integration.db.sig', 'integration.db.tar.gz.sig')):
            need(source in expected and 'alias' not in expected[source], 'regular signed reference required')
            cached = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                info = os.fstat(cached)
                need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                     and not info.st_mode & 0o7022 and 0 < info.st_size <= 8 * 1024**2, 'unsafe sync-cache file')
                data = bytearray()
                while block := os.read(cached, min(65536, 8 * 1024**2 + 1 - len(data))):
                    data.extend(block)
                    need(len(data) <= 8 * 1024**2, 'sync-cache byte bound exceeded')
                need(self.cache_identity(info) == self.cache_identity(os.fstat(cached))
                     and len(data) == info.st_size, 'sync-cache read changed')
                digest = hashlib.sha256(data).hexdigest()
                need(digest == expected[source]['sha256'], 'cached sync bytes differ from retained repository')
                result[name] = {'sha256': digest, 'identity': self.cache_identity(info)}
            finally:
                os.close(cached)
        return result

    def prior_log(self, label):
        rows = [row for row in self.receipts if row['label'] == label]
        need(len(rows) == 1, 'unique prior rejection receipt required')
        row = rows[0]
        need(re.fullmatch(r'[0-9]{3}-' + re.escape(label) + r'\.txt', row['log']), 'prior receipt log path differs')
        path = self.out / row['log']
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                 and info.st_size <= 1024**2, 'regular bounded prior receipt log required')
            data = bytearray()
            while block := os.read(fd, min(65536, 1024**2 + 1 - len(data))):
                data.extend(block)
                need(len(data) <= 1024**2, 'prior log byte bound exceeded')
            need(self.cache_identity(info) == self.cache_identity(os.fstat(fd)) and len(data) == info.st_size,
                 'prior receipt log read changed')
        finally:
            os.close(fd)
        need(len(data) <= 1024**2 and hashlib.sha256(data).hexdigest() == row['sha256'], 'prior receipt log binding differs')
        return row, data.decode('utf-8')

    def reset_revoked_sync_cache(self, retained_a, healthy_b):
        """Only after the actual revoked-A rejection, before the final healthy B."""
        need(self.cases and self.cases[-1] == {'name': REVOKED_CASE, 'result': 'PASS', 'expected_signature_rejection': True}
             and hasattr(self, 'revoked_rejection_state'), 'completed revoked-A rejection required before cache reset')
        need(retained_a == self.scratch / 'repos/baseline-A' and healthy_b == self.scratch / 'repos/updated-B',
             'final repository transition differs')
        active = self.scratch / 'repos/active'
        need(active.is_symlink() and os.readlink(active) == 'baseline-A'
             and self.config.read_text() == STRICT_OPTIONS + STRICT_REPOSITORY, 'revoked-A selection/strict config required')
        rejected, diagnostic = self.prior_log(REVOKED_CASE)
        proof, status = self.prior_log('gpg-revoked-A-status')
        fingerprint = self.keys['signer-A']['fingerprint']
        need(re.fullmatch(r'[0-9A-F]{40}', fingerprint) and rejected['expected'] == 'nonzero' and rejected['exit_code'] != 0
             and 'signature from "TEST ONLY disposable repository signer-A <signer-A@test.invalid>" is invalid' in diagnostic
             and '[GNUPG:] REVKEYSIG ' + fingerprint[-16:] + ' ' in status
             and '[GNUPG:] VALIDSIG ' + fingerprint + ' ' in status, 'actual revoked-A signature rejection proof required')
        references = {str(path): self.repository_bytes(path) for path in (retained_a, healthy_b)}
        before = self.snapshot('revoked-A-sync-cache-reset-before')
        need(before == self.revoked_rejection_state, 'installed state changed after revoked-A rejection')
        with self.sync_directory() as (fd, current):
            files = self.sync_bytes(fd, retained_a)  # Validate both before removing either.
            current()
            for name, row in files.items():
                current()
                need(self.cache_identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) == row['identity'],
                     'sync-cache changed before unlink')
                os.unlink(name, dir_fd=fd)
                current()
            current(absent=True)
            after = self.snapshot('revoked-A-sync-cache-reset-after')
            need(before == after, 'sync-cache reset changed installed inventory/payload')
            need(references == {str(path): self.repository_bytes(path) for path in (retained_a, healthy_b)}
                 and self.config.read_text() == STRICT_OPTIONS + STRICT_REPOSITORY, 'reset changed retained repositories/config')
            current(absent=True)  # Current-path absence, after all other acceptance observations.
            record = {'status': 'PASS', 'scope': 'two private copied-root sync files after revoked-A rejection',
                      'prior_rejection_log_sha256': rejected['sha256'], 'revocation_status_log_sha256': proof['sha256'],
                      'removed': {name: row['sha256'] for name, row in files.items()}, 'absence': 'PASS',
                      'installed_state_unchanged': True}
            path = self.out / 'revoked-A-sync-cache-reset.json'
            write(path, record)
            self.result['sync_cache_reset'] = {'receipt': path.name, 'sha256': sha(path)}

    def verify_final_sync_cache(self, healthy_b):
        need(self.cases and self.cases[-1]['name'] == FINAL_CASE and self.cases[-1]['result'] == 'PASS'
             and self.result.get('sync_cache_reset'), 'final healthy-B transaction/reset required')
        active = self.scratch / 'repos/active'
        need(healthy_b == self.scratch / 'repos/updated-B' and active.is_symlink() and os.readlink(active) == 'updated-B'
             and self.config.read_text() == STRICT_OPTIONS + STRICT_REPOSITORY, 'healthy-B selection/strict config required')
        with self.sync_directory() as (fd, current):
            files = self.sync_bytes(fd, healthy_b)
            current()
        self.result['final_sync_cache'] = {name: row['sha256'] for name, row in files.items()}

    def repository_bytes(self, directory):
        """Bind every flat repository byte and only the known repo-add aliases."""
        directory = Path(directory)
        need(directory.parent == self.scratch / 'repos' and directory.is_dir() and not directory.is_symlink(),
             'missing-database case requires a private local repository')
        aliases = {'integration.db': 'integration.db.tar.gz', 'integration.db.sig': 'integration.db.tar.gz.sig',
                   'integration.files': 'integration.files.tar.gz', 'integration.files.sig': 'integration.files.tar.gz.sig'}
        result = {}
        for path in directory.iterdir():
            need(len(result) < 32, 'repository entry bound exceeded')
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                target = os.readlink(path)
                need(aliases.get(path.name) == target and (directory / target).is_file()
                     and not (directory / target).is_symlink(), 'unexpected repository alias')
                result[path.name] = {'alias': target, 'sha256': sha(path)}
            else:
                need(stat.S_ISREG(mode), 'unexpected repository entry type')
                result[path.name] = {'sha256': sha(path)}
        return result

    def missing_database_inputs(self, repository, reference):
        need(Path(repository).name == 'missing-database-signature-B' and Path(reference).name == 'updated-B',
             'missing-database case source differs')
        original = self.repository_bytes(reference)
        omitted = {'integration.db.tar.gz.sig', 'integration.db.sig'}
        need(omitted <= set(original) and original.get('integration.db', {}).get('alias') == 'integration.db.tar.gz',
             'signed reference database/alias required')
        expected = {name: row for name, row in original.items() if name not in omitted}
        need(self.repository_bytes(repository) == expected, 'missing-database case changed other repository bytes')
        return {'kind': 'missing-required-local-database-signature', 'repository': str(repository),
                'reference': str(reference), 'reference_bytes': original, 'repository_bytes': expected,
                'missing': sorted(omitted)}

    def validate_missing_database(self, proof):
        need(set(proof) == {'kind', 'repository', 'reference', 'reference_bytes', 'repository_bytes', 'missing'}
             and proof['kind'] == 'missing-required-local-database-signature'
             and proof['missing'] == ['integration.db.sig', 'integration.db.tar.gz.sig'], 'unknown database rejection contract')
        repository, reference = Path(proof['repository']), Path(proof['reference'])
        need(self.missing_database_inputs(repository, reference) == proof, 'missing-database case inputs changed')
        active = self.scratch / 'repos/active'
        need(active.is_symlink() and os.readlink(active) == repository.name, 'selected missing-database endpoint differs')
        need(self.config.read_text() == STRICT_OPTIONS + STRICT_REPOSITORY, 'strict local repository signatures required')
        for name in proof['missing']:
            path = repository / name
            need(not path.exists() and not path.is_symlink(), 'database signature must be explicitly absent')

    def missing_database_diagnostic(self, output):
        # Exact local required-signature retrieval failure; no generic download-error exception.
        path = re.escape(str(self.scratch / 'repos/active/integration.db.sig'))
        pattern = (r':: Synchronizing package databases\.\.\.\n integration downloading\.\.\.\n'
                   r"error: failed retrieving file 'integration\.db\.sig' from disk[ ]*: Could not open file "
                   + path + r'\nerror: failed to synchronize all databases \(download library error\)\n')
        need(re.fullmatch(pattern, output) is not None, 'missing-database case lacks exact selected local signature diagnostic')

    def pacman(self, label, options, *, reject=False, missing_database=None):
        if missing_database is not None:
            need(label == MISSING_DATABASE_CASE and reject and options == ['-Syyu', '--noscriptlet'],
                 'typed missing-database rejection is case-specific')
            self.validate_missing_database(missing_database)
        local_query = bool(options and options[0] in {'-Q', '-Ql', '-Qk', '-Dk'})
        argv = ['pacman', '--config', self.query_config if local_query else self.config, '--root', self.target,
                '--dbpath', self.target / 'var/lib/pacman', '--cachedir', self.scratch / 'cache',
                '--gpgdir', self.keys['verifier']['home'], '--hookdir', self.scratch / 'masked-hooks',
                '--logfile', self.out / 'pacman.log', '--noconfirm', '--color', 'never', *options]
        try:
            output = self.command(label, argv, expected='nonzero' if reject else 0,
                                  signature_failure=reject and missing_database is None, stdout_only=local_query,
                                  clean_diagnostics=not reject)
            if missing_database is not None:
                self.missing_database_diagnostic(output)
                self.receipts[-1]['signature_rejection_kind'] = missing_database['kind']
            return output
        finally:
            if missing_database is not None:
                self.validate_missing_database(missing_database)

    def inventory(self, label):
        rows = package_inventory(self.pacman(label, ['-Q']))
        if hasattr(self, 'base_versions'):
            need(all(rows.get(name) == version for name, version in self.base_versions.items())
                 and set(rows) - set(self.base_versions) <= ORIGINALS | {FIXTURE},
                 'inventory differs from complete accepted baseline')
        return rows

    def snapshot(self, label):
        inventory = self.inventory('inventory-' + label)
        files = {}
        for name in self.owned:
            if name.endswith('/'):
                continue
            files[name] = owned_state(self.target, name)
        write(self.out / f'{label}-snapshot.json', {'inventory': inventory_text(inventory), 'files': files})
        return inventory, files

    def installed(self, packages, fixture_version):
        inventory = self.inventory('verify-installed-versions')
        need(inventory ==
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
                    expected_packages=None, fixture_version=None, missing_database=None):
        need(reject or (expected_packages is not None and set(expected_packages) == ORIGINALS and fixture_version in {'1-1', '2-1'}),
             'successful transaction requires all four expected original versions/payloads')
        before = self.snapshot(label + '-before')
        self.select(repository)
        opts = ['-Syyuu' if downgrade else '-Syyu', '--noscriptlet']
        if explicit:
            opts += sorted(ORIGINALS | {FIXTURE})
        try:
            kwargs = {'missing_database': missing_database} if missing_database is not None else {}
            self.pacman(label, opts, reject=reject, **kwargs)
        finally:
            after = self.snapshot(label + '-after')
            if reject:
                need(before == after, label + ': rejected transaction changed inventory/payload')
        if not reject:
            self.installed(expected_packages, fixture_version)
            need((self.target / PAYLOAD).read_text() == f'SYNTHETIC TEST fixture version {fixture_version[0]}\n',
                 'changed/rolled-back TEST fixture content differs')
        case = {'name': label, 'result': 'PASS', 'expected_signature_rejection': reject}
        if missing_database is not None:
            case['rejection_contract'] = missing_database
        self.cases.append(case)
        if label == REVOKED_CASE and reject:
            self.revoked_rejection_state = after

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
        # Pacman validates --cachedir even for -Q, before select() runs.
        (self.scratch / 'cache').mkdir()
        (self.scratch / 'masked-hooks').mkdir()
        for directory in (self.target / 'usr/share/libalpm/hooks', self.target / 'etc/pacman.d/hooks'):
            if directory.exists():
                for hook in directory.glob('*.hook'):
                    mask = self.scratch / 'masked-hooks' / hook.name
                    if not mask.exists() and not mask.is_symlink():
                        mask.symlink_to('/dev/null')
        # Explicit paths, required signatures and a single local repository; no caller pacman config.
        options = STRICT_OPTIONS
        self.query_config.write_text(options)  # No registered sync DB can trigger import prompts.
        self.config.write_text(options + STRICT_REPOSITORY)
        shutil.copyfile(self.config, self.out / 'TEST-pacman.conf')
        shutil.copyfile(self.query_config, self.out / 'TEST-query-pacman.conf')

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
            # Compare the copied root with the actual immutable builder's local DB.
            base = package_inventory(self.command('base-image-inventory', ['pacman', '--config', self.query_config,
                                     '--dbpath', '/var/lib/pacman', '-Q'], stdout_only=True))
            need(len(base) == 341, 'complete accepted 341-package builder inventory required')
            self.base_versions = self.inventory('copied-base-inventory')
            need(self.base_versions == base, 'copied base differs from actual immutable builder inventory')
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
                                   '--verify', a / 'integration.db.tar.gz.sig', a / 'integration.db.tar.gz'], expected='nonzero')
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
                               '--verify', bad_package / (second.name + '.sig'), bad_package / second.name], expected='nonzero')
            need('[GNUPG:] BADSIG' in bad, 'tampered package did not produce a bad-signature receipt')
            self.transaction('tampered-package-signature-rejected', bad_package, reject=True)
            bad_database = self.scratch / 'repos/tampered-database-B'
            shutil.copytree(b, bad_database, symlinks=True)
            with (bad_database / 'integration.db.tar.gz').open('ab') as stream:
                stream.write(b'UNSIGNED TEST DATABASE TAMPER')
            bad = self.command('gpg-tampered-database-status', self.gpg(self.keys['verifier']['home']) + ['--status-fd', '1',
                               '--verify', bad_database / 'integration.db.tar.gz.sig', bad_database / 'integration.db.tar.gz'], expected='nonzero')
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
            proof = self.missing_database_inputs(missing_database, b)
            self.transaction(MISSING_DATABASE_CASE, missing_database, reject=True, missing_database=proof)
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
            self.transaction(REVOKED_CASE, a, reject=True)
            self.reset_revoked_sync_cache(a, b)
            self.transaction(FINAL_CASE, b, explicit=True, expected_packages=updated, fixture_version='2-1')
            self.verify_final_sync_cache(b)
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
