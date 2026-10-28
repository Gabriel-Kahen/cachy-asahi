#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Separate TEST restaging of externally accepted archives; no system installation."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import types

import gate

ROOT = Path(__file__).resolve().parents[3]
SOURCES = {
    'scripts/release/release.py': '418c850e8a44ae71517e074f86f46f5999f5fe7433ca6798de945f318191a918',
    'scripts/client/client.py': '3025aa0e167c836e31c949e0915d4ee82a1007dc0fada598b4895240c82f5f97',
}
ORIGINALS = {'cachy-asahi-hyprland-settings', 'cachy-asahi-fish-config',
             'cachy-asahi-zsh-config', 'cachy-asahi-setup'}
TOOLS = ('python3', 'gpg', 'gpgconf', 'gpg-connect-agent', 'repo-add', 'bsdtar', 'vercmp')
LIMIT, FILE_LIMIT, TOTAL_LIMIT = 1024**2, 16 * 1024**2, 64 * 1024**2
TIMEOUT, TOTAL_SECONDS = 45, 300
PRIVATE = re.compile(rb'-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY|\((?:protected-)?private-key')
DEFERRED_CANCELLATION = []


class Refused(ValueError):
    pass


def need(ok, reason):
    if not ok:
        raise Refused(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def decode(data):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    def invalid(_):
        raise Refused('JSON floats/nonfinite values refused')
    need(isinstance(data, bytes) and 0 < len(data) <= FILE_LIMIT, 'bounded nonempty JSON required')
    value = json.loads(data, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    need(isinstance(value, dict), 'JSON object required')
    return value


def read(path, limit=FILE_LIMIT):
    path = Path(path).absolute()
    need('..' not in path.parts, 'canonical absolute input path required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in path.parts[1:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        child = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(child, 'rb') as stream:
            before = os.fstat(stream.fileno())
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit,
                 'bounded regular single-link input required')
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
            need(len(data) == before.st_size and len(data) <= limit and
                 all(getattr(before, k) == getattr(after, k) for k in fields), 'input changed during read')
            return data
    finally:
        os.close(fd)


def put(path, data, *, dir_fd=None):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def child_limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (TOTAL_LIMIT, TOTAL_LIMIT))
    resource.setrlimit(resource.RLIMIT_CPU, (TIMEOUT, TIMEOUT + 1))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


class Commands:
    """Bound both pipes and whole process groups, including failed commands."""
    def __init__(self, work):
        self.work, self.started, self.records = work, time.monotonic(), []
        self.teardown_started = None
        self.paths, self.pins = {}, {}
        for name in TOOLS:
            path = shutil.which(name, path='/usr/bin:/bin')
            need(path, 'preinstalled tool missing: ' + name)
            path = Path(path).resolve()
            self.paths[name], self.pins[name] = str(path), digest(read(path, 64 * 1024**2))
        (work / 'logs').mkdir(mode=0o700)
        (work / 'home').mkdir(mode=0o700)
        self.env = {'PATH': '/usr/bin:/bin', 'HOME': str(work / 'home'), 'LC_ALL': 'C',
                    'GNUPGHOME': str(work / 'signing-home')}

    def run(self, argv, *, env=None, expected=0):
        argv = [str(x) for x in argv]
        name = Path(argv[0]).name
        need(name in self.paths, 'unreviewed command')
        need(digest(read(self.paths[name], 64 * 1024**2)) == self.pins[name], 'tool changed before execution')
        argv[0] = self.paths[name]
        if self.teardown_started is not None:
            need(name in {'gpgconf', 'gpg-connect-agent'}, 'only private teardown tools allowed after work')
            budget = min(10, 30 - (time.monotonic() - self.teardown_started))
        else:
            budget = min(TIMEOUT, TOTAL_SECONDS - (time.monotonic() - self.started))
        need(budget > 0, 'whole-stage deadline exceeded')
        process = None
        out, err = bytearray(), bytearray()
        try:
            # A signal after Popen returns must not hide the child before this
            # assignment. Pending cancellation is raised inside the cleanup try.
            with defer_cancellation():
                process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           env=env or self.env, start_new_session=True, preexec_fn=child_limits)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, out)
                selector.register(process.stderr, selectors.EVENT_READ, err)
                deadline = time.monotonic() + budget
                while selector.get_map():
                    need(time.monotonic() < deadline, 'command timeout')
                    for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                        block = os.read(key.fileobj.fileno(), 65536)
                        if block:
                            key.data.extend(block)
                            need(len(out) + len(err) <= LIMIT, 'command output limit exceeded')
                        else:
                            selector.unregister(key.fileobj)
                code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        finally:
            if process is not None:
                with defer_cancellation():
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5)
                    process.stdout.close()
                    process.stderr.close()
        number = len(self.records)
        stdout, stderr = f'logs/{number:03d}.stdout', f'logs/{number:03d}.stderr'
        put(self.work / stdout, bytes(out)); put(self.work / stderr, bytes(err))
        self.records.append({'argv': argv, 'exit_code': code, 'expected': expected,
                             'stdout': stdout, 'stdout_sha256': digest(out),
                             'stderr': stderr, 'stderr_sha256': digest(err)})
        need(digest(read(self.paths[name], 64 * 1024**2)) == self.pins[name], 'tool changed after execution')
        need(code == 0 if expected == 0 else code != 0, 'unexpected command exit')
        return bytes(out), bytes(err)


def load_release(source, commands):
    module = types.ModuleType('frozen_repository_client_release')
    module.__file__ = '<verified-frozen-release>'
    exec(compile(source, module.__file__, 'exec'), module.__dict__)
    module.run = lambda argv, env=None: commands.run(argv, env=env)[0]
    return module


def metadata_check(raw, pin, acceptance_pin, accepted):
    need(isinstance(pin, str) and re.fullmatch('[0-9a-f]{64}', pin) and digest(raw) == pin,
         'external metadata checksum mismatch')
    value = decode(raw)
    need(value.get('schema_version') == 1 and type(value['schema_version']) is int and
         value.get('purpose') == 'reviewed-generic-restage-metadata' and value.get('development_only') is True and
         value.get('platform_scope') == 'generic-builder-only', 'reviewed generic metadata required')
    need(value.get('acceptance_sha256') == acceptance_pin, 'metadata belongs to different accepted inputs')
    need(re.fullmatch('[0-9a-f]{40}', value.get('source_commit', '')), 'recipe-origin source commit required')
    need(isinstance(value.get('base'), dict) and isinstance(value.get('policy'), dict),
         'missing complete base metadata or reviewed policy')
    packages = value['base'].get('packages', [])
    need(isinstance(packages, list) and packages and
         len(packages) == len(accepted['base_versions']) and
         sorted((p['name'], p['version']) for p in packages) ==
         sorted((p['name'], p['version']) for p in accepted['base_versions']),
         'full base metadata differs from accepted complete inventory')
    need(value['policy'].get('supported_models') == [], 'generic restage must not declare M2 support')
    need(set(value['policy'].get('selected_packages', [])) == ORIGINALS, 'exact four selected project packages required')
    need(set(value.get('provenance', {})) == ORIGINALS, 'complete four-package provenance required')
    role = accepted['archive_role']
    need(role in {'baseline', 'updated'}, 'explicit accepted archive role required')
    for provenance in value['provenance'].values():
        need(provenance.get('build', {}).get('execution') == ('native' if role == 'baseline' else 'synthetic'),
             'archive lineage execution label differs from accepted role')
        need(provenance.get('build', {}).get('architecture') == 'aarch64', 'provenance builder architecture differs')
    license = value.get('project_license', {})
    need(license.get('spdx') == 'MIT' and isinstance(license.get('text'), str) and
         bool(license['text'].strip()) and digest(license['text'].encode()) == license.get('sha256'),
         'complete externally reviewed project license text/hash required')
    need(not PRIVATE.search(license['text'].encode()), 'private material in purported license refused')
    return value


def restage(accepted, metadata, authority_pin, metadata_pin, sources, work, commands):
    release = load_release(sources['scripts/release/release.py'], commands)
    bundle = work / 'bundle'
    for path in (bundle, bundle / 'repo', bundle / 'provenance', bundle / 'evidence'):
        path.mkdir(mode=0o700)
    packages = []
    for row in accepted['archives']:
        data = read(row['path'])
        need(digest(data) == row['sha256'] and len(data) == row['bytes'], 'accepted archive changed before restaging')
        filename = Path(row['path']).name
        need(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._+:-]*\.pkg\.tar\.(gz|xz|zst)', filename), 'unsafe package filename')
        path = bundle / 'repo' / filename
        put(path, data)
        package = release.pkginfo(path)
        need(package['name'] == row['name'] and package['version'] == row['version'], 'accepted archive metadata mismatch')
        package.update(filename=filename, sha256=row['sha256'], provenance=f"provenance/{row['name']}.json")
        put(bundle / package['provenance'], encoded(metadata['provenance'][row['name']]))
        packages.append(package)
    need(len(packages) == 4 and {p['name'] for p in packages} == ORIGINALS, 'exact four archives; probe excluded')
    lineage = {'schema_version': 1, 'purpose': 'separate-test-signer-restaging', 'development_only': True,
               'original_B_continuity': False, 'repository_authority_sha256': authority_pin,
               'metadata_sha256': metadata_pin, 'repository_source_commit': accepted['source_commit'],
               'archive_role': accepted['archive_role'], 'input_lineage': accepted.get('lineage', {}),
               'original_signer_roles': accepted.get('signer_roles', {}),
               'original_crypto_verification': accepted['crypto_verification'],
               'archives': [{**{k: p[k] for k in ('name', 'filename', 'sha256', 'version')},
                             **{k: row[k] for k in ('original_signer', 'original_signature_sha256') if k in row}}
                            for p, row in zip(packages, accepted['archives'], strict=True)]}
    put(bundle / 'evidence' / 'lineage.json', encoded(lineage))
    put(bundle / 'base.json', encoded(metadata['base']))
    put(bundle / 'project-license.txt', metadata['project_license']['text'].encode())
    spec = {'schema_version': 1, 'synthetic': True, 'target_arch': 'aarch64',
            'release_id': 'test-restage-' + authority_pin[:16], 'repo_name': 'test-restage',
            'source_commit': metadata['source_commit'], 'policy': metadata['policy'],
            'base': {'path': 'base.json', 'sha256': release.sha(bundle / 'base.json'),
                     'snapshot_id': metadata['base']['snapshot_id']},
            'project_license': {'path': 'project-license.txt', 'sha256': release.sha(bundle / 'project-license.txt'), 'spdx': 'MIT'},
            'evidence': [{'id': 'lineage.json', 'path': 'evidence/lineage.json', 'sha256': digest(encoded(lineage))}],
            'packages': [{'artifact': {'path': 'repo/' + p['filename'], 'sha256': p['sha256']},
                          'provenance': {'path': p['provenance'], 'sha256': release.sha(bundle / p['provenance'])}} for p in packages]}
    # Perform complete dependency/provenance checks before any key generation.
    release.dependency_check(spec, packages, metadata['base'])
    for package in packages:
        release.provenance_check(package, metadata['provenance'][package['name']], package['sha256'], spec)
    put(bundle / 'spec.json', encoded(spec))
    home = work / 'signing-home'; home.mkdir(mode=0o700)
    commands.run(['gpg', '--batch', '--no-options', '--pinentry-mode', 'loopback', '--passphrase', '',
                  '--quick-generate-key', 'TEST ONLY separate repository-client restage <restage@test.invalid>',
                  'ed25519', 'sign', '1d'])
    listing = commands.run(['gpg', '--batch', '--no-options', '--with-colons', '--list-keys'])[0].decode()
    keys = [line.split(':')[9] for line in listing.splitlines() if line.startswith('fpr:')]
    need(len(keys) == 1 and re.fullmatch('[0-9A-F]{40}', keys[0]), 'one fresh TEST primary required')
    signer = keys[0]
    need(signer not in {row['fingerprint'] for row in accepted.get('signer_roles', {}).values()},
         'new TEST signer unexpectedly matches original identity')
    def sign(path):
        commands.run(['gpg', '--batch', '--no-options', '--local-user', signer, '--digest-algo', 'SHA256',
                      '--detach-sign', '--output', str(path) + '.sig', path])
    for package in packages:
        sign(bundle / 'repo' / package['filename'])
    commands.run(['repo-add', '--include-sigs', '--sign', '--key', signer,
                  bundle / 'repo' / 'test-restage.db.tar.gz', *[bundle / 'repo' / p['filename'] for p in packages]])
    if not (bundle / 'repo' / 'test-restage.files.tar.gz.sig').exists():
        sign(bundle / 'repo' / 'test-restage.files.tar.gz')
    for path in (bundle / 'repo').iterdir():
        if path.is_symlink():
            target = os.readlink(path)
            need('/' not in target and not (path.parent / target).is_symlink(), 'unexpected repo-add alias')
            data = read(path.parent / target)
            path.unlink(); put(path, data)
    manifest = {'schema_version': 1, 'release_id': spec['release_id'], 'signer': signer,
                'created_utc': datetime.now(timezone.utc).isoformat(), 'packages': packages,
                'files': release.payload_files(bundle), 'symlinks': {}}
    put(bundle / 'release.json', encoded(manifest)); sign(bundle / 'release.json')
    release.verify_release(bundle, signer, commands.env)
    public = commands.run(['gpg', '--batch', '--no-options', '--export', signer])[0]
    put(work / 'public-key.gpg', public)
    put(work / 'client.py', sources['scripts/client/client.py'])
    results = client_cases(work, signer, authority_pin, commands, sign)
    return {'signer': signer, 'namespace': 'test-restage.' + authority_pin[:16],
            'lineage': lineage, 'release_sha256': digest(read(bundle / 'release.json')),
            'release_semantics': 'PASS', 'client_cases': results,
            'new_signature_and_database_sha256': {p.name: digest(read(p)) for p in (bundle / 'repo').iterdir()
                                                  if '.pkg.tar.' not in p.name or p.name.endswith('.sig')}}


def checkpoint(work):
    path = work / 'state' / 'checkpoint.json'
    if not path.exists():
        return None
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid() and
         stat.S_IMODE(info.st_mode) == 0o600, 'private checkpoint ownership/mode required')
    return digest(read(path))


def client_cases(work, signer, pin, commands, sign):
    (work / 'state').mkdir(mode=0o700)
    namespace = 'test-restage.' + pin[:16]
    now = datetime.now(timezone.utc).replace(microsecond=0)
    utc = lambda dt: dt.strftime('%Y-%m-%dT%H:%M:%SZ')
    prefix = ['python3', '-I', work / 'client.py']
    for sequence in (1, 2):
        path = work / f'envelope-{sequence}.json'
        commands.run(prefix + ['build', '--bundle', work / 'bundle', '--namespace', namespace, '--signer', signer,
                              '--sequence', sequence, '--issued-utc', utc(now),
                              '--expires-utc', utc(now + timedelta(hours=1)), '--output', path])
        sign(path)
    changed = decode(read(work / 'envelope-2.json'))
    changed['expires_utc'] = utc(now + timedelta(minutes=30))
    put(work / 'envelope-altered.json', encoded(changed)); sign(work / 'envelope-altered.json')
    plan = [('cold-readonly', '1', False, None), ('apply-1', '1', True, None),
            ('repeat-readonly', '1', False, None), ('apply-2', '2', True, None),
            ('signed-rollback-rejected', '1', True, 'metadata sequence rollback'),
            ('signed-same-sequence-change-rejected', 'altered', True, 'same sequence has altered metadata bytes'),
            ('wrong-namespace-rejected', '2', True, 'metadata namespace/signer differs from external pin')]
    rows = []
    for name, envelope, apply, rejection in plan:
        before = checkpoint(work)
        argv = prefix + ['verify', '--bundle', work / 'bundle', '--namespace', namespace + ('.wrong' if rejection and name == 'wrong-namespace-rejected' else ''),
                         '--signer', signer, '--metadata', work / f'envelope-{envelope}.json',
                         '--signature', work / f'envelope-{envelope}.json.sig', '--public-keyring', work / 'public-key.gpg',
                         '--state-dir', work / 'state', '--minimum-sequence', 1]
        if apply:
            argv += ['--apply']
        out, err = commands.run(argv, expected='nonzero' if rejection else 0)
        after = checkpoint(work)
        if rejection:
            need(rejection in err.decode() and not out and before == after, 'wrong rejection or changed checkpoint')
        else:
            result = decode(out)
            need(result.get('stable_accepted') is False and result.get('scope') == 'development', 'wrong client scope')
            if apply:
                need(result.get('state_changed') is True and result.get('checkpoint_directory_synced') is True and
                     after is not None and before != after, 'checkpoint apply/durability not proven')
            else:
                need(result.get('state_changed') is False and before == after, 'read-only changed state')
        rows.append({'name': name, 'result': 'PASS', 'expected_rejection': rejection,
                     'checkpoint_before': before, 'checkpoint_after': after, 'command_record': len(commands.records) - 1})
    return rows


def cleanup_signer(commands, work):
    commands.teardown_started = time.monotonic()
    if (work / 'signing-home').exists():
        try:
            out = commands.run(['gpg-connect-agent', '--homedir', work / 'signing-home',
                                '--no-autostart', 'GETINFO pid', '/bye'])[0]
            matches = re.findall(rb'^D ([0-9]+)$', out, re.MULTILINE)
            need(len(matches) == 1, 'private signer agent PID not established')
            pid = int(matches[0])
            process = Path(f'/proc/{pid}')
            with (process / 'stat').open('rb') as stream:
                before = stream.read(4097)
            need(len(before) <= 4096 and b'(gpg-agent)' in before and process.stat().st_uid == os.geteuid(),
                 'private signer process identity/owner differs')
            started = before.rsplit(b')', 1)[1].split()[19]
        finally:
            commands.run(['gpgconf', '--homedir', work / 'signing-home', '--kill', 'all'])
        deadline = time.monotonic() + 3
        while Path(f'/proc/{pid}').exists():
            # A reaped-or-zombie process cannot retain a signing capability.
            state = Path(f'/proc/{pid}/stat')
            try:
                raw = state.read_bytes()
            except FileNotFoundError:
                break
            need(len(raw) <= 4096, 'unbounded signer PID record')
            fields = raw.rsplit(b')', 1)[1].split()
            if fields[19] != started:  # Original process is gone; never target a reused PID.
                break
            need(b'(gpg-agent)' in raw, 'signer PID identity changed')
            if fields[0] == b'Z':
                break
            need(time.monotonic() < deadline, 'private signer agent remains alive')
            time.sleep(0.02)


@contextmanager
def defer_cancellation():
    pending = [False]
    def remember(*_):
        pending[0] = True
    previous = {sig: signal.signal(sig, remember) for sig in (signal.SIGTERM, signal.SIGINT)}
    DEFERRED_CANCELLATION.append(pending)
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        DEFERRED_CANCELLATION.pop()
        if pending[0]:
            if DEFERRED_CANCELLATION:
                # Spawn/reap guards inside private teardown must relay the signal
                # until signer stop and directory removal both finish.
                DEFERRED_CANCELLATION[-1][0] = True
            else:
                raise KeyboardInterrupt('stage cancelled during guarded operation')


class Publication:
    """Retain the entire parent chain; publish only through its held directory FD."""
    def __init__(self, path):
        self.path, self.fds, self.root, self.created = path, [], None, False
        try:
            need(path.is_absolute() and '..' not in path.parts, 'canonical absolute output path required')
            self.fds.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY))
            for part in path.parent.parts[1:]:
                self.fds.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fds[-1]))
            info = os.fstat(self.fds[-1])
            need(info.st_uid == os.geteuid() and not stat.S_IMODE(info.st_mode) & 0o022,
                 'private owned output parent required')
            self.identities = [self.identity(os.fstat(fd)) for fd in self.fds]
        except BaseException:
            self.close()
            raise

    @staticmethod
    def identity(info):
        return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid

    def current(self):
        fresh = [os.open('/', os.O_RDONLY | os.O_DIRECTORY)]
        try:
            for part in self.path.parent.parts[1:]:
                fresh.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fresh[-1]))
            need([self.identity(os.fstat(fd)) for fd in fresh] == self.identities and
                 [self.identity(os.fstat(fd)) for fd in self.fds] == self.identities,
                 'output parent chain changed')
            if self.root is not None:
                fresh.append(os.open(self.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fresh[-1]))
                need(self.identity(os.fstat(fresh[-1])) == self.identity(os.fstat(self.root)), 'output directory replaced')
        finally:
            for fd in reversed(fresh):
                os.close(fd)

    def create(self):
        self.current()
        os.mkdir(self.path.name, mode=0o700, dir_fd=self.fds[-1])
        self.root = os.open(self.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=self.fds[-1])
        self.root_identity = self.identity(os.fstat(self.root))
        self.created = True
        self.current()

    def write(self, relative, data):
        self.current()
        parts = Path(relative).parts
        need(parts and not Path(relative).is_absolute() and all(p not in ('..', '.') for p in parts), 'unsafe publication path')
        parent = os.dup(self.root)
        try:
            for part in parts[:-1]:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=parent)
                except FileExistsError:
                    pass
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                os.close(parent); parent = child
            put(Path(parts[-1]), data, dir_fd=parent)
            os.fsync(parent)
            self.current()
        finally:
            os.close(parent)

    def remove_receipt(self):
        # Terminal close may have completed before deferred cancellation fires.
        # Recover only the same recorded output inode through the same ancestors.
        recovered = []
        root = self.root
        try:
            if root is None and self.created:
                recovered.append(os.open('/', os.O_RDONLY | os.O_DIRECTORY))
                for part in self.path.parent.parts[1:]:
                    recovered.append(os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                             dir_fd=recovered[-1]))
                need([self.identity(os.fstat(fd)) for fd in recovered] == self.identities,
                     'output ancestors changed during terminal receipt invalidation')
                recovered.append(os.open(self.path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                         dir_fd=recovered[-1]))
                root = recovered[-1]
                need(self.identity(os.fstat(root)) == self.root_identity,
                     'output replaced during terminal receipt invalidation')
            if root is None:
                return
            try:
                os.unlink('result.json', dir_fd=root)
                os.fsync(root)
            except FileNotFoundError:
                pass
            try:
                os.stat('result.json', dir_fd=root, follow_symlinks=False)
            except FileNotFoundError:
                return
            raise Refused('failed to invalidate authoritative receipt')
        finally:
            for fd in reversed(recovered):
                os.close(fd)

    def close(self):
        if self.root is not None:
            os.close(self.root)
            self.root = None
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds = []


@contextmanager
def cancellation_handlers():
    def interrupted(*_):
        raise KeyboardInterrupt('stage cancelled')
    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def execute(input_root, authority_raw, authority_sha256, metadata_raw, metadata_sha256, output, *, repo_root=ROOT):
    receipt = {'schema_version': 1, 'purpose': 'separate-test-repository-client-restage', 'status': 'NOT RUN',
               'development_only': True, 'selected_for_release': False, 'original_B_continuity': False,
               'stable_promotion': 'NOT RUN', 'production_trust': 'NOT RUN', 'published_endpoint': 'NOT RUN',
               'hardware_validation': 'NOT RUN', 'installation': 'NOT RUN', 'native_build': 'NOT RUN',
               'repository_authority_sha256': authority_sha256,
               'software_environment': {'architecture': platform.machine(), 'page_size': os.sysconf('SC_PAGE_SIZE'),
                                        'execution': 'local-bounded-private-processes'},
               'blockers': [], 'cleanup': {'status': 'NOT RUN'}}
    publication = None
    private_work = None
    try:
        need(threading.current_thread() is threading.main_thread(), 'bounded stage requires main-thread signal handling')
        accepted = gate.accept(Path(input_root), authority_raw, authority_sha256)
        receipt['repository_input_acceptance'] = 'PASS'
        if metadata_raw is None:
            receipt['blockers'] = ['missing full base depend/provides/conflict/file-ownership metadata',
                                   'missing reviewed generic protected/coordinated policy',
                                   'missing receipt-bound four-package provenance/source/license records']
            return receipt
        metadata = metadata_check(metadata_raw, metadata_sha256, authority_sha256, accepted)
        sources = {name: read(Path(repo_root) / name) for name in SOURCES}
        need(all(digest(sources[name]) == pin for name, pin in SOURCES.items()), 'frozen release/client source drift')
        output = Path(output).absolute()
        need(not output.exists() and not output.is_symlink(), 'output already exists')
        need(not output.is_relative_to(Path(input_root).absolute()), 'output must be outside accepted input inventory')
        publication = Publication(output)
        public = {}
        temporary = tempfile.TemporaryDirectory(prefix='repository-client-restage-')
        work = Path(temporary.name); work.chmod(0o700)
        private_work, commands = work, None
        try:
            commands = Commands(work)
            receipt.update(restage(accepted, metadata, authority_sha256, metadata_sha256, sources, work, commands))
            for path in work.rglob('*'):
                rel = path.relative_to(work).as_posix()
                if path.is_file() and (rel.startswith(('bundle/', 'logs/')) or re.fullmatch(r'envelope-[a-z0-9-]+\.json(?:\.sig)?|public-key\.gpg', rel)):
                    public[rel] = read(path)
            need(sum(map(len, public.values())) <= TOTAL_LIMIT and len(public) <= 512, 'public output bound exceeded')
            # Recheck externally accepted input inventory before completing work.
            gate.accept(Path(input_root), authority_raw, authority_sha256)
        finally:
            with defer_cancellation():
                stopped = False
                try:
                    if commands is not None:
                        cleanup_signer(commands, work)
                    stopped = True
                    # Include teardown logs without exporting the private home.
                    if commands is not None:
                        for path in (work / 'logs').iterdir():
                            public[path.relative_to(work).as_posix()] = read(path)
                finally:
                    if commands is not None:
                        receipt['commands'] = commands.records
                        receipt['tool_sha256'] = commands.pins
                    temporary.cleanup()
                    absent = not work.exists()
                    receipt['cleanup'] = {'status': 'PASS' if stopped and absent else 'FAIL',
                                          'private_state_absent': absent,
                                          'signer_agent_stop': 'PASS' if stopped else 'UNCONFIRMED'}
        need(sum(map(len, public.values())) <= TOTAL_LIMIT and len(public) <= 512, 'final public output bound exceeded')
        need(not any(PRIVATE.search(data) for data in public.values()), 'private material in public output refused')
        need(not work.exists(), 'private temporary state remains')
        publication.create()
        for name, data in sorted(public.items()):
            publication.write(name, data)
        receipt.update(status='PASS', source_sha256=SOURCES, metadata_sha256=metadata_sha256,
                       public_files={name: {'sha256': digest(data), 'bytes': len(data)} for name, data in public.items()})
        publication.write('result.json', encoded(receipt))
        expected = {**public, 'result.json': encoded(receipt)}
        gate.tree(output, expected)
        for name, data in expected.items():
            need(read(output / name) == data, 'published output changed or incomplete')
        publication.current()
        os.fsync(publication.root)
        os.fsync(publication.fds[-1])
        # Closing is part of the caught transaction, before the successful return.
        # A cancellation after descriptors close uses recorded-inode recovery.
        with defer_cancellation():
            publication.close()
        return receipt
    except (Exception, KeyboardInterrupt) as error:
        receipt.update(status='FAIL', blockers=[f'{type(error).__name__}: {error}'])
        if private_work is not None and receipt['cleanup']['status'] != 'PASS':
            receipt['cleanup'] = {'status': 'FAIL', 'private_state_absent': not private_work.exists(),
                                  'signer_agent_stop': 'UNCONFIRMED'}
        # No successful receipt survives cancellation or an output write failure.
        if publication is not None:
            with defer_cancellation():
                publication.remove_receipt()
        return receipt
    finally:
        if publication is not None and (publication.root is not None or publication.fds):
            with defer_cancellation():
                # Retry failed-path invalidation before releasing the held FD.
                if receipt['status'] != 'PASS':
                    publication.remove_receipt()
                publication.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', required=True)
    parser.add_argument('--authority', required=True)
    parser.add_argument('--authority-sha256', required=True)
    parser.add_argument('--metadata')
    parser.add_argument('--metadata-sha256')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    with cancellation_handlers():
        result = execute(Path(args.inputs), read(args.authority), args.authority_sha256,
                         read(args.metadata) if args.metadata else None, args.metadata_sha256, Path(args.output))
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
