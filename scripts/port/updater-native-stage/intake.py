#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fetch the four pinned read-only builder carriers in a credential-only job step."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
MANIFEST_SHA256 = 'ef260324c8b7ea4f339f7644fac4ee2d95df635744653d44b498a36fdbe57a58'
SECRET = 'CACHY_NATIVE349_INPUTS_SSH_PRIVATE_KEY'
REMOTE = 'git@github.com:Gabriel-Kahen/cachy-asahi-ci-inputs.git'
HOST_KEY = 'github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl\n'
DEPLOY_KEY = [b'256', b'SHA256:6gnCZBWA+I9mccJV/YzywHoefkGrpuKBHU0dVcgqn7k']
GIT = ['/usr/bin/git', '--no-replace-objects', '-c', 'core.hooksPath=/dev/null',
       '-c', 'maintenance.auto=false', '-c', 'gc.auto=0', '-c', 'pack.threads=1',
       '-c', 'protocol.allow=never', '-c', 'protocol.ssh.allow=always',
       '-c', 'fetch.fsckObjects=true']
REFS = {'native349-r1': (183, 182), 'native623-base-r1': (22, 22),
        'native623-r1': (22, 14), 'native-updater-442-r1': (6, 6)}
OID = re.compile('[0-9a-f]{40}')
SHA256 = re.compile('[0-9a-f]{64}')
MEMBER = re.compile(r'(?:packages|alarm-cache|extension)/([A-Za-z0-9._+@:~-]+\.pkg\.tar\.xz(?:\.sig)?)')


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def private_directory(path):
    info = path.lstat()
    need(path.is_absolute() and path.resolve(strict=True) == path
         and stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() == os.geteuid() > 0
         and stat.S_IMODE(info.st_mode) == 0o700, 'private-directory')


def manifest():
    path = HERE / 'retained-inputs.json'
    with path.open('rb') as stream:
        raw = stream.read(64 * 1024 + 1)
    need(len(raw) <= 64 * 1024 and hashlib.sha256(raw).hexdigest() == MANIFEST_SHA256,
         'manifest-pin')
    data = json.loads(raw)
    need(data['schema_version'] == 1 and data['profiles'].keys() == REFS.keys(), 'manifest-schema')
    names, size = set(), 0
    for ref, profile in data['profiles'].items():
        expected_files, selected = REFS[ref]
        need(OID.fullmatch(profile['commit']) and OID.fullmatch(profile['tree'])
             and profile['tree_files'] == expected_files
             and len(profile['selected']) == selected, 'manifest-profile')
        for path, pin in profile['selected'].items():
            match = MEMBER.fullmatch(path)
            need(match and match[1] not in names and type(pin['bytes']) is int
                 and 0 < pin['bytes'] <= 100 * 1024**2 and SHA256.fullmatch(pin['sha256']),
                 'manifest-member')
            names.add(match[1])
            size += pin['bytes']
    need(len(names) == 224 and size == 632237043, 'manifest-closure')
    return data['profiles']


def clean_environment(scratch):
    return {'PATH': '/usr/bin:/bin', 'HOME': str(scratch), 'LC_ALL': 'C',
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
            'GIT_NO_LAZY_FETCH': '1', 'GIT_TERMINAL_PROMPT': '0',
            'GIT_SSH_VARIANT': 'ssh'}


def command(argv, env, seconds=20, output=subprocess.PIPE):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=output,
                            stderr=subprocess.DEVNULL, env=env, timeout=seconds, check=True)
    need(result.stdout is None or len(result.stdout) <= 64 * 1024, 'git-metadata-bound')
    return result.stdout


def fetch(git, env, profiles, secret, scratch):
    need(64 <= len(secret) <= 32768 and secret.startswith('-----BEGIN OPENSSH PRIVATE KEY-----\n')
         and secret.rstrip().endswith('-----END OPENSSH PRIVATE KEY-----'), 'deploy-key-format')
    with tempfile.TemporaryDirectory(prefix='credential-', dir=scratch) as directory:
        key, known = Path(directory) / 'identity', Path(directory) / 'known_hosts'
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        with os.fdopen(os.open(key, flags, 0o600), 'w') as stream:
            stream.write(secret.rstrip() + '\n')
        known.write_text(HOST_KEY, encoding='ascii')
        observed = command(['/usr/bin/ssh-keygen', '-lf', str(key), '-E', 'sha256'], env).split()
        need(observed[:2] == DEPLOY_KEY, 'deploy-key-fingerprint')
        ssh = ['/usr/bin/ssh', '-q', '-F', '/dev/null', '-i', str(key), '-o', 'BatchMode=yes',
               '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'UserKnownHostsFile=' + str(known), '-o', 'GlobalKnownHostsFile=/dev/null',
               '-o', 'HostKeyAlgorithms=ssh-ed25519', '-o', 'ClearAllForwardings=yes',
               '-o', 'ConnectionAttempts=1', '-o', 'ConnectTimeout=15']
        refs = [f'refs/heads/{ref}:refs/heads/{ref}' for ref in profiles]
        command(git + ['fetch', '--quiet', '--depth=1', '--no-tags', REMOTE, *refs],
                dict(env, GIT_SSH_COMMAND=shlex.join(ssh)), seconds=185,
                output=subprocess.DEVNULL)


def selected_blobs(git, env, ref, profile):
    tip = command(git + ['rev-parse', '--verify', f'refs/heads/{ref}^{{commit}}'], env)
    commit = profile['commit']
    need(tip == (commit + '\n').encode(), 'carrier-commit')
    header = command(git + ['cat-file', 'commit', commit], env).split(b'\n\n', 1)[0].splitlines()
    tree = profile['tree']
    need(header[0] == ('tree ' + tree).encode()
         and not any(line.startswith(b'parent ') for line in header), 'carrier-parentless-tree')
    raw = command(git + ['ls-tree', '-r', '-l', '-z', '--full-tree', tree], env)
    rows = raw.split(b'\x00')
    need(rows.pop() == b'' and len(rows) == profile['tree_files'], 'carrier-tree-size')
    selected = {}
    for row in rows:
        meta, name = row.split(b'\t', 1)
        mode, kind, oid, size = meta.decode('ascii').split()
        need(mode == '100644' and kind == 'blob' and OID.fullmatch(oid), 'carrier-ordinary-blob')
        path = name.decode('ascii')
        if path in profile['selected']:
            need(size == str(profile['selected'][path]['bytes']), 'carrier-blob-size')
            selected[path] = oid
    need(selected.keys() == profile['selected'].keys(), 'carrier-selected-closure')
    return selected


def materialize(git, env, profiles, output):
    for ref, profile in profiles.items():
        for path, oid in selected_blobs(git, env, ref, profile).items():
            pin = profile['selected'][path]
            with (output / path.rsplit('/', 1)[1]).open('x+b') as file:
                command(git + ['cat-file', 'blob', oid], env, seconds=30, output=file)
                need(file.tell() == pin['bytes'], 'carrier-copied-size')
                file.seek(0)
                need(hashlib.file_digest(file, 'sha256').hexdigest() == pin['sha256'],
                     'carrier-copied-digest')


def intake(control, secret):
    profiles = manifest()
    private_directory(control)
    scratch, final = control / 'retained-fetch', control / 'retained-cache'
    need(not os.path.lexists(final), 'retained-cache-exists')
    scratch.mkdir(mode=0o700)
    try:
        env = clean_environment(scratch)
        git = GIT + ['--git-dir=' + str(scratch / 'store.git')]
        command(git + ['init', '--quiet', '--bare', '--template=', '--object-format=sha1'], env)
        fetch(git, env, profiles, secret, scratch)
        del secret
        staged = scratch / 'inputs'
        staged.mkdir(mode=0o700)
        materialize(git, env, profiles, staged)
        need(len(list(staged.iterdir())) == 224, 'retained-copied-count')
        staged.rename(final)
    finally:
        shutil.rmtree(scratch)


def retire(control):
    private_directory(control)
    need(shutil.rmtree.avoids_symlink_attacks, 'safe-retirement-required')
    for name in ('retained-cache', 'retained-fetch'):
        path = control / name
        if os.path.lexists(path):
            private_directory(path)
            shutil.rmtree(path)
        need(not os.path.lexists(path), 'retained-path-not-retired')


def interrupted(_signal, _frame):
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('fetch', 'retire'))
    parser.add_argument('--control', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    signal.signal(signal.SIGTERM, interrupted)
    try:
        need(args.control.parent == Path('/tmp')
             and args.control.name.startswith('cachy-updater-workflow.'), 'workflow-control-path')
        if args.mode == 'fetch':
            intake(args.control, os.environ.pop(SECRET, ''))
        else:
            need(SECRET not in os.environ, 'retirement-must-be-credential-free')
            retire(args.control)
    except (Exception, KeyboardInterrupt):
        print(json.dumps({'retained_inputs': 'FAIL', 'operation': args.mode}))
        return 1
    print(json.dumps({'retained_inputs': 'PASS', 'operation': args.mode}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
