#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Authenticate both sides of a staged development install and print-resolve it in private ALPM storage."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HERE = Path(__file__).absolute().parent
inventory = load('install_inventory', HERE / 'verify.py')
release = load('staging_release', HERE.parent / 'release.py')
client = inventory.client
need = client.need
IDENTITY = ('name', 'version', 'arch', 'depend', 'provides', 'conflict', 'replaces')
REPOSITORY_SUFFIXES = ('.db.tar.gz', '.db.tar.gz.sig', '.files.tar.gz', '.files.tar.gz.sig')


@contextmanager
def directory(path):
    root = client.directory(path)
    try:
        yield root
    finally:
        os.close(root)


def command(argv, *, env, contents=None):
    result = subprocess.run(argv, input=contents, stdin=subprocess.DEVNULL if contents is None else None,
                            env=env, capture_output=True, timeout=60)
    need(result.returncode == 0, f'{argv[0]} failed: {result.stderr.decode(errors="replace")[:512].strip()}')
    return result.stdout


def pinned_read(path, pin):
    raw = client.read_path(path, client.MAX_JSON)
    need(client.HEX.fullmatch(pin or '') and client.digest(raw) == pin, 'base archive lock SHA-256 mismatch')
    return client.decode(raw)


def base_rows(document, declaration):
    rows = document.get('packages')
    inventory.inventory(rows, 'base archive lock')
    need(type(document.get('schema_version')) is int and document['schema_version'] == 1 and
         document.get('snapshot_id') == declaration['snapshot_id'], 'base archive lock snapshot differs from the kit')
    names, expected, size = set(), {}, 0
    for row in rows:
        name, version, arch = (row[key] for key in ('name', 'version', 'arch'))
        filename = row.get('filename')
        need(filename == f'{name}-{version}-{arch}.pkg.tar.xz' and filename not in names,
             'unsafe or duplicate pinned ALARM package filename')
        names.add(filename)
        validate_archive(row, client.MAX_FILE)
        row = dict(row, depend=row['depends'], conflict=row['conflicts'])
        expected[name] = {key: row[key] for key in IDENTITY}
        size += row['size'] + row['signature_size']
    rootfs = document['rootfs']
    validate_archive(rootfs, client.MAX_TOTAL)
    need(size + rootfs['size'] + rootfs['signature_size'] <= client.MAX_TOTAL,
         'base package and rootfs byte budget exceeded')
    declared = {row['name']: {key: row[key] for key in IDENTITY} for row in declaration['packages']}
    need(expected == declared, 'base archive package metadata differs from the signed kit declaration')
    return rows, size


def validate_archive(row, maximum):
    filename = row['filename']
    need(isinstance(filename, str) and Path(filename).name == filename, 'archive filename must be a basename')
    client.reference(filename, row['sha256'])
    client.reference(filename + '.sig', row['signature_sha256'])
    for field, bound in (('size', maximum), ('signature_size', client.MAX_SIGNATURE)):
        need(type(row[field]) is int and 0 < row[field] <= bound, 'invalid archive/signature size')


def verified_archive(root, row, work, verifier):
    filename = row['filename']
    snapshot = work / 'archive'
    try:
        with client.member(root, filename) as fd, snapshot.open('xb') as output:
            before = os.fstat(fd)
            need(before.st_size == row['size'], 'archive size mismatch: ' + filename)
            digest, remaining = hashlib.sha256(), before.st_size
            while remaining:
                chunk = os.read(fd, min(remaining, 1024**2))
                need(chunk, 'short archive read: ' + filename)
                output.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
            need(client.identity(os.fstat(fd)) == client.identity(before) and digest.hexdigest() == row['sha256'],
                 'archive SHA-256 mismatch or concurrent change: ' + filename)
        signature = client.read_member(root, filename + '.sig', client.MAX_SIGNATURE)
        need(len(signature) == row['signature_size'] and client.digest(signature) == row['signature_sha256'],
             'archive signature bytes differ: ' + filename)
        verifier.verify(snapshot, signature)
        return signature
    finally:
        snapshot.unlink(missing_ok=True)


def certified_indexes(root, repo, files, directory, verifier):
    for suffix in REPOSITORY_SUFFIXES[::2]:
        name = repo + suffix
        data = directory / name
        observed, _ = client.hash_member(root, name, snapshot=data)
        need(observed == files[name], 'repository index SHA-256 mismatch: ' + name)
        signature = client.read_member(root, name + '.sig', client.MAX_SIGNATURE)
        need(client.digest(signature) == files[name + '.sig'], 'repository index signature SHA-256 mismatch: ' + name)
        verifier.verify(data, signature)
        (directory / (name + '.sig')).write_bytes(signature)


def base_keyring(root, lock, environment):
    keyfiles = lock.get('keyring_files')
    need(type(keyfiles) is list and {row['filename'] for row in keyfiles} ==
         {'archlinuxarm.gpg', 'archlinuxarm-trusted', 'archlinuxarm-revoked'} and len(keyfiles) == 3,
         'exact pinned ALARM public key files required')
    checked = {}
    for row in keyfiles:
        name = row['filename']
        raw = client.read_member(root, name, client.MAX_KEYRING)
        need(len(raw) == row['size'] and client.digest(raw) == row['sha256'], 'ALARM key file differs: ' + name)
        checked[name] = raw
    keyring = command(['gpg', '--batch', '--no-options', '--no-autostart', '--dearmor'], env=environment,
                      contents=checked['archlinuxarm.gpg'])
    inventory.kit.public_packets(keyring)
    return keyring


def inspect_base(args, lock, declaration, work, env, now):
    rows, size = base_rows(lock, declaration)
    signer = client.fingerprint(args.base_signer)
    keyring = client.read_path(args.base_public_keyring, client.MAX_KEYRING)
    inventory.kit.public_packets(keyring)
    verification = client.Verifier(work, keyring, signer, now)
    indexes = work / 'indexes'
    indexes.mkdir(mode=0o700)
    with directory(args.base_repository) as base, directory(Path(args.base_repository) / 'repo') as repo:
        receipt_path = work / 'staging.json'
        raw = client.read_member(base, 'staging.json')
        need(client.HEX.fullmatch(args.base_receipt_sha256 or '') and client.digest(raw) == args.base_receipt_sha256,
             'base staging receipt SHA-256 mismatch')
        receipt_path.write_bytes(raw)
        verification.verify(receipt_path, client.read_member(base, 'staging.json.sig', client.MAX_SIGNATURE))
        receipt = client.decode(raw)
        original_signer = client.fingerprint(lock['signer_fingerprint'])
        versions = ''.join(f'{row["name"]} {row["version"]}\n' for row in sorted(rows, key=lambda row: row['name']))
        need(receipt['lock_sha256'] == args.base_lock_sha256 and receipt['repository_test_signer'] == signer and
             receipt['original_signer'] == original_signer and receipt['package_count'] == len(rows) and
             receipt['archive_and_signature_bytes'] == size and
             receipt['inventory_sha256'] == client.digest(versions.encode('ascii')),
             'base staging receipt differs from the selected archive lock')
        files = receipt['repository_files']
        db_names = [name.removesuffix('.db.tar.gz') for name in files if name.endswith('.db.tar.gz')]
        need(len(db_names) == 1, 'one signed base repository database required')
        name = release.valid_name(db_names[0])
        need(set(files) == {name + suffix for suffix in REPOSITORY_SUFFIXES}, 'incomplete base database pin map')
        certified_indexes(repo, name, files, indexes, verification)
        official_work = work / 'official'
        official_work.mkdir(mode=0o700)
        official = client.Verifier(official_work, base_keyring(base, lock, env), original_signer, now)
        for row in rows:
            signature = verified_archive(repo, row, official_work, official)
            (indexes / (row['filename'] + '.sig')).write_bytes(signature)
        verified_archive(base, lock['rootfs'], official_work, official)
    release.database_check(indexes, name, [dict(row, depend=row['depends'], conflict=row['conflicts']) for row in rows])
    return name, indexes, keyring


def inspect_overlay(args, checked, work, now):
    with directory(Path(args.kit) / 'release') as root:
        manifest = inventory.read_bound(root, 'release.json', checked['release_sha256'])
        spec = inventory.read_bound(root, 'spec.json', manifest['files']['spec.json'])
        base = inventory.read_bound(root, 'base.json', checked['base_sha256'], limit=inventory.MAX_BASE_BYTES)
        name = release.valid_name(spec['repo_name'])
        overlay = manifest['packages']
        keyring = client.read_path(Path(args.kit) / 'public.gpg', client.MAX_KEYRING)
        inventory.kit.public_packets(keyring)
        verification = client.Verifier(work, keyring, client.fingerprint(args.signer), now)
        indexes = work / 'indexes'
        indexes.mkdir(mode=0o700)
        with directory(Path(args.kit) / 'release' / 'repo') as repo:
            pins = {name + suffix: manifest['files']['repo/' + name + suffix] for suffix in REPOSITORY_SUFFIXES}
            certified_indexes(repo, name, pins, indexes, verification)
            for row in overlay:
                filename = row['filename'] + '.sig'
                raw = client.read_member(repo, filename, client.MAX_SIGNATURE)
                need(client.digest(raw) == manifest['files']['repo/' + filename], 'changed overlay package signature')
                (indexes / filename).write_bytes(raw)
        release.database_check(indexes, name, overlay)
    return (name, indexes, keyring), base, {row['name'] for row in overlay}


def resolve(work, env, repos, signers, expected, overlay_names):
    for path in ('db/local', 'db/sync', 'root', 'cache'):
        (work / path).mkdir(parents=True, mode=0o700)
    config = work / 'pacman.conf'
    config.write_text('[options]\nArchitecture = aarch64\nSigLevel = Required TrustedOnly\n' +
                      ''.join(f'[{name}]\nServer = {index.as_uri()}\n' for name, index, _ in repos))
    for name, indexes, keyring in repos:
        command(['gpg', '--batch', '--no-options', '--import'], env=env, contents=keyring)
        for suffix in ('', '.sig'):
            shutil.copyfile(indexes / (name + '.db.tar.gz' + suffix), work / 'db/sync' / (name + '.db' + suffix))
    command(['gpg', '--batch', '--no-options', '--import-ownertrust'], env=env,
            contents=''.join(signer + ':6:\n' for signer in signers).encode('ascii'))
    origins = {name: repos[0][0] if name in overlay_names else repos[1][0] for name in expected}
    targets = [f'{origins[name]}/{name}' for name in sorted(expected)]
    argv = ['pacman', '--config', str(config), '--root', str(work / 'root'), '--dbpath', str(work / 'db'),
            '--gpgdir', env['GNUPGHOME'], '--cachedir', str(work / 'cache'), '--logfile', str(work / 'pacman.log'),
            '--sync', '--print', '--print-format', '%n %v %r', '--', *targets]
    plan = command(argv, env=env).decode('ascii').splitlines()
    wanted = [f'{name} {version} {origins[name]}' for name, version in expected.items()]
    need(sorted(plan) == sorted(wanted), 'pacman resolution differs from the pinned target inventory or repository origin')
    need(not list((work / 'root').iterdir()) and {item.name for item in (work / 'db/local').iterdir()} <= {'ALPM_DB_VERSION'},
         'resolution changed the scratch root or installed inventory')
    return client.digest(('\n'.join(sorted(plan)) + '\n').encode('ascii'))


def preflight(args):
    checked = inventory.verify(args)
    expected = inventory.target_lock(args.target_lock, args.target_lock_sha256)
    lock = pinned_read(args.base_lock, args.base_lock_sha256)
    signers = [client.fingerprint(signer) for signer in (args.signer, args.base_signer)]
    package_signer = client.fingerprint(lock['signer_fingerprint'])
    need(len({*signers, package_signer}) == 3, 'base, overlay and ALARM package trust identities must be distinct')
    with tempfile.TemporaryDirectory(prefix='cachy-asahi-install-preflight-') as temporary:
        work = Path(temporary)
        for role in ('base', 'overlay', 'trust'):
            (work / role).mkdir(mode=0o700)
        env = {'PATH': os.defpath, 'HOME': str(work), 'GNUPGHOME': str(work / 'trust'), 'LC_ALL': 'C'}
        now = datetime.now(timezone.utc)
        try:
            overlay, declaration, names = inspect_overlay(args, checked, work / 'overlay', now)
            base = inspect_base(args, lock, declaration, work / 'base', env, now)
            need(overlay[0] != base[0], 'base and overlay repository names must be distinct')
            plan = resolve(work, env, (overlay, base), signers, expected, names)
        finally:
            command(['gpgconf', '--homedir', env['GNUPGHOME'], '--kill', 'all'], env=env)
    return dict(checked, status='verified-offline-install-preflight', base_archives_authenticated=True,
                base_rootfs_authenticated=True, base_lock_sha256=args.base_lock_sha256,
                base_receipt_sha256=args.base_receipt_sha256, base_signer=signers[1], base_package_signer=package_signer,
                pacman_plan_sha256=plan, pacman_siglevel='Required TrustedOnly')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('kit', 'kit-sha256', 'namespace', 'signer', 'state-dir', 'target-lock', 'target-lock-sha256',
                 'base-repository', 'base-lock', 'base-lock-sha256', 'base-receipt-sha256', 'base-signer',
                 'base-public-keyring'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--minimum-sequence', type=int, required=True)
    try:
        result = preflight(parser.parse_args(argv))
    except (client.Error, release.Error, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as exc:
        print(f'refused: {exc}', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
