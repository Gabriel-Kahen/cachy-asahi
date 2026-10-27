#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 cachy-asahi contributors
"""Assemble/inspect a portable DEVELOPMENT kit using the existing offline client.

The kit inventory is a transport receipt, pinned externally by SHA-256. It grants
no trust. Receiver signer, namespace, sequence floor and checkpoint are external.
No fetching, signing, checkpoint update or installation is provided.
"""
import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parents[2]
RUNTIME = ('scripts/release/offline_kit.py', 'scripts/client/client.py',
           'scripts/release/source_delivery.py')
loader = importlib.util.spec_from_file_location('offline_kit_client', ROOT / RUNTIME[1])
c = importlib.util.module_from_spec(loader)
loader.loader.exec_module(c)
RECEIPT = 'kit.json'
MAX_MEMBERS = c.MAX_FILES + 32


def public_packets(raw):
    """Accept only finite binary public-export packets; never copy secret packets.

    Cryptographic/key identity validation remains exclusively with client.GPG.
    Armor, partial lengths and packets outside a public export are refused.
    """
    position, primary = 0, 0
    while position < len(raw):
        header = raw[position]; position += 1
        c.need(header & 128, 'binary gpg --export public keyring required')
        if header & 64:
            tag = header & 63
            c.need(position < len(raw), 'truncated public packet')
            length = raw[position]; position += 1
            if 192 <= length < 224:
                c.need(position < len(raw), 'truncated public packet')
                length = ((length - 192) << 8) + raw[position] + 192; position += 1
            elif length == 255:
                c.need(position + 4 <= len(raw), 'truncated public packet')
                length = int.from_bytes(raw[position:position + 4], 'big'); position += 4
            else:
                c.need(length < 192, 'partial public packets refused')
        else:
            tag, kind = (header >> 2) & 15, header & 3
            c.need(kind != 3, 'indeterminate public packet refused')
            width = (1, 2, 4)[kind]
            c.need(position + width <= len(raw), 'truncated public packet')
            length = int.from_bytes(raw[position:position + width], 'big'); position += width
        c.need(tag in {2, 6, 13, 14, 17}, 'non-public/secret key packet refused')
        c.need(length > 0 and position + length <= len(raw), 'truncated public packet')
        primary += tag == 6
        position += length
    c.need(primary > 0, 'public primary key required')


def inventory(path):
    """Reject foreign nodes; hash only bounded regular files and internal aliases."""
    files, links, directories, total, count = {}, {}, set(), 0, 0
    fd = c.directory(path)
    try:
        def scan_error(error):
            raise error
        for parent, dirs, names in os.walk(path, followlinks=False, onerror=scan_error):
            for name in dirs + names:
                item = Path(parent) / name
                relative = item.relative_to(path).as_posix(); c.relative(relative)
                info = item.lstat(); count += 1
                c.need(count <= MAX_MEMBERS, 'kit member bound exceeded')
                if stat.S_ISLNK(info.st_mode):
                    target = os.readlink(item)
                    c.need(target not in {'', '.', '..'} and '/' not in target and '\\' not in target,
                           'escaping kit alias refused')
                    links[relative] = target
                elif stat.S_ISDIR(info.st_mode):
                    directories.add(relative)
                    continue
                else:
                    pin, size = c.hash_member(fd, relative)
                    files[relative] = pin; total += size
                    c.need(total <= c.MAX_TOTAL, 'kit total byte bound exceeded')
        parents = {parent.as_posix() for name in files.keys() | links.keys()
                   for parent in Path(name).parents if parent.as_posix() != '.'}
        c.need(directories == parents, 'empty or unrecorded kit directory refused')
        for name, target in links.items():
            c.need((Path(name).parent / target).as_posix() in files, 'kit alias target missing')
        return files, links
    finally:
        os.close(fd)


def arguments(base, args):
    return argparse.Namespace(bundle=str(base / 'release'), metadata=str(base / 'development.json'),
        signature=str(base / 'development.json.sig'), public_keyring=str(base / 'public.gpg'),
        namespace=args.namespace, signer=args.signer, minimum_sequence=args.minimum_sequence,
        state_dir=args.state_dir, apply=False)


def lock_and_sources(bundle, release_sha256, lock_evidence):
    c.need(type(lock_evidence) is str and c.NAME.fullmatch(lock_evidence), 'lock evidence ID required')
    root = c.directory(bundle)
    try:
        _, release, raw = c.describe(root)
        c.need(c.digest(raw) == release_sha256, 'release changed after authentication')
        spec_raw = c.read_member(root, 'spec.json')
        c.need(c.digest(spec_raw) == release['files']['spec.json'], 'spec changed after authentication')
        spec = c.decode(spec_raw)
        rows = [row for row in spec.get('evidence', []) if row.get('id') == lock_evidence]
        target = 'evidence/' + lock_evidence
        c.need(len(rows) == 1 and target in release['files'] and rows[0]['sha256'] == release['files'][target],
               'required lock is absent from signed release evidence')
        raw = c.read_member(root, target)
        c.need(c.digest(raw) == release['files'][target], 'lock changed after authentication')
        c.decode(raw)  # Opaque bounded JSON object, not an installation authorization.
        index = c.source_associations(root, spec, release)
        source = 'CHECKED_DECLARED_ASSOCIATIONS' if index is not None else 'NOT_DECLARED'
        return release, {'path': 'release/' + target, 'sha256': c.digest(raw)}, source
    finally:
        os.close(root)


def inspect(args):
    base = c.absolute(args.kit)
    raw = c.read_path(base / RECEIPT, c.MAX_JSON)
    c.need(c.HEX.fullmatch(args.kit_sha256 or '') and c.digest(raw) == args.kit_sha256,
           'kit receipt differs from independently supplied SHA-256')
    value = c.decode(raw)
    c.need(set(value) == {'schema_version', 'purpose', 'files', 'symlinks', 'lock_evidence'} and
           type(value['schema_version']) is int and value['schema_version'] == 1 and
           value['purpose'] == 'portable-development-kit', 'unsupported kit receipt')
    files, links = inventory(base)
    files.pop(RECEIPT, None)
    c.need(files == value['files'] and links == value['symlinks'], 'kit incomplete, changed or contains unrecorded files')
    c.need(all(name in files for name in (*RUNTIME, 'receiver-license.txt')), 'kit receiver runtime/license missing')
    public_packets(c.read_path(base / 'public.gpg', c.MAX_KEYRING))
    verified = c.verify(arguments(base, args))
    _, lock, source = lock_and_sources(base / 'release', verified['release_sha256'], value['lock_evidence'])
    # Recheck the complete transferred view after signature/source inspection.
    after_files, after_links = inventory(base)
    c.need(after_files.pop(RECEIPT, None) == args.kit_sha256 and after_files == files and after_links == links,
           'kit changed during inspection')
    return dict(verified, status='inspected-portable-development-kit', kit_sha256=args.kit_sha256,
        lock=lock, source_delivery=source, source_delivery_gap=source == 'NOT_DECLARED',
        source_completeness_accepted=False, legal_acceptance=False, packages_installed=False,
        transaction_authorized=False, hardware_validation=False, native_validation=False,
        runtime_paths={name: str(base / name) for name in ('release', 'development.json', 'development.json.sig', 'public.gpg')})


def publish(staging, parent, output, inspected_inode):
    """Linux atomic fresh-directory publication; no path-based child writes."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, 'renameat2', None)
    c.need(rename is not None, 'Linux renameat2 required; no weaker publication fallback')
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    source = c.directory(staging.parent)
    try:
        before = os.stat(staging.name, dir_fd=source, follow_symlinks=False)
        c.need(stat.S_ISDIR(before.st_mode) and (before.st_dev, before.st_ino) == inspected_inode,
               'inspected staging directory identity changed')
        # RENAME_NOREPLACE refuses all preexisting destinations, including symlinks.
        if rename(source, os.fsencode(staging.name), parent, os.fsencode(output.name), 1):
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        after = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        c.need((after.st_dev, after.st_ino) == (before.st_dev, before.st_ino), 'published kit identity changed')
        visible = c.directory(output.parent)
        try:
            a, b = os.fstat(visible), os.fstat(parent)
            c.need((a.st_dev, a.st_ino) == (b.st_dev, b.st_ino), 'kit parent path changed')
        finally:
            os.close(visible)
        os.fsync(parent)
    finally:
        os.close(source)


def assemble(args):
    output, bundle = c.absolute(args.output), c.absolute(args.bundle)
    c.need(not output.exists() and not output.is_symlink(), 'fresh kit destination required')
    c.need(not output.is_relative_to(bundle), 'kit destination must stay outside producer bundle')
    # Never copy an arbitrary producer directory or a signing home.
    keyring = c.read_path(args.public_keyring, c.MAX_KEYRING); public_packets(keyring)
    checked = c.verify(argparse.Namespace(**{**vars(args), 'apply': False}))
    release, _, _ = lock_and_sources(bundle, checked['release_sha256'], args.lock_evidence)
    parent = c.directory(output.parent)
    try:
        info = os.fstat(parent)
        c.need(info.st_uid == os.geteuid() and not info.st_mode & 0o022,
               'kit parent must be caller-owned without group/world writes')
        # Work privately; publish only an entirely inspected kit.
        with tempfile.TemporaryDirectory(prefix='.offline-kit-', dir=output.parent) as temporary:
            staging = Path(temporary) / 'kit'; staging.mkdir(mode=0o700)
            created = staging.stat(); inspected_inode = (created.st_dev, created.st_ino)
            def write(name, raw):
                path = staging / name; path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with path.open('xb') as stream:
                    stream.write(raw); stream.flush(); os.fsync(stream.fileno())
                path.chmod(0o444)
            root = c.directory(bundle)
            try:
                for name, pin in {**release['files'], 'release.json': checked['release_sha256']}.items():
                    c.reference(name, pin)
                    path = staging / 'release' / name; path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                    actual, _ = c.hash_member(root, name, snapshot=path)
                    c.need(actual == pin, 'producer payload changed during assembly'); path.chmod(0o444)
                write('release/release.json.sig', c.read_member(root, 'release.json.sig', c.MAX_SIGNATURE))
            finally:
                os.close(root)
            for name, target in release.get('symlinks', {}).items():
                c.relative(name)
                c.need('/' not in target and target not in {'', '.', '..'} and '\\' not in target,
                       'unsafe producer alias')
                c.need((Path(name).parent / target).as_posix() in release['files'], 'producer alias target absent')
                path = staging / 'release' / name; path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                path.symlink_to(target)
            write('development.json', c.read_path(args.metadata, c.MAX_JSON))
            write('development.json.sig', c.read_path(args.signature, c.MAX_SIGNATURE))
            write('public.gpg', keyring)
            write('receiver-license.txt', c.read_path(ROOT / 'LICENSE', c.MAX_JSON))
            for name in RUNTIME:
                write(name, c.read_path(ROOT / name, c.MAX_JSON))
            files, links = inventory(staging)
            receipt = dict(schema_version=1, purpose='portable-development-kit', files=files,
                           symlinks=links, lock_evidence=args.lock_evidence)
            raw = c.encoded(receipt); write(RECEIPT, raw)
            inspect_args = argparse.Namespace(**{**vars(args), 'kit': str(staging), 'kit_sha256': c.digest(raw)})
            result = inspect(inspect_args)
            c.need(result['metadata_sha256'] == checked['metadata_sha256'], 'producer metadata changed during assembly')
            publish(staging, parent, output, inspected_inode)
    finally:
        os.close(parent)
    return dict(status='assembled-portable-development-kit', path=str(output), kit_sha256=c.digest(raw),
                release_sha256=checked['release_sha256'], source_delivery=result['source_delivery'],
                source_delivery_gap=result['source_delivery_gap'], packages_installed=False,
                stable_accepted=False, source_completeness_accepted=False,
                receiver_sha256={name: files[name] for name in RUNTIME})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    build = commands.add_parser('assemble'); check = commands.add_parser('inspect')
    for command in (build, check):
        for name in ('namespace', 'signer', 'state-dir'):
            command.add_argument('--' + name, required=True)
        command.add_argument('--minimum-sequence', required=True, type=int)
    for name in ('bundle', 'metadata', 'signature', 'public-keyring', 'lock-evidence', 'output'):
        build.add_argument('--' + name, required=True)
    check.add_argument('--kit', required=True); check.add_argument('--kit-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(assemble(args) if args.command == 'assemble' else inspect(args), sort_keys=True))
        return 0
    except (c.Error, OSError, ValueError, TypeError, KeyError, OverflowError, subprocess.SubprocessError) as error:
        print('offline kit refused: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
