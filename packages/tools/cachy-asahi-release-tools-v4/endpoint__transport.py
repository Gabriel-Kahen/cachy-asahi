#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stream a verified endpoint through a canonical regular-files-only tar."""
import argparse
import contextlib
import ctypes
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DEPENDENCIES = {'scripts/release/endpoint_copy_v1/copy_endpoint.py', 'scripts/client/endpoint.py',
    'scripts/client/client.py', 'scripts/release/export_repository.py', 'scripts/release/release.py',
    'scripts/release/source_delivery.py', 'scripts/release/offline_kit.py'}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def pinned_copy():
    pins = json.loads((HERE / 'dependencies.json').read_bytes())
    need(pins['schema_version'] == 1 and set(pins['files']) == DEPENDENCIES, 'finite dependency pins required')
    for name, row in pins['files'].items():
        path = ROOT / name
        need(path == path.resolve() and path.is_file() and not path.is_symlink(), 'canonical dependency file required')
        raw = path.read_bytes()
        need(len(raw) == row['bytes'] and hashlib.sha256(raw).hexdigest() == row['sha256'],
             'dependency changed: ' + name)
    path = ROOT / 'scripts/release/endpoint_copy_v1/copy_endpoint.py'
    spec = importlib.util.spec_from_file_location('transport_endpoint_copy', path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


try:
    copy = pinned_copy()
except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
    if __name__ == '__main__':
        print(json.dumps(dict(status='endpoint-transport-refused', errors=[str(error)])), file=sys.stderr)
        sys.exit(1)
    raise
p, e, c, k = copy.p, copy.e, copy.c, copy.k
CHUNK = 64 * 1024
MAX_BYTES, MAX_FILES = e.MAX_BYTES, e.MAX_FILES
MAX_ARCHIVE = MAX_BYTES + (MAX_FILES + 1) * 1024 + 10240
MAX_SECONDS = 1800


def tick(deadline):
    need(time.monotonic() < deadline, 'transport deadline exhausted')


def header(name, size):
    c.relative(name)
    need(type(size) is int and 0 <= size <= min(MAX_BYTES, 8 * 1024**3 - 1), 'USTAR file size bound')
    node = tarfile.TarInfo(name); node.size = size; node.mode = 0o644
    return node.tobuf(format=tarfile.USTAR_FORMAT, encoding='utf-8', errors='strict')


def read_exact(stream, size, deadline):
    need(0 <= size <= c.MAX_JSON, 'bounded header/inventory read required')
    raw = bytearray()
    while len(raw) < size:
        tick(deadline)
        block = stream.read(min(CHUNK, size - len(raw)))
        need(block, 'truncated transport archive')
        raw.extend(block)
    return bytes(raw)


def read_header(stream, name, deadline):
    raw = read_exact(stream, 512, deadline)
    node = tarfile.TarInfo.frombuf(raw, 'utf-8', 'strict')
    need(node.type == tarfile.REGTYPE and node.name == name and not node.pax_headers and not node.sparse,
         'unexpected, nonregular or out-of-order archive member')
    need(raw == header(name, node.size), 'noncanonical archive header or mode')
    return node


def transfer(stream, output, size, expected, deadline):
    digest, remaining = hashlib.sha256(), size
    while remaining:
        tick(deadline)
        raw = stream.read(min(CHUNK, remaining))
        need(raw, 'truncated file body')
        remaining -= len(raw); digest.update(raw)
        if output is not None:
            output.write(raw)
    need(digest.hexdigest() == expected, 'file payload SHA-256 mismatch')


def hash_stream(stream, maximum, deadline):
    digest, size = hashlib.sha256(), 0
    while True:
        tick(deadline)
        raw = stream.read(min(CHUNK, maximum - size + 1))
        if not raw:
            return digest.hexdigest(), size
        size += len(raw); need(size <= maximum, 'archive byte bound exceeded'); digest.update(raw)


@contextlib.contextmanager
def source_archive(path):
    path = e.canonical(path); e.regular(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
             and not info.st_mode & 0o022 and 0 < info.st_size <= MAX_ARCHIVE, 'unsafe archive file or size')
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        with os.fdopen(os.dup(fd), 'rb') as stream:
            yield path, fd, info, stream
    finally:
        os.close(fd)


def file_held(path, fd, before):
    e.regular(path)
    need(c.identity(os.fstat(fd)) == c.identity(before) == c.identity(path.stat(follow_symlinks=False)),
         'held archive file changed or replaced')


def output_parent(output, source):
    output = e.canonical(output)
    need(not os.path.lexists(output), 'output already exists')
    need(output != source and not output.is_relative_to(source) and not source.is_relative_to(output),
         'source and output must be disjoint')
    e.managed_directory(output.parent)
    return output


def publish_file(staging, parent, output, identity):
    # Existing offline_kit.publish no-replace pattern, for a regular file rather than a directory.
    libc = ctypes.CDLL(None, use_errno=True); rename = getattr(libc, 'renameat2', None)
    need(rename is not None, 'Linux renameat2 required')
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    fd = c.directory(staging.parent)
    try:
        before = os.stat(staging.name, dir_fd=fd, follow_symlinks=False)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             (before.st_dev, before.st_ino) == identity, 'inspected archive identity changed')
        if rename(fd, os.fsencode(staging.name), parent, os.fsencode(output.name), 1):
            error = ctypes.get_errno(); raise OSError(error, os.strerror(error))
        after = os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        need((after.st_dev, after.st_ino) == identity, 'published archive identity changed')
        copy.directory_held(output.parent, parent); os.fsync(parent)
    finally:
        os.close(fd)


def pack(generation, expected_generation, public_keyring, signer, output):
    deadline = time.monotonic() + MAX_SECONDS
    generation = e.canonical(generation); e.managed_directory(generation)
    output = output_parent(output, generation)
    source, parent = c.directory(generation), None
    try:
        parent = c.directory(output.parent); fcntl.flock(source, fcntl.LOCK_SH | fcntl.LOCK_NB)
        verified = p.verify(generation, expected_generation, public_keyring, signer)
        raw = c.read_member(source, 'export.json'); need(c.digest(raw) == expected_generation, 'inventory changed')
        plan = c.decode(raw); files = dict(plan['files'], **{'export.json': expected_generation})
        need(len(files) <= MAX_FILES and sorted(files)[0] == 'export.json', 'transport member bound/order')
        # Preflight representability and total bytes before writing a temporary archive.
        sizes = {}
        for name in sorted(files):
            with c.member(source, name) as fd:
                sizes[name] = os.fstat(fd).st_size; header(name, sizes[name])
        total = sum(sizes.values()); need(total <= MAX_BYTES, 'transport payload byte bound')
        with tempfile.TemporaryDirectory(prefix='.endpoint-pack-', dir=output.parent) as temporary:
            staging = Path(temporary) / 'endpoint.tar'
            with staging.open('x+b') as archive:
                for name in sorted(files):
                    tick(deadline)
                    with c.member(source, name) as fd:
                        before = os.fstat(fd); need(before.st_size == sizes[name], 'source size changed')
                        archive.write(header(name, before.st_size))
                        with os.fdopen(os.dup(fd), 'rb') as stream:
                            transfer(stream, archive, before.st_size, files[name], deadline)
                        need(c.identity(os.fstat(fd)) == c.identity(before), 'source file changed during pack')
                        archive.write(b'\0' * (-before.st_size % 512))
                archive.write(b'\0' * 1024); archive.flush(); os.fsync(archive.fileno())
                archive.seek(0); checksum, size = hash_stream(archive, MAX_ARCHIVE, deadline)
                os.fchmod(archive.fileno(), 0o444); info = os.fstat(archive.fileno())
                need(p.verify(generation, expected_generation, public_keyring, signer) == verified,
                     'source changed during pack')
                copy.directory_held(generation, source); copy.directory_held(output.parent, parent)
                publish_file(staging, parent, output, (info.st_dev, info.st_ino))
                final = os.fstat(archive.fileno())
                need(c.identity(final)[:-1] == c.identity(info)[:-1], 'archive changed during publication')
                file_held(output, archive.fileno(), final)
            return dict(verified, status='packed-endpoint-archive', output=str(output),
                        archive_sha256=checksum, archive_bytes=size, bytes=total, files=len(files),
                        aliases=len(plan['symlinks']), output_created=True)
    finally:
        if parent is not None: os.close(parent)
        os.close(source)


def unpack(archive, archive_sha256, expected_generation, public_keyring, signer, output):
    deadline = time.monotonic() + MAX_SECONDS
    need(isinstance(archive_sha256, str) and c.HEX.fullmatch(archive_sha256), 'archive SHA-256 required')
    need(isinstance(expected_generation, str) and c.HEX.fullmatch(expected_generation), 'generation SHA-256 required')
    with source_archive(archive) as (archive, fd, initial, stream):
        output = output_parent(output, archive)
        digest, archive_bytes = hash_stream(stream, MAX_ARCHIVE, deadline)
        need(digest == archive_sha256 and archive_bytes == initial.st_size, 'archive SHA-256/size mismatch')
        file_held(archive, fd, initial); stream.seek(0)
        node = read_header(stream, 'export.json', deadline)
        need(node.size <= c.MAX_JSON, 'endpoint inventory JSON bound')
        raw = read_exact(stream, node.size, deadline)
        need(c.digest(raw) == expected_generation, 'endpoint inventory SHA-256 mismatch')
        plan = c.decode(raw); need(e.encoded(plan) == raw, 'noncanonical endpoint inventory')
        p.plan_check(plan, c.fingerprint(signer))
        need(not any(read_exact(stream, -node.size % 512, deadline)), 'nonzero tar padding')
        files = dict(plan['files'], **{'export.json': expected_generation})
        need(len(files) <= MAX_FILES and sorted(files)[0] == 'export.json', 'transport member bound/order')
        total = node.size; need(total <= MAX_BYTES, 'transport payload byte bound')
        parent = c.directory(output.parent)
        try:
            with tempfile.TemporaryDirectory(prefix='.endpoint-unpack-', dir=output.parent) as temporary:
                staging = Path(temporary) / 'generation'; staging.mkdir(mode=0o700)
                parents = {path for name in files.keys() | plan['symlinks'].keys()
                           for path in Path(name).parents if str(path) != '.'}
                for path in sorted(parents, key=lambda path: (len(path.parts), str(path))):
                    (staging / path).mkdir(mode=0o700)
                with (staging / 'export.json').open('xb') as target:
                    target.write(raw); target.flush(); os.fchmod(target.fileno(), 0o444); os.fsync(target.fileno())
                for name in sorted(set(files) - {'export.json'}):
                    node = read_header(stream, name, deadline); total += node.size
                    need(total <= MAX_BYTES, 'transport payload byte bound')
                    with (staging / name).open('xb') as target:
                        transfer(stream, target, node.size, files[name], deadline)
                        target.flush(); os.fchmod(target.fileno(), 0o444); os.fsync(target.fileno())
                    need(not any(read_exact(stream, -node.size % 512, deadline)), 'nonzero tar padding')
                need(read_exact(stream, 1024, deadline) == b'\0' * 1024 and not stream.read(1),
                     'noncanonical archive end or extra members/trailing bytes')
                for name, target in sorted(plan['symlinks'].items()):
                    need(str(Path(name).parent / target) in files, 'alias target not retained')
                    (staging / name).symlink_to(target)
                verified = p.verify(staging, expected_generation, public_keyring, signer)
                file_held(archive, fd, initial); copy.directory_held(output.parent, parent)
                for path in sorted((staging, *(staging / path for path in parents)),
                                   key=lambda path: len(path.parts), reverse=True):
                    e.sync_directory(path)
                info = staging.stat(follow_symlinks=False)
                k.publish(staging, parent, output, (info.st_dev, info.st_ino))
            need(p.verify(output, expected_generation, public_keyring, signer) == verified,
                 'published endpoint differs; inspect retained output')
            file_held(archive, fd, initial); copy.directory_held(output.parent, parent)
            return dict(verified, status='unpacked-endpoint-archive', output=str(output),
                        archive_sha256=digest, archive_bytes=archive_bytes, bytes=total,
                        files=len(files), aliases=len(plan['symlinks']), output_created=True)
        finally:
            os.close(parent)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('pack', 'unpack'):
        command = commands.add_parser(name)
        for field in ('expected-generation', 'public-keyring', 'signer', 'output'):
            command.add_argument('--' + field, required=True)
        if name == 'pack': command.add_argument('--generation', required=True)
        else:
            command.add_argument('--archive', required=True); command.add_argument('--archive-sha256', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'pack':
            result = pack(args.generation, args.expected_generation, args.public_keyring, args.signer, args.output)
        else:
            result = unpack(args.archive, args.archive_sha256, args.expected_generation,
                            args.public_keyring, args.signer, args.output)
        print(json.dumps(result, sort_keys=True)); return 0
    except (c.Error, k.c.Error, e.r.Error, OSError, ValueError, TypeError, KeyError,
            RecursionError, tarfile.TarError, UnicodeError) as error:
        print(json.dumps(dict(status='endpoint-transport-refused', errors=[str(error)])), file=sys.stderr); return 1


if __name__ == '__main__':
    sys.exit(main())
