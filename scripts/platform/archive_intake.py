#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Portable checkout entrypoint for the byte-preserved strict archive intake.

Tracked files need no private modes. Every use first copies the complete pinned
graph into a fresh 0700 runtime and restores its declared private leaf modes.
"""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import types

BASE = Path(__file__).resolve().parent
BUNDLE_SHA = '8c3838da1bfd6d5e7683d3634ffec9d14a5ff6b07966b15c2b06dde5319c4f0d'
ENGINE_SHA = '57b555b2e93534ab0f38dd2f9f7775e00481ea333a9cc102f8bd517ee68c582d'
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')


def need(value, reason):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'),
                       ensure_ascii=True, allow_nan=False) + '\n').encode()


def decode(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, 'duplicate-json-key')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'nonfinite-json'))


def read_pinned(parent, relative, digest, maximum):
    """No-follow source traversal; checkout mode bits convey no authenticity."""
    parts = relative.split('/')
    need(parts and all(x not in ('', '.', '..') for x in parts), 'source-relative-path')
    held = []
    try:
        fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        held.append(fd)
        for part in parts[:-1]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            held.append(fd)
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=fd)
        held.append(leaf)
        before = os.fstat(leaf)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             0 < before.st_size <= maximum, 'source-ordinary-file-bound')
        raw = bytearray()
        while len(raw) <= maximum:
            part = os.read(leaf, min(65536, maximum + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        named = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
        need(all(getattr(before, k) == getattr(os.fstat(leaf), k) == getattr(named, k)
                 for k in FIELDS), 'source-drift')
        need(len(raw) == before.st_size and sha(raw) == digest, 'source-pin')
        return bytes(raw)
    finally:
        failure = sys.exc_info()[1]
        for fd in reversed(held):
            try:
                os.close(fd)
            except BaseException as later:
                if failure is None or (isinstance(failure, Exception) and not isinstance(later, Exception)):
                    later.__cause__ = failure
                    failure = later
                else:
                    failure.add_note('portable-source-close: ' + type(later).__name__)
        if failure is not None:
            raise failure


def pinned_file(path, digest, maximum=1024**2):
    path = Path(path).absolute()
    need(path == path.resolve(), 'input-symlink-or-noncanonical-path')
    return read_pinned(path.parent, path.name, digest, maximum)


@contextmanager
def runtime(private_parent=None):
    """Stage the fixed graph before importing it; retire the private copy on exit."""
    need(sys.exc_info() == (None, None, None), 'normal-entry-required')
    manifest = decode(read_pinned(BASE, 'archive_intake_bundle.json', BUNDLE_SHA, 65536))
    need(type(manifest) is dict and set(manifest) == {'schema_version', 'files'} and
         type(manifest['schema_version']) is int and manifest['schema_version'] == 1,
         'bundle-manifest-schema')
    rows = manifest['files']
    need(type(rows) is list and len(rows) == 48 and
         sum(row['size'] for row in rows) <= 2 * 1024**2 and
         len({row['path'] for row in rows}) == 48, 'bundle-source-closure')
    parent = Path(private_parent or tempfile.gettempdir()).absolute()
    need(parent == parent.resolve(), 'private-parent-symlink')
    root = Path(tempfile.mkdtemp(prefix='archive-intake-runtime-', dir=parent))
    original = None
    failure = None
    try:
        original = root.lstat()
        need(stat.S_ISDIR(original.st_mode) and original.st_uid == os.getuid() and
             stat.S_IMODE(original.st_mode) == 0o700, 'private-runtime-root-state')
        for row in rows:
            need(type(row) is dict and set(row) == {'path', 'size', 'sha256', 'private_mode'} and
                 type(row['private_mode']) is int and row['private_mode'] in (0o600, 0o644),
                 'bundle-leaf-schema')
            raw = read_pinned(BASE, 'archive_intake_bundle/' + row['path'], row['sha256'], row['size'])
            target = root / row['path']
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with target.open('xb') as stream:
                stream.write(raw)
                os.fchmod(stream.fileno(), row['private_mode'])
        # mkdir(mode) is affected by umask, so explicitly restore every private dir.
        for directory in root.rglob('*'):
            if directory.is_dir():
                directory.chmod(0o700)
        raw = read_pinned(root, 'engine.py', ENGINE_SHA, 1024**2)
        engine = types.ModuleType('_private_archive_intake_engine')
        engine.__file__ = str(root / 'engine.py')
        exec(compile(raw, engine.__file__, 'exec'), engine.__dict__)
        yield engine
    except BaseException as error:
        failure = error
    finally:
        try:
            now = root.lstat()
            need(original is not None and (now.st_dev, now.st_ino, now.st_uid) ==
                 (original.st_dev, original.st_ino, os.getuid()) and
                 stat.S_ISDIR(now.st_mode) and stat.S_IMODE(now.st_mode) == 0o700,
                 'private-runtime-root-drift')
            shutil.rmtree(root)
        except BaseException as later:
            if failure is None or (isinstance(failure, Exception) and not isinstance(later, Exception)):
                later.__cause__ = failure
                failure = later
            else:
                failure.add_note('portable-runtime-cleanup: ' + type(later).__name__)
        if failure is not None:
            raise failure


@contextmanager
def prepared(selection, authentication, spool_parent, seconds=1200):
    with runtime(spool_parent) as engine:
        with engine.prepared(selection, authentication, spool_parent, seconds) as session:
            session['_portable_engine'] = engine
            yield session


def assemble(session, destination, epoch=0):
    return session['_portable_engine'].assemble(session, destination, epoch)


def run(selection, authentication, output, epoch=0, seconds=1200):
    """Commit a receipt only after both spool and staged runtime cleanup succeed."""
    output = Path(output).absolute()
    need(output.parent == output.parent.resolve(), 'output-parent-symlink')
    os.mkdir(output, 0o700)
    (output / 'INCOMPLETE.json').write_bytes(encoded(dict(status='INCOMPLETE_NOT_ACCEPTED')))
    with prepared(selection, authentication, output, seconds) as session:
        with (output / 'staging.tar').open('xb') as destination:
            result = assemble(session, destination, epoch)
            destination.flush()
            os.fsync(destination.fileno())
        counts = {p['identity']['name']: dict(nodes=len(p['nodes']), files=len(p['bodies']))
                  for p in session['packages']}
    receipt = dict(status='PASS_EXACT_SELECTED_ARCHIVES_TO_STAGING_ONLY',
                   selection_sha256=sha(encoded(selection)), authentication_input_sha256=sha(encoded(authentication)),
                   bundle=result['bundle'], manifest_sha256=result['manifest_sha256'], packages=counts,
                   archive_authentication=result['manifest']['archive_authentication'],
                   separation=result['manifest']['inert_separation'], io=result['io'],
                   portable_source_inputs=dict(entrypoint_sha256=sha(Path(__file__).read_bytes()),
                                               graph_manifest_sha256=BUNDLE_SHA, engine_sha256=ENGINE_SHA),
                   spool_cleanup='PASS', private_runtime_cleanup='PASS', full261_accepted=False,
                   license_redistribution_accepted=False, independent_owner_trust_accepted=False,
                   native_image_build=False, boot_installation_hardware_release_accepted=False)
    (output / 'assembly.json').write_bytes(encoded(result['manifest']))
    with (output / 'receipt.pending.json').open('xb') as pending:
        pending.write(encoded(receipt))
        pending.flush()
        os.fsync(pending.fileno())
    (output / 'INCOMPLETE.json').unlink()
    os.rename(output / 'receipt.pending.json', output / 'receipt.json')
    return receipt


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('selection', 'selection-sha256', 'authentication', 'authentication-sha256', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--epoch', type=int, default=0)
    parser.add_argument('--seconds', type=int, default=1200)
    args = parser.parse_args()
    selection = decode(pinned_file(args.selection, args.selection_sha256))
    authentication = decode(pinned_file(args.authentication, args.authentication_sha256))
    print(json.dumps(run(selection, authentication, args.output, args.epoch, args.seconds), sort_keys=True))


if __name__ == '__main__':
    main()
