#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Copy one verified local repository generation into fresh offline storage."""
import argparse
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile

sys.dont_write_bytecode = True
SCRIPTS = Path(__file__).resolve().parents[2]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


p = module('endpoint_copy_recipient', SCRIPTS / 'client/endpoint.py')
e, c = p.e, p.c
k = module('endpoint_copy_publication', SCRIPTS / 'release/offline_kit.py')


def directory_held(path, fd):
    e.managed_directory(path)
    actual, held = path.stat(follow_symlinks=False), os.fstat(fd)
    c.need((actual.st_dev, actual.st_ino) == (held.st_dev, held.st_ino),
           'copy directory path changed')


def copy_generation(generation, expected_generation, public_keyring, signer, output, *, apply=False):
    source, output = e.canonical(generation), e.canonical(output)
    c.need(source != output and not output.is_relative_to(source) and not source.is_relative_to(output),
           'source and output must be disjoint')
    c.need(not os.path.lexists(output), 'copy output already exists')
    e.managed_directory(source); e.managed_directory(output.parent)
    source_fd, parent_fd = c.directory(source), None
    try:
        parent_fd = c.directory(output.parent)
        fcntl.flock(source_fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        verified = p.verify(source, expected_generation, public_keyring, signer)
        raw = c.read_member(source_fd, 'export.json')
        c.need(c.digest(raw) == expected_generation, 'source inventory changed after verification')
        plan = c.decode(raw)
        files = dict(plan['files'], **{'export.json': expected_generation})
        total = sum((source / name).stat(follow_symlinks=False).st_size for name in files)
        c.need(total <= e.MAX_BYTES, 'copy byte bound exceeded')
        result = dict(verified, status='planned-local-endpoint-copy', output=str(output),
                      files=len(files), bytes=total, symlinks=len(plan['symlinks']), output_created=False)
        directory_held(source, source_fd); directory_held(output.parent, parent_fd)
        if not apply:
            return result
        with tempfile.TemporaryDirectory(prefix='.endpoint-copy-', dir=output.parent) as temporary:
            staging = Path(temporary) / 'generation'; staging.mkdir(mode=0o700)
            parents = {parent for name in files.keys() | plan['symlinks'].keys()
                       for parent in Path(name).parents if str(parent) != '.'}
            for parent in sorted(parents, key=lambda path: (len(path.parts), str(path))):
                (staging / parent).mkdir(mode=0o700)
            copied = 0
            for name, digest in sorted(files.items()):
                e.copy_file(source / name, staging / name, digest)
                copied += (staging / name).stat().st_size
                c.need(copied <= e.MAX_BYTES, 'copy byte bound exceeded')
            c.need(copied == total, 'source sizes changed during copy')
            for name, target in sorted(plan['symlinks'].items()):
                (staging / name).symlink_to(target)
            staged = p.verify(staging, expected_generation, public_keyring, signer)
            c.need(staged == verified, 'copied endpoint verification differs')
            c.need(p.verify(source, expected_generation, public_keyring, signer) == verified,
                   'source endpoint changed during copy')
            directory_held(source, source_fd); directory_held(output.parent, parent_fd)
            for path in sorted((staging, *(staging / parent for parent in parents)),
                               key=lambda path: len(path.parts), reverse=True):
                e.sync_directory(path)
            info = staging.stat(follow_symlinks=False)
            k.publish(staging, parent_fd, output, (info.st_dev, info.st_ino))
        final = p.verify(output, expected_generation, public_keyring, signer)
        c.need(final == verified, 'published endpoint verification differs; inspect retained output')
        directory_held(output.parent, parent_fd)
        return dict(result, status='copied-local-endpoint', output_created=True)
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
        os.close(source_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('generation', 'expected-generation', 'public-keyring', 'signer', 'output'):
        parser.add_argument('--' + name, required=True)
    parser.add_argument('--apply', action='store_true', help='Copy into the absent output; default verifies and previews')
    args = parser.parse_args(argv)
    try:
        result = copy_generation(args.generation, args.expected_generation, args.public_keyring,
                                 args.signer, args.output, apply=args.apply)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (c.Error, k.c.Error, e.r.Error, OSError, ValueError, TypeError, KeyError) as error:
        print(json.dumps(dict(status='endpoint-copy-refused', errors=[str(error)]), sort_keys=True), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
