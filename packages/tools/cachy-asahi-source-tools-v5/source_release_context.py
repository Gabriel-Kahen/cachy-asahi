#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Materialize and verify a complete offline release context set atomically."""
import argparse
import ctypes
import errno
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tarfile
import tempfile

MANIFEST = 'release-context-set.json'
FIELDS = {'schema_version', 'purpose', 'mirror_sha256', 'mirror_bytes', 'release_sha256',
    'release_id', 'package_count', 'packages', 'synthetic', 'actual_selectors_state',
    'legal_acceptance', 'corresponding_source_completeness', 'native_build', 'installation', 'hardware', 'release'}


def installed_helpers():
    directory = Path(__file__).resolve().parent
    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value); return value
    return (load('release_context_catalog', directory/'source_mirror_catalog.py'),
            load('release_context_consumer', directory.parent/'build/mirror_consumer.py'))


def helpers(deps, catalog_module, consumer_module):
    if catalog_module is None or consumer_module is None:
        catalog, consumer = installed_helpers()
        catalog_module = catalog if catalog_module is None else catalog_module
        consumer_module = consumer if consumer_module is None else consumer_module
    return (consumer_module.dependencies() if deps is None else deps, catalog_module, consumer_module)


def context_path(index, selector, mirror):
    # No name-keyed collapse: each ordered selected identity gets its own path.
    return 'contexts/' + str(index).zfill(4) + '-' + mirror.digest(mirror.encoded(selector))


def context_cost(prepared, consumer, mirror):
    """Compute the frozen consumer's exact output cost before writing it."""
    bodies = prepared['bodies']; selection = dict(prepared['selection'])
    selection['files'] = {name: dict(sha256=mirror.digest(raw), bytes=len(raw), mode=f'{consumer.file_mode(name):04o}')
                          for name, raw in sorted(bodies.items())}
    dirs = set(prepared['directories'])
    dirs.update(str(p) for name in list(dirs) for p in Path(name).parents if str(p) != '.')
    dirs.update(str(p) for name in bodies for p in Path(name).parents if str(p) != '.')
    selection['directories'] = sorted(dirs)
    return len(mirror.encoded(selection)) + sum(map(len, bodies.values())), len(bodies)+1, len(dirs)+1


def bound_context(path, row, selector, mirror_sha256, release_sha256, consumer, deps):
    mirror = deps['mirror']; source = deps['shared'][0]
    verified = consumer.verify_context(path, row['selection_sha256'], deps)
    raw = source.local_read(path, 'selection.json', source.MAX_JSON)
    source.need(mirror.digest(raw) == source.sha(row['selection_sha256']), 'set context selection pin differs')
    selection = source.decode(raw)
    identity = dict(name=selector['package'], version=selector['version'], arch=selector['arch'],
                    sha256=selector['package_sha256'])
    source.need(verified['package'] == selection['package'] == identity
        and selection['mirror_sha256'] == mirror_sha256 and selection['release_sha256'] == release_sha256
        and selection['recipe_sha256'] == selector['recipe_sha256']
        and selection['srcinfo_sha256'] == selector['srcinfo_sha256']
        and selection['profile'] == selector['source_profile'], 'context is not the exact selected release package')
    return selection, raw


def inventory(root, expected_files, expected_dirs, source):
    """Exact private, nonaliased set namespace; child bodies are already verified."""
    found_files, found_dirs = set(), set()
    def walk(fd, prefix=''):
        directory = os.fstat(fd)
        source.need(directory.st_uid == os.getuid() and stat.S_IMODE(directory.st_mode) == 0o700,
                    'private owned release set directory required')
        for leaf in os.listdir(fd):
            name = prefix + leaf; info = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                source.need(name in expected_dirs, 'unexpected release set directory')
                found_dirs.add(name)
                child = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    opened = os.fstat(child)
                    source.need((info.st_dev, info.st_ino) == (opened.st_dev, opened.st_ino), 'set directory replaced')
                    walk(child, name + '/')
                finally:
                    os.close(child)
            else:
                source.need(name in expected_files and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and info.st_uid == os.getuid()
                    and (info.st_size, stat.S_IMODE(info.st_mode)) == expected_files[name],
                    'unexpected or unsafe release set file')
                found_files.add(name)
    fd = source.directory(root)
    try:
        walk(fd)
    finally:
        os.close(fd)
    source.need(found_files == set(expected_files) and found_dirs == expected_dirs, 'release set inventory differs')


def receipt(manifest, manifest_sha256, status):
    return dict(status=status, manifest_sha256=manifest_sha256, mirror_sha256=manifest['mirror_sha256'],
        release_sha256=manifest['release_sha256'], package_count=manifest['package_count'], contexts=manifest['packages'],
        actual_selectors='ALL_NULL', native_build='NOT_RUN', hardware='NOT_RUN', release='NOT_ADMITTED')


def verify_release_context(root, manifest_sha256, deps=None, catalog_module=None, consumer_module=None):
    deps, catalog, consumer = helpers(deps, catalog_module, consumer_module)
    mirror = deps['mirror']; source = deps['shared'][0]; root = Path(root).absolute()
    source.need(root.anchor == '/' and '..' not in root.parts, 'release set path alias refused')
    raw = source.local_read(root, MANIFEST, source.MAX_JSON)
    source.need(mirror.digest(raw) == source.sha(manifest_sha256), 'release set manifest checksum mismatch')
    manifest = source.decode(raw)
    source.need(set(manifest) == FIELDS and type(manifest['schema_version']) is int and manifest['schema_version'] == 1
        and manifest['purpose'] == 'release-context-set' and manifest['actual_selectors_state'] == 'ALL_NULL'
        and manifest['legal_acceptance'] is False and manifest['corresponding_source_completeness'] == 'NOT_ASSERTED'
        and all(manifest[key] == 'NOT_RUN' for key in ('native_build', 'installation', 'hardware'))
        and manifest['release'] == 'NOT_ADMITTED', 'release set schema or evidence boundary differs')
    mirror_raw = source.local_read(root, 'mirror.tar', mirror.MAX_MIRROR)
    source.need(type(manifest['mirror_bytes']) is int and len(mirror_raw) == manifest['mirror_bytes'], 'retained mirror size differs')
    selected = catalog.catalog(mirror_raw, manifest['mirror_sha256'], manifest['release_sha256'])
    rows = manifest['packages']
    source.need(type(rows) is list and type(manifest['package_count']) is int
        and len(rows) == manifest['package_count'] == len(selected['packages'])
        and manifest['release_id'] == selected['release_id'] and manifest['synthetic'] is selected['synthetic'],
        'complete selected release catalog required')
    expected_files = {MANIFEST: (len(raw), 0o400), 'mirror.tar': (len(mirror_raw), 0o400)}
    expected_dirs = {'contexts'}; total_bytes = total_files = total_dirs = 0
    for index, (row, selector) in enumerate(zip(rows, selected['packages'])):
        source.need(type(row) is dict and set(row) == {'selector', 'context', 'selection_sha256'}
            and row['selector'] == selector and row['context'] == context_path(index, selector, mirror),
            'ordered complete context identity/path set differs')
        selection, selection_raw = bound_context(root/row['context'], row, selector,
            manifest['mirror_sha256'], manifest['release_sha256'], consumer, deps)
        base = row['context']; expected_dirs.add(base)
        expected_dirs.update(base+'/'+name for name in selection['directories'])
        expected_files[base+'/selection.json'] = (len(selection_raw), 0o400)
        for name, ref in selection['files'].items():
            expected_files[base+'/'+name] = (ref['bytes'], consumer.file_mode(name))
        total_bytes += len(selection_raw) + sum(ref['bytes'] for ref in selection['files'].values())
        total_files += len(selection['files'])+1; total_dirs += len(selection['directories'])+1
    source.need(total_bytes <= mirror.MAX_TOTAL and total_files <= mirror.MAX_FILES and total_dirs <= mirror.MAX_FILES,
                'release context aggregate exceeds existing context bounds')
    inventory(root, expected_files, expected_dirs, source)
    return receipt(manifest, manifest_sha256, 'VERIFIED_RELEASE_CONTEXT_SET')


def publish_no_replace(parent, staging, output):
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(parent, os.fsencode(staging), parent, os.fsencode(output), 1):
        number = ctypes.get_errno()
        if number == errno.EEXIST:
            raise ValueError('fresh absent release set output required')
        raise OSError(number, os.strerror(number))


def materialize_release(raw, mirror_sha256, release_sha256, output, deps=None, catalog_module=None, consumer_module=None):
    deps, catalog, consumer = helpers(deps, catalog_module, consumer_module)
    mirror = deps['mirror']; source = deps['shared'][0]
    selected = catalog.catalog(raw, mirror_sha256, release_sha256)  # full auth before any output
    output = Path(output).absolute()
    source.need(output.anchor == '/' and '..' not in output.parts and output.name not in ('', '.', '..'), 'canonical fresh output required')
    parent = source.directory(output.parent); staging = None; held = None; primary = None
    try:
        parent_info = os.fstat(parent)
        source.need(parent_info.st_uid == os.getuid() and not stat.S_IMODE(parent_info.st_mode) & 0o022,
                    'owned non-writable-by-others output parent required')
        try:
            os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError('fresh absent release set output required')
        staging = Path(tempfile.mkdtemp(prefix='.release-context-', dir=output.parent))
        held = staging.lstat(); (staging/'contexts').mkdir(mode=0o700)
        rows = []; total_bytes = total_files = total_dirs = 0
        for index, selector in enumerate(selected['packages']):
            prepared = consumer.prepare(raw, mirror_sha256, release_sha256,
                *(selector[key] for key in ('package', 'version', 'arch', 'package_sha256', 'recipe_sha256', 'srcinfo_sha256')), deps)
            size, files, dirs = context_cost(prepared, consumer, mirror)
            source.need(total_bytes+size <= mirror.MAX_TOTAL and total_files+files <= mirror.MAX_FILES
                and total_dirs+dirs <= mirror.MAX_FILES, 'release context aggregate exceeds existing context bounds')
            destination = context_path(index, selector, mirror)
            result = consumer.materialize(prepared, staging/destination, deps)
            row = dict(selector=selector, context=destination, selection_sha256=result['selection_sha256'])
            selection, selection_raw = bound_context(staging/destination, row, selector,
                mirror_sha256, release_sha256, consumer, deps)
            source.need(size == len(selection_raw)+sum(ref['bytes'] for ref in selection['files'].values()),
                        'trusted context output cost differs')
            rows.append(row); total_bytes += size; total_files += files; total_dirs += dirs
        manifest = dict(schema_version=1, purpose='release-context-set', mirror_sha256=mirror_sha256,
            mirror_bytes=len(raw), release_sha256=release_sha256, release_id=selected['release_id'],
            package_count=len(rows), packages=rows, synthetic=selected['synthetic'], actual_selectors_state='ALL_NULL',
            legal_acceptance=False, corresponding_source_completeness='NOT_ASSERTED', native_build='NOT_RUN',
            installation='NOT_RUN', hardware='NOT_RUN', release='NOT_ADMITTED')
        manifest_raw = mirror.encoded(manifest)
        source.need(len(manifest_raw) <= source.MAX_JSON, 'release set manifest exceeds existing JSON bound')
        for name, body in (('mirror.tar', raw), (MANIFEST, manifest_raw)):
            descriptor = os.open(staging/name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(body); stream.flush(); os.fsync(stream.fileno()); os.fchmod(stream.fileno(), 0o400)
        checksum = mirror.digest(manifest_raw)
        verify_release_context(staging, checksum, deps, catalog, consumer)
        current = os.stat(staging.name, dir_fd=parent, follow_symlinks=False)
        source.need((held.st_dev, held.st_ino) == (current.st_dev, current.st_ino) and not staging.is_symlink(), 'staging root replaced')
        current_parent = source.directory(output.parent)
        try:
            info = os.fstat(current_parent)
            source.need((info.st_dev, info.st_ino) == (parent_info.st_dev, parent_info.st_ino), 'output parent replaced')
        finally:
            os.close(current_parent)
        result = receipt(manifest, checksum, 'MATERIALIZED_RELEASE_CONTEXT_SET')
        publish_no_replace(parent, staging.name, output.name)
        staging = None
        return result
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            if staging is not None:
                info = os.stat(staging.name, dir_fd=parent, follow_symlinks=False)
                source.need((held.st_dev, held.st_ino) == (info.st_dev, info.st_ino), 'unowned staging cleanup refused')
                shutil.rmtree(staging.name, dir_fd=parent)
        except BaseException as error:
            if primary is None:
                raise
            primary.add_note('release context staging cleanup: ' + type(error).__name__)
        finally:
            os.close(parent)


class SingleValue(argparse.Action):
    def __call__(self, parser, namespace, value, option_string=None):
        if hasattr(namespace, self.dest):
            parser.error('repeated option refused: ' + option_string)
        setattr(namespace, self.dest, value)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest='command', required=True)
    create = commands.add_parser('materialize', allow_abbrev=False)
    create.add_argument('--bundle', required=True, action=SingleValue, default=argparse.SUPPRESS)
    create.add_argument('--sha256', required=True, action=SingleValue, default=argparse.SUPPRESS)
    create.add_argument('--release-sha256', required=True, action=SingleValue, default=argparse.SUPPRESS)
    create.add_argument('--output', required=True, action=SingleValue, default=argparse.SUPPRESS)
    check = commands.add_parser('verify', allow_abbrev=False)
    check.add_argument('--context-set', required=True, action=SingleValue, default=argparse.SUPPRESS)
    check.add_argument('--manifest-sha256', required=True, action=SingleValue, default=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        deps, catalog, consumer = helpers(None, None, None)
        if args.command == 'verify':
            result = verify_release_context(args.context_set, args.manifest_sha256, deps, catalog, consumer)
        else:
            result = materialize_release(deps['mirror'].read_file(Path(args.bundle)), args.sha256,
                args.release_sha256, args.output, deps, catalog, consumer)
        print(json.dumps(result, sort_keys=True)); return 0
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, tarfile.TarError, EOFError, RecursionError, AttributeError) as error:
        print(json.dumps(dict(status='REFUSED', reason=str(error)), sort_keys=True)); return 1


if __name__ == '__main__':
    sys.dont_write_bytecode = True
    raise SystemExit(main())
