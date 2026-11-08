#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind finite current-package DATA; never execute recipes or construct a Source."""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import tarfile

NAME, VERSION = 'cachy-asahi-source-tools', '0.2.0-1'
SOURCES = ('private-source.tar.gz', 'fixtures.tar.gz', NAME, 'check_package.py',
    'test_package.py', 'multi_package_roundtrip.py', 'README.md', 'source-provenance.json',
    'payload-map.json', 'NOTICE', 'LICENSE', 'test_cli_input_refusal.py',
    'source_mirror_catalog.py', 'test_source_mirror_catalog.py')
FILES = frozenset(SOURCES + ('PKGBUILD', '.SRCINFO'))
CHECKS = dict(cli_tests=9, duplicate_cases=132, catalog_tests=9, catalog_contexts=4,
              original_workflow_controls=17, private_helpers=11, payload_files=18)
DEPENDENCIES = dict(runtime=['python>=3.14', 'xz', 'zstd'], check=['bubblewrap'], build=['base-devel'])
PRIVATE_SHA = 'fa9db2ee4a6f16fee53b79494d437901570c80798de9219d2cc637b9f430575a'
PROVENANCE_SHA = '28b2b8a2708bc3fece91d5560b17da358b59937d4afcebf5a42be28a1802b042'
MAX_FILE, MAX_TOTAL = 4 * 1024**2, 16 * 1024**2


def need(value, reason):
    if not value:
        raise ValueError(reason)


def pin(raw, mode=0o644):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), mode=mode)


def decode(raw):
    need(type(raw) is bytes and len(raw) <= MAX_FILE, 'bounded JSON DATA')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    def invalid(_):
        raise ValueError('noninteger JSON number')
    value = json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    need(type(value) is dict, 'JSON object required')
    return value


def row(value):
    return (type(value) is dict and set(value) == {'bytes', 'sha256', 'mode'}
        and type(value['bytes']) is int and 0 < value['bytes'] <= MAX_FILE
        and type(value['mode']) is int and value['mode'] in (0o644, 0o755)
        and type(value['sha256']) is str and re.fullmatch('[0-9a-f]{64}', value['sha256']))


def relative(value):
    need(type(value) is str and '\\' not in value and '\x00' not in value, 'ordinary relative path')
    path = PurePosixPath(value)
    need(value and path.as_posix() == value and not path.is_absolute()
         and all(part not in ('.', '..') for part in path.parts), 'canonical relative path')
    return path


def selection(value):
    need(type(value) is dict and set(value) == {'schema', 'purpose', 'package', 'recipe',
         'checks', 'dependencies', 'frozen_private_runtime', 'provenance'}, 'selection fields')
    need(type(value['schema']) is int and value['schema'] == 2
         and value['purpose'] == 'source-tools-current-recipe-selection', 'current selection identity')
    need(value['package'] == dict(name=NAME, version=VERSION, arch='any', license='MIT'), 'current package identity')
    need(value['checks'] == CHECKS and all(type(v) is int for v in value['checks'].values()), 'current check counts')
    need(value['dependencies'] == DEPENDENCIES, 'current dependency set')
    recipe = value['recipe']
    need(type(recipe) is dict and set(recipe) == {'sources', 'files', 'payload_files'}
         and type(recipe['sources']) is list and recipe['sources'] == list(SOURCES)
         and type(recipe['files']) is dict and set(recipe['files']) == FILES, 'closed current 14-source/16-file recipe')
    need(all(row(r) and r['mode'] == (0o755 if name == NAME else 0o644)
             for name, r in recipe['files'].items()), 'ordinary pinned recipe modes/bytes')
    payload = recipe['payload_files']
    need(type(payload) is dict and len(payload) == 18 and all(
         relative(name).parts[0] == 'usr' and row(r) for name, r in payload.items()), 'finite 18-file payload')
    frozen = value['frozen_private_runtime']
    need(type(frozen) is dict and set(frozen) == {'archive', 'provenance', 'files'}
         and frozen['archive'] == recipe['files']['private-source.tar.gz']
         and frozen['provenance'] == recipe['files']['source-provenance.json']
         and frozen['archive']['sha256'] == PRIVATE_SHA and frozen['provenance']['sha256'] == PROVENANCE_SHA
         and type(frozen['files']) is dict and len(frozen['files']) == 11
         and all(str(relative(name)).startswith('scripts/') and row(r) and r['mode'] == 0o644
                 for name, r in frozen['files'].items()), 'frozen private eleven-file identity')
    need(type(value['provenance']) is dict, 'descriptive provenance object')
    return value


def _metadata(raw):
    result = {}
    for line in raw.decode('utf-8').splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        match = re.fullmatch(r'\s*([A-Za-z0-9_]+) = (.+)', line)
        need(match is not None, 'literal SRCINFO assignment')
        result.setdefault(match[1], []).append(match[2])
    return result


def _array(text, name):
    lines = re.findall(r'^\s*' + re.escape(name) + r'=([^\n]*)$', text, re.M)
    need(len(lines) == 1 and re.fullmatch(r'\([^()\n]*\)', lines[0]), 'single literal recipe array: ' + name)
    return shlex.split(lines[0][1:-1], posix=True)


def _value(text, name, expected):
    values = re.findall(r'^\s*' + re.escape(name) + r'=([^\n]*)$', text, re.M)
    need(values == [expected], 'single current recipe identity: ' + name)


def _validate(files, chosen):
    chosen = selection(chosen)
    recipe = chosen['recipe']
    need(type(files) is dict and set(files) == FILES and all(type(body) is bytes for body in files.values()), 'complete recipe DATA')
    need(sum(map(len, files.values())) <= MAX_TOTAL, 'recipe aggregate byte bound')
    for name, raw in files.items():
        need(pin(raw, recipe['files'][name]['mode']) == recipe['files'][name], 'recipe whole-body pin: ' + name)
    metadata = _metadata(files['.SRCINFO'])
    need(set(metadata) == {'pkgbase', 'pkgname', 'pkgdesc', 'pkgver', 'pkgrel', 'url', 'arch', 'license',
                          'checkdepends', 'depends', 'options', 'source', 'sha256sums'}, 'SRCINFO field set')
    for key, expected in dict(pkgbase=[NAME], pkgname=[NAME], pkgver=['0.2.0'], pkgrel=['1'],
        arch=['any'], license=['MIT'], depends=DEPENDENCIES['runtime'],
        checkdepends=DEPENDENCIES['check'], options=['!strip', '!debug'], source=list(SOURCES)).items():
        need(metadata[key] == expected, 'current SRCINFO field: ' + key)
    checksums = [recipe['files'][name]['sha256'] for name in SOURCES]
    need(metadata['sha256sums'] == checksums, 'SRCINFO exact source checksums')
    text = files['PKGBUILD'].decode('utf-8')
    for name, expected in dict(pkgname=NAME, pkgver='0.2.0', pkgrel='1').items():
        _value(text, name, expected)
    for name, expected in dict(source=list(SOURCES), sha256sums=checksums, arch=['any'], license=['MIT'],
        depends=DEPENDENCIES['runtime'], checkdepends=DEPENDENCIES['check'], options=['!strip', '!debug']).items():
        need(_array(text, name) == expected, 'literal recipe array differs: ' + name)
    need('--nocheck' not in text and '!check' not in text, 'mandatory positive checks')
    for required in ('$srcdir/test_cli_input_refusal.py', '$srcdir/test_source_mirror_catalog.py',
                     '$srcdir/check_package.py', '$srcdir/test_package.py'):
        need(text.count(required) == 1, 'current four-stage recipe check: ' + required)
    frozen = chosen['frozen_private_runtime']
    provenance = decode(files['source-provenance.json'])
    need(provenance['files'] == frozen['files'] and provenance['license'] == 'MIT'
         and provenance['runtime_dependencies'] == DEPENDENCIES['runtime']
         and provenance['check_dependencies'] == DEPENDENCIES['check']
         and provenance['build_dependencies'] == DEPENDENCIES['build'], 'frozen runtime provenance')
    private = {}
    with tarfile.open(fileobj=io.BytesIO(files['private-source.tar.gz']), mode='r:gz') as archive:
        for member in archive:
            need(len(private) < 11 and member.name.startswith('private/') and member.isfile()
                 and not member.pax_headers and member.mode == 0o644, 'frozen private archive member')
            name = member.name.removeprefix('private/')
            need(name in frozen['files'] and name not in private and member.size <= MAX_FILE, 'private exact member set')
            body = archive.extractfile(member).read()
            need(pin(body) == frozen['files'][name], 'private body pin')
            private[name] = body
    need(set(private) == set(frozen['files']), 'all eleven private helpers')
    mapping = decode(files['payload-map.json'])
    own = 'usr/share/doc/' + NAME + '/payload-map.json'
    need(set(mapping) == {'files', 'package', 'schema_version', 'self'} and type(mapping['schema_version']) is int
         and mapping['schema_version'] == 1 and mapping['package'] == NAME and mapping['self'] == own, 'payload map identity')
    expected = {'usr/bin/' + NAME: pin(files[NAME], 0o755)}
    expected.update({'usr/lib/cachy-asahi/source-tools/' + name: pin(body) for name, body in private.items()})
    expected['usr/lib/cachy-asahi/source-tools/scripts/release/source_mirror_catalog.py'] = pin(files['source_mirror_catalog.py'])
    for name in ('README.md', 'source-provenance.json', 'payload-map.json'):
        expected['usr/share/doc/' + NAME + '/' + name] = pin(files[name])
    for name in ('LICENSE', 'NOTICE'):
        expected['usr/share/licenses/' + NAME + '/' + name] = pin(files[name])
    need(len(expected) == 18 and {**mapping['files'], own: pin(files['payload-map.json'])} == expected
         and recipe['payload_files'] == expected, 'complete current installed payload pins')
    return files


def _directory(path):
    path = Path(path)
    need(path.is_absolute() and path == path.resolve() and '..' not in path.parts, 'canonical absolute recipe root')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def validate_recipe(root, chosen):
    """Read an exact ordinary flat recipe snapshot; no recipe evaluation."""
    chosen = selection(chosen)
    parent = _directory(root)
    files = {}
    try:
        before = os.fstat(parent)
        need(set(os.listdir(parent)) == FILES, 'closed sixteen-file recipe directory')
        for name in sorted(FILES):
            fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            try:
                info = os.fstat(fd)
                # A private Git checkout may remove group/other read bits via
                # umask077. Canonical delivery modes remain exactly0644/0755.
                modes = (0o700, 0o755) if chosen['recipe']['files'][name]['mode'] == 0o755 else (0o600, 0o644)
                need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= MAX_FILE
                     and stat.S_IMODE(info.st_mode) in modes, 'ordinary pinned recipe file: ' + name)
                blocks, total = [], 0
                while block := os.read(fd, min(65536, info.st_size + 1 - total)):
                    blocks.append(block); total += len(block)
                key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
                need(total == info.st_size and key(info) == key(os.fstat(fd)) == key(os.stat(name, dir_fd=parent, follow_symlinks=False)), 'stable complete recipe read')
                files[name] = b''.join(blocks)
            finally:
                os.close(fd)
        after = os.fstat(parent)
        need((before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) ==
             (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns)
             and set(os.listdir(parent)) == FILES, 'recipe namespace changed during read')
    finally:
        os.close(parent)
    return _validate(files, chosen)


def _tar(files, chosen):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, raw in sorted(files.items()):
            member = tarfile.TarInfo('recipe/' + name)
            member.size, member.mode = len(raw), chosen['recipe']['files'][name]['mode']
            member.uid = member.gid = member.mtime = 0
            member.uname = member.gname = ''
            archive.addfile(member, io.BytesIO(raw))
    return output.getvalue()


def recipe_bundle(files, chosen):
    """Return only a canonical recipe-input USTAR; not an immutable Source."""
    return _tar(_validate(files, chosen), chosen)


def verify_bundle(raw, chosen):
    chosen = selection(chosen)
    need(type(raw) is bytes and 0 < len(raw) <= MAX_TOTAL + 32768, 'bounded uncompressed recipe USTAR')
    result = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            need(len(result) < 16 and member.name.startswith('recipe/') and member.isfile()
                 and not member.pax_headers and member.uid == member.gid == member.mtime == 0
                 and member.uname == member.gname == '', 'canonical ordinary recipe member')
            name = member.name.removeprefix('recipe/')
            need(name in FILES and name not in result and member.size <= MAX_FILE
                 and member.mode == chosen['recipe']['files'][name]['mode'], 'exact recipe member size/mode/set')
            result[name] = archive.extractfile(member).read()
    _validate(result, chosen)
    need(raw == _tar(result, chosen), 'canonical complete recipe USTAR encoding')
    return result
