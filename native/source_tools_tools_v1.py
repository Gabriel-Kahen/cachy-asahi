# SPDX-License-Identifier: MIT
"""Finite source-tools package policy, inert fixtures and provenance comparisons.

No process, network, native image or retained-code actor is created on import. The
caller supplies the unchanged owned Commands runner for every future command.
"""
import base64
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import tarfile

OPERATION = 'source-tools-alpm-v1'
NAME = 'cachy-asahi-source-tools'
VERSION = '0.1.0-1'
PREFIX = Path('/opt/native-source-tools-alpm-v1')
SOURCE = PREFIX / 'source'
STORE = PREFIX / 'evidence'
STAGES = ('build-a', 'build-b', 'compare', 'sign', 'install', 'commands-system',
          'commands-moved', 'remove', 'restore', 'cleanup')
SOURCE_ARCHIVE = 'private-source.tar.gz'
SOURCE_FILES = frozenset(('PKGBUILD', '.SRCINFO', SOURCE_ARCHIVE, 'fixtures.tar.gz', NAME, 'check_package.py', 'test_package.py', 'multi_package_roundtrip.py', 'README.md', 'source-provenance.json', 'payload-map.json', 'NOTICE', 'LICENSE'))
SOURCE_ARCHIVE_SHA256 = 'fa9db2ee4a6f16fee53b79494d437901570c80798de9219d2cc637b9f430575a'
MAX_FILE = 16 * 1024**2
MAX_TOTAL = 128 * 1024**2
MAX_NODES = 100000


def need(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def data_pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def ordinary(path, maximum=2 * 1024**2):
    path = Path(path)
    need(not any(part.is_symlink() for part in (path, *path.parents)), 'ordinary nonaliased path required')
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= maximum,
             'bounded ordinary source required')
        pieces, size = [], 0
        while True:
            block = os.read(fd, min(65536, maximum + 1 - size))
            if not block:
                break
            pieces.append(block); size += len(block)
            need(size <= maximum, 'ordinary byte cap exceeded')
        after = os.fstat(fd)
        keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_mode', 'st_uid', 'st_gid')
        need(all(getattr(before, key) == getattr(after, key) for key in keys) and size == after.st_size,
             'ordinary file changed while reading')
        return b''.join(pieces)
    finally:
        os.close(fd)


def pin(path):
    return data_pin(ordinary(path, MAX_FILE))


def _pin_row(item):
    return (type(item) is dict and type(item.get('bytes')) is int and 0 < item['bytes'] <= 1024**2
            and type(item.get('sha256')) is str and re.fullmatch('[0-9a-f]{64}', item['sha256'])
            and type(item.get('mode')) is int and item['mode'] in (0o644, 0o755))


def expected_installed(root):
    """Derive all349 version AND architecture rows from the genuine held inputs."""
    root = Path(root)
    original = json.loads(ordinary(root / 'bootstrap/scripts/ci/inputs.lock.json'))
    additions = json.loads(ordinary(root / 'native/input-profile.json'))['additions']['rows']
    versions = {}
    for row in original['rootfs_packages']:
        need(all(type(row[key]) is list and len(row[key]) == 1 for key in ('name', 'version', 'arch')),
             'exact rootfs package metadata')
        versions[row['name'][0]] = (row['version'][0], row['arch'][0])
    for row in original['packages'] + additions:
        versions[row['name']] = (row['version'], row['arch'])
    need(len(versions) == 349 and all(arch in ('any', 'aarch64') for _, arch in versions.values()),
         'complete genuine349 architecture metadata')
    lock = ordinary(root / 'native/expected349.lock')
    need(lock == ''.join(name + ' ' + version + '\n' for name, (version, _) in sorted(versions.items())).encode(),
         'derived full349 version/architecture inventory differs')
    return sorted(name + '-' + version + '-' + arch for name, (version, arch) in versions.items())


def source_policy(root):
    root = Path(root)
    policy = json.loads(ordinary(root / 'native/source-tools-contract-v1.json'))
    need(policy.get('schema') == 1 and policy.get('operation') == OPERATION
         and type(policy.get('actual')) is dict and all(value is None for value in policy['actual'].values()),
         'unexecuted source-tools source contract identity')
    recipe = policy['recipe']
    need(recipe['archive'] == NAME + '-' + VERSION + '-any.pkg.tar.zst'
         and recipe['expected_test_count'] == 17 and type(recipe['expected_test_count']) is int
         and set(recipe['source_files']) == SOURCE_FILES and len(recipe['payload_files']) == 17,
         'exact frozen recipe and finite payload')
    for name, item in recipe['source_files'].items():
        need(Path(name).name == name and _pin_row(item), 'flat pinned frozen recipe source')
    need(recipe['source_files'][SOURCE_ARCHIVE]['sha256'] == SOURCE_ARCHIVE_SHA256,
         'exact0.1.0 frozen source archive required')
    for name, item in recipe['payload_files'].items():
        need(name.startswith('usr/') and Path(name).as_posix() == name and '..' not in Path(name).parts
             and _pin_row(item), 'pinned 17-file package payload')
    bundle = policy['bundle']
    need(bundle['path'] == 'native/source-tools-sources-v1.tar' and bundle['members'] == 13
         and type(bundle['bytes']) is int and 0 < bundle['bytes'] <= bundle['max_bytes'] <= 1024**2,
         'finite 13-member source delivery')
    base = ordinary(root / 'native/expected349.lock')
    need(data_pin(base) == {key: policy['expected349'][key] for key in ('bytes', 'sha256')}
         and len(base.splitlines()) == 349, 'exact genuine349 lock')
    versions = dict(line.decode().split(' ', 1) for line in base.splitlines())
    need(all(versions.get(name) == version for name, version in policy['dependencies'].items())
         and versions.get('python') == '3.14.8-1' and versions.get('zstd') == '1.5.7-3'
         and versions.get('xz') == '5.8.4-1' and versions.get('bubblewrap') == '0.13.0-1',
         'exact retained native dependencies')
    need(policy['buildinfo_installed'] == expected_installed(root), 'full349 BUILDINFO architecture/version provenance')
    config_row = policy['makepkg_config']
    need(config_row['path'] == 'native/source-tools-makepkg-v1.conf', 'fixed makepkg configuration')
    config = ordinary(root / config_row['path'])
    need(data_pin(config) == {key: config_row[key] for key in ('bytes', 'sha256')}
         and re.search(rb'^BUILDENV=\([^\n]*\bcheck\b', config, re.M) and b'!check' not in config
         and b"PKGEXT='.pkg.tar.zst'" in config, 'positive makepkg check policy')
    return policy, base


def recipe_members(root, policy):
    raw = ordinary(Path(root) / policy['bundle']['path'], policy['bundle']['max_bytes'])
    need(data_pin(raw) == {key: policy['bundle'][key] for key in ('bytes', 'sha256')}, 'source bundle checksum')
    expected = {'recipe/' + name: item for name, item in policy['recipe']['source_files'].items()}
    result = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            need(member.name in expected and member.name not in result and member.isfile() and not member.pax_headers
                 and member.uid == member.gid == member.mtime == 0, 'exact regular source bundle member')
            item = expected[member.name]
            need(member.mode == item['mode'] and member.size == item['bytes'], 'source member size/mode')
            body = archive.extractfile(member).read()
            need(data_pin(body) == {key: item[key] for key in ('bytes', 'sha256')}, 'source member checksum')
            result[member.name] = body
    need(set(result) == set(expected) and len(result) == 13, 'complete 13-file recipe bundle')
    return result


def extract_recipes(root, destination, policy):
    members = recipe_members(root, policy)
    destination = Path(destination)
    destination.mkdir(mode=0o755)
    for label in ('a', 'b'):
        target = destination / label
        target.mkdir(mode=0o755)
        for name, item in policy['recipe']['source_files'].items():
            with (target / name).open('xb') as stream:
                stream.write(members['recipe/' + name])
            (target / name).chmod(item['mode'])
    return destination


def load_workflow(root, policy):
    row = policy['original_workflow']
    path = Path(root) / row['path']; raw = ordinary(path)
    need(data_pin(raw) == {key: row[key] for key in ('bytes', 'sha256')}, 'genuine owned Commands source bytes')
    spec = importlib.util.spec_from_file_location('_source_tools_owned_workflow_v1', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def inventory_expected(base, version=None):
    rows = base.splitlines(keepends=True)
    need(len(rows) == 349 and not any(line.startswith((NAME + ' ').encode()) for line in rows),
         'project package absent from exact349 base')
    if version is not None:
        need(version == VERSION, 'only frozen installed source-tools version')
        rows.append((NAME + ' ' + VERSION + '\n').encode())
    return b''.join(sorted(rows))


def snapshot(root):
    """Bounded quiescent tree bytes/modes/ownership; never follow symlink nodes."""
    root = Path(root)
    need(not any(path.is_symlink() for path in root.parents), 'snapshot ancestry alias refused')
    if not os.path.lexists(root):
        return {}
    need(not root.is_symlink(), 'snapshot root alias refused')
    result, total, count = {}, 0, 0
    def visit(path, name, depth):
        nonlocal total, count
        count += 1
        need(count <= MAX_NODES and depth <= 64, 'snapshot node/depth budget exceeded')
        info = path.lstat()
        item = dict(mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid)
        if stat.S_ISDIR(info.st_mode):
            item['kind'] = 'directory'; result[name] = item
            for child in sorted(path.iterdir()):
                visit(child, str(child.relative_to(root)), depth + 1)
        elif stat.S_ISREG(info.st_mode):
            raw = ordinary(path, min(MAX_FILE, MAX_TOTAL - total))
            total += len(raw); item.update(kind='file', **data_pin(raw)); result[name] = item
        elif stat.S_ISLNK(info.st_mode):
            target = os.readlink(path)
            need(len(target.encode()) <= 4096, 'snapshot link byte cap')
            item.update(kind='symlink', target=target); result[name] = item
        else:
            raise ValueError('snapshot special file refused: ' + name)
    visit(root, '.', 0)
    return result


def snapshot_receipt(root):
    value = snapshot(root)
    return dict(files=len(value), **data_pin(encoded(value)))


def check_payload(root, policy, run, pacman):
    expected = policy['recipe']['payload_files']
    for name, item in expected.items():
        path = Path(root) / name; info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
             and stat.S_IMODE(info.st_mode) == item['mode']
             and pin(path) == {key: item[key] for key in ('bytes', 'sha256')},
             'actual ALPM payload bytes/mode/root ownership: ' + name)
        need(run('owner-' + NAME, ['/usr/bin/pacman', *pacman, '-Qoq', str(path)]).strip() == NAME.encode(),
             'actual ALPM ownership join')
    listed = run('owned-files-' + NAME, ['/usr/bin/pacman', *pacman, '-Qlq', NAME]).decode().splitlines()
    need(len(listed) == len(set(listed)) and all(name.startswith('/') and '..' not in Path(name).parts
         and name.rstrip('/') == Path(name.rstrip('/')).as_posix() for name in listed), 'canonical unique ALPM paths')
    files = {name.lstrip('/') for name in listed if not name.endswith('/')}
    directories = {name.lstrip('/').rstrip('/') for name in listed if name.endswith('/')}
    ancestors = {str(parent) for name in expected for parent in Path(name).parents if str(parent) != '.'}
    need(files == set(expected) and directories == ancestors, 'exact ALPM 17-file and ancestor directory ownership')
    return dict(version=VERSION, count=17, verified=True, stale_absent=True,
                files={name: {key: item[key] for key in ('bytes', 'sha256', 'mode')} for name, item in expected.items()})


def _metadata(raw):
    need(len(raw) <= 256 * 1024, 'metadata byte cap')
    rows = {}
    for line in raw.decode('utf-8').splitlines():
        if not line or line.startswith('#'):
            continue
        need(' = ' in line, 'canonical makepkg metadata field')
        key, value = line.split(' = ', 1)
        need(re.fullmatch('[a-z][a-z0-9_]*', key) and len(value) <= 8192, 'bounded makepkg metadata field')
        rows.setdefault(key, []).append(value)
    return rows


def _archive_data(raw, policy):
    """Decode bounded tar DATA only; exact regular payload and metadata namespace."""
    need(len(raw) <= 2 * 1024**2, 'decoded package byte cap')
    expected = policy['recipe']['payload_files']
    ancestors = {str(parent) for name in expected for parent in Path(name).parents if str(parent) != '.'}
    metadata, payload, directories, seen = {}, {}, set(), set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            name = member.name.rstrip('/')
            need(name not in seen and member.uid == member.gid == 0 and not member.pax_headers
                 and name == Path(name).as_posix() and '..' not in Path(name).parts, 'unique canonical root-owned package members')
            seen.add(name)
            if member.isdir():
                need(name in ancestors and member.mode == 0o755, 'exact package directory mode/namespace')
                directories.add(name)
                continue
            need(member.isfile() and member.size <= 1024**2, 'ordinary finite package member')
            body = archive.extractfile(member).read()
            if name in ('.PKGINFO', '.BUILDINFO', '.MTREE'):
                need(member.mode == 0o644, 'metadata file mode'); metadata[name] = body
            else:
                need(name in expected, 'unexpected package payload or install script')
                item = expected[name]
                need(member.mode == item['mode'] and data_pin(body) == {key: item[key] for key in ('bytes', 'sha256')},
                     'exact package payload bytes/mode')
                payload[name] = dict(mode=member.mode, **data_pin(body))
    need(set(payload) == set(expected) and directories == ancestors
         and set(metadata) == {'.PKGINFO', '.BUILDINFO', '.MTREE'}, 'complete finite package payload/metadata/directory sets')
    pkg = _metadata(metadata['.PKGINFO']); build = _metadata(metadata['.BUILDINFO'])
    for key, expected_value in (('pkgname', NAME), ('pkgbase', NAME), ('pkgver', VERSION), ('arch', 'any')):
        need(pkg.get(key) == [expected_value], 'exact PKGINFO ' + key)
    need(pkg.get('license') == ['MIT'] and pkg.get('depend') == ['python>=3.14', 'xz', 'zstd'] and pkg.get('checkdepend') == ['bubblewrap'], 'exact package license/runtime dependency')
    for key, expected_value in (('format', '2'), ('pkgname', NAME), ('pkgbase', NAME), ('pkgver', VERSION), ('pkgarch', 'any'),
                                ('pkgbuild_sha256sum', policy['recipe']['source_files']['PKGBUILD']['sha256'])):
        need(build.get(key) == [expected_value], 'exact BUILDINFO ' + key)
    installed = build.get('installed', [])
    need(len(installed) == 349 and len(set(installed)) == 349 and sorted(installed) == policy['buildinfo_installed'],
         'all349 exact native dependency provenance rows required')
    need('check' in build.get('buildenv', []) and '!check' not in build['buildenv'], 'actual positive buildenv check')
    return dict(metadata=metadata, payload=payload)


def compare_archives(run, archives, policy, source_map_hash):
    need(set(archives) == {'a', 'b'} and re.fullmatch('[0-9a-f]{64}', source_map_hash or ''), 'exact native pair/source map')
    decoded, builds = {}, {}
    archive_bodies = {}
    for label in ('a', 'b'):
        path = Path(archives[label])
        archive_bodies[label] = ordinary(path, 1024**2)
        raw = run('archive-' + label, ['/usr/bin/zstd', '-dc', str(path)])
        decoded[label] = _archive_data(raw, policy)
        data = decoded[label]
        builds[label] = dict(archive=data_pin(archive_bodies[label]), pkginfo=data_pin(data['metadata']['.PKGINFO']),
                             buildinfo=data_pin(data['metadata']['.BUILDINFO']), mtree=data_pin(data['metadata']['.MTREE']),
                             payload=data['payload'])
    need(archive_bodies['a'] == archive_bodies['b'], 'two clean native package archive bytes differ')
    need(decoded['a'] == decoded['b'], 'two clean native payload/metadata differ')
    data = decoded['a']
    return dict(status='PASS_EXACT_NATIVE_BUILD_PAIR', archive=data_pin(archive_bodies['a']), builds=builds,
                equality=dict(archive=True, payload=True, pkginfo=True, buildinfo=True, mtree=True),
                payload_files=17, base_inventory_count=349, source_map_sha256=source_map_hash,
                pkgbuild_sha256=policy['recipe']['source_files']['PKGBUILD']['sha256'],
                pkginfo_text=data['metadata']['.PKGINFO'].decode(), buildinfo_text=data['metadata']['.BUILDINFO'].decode(),
                mtree_base64=base64.b64encode(data['metadata']['.MTREE']).decode('ascii'))


def _own_tree(root, uid, gid):
    root = Path(root)
    for path in (root, *sorted(root.rglob('*'))):
        info = path.lstat()
        need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'fixture aliases/special nodes refused')
        os.chown(path, uid, gid, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):path.chmod(0o700)


def fixture_members(raw):
    """Decode exact finite trusted fixture DATA; never import fixture Python."""
    need(len(raw) <= 1024**2, 'compressed original fixture cap')
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
        decoded = stream.read(8 * 1024**2 + 1)
    need(len(decoded) <= 8 * 1024**2, 'decoded original fixture cap')
    files, directories = {}, set()
    with tarfile.open(fileobj=io.BytesIO(decoded), mode='r:') as archive:
        for member in archive:
            name = member.name.rstrip('/')
            need(name == Path(name).as_posix() and name.startswith('fixtures/') and
                 '..' not in Path(name).parts and name not in files and name not in directories and
                 not member.pax_headers and member.uid == member.gid == member.mtime == 0,
                 'canonical unique fixture DATA member')
            need(len(files) + len(directories) < 256, 'finite fixture member cap')
            if member.isdir():
                need(member.size == 0 and member.mode in (0o700, 0o755), 'fixture directory mode')
                directories.add(name)
            else:
                need(member.isfile() and 0 <= member.size <= 1024**2 and member.mode == 0o644,
                     'bounded original fixture file')
                files[name] = archive.extractfile(member).read()
    need('fixtures/fixtures.json' in files and len(files) > 2, 'complete fixture manifest required')
    need(sum(map(len, files.values())) <= 8 * 1024**2, 'finite fixture aggregate cap')
    return files


def business(run, cli, root, uid, gid, label, source=SOURCE, policy=None):
    """Future ordinary-user commands from the installed or moved exact payload."""
    from source_tools_probe_v1 import probe
    root, source = Path(root), Path(source)
    need(label in ('system', 'moved') and not os.path.lexists(root), 'fresh finite probe scope')
    if policy is None:policy, _ = source_policy(source)
    members = recipe_members(source, policy)
    raw = members['recipe/fixtures.tar.gz']
    need(data_pin(raw) == {k: policy['recipe']['source_files']['fixtures.tar.gz'][k] for k in ('bytes', 'sha256')},
         'same-source frozen fixture archive required')
    files = fixture_members(raw)
    root.mkdir(mode=0o700)
    for name, body in sorted(files.items()):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with path.open('xb') as stream:stream.write(body)
        path.chmod(0o644)
    work = root / 'workflow'
    work.mkdir(mode=0o700)
    _own_tree(root, uid, gid)
    def command(step, argv, expected=0, cwd=work):
        return run(label + '-' + step, argv, expected, cwd=cwd)
    result = probe(Path(cli), root / 'fixtures', work, command)
    need(result.get('controls') == 17 and result.get('exact_contexts') == 4,
         'complete finite installed/moved source-tool probe')
    result['steps'] = {key: label + '-' + step for key, step in result['steps'].items()}
    return dict(result, cli=str(cli), label=label, fixture_root=str(root/'fixtures'), work_root=str(work), source_fixture=data_pin(raw),
                fixture_snapshot=snapshot_receipt(root), release='NOT_ADMITTED')
