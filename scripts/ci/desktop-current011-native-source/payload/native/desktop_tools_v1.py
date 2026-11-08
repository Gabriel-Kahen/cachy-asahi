# SPDX-License-Identifier: MIT
"""Finite desktop package policy, inert fixtures and provenance comparisons.

No process, network, native image or desktop actor is created on import. The
caller supplies the unchanged owned Commands runner for every future command.
"""
import base64
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

OPERATION = 'desktop-alpm-v1'
NAME = 'cachy-asahi-desktop-tools'
VERSION = '0.1.0-1'
UPDATE_VERSION = '0.1.0-2'
UPDATE_FIXTURE = 'TEST_LIFECYCLE_UPDATE_FIXTURE_ONLY'
PREFIX = Path('/opt/native-desktop-tools-alpm-v1')
SOURCE = PREFIX / 'source'
STORE = PREFIX / 'evidence'
STAGES = ('build-a', 'build-b', 'compare', 'build-update', 'sign', 'install',
          'commands-system', 'commands-moved', 'update', 'commands-updated',
          'remove', 'restore', 'cleanup')
SOURCE_ARCHIVE = NAME + '-0.1.0.tar.gz'
SOURCE_FILES = frozenset(('PKGBUILD', SOURCE_ARCHIVE, 'export_source.py', 'test_export_source.py'))
SOURCE_ARCHIVE_SHA256 = '69d8c7bb3a13086d4b3ae5a46fa79db14ef4a034912bacb9f185ccc4d54b0ba4'
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
    policy = json.loads(ordinary(root / 'native/desktop-contract-v1.json'))
    need(policy.get('schema') == 1 and policy.get('operation') == OPERATION
         and type(policy.get('actual')) is dict and all(value is None for value in policy['actual'].values()),
         'unexecuted desktop source contract identity')
    recipe = policy['recipe']
    need(recipe['archive'] == NAME + '-' + VERSION + '-any.pkg.tar.zst'
         and recipe['expected_test_count'] == 81 and type(recipe['expected_test_count']) is int
         and set(recipe['source_files']) == SOURCE_FILES and len(recipe['payload_files']) == 6,
         'exact frozen recipe and finite payload')
    for name, item in recipe['source_files'].items():
        need(Path(name).name == name and _pin_row(item), 'flat pinned frozen recipe source')
    need(recipe['source_files'][SOURCE_ARCHIVE]['sha256'] == SOURCE_ARCHIVE_SHA256,
         'exact0.1.0 frozen source archive required')
    for name, item in recipe['payload_files'].items():
        need(name.startswith('usr/') and Path(name).as_posix() == name and '..' not in Path(name).parts
             and _pin_row(item), 'pinned six-file package payload')
    update_policy(policy)
    bundle = policy['bundle']
    need(bundle['path'] == 'native/desktop-sources-v1.tar' and bundle['members'] == 5
         and type(bundle['bytes']) is int and 0 < bundle['bytes'] <= bundle['max_bytes'] <= 1024**2,
         'finite five-member source delivery')
    base = ordinary(root / 'native/expected349.lock')
    need(data_pin(base) == {key: policy['expected349'][key] for key in ('bytes', 'sha256')}
         and len(base.splitlines()) == 349, 'exact genuine349 lock')
    versions = dict(line.decode().split(' ', 1) for line in base.splitlines())
    need(all(versions.get(name) == version for name, version in policy['dependencies'].items())
         and versions.get('python') == '3.14.8-1' and versions.get('zstd') == '1.5.7-3',
         'exact retained native dependencies')
    need(policy['buildinfo_installed'] == expected_installed(root), 'full349 BUILDINFO architecture/version provenance')
    config_row = policy['makepkg_config']
    need(config_row['path'] == 'native/desktop-makepkg-v1.conf', 'fixed makepkg configuration')
    config = ordinary(root / config_row['path'])
    need(data_pin(config) == {key: config_row[key] for key in ('bytes', 'sha256')}
         and re.search(rb'^BUILDENV=\([^\n]*\bcheck\b', config, re.M) and b'!check' not in config
         and b"PKGEXT='.pkg.tar.zst'" in config, 'positive makepkg check policy')
    return policy, base


def update_policy(policy):
    """The update is an explicit TEST transaction fixture, never a new product."""
    baseline, update = policy['recipe'], policy['update_recipe']
    need(update.get('scope') == UPDATE_FIXTURE and update.get('version') == UPDATE_VERSION
         and update.get('archive') == NAME + '-' + UPDATE_VERSION + '-any.pkg.tar.zst'
         and type(update.get('expected_test_count')) is int and update['expected_test_count'] == 81
         and set(update.get('source_files', {})) == SOURCE_FILES,
         'explicit TEST-only update recipe contract')
    for name, item in update['source_files'].items():
        need(_pin_row(item), 'pinned generated update source')
        if name != 'PKGBUILD':
            need(item == baseline['source_files'][name], 'update changes only PKGBUILD')
    need(update.get('payload_files', baseline['payload_files']) == baseline['payload_files'],
         'TEST update payload must remain exact original six files')
    return update


def update_recipe_bytes(original):
    lines = original.splitlines(keepends=True)
    need(lines.count(b'pkgrel=1\n') == 1 and sum(line.startswith(b'pkgrel=') for line in lines) == 1,
         'one exact original pkgrel=1 line required')
    lines[lines.index(b'pkgrel=1\n')] = b'pkgrel=2\n'
    return b''.join(lines)


def update_generation(policy, members):
    update = update_policy(policy)
    before, after = members['recipe/PKGBUILD'], members['update/PKGBUILD']
    need(data_pin(before) == {key: policy['recipe']['source_files']['PKGBUILD'][key] for key in ('bytes', 'sha256')}
         and data_pin(after) == {key: update['source_files']['PKGBUILD'][key] for key in ('bytes', 'sha256')}
         and after == update_recipe_bytes(before), 'exact one-line generated update recipe proof')
    return dict(scope=UPDATE_FIXTURE, version_from=VERSION, version_to=UPDATE_VERSION,
                source_archive={key: policy['recipe']['source_files'][SOURCE_ARCHIVE][key] for key in ('bytes', 'sha256')},
                recipe_before=data_pin(before), recipe_after=data_pin(after),
                replacement=dict(before='pkgrel=1\n', after='pkgrel=2\n', count=1),
                unchanged_payload=True, changed_sources=['PKGBUILD'])


def recipe_members(root, policy):
    raw = ordinary(Path(root) / policy['bundle']['path'], policy['bundle']['max_bytes'])
    need(data_pin(raw) == {key: policy['bundle'][key] for key in ('bytes', 'sha256')}, 'source bundle checksum')
    update = update_policy(policy)
    expected = {'recipe/' + name: item for name, item in policy['recipe']['source_files'].items()}
    expected['update/PKGBUILD'] = update['source_files']['PKGBUILD']
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
    need(set(result) == set(expected) and len(result) == 5, 'complete five-member recipe/update bundle')
    update_generation(policy, result)
    return result


def extract_recipes(root, destination, policy):
    members = recipe_members(root, policy)
    destination = Path(destination)
    destination.mkdir(mode=0o755)
    for label in ('a', 'b', 'update'):
        target = destination / label
        target.mkdir(mode=0o755)
        recipe = policy['update_recipe'] if label == 'update' else policy['recipe']
        for name, item in recipe['source_files'].items():
            with (target / name).open('xb') as stream:
                stream.write(members['update/PKGBUILD' if label == 'update' and name == 'PKGBUILD' else 'recipe/' + name])
            (target / name).chmod(item['mode'])
    return destination


def load_workflow(root, policy):
    row = policy['original_workflow']
    path = Path(root) / row['path']; raw = ordinary(path)
    need(data_pin(raw) == {key: row[key] for key in ('bytes', 'sha256')}, 'genuine owned Commands source bytes')
    spec = importlib.util.spec_from_file_location('_desktop_owned_workflow_v1', path)
    module = importlib.util.module_from_spec(spec)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def inventory_expected(base, version=None):
    rows = base.splitlines(keepends=True)
    need(len(rows) == 349 and not any(line.startswith((NAME + ' ').encode()) for line in rows),
         'project package absent from exact349 base')
    if version is not None:
        need(version in (VERSION, UPDATE_VERSION), 'finite baseline or TEST-update version only')
        rows.append((NAME + ' ' + version + '\n').encode())
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


def check_payload(root, policy, run, pacman, version=VERSION):
    need(version in (VERSION, UPDATE_VERSION), 'finite payload version only')
    expected = policy['recipe']['payload_files']
    for name, item in expected.items():
        path = Path(root) / name; info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0
             and stat.S_IMODE(info.st_mode) == item['mode']
             and pin(path) == {key: item[key] for key in ('bytes', 'sha256')},
             'actual ALPM payload bytes/mode/root ownership: ' + name)
        need(run('owner-' + NAME + '-' + version, ['/usr/bin/pacman', *pacman, '-Qoq', str(path)]).strip() == NAME.encode(),
             'actual ALPM ownership join')
    listed = run('owned-files-' + NAME + '-' + version, ['/usr/bin/pacman', *pacman, '-Qlq', NAME]).decode().splitlines()
    need(len(listed) == len(set(listed)) and all(name.startswith('/') and '..' not in Path(name).parts
         and name.rstrip('/') == Path(name.rstrip('/')).as_posix() for name in listed), 'canonical unique ALPM paths')
    files = {name.lstrip('/') for name in listed if not name.endswith('/')}
    directories = {name.lstrip('/').rstrip('/') for name in listed if name.endswith('/')}
    ancestors = {str(parent) for name in expected for parent in Path(name).parents if str(parent) != '.'}
    need(files == set(expected) and directories == ancestors, 'exact ALPM six-file and ancestor directory ownership')
    return dict(version=version, count=6, verified=True, stale_absent=True,
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


def _archive_data(raw, policy, version=VERSION):
    need(version in (VERSION, UPDATE_VERSION), 'finite archive version only')
    recipe = update_policy(policy) if version == UPDATE_VERSION else policy['recipe']
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
    for key, expected_value in (('pkgname', NAME), ('pkgbase', NAME), ('pkgver', version), ('arch', 'any')):
        need(pkg.get(key) == [expected_value], 'exact PKGINFO ' + key)
    need(pkg.get('license') == ['MIT'] and pkg.get('depend') == ['python>=3.11'], 'exact package license/runtime dependency')
    for key, expected_value in (('format', '2'), ('pkgname', NAME), ('pkgbase', NAME), ('pkgver', version), ('pkgarch', 'any'),
                                ('pkgbuild_sha256sum', recipe['source_files']['PKGBUILD']['sha256'])):
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
                payload_files=6, base_inventory_count=349, source_map_sha256=source_map_hash,
                pkgbuild_sha256=policy['recipe']['source_files']['PKGBUILD']['sha256'],
                pkginfo_text=data['metadata']['.PKGINFO'].decode(), buildinfo_text=data['metadata']['.BUILDINFO'].decode(),
                mtree_base64=base64.b64encode(data['metadata']['.MTREE']).decode('ascii'))


def compare_update(run, archive, policy, source_map_hash):
    need(re.fullmatch('[0-9a-f]{64}', source_map_hash or ''), 'exact update Source map')
    path = Path(archive)
    body = ordinary(path, 1024**2)
    raw = run('archive-update', ['/usr/bin/zstd', '-dc', str(path)])
    data = _archive_data(raw, policy, UPDATE_VERSION)
    return dict(status='PASS_TEST_LIFECYCLE_UPDATE_ARCHIVE', fixture=UPDATE_FIXTURE, version=UPDATE_VERSION,
                archive=data_pin(body), pkginfo=data_pin(data['metadata']['.PKGINFO']),
                buildinfo=data_pin(data['metadata']['.BUILDINFO']), mtree=data_pin(data['metadata']['.MTREE']),
                payload=data['payload'], pkginfo_text=data['metadata']['.PKGINFO'].decode(),
                buildinfo_text=data['metadata']['.BUILDINFO'].decode(),
                mtree_base64=base64.b64encode(data['metadata']['.MTREE']).decode('ascii'),
                source_map_sha256=source_map_hash,
                pkgbuild_sha256=policy['update_recipe']['source_files']['PKGBUILD']['sha256'], base_inventory_count=349)


def _elf():
    """Original inert AArch64 ELF header, deliberately not an executable body."""
    raw = bytearray(64); raw[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', raw, 16, 2, 183, 1)
    struct.pack_into('<HHH', raw, 52, 64, 56, 0)
    return bytes(raw)


def _own_tree(root, uid, gid):
    root = Path(root)
    for path in (root, *sorted(root.rglob('*'))):
        info = path.lstat(); os.chown(path, uid, gid, follow_symlinks=False)
        if not stat.S_ISLNK(info.st_mode):
            path.chmod(0o755 if stat.S_ISDIR(info.st_mode) or info.st_mode & 0o111 else 0o644)


def business(run, cli, root, uid, gid, label, version=VERSION):
    """Future actual installed CLI checks; every staged command remains inert."""
    need(version in (VERSION, UPDATE_VERSION), 'finite business package version only')
    root = Path(root); root.mkdir(mode=0o755)
    staged = root / 'staged-root'; staged.mkdir()
    marker = root / 'MUST-NOT-EXIST'
    def put(name, raw, mode=0o644):
        path = staged / name.lstrip('/'); path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw.encode() if isinstance(raw, str) else raw); path.chmod(mode)
    put('/usr/bin/tool', '#!/usr/bin/interpreter\ntouch ' + str(marker) + '\n', 0o755)
    put('/usr/bin/interpreter', _elf(), 0o755); put('/usr/bin/terminal', _elf(), 0o755)
    (staged / 'usr/bin/tool-link').symlink_to('/usr/bin/tool')
    put('/usr/share/applications/tool.desktop', '[Desktop Entry]\nType=Application\nName=Original Offline Fixture\n'
        'Exec=tool-link %F\nTryExec=tool\nTerminal=true\nNoDisplay=true\nIcon=fixture\nMimeType=text/plain;\n')
    put('/usr/share/icons/hicolor/index.theme', '[Icon Theme]\nName=Hicolor\nComment=Original fixture\nDirectories=48x48/apps\n'
        '[48x48/apps]\nSize=48\nType=Fixed\n')
    put('/usr/share/icons/hicolor/48x48/apps/fixture.png', b'INERT ORIGINAL ICON DATA')
    put('/etc/xdg/mimeapps.list', '[Default Applications]\ntext/plain=tool.desktop;\n')
    env = dict(HOME='/home/fixture', XDG_DATA_HOME='/home/fixture/.local/share', XDG_DATA_DIRS='/usr/local/share:/usr/share',
               XDG_CONFIG_HOME='/home/fixture/.config', XDG_CONFIG_DIRS='/etc/xdg', XDG_CURRENT_DESKTOP='Hyprland',
               PATH='/usr/local/bin:/usr/bin', icon_theme='hicolor', icon_size=48, icon_scale=1,
               terminal_argv=['terminal', '-e'], locale='C')
    environment = root / 'environment.json'; environment.write_bytes(encoded(env))
    _own_tree(root, uid, gid)
    reports, steps = {}, {}
    def command(key, operation, extra=(), expected=0):
        step = label + '-' + key.replace('_', '-')
        args = ['--root', str(staged), '--environment', str(environment), '--select', 'tool.desktop', '--mime', 'text/plain']
        argv = ['/usr/bin/runuser', '-u', 'alarm', '--', '/usr/bin/env', 'HOME=' + str(root), str(cli), operation, *args, *map(str, extra)]
        raw = run(step, argv, expected, cwd=root)
        need(not os.path.lexists(marker), 'no desktop fixture command may execute')
        reports[key] = data_pin(raw); steps[key] = step
        return raw, json.loads(raw)
    raw, inventory = command('capture', 'capture')
    need(inventory.get('kind') == 'cachy-asahi-desktop-static-inventory-v1'
         and inventory.get('selected') == ['tool.desktop'] and inventory.get('mime') == ['text/plain']
         and inventory.get('environment') == pin(environment), 'actual captured static inventory')
    inventory_path = root / 'inventory.json'; inventory_path.write_bytes(raw); inventory_path.chmod(0o644)
    os.chown(inventory_path, uid, gid)
    inventory_pin = data_pin(raw)
    extra = ['--inventory', str(inventory_path), '--inventory-sha256', inventory_pin['sha256']]
    _, audited = command('audit', 'audit', extra)
    need(audited.get('status') == 'PASS_STAGED_CHECKS' and audited.get('inventory_binding') == 'EXACT_STATIC_INVENTORY'
         and audited.get('inventory_input') == inventory_pin, 'actual installed static audit with exact inventory')
    moved = root / 'moved-staged-root'; staged.rename(moved); staged = moved
    _, relocated = command('moved_root', 'audit', extra)
    need(relocated.get('status') == 'PASS_STAGED_CHECKS' and relocated.get('inventory_binding') == 'EXACT_STATIC_INVENTORY'
         and relocated.get('pins') == audited.get('pins'), 'moved staged-root exact bindings')
    (staged / 'usr/share/icons/hicolor/48x48/apps/fixture.png').write_bytes(b'CHANGED ORIGINAL ICON DATA')
    _, refused = command('changed_data', 'audit', extra, 2)
    need(refused.get('status') == 'REFUSED' and 'staged inventory differs' in refused.get('error', ''),
         'actual changed-data refusal required')
    need(not list(root.rglob('__pycache__')), 'no generated bytecode cache in caller fixtures')
    result = dict(status='PASS_ACTUAL_STATIC_CAPTURE_AUDIT_REFUSAL', cli=str(cli), synthetic=True, version=version, payload_cli_version='0.1.0',
                inventory=inventory_pin, environment=pin(environment), selected=['tool.desktop'], mime=['text/plain'],
                reports=reports, steps=steps, baseline_status='PASS_STAGED_CHECKS', moved_root_status='PASS_STAGED_CHECKS',
                changed_data_status='REFUSED', changed_data_exit=2, zero_payload_execution=True,
                fixture_snapshot=snapshot_receipt(root), release='NOT_ADMITTED')

    if version == UPDATE_VERSION:
        result['fixture'] = UPDATE_FIXTURE
    return result


# Exact current package family; old/default helpers above remain unchanged.
CURRENT011_VERSION = '0.1.1-1'
CURRENT011_UPDATE_VERSION = '0.1.1-2'
CURRENT011_SOURCE_ARCHIVE = NAME + '-0.1.1.tar.gz'
CURRENT011_SOURCE_FILES = frozenset(('PKGBUILD', CURRENT011_SOURCE_ARCHIVE, 'export_source.py', 'test_export_source.py'))
CURRENT011_SOURCE_ARCHIVE_SHA256 = '11a59ada0d99f1202694ed98adb7891594b27a7048e39a99d5590e425fc31986'


def current011_source_policy(root):
    root = Path(root)
    policy = json.loads(ordinary(root / 'native/desktop-contract-v1.json'))
    need(policy.get('schema') == 1 and policy.get('operation') == OPERATION and (type(policy.get('actual')) is dict) and all((value is None for value in policy['actual'].values())), 'unexecuted desktop source contract identity')
    need(policy.get('current011') == current011_package_selection(), 'exact current011 package selection contract')
    need(policy.get('product', {}).get('accepted_main') == '2561dcebee3ba70b924c9c4b42e4316b2994d832'
         and policy['product'].get('package_source_commit') == '446f657723c2e4443f8a3fe8ccbe592ebbaf282b', 'exact Root-merged current package input')
    recipe = policy['recipe']
    need(recipe['archive'] == NAME + '-' + CURRENT011_VERSION + '-any.pkg.tar.zst' and recipe['expected_test_count'] == 91 and (type(recipe['expected_test_count']) is int) and (set(recipe['source_files']) == CURRENT011_SOURCE_FILES) and (len(recipe['payload_files']) == 6), 'exact frozen recipe and finite payload')
    for name, item in recipe['source_files'].items():
        need(Path(name).name == name and _pin_row(item), 'flat pinned frozen recipe source')
    need(recipe['source_files'][CURRENT011_SOURCE_ARCHIVE]['sha256'] == CURRENT011_SOURCE_ARCHIVE_SHA256, 'exact0.1.1 frozen source archive required')
    for name, item in recipe['payload_files'].items():
        need(name.startswith('usr/') and Path(name).as_posix() == name and ('..' not in Path(name).parts) and _pin_row(item), 'pinned six-file package payload')
    current011_update_policy(policy)
    bundle = policy['bundle']
    need(bundle['path'] == 'native/desktop-sources-v1.tar' and bundle['members'] == 5 and (type(bundle['bytes']) is int) and (0 < bundle['bytes'] <= bundle['max_bytes'] <= 1024 ** 2), 'finite five-member source delivery')
    base = ordinary(root / 'native/expected349.lock')
    need(data_pin(base) == {key: policy['expected349'][key] for key in ('bytes', 'sha256')} and len(base.splitlines()) == 349, 'exact genuine349 lock')
    versions = dict((line.decode().split(' ', 1) for line in base.splitlines()))
    need(all((versions.get(name) == version for name, version in policy['dependencies'].items())) and versions.get('python') == '3.14.8-1' and (versions.get('zstd') == '1.5.7-3'), 'exact retained native dependencies')
    need(policy['buildinfo_installed'] == expected_installed(root), 'full349 BUILDINFO architecture/version provenance')
    config_row = policy['makepkg_config']
    need(config_row['path'] == 'native/desktop-makepkg-v1.conf', 'fixed makepkg configuration')
    config = ordinary(root / config_row['path'])
    need(data_pin(config) == {key: config_row[key] for key in ('bytes', 'sha256')} and re.search(b'^BUILDENV=\\([^\\n]*\\bcheck\\b', config, re.M) and (b'!check' not in config) and (b"PKGEXT='.pkg.tar.zst'" in config), 'positive makepkg check policy')
    return (policy, base)

def current011_update_policy(policy):
    """The update is an explicit TEST transaction fixture, never a new product."""
    baseline, update = (policy['recipe'], policy['update_recipe'])
    need(update.get('scope') == UPDATE_FIXTURE and update.get('version') == CURRENT011_UPDATE_VERSION and (update.get('archive') == NAME + '-' + CURRENT011_UPDATE_VERSION + '-any.pkg.tar.zst') and (type(update.get('expected_test_count')) is int) and (update['expected_test_count'] == 91) and (set(update.get('source_files', {})) == CURRENT011_SOURCE_FILES), 'explicit TEST-only update recipe contract')
    for name, item in update['source_files'].items():
        need(_pin_row(item), 'pinned generated update source')
        if name != 'PKGBUILD':
            need(item == baseline['source_files'][name], 'update changes only PKGBUILD')
    need(update.get('payload_files', baseline['payload_files']) == baseline['payload_files'], 'TEST update payload must remain exact original six files')
    return update

def current011_update_generation(policy, members):
    update = current011_update_policy(policy)
    before, after = (members['recipe/PKGBUILD'], members['update/PKGBUILD'])
    need(data_pin(before) == {key: policy['recipe']['source_files']['PKGBUILD'][key] for key in ('bytes', 'sha256')} and data_pin(after) == {key: update['source_files']['PKGBUILD'][key] for key in ('bytes', 'sha256')} and (after == update_recipe_bytes(before)), 'exact one-line generated update recipe proof')
    return dict(scope=UPDATE_FIXTURE, version_from=CURRENT011_VERSION, version_to=CURRENT011_UPDATE_VERSION, source_archive={key: policy['recipe']['source_files'][CURRENT011_SOURCE_ARCHIVE][key] for key in ('bytes', 'sha256')}, recipe_before=data_pin(before), recipe_after=data_pin(after), replacement=dict(before='pkgrel=1\n', after='pkgrel=2\n', count=1), unchanged_payload=True, changed_sources=['PKGBUILD'])

def current011_recipe_members(root, policy):
    raw = ordinary(Path(root) / policy['bundle']['path'], policy['bundle']['max_bytes'])
    need(data_pin(raw) == {key: policy['bundle'][key] for key in ('bytes', 'sha256')}, 'source bundle checksum')
    update = current011_update_policy(policy)
    expected = {'recipe/' + name: item for name, item in policy['recipe']['source_files'].items()}
    expected['update/PKGBUILD'] = update['source_files']['PKGBUILD']
    result = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            need(member.name in expected and member.name not in result and member.isfile() and (not member.pax_headers) and (member.uid == member.gid == member.mtime == 0), 'exact regular source bundle member')
            item = expected[member.name]
            need(member.mode == item['mode'] and member.size == item['bytes'], 'source member size/mode')
            body = archive.extractfile(member).read()
            need(data_pin(body) == {key: item[key] for key in ('bytes', 'sha256')}, 'source member checksum')
            result[member.name] = body
    need(set(result) == set(expected) and len(result) == 5, 'complete five-member recipe/update bundle')
    current011_update_generation(policy, result)
    return result

def current011_extract_recipes(root, destination, policy):
    members = current011_recipe_members(root, policy)
    destination = Path(destination)
    destination.mkdir(mode=493)
    for label in ('a', 'b', 'update'):
        target = destination / label
        target.mkdir(mode=493)
        recipe = policy['update_recipe'] if label == 'update' else policy['recipe']
        for name, item in recipe['source_files'].items():
            with (target / name).open('xb') as stream:
                stream.write(members['update/PKGBUILD' if label == 'update' and name == 'PKGBUILD' else 'recipe/' + name])
            (target / name).chmod(item['mode'])
    return destination

def current011_inventory_expected(base, version=None):
    rows = base.splitlines(keepends=True)
    need(len(rows) == 349 and (not any((line.startswith((NAME + ' ').encode()) for line in rows))), 'project package absent from exact349 base')
    if version is not None:
        need(version in (CURRENT011_VERSION, CURRENT011_UPDATE_VERSION), 'finite baseline or TEST-update version only')
        rows.append((NAME + ' ' + version + '\n').encode())
    return b''.join(sorted(rows))

def current011_check_payload(root, policy, run, pacman, version=CURRENT011_VERSION):
    need(version in (CURRENT011_VERSION, CURRENT011_UPDATE_VERSION), 'finite payload version only')
    expected = policy['recipe']['payload_files']
    for name, item in expected.items():
        path = Path(root) / name
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == info.st_gid == 0 and (stat.S_IMODE(info.st_mode) == item['mode']) and (pin(path) == {key: item[key] for key in ('bytes', 'sha256')}), 'actual ALPM payload bytes/mode/root ownership: ' + name)
        need(run('owner-' + NAME + '-' + version, ['/usr/bin/pacman', *pacman, '-Qoq', str(path)]).strip() == NAME.encode(), 'actual ALPM ownership join')
    listed = run('owned-files-' + NAME + '-' + version, ['/usr/bin/pacman', *pacman, '-Qlq', NAME]).decode().splitlines()
    need(len(listed) == len(set(listed)) and all((name.startswith('/') and '..' not in Path(name).parts and (name.rstrip('/') == Path(name.rstrip('/')).as_posix()) for name in listed)), 'canonical unique ALPM paths')
    files = {name.lstrip('/') for name in listed if not name.endswith('/')}
    directories = {name.lstrip('/').rstrip('/') for name in listed if name.endswith('/')}
    ancestors = {str(parent) for name in expected for parent in Path(name).parents if str(parent) != '.'}
    need(files == set(expected) and directories == ancestors, 'exact ALPM six-file and ancestor directory ownership')
    return dict(version=version, count=6, verified=True, stale_absent=True, files={name: {key: item[key] for key in ('bytes', 'sha256', 'mode')} for name, item in expected.items()})

def current011__archive_data(raw, policy, version=CURRENT011_VERSION):
    need(version in (CURRENT011_VERSION, CURRENT011_UPDATE_VERSION), 'finite archive version only')
    recipe = current011_update_policy(policy) if version == CURRENT011_UPDATE_VERSION else policy['recipe']
    'Decode bounded tar DATA only; exact regular payload and metadata namespace.'
    need(len(raw) <= 2 * 1024 ** 2, 'decoded package byte cap')
    expected = policy['recipe']['payload_files']
    ancestors = {str(parent) for name in expected for parent in Path(name).parents if str(parent) != '.'}
    metadata, payload, directories, seen = ({}, {}, set(), set())
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            name = member.name.rstrip('/')
            need(name not in seen and member.uid == member.gid == 0 and (not member.pax_headers) and (name == Path(name).as_posix()) and ('..' not in Path(name).parts), 'unique canonical root-owned package members')
            seen.add(name)
            if member.isdir():
                need(name in ancestors and member.mode == 493, 'exact package directory mode/namespace')
                directories.add(name)
                continue
            need(member.isfile() and member.size <= 1024 ** 2, 'ordinary finite package member')
            body = archive.extractfile(member).read()
            if name in ('.PKGINFO', '.BUILDINFO', '.MTREE'):
                need(member.mode == 420, 'metadata file mode')
                metadata[name] = body
            else:
                need(name in expected, 'unexpected package payload or install script')
                item = expected[name]
                need(member.mode == item['mode'] and data_pin(body) == {key: item[key] for key in ('bytes', 'sha256')}, 'exact package payload bytes/mode')
                payload[name] = dict(mode=member.mode, **data_pin(body))
    need(set(payload) == set(expected) and directories == ancestors and (set(metadata) == {'.PKGINFO', '.BUILDINFO', '.MTREE'}), 'complete finite package payload/metadata/directory sets')
    pkg = _metadata(metadata['.PKGINFO'])
    build = _metadata(metadata['.BUILDINFO'])
    for key, expected_value in (('pkgname', NAME), ('pkgbase', NAME), ('pkgver', version), ('arch', 'any')):
        need(pkg.get(key) == [expected_value], 'exact PKGINFO ' + key)
    need(pkg.get('license') == ['MIT'] and pkg.get('depend') == ['python>=3.11'], 'exact package license/runtime dependency')
    for key, expected_value in (('format', '2'), ('pkgname', NAME), ('pkgbase', NAME), ('pkgver', version), ('pkgarch', 'any'), ('pkgbuild_sha256sum', recipe['source_files']['PKGBUILD']['sha256'])):
        need(build.get(key) == [expected_value], 'exact BUILDINFO ' + key)
    installed = build.get('installed', [])
    need(len(installed) == 349 and len(set(installed)) == 349 and (sorted(installed) == policy['buildinfo_installed']), 'all349 exact native dependency provenance rows required')
    need('check' in build.get('buildenv', []) and '!check' not in build['buildenv'], 'actual positive buildenv check')
    return dict(metadata=metadata, payload=payload)

def current011_compare_archives(run, archives, policy, source_map_hash):
    need(set(archives) == {'a', 'b'} and re.fullmatch('[0-9a-f]{64}', source_map_hash or ''), 'exact native pair/source map')
    decoded, builds = ({}, {})
    archive_bodies = {}
    for label in ('a', 'b'):
        path = Path(archives[label])
        archive_bodies[label] = ordinary(path, 1024 ** 2)
        raw = run('archive-' + label, ['/usr/bin/zstd', '-dc', str(path)])
        decoded[label] = current011__archive_data(raw, policy)
        data = decoded[label]
        builds[label] = dict(archive=data_pin(archive_bodies[label]), pkginfo=data_pin(data['metadata']['.PKGINFO']), buildinfo=data_pin(data['metadata']['.BUILDINFO']), mtree=data_pin(data['metadata']['.MTREE']), payload=data['payload'])
    need(archive_bodies['a'] == archive_bodies['b'], 'two clean native package archive bytes differ')
    need(decoded['a'] == decoded['b'], 'two clean native payload/metadata differ')
    data = decoded['a']
    return dict(status='PASS_EXACT_NATIVE_BUILD_PAIR', archive=data_pin(archive_bodies['a']), builds=builds, equality=dict(archive=True, payload=True, pkginfo=True, buildinfo=True, mtree=True), payload_files=6, base_inventory_count=349, source_map_sha256=source_map_hash, pkgbuild_sha256=policy['recipe']['source_files']['PKGBUILD']['sha256'], pkginfo_text=data['metadata']['.PKGINFO'].decode(), buildinfo_text=data['metadata']['.BUILDINFO'].decode(), mtree_base64=base64.b64encode(data['metadata']['.MTREE']).decode('ascii'))

def current011_compare_update(run, archive, policy, source_map_hash):
    need(re.fullmatch('[0-9a-f]{64}', source_map_hash or ''), 'exact update Source map')
    path = Path(archive)
    body = ordinary(path, 1024 ** 2)
    raw = run('archive-update', ['/usr/bin/zstd', '-dc', str(path)])
    data = current011__archive_data(raw, policy, CURRENT011_UPDATE_VERSION)
    return dict(status='PASS_TEST_LIFECYCLE_UPDATE_ARCHIVE', fixture=UPDATE_FIXTURE, version=CURRENT011_UPDATE_VERSION, archive=data_pin(body), pkginfo=data_pin(data['metadata']['.PKGINFO']), buildinfo=data_pin(data['metadata']['.BUILDINFO']), mtree=data_pin(data['metadata']['.MTREE']), payload=data['payload'], pkginfo_text=data['metadata']['.PKGINFO'].decode(), buildinfo_text=data['metadata']['.BUILDINFO'].decode(), mtree_base64=base64.b64encode(data['metadata']['.MTREE']).decode('ascii'), source_map_sha256=source_map_hash, pkgbuild_sha256=policy['update_recipe']['source_files']['PKGBUILD']['sha256'], base_inventory_count=349)

def current011_business(run, cli, root, uid, gid, label, version=CURRENT011_VERSION):
    """Future actual installed CLI checks; every staged command remains inert."""
    need(version in (CURRENT011_VERSION, CURRENT011_UPDATE_VERSION), 'finite business package version only')
    root = Path(root)
    root.mkdir(mode=493)
    staged = root / 'staged-root'
    staged.mkdir()
    marker = root / 'MUST-NOT-EXIST'

    def put(name, raw, mode=420):
        path = staged / name.lstrip('/')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw.encode() if isinstance(raw, str) else raw)
        path.chmod(mode)
    put('/usr/bin/tool', '#!/usr/bin/interpreter\ntouch ' + str(marker) + '\n', 493)
    put('/usr/bin/interpreter', _elf(), 493)
    put('/usr/bin/terminal', _elf(), 493)
    (staged / 'usr/bin/tool-link').symlink_to('/usr/bin/tool')
    put('/usr/share/applications/tool.desktop', '[Desktop Entry]\nType=Application\nName=Original Offline Fixture\nExec=tool-link %F\nTryExec=tool\nTerminal=true\nNoDisplay=true\nIcon=fixture\nMimeType=text/plain;\n')
    put('/usr/share/icons/hicolor/index.theme', '[Icon Theme]\nName=Hicolor\nComment=Original fixture\nDirectories=48x48/apps\n[48x48/apps]\nSize=48\nType=Fixed\n')
    put('/usr/share/icons/hicolor/48x48/apps/fixture.png', b'INERT ORIGINAL ICON DATA')
    put('/etc/xdg/mimeapps.list', '[Default Applications]\ntext/plain=tool.desktop;\n')
    env = dict(HOME='/home/fixture', XDG_DATA_HOME='/home/fixture/.local/share', XDG_DATA_DIRS='/usr/local/share:/usr/share', XDG_CONFIG_HOME='/home/fixture/.config', XDG_CONFIG_DIRS='/etc/xdg', XDG_CURRENT_DESKTOP='Hyprland', PATH='/usr/local/bin:/usr/bin', icon_theme='hicolor', icon_size=48, icon_scale=1, terminal_argv=['terminal', '-e'], locale='C')
    environment = root / 'environment.json'
    environment.write_bytes(encoded(env))
    _own_tree(root, uid, gid)
    reports, steps = ({}, {})

    def command(key, operation, extra=(), expected=0):
        step = label + '-' + key.replace('_', '-')
        args = ['--root', str(staged), '--environment', str(environment), '--select', 'tool.desktop', '--mime', 'text/plain']
        argv = ['/usr/bin/runuser', '-u', 'alarm', '--', '/usr/bin/env', 'HOME=' + str(root), str(cli), operation, *args, *map(str, extra)]
        raw = run(step, argv, expected, cwd=root)
        need(not os.path.lexists(marker), 'no desktop fixture command may execute')
        reports[key] = data_pin(raw)
        steps[key] = step
        return (raw, json.loads(raw))
    raw, inventory = command('capture', 'capture')
    need(inventory.get('kind') == 'cachy-asahi-desktop-static-inventory-v1' and inventory.get('selected') == ['tool.desktop'] and (inventory.get('mime') == ['text/plain']) and (inventory.get('environment') == pin(environment)), 'actual captured static inventory')
    inventory_path = root / 'inventory.json'
    inventory_path.write_bytes(raw)
    inventory_path.chmod(420)
    os.chown(inventory_path, uid, gid)
    inventory_pin = data_pin(raw)
    extra = ['--inventory', str(inventory_path), '--inventory-sha256', inventory_pin['sha256']]
    _, audited = command('audit', 'audit', extra)
    need(audited.get('status') == 'PASS_STAGED_CHECKS' and audited.get('inventory_binding') == 'EXACT_STATIC_INVENTORY' and (audited.get('inventory_input') == inventory_pin), 'actual installed static audit with exact inventory')
    moved = root / 'moved-staged-root'
    staged.rename(moved)
    staged = moved
    _, relocated = command('moved_root', 'audit', extra)
    need(relocated.get('status') == 'PASS_STAGED_CHECKS' and relocated.get('inventory_binding') == 'EXACT_STATIC_INVENTORY' and (relocated.get('pins') == audited.get('pins')), 'moved staged-root exact bindings')
    (staged / 'usr/share/icons/hicolor/48x48/apps/fixture.png').write_bytes(b'CHANGED ORIGINAL ICON DATA')
    _, refused = command('changed_data', 'audit', extra, 2)
    need(refused.get('status') == 'REFUSED' and 'staged inventory differs' in refused.get('error', ''), 'actual changed-data refusal required')
    need(not list(root.rglob('__pycache__')), 'no generated bytecode cache in caller fixtures')
    result = dict(status='PASS_ACTUAL_STATIC_CAPTURE_AUDIT_REFUSAL', cli=str(cli), synthetic=True, version=version, payload_cli_version='0.1.1', inventory=inventory_pin, environment=pin(environment), selected=['tool.desktop'], mime=['text/plain'], reports=reports, steps=steps, baseline_status='PASS_STAGED_CHECKS', moved_root_status='PASS_STAGED_CHECKS', changed_data_status='REFUSED', changed_data_exit=2, zero_payload_execution=True, fixture_snapshot=snapshot_receipt(root), release='NOT_ADMITTED')
    if version == CURRENT011_UPDATE_VERSION:
        result['fixture'] = UPDATE_FIXTURE
    # Fresh user override probes bind the actual installed current CLI only.
    put('/usr/bin/env', _elf(), 0o755)
    put('/usr/share/icons/hicolor/48x48/apps/fixture.png', b'INERT ORIGINAL ICON DATA')
    override_logical = env['XDG_DATA_HOME'] + '/applications/tool.desktop'
    override = staged / override_logical.lstrip('/')
    def override_exec(command_text):
        put(override_logical, '[Desktop Entry]\nType=Application\nName=Current user override\nExec=' + command_text + '\nTryExec=tool\nTerminal=true\nNoDisplay=true\nIcon=fixture\nMimeType=text/plain;\n')
        _own_tree(root, uid, gid)
    override_exec('env --unset=WAYLAND_DISPLAY tool-link %F')
    override_before = pin(override)
    env_raw, env_inventory = command('env_unset_capture', 'capture')
    need(env_inventory.get('kind') == 'cachy-asahi-desktop-static-inventory-v1', 'actual current env-unset inventory')
    env_path = root / 'env-unset-inventory.json'
    env_path.write_bytes(env_raw); env_path.chmod(0o644); os.chown(env_path, uid, gid)
    env_pin = data_pin(env_raw)
    env_extra = ['--inventory', str(env_path), '--inventory-sha256', env_pin['sha256']]
    _, env_audit = command('env_unset_audit', 'audit', env_extra)
    app = env_audit['applications'][0]
    need(env_audit.get('status') == 'PASS_STAGED_CHECKS' and env_audit.get('inventory_input') == env_pin
         and app.get('origin') == 'user_override'
         and app['exec']['resolution']['env_target']['file']['path'] == '/usr/bin/tool-link', 'equals-form user override actual audit')
    override_after = pin(override)
    need(override_after == override_before, 'static current audit preserves user override bytes')
    override_exec('env --unset=PATH tool-link %F')
    _, path_refusal = command('env_unset_path_refusal', 'capture', expected=1)
    need(path_refusal.get('status') == 'FAIL_STAGED_CHECKS'
         and 'PATH unset' in path_refusal['applications'][0]['exec']['resolution']['env_target'].get('error', ''), 'no inferred PATH after unset')
    override_exec('env --unset=PATH /usr/bin/tool-link %F')
    _, absolute_inventory = command('env_unset_absolute_capture', 'capture')
    need(absolute_inventory.get('kind') == 'cachy-asahi-desktop-static-inventory-v1', 'absolute current env-unset capture')
    override_exec('env --unset=PATH PATH=/usr/bin tool-link %F')
    _, restored_inventory = command('env_unset_restored_capture', 'capture')
    need(restored_inventory.get('kind') == 'cachy-asahi-desktop-static-inventory-v1', 'explicit PATH restoration capture')
    override_exec('env --unset= tool-link %F')
    _, malformed = command('env_unset_malformed_refusal', 'capture', expected=1)
    need(malformed.get('status') == 'FAIL_STAGED_CHECKS'
         and malformed['applications'][0]['exec']['resolution']['env_target'].get('error') == 'invalid env unset variable', 'malformed equals-form name refusal')
    keys = ('env_unset_capture', 'env_unset_audit', 'env_unset_path_refusal', 'env_unset_absolute_capture', 'env_unset_restored_capture', 'env_unset_malformed_refusal')
    result['env_unset'] = dict(schema=1, selection='GNU_ENV_UNSET_EQUALS_BOUNDED', inventory=env_pin,
        inventory_leaf='env-unset-inventory.json', override_logical=override_logical,
        override_before=override_before, override_after=override_after, override_preserved=True,
        reports={key: reports.pop(key) for key in keys}, steps={key: steps.pop(key) for key in keys},
        checks=dict(long_form='PASS_STAGED_CHECKS', path_basename='FAIL_STAGED_CHECKS',
                    absolute='PASS_CAPTURE_INVENTORY', restored='PASS_CAPTURE_INVENTORY', malformed='FAIL_STAGED_CHECKS'),
        zero_payload_execution=True)
    result['fixture_snapshot'] = snapshot_receipt(root)
    return result


def current011_package_selection():
    return dict(schema=1, selection='desktop-current011', version=CURRENT011_VERSION,
                update_version=CURRENT011_UPDATE_VERSION, source_archive_sha256=CURRENT011_SOURCE_ARCHIVE_SHA256,
                expected_test_count=91)


class _Current011:
    OPERATION = OPERATION
    NAME = NAME
    VERSION = CURRENT011_VERSION
    UPDATE_VERSION = CURRENT011_UPDATE_VERSION
    UPDATE_FIXTURE = UPDATE_FIXTURE
    PREFIX = PREFIX
    SOURCE = SOURCE
    STORE = STORE
    STAGES = STAGES
    SOURCE_ARCHIVE = CURRENT011_SOURCE_ARCHIVE
    SOURCE_ARCHIVE_SHA256 = CURRENT011_SOURCE_ARCHIVE_SHA256
    SOURCE_FILES = CURRENT011_SOURCE_FILES
    need = staticmethod(need)
    encoded = staticmethod(encoded)
    data_pin = staticmethod(data_pin)
    ordinary = staticmethod(ordinary)
    pin = staticmethod(pin)
    _pin_row = staticmethod(_pin_row)
    expected_installed = staticmethod(expected_installed)
    source_policy = staticmethod(current011_source_policy)
    update_policy = staticmethod(current011_update_policy)
    update_recipe_bytes = staticmethod(update_recipe_bytes)
    update_generation = staticmethod(current011_update_generation)
    recipe_members = staticmethod(current011_recipe_members)
    extract_recipes = staticmethod(current011_extract_recipes)
    load_workflow = staticmethod(load_workflow)
    inventory_expected = staticmethod(current011_inventory_expected)
    snapshot = staticmethod(snapshot)
    snapshot_receipt = staticmethod(snapshot_receipt)
    check_payload = staticmethod(current011_check_payload)
    _metadata = staticmethod(_metadata)
    _archive_data = staticmethod(current011__archive_data)
    compare_archives = staticmethod(current011_compare_archives)
    compare_update = staticmethod(current011_compare_update)
    _elf = staticmethod(_elf)
    _own_tree = staticmethod(_own_tree)
    business = staticmethod(current011_business)
    package_selection = staticmethod(current011_package_selection)


def current011_namespace():
    """The single reviewed current package family; no caller-supplied versions."""
    return _Current011
