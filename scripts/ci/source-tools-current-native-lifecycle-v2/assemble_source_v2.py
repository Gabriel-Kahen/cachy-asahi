#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Assemble one exact closed native Source from retained, verified DATA.

No source operand is imported, evaluated, built, fetched or installed. A native
run remains a separate Root action after actual Git publication and binding.
"""
import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
import io
import tarfile

HERE = Path(__file__).resolve().parent
GENUINE_PARENT = '419d27f1d519dc91789a322385eb603bd1ca1f09'
PARENT_TREE = 'ee92fee27e320016c151de1abd4ea529508255a4'
PARENT_MAP_SHA256 = '11ec9193b418c922d8e63889795cb4fafa01e309328cff93f70e68560f5a5adf'
PRIVATE_SHA256 = 'fa9db2ee4a6f16fee53b79494d437901570c80798de9219d2cc637b9f430575a'
PROVENANCE_SHA256 = '28b2b8a2708bc3fece91d5560b17da358b59937d4afcebf5a42be28a1802b042'
OPERATION = 'source-tools-alpm-v2'
MAX_FILE, MAX_TOTAL, MAX_FILES = 64 * 1024**2, 128 * 1024**2, 256
MAP = 'native/source-map.json'
SEAMS = frozenset((MAP, 'native/common.py', 'native/owner.py', 'native/invocation.json',
    '.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-developer-workflows.yml'))
ADDITIONS = frozenset('native/' + name for name in (
    'source_tools_alpm_v2.py', 'source_tools_tools_v2.py', 'source_tools_guest_v2.py',
    'source_tools_probe_v2.py', 'source_tools_reader_v2.py', 'source_tools_projection_v2.py',
    'source_tools_current_check_v2.py', 'source_tools_current_package_v2.py',
    'source-tools-contract-v2.json', 'source-tools-makepkg-v2.conf', 'source-tools-sources-v2.tar',
    'source-tools-producers-v2.json'))
PRODUCERS = ADDITIONS - frozenset(('native/source_tools_reader_v2.py',
    'native/source_tools_projection_v2.py', 'native/source-tools-producers-v2.json'))
FIELDS = frozenset(('schema', 'purpose', 'genuine_parent', 'parent_tree', 'parent_files',
    'overlay', 'source_map_sha256', 'prospective_tree', 'operation', 'actual', 'main_base', 'source_files'))
RECIPE_FILES = frozenset(('PKGBUILD', '.SRCINFO', 'private-source.tar.gz', 'fixtures.tar.gz',
    'cachy-asahi-source-tools', 'check_package.py', 'test_package.py', 'multi_package_roundtrip.py',
    'README.md', 'source-provenance.json', 'payload-map.json', 'NOTICE', 'LICENSE',
    'test_cli_input_refusal.py', 'source_mirror_catalog.py', 'test_source_mirror_catalog.py'))
CHECKS = dict(cli_tests=9, duplicate_cases=132, catalog_tests=9, catalog_contexts=4,
    original_workflow_controls=17, private_helpers=11, payload_files=18)
WORKFLOWS = ('.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-developer-workflows.yml')
COMMON_BEFORE = b"rows = manifest['files']; need(MAP not in rows and len(rows) <= 200, 'finite nonrecursive source map')"
COMMON_AFTER = b"rows = manifest['files']; need(MAP not in rows and (len(rows) == 211 if manifest.get('source_tools_operation') == 'source-tools-alpm-v2' else len(rows) <= 200), 'finite nonrecursive source map')"



def need(ok, message):
    if not ok:
        raise ValueError(message)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def oid(kind, raw):
    return hashlib.sha1(kind + b' ' + str(len(raw)).encode() + b'\0' + raw).digest()


def absolute(path):
    path = Path(path)
    need(path.is_absolute() and path.anchor == '/' and '..' not in path.parts, 'canonical absolute path required')
    return path


def relative(name):
    need(type(name) is str and 0 < len(name) <= 240 and '\\' not in name, 'bounded relative source path required')
    path = PurePosixPath(name)
    need(not path.is_absolute() and path.as_posix() == name and len(path.parts) <= 16 and
         all(part not in ('.', '..') and re.fullmatch(r'[A-Za-z0-9._+-]+', part) for part in path.parts), 'unsafe source path')
    return path


def decode(raw):
    need(len(raw) <= 1024**2, 'profile/manifest JSON cap')
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    def invalid(_):
        raise ValueError('noninteger/nonfinite JSON refused')
    value = json.loads(raw, object_pairs_hook=pairs, parse_float=invalid, parse_constant=invalid)
    need(type(value) is dict, 'JSON object required')
    return value


def directory(path):
    path = absolute(path)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def identity(info):
    return tuple(getattr(info, key) for key in ('st_dev', 'st_ino', 'st_mode', 'st_nlink',
        'st_uid', 'st_gid', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def read_at(parent, leaf, cap):
    fd = os.open(leaf, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= cap,
             'bounded regular single-link source required')
        chunks, size = [], 0
        while block := os.read(fd, min(65536, cap + 1 - size)):
            chunks.append(block); size += len(block)
            need(size <= cap, 'source file byte cap')
        need(size == before.st_size and identity(before) == identity(os.fstat(fd)) ==
             identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)), 'source changed while reading')
        return b''.join(chunks), stat.S_IMODE(before.st_mode)
    finally:
        os.close(fd)


def read(path, cap=MAX_FILE):
    path = absolute(path); fd = directory(path.parent)
    try:
        return read_at(fd, path.name, cap)
    finally:
        os.close(fd)


def snapshot(root):
    """Descriptor-relative finite regular tree; no symlinks or empty directories."""
    files, dirs, total = {}, set(), 0
    fd = directory(root)
    def walk(parent, prefix=''):
        nonlocal total
        before = os.fstat(parent)
        for leaf in sorted(os.listdir(parent)):
            name = prefix + leaf; relative(name)
            info = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
            need(len(files) + len(dirs) < MAX_FILES * 4, 'source node cap')
            if stat.S_ISDIR(info.st_mode):
                dirs.add(name)
                child = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    need(identity(info) == identity(os.fstat(child)), 'source directory changed before read')
                    walk(child, name + '/')
                    need(identity(info) == identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)), 'source directory changed after read')
                finally:
                    os.close(child)
            else:
                need(len(files) < MAX_FILES and stat.S_ISREG(info.st_mode), 'source aliases/special files refused')
                raw, mode = read_at(parent, leaf, min(MAX_FILE, MAX_TOTAL - total))
                need(mode in (0o600, 0o644, 0o700, 0o755), 'source file mode must be canonical or private equivalent')
                mode = 0o755 if mode in (0o700, 0o755) else 0o644
                total += len(raw); need(total <= MAX_TOTAL, 'source aggregate cap')
                files[name] = (raw, mode)
        need(identity(before) == identity(os.fstat(parent)), 'source directory changed during scan')
    try:
        walk(fd)
    finally:
        os.close(fd)
    wanted = {str(parent) for name in files for parent in PurePosixPath(name).parents if str(parent) != '.'}
    need(dirs == wanted, 'empty or unrecorded source directory refused')
    return files


def descriptors(files):
    return {name: dict(**pin(raw), mode=mode) for name, (raw, mode) in files.items()}


def tree(files):
    nodes = {}
    for name, value in files.items():
        path = relative(name); target = nodes
        for part in path.parts[:-1]:
            target = target.setdefault(part, {})
            need(type(target) is dict, 'source file/directory collision')
        need(path.name not in target, 'source file/directory collision')
        target[path.name] = value
    def body(node):
        raw = b''
        for name, value in sorted(node.items(), key=lambda row: row[0].encode() + (b'/' if type(row[1]) is dict else b'')):
            if type(value) is dict:
                mode, digest = b'40000', body(value)
            else:
                data, mode_value = value
                mode, digest = (b'100755' if mode_value == 0o755 else b'100644'), oid(b'blob', data)
            raw += mode + b' ' + name.encode() + b'\0' + digest
        return oid(b'tree', raw)
    return body(nodes).hex()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def source_rows(rows, count):
    need(type(rows) is dict and len(rows) == count, 'exact finite source row count required')
    for name, row in rows.items():
        relative(name)
        need(type(row) is dict and set(row) == {'bytes', 'sha256', 'mode'}
             and type(row['bytes']) is int and 0 < row['bytes'] <= MAX_FILE
             and type(row['mode']) is int and row['mode'] in (0o644, 0o755)
             and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']),
             'finite typed source descriptor required')
    need(sum(row['bytes'] for row in rows.values()) <= MAX_TOTAL, 'source profile aggregate cap')


def profile(raw, checksum):
    need(type(checksum) is str and re.fullmatch('[0-9a-f]{64}', checksum)
         and pin(raw)['sha256'] == checksum, 'caller-authenticated profile checksum differs')
    value = decode(raw)
    need(set(value) == FIELDS and type(value['schema']) is int and value['schema'] == 1
         and value['purpose'] == 'source-tools-current-native-overlay-v2'
         and value['genuine_parent'] == GENUINE_PARENT and value['parent_tree'] == PARENT_TREE
         and value['operation'] == OPERATION and type(value['source_files']) is int
         and value['source_files'] == 212 and value['actual'] == dict(source=None, ref=None, run=None),
         'exact unexecuted v2 overlay identity required')
    source_rows(value['parent_files'], 200)
    source_rows(value['overlay'], 18)
    need(set(value['overlay']) == SEAMS | ADDITIONS and SEAMS <= set(value['parent_files'])
         and not ADDITIONS.intersection(value['parent_files']), 'only six seams and twelve additions allowed')
    need(all(row['mode'] == 0o644 for row in value['overlay'].values()), 'v2 route operands stay non-executable DATA')
    for name, size in (('source_map_sha256', 64), ('prospective_tree', 40), ('main_base', 40)):
        need(type(value[name]) is str and re.fullmatch('[0-9a-f]{%d}' % size, value[name]),
             'typed source/profile identity required: ' + name)
    return value


def check_row_bound(manifest):
    rows = manifest['files']
    need(type(rows) is dict and MAP not in rows
         and (len(rows) == 211 if manifest.get('source_tools_operation') == OPERATION else len(rows) <= 200),
         'legacy map cap200 or exact explicit v2 map211 required')


def check_manifest(files, expected_hash, count):
    need(len(files) == count and sum(len(raw) for raw, _ in files.values()) <= MAX_TOTAL,
         'closed Source file/byte count differs')
    need(pin(files[MAP][0])['sha256'] == expected_hash, 'source map checksum differs')
    manifest = decode(files[MAP][0])
    check_row_bound(manifest)
    need(manifest.get('schema') == 1 and type(manifest['schema']) is int
         and manifest.get('actual') == dict(source=None, ref=None, run=None)
         and manifest.get('files') == {name: row for name, row in descriptors(files).items() if name != MAP}
         and len(manifest['files']) == count-1, 'whole source map and NULL actuals required')
    need((manifest.get('source_tools_operation') == OPERATION) == (count == 212), 'explicit v2 source map marker')
    return manifest


def check_contract(files):
    value = decode(files['native/source-tools-contract-v2.json'][0])
    need(value.get('schema') == 1 and type(value['schema']) is int and value.get('operation') == OPERATION
         and value.get('actual') == dict(source=None, ref=None, run=None, job=None, artifact=None),
         'v2 native contract and NULL selectors required')
    recipe = value['recipe']
    need(recipe['version'] == '0.2.0-1' and recipe['archive'] == 'cachy-asahi-source-tools-0.2.0-1-any.pkg.tar.zst'
         and type(recipe['expected_test_count']) is int and recipe['expected_test_count'] == 28
         and set(recipe['source_files']) == RECIPE_FILES and len(recipe['payload_files']) == 18,
         'exact current recipe/version/business and payload counts required')
    source_rows(recipe['source_files'], 16)
    source_rows(recipe['payload_files'], 18)
    need(value.get('checks') == CHECKS and all(type(n) is int for n in value['checks'].values()),
         'exact current CLI/catalog/original check counts required')
    need(recipe['source_files']['private-source.tar.gz']['sha256'] == PRIVATE_SHA256
         and recipe['source_files']['source-provenance.json']['sha256'] == PROVENANCE_SHA256,
         'frozen private11/archive provenance identity required')
    selection = value['current_recipe_selection']
    need(selection.get('schema') == 2 and selection.get('purpose') == 'source-tools-current-recipe-selection'
         and selection['package'] == dict(name='cachy-asahi-source-tools', version='0.2.0-1', arch='any', license='MIT')
         and selection['recipe']['files'] == recipe['source_files']
         and selection['recipe']['payload_files'] == recipe['payload_files']
         and selection['checks'] == CHECKS and len(selection['recipe']['sources']) == 14
         and set(selection['recipe']['sources']) | {'PKGBUILD', '.SRCINFO'} == RECIPE_FILES,
         'complete current package selection binding required')
    bundle = value['bundle']; raw, mode = files['native/source-tools-sources-v2.tar']
    need(bundle['path'] == 'native/source-tools-sources-v2.tar' and bundle['members'] == 16
         and type(bundle['members']) is int and type(bundle['max_bytes']) is int
         and len(raw) <= bundle['max_bytes'] <= MAX_FILE and mode == 0o644
         and pin(raw) == {key: bundle[key] for key in ('bytes', 'sha256')}, 'finite exact16 recipe bundle')
    seen = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            need(member.name.startswith('recipe/') and member.isfile() and not member.pax_headers
                 and member.uid == member.gid == member.mtime == 0, 'ordinary canonical recipe member')
            name = member.name.removeprefix('recipe/')
            need(name in RECIPE_FILES and name not in seen, 'exact unique current recipe namespace')
            row = recipe['source_files'][name]
            need(member.size == row['bytes'] and member.mode == row['mode'], 'recipe member mode/size')
            body = archive.extractfile(member).read()
            need(pin(body) == {key: row[key] for key in ('bytes', 'sha256')}, 'recipe member pin differs')
            seen[name] = body
    need(set(seen) == RECIPE_FILES, 'complete sixteen-file package bundle required')
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(seen):
            body = seen[name]; member = tarfile.TarInfo('recipe/' + name)
            member.size = len(body); member.mode = recipe['source_files'][name]['mode']
            member.uid = member.gid = member.mtime = 0
            archive.addfile(member, io.BytesIO(body))
    need(output.getvalue() == raw, 'canonical uncompressed USTAR bytes required')
    mapping = decode(seen['payload-map.json']); own = 'usr/share/doc/cachy-asahi-source-tools/payload-map.json'
    need(mapping.get('schema_version') == 1 and type(mapping['schema_version']) is int
         and mapping.get('package') == 'cachy-asahi-source-tools' and mapping.get('self') == own
         and {**mapping['files'], own: dict(**pin(seen['payload-map.json']), mode=0o644)} == recipe['payload_files']
         and recipe['payload_files']['usr/bin/cachy-asahi-source-tools'] ==
             dict(**pin(seen['cachy-asahi-source-tools']), mode=0o755)
         and recipe['payload_files']['usr/lib/cachy-asahi/source-tools/scripts/release/source_mirror_catalog.py'] ==
             dict(**pin(seen['source_mirror_catalog.py']), mode=0o644), 'complete current payload-map body binding')
    for field, path in (('current_package_module', 'native/source_tools_current_package_v2.py'),
                        ('current_check_module', 'native/source_tools_current_check_v2.py')):
        descriptor = value[field]
        need(descriptor['path'] == path and files[path][1] == 0o644
             and {key: descriptor[key] for key in ('bytes', 'sha256')} == pin(files[path][0]),
             'exact current package/check DATA module required')
    config = value['makepkg_config']; body, mode = files['native/source-tools-makepkg-v2.conf']
    need(config['path'] == 'native/source-tools-makepkg-v2.conf' and mode == 0o644
         and {key: config[key] for key in ('bytes', 'sha256')} == pin(body)
         and b'BUILDENV=(!distcc !color !ccache check !sign)' in body and b'!check' not in body,
         'positive makepkg check policy required')
    producers = decode(files['native/source-tools-producers-v2.json'][0])
    need(set(producers) == {'schema', 'purpose', 'files'} and type(producers['schema']) is int
         and producers['schema'] == 1 and producers['purpose'] == 'source-tools-current-producer-pins'
         and producers['files'] == {name: dict(**pin(files[name][0]), mode=files[name][1]) for name in PRODUCERS}
         and len(producers['files']) == 9 and all(row['mode'] == 0o644 for row in producers['files'].values()),
         'noncircular exact nine-producer body/mode map required')
    return value


def check_route(parent, files):
    """Keep all v1 invocation semantics and every workflow byte except v2 enum."""
    before = decode(parent['native/invocation.json'][0])
    after = decode(files['native/invocation.json'][0])
    need({key: value for key, value in before.items() if key != 'operations'} ==
         {key: value for key, value in after.items() if key != 'operations'}, 'held invocation fields changed')
    need(set(after['operations']) == set(before['operations']) | {OPERATION}
         and all(after['operations'][name] == row for name, row in before['operations'].items()),
         'v1 invocation routes must remain held')
    route = after['operations'][OPERATION]
    need(route.get('actual') == dict(source=None, ref=None, run=None)
         and route.get('argv_extra') == ['--operation', OPERATION]
         and route.get('matching_reader') == 'native/source_tools_reader_v2.py'
         and type(route.get('prerequisite')) is str and route['prerequisite'], 'explicit NULL v2 invocation/reader route')
    common, mode = parent['native/common.py']
    need(common.count(COMMON_BEFORE) == 1 and files['native/common.py'] == (common.replace(COMMON_BEFORE, COMMON_AFTER, 1), mode),
         'only exact v2 namespace bound may change; legacy/runtime/HTTP/member caps held')
    old = b'options: [source184, source-tools-alpm-v1]'
    new = b'options: [source184, source-tools-alpm-v1, source-tools-alpm-v2]'
    need(parent[WORKFLOWS[0]] == parent[WORKFLOWS[1]] and files[WORKFLOWS[0]] == files[WORKFLOWS[1]],
         'native workflow aliases differ')
    for name in WORKFLOWS:
        raw, mode = parent[name]
        old_common = pin(common)['sha256'].encode()
        new_common = pin(files['native/common.py'][0])['sha256'].encode()
        need(raw.count(old) == 1 and raw.count(old_common) == 1
             and files[name] == (raw.replace(old, new, 1).replace(old_common, new_common, 1), mode),
             'only v2 workflow choice/common proof may change; group/caps/service bytes held')


def check_final(files, policy):
    check_manifest(files, policy['source_map_sha256'], 212)
    check_contract(files)
    need(tree(files) == policy['prospective_tree'], 'prospective closed Source tree differs')


def validate_delta(parent, overlay, policy):
    """Validate only DATA maps; no output tree or process is created."""
    need(descriptors(parent) == policy['parent_files'] and tree(parent) == policy['parent_tree']
         and policy['parent_tree'] == PARENT_TREE, 'full frozen419 parent bytes/modes/tree differ')
    check_manifest(parent, PARENT_MAP_SHA256, 200)
    need(set(overlay) == SEAMS | ADDITIONS and descriptors(overlay) == policy['overlay'],
         'exact18 overlay bytes/modes/namespace differ')
    files = dict(parent); files.update(overlay)
    need(len(files) == 212 and set(files) == set(parent) | ADDITIONS
         and all(files[name] == value for name, value in parent.items() if name not in SEAMS),
         'all frozen v1/unlisted parent identities must stay held')
    check_route(parent, files)
    check_final(files, policy)
    return files


def parent_commit(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 16384
         and oid(b'commit', raw).hex() == GENUINE_PARENT, 'retained raw genuine419 commit differs')
    headers = raw.split(b'\n\n', 1)[0].splitlines()
    need([line[5:].decode() for line in headers if line.startswith(b'tree ')] == [PARENT_TREE],
         'single retained genuine419 physical tree required')


def publish(files, output):
    """Root-only construction: fresh staging and atomic no-replace publication."""
    output = absolute(output)
    need(output != Path('/') and output.name not in ('', '.', '..'), 'fresh output child required')
    parent = directory(output.parent); staging = None
    try:
        info = os.fstat(parent)
        need(info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o022,
             'owned output parent without group/world writes required')
        try:
            os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError('fresh absent output required')
        staging = Path(tempfile.mkdtemp(prefix='.source-tools-v2-stage-', dir=output.parent))
        held = staging.lstat()
        for name, (raw, mode) in sorted(files.items()):
            target = staging / relative(name)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno()); os.fchmod(stream.fileno(), mode)
        need(snapshot(staging) == files, 'written Source differs before publication')
        need(identity(staging.lstat())[:2] == identity(held)[:2], 'owned staging root identity changed')
        libc = ctypes.CDLL(None, use_errno=True)
        rename = libc.renameat2
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        if rename(parent, os.fsencode(staging.name), parent, os.fsencode(output.name), 1):
            error = ctypes.get_errno()
            if error == errno.EEXIST:
                raise ValueError('fresh absent output required')
            raise OSError(error, os.strerror(error))
        staging = None
    finally:
        if staging is not None and staging.exists():
            need(identity(staging.lstat())[:2] == identity(held)[:2], 'unowned staging cleanup refused')
            shutil.rmtree(staging)
        os.close(parent)


def assemble(parent_source, raw_parent_commit, profile_path, profile_sha256, output):
    """Root alone may invoke this genuine Source constructor after review."""
    parent_source, output = absolute(parent_source), absolute(output)
    need(not output.is_relative_to(parent_source) and not parent_source.is_relative_to(output),
         'retained frozen parent and fresh output must be disjoint')
    raw, _ = read(profile_path, 1024**2); policy = profile(raw, profile_sha256)
    raw_parent, _ = read(raw_parent_commit, 16384); parent_commit(raw_parent)
    parent = snapshot(parent_source)
    overlay = snapshot(absolute(profile_path).parent / 'overlay')
    files = validate_delta(parent, overlay, policy)
    publish(files, output)
    return dict(status='ASSEMBLED_EXACT_CLOSED_SOURCE_DATA_ONLY', source_files=212, source_map_rows=211,
        source_map_sha256=policy['source_map_sha256'], prospective_tree=policy['prospective_tree'],
        genuine_parent=GENUINE_PARENT, main_base=policy['main_base'], operation=OPERATION,
        actual=policy['actual'], native='NOT_RUN', publication='NOT_RUN', hardware='NOT_RUN', release='NOT_ADMITTED')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent-source', type=Path, required=True)
    parser.add_argument('--raw-parent-commit', type=Path, required=True)
    parser.add_argument('--profile-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        value = assemble(absolute(args.parent_source), absolute(args.raw_parent_commit),
            Path(__file__).absolute().with_name('profile.json'), args.profile_sha256, absolute(args.output))
        print(json.dumps(value, sort_keys=True)); return 0
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, AttributeError, tarfile.TarError) as error:
        print(json.dumps(dict(status='REFUSED', reason=str(error)), sort_keys=True)); return 1


if __name__ == '__main__':
    raise SystemExit(main())
