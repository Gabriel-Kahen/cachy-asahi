#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-only exact current011 Source proposal constructor; no actor on import."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile

HERE = Path(__file__).resolve().parent
PARENT = 'd3c25388b6b44d8fc978c28cf118f5b2f258daf0'
PARENT_TREE = '54f053d477f6e5d6ef7edfdde23ce30967e90b12'
PARENT_MAP_SHA256 = '1f3a0f0f32ba80a73ae83da6039e3eb46274eefb4fcb19c4c8bda556066dd6b8'
PARENT_RAW_SHA256 = 'b2152d25153c5d1833c9bb218fdf010973759429faedc0288e4f157ff9d4168f'
SELECTION = 'desktop-current011'
READER_SELECTION = 'desktop-current011-owned-v2-reader-v1'
MAX_FILE, MAX_TOTAL, MAX_FILES = 64 * 1024**2, 96 * 1024**2, 200
NULL_ACTUAL = dict(source=None, ref=None, run=None, job=None, artifact=None)
NULL_READER = dict(source=None, ref=None, run=None, map_sha256=None)
STAT_FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
ALLOWED_CHANGES = frozenset(('.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-developer-workflows.yml',
    'native/desktop_tools_v1.py', 'native/desktop_alpm_v1.py', 'native/desktop-sources-v1.tar', 'native/owner.py',
    'native/invocation.json', 'native/desktop-contract-v1.json', 'native/desktop_projection_v1.py',
    'native/desktop_reader_v1.py', 'native/reader.py', 'native/source-map.json'))


def need(value, why):
    if not value:
        raise ValueError(why)

def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()

def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate JSON key refused')
        result[key] = value
    return result

def document(raw):
    def nonfinite(value):
        raise ValueError('nonfinite JSON refused')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)

def relative(name, max_parts=24):
    need(type(name) is str and 0 < len(name) <= 512, 'bounded relative name required')
    path = PurePosixPath(name)
    need(path.as_posix() == name and not path.is_absolute() and len(path.parts) <= max_parts
         and all(re.fullmatch(r'[A-Za-z0-9_.+-]+', part) and part not in ('.', '..', '.git')
                 for part in path.parts), 'canonical relative Source name required')
    return path

def absolute(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts
         and not any(part.is_symlink() for part in (path, *path.parents)),
         'absolute nonaliased path required')
    return path

def identity(info):
    return tuple(getattr(info, key) for key in STAT_FIELDS)

def read(path, limit=MAX_FILE):
    path = absolute(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
             'bounded ordinary single-link input required')
        chunks, size = [], 0
        while True:
            block = os.read(fd, min(65536, limit + 1 - size))
            if not block:
                break
            chunks.append(block); size += len(block)
            need(size <= limit, 'input byte cap exceeded')
        after = os.fstat(fd)
        need(size == before.st_size and identity(before) == identity(after) == identity(path.lstat()),
             'input changed during read')
        return b''.join(chunks), stat.S_IMODE(after.st_mode)
    finally:
        os.close(fd)

def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def oid(kind, raw):
    return hashlib.sha1(kind + b' ' + str(len(raw)).encode() + b'\0' + raw).digest()

def row(raw, mode):
    return dict(**pin(raw), mode=mode, blob=oid(b'blob', raw).hex())

def body_rows(files):
    return {name: row(raw, mode) for name, (raw, mode) in files.items()}

def simple_rows(value):
    return {name: {key: item[key] for key in ('bytes', 'sha256', 'mode')} for name, item in value.items()}

def snapshot(root, expected=None):
    """Stable closed ordinary tree, with unchanged Source200/64MiB/96MiB caps."""
    root = absolute(root)
    need(stat.S_ISDIR(root.lstat().st_mode), 'ordinary Source directory required')
    files, directories, total, nodes = {}, set(), 0, 0
    expected_names = None if expected is None else set(expected)
    expected_dirs = None if expected is None else {parent.as_posix() for name in expected_names
                    for parent in relative(name).parents if parent.as_posix() != '.'}
    def visit(directory, depth):
        nonlocal total, nodes
        need(depth <= 24, 'Source directory depth cap')
        before = directory.lstat()
        need(stat.S_ISDIR(before.st_mode), 'Source directory alias or special node refused')
        names = []
        with os.scandir(directory) as entries:
            for entry in entries:
                nodes += 1
                need(nodes <= MAX_FILES * 25, 'Source namespace node cap')
                names.append(entry.name)
        for leaf in sorted(names):
            path = directory / leaf; name = path.relative_to(root).as_posix(); relative(name)
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                need(expected_dirs is None or name in expected_dirs, 'unlisted Source directory refused')
                directories.add(name); visit(path, depth + 1)
            else:
                need(expected_names is None or name in expected_names, 'unlisted Source leaf refused before read')
                need(stat.S_ISREG(info.st_mode) and len(files) < MAX_FILES, 'Source leaf count/type cap')
                raw, mode = read(path); total += len(raw)
                need(total <= MAX_TOTAL and mode in (0o644, 0o755), 'Source total/mode cap')
                files[name] = (raw, mode)
        need(identity(before) == identity(directory.lstat()), 'Source directory changed during read')
    visit(root, 0)
    expected_dirs = {parent.as_posix() for name in files for parent in relative(name).parents
                     if parent.as_posix() != '.'}
    need(directories == expected_dirs, 'unexpected or empty Source directory refused')
    need(expected_names is None or set(files) == expected_names, 'complete declared Source namespace required')
    return files

def git_tree(files):
    nested = {}
    for name, item in files.items():
        parts = relative(name).parts; current = nested
        for part in parts[:-1]:
            need(not isinstance(current.get(part), tuple), 'Source file/directory collision')
            current = current.setdefault(part, {})
        need(parts[-1] not in current, 'duplicate Source leaf')
        current[parts[-1]] = item
    def digest(directory):
        raw = bytearray()
        for name, value in sorted(directory.items(), key=lambda item: item[0].encode() +
                                  (b'/' if isinstance(item[1], dict) else b'')):
            subdir = isinstance(value, dict)
            mode = b'40000' if subdir else b'100755' if value[1] == 0o755 else b'100644'
            raw.extend(mode + b' ' + name.encode() + b'\0' +
                       (digest(value) if subdir else oid(b'blob', value[0])))
        return oid(b'tree', raw)
    return digest(nested).hex()

def check_rows(value, count):
    need(type(value) is dict and len(value) == count <= MAX_FILES, 'exact Source row cardinality')
    total = 0
    for name, item in value.items():
        relative(name)
        need(type(item) is dict and set(item) == {'bytes', 'sha256', 'mode', 'blob'}
             and type(item['bytes']) is int and 0 <= item['bytes'] <= MAX_FILE
             and type(item['mode']) is int and item['mode'] in (0o644, 0o755)
             and type(item['sha256']) is str and re.fullmatch('[0-9a-f]{64}', item['sha256'])
             and type(item['blob']) is str and re.fullmatch('[0-9a-f]{40}', item['blob']),
             'typed Source byte/SHA/mode/blob row required')
        total += item['bytes']
    need(total <= MAX_TOTAL, 'whole Source byte cap')

def source_map(files, count):
    mapped = document(files['native/source-map.json'][0])
    need(type(mapped) is dict and type(mapped.get('schema')) is int and mapped['schema'] == 1 and mapped.get('actual') == dict(source=None, ref=None, run=None)
         and len(files) == count and len(mapped['files']) == count - 1 <= MAX_FILES
         and mapped['files'] == {name: item for name, item in simple_rows(body_rows(files)).items()
                                 if name != 'native/source-map.json'}, 'closed complete unchanged-bound Source map')

def write_new(root, name, raw, mode):
    relative(name, max_parts=25); path = root / name
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open('xb') as stream:
        stream.write(raw)
    path.chmod(mode)

def owned_directory(path):
    path = absolute(path); info = path.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
         and stat.S_IMODE(info.st_mode) == 0o700, 'caller-owned0700 ordinary directory required')
    return info

def namespace(root, expected):
    """The stage also holds finite inverse/metadata leaves, outside Source200."""
    actual, directories, count = set(), set(), 0
    def visit(directory):
        nonlocal count
        before = directory.lstat()
        need(stat.S_ISDIR(before.st_mode), 'stage directory alias refused')
        with os.scandir(directory) as entries:
            names = []
            for entry in entries:
                count += 1; need(count <= len(expected) * 25, 'stage namespace bound')
                names.append(entry.name)
        for leaf in sorted(names):
            path = directory / leaf; name = path.relative_to(root).as_posix(); relative(name, max_parts=25)
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                directories.add(name); visit(path)
            else:
                need(stat.S_ISREG(info.st_mode) and name in expected and name not in actual,
                     'unknown/aliased/special stage leaf refused')
                actual.add(name)
        need(identity(before) == identity(directory.lstat()), 'stage directory changed during read')
    visit(root)
    expected_dirs = {parent.as_posix() for name in expected for parent in relative(name, max_parts=25).parents
                     if parent.as_posix() != '.'}
    need(actual == expected and directories == expected_dirs, 'whole stage namespace differs')


def selected(selection, owned_retirement_v2):
    need(selection == SELECTION and owned_retirement_v2 is True,
         'current011 requires explicit current package and owned-v2 selections')


def validate_profile(value):
    need(type(value) is dict and type(value.get('schema')) is int and value['schema'] == 1
         and value.get('kind') == 'desktop-current011-source-proposal-v1'
         and value.get('selection') == SELECTION, 'exact current011 profile identity')
    need(type(value.get('package_input')) is dict and value['package_input'] == dict(accepted_main='2561dcebee3ba70b924c9c4b42e4316b2994d832',
         source_commit='446f657723c2e4443f8a3fe8ccbe592ebbaf282b'), 'exact current011 package input required')
    need(value.get('actual') == NULL_ACTUAL and value.get('matching_reader_actual') == NULL_READER
         and value.get('Source_generated') is False, 'all prospective actuals must remain NULL')
    need(value['parent'] == dict(commit=PARENT, tree=PARENT_TREE, map_sha256=PARENT_MAP_SHA256,
         raw_commit=dict(path='parent-commit.raw', bytes=335, sha256=PARENT_RAW_SHA256)), 'exact Source200 physical parent')
    before, after = value['before200'], value['after200']
    check_rows(before, 200); check_rows(after, 200)
    need(set(before) == set(after) and before['native/source-map.json']['sha256'] == PARENT_MAP_SHA256,
         'same closed200 namespace and held parent map required')
    changed = {name for name in before if before[name] != after[name]}
    required = ALLOWED_CHANGES - {'native/reader.py'}
    need(required <= changed <= ALLOWED_CHANGES and all(before[n]['mode'] == after[n]['mode'] for n in before),
         'only reviewed current011 leaf replacements; all modes held')
    need(value['payload'] == {name: 'payload/' + name for name in changed}, 'exact finite replacement payload')
    need(type(value['output']) is dict and set(value['output']) == {'tree', 'map_sha256'}
         and type(value['output']['tree']) is str and re.fullmatch('[0-9a-f]{40}', value['output']['tree'])
         and value['output']['map_sha256'] == after['native/source-map.json']['sha256'], 'exact prospective output tree/map')
    reader = value['reader_contract']
    expected_reader = dict(selection=READER_SELECTION, path='native/desktop_reader_v1.py',
            runtime_selection='desktop-owned-retirement-v2', payload_contract='native/desktop-contract-v1.json',
            payload_files=6, package_version='0.1.1-1', update_version='0.1.1-2', expected_test_count=91,
            source_archive_sha256='11a59ada0d99f1202694ed98adb7891594b27a7048e39a99d5590e425fc31986',
            package_source_commit='446f657723c2e4443f8a3fe8ccbe592ebbaf282b',
            scope='FINITE_NATURAL_RETIREMENT_OPTIONAL_QUALIFIED_ZERO_CHILD',
            private_layout='desktop-alpm-v1-public-data-v1', process_layout='bash-pid1-direct-python-child-v1')
    need(type(reader) is dict and set(reader) == set(expected_reader), 'exact closed current reader metadata')
    for key, expected in expected_reader.items():
        need(type(reader[key]) is type(expected) and reader[key] == expected, 'exact current reader ' + key)
    return value


def profile(external):
    need(type(external) is str and re.fullmatch('[0-9a-f]{64}', external), 'external reviewed profile SHA required')
    raw, mode = read(HERE / 'profile.json', 1024**2)
    need(mode == 0o644 and pin(raw)['sha256'] == external, 'whole reviewed profile differs')
    return validate_profile(document(raw))


def check_map_transition(before, after, value):
    source_map(before, 200); source_map(after, 200)
    old = document(before['native/source-map.json'][0]); new = document(after['native/source-map.json'][0])
    need(set(new) == set(old) | {'desktop_current011_reader'}
         and all(new[key] == old[key] for key in old if key != 'files')
         and new['desktop_current011_reader'] == value['reader_contract'],
         'all historical Source metadata held; only explicit current reader metadata added')


def raw_parent(value):
    expected = value['parent']['raw_commit']; raw, mode = read(HERE / expected['path'], 4096)
    need(mode == 0o644 and pin(raw) == {key: expected[key] for key in ('bytes', 'sha256')}
         and oid(b'commit', raw).hex() == PARENT, 'actual raw Source200 parent differs')
    need(raw.splitlines()[0] == ('tree ' + PARENT_TREE).encode(), 'actual Source200 header tree differs')
    return raw


def compose(before, payload, value):
    need(body_rows(before) == value['before200'] and git_tree(before) == PARENT_TREE, 'complete physical Source200 parent differs')
    need(set(payload) == set(value['payload']) and body_rows(payload) ==
         {name: value['after200'][name] for name in payload}, 'complete reviewed replacement payload differs')
    after = dict(before); after.update(payload)
    need(body_rows(after) == value['after200'] and git_tree(after) == value['output']['tree'], 'complete prospective200 tree differs')
    check_map_transition(before, after, value)
    inverse = dict(after); inverse.update({name: before[name] for name in payload})
    need(inverse == before and git_tree(inverse) == PARENT_TREE, 'full byte/mode inverse and unlisted preservation')
    return after


def stage_document(value, external):
    return dict(schema=1, status='SOURCE_ONLY_EXPLICIT_CURRENT011_PROPOSAL', selection=SELECTION,
        parent=PARENT, parent_tree=PARENT_TREE, tree=value['output']['tree'],
        map_sha256=value['output']['map_sha256'], source_files=200, source_map_rows=199,
        profile_sha256=external, actual=dict(NULL_ACTUAL), matching_reader=dict(NULL_READER),
        default_switch=False, native='NOT_RUN', ALPM='NOT_RUN', GPG='NOT_RUN',
        physical_M2='NOT_RUN', native_16K='NOT_QUALIFIED', performance='NOT_MEASURED', release='NOT_ADMITTED')


def metadata(value, external):
    after = value['after200']
    return {'source-authorization.json': encoded({n: {k: r[k] for k in ('bytes', 'sha256')} for n, r in after.items()}),
        'source-modes.json': encoded({n: r['mode'] for n, r in after.items()}),
        'git-blobs.json': encoded({n: dict(blob=r['blob']) for n, r in after.items()}),
        'parent-commit.raw': raw_parent(value),
        'delta200.json': encoded({n: dict(before=value['before200'][n], after=after[n]) for n in value['payload']}),
        'stage.json': encoded(stage_document(value, external)),
        'reader-binding.NULL.json': encoded(NULL_READER),
        'params.NULL.json': encoded(dict(NULL_ACTUAL, matching_reader=None))}


def verify_output(stage, external):
    root = absolute(stage); owned_directory(root); owned_directory(root.parent)
    value = profile(external); expected_metadata = metadata(value, external)
    after = snapshot(root / 'source', value['after200'])
    need(body_rows(after) == value['after200'] and git_tree(after) == value['output']['tree'], 'whole emitted200 Source differs')
    originals_expected = {n: value['before200'][n] for n in value['payload']}
    originals = snapshot(root / 'before200', originals_expected)
    need(body_rows(originals) == originals_expected, 'complete physical inverse operands differ')
    names = {'source/' + n for n in after} | {'before200/' + n for n in originals} | set(expected_metadata)
    namespace(root, names)
    for name, expected in expected_metadata.items():
        raw, mode = read(root / name, 1024**2)
        need(mode == 0o644 and raw == expected, 'whole stage metadata differs: ' + name)
    with tempfile.TemporaryDirectory(prefix='.current011-inverse-', dir=root.parent) as temporary:
        restored_root = Path(temporary) / 'source'; restored_root.mkdir(mode=0o700)
        for name, (raw, mode) in after.items(): write_new(restored_root, name, raw, mode)
        for name, (raw, mode) in originals.items():
            path = restored_root / name; path.write_bytes(raw); path.chmod(mode)
        restored = snapshot(restored_root, value['before200'])
        need(body_rows(restored) == value['before200'] and git_tree(restored) == PARENT_TREE, 'physical full200 inverse differs')
        check_map_transition(restored, after, value)
    return stage_document(value, external)


def materialize(parent_source, output, *, selection, owned_retirement_v2, profile_sha256):
    selected(selection, owned_retirement_v2)
    parent_source, output = absolute(parent_source), absolute(output)
    for source in (parent_source, HERE):
        need(not output.is_relative_to(source) and not source.is_relative_to(output), 'disjoint input/output required')
    parent_info = owned_directory(output.parent)
    need(not os.path.lexists(output), 'absent output required')
    value = profile(profile_sha256); raw_parent(value)
    before = snapshot(parent_source, value['before200'])
    payload = snapshot(HERE / 'payload', {n: value['after200'][n] for n in value['payload']})
    after = compose(before, payload, value)
    with tempfile.TemporaryDirectory(prefix='.desktop-current011-', dir=output.parent) as temporary:
        temporary = Path(temporary); staged = temporary / 'stage'; staged.mkdir(mode=0o700)
        for name, (raw, mode) in after.items(): write_new(staged, 'source/' + name, raw, mode)
        for name, (raw, mode) in before.items():
            if name in payload: write_new(staged, 'before200/' + name, raw, mode)
        for name, raw in metadata(value, profile_sha256).items(): write_new(staged, name, raw, 0o644)
        result = verify_output(staged, profile_sha256)
        current = owned_directory(output.parent)
        need((parent_info.st_dev, parent_info.st_ino) == (current.st_dev, current.st_ino), 'output parent identity changed')
        rename = ctypes.CDLL(None, use_errno=True).renameat2
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        source_fd = output_fd = None
        try:
            source_fd = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            output_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            need((os.fstat(output_fd).st_dev, os.fstat(output_fd).st_ino) == (parent_info.st_dev, parent_info.st_ino), 'held output parent differs')
            if rename(source_fd, b'stage', output_fd, os.fsencode(output.name), 1):
                code = ctypes.get_errno(); raise OSError(code, os.strerror(code))
        finally:
            if output_fd is not None: os.close(output_fd)
            if source_fd is not None: os.close(source_fd)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', required=True, choices=(SELECTION,))
    parser.add_argument('--owned-retirement-v2', action='store_true', required=True)
    parser.add_argument('--profile-sha256', required=True)
    parser.add_argument('--parent-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--root-source-authorized', action='store_true', required=True)
    args = parser.parse_args()
    print(json.dumps(materialize(args.parent_source, args.output, selection=args.selection,
        owned_retirement_v2=args.owned_retirement_v2, profile_sha256=args.profile_sha256), sort_keys=True))


if __name__ == '__main__':
    main()
