#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit pinned Source200 construction and physical inverse checks as DATA.

No Git, subprocess, network, native control, Source script or package is run.
The Root-issued finite native control is copied by pin; it is never replayed.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
PROFILE_SHA256 = '2b34ce484406cfeedfc990bc0bb3698ba01bec71d36e4f9b35d18c50e6edc9c5'
SELECTION = 'desktop-owned-retirement-v2'
PARENT = '72bc639de295704b94901c03ac8acf7667ff6f9c'
PARENT_TREE = '7af3afe8534967e635b741a80ad0b661dee19bae'
PARENT_RAW_SHA256 = '1d9fa29c92f101e607bbae7aee7847f5c56cc3b9e875654aa06d4e6e53f823be'
RUNTIME_PATH = 'native/desktop_owned_process_v2.py'
RUNTIME_SOURCE = 'd9708daa75083f85f1a182cb3aa97a728d04d695'
HISTORICAL_RUNTIME_SOURCE = '3ab5da1b4a11495075a9660ad09625a4ff5f0f64'
RUNTIME = dict(bytes=38256, sha256='9388d270d06e28fee50160b7c04dd69593e383647d791f8aaff69380032165d5',
               mode=0o755, blob='e336152d4b0185ec704661243f0c8968ed37be44')
MAX_FILE, MAX_TOTAL, MAX_FILES = 64 * 1024**2, 96 * 1024**2, 200
NULL_ACTUAL = dict(source=None, ref=None, run=None, job=None, artifact=None)
NULL_READER = dict(source=None, ref=None, run=None, map_sha256=None)
NULL_PARAMS = dict(NULL_ACTUAL, matching_reader=None)
STAT_FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
               'st_size', 'st_mtime_ns', 'st_ctime_ns')


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


def changes(value):
    before, after = value['before199'], value['after200']
    return {name: dict(before=before.get(name), after=after.get(name))
            for name in sorted(before.keys() | after.keys()) if before.get(name) != after.get(name)}


def native_control(value):
    selected = value['native_control']
    need(type(selected) is dict and set(selected) == {'path', 'bytes', 'sha256'}
         and selected['path'] == 'native-control.json' and type(selected['bytes']) is int
         and 0 < selected['bytes'] <= 1024**2 and type(selected['sha256']) is str
         and re.fullmatch('[0-9a-f]{64}', selected['sha256']), 'fixed public native-control pin')
    raw, mode = read(HERE / selected['path'], 1024**2)
    need(mode == 0o644 and pin(raw) == {key: selected[key] for key in ('bytes', 'sha256')},
         'whole public native-control summary differs')
    control = document(raw)
    need(type(control) is dict and type(control.get('schema')) is int and control['schema'] == 1 and control.get('issuer') == 'Root'
         and control.get('status') == 'ROOT_ACCEPTED_FINITE_NATIVE_ARM4K_ADOPTED_ZERO_EXIT_CHILD_PROCESS_CONTROL'
         and control.get('scope') == 'EXACT_NATIVE_RUNTIME_ONE_GENUINE_ADOPTED_ZERO_CHILD_BRANCH_ONLY'
         and control.get('runtime_source') == HISTORICAL_RUNTIME_SOURCE and control.get('runtime') == RUNTIME
         and type(control.get('scope_limits')) is dict and bool(control['scope_limits'])
         and all(item is False for item in control['scope_limits'].values())
         and control.get('actual', {}).get('architecture') == 'aarch64'
         and type(control['actual'].get('page_size')) is int and control['actual']['page_size'] == 4096,
         'finite Root zero-child scope only; no runtime/component/default/M2/release acceptance')
    return raw, control


def profile():
    raw, mode = read(HERE / 'profile.json', 1024**2)
    need(mode == 0o644 and re.fullmatch('[0-9a-f]{64}', PROFILE_SHA256)
         and pin(raw)['sha256'] == PROFILE_SHA256, 'whole pinned owned-v2 Source profile differs')
    value = document(raw)
    need(type(value) is dict and type(value.get('schema')) is int and value['schema'] == 1 and value.get('selection') == SELECTION, 'explicit owned-v2 profile identity')
    need(value['parent']['commit'] == PARENT and value['parent']['tree'] == PARENT_TREE
         and value['parent']['raw_commit'] == dict(path='parent-commit.raw', bytes=319, sha256=PARENT_RAW_SHA256),
         'exact actual Desktop parent identity')
    check_rows(value['before199'], 199); check_rows(value['after200'], 200)
    before, after, delta = value['before199'], value['after200'], changes(value)
    need(set(after) - set(before) == {RUNTIME_PATH} and not set(before) - set(after)
         and len(delta) == 9 and sum(item['before'] is not None for item in delta.values()) == 8
         and after[RUNTIME_PATH] == RUNTIME, 'exact eight replacements plus one pinned0755 runtime')
    need(all(after[name]['mode'] == before[name]['mode'] for name in before), 'existing Source modes held')
    need(type(value['payload']) is dict and value['payload'] == {name: 'payload/' + name for name in delta},
         'exact finite nine-body payload namespace')
    output = value['output']
    need(type(output) is dict and set(output) == {'tree', 'map_sha256'}
         and re.fullmatch('[0-9a-f]{40}', output['tree'])
         and re.fullmatch('[0-9a-f]{64}', output['map_sha256'])
         and after['native/source-map.json']['sha256'] == output['map_sha256'], 'complete Source tree/map pins')
    aliases = dict(parent_source=PARENT, parent_tree=PARENT_TREE, runtime_source=RUNTIME_SOURCE,
                   runtime={key: RUNTIME[key] for key in ('bytes', 'sha256', 'mode')},
                   source_files=200, source_map_rows=199, map_rows=199, common_mapped_cap=200,
                   factory_full_file_cap=200, source_tree=output['tree'], source_map_sha256=output['map_sha256'],
                   map_sha256=output['map_sha256'], parent_map_sha256=before['native/source-map.json']['sha256'],
                   MAX_FILE=MAX_FILE, MAX_TOTAL=MAX_TOTAL, total_bytes=sum(item['bytes'] for item in after.values()),
                   actual=NULL_ACTUAL, Source_generated=False, constructor_invoked=False)
    for name, expected in aliases.items():
        if name in value:
            need(encoded(value[name]) == encoded(expected), 'profile alias differs: ' + name)
    if 'kind' in value:
        need(value['kind'] == 'desktop-owned-v2-source-proposal-v1', 'profile kind alias')
    if 'after' in value:
        need(encoded(value['after']) in (encoded(after), encoded(simple_rows(after))), 'after alias differs')
    if 'delta' in value:
        listed = value['delta']
        need(type(listed) is list and len(listed) == len(delta), 'finite delta alias')
        seen = set()
        for item in listed:
            need(type(item) is dict and set(item) == {'path', 'candidate_body', 'before', 'after'}
                 and item['path'] in delta and item['path'] not in seen, 'exact unique delta alias row')
            name = item['path']; seen.add(name)
            need(item['candidate_body'] == value['payload'][name] and encoded(item['before']) == encoded(delta[name]['before'])
                 and encoded(item['after']) == encoded(delta[name]['after']), 'delta alias body/pins differ')
    if 'all_unlisted_held' in value:
        held = {name: item for name, item in after.items() if name not in delta}
        need(encoded(value['all_unlisted_held']) in (encoded(held), encoded(simple_rows(held))),
             'all unlisted held Source rows differ')
    native_control(value)
    return value


def source_map(files, count):
    mapped = document(files['native/source-map.json'][0])
    need(type(mapped) is dict and type(mapped.get('schema')) is int and mapped['schema'] == 1 and mapped.get('actual') == dict(source=None, ref=None, run=None)
         and len(files) == count and len(mapped['files']) == count - 1 <= MAX_FILES
         and mapped['files'] == {name: item for name, item in simple_rows(body_rows(files)).items()
                                 if name != 'native/source-map.json'}, 'closed complete unchanged-bound Source map')


def parent_raw(value):
    selected = value['parent']['raw_commit']; raw, mode = read(HERE / selected['path'], 4096)
    need(mode == 0o644 and pin(raw) == {key: selected[key] for key in ('bytes', 'sha256')}
         and oid(b'commit', raw).hex() == PARENT, 'held raw parent commit identity differs')
    header = raw.split(b'\n\n', 1)[0].splitlines()
    need([line[5:].decode('ascii') for line in header if line.startswith(b'tree ')] == [PARENT_TREE],
         'raw actual parent header tree differs')
    return raw


def verify_parent(parent_source):
    value = profile(); files = snapshot(absolute(parent_source), value['before199'])
    need(body_rows(files) == value['before199'] and git_tree(files) == PARENT_TREE, 'whole actual199 parent differs')
    source_map(files, 199)
    return dict(profile=value, files=files, raw_parent=parent_raw(value))


def stage_document(value):
    return dict(status='SOURCE_ONLY_EXPLICIT_DESKTOP_OWNED_RETIREMENT_V2', selection=SELECTION,
                operation='desktop-alpm-v1', parent=PARENT, parent_tree=PARENT_TREE,
                prospective_tree=value['output']['tree'], tree=value['output']['tree'],
                source_map_sha256=value['output']['map_sha256'], map_sha256=value['output']['map_sha256'],
                source_files=200, source_map_rows=199, map_rows=199, profile_sha256=PROFILE_SHA256,
                actual=dict(NULL_ACTUAL), matching_reader=None, default_switch=False,
                native_control=dict(value['native_control'], scope='FINITE_ZERO_CHILD_ONLY_NO_NATIVE_LANE_ACCEPTANCE'),
                native='NOT_RUN', native_lane='NOT_RUN', GPG='NOT_RUN', ALPM='NOT_RUN',
                native_16K='NOT_QUALIFIED', physical_M2='NOT_RUN', performance='NOT_MEASURED', release='NOT_ADMITTED')


def delta_document(value):
    return dict(parent=PARENT, basis_tree=PARENT_TREE, changes=changes(value))


def metadata(value):
    after = value['after200']
    return {
        'source-authorization.json': encoded({name: {key: item[key] for key in ('bytes', 'sha256')}
                                               for name, item in after.items()}),
        'source-modes.json': encoded({name: item['mode'] for name, item in after.items()}),
        'git-blobs.json': encoded({name: dict(blob=item['blob']) for name, item in after.items()}),
        'parent-commit.raw': parent_raw(value),
        'delta199.json': encoded(delta_document(value)),
        'stage.json': encoded(stage_document(value)),
        'reader-binding.NULL.json': encoded(NULL_READER),
        'params.NULL.json': encoded(NULL_PARAMS),
        'native-control.json': native_control(value)[0],
    }


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


def verify_output(stage):
    root = absolute(stage); owned_directory(root); owned_directory(root.parent)
    value = profile(); expected_metadata = metadata(value)
    after = snapshot(root / 'source', value['after200'])
    need(body_rows(after) == value['after200'] and git_tree(after) == value['output']['tree'],
         'whole emitted200 Source body/mode/blob/tree differs')
    source_map(after, 200)
    need(pin(after['native/source-map.json'][0])['sha256'] == value['output']['map_sha256'], 'emitted Source map pin')
    delta = changes(value)
    expected_originals = {name: item['before'] for name, item in delta.items() if item['before'] is not None}
    originals = snapshot(root / 'before199', expected_originals)
    need(len(expected_originals) == 8 and body_rows(originals) == expected_originals, 'exact eight physical inverse operands')
    expected_names = {'source/' + name for name in after} | {'before199/' + name for name in originals} | set(expected_metadata)
    namespace(root, expected_names)
    for name, expected in expected_metadata.items():
        raw, mode = read(root / name, 1024**2)
        need(mode == 0o644 and raw == expected, 'emitted stage metadata differs: ' + name)
    # Reconstruct on disk: restore eight originals and delete the one new leaf.
    with tempfile.TemporaryDirectory(prefix='.owned-v2-inverse-', dir=root.parent) as temporary:
        inverse = Path(temporary) / 'source'; inverse.mkdir(mode=0o700)
        for name, (raw, mode) in sorted(after.items()):
            write_new(inverse, name, raw, mode)
        (inverse / RUNTIME_PATH).unlink()
        for name, (raw, mode) in sorted(originals.items()):
            target = inverse / name
            with target.open('wb') as stream:
                stream.write(raw)
            target.chmod(mode)
        restored = snapshot(inverse, value['before199'])
        need(body_rows(restored) == value['before199'] and git_tree(restored) == PARENT_TREE,
             'physical full199 inverse body/mode/blob/tree differs')
        source_map(restored, 199)
    return stage_document(value)


def materialize(parent_source, output, *, selection):
    need(selection == SELECTION, 'explicit desktop-owned-retirement-v2 selection required; no default')
    parent_source, output = absolute(parent_source), absolute(output)
    for source in (parent_source, HERE):
        need(not output.is_relative_to(source) and not source.is_relative_to(output), 'disjoint input/output required')
    parent_info = owned_directory(output.parent)
    need(not os.path.lexists(output), 'absent output required')
    verified = verify_parent(parent_source); value = verified['profile']; before = verified['files']
    payload = snapshot(HERE / 'payload', value['payload'])
    need(body_rows(payload) == {name: value['after200'][name] for name in value['payload']},
         'complete nine pinned payload bodies/modes/blobs differ')
    after = dict(before); after.update(payload)
    need(body_rows(after) == value['after200'] and git_tree(after) == value['output']['tree'], 'complete intended Source200 differs')
    source_map(after, 200)
    with tempfile.TemporaryDirectory(prefix='.desktop-owned-v2-', dir=output.parent) as temporary:
        temporary = Path(temporary); staged = temporary / 'stage'; staged.mkdir(mode=0o700)
        for name, (raw, mode) in sorted(after.items()):
            write_new(staged, 'source/' + name, raw, mode)
        for name, raw in sorted(metadata(value).items()):
            write_new(staged, name, raw, 0o644)
        for name, item in changes(value).items():
            if item['before'] is not None:
                raw, mode = before[name]; write_new(staged, 'before199/' + name, raw, mode)
        result = verify_output(staged)
        current = owned_directory(output.parent)
        need((parent_info.st_dev, parent_info.st_ino) == (current.st_dev, current.st_ino), 'output parent identity changed')
        # Linux RENAME_NOREPLACE, using held directory descriptors; no clobber fallback.
        rename = ctypes.CDLL(None, use_errno=True).renameat2
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        source_fd = output_fd = None
        try:
            source_fd = os.open(temporary, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            output_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            need((os.fstat(output_fd).st_dev, os.fstat(output_fd).st_ino) == (parent_info.st_dev, parent_info.st_ino),
                 'held output-parent descriptor identity differs')
            if rename(source_fd, b'stage', output_fd, os.fsencode(output.name), 1):
                code = ctypes.get_errno(); raise OSError(code, os.strerror(code))
        finally:
            if output_fd is not None:
                os.close(output_fd)
            if source_fd is not None:
                os.close(source_fd)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--selection', required=True, choices=(SELECTION,))
    parser.add_argument('--parent-source', type=Path, required=True, help='Exact locally retained closed199 actual Desktop Source')
    parser.add_argument('--output', type=Path, required=True, help='Absent stage under a caller-owned0700 parent')
    args = parser.parse_args()
    try:
        result = materialize(args.parent_source.absolute(), args.output.absolute(), selection=args.selection)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, AttributeError) as error:
        parser.exit(1, 'owned-v2 Source refused: ' + str(error) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
