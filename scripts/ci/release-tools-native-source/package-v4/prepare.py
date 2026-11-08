#!/usr/bin/env python3
"""Plan package-v4 Source201 DATA; construction is an explicit future Root action."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

HERE = Path(__file__).resolve().parent
PARENT = '686958cf7a3248fc0ef33ad4b61ffd22a325c4e5'
PARENT_TREE = 'bcf78785cd46a2acc75c772f9f6ba21f7bd831b0'
MAP = 'native/source-map.json'
PAYLOAD = frozenset('native/' + name for name in (
    'release-contract-v1.json', 'release-sources-v1.tar', 'release_tools_v1.py',
    'release_alpm_v1.py', 'release_projection_v1.py', 'release_reader_v1.py'))
ACTUAL = dict(source=None, ref=None, run=None)
MAX_INPUT = 32 * 1024**2


def need(ok, why):
    if not ok:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def oid(kind, raw):
    return hashlib.sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def identity(info):
    return tuple(getattr(info, name) for name in (
        'st_dev', 'st_ino', 'st_uid', 'st_gid', 'st_mode', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def read(path, cap=MAX_INPUT):
    path = Path(path)
    need(path.is_absolute() and path == path.resolve()
         and not any(p.is_symlink() for p in (path, *path.parents)), 'canonical DATA path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= cap, 'bounded single-link regular DATA')
        chunks = []
        size = 0
        while size <= before.st_size:
            part = os.read(fd, min(65536, before.st_size + 1 - size))
            if not part:
                break
            chunks.append(part)
            size += len(part)
        need(size == before.st_size and identity(before) == identity(os.fstat(fd))
             == identity(path.lstat()), 'stable complete DATA input')
        return b''.join(chunks)
    finally:
        os.close(fd)


def name(value):
    need(type(value) is str and value and '\0' not in value, 'Source path required')
    path = PurePosixPath(value)
    need(not path.is_absolute() and '..' not in path.parts and '.' not in path.parts
         and path.as_posix() == value, 'canonical Source path')
    return path


def check_rows(rows):
    need(type(rows) is dict and len(rows) == 201 and MAP in rows, 'exact Source201 rows')
    for path, row in rows.items():
        name(path)
        need(type(row) is dict and set(row) == {'bytes', 'sha256', 'mode', 'oid'}
             and type(row['bytes']) is int and 0 <= row['bytes'] <= MAX_INPUT
             and row['mode'] in ('100644', '100755')
             and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256'])
             and type(row['oid']) is str and re.fullmatch('[0-9a-f]{40}', row['oid']), 'complete regular Git DATA row')


def tree(rows):
    root = {}
    for path, row in rows.items():
        parts = name(path).parts
        at = root
        for part in parts[:-1]:
            need(part not in at or type(at[part]) is dict, 'Source path prefix collision')
            at = at.setdefault(part, {})
        need(parts[-1] not in at, 'duplicate Source path')
        at[parts[-1]] = (row['mode'], row['oid'])

    def walk(at):
        chunks = []
        for leaf, row in sorted(at.items(), key=lambda item: (
                item[0] + ('/' if type(item[1]) is dict else '')).encode()):
            mode, blob = ('40000', walk(row)) if type(row) is dict else row
            chunks.append(mode.encode() + b' ' + leaf.encode() + b'\0' + bytes.fromhex(blob))
        return oid('tree', b''.join(chunks))
    return walk(root)


def compose(rows, parentmanifest, payload):
    """Pure metadata/bytes transform; never reads Source or writes an output."""
    check_rows(rows)
    need(tree(rows) == PARENT_TREE, 'actual parent full tree')
    need(type(parentmanifest) is dict and parentmanifest['schema'] == 1
         and parentmanifest['actual'] == ACTUAL and len(parentmanifest['files']) == 200
         and set(parentmanifest['files']) == set(rows) - {MAP}, 'complete parent MAP200')
    parentmap = encode(parentmanifest)
    need(pin(parentmap) == {key: rows[MAP][key] for key in ('bytes', 'sha256')}
         and oid('blob', parentmap) == rows[MAP]['oid'], 'exact parent MAP body')
    for path, row in parentmanifest['files'].items():
        need(row == dict(bytes=rows[path]['bytes'], sha256=rows[path]['sha256'],
                         mode=int(rows[path]['mode'], 8) & 0o777), 'parent MAP/full-row join')
    need(type(payload) is dict and set(payload) == PAYLOAD
         and all(type(body) is bytes and len(body) <= MAX_INPUT for body in payload.values()),
         'exact six payload DATA bodies')
    manifest = json.loads(parentmap)
    after = {path: dict(row) for path, row in rows.items()}
    for path, body in payload.items():
        need(rows[path]['mode'] == '100644', 'payload Git100644 retained')
        after[path] = dict(pin(body), mode='100644', oid=oid('blob', body))
        manifest['files'][path] = dict(pin(body), mode=0o644)
    manifest['release_package_v4_parent'] = PARENT
    manifest['release_package_v4_scope'] = 'EXACT_0.1.0_TO_0.4.0_DATA_VARIANT_PARENT201_HELD194'
    mapbody = encode(manifest)
    after[MAP] = dict(pin(mapbody), mode=rows[MAP]['mode'], oid=oid('blob', mapbody))
    changed = {path for path in rows if rows[path] != after[path]}
    need(changed == PAYLOAD | {MAP}, 'exact seven changed Source201 leaves')
    inverse = dict(after)
    for path in changed:
        inverse[path] = rows[path]
    need(inverse == rows and tree(inverse) == PARENT_TREE, 'complete Source201 inverse')
    return dict(rows=after, tree=tree(after), source_map_bytes=mapbody,
                source_map_pin=pin(mapbody), changed=sorted(changed), held=194)


def pureplan(profile_sha):
    """Authenticate reviewed local DATA and calculate the future201 map only."""
    need(type(profile_sha) is str and re.fullmatch('[0-9a-f]{64}', profile_sha),
         'external profile SHA256 required')
    raw = read(HERE / 'profile.json', 1024**2)
    need(pin(raw)['sha256'] == profile_sha, 'externally reviewed profile SHA256')
    profile = json.loads(raw)
    need(profile['schema'] == 1 and profile['variant'] == 'package-v4'
         and profile['parent_source'] == PARENT and profile['parent_tree'] == PARENT_TREE
         and profile['actual'] == ACTUAL, 'explicit unrun package-v4 identity')
    inputs = {}
    for field, leaf in (('parent_files', 'parent-files.json'), ('parent_raw', 'parent.raw-commit'),
                        ('parent_source_map', 'parent-source-map.json'),
                        ('parent_function_pins', 'parent-function-pins.json')):
        body = read(HERE / leaf, 1024**2)
        need(pin(body) == profile[field], 'pinned parent metadata: ' + field)
        inputs[field] = body
    need(oid('commit', inputs['parent_raw']) == PARENT
         and inputs['parent_raw'].split(b'\n\n', 1)[0].splitlines()[0]
         == ('tree ' + PARENT_TREE).encode(), 'raw actual parent commit/tree')
    rows = json.loads(inputs['parent_files'])
    need(set(profile['payload']) == PAYLOAD, 'six reviewed payload pins')
    payload = {}
    for path, wanted in profile['payload'].items():
        body = read(HERE / 'payload' / path)
        need(pin(body) == wanted, 'reviewed payload body: ' + path)
        payload[path] = body
    result = compose(rows, json.loads(inputs['parent_source_map']), payload)
    need(result['tree'] == profile['source_tree'] and result['source_map_pin'] == profile['source_map'],
         'reviewed whole successor tree/MAP pin')
    return result


def namespace(parent, allow_git=False):
    names, directories = set(), set()
    for directory, dirs, files in os.walk(parent, followlinks=False):
        base = Path(directory)
        if allow_git and base == parent and '.git' in dirs:
            dirs.remove('.git')  # Root checkout metadata is outside the Source201 namespace.
        for leaf in dirs:
            path = base / leaf
            need(not path.is_symlink(), 'no parent directory alias')
            directories.add(path.relative_to(parent).as_posix())
        for leaf in files:
            if allow_git and base == parent and leaf == '.git':
                continue
            names.add((base / leaf).relative_to(parent).as_posix())
    return names, directories


def output_target(parent, output):
    """Validate only output path metadata; never creates a directory."""
    parent, output = Path(parent).absolute(), Path(output).absolute()
    need(not os.path.lexists(output) and output.parent == output.parent.resolve()
         and output.parent.is_dir() and output.parent.stat().st_uid == os.getuid()
         and not stat.S_IMODE(output.parent.stat().st_mode) & 0o022
         and not any(p.is_symlink() for p in (output.parent, *output.parent.parents))
         and not output.is_relative_to(parent) and not parent.is_relative_to(output)
         and not output.is_relative_to(HERE) and not HERE.is_relative_to(output),
         'fresh canonical owned output disjoint from Source and constructor')
    return output


def construct(parent, output, profile_sha):
    """Explicit future Root-only materialization; never called by DATA tests/CI."""
    planned = pureplan(profile_sha)
    rows = json.loads(read(HERE / 'parent-files.json', 1024**2))
    parent, output = Path(parent).absolute(), Path(output).absolute()
    need(parent == parent.resolve() and parent.is_dir() and parent.stat().st_uid == os.getuid()
         and not any(p.is_symlink() for p in (parent, *parent.parents)), 'canonical owned parent Source')
    names, dirs = namespace(parent, allow_git=True)
    need(names == set(rows) and dirs == {p.as_posix() for n in rows for p in Path(n).parents
                                       if p != Path('.')}, 'exact full201 parent namespace')
    bodies = {}
    for path, row in rows.items():
        body = read(parent / path)
        need(pin(body) == {key: row[key] for key in ('bytes', 'sha256')}
             and oid('blob', body) == row['oid']
             and stat.S_IMODE((parent / path).stat().st_mode) == int(row['mode'], 8) & 0o777,
             'complete actual parent body/mode/OID')
        bodies[path] = body
    for path in PAYLOAD:
        body = read(HERE / 'payload' / path)
        need(pin(body) == {key: planned['rows'][path][key] for key in ('bytes', 'sha256')},
             'payload unchanged after planning')
        bodies[path] = body
    bodies[MAP] = planned['source_map_bytes']
    need(set(bodies) == set(planned['rows']) and all(
        dict(pin(body), mode=rows[path]['mode'], oid=oid('blob', body)) == planned['rows'][path]
        for path, body in bodies.items()), 'whole201 final body/mode/OID join before output')
    output = output_target(parent, output)
    output.mkdir(mode=0o700)
    os.chmod(output, 0o700)
    for path, body in bodies.items():
        target = output / path
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(body)
        target.chmod(int(planned['rows'][path]['mode'], 8) & 0o777)
    actual_names, actual_dirs = namespace(output)
    need(actual_names == set(planned['rows']) and actual_dirs == dirs, 'whole written201 namespace')
    for path, row in planned['rows'].items():
        body = read(output / path)
        need(dict(pin(body), mode=format(stat.S_IMODE((output / path).stat().st_mode) | 0o100000, 'o'),
                  oid=oid('blob', body)) == row, 'whole written201 readback body/mode/OID')
    return dict(status='PREPARED_CLOSED_PACKAGE_V4_SOURCE201_DATA_ONLY', parent=PARENT,
                source=None, tree=planned['tree'], map_sha256=planned['source_map_pin']['sha256'],
                files=201, changed=7, held=194, actual=ACTUAL, native='NOT_RUN', reader_executed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile-sha256', required=True)
    parser.add_argument('--execute-root-constructor', action='store_true', required=True)
    args = parser.parse_args()
    print(json.dumps(construct(args.parent_source, args.output, args.profile_sha256), sort_keys=True))


if __name__ == '__main__':
    main()
