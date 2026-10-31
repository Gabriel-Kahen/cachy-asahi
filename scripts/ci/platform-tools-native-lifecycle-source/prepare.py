#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Materialize the exact platform native Source as DATA; never execute actors."""
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
PROFILE_SHA256 = '12d95d49ba520ee7ee90891c524635ba6fc7512dd1c8a855fe91be4fb0d6a561'
MAX_FILE, MAX_TOTAL, MAX_FILES = 64 * 1024**2, 96 * 1024**2, 200


def need(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw, mode):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), mode=mode)


def relative(name):
    need(type(name) is str and 0 < len(name) <= 512, 'bounded source name required')
    path = PurePosixPath(name)
    need(path.as_posix() == name and not path.is_absolute() and len(path.parts) <= 24
         and all(re.fullmatch(r'[A-Za-z0-9_.+-]+', part) and part not in ('.', '..', '.git')
                 for part in path.parts), 'safe canonical relative source name required')
    return path


def absolute(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts
         and not any(p.is_symlink() for p in (path, *path.parents)), 'absolute nonaliased path required')
    return path


def read(path, limit=MAX_FILE):
    path = absolute(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= limit,
             'bounded ordinary single-link source required')
        chunks, size = [], 0
        while True:
            block = os.read(fd, min(65536, limit + 1 - size))
            if not block:
                break
            chunks.append(block); size += len(block)
            need(size <= limit, 'source byte bound exceeded')
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        need(size == before.st_size and all(getattr(before, k) == getattr(after, k) for k in fields),
             'source changed during read')
        return b''.join(chunks), stat.S_IMODE(after.st_mode)
    finally:
        os.close(fd)


def tree(root, checkout=False):
    root = absolute(root); need(root.is_dir(), 'ordinary source root required')
    result, directories, total = {}, set(), 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        current = Path(directory)
        if checkout and current == root:
            dirs[:] = [n for n in dirs if n != '.git']
            names = [n for n in names if n != '.git']
        for name in dirs:
            child = current / name
            need(stat.S_ISDIR(child.lstat().st_mode), 'source directory alias or special node refused')
            directories.add(child.relative_to(root).as_posix())
        for name in names:
            child = current / name; leaf = child.relative_to(root).as_posix(); relative(leaf)
            need(len(result) < MAX_FILES, 'source member count exceeded')
            raw, mode = read(child); total += len(raw)
            need(total <= MAX_TOTAL and mode in (0o644, 0o755), 'source total/mode bound exceeded')
            result[leaf] = (raw, mode)
    wanted = {p.as_posix() for name in result for p in PurePosixPath(name).parents if p.as_posix() != '.'}
    need(directories == wanted, 'empty or unexpected source directory refused')
    return result


def rows(files):
    return {name: pin(raw, mode) for name, (raw, mode) in files.items()}


def oid(kind, raw):
    return hashlib.sha1(kind + b' ' + str(len(raw)).encode() + b'\0' + raw).digest()


def git_tree(files):
    nested = {}
    for name, (raw, mode) in files.items():
        parts = relative(name).parts; node = nested
        for part in parts[:-1]:
            need(not isinstance(node.get(part), tuple), 'source file/directory collision')
            node = node.setdefault(part, {})
        need(parts[-1] not in node, 'duplicate source leaf'); node[parts[-1]] = (raw, mode)
    def visit(node):
        body = bytearray()
        for name, value in sorted(node.items(), key=lambda pair: pair[0].encode() + (b'/' if isinstance(pair[1], dict) else b'')):
            directory = isinstance(value, dict)
            mode = b'40000' if directory else b'100755' if value[1] == 0o755 else b'100644'
            body.extend(mode + b' ' + name.encode() + b'\0' + (visit(value) if directory else oid(b'blob', value[0])))
        return oid(b'tree', body)
    return visit(nested).hex()



PRODUCER_BEFORE = {'bootstrap/scripts/ci/native_arm.py': {'bytes': 28318, 'sha256': 'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898'}, 'native/failure_retention.py': {'bytes': 13639, 'sha256': '20f9f6fb153d3be98e41c343e63f5994aa3708ccbd4299e1f551a38b697ffbe3'}, 'native/platform_alpm_v1.py': {'bytes': 22616, 'sha256': '77e71a7d20002aadc62c3b77aae40f9631ebcdc1e95ef9dc85f317e417a87293'}, 'native/platform_reader_v1.py': {'bytes': 117959, 'sha256': '2e29062143e5a41d3ffa288af1624ef4b48cfaa0923f13b5d489a67e37fb3f3e'}, 'native/platform_projection_v1.py': {'bytes': 14295, 'sha256': 'db35e422138546744bc1b31c81a8e594a0f9e8e289fa1999a269098b6a2ed969'}}
PRODUCER_AFTER = {'native/failure_retention.py': {'bytes': 13639, 'sha256': 'cdb50b755f3e76d0229278bb89476752702544f3c31947e74676c82b213a8dc7', 'mode': 420}, 'native/platform_alpm_v1.py': {'bytes': 22862, 'sha256': '7867244f91d73da5ad1daca1dc13a71ad5a4b5e8f66517490fa1feae8361dfb5', 'mode': 420}, 'native/platform_reader_v1.py': {'bytes': 118148, 'sha256': 'c7ad1e8af0e06db2182fc72546bfa2c4e59c22f79fd63f248700970c8a76a205', 'mode': 420}, 'native/platform_projection_v1.py': {'bytes': 14295, 'sha256': 'ac673854bd1f21a6079ca0910c41cfc49a5793ebe44069c113a3eb30574467be', 'mode': 420}, 'bootstrap/scripts/ci/native_arm.py': {'bytes': 28877, 'sha256': '8e71ba83e7d5037c6f7772401ec3b872684ccfa8472d855d8d6d3052cb1f41ba', 'mode': 420}}


def retired_producer(bodies):
    """Five authenticated producer/cleanup replacements; operands never execute."""
    need({name: dict(bytes=len(bodies[name]), sha256=hashlib.sha256(bodies[name]).hexdigest()) for name in PRODUCER_BEFORE} == PRODUCER_BEFORE,
         'strict frozen producer/observer inputs differ')
    overlay = tree(HERE / 'producer-overlay')
    need(rows(overlay) == PRODUCER_AFTER, 'fixed producer retirement overlay differs')
    result = dict(bodies)
    result.update({name: raw for name, (raw, _) in overlay.items()})
    return result

CONCURRENCY_GROUP = 'native-arm-platform-tools'
WORKFLOW_ALIASES = ('.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-developer-workflows.yml')


def scheduled_workflows(bodies):
    """Change only the authenticated legacy scheduling block, never job behavior."""
    before = b'concurrency:\n  group: native-arm-developer-workflows\n  cancel-in-progress: false\njobs:\n'
    after = ('concurrency:\n  group: ' + CONCURRENCY_GROUP + '\n  cancel-in-progress: false\n  queue: max\njobs:\n').encode()
    need(bodies[WORKFLOW_ALIASES[0]] == bodies[WORKFLOW_ALIASES[1]], 'workflow aliases differ before scheduling')
    result = dict(bodies)
    for name in WORKFLOW_ALIASES:
        raw = bodies[name]
        need(raw.count(before) == 1 and raw.count(b'\nconcurrency:\n') == 1, 'exact unqueued legacy concurrency block required')
        result[name] = raw.replace(before, after, 1)
    return result


def scheduled_source(files):
    original = {name: raw for name, (raw, _) in files.items()}
    bodies = retired_producer(scheduled_workflows(original))
    result = {name: (raw, files[name][1]) for name, raw in bodies.items()}
    manifest = json.loads(files['native/source-map.json'][0])
    need(manifest['files'] == {name: row for name, row in rows(files).items() if name != 'native/source-map.json'}, 'original source map before scheduling differs')
    manifest['files'] = {name: row for name, row in rows(result).items() if name != 'native/source-map.json'}
    result['native/source-map.json'] = ((json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode(), files['native/source-map.json'][1])
    return result


def profile():
    raw, _ = read(HERE / 'profile.json', 1024**2)
    need(hashlib.sha256(raw).hexdigest() == PROFILE_SHA256, 'whole fixed Source profile differs')
    value = json.loads(raw)
    need(value['kind'] == 'platform-tools-native-source-profile-v1' and value['pr_base'] == 'main'
         and value['integration_base'] == '3a3ccc6c69d1b800dc47fbaea051b87f5f3d43b4'
         and len(value['basis']) == 191 and len(value['payload']) == 13 and len(value['after']) == 199
         and all(item is None for item in value['actual'].values()) and value['producer_overlay'] == PRODUCER_AFTER, 'exact unexecuted Source profile required')
    return value


def render(basis):
    value = profile(); before = tree(basis, checkout=True)
    need(rows(before) == value['basis'] and git_tree(before) == value['parent_tree'], 'whole genuine191 basis differs')
    raw, mode = read(HERE / 'parent-commit.raw')
    need(pin(raw, mode) == value['parent_raw'] and oid(b'commit', raw).hex() == value['genuine_parent'], 'genuine raw parent commit differs')
    header = raw.split(b'\n\n', 1)[0].splitlines()
    need([r[5:].decode() for r in header if r.startswith(b'tree ')] == [value['parent_tree']], 'raw parent tree differs')
    payload = tree(HERE / 'payload')
    need(rows(payload) == value['payload'], 'whole finite native payload differs')
    after = dict(before); after.update(payload); after = scheduled_source(after)
    need(rows(after) == value['after'] and git_tree(after) == value['source_tree'], 'whole prospective199 Source differs')
    manifest_raw = after['native/source-map.json'][0]
    need(hashlib.sha256(manifest_raw).hexdigest() == value['source_map_sha256'], 'source-map checksum differs')
    manifest = json.loads(manifest_raw)
    need(manifest['actual'] == dict(source=None, ref=None, run=None)
         and manifest['files'] == {n: r for n, r in rows(after).items() if n != 'native/source-map.json'}
         and len(manifest['files']) == 198 <= MAX_FILES, 'closed complete Source map differs')
    for name, (body, _) in after.items():
        if name.endswith('.py'):
            compile(body, name, 'exec')
    return value, before, after


def emit(basis, output):
    basis, output = absolute(basis), absolute(output)
    for source in (basis, HERE):
        need(not output.is_relative_to(source) and not source.is_relative_to(output), 'disjoint source/output required')
    parent = output.parent; info = parent.stat()
    need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700 and not output.exists(),
         'fresh output in caller-owned0700 parent required')
    value, before, after = render(basis)
    stage = dict(status='SOURCE_ONLY_EXACT_PLATFORM_NATIVE199', operation='platform-alpm-v1',
                 parent=value['genuine_parent'], parent_tree=value['parent_tree'],
                 prospective_tree=value['source_tree'], source_map_sha256=value['source_map_sha256'],
                 source_files=199, source_map_rows=198, pr_base='main', integration_base=value['integration_base'],
                 actual=value['actual'], native='NOT_RUN', authenticated_platform_transition='NOT_RUN', release='NOT_ADMITTED')
    bodies = {'source/' + name: item for name, item in after.items()}
    before_rows, after_rows = rows(before), rows(after)
    delta = {n: dict(before=before_rows.get(n), after=after_rows.get(n)) for n in set(value['payload']) | set(value['producer_overlay'])}
    bodies.update({
        'stage.json': (encoded(stage), 0o644),
        'source-authorization.json': (encoded({n: {k: r[k] for k in ('bytes', 'sha256')} for n, r in rows(after).items()}), 0o644),
        'source-modes.json': (encoded({n: mode for n, (_, mode) in after.items()}), 0o644),
        'git-blobs.json': (encoded({n: dict(blob=oid(b'blob', raw).hex()) for n, (raw, _) in after.items()}), 0o644),
        'delta191.json': (encoded(dict(parent=value['genuine_parent'], changes=delta)), 0o644),
        'parent-commit.raw': (read(HERE / 'parent-commit.raw')[0], 0o644),
    })
    for name in set(value['payload']) | set(value['producer_overlay']):
        if name in before:
            bodies['before191/' + name] = before[name]
    with tempfile.TemporaryDirectory(prefix='.platform-source-', dir=parent) as temp:
        staged = Path(temp) / 'output'; staged.mkdir(mode=0o700)
        for name, (raw, mode) in sorted(bodies.items()):
            target = staged / name; target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with target.open('xb') as stream:
                stream.write(raw)
            target.chmod(mode)
        need(rows(tree(staged / 'source')) == value['after'], 'complete emitted Source differs')
        # RENAME_NOREPLACE preserves an output created concurrently by another owner.
        rename = ctypes.CDLL(None, use_errno=True).renameat2
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(staged), -100, os.fsencode(output), 1):
            code = ctypes.get_errno(); raise OSError(code, os.strerror(code))
    return stage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--basis', type=Path, required=True, help='Exact locally retained genuine191 Source')
    parser.add_argument('--output', type=Path, required=True, help='Absent directory inside an owned0700 parent')
    args = parser.parse_args()
    try:
        result = emit(args.basis.absolute(), args.output.absolute())
    except (OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
        parser.exit(1, 'platform native Source refused: ' + str(error) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
