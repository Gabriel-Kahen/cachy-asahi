#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-invoked Source201 DATA constructor; import never constructs or executes."""
import argparse
import ast
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
PARENT = '05df8c71ea2bcb525bb1cfbc59983452062a1e97'
PROFILE_SHA256 = '87c87e685a77609f09c1ba19a8e27c0fa2ede60b70ee3fff27707d5653020f35'
MAP = 'native/source-map.json'
MAX_SOURCE_MAPPED, MAX_SOURCE_PHYSICAL = 200, 201
MAX_FILE, MAX_TOTAL = 32 * 1024**2, 96 * 1024**2
OPERATION = 'platform-namespace-policy-matrix-v1'


def need(value, message):
    if not value:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw, mode=None):
    result = dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    if mode is not None:
        result['mode'] = mode
    return result


def pairs(rows):
    result = {}
    for key, value in rows:
        need(key not in result, 'duplicate JSON field')
        result[key] = value
    return result


def document(raw):
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: need(False, 'nonfinite JSON refused'))


def relative(name):
    need(type(name) is str and 0 < len(name) <= 512, 'bounded Source path')
    path = PurePosixPath(name)
    need(path.as_posix() == name and not path.is_absolute() and len(path.parts) <= 24
         and all(re.fullmatch(r'[A-Za-z0-9_.+-]+', part) and part not in ('.', '..', '.git')
                 for part in path.parts), 'canonical Source path')
    return path


def absolute(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts
         and not any(p.is_symlink() for p in (path, *path.parents)), 'absolute nonaliased path')
    return path


def read(path, maximum=MAX_FILE):
    path = absolute(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= maximum, 'bounded ordinary Source operand')
        chunks, size = [], 0
        while block := os.read(fd, min(65536, before.st_size + 1 - size)):
            chunks.append(block); size += len(block)
            need(size <= before.st_size, 'growing Source operand')
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        after = os.fstat(fd)
        need(size == before.st_size and all(getattr(before, k) == getattr(after, k)
             == getattr(path.lstat(), k) for k in fields), 'stable whole FD/path Source operand')
        return b''.join(chunks), stat.S_IMODE(before.st_mode)
    finally:
        os.close(fd)


def scan(root, maximum, checkout=False):
    root = absolute(root); need(root.is_dir(), 'existing ordinary Source root')
    result, directories, total = {}, set(), 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        current = Path(directory)
        if checkout and current == root:
            for name in list(dirs) + list(names):
                if name == '.git':
                    need(not (current / name).is_symlink(), 'root Git metadata alias')
            dirs[:] = [name for name in dirs if name != '.git']
            names = [name for name in names if name != '.git']
        for name in dirs:
            child = current / name
            need(stat.S_ISDIR(child.lstat().st_mode), 'Source directory alias/special node')
            directories.add(child.relative_to(root).as_posix())
        for name in names:
            child = current / name; leaf = child.relative_to(root).as_posix(); relative(leaf)
            need(len(result) < maximum, 'bounded Source physical namespace')
            raw, mode = read(child); total += len(raw)
            need(mode in (0o644, 0o755) and total <= MAX_TOTAL, 'Source mode/total bound')
            result[leaf] = raw, mode
    wanted = {q.as_posix() for name in result for q in PurePosixPath(name).parents
              if q != PurePosixPath('.')}
    need(directories == wanted, 'complete Source directory inverse')
    return result


def rows(files):
    return {name: pin(raw, mode) for name, (raw, mode) in sorted(files.items())}


def oid(kind, raw):
    return hashlib.sha1(kind + b' ' + str(len(raw)).encode() + b'\0' + raw).digest()


def git_tree(files):
    nested = {}
    for name, (raw, mode) in files.items():
        parts = relative(name).parts; at = nested
        for part in parts[:-1]:
            need(not isinstance(at.get(part), tuple), 'Source tree directory collision')
            at = at.setdefault(part, {})
        need(parts[-1] not in at, 'Source tree duplicate')
        at[parts[-1]] = raw, mode
    def visit(at):
        body = bytearray()
        for name, item in sorted(at.items(), key=lambda row:
                (row[0] + ('/' if type(row[1]) is dict else '')).encode()):
            directory = type(item) is dict
            mode = b'40000' if directory else b'100755' if item[1] == 0o755 else b'100644'
            body += mode + b' ' + name.encode() + b'\0'
            body += visit(item) if directory else oid(b'blob', item[0])
        return oid(b'tree', bytes(body))
    return visit(nested).hex()


def parent_profile():
    raw, _ = read(HERE / 'parent-profile.json', 1024**2)
    need(pin(raw)['sha256'] == PROFILE_SHA256, 'fixed whole parent authority')
    value = document(raw)
    need(value['schema'] == 1 and value['kind'] == 'platform-namespace-policy-parent-v1'
         and value['parent'] == PARENT and len(value['files']) == 199
         and value['limits'] == dict(mapped=200, physical=201, leaf=MAX_FILE, total=MAX_TOTAL)
         and value['actual'] == dict(source=None, ref=None, run=None)
         and value['operation'] == OPERATION and value['concurrency_group'] == 'native-arm-platform-tools',
         'exact inert parent/limits/operation authority')
    commit, _ = read(HERE / 'parent-commit.raw', 4096)
    need(pin(commit) == value['parent_raw'] and oid(b'commit', commit).hex() == PARENT,
         'actual05df raw commit identity')
    header = commit.split(b'\n\n', 1)[0].splitlines()
    need([line[5:].decode() for line in header if line.startswith(b'tree ')] == [value['parent_tree']]
         and [line[7:].decode() for line in header if line.startswith(b'parent ')] == [value['parent_sole_parent']],
         'actual05df raw tree/sole d78 parent')
    return value, commit


def render(basis, overlay_root, overlay_manifest, manifest_sha256):
    """Future explicit construction only; imported Source modules never execute."""
    profile, commit = parent_profile()
    before = scan(basis, 199, checkout=True)
    wanted = {name: {k: row[k] for k in ('bytes', 'sha256', 'mode')}
              for name, row in profile['files'].items()}
    need(rows(before) == wanted and git_tree(before) == profile['parent_tree'],
         'full199 parent body/mode/tree inverse')
    need(all(oid(b'blob', before[name][0]).hex() == row['blob']
             for name, row in profile['files'].items()), 'full199 parent Git blob inverse')
    old_map = document(before[MAP][0])
    need(pin(before[MAP][0])['sha256'] == profile['parent_map_sha256']
         and old_map['schema'] == 1 and old_map['actual'] == dict(source=None, ref=None, run=None)
         and old_map['files'] == {n: row for n, row in rows(before).items() if n != MAP},
         'complete198 parent map/body inverse')
    raw, _ = read(overlay_manifest, 1024**2)
    need(type(manifest_sha256) is str and re.fullmatch('[0-9a-f]{64}', manifest_sha256)
         and pin(raw)['sha256'] == manifest_sha256, 'independently selected whole overlay manifest')
    selected = document(raw)
    need(set(selected) == {'schema', 'kind', 'parent', 'operation', 'files', 'expected_tree', 'expected_map_sha256'}
         and selected['schema'] == 1 and selected['kind'] == 'platform-namespace-policy-overlay-v1'
         and selected['parent'] == PARENT and selected['operation'] == OPERATION
         and set(selected['files']) == set(profile['overlay_paths']), 'exact six-path overlay authority')
    need(re.fullmatch('[0-9a-f]{40}', selected['expected_tree'])
         and re.fullmatch('[0-9a-f]{64}', selected['expected_map_sha256']), 'explicit expected Source tree/map')
    overlay = scan(overlay_root, 6)
    need(rows(overlay) == selected['files'] and set(overlay) - set(before) == set(profile['new_paths']),
         'only exact two added leaves and four authenticated driver changes')
    core = overlay['native/platform_namespace_policy_v1.py'][0]
    need(pin(core[:profile['matrix_core']['bytes']]) == profile['matrix_core']
         and pin(overlay['native/platform-namespace-policy-v1.json'][0]) == profile['matrix_contract'],
         'frozen86 DATA core prefix and contract preserved')
    aliases = ('.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-developer-workflows.yml')
    workflow = overlay[aliases[0]][0]
    need(workflow == overlay[aliases[1]][0] and OPERATION.encode() in workflow
         and b'concurrency:\n  group: native-arm-platform-tools\n  cancel-in-progress: false\n  queue: max\njobs:\n' in workflow,
         'exact workflow aliases/fixed native group/false cancellation/queue')
    after = dict(before); after.update(overlay)
    new_map = dict(old_map)
    new_map['files'] = {n: row for n, row in rows(after).items() if n != MAP}
    need(len(new_map['files']) == MAX_SOURCE_MAPPED, 'unchanged Source mapped-file cap200')
    after[MAP] = encoded(new_map), before[MAP][1]
    need(len(after) == MAX_SOURCE_PHYSICAL and git_tree(after) == selected['expected_tree']
         and pin(after[MAP][0])['sha256'] == selected['expected_map_sha256'], 'full201 prospective Source tree/map')
    changed = {n for n in before.keys() | after.keys() if before.get(n) != after.get(n)}
    need(changed == set(profile['overlay_paths']) | {MAP}, 'all unlisted parent bodies/modes held')
    inverse = {n: after[n] for n in before if n not in changed}
    inverse.update({n: before[n] for n in changed if n in before})
    need(rows(inverse) == wanted and git_tree(inverse) == profile['parent_tree'], 'full199 physical inverse to actual05df')
    for name, (body, _) in after.items():
        if name.endswith('.py'):
            ast.parse(body, filename=name)  # Parse only; never import or execute any Source actor.
    return profile, commit, before, after, changed, selected


def emit(basis, overlay_root, overlay_manifest, manifest_sha256, output):
    basis, overlay_root, overlay_manifest, output = map(absolute,
        (basis, overlay_root, overlay_manifest, output))
    for operand in (basis, overlay_root, HERE):
        need(not output.is_relative_to(operand) and not operand.is_relative_to(output), 'disjoint Source/output roots')
    parent = output.parent; info = parent.stat()
    need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700
         and not os.path.lexists(output), 'fresh output in owned0700 parent')
    profile, commit, before, after, changed, selected = render(
        basis, overlay_root, overlay_manifest, manifest_sha256)
    stage = dict(status='SOURCE_ONLY_EXACT_PLATFORM_NAMESPACE_POLICY201', operation=OPERATION,
        parent=PARENT, parent_tree=profile['parent_tree'], prospective_tree=selected['expected_tree'],
        source_map_sha256=selected['expected_map_sha256'], source_files=201, source_map_rows=200,
        concurrency_group='native-arm-platform-tools', actual=dict(source=None, ref=None, run=None),
        constructed=True, built=False, installed=False, native='NOT_RUN', namespace_probe='NOT_RUN',
        physical_M2='NOT_RUN', release='NOT_ADMITTED', acceptance=False)
    before_rows, after_rows = rows(before), rows(after)
    bodies = {'source/' + n: item for n, item in after.items()}
    bodies.update({
        'stage.json': (encoded(stage), 0o644),
        'source-authorization.json': (encoded({n: pin(raw) for n, (raw, _) in after.items()}), 0o644),
        'source-modes.json': (encoded({n: mode for n, (_, mode) in after.items()}), 0o644),
        'git-blobs.json': (encoded({n: dict(blob=oid(b'blob', raw).hex()) for n, (raw, _) in after.items()}), 0o644),
        'parent-commit.raw': (commit, 0o644),
        'parent-full-map.json': (encoded(profile['files']), 0o644),
        'delta05df.json': (encoded(dict(parent=PARENT, changes={n: dict(before=before_rows.get(n),
            after=after_rows.get(n)) for n in sorted(changed)}, full_parent_inverse=True)), 0o644),
        'selected-overlay.json': (encoded(selected), 0o644),
    })
    for name in changed:
        if name in before:
            bodies['before05df/' + name] = before[name]
    with tempfile.TemporaryDirectory(prefix='.namespace-policy-source-', dir=parent) as temporary:
        staged = Path(temporary) / 'output'; staged.mkdir(mode=0o700)
        for name, (raw, mode) in sorted(bodies.items()):
            target = staged / name; target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with target.open('xb') as stream:
                need(stream.write(raw) == len(raw), 'whole Source DATA write'); stream.flush(); os.fsync(stream.fileno())
            target.chmod(mode)
        need(rows(scan(staged / 'source', MAX_SOURCE_PHYSICAL)) == after_rows, 'complete emitted201 body/mode inverse')
        rename = ctypes.CDLL(None, use_errno=True).renameat2
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(staged), -100, os.fsencode(output), 1):
            code = ctypes.get_errno(); raise OSError(code, os.strerror(code))
    return stage


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--basis', type=Path, required=True, help='Exact public actual05df Source199 checkout')
    parser.add_argument('--overlay-root', type=Path, required=True, help='Only six authenticated sparse Source operands')
    parser.add_argument('--overlay-manifest', type=Path, required=True)
    parser.add_argument('--overlay-manifest-sha256', required=True, help='Root-selected whole manifest hash, never auto-derived')
    parser.add_argument('--output', type=Path, required=True, help='Absent directory in owned0700 parent')
    args = parser.parse_args()
    try:
        result = emit(args.basis.absolute(), args.overlay_root.absolute(), args.overlay_manifest.absolute(),
                      args.overlay_manifest_sha256, args.output.absolute())
    except (OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
        parser.exit(1, 'namespace policy Source refused: ' + str(error) + '\n')
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main()
