#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-owned finite recovery Source constructor; no package/native execution."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

HERE = Path(__file__).resolve().parent
PROFILE_SHA256 = '9c5b2d305e24a9414d30bbe2fd36c6f329609f2d1d4482c6866e6adfdd93a9e0'
CAP = 64 * 1024**2
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns')


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def oid(kind, raw):
    return hashlib.sha1(kind + b' ' + str(len(raw)).encode() + b'\0' + raw).digest()


def name(value):
    need(type(value) is str and re.fullmatch('[A-Za-z0-9._+/-]+', value)
         and not value.startswith('/') and all(p not in ('', '.', '..') for p in value.split('/')),
         'finite relative Source path')
    return value


def read(path):
    path = Path(path).absolute()
    need(path == path.resolve(), 'canonical nonsymlink input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 <= before.st_size <= CAP, 'bounded regular Source input')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(before.st_size + 1)
        need(len(raw) == before.st_size and all(getattr(before, k) == getattr(os.fstat(fd), k)
             == getattr(path.lstat(), k) for k in FIELDS), 'Source changed during read')
        return raw
    finally:
        os.close(fd)


def snapshot(root, limit):
    root = Path(root).absolute()
    need(root == root.resolve() and root.is_dir(), 'canonical Source root')
    rows, bodies, dirs = {}, {}, set()
    for directory, children, files in os.walk(root, followlinks=False):
        base = Path(directory)
        for child in tuple(children):
            path = base / child
            if base == root and child == '.git':
                children.remove(child)
                continue
            need(not path.is_symlink(), 'ordinary Source directory')
            dirs.add(path.relative_to(root).as_posix())
        for leaf in files:
            if base == root and leaf == '.git':
                continue
            path = base / leaf; relative = name(path.relative_to(root).as_posix())
            raw = read(path); mode = stat.S_IMODE(path.stat().st_mode)
            need(mode in (0o644, 0o755), 'exact Source mode')
            bodies[relative] = raw; rows[relative] = dict(**pin(raw), mode=mode)
            need(len(rows) <= limit and sum(r['bytes'] for r in rows.values()) <= CAP,
                 'finite Source namespace and total bytes')
    need(dirs == {str(p) for n in rows for p in Path(n).parents if p != Path('.')},
         'complete Source directory namespace')
    return rows, bodies


def tree(bodies, modes):
    root = {}
    for relative, raw in bodies.items():
        node = root; parts = name(relative).split('/')
        for part in parts[:-1]:
            node = node.setdefault(part, {})
            need(type(node) is dict, 'Source file/directory overlap')
        need(parts[-1] not in node, 'duplicate Source leaf')
        node[parts[-1]] = raw, modes[relative]
    def walk(node):
        raw = b''
        for leaf, value in sorted(node.items(), key=lambda x: (x[0] + ('/' if type(x[1]) is dict else '')).encode()):
            mode, digest = (b'40000', walk(value)) if type(value) is dict else (
                b'100755' if value[1] == 0o755 else b'100644', oid(b'blob', value[0]))
            raw += mode + b' ' + leaf.encode() + b'\0' + digest
        return oid(b'tree', raw)
    return walk(root).hex()


def profile():
    raw = read(HERE / 'profile.json')
    need(pin(raw)['sha256'] == PROFILE_SHA256, 'whole recovery factory profile')
    value = json.loads(raw)
    need(value['schema'] == 1 and value['kind'] == 'security-interrupted-recovery-native-source-v1'
         and value['operation'] == 'security-alpm-interrupted-recovery-v1'
         and value['parent']['source'] == '850368889d6dcabdc8afbe87f64f05650c44f90a'
         and len(value['parent']['files']) == 200 and len(value['expected']['files']) == value['files']
         and value['map_rows'] == value['files'] - 1
         and value['actual'] == dict(source=None, ref=None, run=None, job=None, artifact=None),
         'exact finite unexecuted recovery successor')
    return value


def render(parent):
    value = profile(); before, bodies = snapshot(parent, 200)
    need(before == value['parent']['files'] and tree(bodies, {n: r['mode'] for n, r in before.items()})
         == value['parent']['tree'], 'all200 genuine Source850 inputs')
    raw = read(HERE / 'parent-commit.raw'); header = raw.split(b'\n\n', 1)[0].splitlines()
    need(pin(raw) == value['parent']['raw_commit'] and oid(b'commit', raw).hex() == value['parent']['source']
         and [x[5:].decode() for x in header if x.startswith(b'tree ')] == [value['parent']['tree']]
         and [x[7:].decode() for x in header if x.startswith(b'parent ')]
         == ['ff8241ec2c73b69d6e54b8ee15209ef30760d619'], 'actual parent raw/tree/sole ff ancestry')
    overlay_rows, overlay = snapshot(HERE / 'overlay', value['files'])
    need(overlay_rows == value['payload'], 'exact finite overlay')
    need(json.loads(bodies['native/source-map.json'])['files']
         == {n: r for n, r in before.items() if n != 'native/source-map.json'}, 'parent map199')
    bodies.update(overlay); modes = {n: r['mode'] for n, r in value['expected']['files'].items()}
    mapping = dict(value['source_map_metadata'])
    mapping['files'] = {n: dict(**pin(raw), mode=modes[n]) for n, raw in sorted(bodies.items())
                        if n != 'native/source-map.json'}
    need(len(mapping['files']) == value['map_rows'] and mapping['actual']
         == dict(source=None, ref=None, run=None), 'finite nonrecursive new map; no predicted actual selectors')
    bodies['native/source-map.json'] = encoded(mapping)
    after = {n: dict(**pin(raw), mode=modes[n]) for n, raw in bodies.items()}
    need(after == value['expected']['files'] and tree(bodies, modes) == value['expected']['tree'],
         'whole recovery Source body/mode/map/tree')
    for alias in ('.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-developer-workflows.yml'):
        declarations = re.findall(rb"'([0-9a-f]{64})' native/common.py \| sha256sum --check", bodies[alias])
        need(declarations == [pin(bodies['native/common.py'])['sha256'].encode()], 'workflow/common binding')
    return value, bodies, modes


def assemble(parent, output):
    parent, output = Path(parent).absolute(), Path(output).absolute()
    need(not os.path.lexists(output) and output.parent == output.parent.resolve()
         and output.parent.is_dir() and output.parent.stat().st_uid == os.geteuid()
         and stat.S_IMODE(output.parent.stat().st_mode) == 0o700, 'fresh output in caller-owned0700 directory')
    need(not output.is_relative_to(parent) and not parent.is_relative_to(output)
         and not output.is_relative_to(HERE) and not HERE.is_relative_to(output), 'disjoint input/output')
    value, bodies, modes = render(parent)
    stage = dict(status='PREPARED_FINITE_SECURITY_RECOVERY_SOURCE_NOT_NATIVE', files=value['files'],
        map_rows=value['map_rows'], prospective_tree=value['expected']['tree'], parent=value['parent']['source'],
        ref=value['proposed_ref'], operation=value['operation'], actual=value['actual'], native='NOT_RUN',
        interruption='NOT_RUN', recovery='NOT_RUN', upstream_source_binary_correspondence='OPEN')
    with tempfile.TemporaryDirectory(prefix='.recovery-source-', dir=output.parent) as temporary:
        work = Path(temporary) / 'stage'; work.mkdir(mode=0o700)
        for name, raw in bodies.items():
            path = work / 'source' / name; path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as stream: stream.write(raw)
            path.chmod(modes[name])
        for name, data in {'stage.json': stage,
                           'source-authorization.json': {n: pin(b) for n, b in bodies.items()},
                           'source-modes.json': modes,
                           'dispatch-template.json': dict(ref=value['proposed_ref'], inputs=dict(
                               source_sha=None, source_map_sha256=pin(bodies['native/source-map.json'])['sha256'],
                               operation=value['operation'])),
                           'reader-binding-template.json': dict(source=None, ref=None, run=None,
                               map_sha256=pin(bodies['native/source-map.json'])['sha256'])}.items():
            (work / name).write_bytes(encoded(data))
        need(snapshot(work / 'source', value['files'])[0] == value['expected']['files'], 'emitted exact Source')
        rename = ctypes.CDLL(None, use_errno=True).renameat2
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(work), -100, os.fsencode(output), 1):
            code = ctypes.get_errno(); raise OSError(code, os.strerror(code))
    return stage


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(assemble(args.parent, args.output), sort_keys=True))
