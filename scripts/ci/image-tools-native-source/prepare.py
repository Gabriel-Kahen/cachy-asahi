#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit an exact image-tools native Source from a held parent; no actors."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

HERE = Path(__file__).resolve().parent
PROFILE_SHA256 = '14355b0aa64cd6eadea85bb268c61224553fee70f8c0a3d0596a7f53da29ed82'
FIELDS = ('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
MAX_FILE = 64*1024**2
MAX_SOURCE = 64*1024**2


def need(value, why):
    if not value:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def read(path, maximum=MAX_FILE):
    path = Path(path).absolute()
    need(path == path.resolve(), 'source symlink ancestry')
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= maximum,
             'bounded ordinary single-link source')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            raw = stream.read(maximum+1)
        need(len(raw) == before.st_size and all(getattr(before,key) == getattr(os.fstat(fd),key)
             == getattr(path.lstat(),key) for key in FIELDS), 'source changed during read')
        return raw
    finally:
        os.close(fd)


def name(value):
    need(type(value) is str and re.fullmatch(r'[A-Za-z0-9._+/-]+',value)
         and not value.startswith('/') and all(part not in ('','.','..') for part in value.split('/')), 'relative source path')
    return value


def snapshot(root, *, checkout=False):
    root = Path(root).absolute()
    need(root == root.resolve() and root.is_dir(), 'ordinary source root')
    rows, bodies, directories = {}, {}, set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        base = Path(directory)
        for leaf in tuple(dirs):
            path = base/leaf
            need(not path.is_symlink(), 'source directory alias')
            if checkout and base == root and leaf == '.git':
                dirs.remove(leaf)
            else:
                directories.add(path.relative_to(root).as_posix())
        for leaf in files:
            if checkout and base == root and leaf == '.git':
                continue
            path = base/leaf; relative = name(path.relative_to(root).as_posix())
            raw = read(path); mode = stat.S_IMODE(path.lstat().st_mode)
            need(mode in (0o644,0o755), 'source mode')
            rows[relative] = dict(**pin(raw),mode=mode); bodies[relative] = raw
            need(len(rows) <= 256 and sum(item['bytes'] for item in rows.values()) <= MAX_SOURCE, 'finite source bounds')
    expected_dirs = {str(p) for leaf in rows for p in Path(leaf).parents if p != Path('.')}
    need(directories == expected_dirs, 'source directory namespace')
    return rows, bodies


def object_id(kind, raw):
    return hashlib.sha1(kind+b' '+str(len(raw)).encode()+b'\0'+raw).digest()


def tree_id(bodies, modes):
    nodes = {}
    for leaf, raw in bodies.items():
        parts = name(leaf).split('/'); parent = nodes
        for part in parts[:-1]:
            parent = parent.setdefault(part,{})
            need(type(parent) is dict, 'file/directory overlap')
        need(parts[-1] not in parent, 'duplicate source path')
        parent[parts[-1]] = (raw,modes[leaf])
    def digest(directory):
        result = b''
        for leaf,value in sorted(directory.items(),key=lambda row:row[0].encode()+(b'/' if type(row[1]) is dict else b'')):
            if type(value) is dict:
                mode,body = b'40000',digest(value)
            else:
                raw,source_mode = value; mode = b'100755' if source_mode == 0o755 else b'100644'; body = object_id(b'blob',raw)
            result += mode+b' '+leaf.encode()+b'\0'+body
        return object_id(b'tree',result)
    return digest(nodes).hex()


def profile():
    raw = read(HERE/'profile.json',1024**2)
    need(pin(raw)['sha256'] == PROFILE_SHA256, 'whole fixed source profile')
    value = json.loads(raw)
    need(value['schema'] == 1 and value['operation'] == 'image-tools-alpm-v1'
         and value['target_base'] == 'main' and value['actual'] == dict(source=None,ref=None,run=None)
         and len(value['parent']['files']) == 191 and len(value['expected']['files']) == 202
         and len(value['payload']) == 17, 'finite Source-only profile')
    return value


def assemble(parent, output):
    value = profile(); parent, output = Path(parent).absolute(), Path(output).absolute()
    need(not os.path.lexists(output) and output.parent.is_dir() and output.parent == output.parent.resolve(), 'fresh ordinary output')
    need(all(not output.is_relative_to(root) and not root.is_relative_to(output) for root in (parent,HERE)), 'disjoint Source output')
    before, bodies = snapshot(parent,checkout=True)
    need(before == value['parent']['files'] and tree_id(bodies,{n:r['mode'] for n,r in before.items()}) == value['parent']['tree'], 'complete exact parent body/mode/tree')
    maintained, replacements = snapshot(HERE/'payload')
    need(maintained == value['payload'], 'complete fixed payload')
    # All parent and maintained input bytes are authenticated before writing output.
    bodies.update(replacements)
    expected = value['expected']['files']; modes = {n:r['mode'] for n,r in expected.items()}
    mapping = dict(value['source_map_metadata'])
    mapping['files'] = {n:dict(**pin(raw),mode=modes[n]) for n,raw in sorted(bodies.items()) if n != 'native/source-map.json'}
    bodies['native/source-map.json'] = (json.dumps(mapping,sort_keys=True,indent=2)+'\n').encode()
    actual = {n:dict(**pin(raw),mode=modes[n]) for n,raw in bodies.items()}
    need(actual == expected and tree_id(bodies,modes) == value['expected']['tree'], 'exact generated Source body/mode/tree')
    for alias in ('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-developer-workflows.yml'):
        declarations = re.findall(rb"'([0-9a-f]{64})' native/common.py \| sha256sum --check",bodies[alias])
        need(declarations == [hashlib.sha256(bodies['native/common.py']).hexdigest().encode()], 'native workflow common checksum binding')
    output.mkdir(mode=0o700)
    for leaf,raw in sorted(bodies.items()):
        target = output/leaf; target.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        with target.open('xb') as stream:
            stream.write(raw)
        target.chmod(modes[leaf])
    after,_ = snapshot(output)
    need(after == expected, 'full emitted Source verification')
    return dict(status='PREPARED_NATIVE_SOURCE_ONLY',operation=value['operation'],files=202,tree=value['expected']['tree'],
                source_map_sha256=pin(bodies['native/source-map.json'])['sha256'],target_base='main',actual=value['actual'],
                native='NOT_RUN',GPG='NOT_RUN',ALPM='NOT_RUN',M2='NOT_RUN',release='NOT_ADMITTED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    print(json.dumps(assemble(args.parent,args.output),sort_keys=True))


if __name__ == '__main__':
    main()
