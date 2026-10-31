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
PROFILE_SHA256 = '3dcdfb0d2f78693b909800cee83b424096d943d0440bf10087c6d397354cad15'
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



PRODUCER_BEFORE = {'bootstrap/scripts/ci/native_arm.py': {'bytes': 28318, 'sha256': 'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898'}, 'native/failure_retention.py': {'bytes': 13639, 'sha256': '20f9f6fb153d3be98e41c343e63f5994aa3708ccbd4299e1f551a38b697ffbe3'}, 'native/image_alpm_v1.py': {'bytes': 26998, 'sha256': '1f88ed10057cadfd99fe84822aa3f5e283f25baa1da948b42f9b01d6683a6cba'}, 'native/image_reader_v1.py': {'bytes': 102877, 'sha256': 'f7030add0ba69d559e3503cb0e411f99dc5ce170160a313c2e6bba1653af9c83'}, 'native/image_projection_v1.py': {'bytes': 12748, 'sha256': '4795b8a437cd63863823c05875f75f29eca517829cf8217d18dee0f890f62bfa'}}
PRODUCER_AFTER = {'bootstrap/scripts/ci/native_arm.py': {'bytes': 28877, 'mode': 420, 'sha256': '8e71ba83e7d5037c6f7772401ec3b872684ccfa8472d855d8d6d3052cb1f41ba'}, 'native/failure_retention.py': {'bytes': 13639, 'mode': 420, 'sha256': 'cdb50b755f3e76d0229278bb89476752702544f3c31947e74676c82b213a8dc7'}, 'native/image_alpm_v1.py': {'bytes': 29047, 'sha256': '6babb792a704a5d1465ddcc69f7e8e075f1badc7a13d5ce6a487f0ae98f1cf1e', 'mode': 420}, 'native/image_projection_v1.py': {'bytes': 12748, 'sha256': '3c2bd46a2b3cf4136187d6652a952c3d372ce30a8675b3c23c0b1ee67692d675', 'mode': 420}, 'native/image_reader_v1.py': {'bytes': 107867, 'sha256': '3a01b32e3daa8fe8164005040da75d6b6b8499a372ddae847457c610ee4edce1', 'mode': 420}}


def retired_producer(bodies):
    """Five authenticated producer/cleanup replacements; operands never execute."""
    need({name: dict(bytes=len(bodies[name]), sha256=hashlib.sha256(bodies[name]).hexdigest()) for name in PRODUCER_BEFORE} == PRODUCER_BEFORE,
         'strict frozen producer/observer inputs differ')
    overlay_rows, overlay = snapshot(HERE / 'producer-overlay')
    need(overlay_rows == PRODUCER_AFTER, 'fixed producer retirement overlay differs')
    result = dict(bodies)
    result.update(overlay)
    return result

CONCURRENCY_GROUP = 'native-arm-image-tools'
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


def profile():
    raw = read(HERE/'profile.json',1024**2)
    need(pin(raw)['sha256'] == PROFILE_SHA256, 'whole fixed source profile')
    value = json.loads(raw)
    need(value['schema'] == 1 and value['operation'] == 'image-tools-alpm-v1'
         and value['target_base'] == 'main' and value['actual'] == dict(source=None,ref=None,run=None)
         and len(value['parent']['files']) == 191 and len(value['expected']['files']) == 202
         and len(value['payload']) == 17 and value['producer_overlay'] == PRODUCER_AFTER, 'finite Source-only profile')
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
    bodies = retired_producer(scheduled_workflows(bodies))
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
