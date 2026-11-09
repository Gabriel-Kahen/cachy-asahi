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

HERE = Path(__file__).resolve().parent
MAX_FILE, MAX_TOTAL, MAX_FILES = 64 * 1024**2, 128 * 1024**2, 256
MAP = 'native/source-map.json'
PARENT = '97a44c4c7cb206704bf76e9fd1f1afb2266278c2'
PARENT_TREE = '81d61d9e1f33c1638e9f67fbd7e39b158c603451'
OPERATION = 'hyprland03-alpm-v1'
ALLOWED = frozenset(('.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-developer-workflows.yml',
    'native/build-tools-contract-v2.json', 'native/build-tools-sources-v2.tar', 'native/build_tools_alpm_v2.py',
    'native/build_tools_guest_v2.py', 'native/build_tools_projection_v2.py', 'native/build_tools_reader_v2.py',
    'native/build_tools_tools_v2.py', 'native/invocation.json', 'native/owner.py'))

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
                need(mode in (0o644, 0o755), 'source file mode must be 0644/0755')
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



def publish(files, output):
    """Own only a fresh staging tree; atomically refuse preexisting destinations."""
    output = absolute(output)
    need(output != Path('/') and output.name not in ('', '.', '..'), 'fresh output child required')
    parent = directory(output.parent); staging = None
    try:
        info = os.fstat(parent)
        need(info.st_uid == os.getuid() and not stat.S_IMODE(info.st_mode) & 0o022, 'owned output parent without group/world writes required')
        try:
            os.stat(output.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError('fresh absent output required')
        staging = Path(tempfile.mkdtemp(prefix='.hyprland03-stage-', dir=output.parent))
        held = staging.lstat()
        for name, (raw, mode) in sorted(files.items()):
            target = staging / relative(name)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw); stream.flush(); os.fchmod(stream.fileno(), mode)
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


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def profile(raw, checksum):
    need(type(checksum) is str and re.fullmatch('[0-9a-f]{64}', checksum) and pin(raw)['sha256'] == checksum,
         'externally authenticated whole profile checksum required')
    value = decode(raw)
    need(set(value) == {'schema','purpose','parent','parent_tree','parent_raw','parent_files','overlay',
                       'operation','actual','main_base','prospective_tree','map_sha256','parent_blobs'}
         and type(value['schema']) is int and value['schema'] == 1
         and value['purpose'] == 'hyprland03-finite-native-source-v1'
         and value['parent'] == PARENT and value['parent_tree'] == PARENT_TREE
         and value['operation'] == OPERATION
         and value['actual'] == dict(source=None, ref=None, run=None, job=None, artifact=None)
         and value['main_base'] == 'dd12e3cc59a8669f9c5e0bcc02d04171339870a3', 'exact unexecuted Hyprland03 profile required')
    for name, count in (('parent_files', 200), ('overlay', 11)):
        rows = value[name]
        need(type(rows) is dict and len(rows) == count, 'exact finite row count')
        for path, item in rows.items():
            relative(path)
            need(type(item) is dict and set(item) == {'bytes','sha256','mode'}
                 and type(item['bytes']) is int and 0 < item['bytes'] <= MAX_FILE
                 and type(item['mode']) is int and item['mode'] in (0o644,0o755)
                 and type(item['sha256']) is str and re.fullmatch('[0-9a-f]{64}',item['sha256']), 'typed finite descriptor required')
        need(sum(item['bytes'] for item in rows.values()) <= MAX_TOTAL, 'finite aggregate source bound')
    need(type(value['parent_blobs']) is dict and set(value['parent_blobs']) == set(value['parent_files'])
         and all(type(v) is str and re.fullmatch('[0-9a-f]{40}',v) for v in value['parent_blobs'].values()), 'complete parent blob row identity required')
    need(set(value['overlay']) == ALLOWED and ALLOWED <= set(value['parent_files']) and MAP not in value['overlay'],
         'finite same-namespace replacements only; map is independently generated')
    need(all(type(value[k]) is str and re.fullmatch('[0-9a-f]{40}' if k == 'prospective_tree' else '[0-9a-f]{64}',value[k])
             for k in ('prospective_tree','map_sha256')), 'exact prospective Source identity required')
    return value


def compose(before, overlay, value):
    need({n:oid(b'blob',r).hex() for n,(r,m) in before.items()} == value['parent_blobs'], 'all genuine parent Git blob bodies required')
    need(descriptors(before) == value['parent_files'] and tree(before) == PARENT_TREE,
         'complete physical genuine Source97 parent differs')
    need(descriptors(overlay) == value['overlay'], 'whole reviewed package overlay differs')
    after = dict(before); after.update(overlay)
    mapping = decode(before[MAP][0]); mapping['hyprland03_operation'] = OPERATION
    mapping['files'] = {n:r for n,r in descriptors(after).items() if n != MAP}
    after[MAP] = (encoded(mapping), before[MAP][1])
    need(len(after) == 200 and len(mapping['files']) == 199
         and mapping['actual'] == dict(source=None,ref=None,run=None)
         and pin(after[MAP][0])['sha256'] == value['map_sha256'] and tree(after) == value['prospective_tree'],
         'exact complete Source200/map199 closure differs')
    inverse = dict(after)
    for name in {*overlay, MAP}: inverse[name] = before[name]
    need(inverse == before and tree(inverse) == PARENT_TREE, 'complete byte/mode inverse differs')
    return after


def prepare(parent_source, output, profile_sha256):
    value = profile(read(HERE/'profile.json', 1024**2)[0], profile_sha256)
    raw, mode = read(HERE/'parent.raw', 4096)
    need(mode == 0o644 and pin(raw) == value['parent_raw'] and oid(b'commit',raw).hex() == PARENT
         and raw.splitlines()[0] == ('tree '+PARENT_TREE).encode(), 'genuine physical parent commit identity required')
    parent_source, output = absolute(parent_source), absolute(output)
    need(output != parent_source and parent_source not in output.parents and output not in parent_source.parents
         and output != HERE and HERE not in output.parents and output not in HERE.parents, 'fresh disjoint output required')
    before = snapshot(parent_source); overlay = snapshot(HERE/'payload')
    after = compose(before, overlay, value)
    publish(after, output)
    return dict(status='SOURCE_DATA_ONLY', source_files=200, tree=value['prospective_tree'],
                map_sha256=value['map_sha256'], actual=value['actual'], native='NOT_RUN', installation='NOT_RUN',
                physical_M2='NOT_RUN', GUI='NOT_RUN', capture='NOT_RUN', release='NOT_ADMITTED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile-sha256', required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.parent_source,args.output,args.profile_sha256),sort_keys=True))
