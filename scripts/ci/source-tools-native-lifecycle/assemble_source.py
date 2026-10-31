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
GENUINE_PARENT = '111f14d2b21b220d86912d5ead978848c7ef1cb0'
PARENT_TREE = 'f45820b0ef37b48f50bbc361a22f53b5dd309506'
MAIN_BASE = 'eaf43eddc5604773d8176f319700a450bc32ccb0'
OPERATION = 'source-tools-alpm-v1'
MAX_FILE, MAX_TOTAL, MAX_FILES = 64 * 1024**2, 128 * 1024**2, 256
MAP = 'native/source-map.json'
SEAMS = frozenset((MAP, 'native/owner.py', 'native/invocation.json',
    '.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-developer-workflows.yml'))
ADDITIONS = frozenset('native/' + name for name in (
    'source_tools_alpm_v1.py', 'source_tools_tools_v1.py', 'source_tools_guest_v1.py',
    'source_tools_probe_v1.py', 'source_tools_reader_v1.py', 'source_tools_projection_v1.py',
    'source-tools-contract-v1.json', 'source-tools-makepkg-v1.conf', 'source-tools-sources-v1.tar'))
FIELDS = frozenset(('schema', 'purpose', 'genuine_parent', 'parent_tree', 'parent_files',
    'overlay', 'producer_overlay', 'source_map_sha256', 'prospective_tree', 'operation', 'actual', 'main_base', 'source_files'))


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



PRODUCER_BEFORE = {'bootstrap/scripts/ci/native_arm.py': {'bytes': 28318, 'sha256': 'a8b6ed8971a38089a4499dcec605477c4e48d7a47c3de485d205f6a44678b898'}, 'native/failure_retention.py': {'bytes': 13639, 'sha256': '20f9f6fb153d3be98e41c343e63f5994aa3708ccbd4299e1f551a38b697ffbe3'}, 'native/source_tools_alpm_v1.py': {'bytes': 27900, 'sha256': '4299d71ba98f8d6e8cf3cbbe057294a7b82359e93162c850b7808b0216141d3d'}, 'native/source_tools_reader_v1.py': {'bytes': 116262, 'sha256': '6a640d1008d5f6364631a330f341945b55e8d59bda089360fb1656d0dcad5a92'}, 'native/source_tools_projection_v1.py': {'bytes': 10628, 'sha256': '0c91e8bd674b05f1a68d6cff6000dcaa74752d665e0566f2ff7768764ce8150c'}}
PRODUCER_AFTER = {'native/failure_retention.py': {'bytes': 13639, 'sha256': 'cdb50b755f3e76d0229278bb89476752702544f3c31947e74676c82b213a8dc7', 'mode': 420}, 'native/source_tools_alpm_v1.py': {'bytes': 28092, 'sha256': 'c332fbef08d7e03be918b45a67c1eb705eaa41425e02bd84111a50058eed0279', 'mode': 420}, 'native/source_tools_reader_v1.py': {'bytes': 116398, 'sha256': '05c3ff5a7d32d6d797976337a8b28f95dc8dfd9b438b9ca916adc5d44ea65833', 'mode': 420}, 'native/source_tools_projection_v1.py': {'bytes': 10628, 'sha256': '91b906e7fc89fbe2df4cff1d2f7a37c8fc42b6eb34f6e3b2ff7d63a4601a1c3b', 'mode': 420}, 'bootstrap/scripts/ci/native_arm.py': {'bytes': 28877, 'sha256': '8e71ba83e7d5037c6f7772401ec3b872684ccfa8472d855d8d6d3052cb1f41ba', 'mode': 420}}


def retired_producer(bodies):
    """Five authenticated producer/cleanup replacements; operands never execute."""
    need({name: dict(bytes=len(bodies[name]), sha256=hashlib.sha256(bodies[name]).hexdigest()) for name in PRODUCER_BEFORE} == PRODUCER_BEFORE,
         'strict frozen producer/observer inputs differ')
    overlay = snapshot(HERE / 'producer-overlay')
    need(descriptors(overlay) == PRODUCER_AFTER, 'fixed producer retirement overlay differs')
    result = dict(bodies)
    result.update({name: raw for name, (raw, _) in overlay.items()})
    return result

CONCURRENCY_GROUP = 'native-arm-source-tools'
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
    manifest = decode(files['native/source-map.json'][0])
    need(manifest['files'] == {name: row for name, row in descriptors(files).items() if name != 'native/source-map.json'}, 'original source map before scheduling differs')
    manifest['files'] = {name: row for name, row in descriptors(result).items() if name != 'native/source-map.json'}
    result['native/source-map.json'] = ((json.dumps(manifest, sort_keys=True, indent=2) + '\n').encode(), files['native/source-map.json'][1])
    return result


def profile(raw, checksum):
    need(type(checksum) is str and re.fullmatch('[0-9a-f]{64}', checksum) and pin(raw)['sha256'] == checksum,
         'caller-authenticated profile checksum differs')
    value = decode(raw)
    need(set(value) == FIELDS and type(value['schema']) is int and value['schema'] == 1 and
         value['purpose'] == 'source-tools-native-main-overlay' and value['genuine_parent'] == GENUINE_PARENT and
         value['parent_tree'] == PARENT_TREE and value['main_base'] == MAIN_BASE and
         value['operation'] == OPERATION and type(value['source_files']) is int and value['source_files'] == 200 and
         value['actual'] == dict(source=None, ref=None, run=None) and value['producer_overlay'] == PRODUCER_AFTER, 'exact unexecuted native overlay identity required')
    for field, count in (('parent_files', 191), ('overlay', 14)):
        rows = value[field]
        need(type(rows) is dict and len(rows) == count, 'exact finite source row count required')
        for name, row in rows.items():
            relative(name)
            need(type(row) is dict and set(row) == {'bytes', 'sha256', 'mode'} and
                 type(row['bytes']) is int and 0 < row['bytes'] <= MAX_FILE and
                 type(row['mode']) is int and row['mode'] in (0o644, 0o755) and
                 type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}', row['sha256']), 'finite typed source descriptor required')
        need(sum(row['bytes'] for row in rows.values()) <= MAX_TOTAL, 'source profile aggregate cap')
    need(set(value['overlay']) == SEAMS | ADDITIONS and SEAMS <= set(value['parent_files']) and
         not ADDITIONS.intersection(value['parent_files']), 'only five parent seams and nine additions allowed')
    need(all(type(value[key]) is str and re.fullmatch('[0-9a-f]{64}' if key == 'source_map_sha256' else '[0-9a-f]{40}', value[key])
             for key in ('source_map_sha256', 'prospective_tree')), 'exact final source identities required')
    return value


def check_final(files, policy):
    need(len(files) == policy['source_files'] == 200 and pin(files[MAP][0])['sha256'] == policy['source_map_sha256'],
         'exact closed200 source-map identity required')
    manifest = decode(files[MAP][0])
    need(manifest.get('schema') == 1 and type(manifest['schema']) is int and
         manifest.get('actual') == dict(source=None, ref=None, run=None) and
         manifest.get('files') == {name: row for name, row in descriptors(files).items() if name != MAP} and
         len(manifest['files']) == 199, 'exact199 source-map rows and NULL actuals required')
    contract = decode(files['native/source-tools-contract-v1.json'][0])
    need(contract.get('operation') == OPERATION and type(contract.get('actual')) is dict and
         contract['actual'] == dict(source=None, ref=None, run=None, job=None, artifact=None), 'native contract actual selectors must stay NULL')
    need(files['.github/workflows/native-arm-build.yml'] == files['.github/workflows/native-arm-developer-workflows.yml'],
         'closed source workflow aliases differ')
    need(tree(files) == policy['prospective_tree'], 'prospective closed Source Git tree differs')


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
        staging = Path(tempfile.mkdtemp(prefix='.source-tools-stage-', dir=output.parent))
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


def assemble(parent_source, raw_parent_commit, profile_path, profile_sha256, output):
    raw, _ = read(profile_path, 1024**2); policy = profile(raw, profile_sha256)
    parent_raw, _ = read(raw_parent_commit, 16384)
    need(oid(b'commit', parent_raw).hex() == GENUINE_PARENT and
         parent_raw.split(b'\n', 1)[0] == b'tree ' + PARENT_TREE.encode(), 'retained raw genuine parent commit differs')
    parent = snapshot(parent_source)
    need(descriptors(parent) == policy['parent_files'] and tree(parent) == PARENT_TREE, 'full genuine191 source bytes/modes/tree differ')
    overlay = snapshot(absolute(profile_path).parent / 'overlay')
    need(descriptors(overlay) == policy['overlay'], 'exact14 canonical overlay bytes/modes/namespace differ')
    files = dict(parent); files.update(overlay); files = scheduled_source(files); check_final(files, policy)
    publish(files, output)
    return dict(status='ASSEMBLED_EXACT_CLOSED_SOURCE_DATA_ONLY', source_files=200, source_map_rows=199,
        source_map_sha256=policy['source_map_sha256'], prospective_tree=policy['prospective_tree'],
        genuine_parent=GENUINE_PARENT, main_base=MAIN_BASE, operation=OPERATION, actual=policy['actual'],
        native='NOT_RUN', publication='NOT_RUN', hardware='NOT_RUN', release='NOT_ADMITTED')


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
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, AttributeError) as error:
        print(json.dumps(dict(status='REFUSED', reason=str(error)), sort_keys=True)); return 1


if __name__ == '__main__':
    raise SystemExit(main())
