# SPDX-License-Identifier: MIT
"""Finite Source78 -> dispatch Source79 DATA; never a publication or Root grant.

Only the pinned workflow is added. The inverse reconstructs the original
canonical map, then requires its whole pin and complete body/mode/tree identity.
This is exact byte reconstruction, not inferred source correspondence.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
WORKFLOW = '.github/workflows/native-arm-bankstown-qt3-hosted-v1.yml'
WORKFLOW_PIN = dict(bytes=5376, sha256='7ac7accbf0b56587c85f865c6958669a94cbfe03d36843942de90c91806035b7')
SOURCE78 = dict(files=78, bytes=35742081, tree='5c2e5f8ea02ce1304684026bb8e2e06912b068d9',
                source_map=dict(bytes=15363, sha256='dc3197203a91bdcd98cdd98f4f672d05abbc6865e26f2b744c3646c1b4d761eb'))
SOURCE72_MAP = dict(bytes=14203, sha256='5643afddb02e2d4d29f1215f44b8409599d9b17dd3849699e8fd6897eb6c40b8')
PREFIX = 'scripts/ci/bankstown-qt3-hosted-v1/'
RUNTIME_PINS = {
 'basis-origin.DATA.json': dict(bytes=928, mode=420, sha256='5cfeced01b6e9e7c0010e9f4447fce7e7a232efcce524ded4a7a28b8f53cc661'),
 'basis/hosted_current_v3.py': dict(bytes=66263, mode=420, sha256='f8387c748f31698b45656998248f099a8207bb58f7f9d7e70ef53a73be286d97'),
 'hosted.py': dict(bytes=9677, mode=420, sha256='4f4bc0268ea83b97e294642ceaa1963c7dcbd3375af1d29c5805a666bffad2ea'),
 'inputs.py': dict(bytes=10052, mode=420, sha256='7c19b63a3135e372f8b31f8297cb0aee1d783a69b282c3e6aa19ee4777174617'),
 'policy.PROPOSAL.json': dict(bytes=5703, mode=420, sha256='7bd20f3c36cce413b4e732232cb3e60dee5ce9d8f791d9cb046eed19654b03ba'),
 'source72-map.DATA.json': dict(SOURCE72_MAP, mode=420)}
PREPARE_PIN = dict(bytes=7575, sha256='9d57ab989b433307087e9ae6aeb65fba29bb8b574f2ae12a016e301628598b8a')
NATIVE_PIN = dict(bytes=7772, sha256='790be263d158dd576fef649797a77a5bebb1c597d91b90420832f9a8a372586a')
HANDOFF_PIN = dict(bytes=8111, sha256='284f9270ddba904e28bc4750576c7be54660b00c2d4a8ba2f846955f88a8cebb')
ALIASES = {'source-map.json', 'source.lock.json'}
KIND = 'BANKSTOWN_QT3_CLOSED_NATIVE_SOURCE_V1'
OPERATION = 'bankstown-qt3-native-private-test-v1'


def need(value, why):
    if not value:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            need(key not in result, 'DUPLICATE_DATA_KEY')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: need(False, 'NONFINITE_DATA'))


def member(name):
    need(type(name) is str and 0 < len(name) <= 240
         and re.fullmatch(r'[A-Za-z0-9._+/-]+', name)
         and not name.startswith('/') and len(name.split('/')) <= 16
         and all(part not in ('', '.', '..', '.git', 'work', '__pycache__')
                 for part in name.split('/')), 'ORDINARY_CLOSED_SOURCE_MEMBER')
    return name


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and path == path.resolve()
         and not any(p.is_symlink() for p in (path, *path.parents)), 'UNALIASED_DATA_PATH')
    return path


def read(path, cap=64 * 1024**2):
    path = ordinary(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 < before.st_size <= cap, 'ORDINARY_FINITE_DATA_FILE')
        parts, size = [], 0
        while chunk := os.read(fd, min(1024**2, cap + 1 - size)):
            parts.append(chunk)
            size += len(chunk)
            need(size <= cap, 'DATA_FILE_BOUND')
        keys = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
                'st_size', 'st_mtime_ns', 'st_ctime_ns')
        stable = lambda row: tuple(getattr(row, key) for key in keys)
        need(size == before.st_size and stable(before) == stable(os.fstat(fd))
             == stable(path.lstat()), 'DATA_FILE_CHANGED')
        return b''.join(parts), stat.S_IMODE(before.st_mode)
    finally:
        os.close(fd)


def trusted_prepare():
    paths = ((HERE / 'prepare.py', PREPARE_PIN),
             (ROOT / 'scripts/ci/bankstown-qt3-native-source/prepare.py', NATIVE_PIN),
             (ROOT / 'scripts/ci/bankstown-qt3-native-source/handoff.py', HANDOFF_PIN))
    for path, expected in paths:
        raw, _ = read(path, 128 * 1024)
        need(pin(raw) == expected, 'EXACT_MAINTAINED_CONSTRUCTOR_BEFORE_IMPORT')
    path = HERE / 'prepare.py'
    spec = importlib.util.spec_from_file_location('bankstown_dispatch_held_prepare', path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value.helper()


def snapshot(root, *, names_only=False):
    root = ordinary(root)
    need(root.is_dir(), 'SOURCE_DIRECTORY')
    files, directories, pending, nodes = {}, set(), [root], 0
    while pending:
        parent = pending.pop()
        for path in parent.iterdir():
            nodes += 1
            need(nodes <= 1024, 'SOURCE_NAMESPACE_BOUND')
            name = member(path.relative_to(root).as_posix())
            row = path.lstat()
            if stat.S_ISDIR(row.st_mode):
                directories.add(name)
                pending.append(path)
            else:
                need(len(files) < 256, 'SOURCE_FILE_BOUND')
                need(stat.S_ISREG(row.st_mode) and row.st_nlink == 1, 'ORDINARY_SOURCE_FILE')
                files[name] = None if names_only else read(path)
    need(directories == {str(p) for n in files for p in PurePosixPath(n).parents
                         if str(p) != '.'}, 'NO_FOREIGN_EMPTY_SOURCE_DIRECTORY')
    return files


def tree(files):
    def oid(kind, body):
        digest = hashlib.sha1(kind + b' ' + str(len(body)).encode() + b'\0')
        digest.update(body)
        return digest.hexdigest()
    nested = {}
    for name, (body, mode) in files.items():
        current = nested
        parts = name.split('/')
        for part in parts[:-1]:
            current = current.setdefault(part, {})
        current[parts[-1]] = (oid(b'blob', body), mode)
    def visit(node):
        raw = b''
        for name, value in sorted(node.items(), key=lambda row: (row[0] + '/' if isinstance(row[1], dict) else row[0]).encode()):
            directory = isinstance(value, dict)
            digest = visit(value) if directory else value[0]
            mode = b'40000' if directory else b'100755' if value[1] == 0o755 else b'100644'
            raw += mode + b' ' + name.encode() + b'\0' + bytes.fromhex(digest)
        return oid(b'tree', raw)
    return visit(nested)


def identity(files):
    return dict(files=len(files), bytes=sum(len(body) for body, _ in files.values()),
                tree=tree(files), source_map=pin(files['source-map.json'][0]))


def mapping(files, count):
    need(type(files) is dict and len(files) == count, 'EXACT_SOURCE_FILE_COUNT')
    total = 0
    for name, row in files.items():
        member(name)
        need(type(row) is tuple and len(row) == 2 and type(row[0]) is bytes
             and 0 < len(row[0]) <= 64 * 1024**2 and type(row[1]) is int
             and row[1] in (0o644, 0o755), 'SOURCE_BODY_AND_MODE')
        need(not any(str(p) in files for p in PurePosixPath(name).parents if str(p) != '.'),
             'SOURCE_FILE_DIRECTORY_COLLISION')
        total += len(row[0])
    need(total <= 128 * 1024**2, 'SOURCE_TOTAL_BOUND')
    raw, mode = files['source-map.json']
    need(len(raw) <= 128 * 1024 and mode == 0o644
         and files['source.lock.json'] == (raw, mode), 'CANONICAL_MAP_ALIASES_0644')
    value = decode(raw)
    need(raw == encoded(value) and set(value) == {'schema', 'kind', 'operation', 'actual', 'files'}
         and type(value['schema']) is int and value['schema'] == 1
         and value['kind'] == KIND and value['operation'] == OPERATION
         and type(value['actual']) is dict and value['actual']
         and all(v is None for v in value['actual'].values()), 'CANONICAL_UNISSUED_SOURCE_MAP')
    need(value['files'] == {n: dict(pin(body), mode=bits)
                           for n, (body, bits) in files.items() if n not in ALIASES},
         'ALL_SOURCE_MAP_BODY_MODE_ROWS')
    return value


def verify_source78(files):
    value = mapping(files, SOURCE78['files'])
    need(identity(files) == SOURCE78, 'EXACT_ORIGINAL_SOURCE78_TUPLE')
    raw, mode = files[PREFIX + 'source72-map.DATA.json']
    need(mode == 0o644 and pin(raw) == SOURCE72_MAP, 'EXACT_SOURCE72_PARENT_MAP')
    previous = decode(raw)
    need(raw == encoded(previous) and set(previous) == set(value)
         and previous['kind'] == KIND and previous['operation'] == OPERATION
         and len(previous['files']) == 70 and type(previous['actual']) is dict
         and previous['actual'] and all(v is None for v in previous['actual'].values()),
         'ORIGINAL_SOURCE72_DATA')
    need(set(value['files']) == set(previous['files']) | {PREFIX + n for n in RUNTIME_PINS}
         and all(value['files'][n] == row for n, row in previous['files'].items())
         and all(value['files'][PREFIX + n] == row for n, row in RUNTIME_PINS.items()),
         'ALL_SEVENTY_PRESERVED_AND_EXACT_SIX_RUNTIME')
    return True


def inverse_files(files):
    value = mapping(files, SOURCE78['files'] + 1)
    need(files.get(WORKFLOW) is not None and files[WORKFLOW][1] == 0o644
         and pin(files[WORKFLOW][0]) == WORKFLOW_PIN, 'EXACT_ADDED_WORKFLOW_0644')
    old = dict(value, files={n: row for n, row in value['files'].items() if n != WORKFLOW})
    raw = encoded(old)
    need(pin(raw) == SOURCE78['source_map'], 'EXACT_RECONSTRUCTED_ORIGINAL_MAP')
    original = {n: row for n, row in files.items() if n not in ALIASES | {WORKFLOW}}
    original.update({name: (raw, 0o644) for name in ALIASES})
    verify_source78(original)
    return original


def prepare_source(*, source78, output, workflow_path=ROOT / WORKFLOW):
    source78, output = ordinary(source78), ordinary(output)
    need(not output.exists() and not output.is_relative_to(source78)
         and not source78.is_relative_to(output), 'FRESH_DISJOINT_SOURCE79_OUTPUT')
    files = snapshot(source78)
    verify_source78(files)
    workflow_path = ordinary(workflow_path)
    raw, mode = read(workflow_path, 128 * 1024)
    need(mode == 0o644 and pin(raw) == WORKFLOW_PIN and WORKFLOW not in files,
         'EXACT_WORKFLOW_PROPOSAL_DATA')
    P = trusted_prepare()
    rows = {n: dict(path=str(source78 / n), **pin(body), mode=bits)
            for n, (body, bits) in files.items() if n not in ALIASES}
    rows[WORKFLOW] = dict(path=str(workflow_path), **WORKFLOW_PIN, mode=0o644)
    result = P.prepare_source(file_rows=rows, file_rows_sha256=pin(encoded(rows))['sha256'], output=output)
    emitted = snapshot(output)
    need(inverse_files(emitted) == files, 'COMPLETE_SOURCE79_TO_SOURCE78_INVERSE')
    # Streaming requalification keeps the preserved input unchanged across copying.
    for name, (body, bits) in files.items():
        path = source78 / name
        need(stat.S_IMODE(path.lstat().st_mode) == bits, 'ORIGINAL_SOURCE78_MODE_CHANGED')
        P.H.verify_reference(dict(path=str(path), **pin(body)), cap=64 * 1024**2)
    need(set(snapshot(source78, names_only=True)) == set(files), 'ORIGINAL_SOURCE78_NAMESPACE_CHANGED')
    return dict(schema=1, kind='BANKSTOWN_QT3_DISPATCH_SOURCE79_DATA_V1', source=identity(emitted),
                preserved_Source78=SOURCE78, added_workflow=dict(member=WORKFLOW, **WORKFLOW_PIN, mode=0o644),
                complete_inverse=True, maintained_constructor=NATIVE_PIN, result=result,
                actual=dict(commit=None, ref=None, Main=None, Root_authority=None, Root_acceptance=None,
                            run=None, job=None, image=None, profile=None, executor=None), native_credit=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source78', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare_source(source78=args.source78, output=args.output), sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
