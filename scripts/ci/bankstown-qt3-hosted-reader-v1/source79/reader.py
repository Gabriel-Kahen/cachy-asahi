#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Finite Source79 admission over the unchanged Source78 Reader; no authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import types

HERE = Path(__file__).resolve().parent
LEGACY = HERE.parent
LEGACY_READER = dict(bytes=11489, sha256='74e7f8c2cf9c3eb974fb69d24964051cde5a3b3e284fa8f4560203db908235d6')
LEGACY_RESULT = dict(bytes=25600, sha256='52446cb3b534fe041be3656f8d1f2cf3cd75a87a2878fd53457e54fd433a7355')
WORKFLOW = '.github/workflows/native-arm-bankstown-qt3-hosted-v1.yml'
WORKFLOW_PIN = dict(bytes=5376, sha256='7ac7accbf0b56587c85f865c6958669a94cbfe03d36843942de90c91806035b7')
SOURCE79 = dict(files=79, bytes=35747849, tree='3a5082263b9e0bf1bd0ffc87b2dd9570d5effb8a',
                source_map=dict(bytes=15559, sha256='e5560b70bc993b6d894de5319804bab4e907dc354750fb55a1f4cf54cbd9e764'))
ALIASES = {'source-map.json', 'source.lock.json'}


def need(value, why):
    if not value:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def read(path, cap=128 * 1024):
    """Read ordinary bounded DATA once; execute only the returned pinned bytes."""
    path = Path(path)
    need(path.is_absolute() and path == path.resolve()
         and not any(p.is_symlink() for p in (path, *path.parents)), 'UNALIASED_READER_DATA')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 < before.st_size <= cap, 'FINITE_SINGLE_LINK_READER_DATA')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(cap + 1)
        keys = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        identity = lambda row: tuple(getattr(row, key) for key in keys)
        need(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))
             == identity(path.lstat()), 'STABLE_READER_DATA')
        return raw, stat.S_IMODE(before.st_mode)
    finally:
        os.close(fd)


def pinned_module(path, expected, name):
    raw, mode = read(path)
    need(pin(raw) == expected and mode == 0o644, 'FROZEN_READER_PROGRAM_PIN')
    module = types.ModuleType(name)
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def legacy():
    return pinned_module(LEGACY / 'reader.py', LEGACY_READER, 'source79_frozen_reader6ef')


def namespace(root, names, *, allow_git_metadata):
    """Keep files-only audits strict; actual checkout metadata is never Source."""
    R = legacy()
    if not allow_git_metadata:
        R.P.namespace(root, names)
        return
    expected_dirs = {str(p) for name in names for p in Path(name).parents if str(p) != '.'}
    pending, found, directories, nodes = [root], set(), set(), 0
    while pending:
        parent = pending.pop()
        for path in parent.iterdir():
            row = path.lstat()
            if parent == root and path.name == '.git':
                need(stat.S_ISDIR(row.st_mode) or stat.S_ISREG(row.st_mode) and row.st_nlink == 1,
                     'ORDINARY_CHECKOUT_METADATA_ONLY')
                continue
            nodes += 1
            need(nodes <= 1024, 'SOURCE79_NAMESPACE_BOUND')
            name = path.relative_to(root).as_posix()
            if stat.S_ISDIR(row.st_mode):
                need(name in expected_dirs, 'FOREIGN_SOURCE79_DIRECTORY')
                directories.add(name); pending.append(path)
            else:
                need(stat.S_ISREG(row.st_mode) and row.st_nlink == 1 and name in names,
                     'FOREIGN_OR_ALIASED_SOURCE79_MEMBER')
                found.add(name)
    need(found == set(names) and directories == expected_dirs, 'COMPLETE_SOURCE79_NAMESPACE')


def git_tree(files):
    def oid(kind, raw):
        return hashlib.sha1(kind + b' ' + str(len(raw)).encode() + b'\0' + raw).digest()
    node = {}
    for name, (raw, mode) in files.items():
        current = node
        parts = name.split('/')
        for part in parts[:-1]:
            current = current.setdefault(part, {})
        current[parts[-1]] = (raw, mode)
    def visit(items):
        raw = bytearray()
        for name, value in sorted(items.items(), key=lambda row: (row[0] + ('/' if type(row[1]) is dict else '')).encode()):
            directory = type(value) is dict
            mode = b'40000' if directory else b'100755' if value[1] == 0o755 else b'100644'
            raw.extend(mode + b' ' + name.encode() + b'\0' + (visit(value) if directory else oid(b'blob', value[0])))
        return oid(b'tree', raw)
    return visit(node).hex()


def inverse_files(files):
    """Pure fixed79-to78 inverse. Old fixed map is the independent inner gate."""
    R = legacy()
    raw, mode = files['source-map.json']
    need(mode == 0o644 and files['source.lock.json'] == (raw, mode), 'EXACT_SOURCE79_ALIASES')
    value = R.H.decoded(raw)
    need(raw == R.encoded(value) and set(value) == {'schema', 'kind', 'operation', 'actual', 'files'}
         and type(value['schema']) is int and value['schema'] == 1
         and value['kind'] == R.C.SOURCE_KIND and value['operation'] == R.C.OPERATION
         and type(value['actual']) is dict and value['actual']
         and all(v is None for v in value['actual'].values())
         and type(value['files']) is dict and len(value['files']) == 77, 'CANONICAL_UNISSUED_SOURCE79')
    need(files.get(WORKFLOW) == read(LEGACY.parents[2] / WORKFLOW, WORKFLOW_PIN['bytes'])
         and pin(files[WORKFLOW][0]) == WORKFLOW_PIN
         and value['files'].get(WORKFLOW) == dict(WORKFLOW_PIN, mode=0o644), 'EXACT_SOURCE79_WORKFLOW')
    need(set(files) == set(value['files']) | ALIASES
         and all(row == dict(pin(files[name][0]), mode=files[name][1])
                 for name, row in value['files'].items()), 'WHOLE_SOURCE79_MAP_BODY_MODES')
    previous = dict(value, files={name: row for name, row in value['files'].items() if name != WORKFLOW})
    original_map = R.encoded(previous)
    need(pin(original_map) == R.SOURCE78, 'EXACT_CANONICAL_SOURCE78_INVERSE_MAP')
    result = {name: row for name, row in files.items() if name not in ALIASES | {WORKFLOW}}
    result.update({name: (original_map, 0o644) for name in ALIASES})
    return result


def source_readiness(source_root, *, allow_git_metadata=False):
    R = legacy()
    root = R.N.ordinary(str(source_root))
    raw, mode = read(root / 'source-map.json')
    need(mode == 0o644 and pin(raw) == SOURCE79['source_map'], 'EXACT_SOURCE79_MAP_PIN')
    value = R.H.decoded(raw)
    need(type(value) is dict and type(value.get('files')) is dict, 'SOURCE79_FILE_MAP')
    namespace(root, set(value['files']) | ALIASES, allow_git_metadata=allow_git_metadata)
    files = {}
    rows = dict(value['files'], **{name: dict(SOURCE79['source_map'], mode=0o644) for name in ALIASES})
    for name, row in rows.items():
        body, bits = read(root / name, row['bytes'])
        need(bits == row['mode'] and pin(body) == {k: row[k] for k in ('bytes', 'sha256')},
             'EXACT_SOURCE79_BODY_MODE_BEFORE_RETENTION')
        files[name] = (body, bits)
    need(len(files) == SOURCE79['files'] and sum(len(body) for body, _ in files.values()) == SOURCE79['bytes']
         and git_tree(files) == SOURCE79['tree'], 'EXACT_SOURCE79_COUNT_BYTES_TREE')
    original = inverse_files(files)
    with tempfile.TemporaryDirectory(prefix='source79-inverse78-DATA-') as temporary:
        inverse = Path(temporary) / 'Source78'; inverse.mkdir(mode=0o700)
        for name, (body, bits) in original.items():
            path = inverse / name; path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as stream: stream.write(body)
            path.chmod(bits)
        proof = R.source_readiness(inverse)
    # Rejoin stable originals after all inverse/legacy DATA reads.
    need(all(read(root / name, len(row[0])) == row for name, row in files.items()), 'SOURCE79_CHANGED_DURING_INVERSE')
    namespace(root, set(files), allow_git_metadata=allow_git_metadata)
    return dict(status='PASS_SOURCE79_DATA_ONLY', **SOURCE79, full_inverse=True,
                preserved_Source78_pin=R.SOURCE78, inverse_status=proof['status'],
                preserved_Source72_members=proof['preserved_Source72_members'],
                prospective_inventory_joins=proof['prospective_inventory_joins'],
                workflow_gap_closed=True, dispatch_ready=False,
                dispatch='EXACT_WORKFLOW_PRESENT_REGISTRATION_AND_AUTHORITY_UNISSUED',
                actual=proof['actual'], **R.FINAL)


def admission_reader():
    """Only two Source selectors change in one private frozen Reader instance.

    Its request/context/workflow/complete773/policy/lifetime admission functions
    and all result predicates retain their original function bodies.
    """
    R = legacy()
    R.SOURCE78 = dict(SOURCE79['source_map'])
    R.source_readiness = lambda root: source_readiness(root, allow_git_metadata=True)
    return R


def admit_inputs(**kwargs):
    return admission_reader().admit_inputs(**kwargs)


def qualify_result(state, records, *, reader_pin, now_monotonic=None):
    need(reader_pin == pin(read(Path(__file__))[0]), 'EXTERNALLY_SELECTED_SOURCE79_READER')
    Q = pinned_module(LEGACY / 'result.py', LEGACY_RESULT, 'source79_frozen_result6ef')
    return Q.qualify(state, records, reader_pin=reader_pin,
                     now_monotonic=time.monotonic() if now_monotonic is None else now_monotonic)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('source', 'inputs', 'result'))
    parser.add_argument('--source-root', type=Path, required=True)
    for role in ('request', 'provider', 'context', 'workflow', 'registration', 'records'):
        parser.add_argument('--' + role, type=Path)
        parser.add_argument('--' + role + '-sha256')
    parser.add_argument('--reader-sha256')
    args = parser.parse_args(); R = legacy()
    if args.operation == 'source':
        report = source_readiness(args.source_root)
    else:
        for role in ('request', 'provider', 'context', 'workflow', 'registration'):
            need(getattr(args, role) is not None and getattr(args, role + '_sha256') is not None,
                 'EXPLICIT_WHOLE_' + role.upper())
        state = admit_inputs(source_root=args.source_root, request_path=args.request,
            request_sha256=args.request_sha256,
            **{role: R.reference(getattr(args, role), getattr(args, role + '_sha256'))
               for role in ('provider', 'context', 'workflow')},
            registration=R.selected(R.reference(args.registration, args.registration_sha256)))
        report = dict(status='PASS_COMPLETE773_SOURCE79_INPUT_DATA_ONLY', intake=state['intake'], **R.FINAL)
        if args.operation == 'result':
            need(args.records is not None and args.records_sha256 is not None
                 and args.reader_sha256 is not None, 'EXPLICIT_RESULT_AND_READER_SELECTION')
            report = qualify_result(state, R.selected(R.reference(args.records, args.records_sha256)),
                reader_pin=dict(bytes=Path(__file__).stat().st_size, sha256=args.reader_sha256))
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('HOLD_SOURCE79_READER: ' + type(error).__name__ + ': ' + str(error), file=sys.stderr)
        raise SystemExit(2)
