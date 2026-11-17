# SPDX-License-Identifier: MIT
"""Add explicit hosted runtime DATA to exact preserved Source72; issue no grant."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PREFIX = 'scripts/ci/bankstown-qt3-hosted-v1/'
RUNTIME = ('hosted.py', 'inputs.py', 'policy.PROPOSAL.json', 'source72-map.DATA.json',
           'basis/hosted_current_v3.py', 'basis-origin.DATA.json')
SOURCE72_PIN = dict(bytes=14203, sha256='5643afddb02e2d4d29f1215f44b8409599d9b17dd3849699e8fd6897eb6c40b8')
HELPER = 'scripts/ci/bankstown-qt3-native-source/prepare.py'
HELPER_PIN = dict(bytes=7772, sha256='790be263d158dd576fef649797a77a5bebb1c597d91b90420832f9a8a372586a')
HANDOFF_PIN = dict(bytes=8111, sha256='284f9270ddba904e28bc4750576c7be54660b00c2d4a8ba2f846955f88a8cebb')


def need(value, why):
    if not value:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def read_runtime(path, cap=128 * 1024):
    need(path == path.resolve(), 'ORDINARY_FINITE_HOSTED_RUNTIME')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
             and 0 < before.st_size <= cap, 'ORDINARY_FINITE_HOSTED_RUNTIME')
        raw = bytearray()
        while len(raw) <= cap:
            part = os.read(fd, min(65536, cap + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_uid', 'st_gid',
                  'st_size', 'st_mtime_ns', 'st_ctime_ns')
        identity = lambda row: tuple(getattr(row, key) for key in fields)
        need(len(raw) == before.st_size <= cap
             and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
             'STABLE_FINITE_RUNTIME')
        return bytes(raw)
    finally:
        os.close(fd)


def helper():
    # Both files are exact Main875 maintained DATA helpers, not Source-selected code.
    for path, expected in ((ROOT / HELPER, HELPER_PIN),
                           (ROOT / HELPER.replace('prepare.py', 'handoff.py'), HANDOFF_PIN)):
        need(path == path.resolve() and path.is_file() and path.stat().st_nlink == 1,
             'UNALIASED_MAINTAINED_CONSTRUCTOR')
        need(pin(read_runtime(path)) == expected, 'WHOLE_MAINTAINED_CONSTRUCTOR_PIN')
    spec = importlib.util.spec_from_file_location('bankstown_hosted_held_prepare', ROOT / HELPER)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def namespace(root, names):
    expected_dirs = {str(p) for n in names for p in Path(n).parents if str(p) != '.'}
    pending, found, directories, nodes = [root], set(), set(), 0
    while pending:
        parent = pending.pop()
        for path in parent.iterdir():
            nodes += 1
            need(nodes <= 1024, 'SOURCE_NAMESPACE_BOUND')
            name, row = path.relative_to(root).as_posix(), path.lstat()
            if stat.S_ISDIR(row.st_mode):
                need(name in expected_dirs, 'FOREIGN_SOURCE_DIRECTORY')
                directories.add(name)
                pending.append(path)
            else:
                need(stat.S_ISREG(row.st_mode) and row.st_nlink == 1 and name in names,
                     'FOREIGN_OR_ALIASED_SOURCE_MEMBER')
                found.add(name)
    need(found == set(names) and directories == expected_dirs, 'COMPLETE_SOURCE_NAMESPACE')


def source72_rows(root, P):
    H = P.H
    root = H.ordinary(str(root))
    need(all(stat.S_IMODE((root / name).lstat().st_mode) == 0o644
             for name in ('source-map.json', 'source.lock.json')), 'SOURCE72_MAP_MODE_CHANGED')
    raw = H.verify_reference(dict(path=str(root / 'source-map.json'), **SOURCE72_PIN),
                             cap=128 * 1024, body=True)
    need(H.verify_reference(dict(path=str(root / 'source.lock.json'), **SOURCE72_PIN),
                            cap=128 * 1024, body=True) == raw, 'SOURCE72_MAP_ALIASES')
    value = H.decoded(raw)
    need(value.get('schema') == 1 and value.get('kind') == 'BANKSTOWN_QT3_CLOSED_NATIVE_SOURCE_V1'
         and value.get('operation') == 'bankstown-qt3-native-private-test-v1'
         and type(value.get('files')) is dict and len(value['files']) == 70
         and type(value.get('actual')) is dict and bool(value['actual'])
         and all(v is None for v in value['actual'].values()),
         'EXACT_UNISSUED_SOURCE72_SHAPE')
    namespace(root, set(value['files']) | {'source-map.json', 'source.lock.json'})
    result = {}
    for name, row in value['files'].items():
        P.member(name)
        need(type(row) is dict and set(row) == {'bytes', 'sha256', 'mode'}
             and type(row['mode']) is int and row['mode'] in (0o644, 0o755), 'SOURCE72_ROW')
        path = root / name
        need(stat.S_IMODE(path.lstat().st_mode) == row['mode'], 'SOURCE72_MODE_CHANGED')
        H.verify_reference(dict(path=str(path), **{k: row[k] for k in ('bytes', 'sha256')}),
                           cap=64 * 1024**2)
        result[name] = dict(path=str(path), **row)
    return raw, result


def prepare_source(*, source72, output, runtime_root=HERE):
    P = helper()
    out, original = P.H.ordinary(str(output)), P.H.ordinary(str(source72))
    need(not out.is_relative_to(original) and not original.is_relative_to(out),
         'SOURCE72_OUTPUT_DISJOINT')
    raw, rows = source72_rows(source72, P)
    selected = {}
    runtime_root = P.H.ordinary(str(runtime_root))
    for name in RUNTIME:
        member = PREFIX + name
        P.member(member)
        need(member not in rows, 'HOSTED_MEMBER_COLLISION')
        path = runtime_root / name
        need(path.is_file(), 'ORDINARY_FINITE_HOSTED_RUNTIME')
        body = read_runtime(path)
        selected[member] = dict(path=str(path), **pin(body), mode=0o644)
    need(read_runtime(runtime_root / 'source72-map.DATA.json') == raw, 'RETAINED_SOURCE72_MAP')
    chosen = rows | selected
    result = P.prepare_source(file_rows=chosen, file_rows_sha256=P.H.pin(P.H.encoded(chosen))['sha256'],
                              output=output)
    need(source72_rows(source72, P) == (raw, rows), 'SOURCE72_STAYED_UNCHANGED')
    # Rejoin every preserved original descriptor with the new actual output.
    new_raw = (Path(output) / 'source-map.json').read_bytes()
    new_map = P.H.decoded(new_raw)
    need(all(new_map['files'][n] == {k: r[k] for k in ('bytes', 'sha256', 'mode')}
             for n, r in rows.items()), 'ORIGINAL_SOURCE72_PRESERVED')
    namespace(Path(output), set(chosen) | {'source-map.json', 'source.lock.json'})
    return dict(schema=1, kind='BANKSTOWN_QT3_HOSTED_PREPARED_SOURCE_DATA_V1',
                source72_map=SOURCE72_PIN, maintained_constructor=HELPER_PIN,
                runtime_selection={n: {k: r[k] for k in ('bytes', 'sha256', 'mode')}
                                   for n, r in selected.items()},
                result=result, actual_source=None, actual_ref=None, Root_final_acceptance=None,
                native_credit=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source72', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare_source(source72=args.source72, output=args.output), sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
