# SPDX-License-Identifier: MIT
"""Finite source/package selection contracts; data-only and actor-free."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat

MAP = 'native/source-map.json'
INPUTS_SHA = 'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f'
LOCK_SHA = 'fc853bd6890b76f05178eba69436da434dd6b99daf166301f692b725d7c39e25'
LABEL = 'org.cachy-asahi.support-native'
RUNTIME = {'support_bundle.py': '2fff76ad4df036f383927381b0b56c89904c3087f7ca151902ba80fb8c82bdc8',
           'collect_support.py': '2116e931e91ceed87627eeeb1acec2da1158a523c7c2f71fc2f4b4b41936159e',
           'doctor.py': 'ddd8c3cedc5ba1291dcdd2d1d7a188e5b4d4a4ac7323ffe6f7ee554f6687d41e',
           'session_probe.py': '9c5c41899cd991b0de4bf8d30bad6f5452b4592ea9440df0f0b4a7b54bc66984'}
ALIASES = ('.github/workflows/native-arm-build.yml', '.github/workflows/native-arm-support.yml')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def relative(name):
    need(type(name) is str and 0 < len(name) <= 255, 'bounded path text')
    path = Path(name)
    need(not path.is_absolute() and '..' not in path.parts and path.as_posix() == name and name != '.', 'relative path')
    return path


def read(path, cap=16 * 1024**2):
    path = Path(path).absolute()
    need(not any(p.is_symlink() for p in path.parents), 'ordinary path ancestry')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 <= before.st_size <= cap, 'bounded regular single-link file')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(cap + 1)
        after = os.fstat(fd)
        stable = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns, x.st_nlink)
        need(stable(before) == stable(after) and len(raw) == before.st_size, 'file changed during read')
        return raw
    finally:
        os.close(fd)


def decode(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            need(key not in value, 'duplicate JSON key')
            value[key] = item
        return value
    def invalid(_):
        raise ValueError('nonfinite JSON refused')
    def floating(value):
        number = float(value)
        need(math.isfinite(number), 'nonfinite JSON refused')
        return number
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid, parse_float=floating)


def load(path):
    return decode(read(path))


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def save(path, value):
    Path(path).write_bytes(encoded(value))


def package_selection(value, *, control=False):
    need(type(value) is dict and type(value.get('schema')) is int and value['schema'] == 1, 'package selection contract')
    status = 'SOURCE_CONTROL_FIXTURE_ONLY' if control else 'ROOT_AUTHORIZED_SEALED_V2_PACKET'
    need(value.get('selection_status') == status, 'Root-sealed final package required; unfinished/default selection refused')
    package = value.get('package')
    need(type(package) is dict and package.get('name') == 'cachy-asahi-support'
         and package.get('version') == ('0.1.0-1' if control else '0.2.0-1')
         and package.get('arch') == 'any' and package.get('depends') == ['python>=3.11']
         and package.get('license') == ['MIT'], 'finite selected support package identity')
    if not control:
        need(value.get('candidate_source') is None and value.get('recipe_root') == 'packages/tools/cachy-asahi-support2'
             and re.fullmatch('[0-9a-f]{64}', value.get('seal_sha256') or '')
             and value.get('seal_sha256') == value.get('closure_sha256'), 'explicit Root-authorized sealed v2 packet required')
    rows = value.get('files')
    need(type(rows) is dict and 15 <= len(rows) <= 64, 'complete finite selected package file closure')
    for name, row in rows.items():
        relative(name)
        need(type(row) is dict and type(row.get('bytes')) is int and 0 < row['bytes'] <= 1024**2
             and re.fullmatch('[0-9a-f]{64}', row.get('sha256') or '') and row.get('mode') == 0o644, 'selected source pin/mode')
    base = 'packages/tools/cachy-asahi-support2/'
    need(all(name.startswith(base) or name in ('scripts/release/support_source_delivery_v2.py',
             'scripts/release/test_support_source_delivery_v2.py') for name in rows), 'support2 sealed package namespace only')
    for name, checksum in RUNTIME.items():
        need(rows[base + name]['sha256'] == checksum, 'held v1 runtime changed')
    need(value.get('recipe_sha256') == rows[base + 'PKGBUILD']['sha256'], 'exact selected recipe hash')
    payload = value.get('payload')
    need(type(payload) is dict and 10 <= len(payload) <= 24, 'finite reviewed installed payload')
    for name, row in payload.items():
        relative(name)
        need(name.startswith(('usr/bin/cachy-asahi-support', 'usr/lib/cachy-asahi/support/',
                             'usr/share/doc/cachy-asahi-support/', 'usr/share/licenses/cachy-asahi-support/')),
             'private support payload only')
        need(type(row) is dict and row.get('mode') in (0o644, 0o755) and type(row.get('bytes')) is int
             and row['bytes'] > 0 and re.fullmatch('[0-9a-f]{64}', row.get('sha256') or ''), 'payload byte/mode binding')
    if not control:
        contract = value.get('cli_contract')
        need(type(contract) is dict and set(contract) in ({'collect', 'create', 'verify'}, {'collect', 'create', 'verify', 'session_relative'}), 'sealed collect/create/verify argv contract required')
        if 'session_relative' in contract:
            relative(contract['session_relative'])
        for name in ('collect', 'create', 'verify'):
            argv = contract[name]
            need(type(argv) is list and 1 <= len(argv) <= 48 and argv[0] == name
                 and all(type(a) is str and 0 < len(a) <= 512 and a.isprintable() for a in argv), 'finite support argv')
    return value


def verify_source(root, checksum):
    root = Path(root).absolute()
    need(re.fullmatch('[0-9a-f]{64}', checksum or ''), 'whole source-map SHA256 required')
    raw = read(root / MAP)
    need(pin(raw)['sha256'] == checksum, 'whole source-map differs')
    manifest = decode(raw)
    need(type(manifest.get('schema')) is int and manifest['schema'] == 1 and manifest.get('actual') == dict(source_sha=None, ref=None, run_id=None), 'unexecuted source selectors remain NULL')
    rows = manifest['files']
    need(type(rows) is dict and len(rows) <= 200 and MAP not in rows and not set(ALIASES) & rows.keys(), 'finite nonrecursive source map')
    actual, actual_dirs = set(), set()
    for directory, dirs, names in os.walk(root, followlinks=False):
        base = Path(directory)
        for name in tuple(dirs):
            need(not (base / name).is_symlink(), 'source directory alias')
            if base == root and name == '.git':
                dirs.remove(name)
            else:
                actual_dirs.add(str((base / name).relative_to(root)))
        actual.update(str((base / n).relative_to(root)) for n in names)
    need(actual == set(rows) | {MAP, *ALIASES}, 'complete closed source namespace')
    expected_dirs = {str(p) for name in actual for p in Path(name).parents if p != Path('.')}
    need(actual_dirs == expected_dirs, 'complete closed source directory namespace')
    for name, row in rows.items():
        path = root / relative(name)
        need(pin(read(path)) == {k: row[k] for k in ('bytes', 'sha256')}
             and stat.S_IMODE(path.stat().st_mode) == row['mode'], 'source byte/mode drift: ' + name)
    workflow = read(root / 'native/workflow.yml.in').replace(b'@OWNER_SHA@', rows['native/owner.py']['sha256'].encode()).replace(b'@MAP_SHA@', checksum.encode())
    need(all(read(root / name) == workflow for name in ALIASES), 'exact workflow aliases')
    return manifest


def execution_selection(root):
    policy = load(Path(root) / 'native/policy.json')
    package_selection(policy['selected_package'])
    admission = policy.get('base_input_admission')
    need(type(admission) is dict and admission.get('status') == 'ROOT_RESOLVED_BASE_INPUT_ACQUISITIONS'
         and re.fullmatch('[0-9a-f]{64}', admission.get('receipt_sha256') or ''),
         'base-input acquisition/diagnostic fix remains a separate Root gate')
    return policy
