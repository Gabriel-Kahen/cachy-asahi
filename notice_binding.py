# SPDX-License-Identifier: MIT
"""Exact notice successor candidate DATA binding; grants and roles stay external."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat

BINDING = {'audit_seal_sha256': 'd66d49a2734e79c6f9d1f5a57fda98ab519d39016483da0f4f88a0f626576fd9', 'base_candidate_map_pin': {'bytes': 1470, 'sha256': '355293f0cc318f40ce6e96e831b294888f7d2fe87bf306571e5df85cbdfb2aec'}, 'base_commit': 'dd6871d566661c4fe9eba055ae19e1e017e0b69d', 'catalogue_sha256': '1c477c7481df39c1b8b8e82edf73f8df99c63e3f7657e440393b6c812c8d421c', 'files': 11, 'files_pin': {'bytes': 1602, 'sha256': '3c4efd6ddbe30caf79196bbdbead178fe10750be0104beba2f791505726c9e67'}, 'holds_preserved': True, 'kind': 'RUST199_NOTICE_PRESERVATION_CANDIDATE_V7', 'schema': 1, 'tree': '16fc80733ba831a426fc54363ec8cff6dfe54110'}
MAP_PIN = {'bytes': 2522, 'sha256': 'fe33c24896cea0a02b5a5698fccf5d51250d68963c403e6edddf1c03158e1ff5'}
CONTRACT_PIN = {'bytes': 16968, 'sha256': '5631e474e818704e5cae38ce1aba761dcbf2581c3e815bf43e88090b5b21ac93'}
NAMES = {'.SRCINFO', 'LICENSE.packaging', 'PKGBUILD', 'README.md', 'admission.example.json',
         'bootstrap.toml', 'inputs.json', 'reference.py', 'test_reference.py',
         'notice_preservation.py', 'notice-catalogue.DATA.json'}
ACTUAL = dict.fromkeys(('source', 'ref', 'run', 'job', 'approval', 'artifact', 'image'))
SCOPE = 'RUST199_NOTICE_PRESERVATION_UNADMITTED_SOURCE_V7'


def need(value, why):
    if not value:
        raise ValueError(why)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def read(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and all(not p.is_symlink() for p in (path, *path.parents)),
         'ordinary absolute candidate binding input')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= 4 * 1024**2,
             'finite single-link candidate binding input')
        raw = b''
        while block := os.read(fd, min(65536, 4 * 1024**2 + 1 - len(raw))):
            raw += block
            need(len(raw) <= 4 * 1024**2, 'candidate binding input cap')
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd)) == identity(path.lstat()),
             'candidate binding input changed')
        return raw, stat.S_IMODE(before.st_mode)
    finally:
        os.close(fd)


def validate(root):
    root = Path(root)
    raw, mode = read(root / 'candidate-map.json')
    need(mode == 0o644 and pin(raw) == MAP_PIN, 'exact effective eleven-file candidate map')
    candidate = json.loads(raw)
    raw, mode = read(root / 'contract.json')
    need(mode == 0o644 and pin(raw) == CONTRACT_PIN, 'exact notice successor actor contract')
    contract = json.loads(raw)
    need(set(candidate) == {'schema', 'commit', 'files', 'notice_binding'} and type(candidate['schema']) is int
         and candidate['schema'] == 1 and candidate['commit'] == BINDING['base_commit']
         and candidate['notice_binding'] == BINDING and set(candidate['files']) == NAMES
         and pin(encode(candidate['files'])) == BINDING['files_pin'], 'complete successor files and explicit base provenance')
    need(contract['candidate'] == {key: candidate[key] for key in ('commit', 'files', 'notice_binding')}
         and contract['actual'] == ACTUAL, 'same unadmitted successor candidate in contract')
    directory = root / 'packages/port/rust199-source-reference'
    need(directory.is_dir() and not directory.is_symlink() and {p.name for p in directory.iterdir()} == NAMES,
         'complete effective candidate namespace')
    tree = b''
    for name in sorted(NAMES):
        raw, mode = read(directory / name)
        need(dict(**pin(raw), mode=mode) == candidate['files'][name], 'whole candidate bytes/mode: ' + name)
        blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).digest()
        tree += b'100644 ' + name.encode() + b'\0' + blob
    need(hashlib.sha1(b'tree ' + str(len(tree)).encode() + b'\0' + tree).hexdigest() == BINDING['tree'],
         'whole effective candidate Git tree identity')
    return copy.deepcopy(BINDING)


def source_marker(root, binding):
    raw, mode = read(Path(root) / 'notice-preservation.json')
    marker = json.loads(raw)
    need(mode == 0o644 and type(marker['schema']) is int and marker['schema'] == 7
         and marker['scope'] == SCOPE and marker['pending'] is None and marker['actual'] == ACTUAL
         and marker['unadmitted'] is True and marker['holds_preserved'] is True
         and marker['candidate_binding'] == binding == BINDING and marker['candidate_map_pin'] == MAP_PIN
         and marker['contract_pin'] == CONTRACT_PIN, 'complete unadmitted notice successor checkpoint')
    return marker
