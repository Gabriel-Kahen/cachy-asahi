#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Project the exact published Fish r11 Source to r12's native check-log catalog."""
import argparse
import importlib.util
import json
from pathlib import Path
import stat
import sys

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('fish_source_io', HERE.parent/'successor_v8/prepare.py')
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)

PREFIX = P.PREFIX
DATA, EXPORT, POLICY, PROGRAM = (PREFIX + name for name in
                                 ('data.py', 'public_evidence.py', 'policy.json', 'owner-program.json'))
MAP = 'source-map.json'
HELD = 'held-source32/scripts/ci/fish-config02-native-source/'
WORKFLOW = '.github/workflows/native-arm-fish02-pinned-input-source.yml'
OLD_KIND = 'FISH02_EXACT_PACMAN_CONFIG_MODE_SOURCE_V11'
NEW_KIND = 'FISH02_EXACT_CHECK_LOG_RETENTION_SOURCE_V12'
OLD_LOG = 'cachy-asahi-fish-config-0.1.0-2-any-check.log'
NEW_LOG = 'cachy-asahi-fish-config-0.1.0-2-aarch64-check.log'
R11 = dict(files=70, bytes=2090583, tree='502a3c8d89050fde5c03ca19d617fc5c2d067687',
           map=dict(bytes=14996, sha256='69315946d019b810ff4b4d14f01c6730e4f416b5836eff4b8f05bf7f0735c1c5'))
R12 = dict(files=70, bytes=2093900, tree='de61a2e7351a09d1dcf0471d50c80e3a1a6ee479',
           map=dict(bytes=14997, sha256='14a3f9d1f12f224bf43a71a7bb4ef9ba3bfe03b5918b25aabc33ce1fdb71a3b2'))
DATA_EDITS = (
    (f"    need(value['kind']=='{OLD_KIND}' and len(rows)==69 and\n".encode(),
     f"    need(value['kind']=='{NEW_KIND}' and len(rows)==69 and\n".encode()),
    (b'    prior10 = inverse_source_r10_pacman_mode(bodies)\n',
     b'    prior10 = inverse_source_r10_pacman_mode(inverse_source_r11_retention(bodies))\n'),
)
EXPORT_EDITS = (
    (b"PACKAGE = 'cachy-asahi-fish-config-0.1.0-2-any'\n",
     f"PACKAGE = 'cachy-asahi-fish-config-0.1.0-2-any'\nCHECK_LOG = '{NEW_LOG}'\n".encode()),
    (b"*(PACKAGE+'-'+phase+'.log' for phase", b"*(CHECK_LOG if phase == 'check' else PACKAGE+'-'+phase+'.log' for phase"),
    (b"PACKAGE+'.pkg.tar.xz', PACKAGE+'-check.log'", b"PACKAGE+'.pkg.tar.xz', CHECK_LOG"),
)


def edit(body, pairs):
    for prior, current in pairs:
        P.need(body.count(prior) == 1 and current not in body, 'one exact Fish retention source seam')
        body = body.replace(prior, current, 1)
    return body


def identity(bodies, data):
    return dict(files=len(bodies), bytes=sum(map(len, bodies.values())),
                tree=data.git_tree(bodies), map=P.pin(bodies[MAP]))


def read_parent(base):
    raw = P.read(base/MAP)
    P.need(P.pin(raw) == R11['map'], 'exact published Fish r11 map')
    rows = json.loads(raw)['files']
    data = P.read(base/DATA)
    P.need(P.row(data) == rows[DATA], 'whole pinned r11 source validator')
    validator = P.load_bytes(data, 'fish_r11_source_validator', base/DATA)
    validator.source(base, R11['map']['sha256'])
    bodies = {MAP: raw}
    for name, wanted in rows.items():
        leaf = base/name
        value = P.read(leaf)
        P.need(P.row(value) == wanted and stat.S_IMODE(leaf.stat().st_mode) == 0o644,
               'exact r11 Source body and mode')
        bodies[name] = value
    P.need(identity(bodies, validator) == R11, 'exact published Fish r11 tree and census')
    return bodies


def assemble(old):
    new = dict(old)
    new[DATA] = edit(old[DATA], DATA_EDITS) + b'\n\n' + P.read(HERE/'inverse.py')
    new[EXPORT] = edit(old[EXPORT], EXPORT_EDITS)
    policy = json.loads(old[POLICY])
    retention = policy['inner_public_retention']
    for collection in ('public_leaves', 'success_required'):
        paths = retention[collection]
        for build in (1, 2):
            stem = f'build-{build}/artifacts/'
            before, after = stem+OLD_LOG, stem+NEW_LOG
            P.need(paths.count(before) == 1 and after not in paths, 'exact Fish check-log path in policy')
            paths[paths.index(before)] = after
    new[POLICY] = P.encode(policy)
    exporter = P.load_bytes(new[EXPORT], 'fish_r12_public_evidence', HERE/'public_evidence.py')
    P.need(exporter.DECLARATION == retention, 'whole Fish public exporter and policy agree')

    program = json.loads(old[PROGRAM])
    program['files'].update({name: P.row(new[name]) for name in (DATA, EXPORT, POLICY)})
    new[PROGRAM] = P.encode(program)
    mapping = json.loads(old[MAP])
    mapping['kind'] = NEW_KIND
    mapping['files'].update({name: P.row(new[name]) for name in (DATA, EXPORT, POLICY, PROGRAM)})
    new[MAP] = P.encode(mapping)

    data = P.load_bytes(new[DATA], 'fish_r12_source_validator', HERE/'data.py')
    P.need(identity(new, data) == R12, 'exact reviewed Fish r12 tree and census')
    P.need(data.inverse_source_r11_retention(new) == old, 'exact whole r11 inverse')
    return new, data


def construct(base, output):
    base, output = map(Path, (base, output))
    P.need(base.is_dir() and base == base.resolve() and output == output.resolve()
           and output.parent.is_dir() and not output.exists()
           and not output.is_relative_to(base) and not base.is_relative_to(output),
           'fresh disjoint Fish Source output')
    new, data = assemble(read_parent(base))
    output.mkdir(mode=0o700)
    for name, raw in new.items():
        path = output/name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(raw)
        path.chmod(0o644)
    data.source(output, R12['map']['sha256'])
    contract = P.load_bytes(new[HELD+'contract.py'], 'fish_held_contract', output/HELD/'contract.py')
    binding = json.loads(new[PREFIX+'base-binding.json'])
    contract.verify_source(output/'held-source32', binding['map']['sha256'])
    return dict(status='FISH02_CHECK_LOG_RETENTION_SOURCE_UNISSUED', files=R12['files'], bytes=R12['bytes'],
                tree=R12['tree'], source_map=R12['map'], workflow=P.pin(new[WORKFLOW]), policy=P.pin(new[POLICY]),
                owner_program=P.pin(new[PROGRAM]), Root_authority=None, native_pair='NOT RUN')


if __name__ == '__main__':
    P.need(sys.flags.isolated and sys.flags.dont_write_bytecode and __debug__, 'use unoptimized Python -I -B')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True, help='exact published r11 readback directory')
    parser.add_argument('--output', type=Path, required=True, help='fresh disjoint r12 Source directory')
    args = parser.parse_args()
    print(json.dumps(construct(args.base, args.output), indent=2, sort_keys=True))
