#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check the selected desktop successor and caller without launching an actor."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace


PROFILE = Path(__file__).with_name('source.json')
VIRTUAL = Path('scripts/virtual')
CALLER = Path('scripts/ci/development')
PACKET = CALLER / 'packet.lock.json'
SOURCE_LIMIT = 8 * 1024**2


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(body):
    return hashlib.sha256(body).hexdigest()


def check_file(root, name, row):
    path = root / name
    require(path.resolve(strict=True) == path and path.is_relative_to(root), 'alias or out-of-tree source: ' + name)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == row['bytes'] <= SOURCE_LIMIT and
            f'{stat.S_IMODE(info.st_mode):04o}' == row['mode'], 'source shape differs: ' + name)
    with path.open('rb') as handle:
        body = handle.read(row['bytes'] + 1)
    require(len(body) == row['bytes'] and sha256(body) == row['sha256'], 'source bytes differ: ' + name)
    return body


def git_head(root):
    return subprocess.check_output(['git', '--no-replace-objects', '-C', str(root), 'rev-parse', 'HEAD'], text=True,
                                   env={'PATH': os.environ['PATH'], 'GIT_NO_LAZY_FETCH': '1', 'LC_ALL': 'C'}, timeout=10).strip()


def freeze_maintained(carrier, successor, profile, output):
    selection = profile['maintained']
    require(git_head(carrier) == selection['carrier_commit'], 'maintained carrier commit differs')
    raw = check_file(carrier, str(PACKET), selection['carrier_packet'])
    old = json.loads(raw)
    updated = set(selection['updated_rows'])
    with tempfile.TemporaryDirectory(prefix='virtual-desktop-v2-packet-') as directory:
        scratch = Path(directory)
        root = scratch / 'source'
        for name, row in old['source_files'].items():
            if name in updated:
                member = profile['source_files'][name]
                body = check_file(successor, name, member)
                mode = int(member['mode'], 8)
            else:
                source = carrier / name
                mode = row['mode']
                member = row | {'mode': f'{mode:04o}', 'bytes': source.lstat().st_size}
                body = check_file(carrier, name, member)
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
            target.chmod(mode)
        freezer = root / CALLER / 'packet.py'
        spec = importlib.util.spec_from_file_location('maintained_packet_freezer', freezer)
        packet = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(packet)
        initial = 'scripts/ci/integration.lock.json'
        pins = old['metadata_pins']
        candidate = scratch / 'candidate.json'
        digest = packet.freeze_composed(root, candidate, root / initial, pins[initial], pins,
                                        composition=selection['composition'])
        raw = candidate.read_bytes()
        require(digest == sha256(raw) == selection['candidate_packet_sha256'], 'maintained successor packet differs')
        proposed = json.loads(raw)
        rows = proposed['source_files']
        require(len(rows) == 261 and set(old['source_files']) - set(rows) == set(packet.INSTALLER_EXTRA) and
                {name for name, row in rows.items() if old['source_files'].get(name) != row} == updated and
                all(proposed[k] == old[k] for k in ('initial_source_files', 'generated_fixture_files', 'metadata_pins')),
                'maintained successor row scope differs')
    if output is not None:
        output = output.parent.resolve(strict=True) / output.name
        require(not output.is_relative_to(carrier) and not output.is_relative_to(successor), 'fresh external packet path required')
        with output.open('xb') as handle:
            handle.write(raw)
    return digest


def preflight(root, maintained_root=None, packet_output=None):
    root = root.resolve(strict=True)
    profile = json.loads(PROFILE.read_bytes())
    head = git_head(root)
    require(head == profile['source_commit'], 'selected source commit differs')
    for name, row in profile['source_files'].items():
        check_file(root, name, row)
    sys.path.insert(0, str(root / CALLER))
    try:
        import virtual_stage

        pins = {name: profile['source_files'][str(VIRTUAL / name)]['sha256'] for name in virtual_stage.PACKET_FILES}
        accepted, declarations = virtual_stage.source_packet(SimpleNamespace(virtual_packet_sha256=pins), root)
    finally:
        sys.path.pop(0)
    result = {'status': 'PASS_VIRTUAL_DESKTOP_SUCCESSOR_SOURCE_ONLY', 'source_commit': head,
              'caller_sha256': profile['source_files'][str(CALLER / 'virtual_stage.py')]['sha256'],
              'packet_members': len(accepted), 'core_members': len(declarations['CORE']),
              'guest_execution': 'NOT RUN', 'hardware_validation': 'NOT RUN'}
    if maintained_root is not None:
        result['maintained_packet_sha256'] = freeze_maintained(maintained_root.resolve(strict=True), root, profile,
                                                               packet_output)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True, help='Checkout of the selected successor source')
    parser.add_argument('--maintained-root', type=Path, help='Checkout of the registered maintained carrier')
    parser.add_argument('--packet-output', type=Path, help='Optional new output for the exact maintained packet')
    args = parser.parse_args()
    if args.packet_output is not None and args.maintained_root is None:
        parser.error('--packet-output requires --maintained-root')
    print(json.dumps(preflight(args.root, args.maintained_root, args.packet_output), sort_keys=True))
