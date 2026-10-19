#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit the whole NULL-selected Welcome-on606 source; no actors or admission."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
LANE = 'scripts/ci/current606-welcome5-closed-owner'
CARRIER = 'deaf5d618fbc7be87b4e0296481beb7e336a9155'


def need(ok, why):
    if not ok:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def ordinary(path):
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary source operand')


def validate(source, pins):
    ordinary(source)
    need(source.is_dir(), 'source directory')
    for name, wanted in pins['files'].items():
        path = source / name
        ordinary(path)
        need(path.is_file() and path.stat().st_nlink == 1 and pin(path.read_bytes()) == wanted,
             'canonical owner source differs: ' + name)
    lane = source / LANE
    need({p.name for p in lane.iterdir()} ==
         {Path(n).name for n in pins['files'] if n.startswith(LANE + '/')},
         'exact canonical owner namespace')
    policy = json.loads((lane / 'input-policy.json').read_bytes())
    need(policy['status'] == 'UNBOUND_SOURCE_TEMPLATE' and
         all(v is None for v in policy['current606'].values()) and
         all(policy[k] is None for k in ('actual_source', 'actual_ref', 'actual_run', 'nonce',
                                        'measurement', 'output', 'retirement', 'capture_receipt')),
         'canonical owner selection remains NULL')


def emit(source, basis, output):
    need(CARRIER is not None, 'Root new copyworker source carrier pending')
    pins = json.loads((HERE / 'source-pins.json').read_bytes())
    need(pins['schema_version'] == 1 and pins['carrier'] == CARRIER and
         pins['purpose'] == 'SOURCE_CARRIER_ONLY_NOT_NATIVE_AUTHORITY', 'fixed public source carrier')
    validate(source, pins)
    ordinary(basis)
    need(basis.is_dir(), 'four-role source carrier directory')
    lane = source / LANE
    # The registration wrapper is outside the runtime namespace. The unchanged
    # emitter validates every file of all four roles before creating output.
    sys.path.insert(0, str(lane))
    spec = importlib.util.spec_from_file_location('_canonical_welcome606_prepare', lane / 'prepare.py')
    prepare = importlib.util.module_from_spec(spec)
    with patch.object(subprocess, 'Popen', side_effect=AssertionError('no actor/network/Git process')):
        spec.loader.exec_module(prepare)
        rows = prepare.emit({role: basis / role for role in prepare.C.ROLES}, output)
        need(rows == pins['emitted_files'] and len(rows) == 440, 'genuine complete440 source emission')
        for name, wanted in pins['files'].items():
            need(pin((output / name).read_bytes()) == wanted, 'emitted default differs: ' + name)
    return dict(status='PASS_CANONICAL_NULL_WELCOME606_SOURCE440_NO_ACTORS', files=len(rows),
                source_carrier=CARRIER, source_carrier_scope='SOURCE_BYTES_ONLY',
                actual_source=None, actual_ref=None, actual_run=None,
                native='NOT_RUN', hardware='NOT_RUN', release='NOT_ADMITTED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--basis', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(emit(*(p.absolute() for p in (args.source, args.basis, args.output))), sort_keys=True))


if __name__ == '__main__':
    main()
