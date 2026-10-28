#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit the NULL-selected606 source from whole-pinned public roles; no actors."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def need(ok, why):
    if not ok:
        raise ValueError(why)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--basis', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source, basis, output = (p.absolute() for p in (args.source, args.basis, args.output))
    for root in (source, basis):
        need(root.is_dir() and not any(p.is_symlink() for p in (root, *root.parents)), 'ordinary source operand')
    pins = json.loads((HERE / 'source-pins.json').read_bytes())
    for name, wanted in pins['files'].items():
        path = source / name
        need(not any(p.is_symlink() for p in (path, *path.parents)) and path.is_file() and pin(path.read_bytes()) == wanted,
             'canonical606 source differs: ' + name)
    lane = source / 'scripts/ci/current606-native'
    need({p.name for p in lane.iterdir()} == {Path(n).name for n in pins['files'] if n.startswith('scripts/ci/current606-native/')},
         'exact canonical606 lane files')
    need((lane / 'input-policy.json').read_bytes() == (lane / 'default-input-policy.json').read_bytes(),
         'canonical606 remains explicitly NULL')
    sys.path.insert(0, str(lane))
    spec = importlib.util.spec_from_file_location('_canonical606_prepare', lane / 'prepare.py')
    prepare = importlib.util.module_from_spec(spec)
    with patch.object(subprocess, 'Popen', side_effect=AssertionError('preflight creates no actor/network/Git process')):
        spec.loader.exec_module(prepare)
        rows = json.loads((lane / 'metadata-pins.json').read_bytes())['files']
        with tempfile.TemporaryDirectory(prefix='canonical606-metadata-') as directory:
            metadata = Path(directory)
            for name, wanted in rows.items():
                original = basis / 'held604' / name
                need(not any(p.is_symlink() for p in (original, *original.parents)) and pin(original.read_bytes()) == wanted,
                     'whole47 metadata source differs: ' + name)
                path = metadata / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(original.read_bytes())
            result = prepare.emit(basis / 'held604', basis / 'held-tools', output,
                                  metadata_source=metadata)
    need(len(result['files']) == 263 and all(result[k] is None for k in ('actual_source', 'actual_ref', 'actual_run')),
         'complete263 source-only emission required')
    print(json.dumps(dict(status='PASS_CANONICAL606_NULL_SOURCE263_NO_ACTORS', files=263,
                          native='NOT_RUN', hardware='NOT_RUN', actual_source=None, actual_run=None)))


if __name__ == '__main__':
    main()
