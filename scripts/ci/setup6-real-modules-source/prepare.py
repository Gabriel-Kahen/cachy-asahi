#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Materialize the fixed Setup6 real-module source without running its actors."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

HERE = Path(__file__).resolve().parent


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def regular(path):
    path = Path(path).absolute()
    need('..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary absolute source path required')
    before = path.stat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= 16 * 1024**2, 'bounded single-link source file required')
    raw = path.read_bytes()
    after = path.stat()
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    need(all(getattr(before, k) == getattr(after, k) for k in fields) and len(raw) == before.st_size, 'source changed during read')
    return raw


def selected(root, rows):
    result = {}
    for name, wanted in rows.items():
        relative = Path(name)
        need(not relative.is_absolute() and '..' not in relative.parts, 'contained source name required')
        raw = regular(root / relative)
        need(pin(raw) == wanted, 'source pin differs: ' + name)
        result[name] = raw
    return result


def emit(parent, setup6, output):
    parent, setup6, output = map(lambda p: Path(p).absolute(), (parent, setup6, output))
    profile = json.loads(regular(HERE / 'profile.json'))
    need(profile['schema_version'] == 1 and len(profile['output_files']) == 240, 'fixed Setup6 source profile required')
    need(not os.path.lexists(output) and output.parent.is_dir() and not any(p.is_symlink() for p in (output.parent, *output.parents)), 'fresh ordinary output required')
    need(all(output != p and p not in output.parents for p in (parent, setup6, HERE)), 'output must be outside every input')
    bodies = selected(parent, profile['parent_files'])
    bodies.update({'setup6-source/' + n: raw for n, raw in selected(setup6, profile['setup6_files']).items()})
    bodies.update(selected(HERE / 'payload', profile['payload_files']))
    need({n: pin(raw) for n, raw in bodies.items()} == profile['output_files'], 'whole emitted source differs')
    output.mkdir(mode=0o700)
    for name, raw in sorted(bodies.items()):
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(raw)
    return dict(status='PASS_EXACT_SETUP6_REAL_MODULES_SOURCE_ONLY', files=240, expected_source=profile['expected_source'], native='NOT_RUN', hardware='NOT_RUN', release='NOT_ADMITTED')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original-checkout', type=Path, required=True)
    parser.add_argument('--setup6-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(emit(args.original_checkout, args.setup6_source, args.output), sort_keys=True))
