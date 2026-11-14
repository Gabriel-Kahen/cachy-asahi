#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check exact pinned local source snapshots; no fetching or system changes."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import subprocess

REVISION = '1c4c455b486fd0b0f1c7ae587130a2c05e7a9560'


def need(ok, message):
    if not ok:
        raise ValueError(message)


def descriptor(path):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 4 * 1024**2,
         'bounded single-link source file required: ' + str(path))
    raw = path.read_bytes()
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), mode=0o644)


def tree(root):
    result = {}
    for path in root.rglob('*'):
        need(not path.is_symlink(), 'source aliases refused')
        if path.is_file():
            result[path.relative_to(root).as_posix()] = descriptor(path)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--srcdir', type=Path, required=True)
    parser.add_argument('--root', type=Path, help='optional trusted checkout body comparison; never needed at runtime')
    args = parser.parse_args()
    source = args.srcdir.resolve()
    provenance = json.loads((source/'source-provenance.json').read_bytes())
    need(provenance['source_revision'] == REVISION, 'exact source revision differs')
    need(tree(source/'private') == provenance['runtime_files'], 'finite runtime snapshot differs')
    need(tree(source/'checks') == provenance['check_files'], 'check-only snapshot differs')
    spec = importlib.util.spec_from_file_location('package_source_runtime', source/'private/scripts/install/fresh_handoff/runtime.py')
    runtime = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runtime)
    lock = runtime.verify(source/'private', provenance['runtime_sha256'])
    need(lock['source_commit'] == REVISION, 'runtime owning-source commit differs')
    need(len(runtime.RUNTIME) == 17 and len(runtime.INTERFACES) == 15 and len(provenance['runtime_files']) == 33,
         'runtime closure changed')
    if args.root:
        # Generated source/runtime receipts have no pretended historical Git body.
        for name in set(runtime.RUNTIME) | set(runtime.INTERFACES) | {'LICENSE'}:
            raw = subprocess.check_output(['git', '-C', str(args.root.resolve()), 'show', REVISION+':'+name])
            need((source/'private'/name).read_bytes() == raw, 'committed runtime/interface body differs: ' + name)
        for name in ('scripts/install/fresh_handoff/signed_fixture.py', 'scripts/release/test_release.py', 'scripts/release/release.py'):
            raw = subprocess.check_output(['git', '-C', str(args.root.resolve()), 'show', REVISION+':'+name])
            need((source/'checks'/name).read_bytes() == raw, 'committed check body differs: ' + name)
    print(json.dumps(dict(status='PASS finite source snapshot', runtime_files=33,
                          check_files=len(provenance['check_files']), source_revision=REVISION), sort_keys=True))


if __name__ == '__main__':
    main()
