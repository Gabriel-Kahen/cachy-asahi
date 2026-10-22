#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit one exact native4K wrapper source, without executing any runtime actor."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import stat

HERE = Path(__file__).resolve().parent
PROFILE_SHA = '6807bec067011855e31fda63f565189a1d72fdfd79c145d5c316234016541dee'
HELD = 'b21a5864d5a4610b9181a1c270ac8821d8448a17'
CASES = ('precommit-exit86', 'postcommit-exit87')
WF = '.github/workflows/native-arm-build.yml'


def need(value, reason):
    if not value:
        raise ValueError(reason)


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def identity(value):
    return tuple(getattr(value, name) for name in (
        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def ordinary(path):
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary no-alias ancestry')


def read(path):
    ordinary(path)
    before = path.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
         0 <= before.st_size <= 32 * 1024**2, 'bounded single-link source')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as stream:
        need(identity(os.fstat(stream.fileno())) == identity(before), 'opened source identity')
        raw = stream.read(before.st_size + 1)
        need(identity(os.fstat(stream.fileno())) == identity(before), 'stable source descriptor')
    ordinary(path)
    need(identity(path.lstat()) == identity(before) and len(raw) == before.st_size,
         'stable source path and complete bytes')
    return raw


def tree(root, checkout=False):
    ordinary(root)
    need(root.is_dir(), 'ordinary complete source directory')
    result = {}
    for directory, dirs, names in os.walk(root, followlinks=False):
        directory = Path(directory)
        if directory == root and checkout:
            dirs[:] = [name for name in dirs if name != '.git']
            names = [name for name in names if name != '.git']
        for name in dirs:
            need(stat.S_ISDIR((directory / name).lstat().st_mode), 'ordinary source directory')
        for name in names:
            path = directory / name
            result[path.relative_to(root).as_posix()] = read(path)
    return result


def pins(rows):
    return {name: pin(raw) for name, raw in rows.items()}


def profile():
    raw = read(HERE / 'profile.json')
    need(pin(raw)['sha256'] == PROFILE_SHA, 'whole fixed wrapper profile')
    value = json.loads(raw)
    need(value['status'] == 'EXACT_SOURCE_ONLY_NATIVE_ARM4K_WRAPPERS' and
         value['held_source'] == HELD and value['held_source_files'] == 489 and
         set(value['variants']) == {'normal', 'recovery'} and value['actual'] is None,
         'explicit source-only variants')
    return value


def emit(held, output, selected):
    need(selected in ('normal', 'recovery'), 'explicit normal or recovery profile')
    held, output = Path(held).absolute(), Path(output).absolute()
    ordinary(held)
    ordinary(output)
    need(not output.exists() and output.parent.is_dir(), 'fresh output with existing parent')
    for source in (held, HERE):
        need(not output.is_relative_to(source) and not source.is_relative_to(output),
             'disjoint source and output')
    value = profile()
    base_raw = read(HERE / 'input-profile.json')
    need(pin(base_raw) == value['input_profile'], 'whole held input profile')
    base = json.loads(base_raw)
    need(base['held_source'] == base['held_publication']['source'] ==
         base['held_git']['source'] == HELD and
         base['held_publication']['status'] == 'COMMITTED_EXACT_CLOSED_TRIAL_SOURCE' and
         base['held_git']['status'] == 'PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN' and
         len(base['held_files']) == 489 and base['held_git']['files'] == base['held_files'],
         'complete immutable b21489 source identity')
    need(pins(tree(held, checkout=True)) == base['held_files'], 'whole pinned held489')
    payload = tree(HERE / 'payload')
    need(pins(payload) == value['payload'] and len(payload) == 16, 'whole used readable payloads')
    selected_profile = copy.deepcopy(base)
    if selected == 'recovery':
        selected_profile.pop('case')
        selected_profile.update(cases=list(CASES),
            status='EXPLICIT_NATIVE_ARM4K_UPDATER604_RECOVERY_SOURCE_ONLY_NOT_ACCEPTED',
            normal_wrapper_parent=value['normal_parent'])
        selected_profile['limits']['driver'] = 2400
    rows = {name: payload[selected + '/' + name] for name in (
        'case.py', 'runtime.py', 'entry.py', 'cleanup.py', 'retain.py',
        'test_source.py', 'source-manifest.json')}
    rows['profile.json'] = base_raw if selected == 'normal' else encoded(selected_profile)
    rows[WF] = payload[selected + '/workflow.json']
    named = '.github/workflows/native-arm-updater604-' + (
        'copy4k' if selected == 'normal' else 'recovery4k') + '.yml'
    rows[named] = rows[WF]
    expected = value['variants'][selected]
    need(pins(rows) == expected['files'] and len(rows) == 10,
         'complete exact selected10 before any output')
    manifest = json.loads(rows['source-manifest.json'])
    need(manifest['files'] == {n: pin(b) for n, b in rows.items() if n != 'source-manifest.json'} and
         all(manifest[k] is None for k in ('actual_source', 'actual_ref', 'actual_run')) and
         all(selected_profile[k] is None for k in ('wrapper_source', 'wrapper_ref', 'wrapper_run')),
         'whole source manifest and NULL actuals')
    output.mkdir(mode=0o700)
    for name, raw in sorted(rows.items()):
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            stream.write(raw)
    need(pins(tree(output)) == expected['files'], 'complete emitted selected10')
    return dict(status='SOURCE_ONLY_NATIVE_ARM4K_WRAPPER', profile=selected, files=10,
                held_source=HELD, expected_source=expected['source'], expected_ref=expected['ref'],
                actual=None, native_result='UNQUALIFIED', hardware='NOT_RUN', release='NOT_ADMITTED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--held', type=Path, required=True, help='whole pinned b21489 source checkout')
    parser.add_argument('--profile', choices=('normal', 'recovery'), required=True)
    parser.add_argument('--output', type=Path, required=True, help='fresh disjoint source directory')
    args = parser.parse_args()
    print(json.dumps(emit(args.held, args.output, args.profile), sort_keys=True))


if __name__ == '__main__':
    main()
