# SPDX-License-Identifier: MIT
"""Reproduce public Core45 from the complete pinned Core44 source; no actors."""
import argparse
import hashlib
import json
import os
import stat
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROFILE = {'bytes': 19018, 'sha256': '18a0b9212b327700fbe2ae1c40e514299d17f869291f928f9ab84315092fc104'}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and path == Path(os.path.abspath(path)), 'absolute normalized path')
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'no symlink path components')
    return path


def read(path):
    path = ordinary(path)
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 4 * 1024**2,
         'bounded ordinary single-link source file')
    return path.read_bytes()


def tree(root):
    root = ordinary(root)
    need(root.is_dir(), 'complete source directory required')
    values = {}
    for path in sorted(root.rglob('*')):
        info = path.lstat()
        need(not path.is_symlink(), 'source symlink refused')
        if stat.S_ISDIR(info.st_mode):
            continue
        values[path.relative_to(root).as_posix()] = read(path)
    return values


def compose(source):
    source = ordinary(source)
    raw_profile = read(HERE / 'profile.json')
    need(pin(raw_profile) == PROFILE, 'fixed source-only profile')
    profile = json.loads(raw_profile)
    values = tree(source)
    need({n: pin(b) for n, b in values.items()} == profile['parent']['files'],
         'complete exact public44 input required')
    before = dict(values)
    for name, edits in profile['edits'].items():
        for old, new in edits:
            need(values[name].count(old.encode()) == 1, 'one counted source seam')
            values[name] = values[name].replace(old.encode(), new.encode(), 1)
    payload = read(HERE / 'transaction_output.py.in')
    need(pin(payload) == profile['payload'], 'complete readable guard payload')
    values['transaction_output.py'] = payload
    values['source-manifest.json'] = encoded(dict(
        schema=1, purpose='CORE7_REAL_HOOKS_AND_ACTUAL_PID1_SOURCE_ONLY', actual=None,
        files={n: pin(b) for n, b in values.items()
               if n != 'source-manifest.json' and not n.startswith('.github/')}))
    workflow = values['workflow.yml.in'].replace(
        b'@ENTRY_SHA@', pin(values['entry.py'])['sha256'].encode()).replace(
        b'@MANIFEST_SHA@', pin(values['source-manifest.json'])['sha256'].encode())
    for name in ('.github/workflows/native-arm-build.yml',
                 '.github/workflows/native-arm-core7-real-systemd.yml'):
        values[name] = workflow
    need({n: pin(b) for n, b in values.items()} == profile['result']['files'],
         'all45 output bytes must match public source')
    need(all(before[n] == values[n] for n in profile['held']), 'all39 held source leaves')
    need(read(HERE / 'profile.json') == raw_profile and
         read(HERE / 'transaction_output.py.in') == payload and tree(source) == before,
         'late source/profile/payload mutation')
    return values, profile


def emit(source, output, context):
    source, output = ordinary(source), ordinary(output)
    need(context in ('known', 'null'), 'explicit source-only context')
    need(output.parent.is_dir() and not os.path.lexists(output), 'fresh output required')
    for protected in (source, HERE):
        need(not output.is_relative_to(protected) and not protected.is_relative_to(output),
             'disjoint input/factory/output paths')
    values, profile = compose(source)
    output.mkdir(mode=0o700)
    for name, raw in values.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(raw)
    need(tree(output) == values, 'all45 emitted bytes')
    identity = profile['result'] if context == 'known' else dict(source=None, ref=None)
    return dict(status='SOURCE_ONLY_EXACT_CORE45_NOT_NATIVE_ACCEPTANCE',
                files=45, source=identity['source'], ref=identity['ref'], actual=None,
                native_acceptance=False, current90fit='NOT_ESTABLISHED', M2='NOT_RUN')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--context', choices=('known', 'null'), required=True)
    args = parser.parse_args()
    print(json.dumps(emit(args.source, args.output, args.context), sort_keys=True))
