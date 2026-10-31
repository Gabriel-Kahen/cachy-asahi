# SPDX-License-Identifier: MIT
"""Portable public1192→1197 exact-tooling source factory; no native authority."""
import argparse
import hashlib
import json
import os
import stat
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROFILE = {'bytes': 3022, 'sha256': 'bfc2f01f76d2f0f7bf03d0980c9abe3290c07cc29f40652175a6d56db867b29b'}


def need(ok, message):
    if not ok:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def canonical(value):
    raw = os.fspath(value)
    need(type(raw) is str and os.path.isabs(raw) and raw == os.path.normpath(raw),
         'absolute normalized path required')
    path = Path(raw)
    need(not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary nonalias ancestry')
    return path


def identity(info):
    # Reading a file/directory may update atime; it is never identity evidence.
    return tuple(getattr(info, key) for key in (
        'st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
        'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def read_state(value):
    path = canonical(value)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             0 <= before.st_size <= 16 * 1024**2, 'bounded ordinary single-link source file')
        parts, size = [], 0
        while part := os.read(fd, 1024**2):
            parts.append(part)
            size += len(part)
            need(size <= before.st_size, 'source file grew during read')
        need(size == before.st_size and identity(before) == identity(os.fstat(fd)) ==
             identity(path.lstat()), 'whole stable descriptor and path identity')
        return b''.join(parts), identity(before)
    finally:
        os.close(fd)


def read(path):
    return read_state(path)[0]


def scan(value):
    root = canonical(value)
    need(root.is_dir(), 'ordinary source root required')
    files, state, directories = {}, {}, {}
    for path in (root, *sorted(root.rglob('*'))):
        info = path.lstat()
        need(not path.is_symlink(), 'source alias refused')
        name = path.relative_to(root).as_posix() if path != root else ''
        if stat.S_ISDIR(info.st_mode):
            directories[name] = (identity(info), tuple(sorted(p.name for p in path.iterdir())))
        else:
            raw, record = read_state(path)
            files[name], state[name] = raw, record
    required = {''}
    for name in files:
        required.update('' if str(p) == '.' else p.as_posix() for p in Path(name).parents)
    need(set(directories) == required, 'closed source directory membership, no foreign empty dirs')
    for name, (record, names) in directories.items():
        path = root / name
        need(identity(path.lstat()) == record and
             tuple(sorted(p.name for p in path.iterdir())) == names, 'stable whole source namespace')
    return files, dict(files=state, directories=directories)


def paths(source, output):
    source, output = canonical(source), canonical(output)
    need(output.parent.is_dir() and not os.path.lexists(output), 'fresh output required')
    need(not any('native-actual' in p.name for p in (output, *output.parents)),
         'native actual roots are not source-factory destinations')
    for protected in (source, HERE):
        need(not output.is_relative_to(protected) and not protected.is_relative_to(output),
             'disjoint supplied source/factory/output paths')
    return source, output


def tree(root):
    return scan(root)[0]


def render(parent):
    profile_raw, profile_state = read_state(HERE / 'profile.json')
    need(pin(profile_raw) == PROFILE, 'entry-point-pinned exact1197 factory profile')
    profile = json.loads(profile_raw)
    need((profile['parent'], profile['result'], profile['held']) == (1192,1197,1185) and
         len(profile['changed']) == 7 and len(profile['added']) == 5 and
         all(profile[k] is None for k in ('actual_source','actual_ref','actual_run','Root_acceptance')),
         'closed1192→1197 source-only profile')
    need(profile['role'] == 'APPS6_BASELINE' and profile['Apps_version'] == '0.1.0-6' and
         profile['other606'] == profile['Runtime1'] == 'HELD' and
         profile['target'] == dict(bytes=12075,sha256='72818a8a2ae488281b08486b92c435ec244ef3b5313f23b97473d1684ecb68b4'),
         'exact Apps6 baseline target and other606/Runtime1 held')
    entry = read_state(HERE / 'prepare.py')
    operands = {n:read_state(HERE / n) for n in profile['files']}
    need({n:pin(v[0]) for n,v in operands.items()} == profile['files'],
         'all seven readable source transform operands pinned')
    inputs = {n:v[0] for n,v in operands.items()}
    expected = json.loads(inputs['input-source.json'])
    before, identities = scan(parent)
    need(expected['source'] == '412742e6320aaf8f546c537cdcda534a843b6dcd' and
         len(before) == 1192 and {n:pin(b) for n,b in before.items()} == expected['files'],
         'whole exact public1192 source required')
    # Execute only the sealed plain-text module's pure DATA transform. Its common
    # capability has precisely these three helpers. No compressed inverse DATA,
    # parent Python, producer, VM, fetch, source guard or result is executed here.
    common = types.SimpleNamespace(need=need,pin=pin,enc=encoded)
    missing = object()
    previous = sys.modules.get('common',missing)
    library = types.ModuleType('_closed1197_transform')
    library.__file__ = str(HERE / 'tooling_source.py.in')
    try:
        sys.modules['common'] = common
        exec(compile(inputs['tooling_source.py.in'],library.__file__,'exec'),vars(library))
    finally:
        if previous is missing:
            sys.modules.pop('common',None)
        else:
            sys.modules['common'] = previous
    out = library.transformed(before,inputs['tooling_inputs.py.in'],
        inputs['tooling_source.py.in'],inputs['tooling-profile.json.in'],
        inputs['tooling-builder574.lock.in'],inputs['tooling-parent.json.in'])
    wanted = json.loads(inputs['output-source.json'])
    need(wanted['source'] == '04f4ae2f164fe6c58a4b3b31ea8ab544880d9892' and
         wanted['actual'] is None and len(out) == 1197 and
         {n:pin(b) for n,b in out.items()} == wanted['files'], 'whole exact public1197 output')
    need(set(out)-set(before) == set(profile['added']) and
         {n for n in before if out[n] != before[n]} == set(profile['changed']),
         '1185 held/seven changed/five added exact source partition')
    states = dict(operands, **{'profile.json':(profile_raw,profile_state),'prepare.py':entry})
    need(scan(parent) == (before,identities) and
         all(read_state(HERE / n) == state for n,state in states.items()),
         'late whole parent/transform identity or content drift')
    return out, (before,identities), states


def build(parent, output, context='known'):
    need(context in ('known','null'), 'source-only known/NULL receipt choice')
    parent, output = paths(parent,output)
    values, before, states = render(parent)
    paths(parent,output)
    need(scan(parent) == before and all(read_state(HERE / n) == row for n,row in states.items()),
         'late complete source/operands before any output write')
    output.mkdir(mode=0o700)
    for n,b in sorted(values.items()):
        p = output / n
        p.parent.mkdir(parents=True,exist_ok=True)
        fd = os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(b)
    need(tree(output) == values, 'complete1197 output unchanged')
    return dict(status='REPRODUCED_SOURCE_ONLY_APPS6_BASELINE1197_EXACT35_ORIGINAL_TOOLING_CACHE',
        context=context,files={n:pin(b) for n,b in values.items()},actual_source=None,
        actual_ref=None,actual_run=None,Root_acceptance=None,hardware='NOT_RUN')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--context',choices=('known','null'),default='known')
    args = parser.parse_args()
    print(json.dumps(build(args.parent,args.output,args.context),sort_keys=True,indent=2))
