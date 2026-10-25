# SPDX-License-Identifier: MIT
"""Pure portable public Core49→51 factory; no installed/native authority."""
import argparse
import hashlib
import json
import os
import stat
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROFILE = {'bytes': 22756, 'sha256': '232ac086052a79bc2383ad66bfd94b4c3e98a2ae91917b00030c13ad4bdbb4e4'}
SEALS = ('source-manifest.json', '.github/workflows/native-arm-build.yml',
         '.github/workflows/native-arm-core7-real-systemd.yml')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def ordinary(value):
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
    path = ordinary(value)
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and
             0 <= before.st_size <= 4 * 1024**2, 'bounded ordinary single-link source file')
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
    root = ordinary(value)
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


def tree(root):
    return scan(root)[0]


def paths(source, output):
    source, output = ordinary(source), ordinary(output)
    need(output.parent.is_dir() and not os.path.lexists(output), 'fresh output required')
    need(not any('native-actual' in p.name for p in (output, *output.parents)),
         'native actual roots are not source-factory destinations')
    for protected in (source, HERE):
        need(not output.is_relative_to(protected) and not protected.is_relative_to(output),
             'disjoint supplied source/factory/output paths')
    return source, output


def compose(value):
    source = ordinary(value)
    entry_state = read_state(HERE / 'prepare.py')
    profile_raw, profile_state = read_state(HERE / 'profile.json')
    need(pin(profile_raw) == PROFILE, 'fixed entry-point-pinned source profile')
    profile = json.loads(profile_raw)
    need(profile['counts'] == dict(parent=49, result=51, held=40, changed=9, added=2) and
         profile['actual'] is None and profile['native_acceptance'] is False,
         'closed source-only 49→51 scope')
    before, source_state = scan(source)
    need({n: pin(b) for n, b in before.items()} == profile['parent']['files'],
         'whole exact public49 input required')
    values = dict(before)
    for name, edits in profile['edits'].items():
        for old, new in edits:
            need(values[name].count(old.encode()) == 1, 'one counted complete source seam')
            values[name] = values[name].replace(old.encode(), new.encode(), 1)
    need(set(profile['payloads']) == {'serial_result.py', 'serial-profile.json'},
         'only two fixed readable serial operands')
    payload_states = {}
    for name, row in profile['payloads'].items():
        need(row['file'] == ('serial_result.py.in' if name == 'serial_result.py' else name),
             'closed ordinary payload operand')
        raw, record = read_state(HERE / row['file'])
        need(pin(raw) == {k: row[k] for k in ('bytes', 'sha256')}, 'whole readable payload pin')
        values[name], payload_states[row['file']] = raw, (raw, record)
    values['source-manifest.json'] = encoded(dict(
        schema=1, purpose='CORE7_REAL_HOOKS_AND_ACTUAL_PID1_SOURCE_ONLY', actual=None,
        files={n: pin(b) for n, b in values.items()
               if n != 'source-manifest.json' and not n.startswith('.github/')}))
    workflow = values['workflow.yml.in']
    for marker, replacement in ((b'@ENTRY_SHA@', pin(values['entry.py'])['sha256'].encode()),
                                (b'@MANIFEST_SHA@', pin(values['source-manifest.json'])['sha256'].encode())):
        need(workflow.count(marker) == 1, 'one fixed workflow seal')
        workflow = workflow.replace(marker, replacement, 1)
    for name in SEALS[1:]:
        values[name] = workflow
    need({n: pin(b) for n, b in values.items()} == profile['result']['files'],
         'all51 output bytes must match exact public source')
    restored = dict(values)
    for name in profile['payloads']:
        restored.pop(name)
    for name, edits in profile['edits'].items():
        for old, new in reversed(edits):
            need(restored[name].count(new.encode()) == 1, 'one exact before-body inverse')
            restored[name] = restored[name].replace(new.encode(), old.encode(), 1)
    for name in SEALS:
        restored[name] = before[name]
    need(restored == before and all(values[n] == before[n] for n in profile['held']),
         'whole49 inverse and all40 held runtime/security/clock files')
    factory_states = dict(payload_states, **{'profile.json': (profile_raw, profile_state),
                                           'prepare.py': entry_state})
    need(all(read_state(HERE / n) == record for n, record in factory_states.items()) and
         scan(source) == (before, source_state), 'late source/profile/payload content or identity drift')
    return values, profile, (before, source_state), factory_states


def emit(source, output, context):
    need(context in ('known', 'null'), 'explicit known/NULL source-only context')
    source, output = paths(source, output)
    values, profile, before, factory_states = compose(source)
    paths(source, output)
    need(scan(source) == before and
         all(read_state(HERE / n) == record for n, record in factory_states.items()),
         'late complete input drift before any write')
    output.mkdir(mode=0o700)
    for name, raw in sorted(values.items()):
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(raw)
    need(tree(output) == values, 'complete exact51 emission')
    result = profile['result'] if context == 'known' else dict(source=None, ref=None)
    return dict(status='SOURCE_ONLY_EXACT_CORE51_NOT_NATIVE_ACCEPTANCE', files=51,
                source=result['source'], ref=result['ref'], actual=None,
                native_acceptance=False, M2='NOT_RUN', performance='NOT_RUN', clocks='ALL_HELD')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--context', choices=('known', 'null'), required=True)
    args = parser.parse_args()
    print(json.dumps(emit(args.source, args.output, args.context), sort_keys=True))
