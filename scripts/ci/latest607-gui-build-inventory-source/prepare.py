# SPDX-License-Identifier: MIT
"""Portable exact public687→public692; supplied source is DATA, never executed."""
import argparse
import hashlib
import json
import os
import stat
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROFILE = {'bytes': 393996, 'sha256': '11d64a0a89e737b588d56e75b5abffb0ea976d5dd732dd64e837eafd5347da7f'}


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
             0 <= before.st_size <= 8 * 1024**2, 'bounded ordinary single-link source file')
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


def apply(raw, edits, reverse=False):
    for seam in reversed(edits) if reverse else edits:
        old, new = seam['before'].encode(), seam['after'].encode()
        if reverse:
            old, new = new, old
        need(old and raw.count(old) == seam['count'], 'exact counted source seam')
        raw = raw.replace(old, new)
    return raw


def compose(value):
    import base64
    source = ordinary(value)
    entry_state = read_state(HERE / 'prepare.py')
    profile_raw, profile_state = read_state(HERE / 'profile.json')
    need(pin(profile_raw) == PROFILE, 'entry-point-pinned closed build-inventory profile')
    profile = json.loads(profile_raw)
    need(profile['counts'] == dict(parent=687, result=692, held=670, changed=17, added=5) and
         profile['actual'] is None and profile['native_acceptance'] is False and
         profile['build_policy']['role'] == 'runtime607' and
         profile['build_policy']['target'] == dict(bytes=12076, sha256=
             'be35402204ba5c03d78279722afa83047c9575d2da70fb5c4064f46ed15954c5'),
         'exact selected607 source-only scope; original defaults held')
    before, source_state = scan(source)
    need({n: pin(b) for n, b in before.items()} == profile['parent']['files'],
         'whole exact ordinary public687 input required')
    values = {name: before[name] for name in profile['parent']['files']}
    operands, operand_states = {}, {}
    for name, expected in profile['operands'].items():
        raw, record = read_state(HERE / name)
        need(pin(raw) == expected, 'whole readable fixed operand')
        operands[name], operand_states[name] = raw, (raw, record)
    for name, edits in profile['edits'].items():
        values[name] = apply(values[name], edits)
    for name, operand in profile['append'].items():
        values[name] += operands[operand]
    home = 'implementation/factory/'
    capacity = json.loads(before[home + 'service-vm-profile.json'])
    footer = ("\n# Explicit selected TCG route; every original factory function/default above is held.\n"
              "def service1800():\n    return load('_owned_service1800_capacity',HERE/'service_capacity.py').factory(globals(),'tcg1800')\n").encode()
    need(values[home + 'factory.py'].endswith(footer), 'exact held service route footer')
    capacity['original_helpers']['factory.py'] = pin(values[home + 'factory.py'][:-len(footer)])
    values[home + 'service-vm-profile.json'] = encoded(capacity)
    values['implementation/runner-context-policy.json'] = operands['runner-context-policy.json.in']
    inverse = json.loads(before['implementation/body-inverses.json'])
    seams = dict(profile['edits'])
    seams.update({name: [dict(before='', after=operands[operand].decode(), count=1)]
                  for name, operand in profile['append'].items()})
    for row in inverse:
        if row['after_path'] in seams:
            row['seams'].extend(seams[row['after_path']])
    for name in ('build_scope.py', 'failure_cleanup.py'):
        path = home + name
        original = 'parent574/factory/' + name
        need(before[path] == before[original], 'entire original606 default helper')
        inverse.append(dict(after_path=path, before_path=original, seams=seams[path]))
    values['implementation/body-inverses.json'] = encoded(inverse)
    for name in ('build_inventory.py', 'test_build_inventory.py'):
        values['implementation/' + name] = operands[name + '.in']
    values['implementation/build-inventory-policy.json'] = encoded(profile['build_policy'])
    changed = {name for name in before if values.get(name) != before[name]}
    parent = dict(schema=1, variant='known', source=profile['parent']['source'],
                  ref=profile['parent']['ref'], actual=None, files=profile['parent']['files'],
                  before={name: base64.b64encode(before[name]).decode()
                          for name in changed | {'source-manifest.json'}})
    # These exact before DATA bytes are GENERATED from supplied687; no codec is
    # decoded or executed and no before-source blob ships in the factory.
    values['implementation/build-inventory-parent.json'] = encoded(parent)
    guard = operands['build_inventory_guard.py.in']
    need(guard.count(b'PARENT_PINS=None') == guard.count(b'PRODUCTS=None') ==
         guard.count(b"\nSELF_SHA='@SELF@'\ndef verify") == 1, 'three closed guard seal operands')
    guard = guard.replace(b'PARENT_PINS=None', ('PARENT_PINS=' + repr(profile['parent_pins'])).encode())
    products = {n: pin(b) for n, b in values.items()
                if n not in ('implementation/build_inventory_guard.py', 'source-manifest.json')}
    guard = guard.replace(b'PRODUCTS=None', ('PRODUCTS=' + repr(products)).encode())
    guard = guard.replace(b"SELF_SHA='@SELF@'", ('SELF_SHA=' + repr(pin(guard)['sha256'])).encode(), 1)
    values['implementation/build_inventory_guard.py'] = guard
    manifest = json.loads(before['source-manifest.json'])
    manifest['files'] = {n: pin(b) for n, b in values.items() if n != 'source-manifest.json'}
    values['source-manifest.json'] = encoded(manifest)
    need({n: pin(b) for n, b in values.items()} == profile['result']['files'],
         'every exact public692 output byte')
    restored = dict(values)
    for name in set(values) - set(before):
        restored.pop(name)
    for name, edits in profile['edits'].items():
        restored[name] = apply(restored[name], edits, reverse=True)
    for name, operand in profile['append'].items():
        footer = operands[operand]
        need(restored[name].endswith(footer), 'one exact readable footer inverse')
        restored[name] = restored[name][:-len(footer)]
    for name in ('implementation/factory/service-vm-profile.json',
                 'implementation/runner-context-policy.json', 'implementation/body-inverses.json',
                 'source-manifest.json'):
        restored[name] = before[name]
    need(restored == before and all(values[n] == before[n] for n in profile['held']),
         'complete687 inverse and all670 held source/default/security/clock bodies')
    states = dict(operand_states, **{'profile.json': (profile_raw, profile_state),
                                    'prepare.py': entry_state})
    need(all(read_state(HERE / n) == record for n, record in states.items()) and
         scan(source) == (before, source_state), 'late source/profile/operand identity or byte drift')
    return values, profile, (before, source_state), states


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
    need(tree(output) == values, 'complete exact692 emission')
    result = profile['result'] if context == 'known' else dict(source=None, ref=None)
    return dict(status='SOURCE_ONLY_EXACT_GUI692_NOT_GUI_ACCEPTANCE', files=692,
                source=result['source'], ref=result['ref'], actual=None,
                native_acceptance=False, GUI='NOT_RUN', M2='NOT_RUN', performance='NOT_RUN', clocks='ALL_HELD')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--context', choices=('known', 'null'), required=True)
    args = parser.parse_args()
    print(json.dumps(emit(args.source, args.output, args.context), sort_keys=True))
