# SPDX-License-Identifier: MIT
"""Portable exact owned-VM inspect1800 source245 from pinned public652 input."""
import argparse,base64,hashlib,json,os,stat,zlib
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE_SHA='eaf3825305d5249f76e190038e50b1ef49edf0c9a55bd0ff7d668670e0e0ec62'
def need(ok, message):
    if not ok:
        raise ValueError(message)


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def canonical(value):
    raw = os.fspath(value)
    need(type(raw) is str and os.path.isabs(raw) and raw == os.path.normpath(raw) and not raw.startswith('//'),
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


A='scripts/ci/apps7-full574-repair16k/adapter.py'
V='scripts/ci/apps7-full574-repair16k/vm.py'
H='apps16-repair/inspect_validation.py'
G='apps16-repair/relative_source.py'
Q='apps16-repair/relative-profile.json'
SUCCESSOR='apps16-repair/successor.json'
MANIFESTS=('scripts/ci/apps7-full574-repair-native/source-manifest.json',
           'scripts/ci/apps7-full574-repair16k/source-manifest.json',
           'scripts/ci/apps7-full574-repair16k-ci/source-manifest.json')
WORKFLOWS=('.github/workflows/native-arm-build.yml',
           '.github/workflows/native-arm-apps7-full574-repair16k.yml')


def one(raw, before, after):
    need(raw.count(before) == 1, 'one exact counted source operand')
    result = raw.replace(before, after, 1)
    need(result.count(after) == 1 and result.replace(after, before, 1) == raw,
         'whole counted source inverse')
    return result


def transform(before, p, operands):
    values = dict(before)
    edits = json.loads(operands['file-edits.json'])
    guard_edits = json.loads(operands['guard-edits.json'])
    for name, changes in edits.items():
        for old, new in changes:
            values[name] = one(values[name], old.encode(), new.encode())
    values[A] += operands['adapter-append.py.txt']
    profile = json.loads(before[Q])
    need(V not in profile['before_bodies_zlib'] and
         pin(before[V]) == profile['before'][V], 'held original VM before operand')
    # Compression representation differs across zlib implementations. Preserve
    # the published metadata and join its complete decoded body to this input.
    vm_before = operands['vm-before-body.zlib.base64.txt'].decode('ascii').removesuffix('\n')
    packed = base64.b64decode(vm_before, validate=True)
    need(base64.b64encode(packed).decode() == vm_before, 'canonical before VM metadata')
    decoder = zlib.decompressobj()
    decoded = decoder.decompress(packed, len(before[V]) + 1)
    need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and
         decoded == before[V], 'complete published compressed metadata equals parent VM')
    profile['before_bodies_zlib'][V] = vm_before
    guard = before[G]
    for old, new in guard_edits:
        guard = one(guard, old.encode(), new.encode())
    guard += operands['guard-append.py.txt']
    profile['inspect_capacity'] = dict(
        p['capacity'], before=p['parent']['files'],
        git=dict(p['parent']['git_header'], files=p['parent']['files']),
        before_guard_template=profile['guard_template'], file_edits=edits,
        guard_edits=guard_edits, adapter_append=operands['adapter-append.py.txt'].decode(),
        guard_append=operands['guard-append.py.txt'].decode())
    old_seal = pin(before[Q])['sha256'].encode()
    need(guard.count(old_seal) == 1, 'one original guard seal')
    profile['guard_template'] = pin(guard.replace(old_seal, b'PROFILE_SHA_PLACEHOLDER', 1))
    values[Q] = encoded(profile)
    need(len(values[Q]) < 8 * 1024**2, 'held 8MiB source profile cap')
    values[G] = one(guard, old_seal, pin(values[Q])['sha256'].encode())
    successor = json.loads(before[SUCCESSOR])
    successor['after'] = {n: pin(b) for n, b in sorted(values.items())
                          if n not in successor['excluded_seals']}
    values[SUCCESSOR] = encoded(successor)
    for name in MANIFESTS:
        manifest = json.loads(before[name])
        manifest['files'] = {n: pin(values[n]) for n in sorted(manifest['files'])}
        values[name] = encoded(manifest)
    for name in WORKFLOWS:
        values[name] = one(before[name], pin(before[MANIFESTS[-1]])['sha256'].encode(),
                           pin(values[MANIFESTS[-1]])['sha256'].encode())
    return values


def inverse(values, p):
    capacity = json.loads(values[Q])['inspect_capacity']
    before = p['parent']['files']
    profile = json.loads(values[Q])
    profile.pop('inspect_capacity')
    profile['guard_template'] = capacity['before_guard_template']
    for name in capacity['added_before_bodies']:
        profile['before_bodies_zlib'].pop(name)
    restored = {}
    for name, expected in before.items():
        raw = values[name]
        if name in capacity['file_edits']:
            if name == A:
                tail = capacity['adapter_append'].encode()
                need(tail and raw.endswith(tail), 'whole adapter footer inverse')
                raw = raw[:-len(tail)]
            for old, new in reversed(capacity['file_edits'][name]):
                raw = one(raw, new.encode(), old.encode())
        elif name == Q:
            raw = encoded(profile)
        elif name == G:
            raw = one(raw, pin(values[Q])['sha256'].encode(), before[Q]['sha256'].encode())
            tail = capacity['guard_append'].encode()
            need(tail and raw.endswith(tail), 'whole guard footer inverse')
            raw = raw[:-len(tail)]
            for old, new in reversed(capacity['guard_edits']):
                raw = one(raw, new.encode(), old.encode())
        elif name == SUCCESSOR:
            document = json.loads(raw)
            document['after'] = {n: before[n] for n in document['after']}
            raw = encoded(document)
        elif name in MANIFESTS:
            document = json.loads(raw)
            document['files'] = {n: before[n] for n in document['files']}
            raw = encoded(document)
        elif name in WORKFLOWS:
            raw = one(raw, pin(values[MANIFESTS[-1]])['sha256'].encode(),
                      before[MANIFESTS[-1]]['sha256'].encode())
        need(pin(raw) == expected, 'whole genuine652 source inverse: ' + name)
        restored[name] = raw
    return restored


def compose(source):
    source = canonical(source)
    profile_raw, profile_state = read_state(HERE / 'profile.json')
    need(pin(profile_raw)['sha256'] == PROFILE_SHA, 'fixed portable source profile')
    p = json.loads(profile_raw)
    operands, states = {}, {}
    for name, expected in p['operands'].items():
        raw, state = read_state(HERE / name)
        need(pin(raw) == expected, 'readable counted source operand: ' + name)
        operands[name], states[name] = raw, (raw, state)
    before, state = scan(source)
    need({n: pin(b) for n, b in before.items()} == p['parent']['files'],
         'entire exact exported public652 input')
    values = transform(before, p, operands)
    need({n: pin(b) for n, b in values.items()} == p['result']['files'],
         'entire exact inspect1800 public245 output')
    need(inverse(values, p) == before and set(values) == set(before) and
         {n for n in before if values[n] != before[n]} == set(p['changed']) and
         all(values[n] == before[n] for n in p['held']),
         'complete245 inverse, ten changed and235 held')
    for name, raw in values.items():
        if name.endswith('.py'):
            compile(raw, name, 'exec')
    need(scan(source) == (before, state) and
         read_state(HERE / 'profile.json') == (profile_raw, profile_state) and
         all(read_state(HERE / name) == record for name, record in states.items()),
         'late byte/inode/namespace/profile/operand drift before writes')
    return values, p

def destinations(source,output,receipt):
    source,output=map(canonical,(source,output));receipt=canonical(receipt)if receipt is not None else None
    for value in(output,receipt):
        if value is None:continue
        need(value.parent.is_dir()and not os.path.lexists(value),'fresh output/receipt with existing parent')
        need(not any('native-actual'in x.name for x in(value,*value.parents)),'actual namespace protected')
        for root in(source,HERE):need(not value.is_relative_to(root)and not root.is_relative_to(value),'disjoint input/factory/output/receipt')
    if receipt is not None:need(not output.is_relative_to(receipt)and not receipt.is_relative_to(output),'disjoint output and receipt')
    return source,output,receipt

def emit(source,output,context,receipt=None):
    need(context in('known','null'),'explicit source-only known/NULL context')
    source,output,receipt=destinations(source,output,receipt);values,p=compose(source);destinations(source,output,receipt)
    output.mkdir(mode=0o700)
    for n,b in values.items():
        path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
        with os.fdopen(fd,'wb')as stream:stream.write(b);os.fchmod(stream.fileno(),0o644)
    need(scan(output)[0]==values,'entire emitted245 bytes')
    row=dict(status='SOURCE_ONLY_EXACT_INSPECT1800_PUBLIC245_NOT_NATIVE_ACCEPTANCE',source=p['result']['source']if context=='known'else None,ref=p['result']['ref']if context=='known'else None,files=245,actual=None,Root_acceptance=None,native='NOT_RUN',deadline_fit='NOT_ESTABLISHED',old600_fit='NOT_ESTABLISHED',old1200_fit='NOT_ESTABLISHED',new1800_fit='NOT_ESTABLISHED',outer_capacity='UNCHANGED_18000_MAXIMUM',M2='NOT_RUN')
    if receipt is not None:
        with receipt.open('xb')as stream:stream.write(encoded(dict(row,file_map=p['result']['files'])))
    return row

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for n in('source','output'):parser.add_argument('--'+n,required=True)
    parser.add_argument('--context',choices=('known','null'),required=True);parser.add_argument('--receipt');args=parser.parse_args()
    print(json.dumps(emit(args.source,args.output,args.context,args.receipt),sort_keys=True))
