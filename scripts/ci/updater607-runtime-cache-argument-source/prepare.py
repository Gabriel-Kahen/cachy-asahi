# SPDX-License-Identifier: MIT
"""Reproduce the runtime-only incoming-cache argument correction from exact360."""
import argparse,hashlib,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 200458, 'sha256': '6e7434b2016d4bef6259e991c332373e1965c224509f586d7308566e9fbfa45f'}

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
    need(path == path.resolve(), 'canonical resolved path required')
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

def apply(raw,rows,reverse=False):
    for a,b in(reversed(rows)if reverse else rows):
        old,new=(b.encode(),a.encode())if reverse else(a.encode(),b.encode())
        need(old and raw.count(old)==1,'one exact readable source seam')
        raw=raw.replace(old,new,1)
    return raw


def compose(source):
    source = ordinary(source)
    own = read_state(HERE / 'prepare.py')
    raw, state = read_state(HERE / 'profile.json')
    need(pin(raw) == PROFILE, 'entry-pinned profile')
    p = json.loads(raw)
    need(p['counts'] == dict(before=360,after=360,held=355,changed=5,added=0)
         and all(p[k] is None for k in ('actual_source','actual_ref','actual_run','Root_acceptance'))
         and p['acceptance_authority'] is False, 'fixed source-only scope')
    before, bstate = scan(source)
    need({n:pin(b) for n,b in before.items()} == p['parent']['files'], 'whole exact360 parent')
    operands, states = {}, {'prepare.py':own,'profile.json':(raw,state)}
    for name,wanted in p['operands'].items():
        body, identity = read_state(HERE / name)
        need(pin(body) == wanted, 'fixed readable operand '+name)
        operands[name] = body
        states[name] = body,identity
    c = json.loads(operands['binding-context.json'])
    need(c['source'] == p['parent']['source'] and c['ref'] == p['parent']['ref']
         and c['acceptance'] is False and all(c[k] is None for k in
         ('actual_source','actual_ref','actual_run')), 'exact source-only parent context')
    c['files'] = p['parent']['files']
    edits = json.loads(operands['edits.json'])
    need(set(edits) == {'implementation/runtime.py','implementation/namespace_context.py','test_source.py'},
         'only declared runtime/guard/control text operands')
    c['before_bodies'] = {n:before[n].decode() for n in edits}
    values = dict(before)
    for name,rows in edits.items():
        values[name] = apply(before[name],rows)
        need(apply(values[name],rows,reverse=True) == before[name], 'whole counted body inverse '+name)
    parentname = 'implementation/parent355.json'
    parent = json.loads(before[parentname])
    need('argument_binding' not in parent['dependency_cache_context'], 'fresh finite binding context')
    parent['dependency_cache_context']['argument_binding'] = c
    values[parentname] = encoded(parent)
    manifest = json.loads(before['source-manifest.json'])
    manifest['files'] = {n:pin(b) for n,b in values.items() if n != 'source-manifest.json'}
    values['source-manifest.json'] = encoded(manifest)
    need({n:pin(b) for n,b in values.items()} == p['result']['files'], 'all exact published360 bytes')
    need({n for n in before if values[n] != before[n]} == set(p['changed'])
         and all(values[n] == before[n] for n in p['held']), 'only five changed/355 held')
    need(scan(source) == (before,bstate) and all(read_state(HERE/n) == v for n,v in states.items()),
         'late whole source and operand identities')
    return values,p,(before,bstate),states

def emit(source,output,context):
 need(context in('known','null'),'known/NULL receipt only');source,output=paths(source,output);values,p,before,states=compose(source);paths(source,output)
 need(scan(source)==before and all(read_state(HERE/n)==v for n,v in states.items()),'late inputs before writes');output.mkdir(mode=0o700)
 for n,b in sorted(values.items()):
  q=output/n;q.parent.mkdir(parents=True,exist_ok=True);fd=os.open(q,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb')as f:f.write(b);os.fchmod(f.fileno(),0o644)
 need(tree(output)==values and all(stat.S_IMODE((output/n).stat().st_mode)==0o644 for n in values),'exact production360 bytes/modes')
 return dict(status='SOURCE_ONLY_RUNTIME_CACHE_ARGUMENT_NOT_ACCEPTANCE',context=context,files=p['result']['files'],source=p['result']['source']if context=='known'else None,ref=p['result']['ref']if context=='known'else None,actual_source=None,actual_ref=None,actual_run=None,Root_acceptance=None,hardware='NOT_RUN',performance='NOT_MEASURED')

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','output','context'):
        parser.add_argument('--'+name,required=True)
    args=parser.parse_args()
    print(json.dumps(emit(args.source,args.output,args.context),sort_keys=True,indent=2))
