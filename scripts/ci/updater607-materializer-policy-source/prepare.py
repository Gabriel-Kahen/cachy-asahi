# SPDX-License-Identifier: MIT
"""Reproduce public360 descriptor, private cleanup and selected607 database correction."""
import argparse,hashlib,importlib.util,json,os,stat,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 302588, 'sha256': '3ba41e1409f9bc9bb554a9f0f5aa2a2e36b21cbe0bb7ce086452fa7a16ddef63'}

_spec=importlib.util.spec_from_file_location('_trusted_updater_source_transform',HERE/'transformed.py')
_TRANSFORM=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_TRANSFORM)

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
    need(p['counts'] == dict(before=360,after=360,held=344,changed=16,added=0)
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
    contexts=json.loads(operands['binding-context.json']);edits=json.loads(operands['edits.json'])
    need(set(contexts)==set(edits)=={'descriptor','cleanup','database'} and p['intermediate']['kind']=='FROZEN_AUTHOR_SOURCE_DATA_NOT_PUBLISHED_AUTHORITY','closed finite source family')
    descriptor=contexts['descriptor'];cleanup=contexts['cleanup'];database=contexts['database']
    need((database['source'],database['ref'])==(p['database_parent']['source'],p['database_parent']['ref']),'exact public027a database parent context')
    need((descriptor['source'],descriptor['ref'])==(p['parent']['source'],p['parent']['ref']) and cleanup['source'] is cleanup['ref'] is None and cleanup['source_author_freeze']==p['intermediate']['author_freeze'] and cleanup['source_files_pin']==pin(encoded(p['intermediate']['files'])),'public parent versus frozen descriptor SOURCE_DATA identities')
    for role in contexts:
        c=contexts[role];need(c['acceptance'] is False and all(c[k] is None for k in('actual_source','actual_ref','actual_run')),'source-only context, never actual authority')
    need(set(edits['descriptor'])=={'implementation/adapter.py','implementation/namespace_context.py','test_source.py'} and set(edits['cleanup'])=={'implementation/runtime.py','implementation/namespace_context.py','test_source.py'},'only named readable source operands')
    need(set(edits['database'])=={'implementation/adapter.py','implementation/namespace_context.py','test_source.py'},'only three readable database operands')
    api=types.SimpleNamespace(need=need,pin=pin,encoded=encoded,apply=apply)
    intermediate=_TRANSFORM.descriptor(before,p,descriptor,edits,api)
    database_before=_TRANSFORM.cleanup(intermediate,p,cleanup,edits,api)
    need({n:pin(b)for n,b in database_before.items()}==p['database_parent']['files'],'entire exact public027a before database correction')
    values=_TRANSFORM.database(database_before,p,database,edits,api)
    restored=_TRANSFORM.database_inverse(values,database_before,p,database,edits,api)
    need(_TRANSFORM.inverse(restored,before,intermediate,p,contexts,edits,api)==before,'complete360 parent inverse')
    need({n:pin(b) for n,b in values.items()} == p['result']['files'], 'all exact published360 bytes')
    need({n for n in before if values[n] != before[n]} == set(p['changed'])
         and all(values[n] == before[n] for n in p['held']), 'only sixteen changed/344 held')
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
 return dict(status='SOURCE_ONLY_DESCRIPTOR_CLEANUP_SELECTED_DATABASE_NOT_ACCEPTANCE',context=context,files=p['result']['files'],source=p['result']['source']if context=='known'else None,ref=p['result']['ref']if context=='known'else None,actual_source=None,actual_ref=None,actual_run=None,Root_acceptance=None,hardware='NOT_RUN',performance='NOT_MEASURED')

if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','output','context'):
        parser.add_argument('--'+name,required=True)
    args=parser.parse_args()
    print(json.dumps(emit(args.source,args.output,args.context),sort_keys=True,indent=2))
