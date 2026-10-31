# SPDX-License-Identifier: MIT
"""Reproduce the exact early adapter binding from its pinned current607 parent."""
import argparse,hashlib,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 714504, 'sha256': '68c3e5223150e26ce3bed82e35e6771935cd7d83d5cac471d66545749ab71a84'}

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
             0 <= before.st_size <= (16 if path.name == "page-parent.json" else 8) * 1024**2, 'bounded ordinary single-link source file')
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
    need(p['counts'] == dict(before=1203, after=1203, held=1197, changed=6, added=0)
         and all(p[k] is None for k in ('actual_source','actual_ref','actual_run','Root_acceptance'))
         and p['acceptance_authority'] is False, 'source-only fixed scope')
    before, bstate = scan(source)
    need({n: pin(b) for n, b in before.items()} == p['parent']['files'], 'whole parent1203')
    craw, cstate = read_state(HERE / 'binding-context.json')
    need(pin(craw) == p['operands']['binding-context.json'], 'fixed readable binding context')
    c = json.loads(craw)
    c['files'] = p['parent']['files']
    c['git']['files'] = p['parent']['files']
    mode, guardname, parentname = ('implementation/page_mode.py',
                                 'implementation/page_source.py', 'implementation/page-parent.json')
    parent = json.loads(before[parentname])
    oldsha = pin(before[parentname])['sha256']
    guard = before[guardname]
    need(guard.count(oldsha.encode()) == 1, 'one original guard seal')
    template = apply(guard.replace(oldsha.encode(), b'@PARENT_SHA@', 1), c['guard_edits'])
    newmode = apply(before[mode], c['mode_edits'])
    need(c['guard_template'] == parent['guard_template']
         and c['product_before'] == parent['products'][mode], 'whole original guard/product operands')
    for path, names in c['added_before_bodies'].items():
        target = parent
        for key in path.split('.'):
            target = target[key]
        for name in names:
            need(name not in target, 'only missing declared before body')
            target[name] = before[name].decode()
    parent['page_adapter_binding_parent'] = c
    parent['products'][mode] = pin(newmode)
    parent['guard_template'] = pin(template)
    praw = encoded(parent)
    need(len(praw) < 16 * 1024**2 and template.count(b'@PARENT_SHA@') == 1, 'fixed parent cap/seal')
    values = dict(before)
    values.update({mode: newmode, parentname: praw,
                   guardname: template.replace(b'@PARENT_SHA@', pin(praw)['sha256'].encode(), 1)})
    aliases = ('.github/workflows/native-arm-build.yml',
               '.github/workflows/native-arm-latest607-fresh-installer.yml')
    manifest = json.loads(before['source-manifest.json'])
    manifest['files'] = {n: pin(b) for n,b in values.items() if n not in ('source-manifest.json', *aliases)}
    values['source-manifest.json'] = encoded(manifest)
    workflow = before['implementation/workflow-template.yml']
    need(workflow.count(b'@FRESH607_MANIFEST@') == 1, 'one workflow manifest seal')
    for name in aliases:
        values[name] = workflow.replace(b'@FRESH607_MANIFEST@', pin(values['source-manifest.json'])['sha256'].encode(), 1)
    need({n: pin(b) for n,b in values.items()} == p['result']['files'], 'all exact published1203 bytes')
    need({n for n in before if before[n] != values[n]} == set(p['changed'])
         and all(values[n] == before[n] for n in p['held']), 'six changes/all1197 held')
    need(apply(newmode, c['mode_edits'], reverse=True) == before[mode]
         and apply(template, c['guard_edits'], reverse=True).replace(b'@PARENT_SHA@', oldsha.encode(), 1)
         == before[guardname], 'whole helper/guard inverse')
    states = {'prepare.py': own, 'profile.json': (raw,state), 'binding-context.json': (craw,cstate)}
    need(scan(source) == (before,bstate) and all(read_state(HERE/n) == v for n,v in states.items()),
         'late whole input/operand identities')
    return values,p,(before,bstate),states

def emit(source,output,context):
 need(context in('known','null'),'known/NULL receipt only');source,output=paths(source,output);values,p,before,states=compose(source);paths(source,output)
 need(scan(source)==before and all(read_state(HERE/n)==v for n,v in states.items()),'late inputs before writes');output.mkdir(mode=0o700)
 for n,b in sorted(values.items()):
  q=output/n;q.parent.mkdir(parents=True,exist_ok=True);fd=os.open(q,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb')as f:f.write(b);os.fchmod(f.fileno(),0o644)
 need(tree(output)==values and all(stat.S_IMODE((output/n).stat().st_mode)==0o644 for n in values),'exact production1203 bytes/modes')
 return dict(status='SOURCE_ONLY_EARLY_ADAPTER_BINDING_NOT_ACCEPTANCE',context=context,files=p['result']['files'],source=p['result']['source']if context=='known'else None,ref=p['result']['ref']if context=='known'else None,actual_source=None,actual_ref=None,actual_run=None,Root_acceptance=None,hardware='NOT_RUN',performance='NOT_MEASURED')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source','output','context'):
        parser.add_argument('--'+name, required=True)
    args = parser.parse_args()
    print(json.dumps(emit(args.source,args.output,args.context), sort_keys=True, indent=2))
