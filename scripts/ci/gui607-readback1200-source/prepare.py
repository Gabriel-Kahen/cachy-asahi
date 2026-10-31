# SPDX-License-Identifier: MIT
"""Portable exact public692→selected-readback692; supplied source is DATA."""
import argparse
import hashlib
import json
import os
import stat
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROFILE = {'bytes': 396663, 'sha256': '07663ab375402e4ccd75009f0a1a5e48291de92b7dd79e32214ae167819814c0'}


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


def apply(raw, rows, reverse=False):
    for row in reversed(rows) if reverse else rows:
        old,new=row['before'].encode(),row['after'].encode()
        if reverse:old,new=new,old
        need(old and raw.count(old)==row['count'], 'one finite counted readback seam')
        raw=raw.replace(old,new)
    return raw


def compose(source):
    import base64
    entry=read_state(HERE/'prepare.py')
    profile_raw,profile_state=read_state(HERE/'profile.json')
    need(pin(profile_raw)==PROFILE, 'entry-point-pinned qualified readback profile')
    p=json.loads(profile_raw)
    need(p['counts']==dict(parent=692,result=692,held=683,changed=9,added=0) and
         p['actual'] is None and p['native_acceptance'] is False and
         p['policy']==dict(bytes=33924,sha256='dc73b1aea955d67d96b4b7c6d3ed463852c884ffc46e70341a2c41ded9dcbf26') and
         p['selected_profile']['kind']=='GUI_TCG_INSTALLED607_READBACK1200_V1' and
         tuple(p['selected_profile'][n] for n in
               ('observer_seconds','caller_seconds','default_observer_seconds','default_caller_seconds','capture_seconds','service_seconds'))==(1200,1210,600,600,600,1800),
         'exact current qualified policy, selected role and held defaults/clocks')
    before,identity_before=scan(source)
    need(p['parent']['source']=='0e7211b326679319b4454bfe2a1c1e8e9b0aac29' and
         p['parent']['ref']=='codex/latest607-gui-build-inventory-v1' and
         {n:pin(b) for n,b in before.items()}==p['parent']['files'], 'whole public692 input')
    states={n:read_state(HERE/n) for n in p['operands']}
    need({n:pin(row[0]) for n,row in states.items()}==p['operands'], 'exact readable qualified operands')
    operands={n:row[0] for n,row in states.items()}
    need(pin(operands['runner-context-policy.json.in'])==p['policy'],
         'qualified policy only; stale staging policy refused')
    seams={}
    for name,rows in p['edits'].items():
        seams[name]=[]
        for row in rows:
            if 'after_operand' in row:
                need(set(row)=={'before','after_operand','count'} and
                     row['after_operand']=='test-readback-method.py.in', 'closed readable test footer')
                row=dict(before=row['before'],after=operands[row['after_operand']].decode()+'\n'+row['before'],count=row['count'])
            seams[name].append(row)
    values={n:before[n] for n in p['parent']['files']}
    for n,rows in seams.items():values[n]=apply(values[n],rows)
    values['implementation/runner-context-policy.json']=operands['runner-context-policy.json.in']
    ledger=json.loads(before['implementation/body-inverses.json'])
    for row in ledger:
        if row['after_path'] in seams:row['seams'].extend(seams[row['after_path']])
    values['implementation/body-inverses.json']=encoded(ledger)
    descriptor=dict(schema=1,profile=p['selected_profile'],source=p['parent']['source'],
        ref=p['parent']['ref'],actual=None,files=p['parent']['files'],
        before={n:base64.b64encode(before[n]).decode() for n in sorted(p['changed'])},seams=seams)
    parent=json.loads(before['implementation/build-inventory-parent.json'])
    parent['selected_readback']=descriptor
    values['implementation/build-inventory-parent.json']=encoded(parent)
    guard=operands['build_inventory_guard.py.in']
    need(guard.count(b'PARENT_PINS=None')==guard.count(b'PRODUCTS=None')==1 and
         guard.count(b"\nSELF_SHA='@SELF@'\ndef verify")==1, 'three existing guard seal operands')
    guard=guard.replace(b'PARENT_PINS=None',('PARENT_PINS='+repr(p['parent_pins'])).encode())
    guard=guard.replace(b'PRODUCTS=None',('PRODUCTS='+repr({n:pin(b) for n,b in values.items()
        if n not in ('implementation/build_inventory_guard.py','source-manifest.json')})).encode())
    guard=guard.replace(b"SELF_SHA='@SELF@'",('SELF_SHA='+repr(pin(guard)['sha256'])).encode(),1)
    values['implementation/build_inventory_guard.py']=guard
    manifest=json.loads(before['source-manifest.json'])
    manifest['files']={n:pin(b) for n,b in values.items() if n!='source-manifest.json'}
    values['source-manifest.json']=encoded(manifest)
    need({n:pin(b) for n,b in values.items()}==p['result']['files'] and
         p['result']['source']=='7c7ee9dc3c8c4289d21c3070d7d159add649a233' and
         p['result']['ref']=='codex/latest607-gui-readback1200-v1',
         'literal current qualified public692 output before writes')
    restored=dict(values)
    for n,rows in seams.items():restored[n]=apply(restored[n],rows,reverse=True)
    for n in p['changed']:
        if n not in seams:restored[n]=before[n]
    need(restored==before and set(values)==set(before) and
         {n for n in before if values[n]!=before[n]}==set(p['changed']) and
         all(values[n]==before[n] for n in p['held']), 'whole692 inverse and683 held bodies')
    states.update({'profile.json':(profile_raw,profile_state),'prepare.py':entry})
    need(scan(source)==(before,identity_before) and
         all(read_state(HERE/n)==row for n,row in states.items()), 'late whole input/operand identity drift')
    return values,p,(before,identity_before),states


def emit(source, output, context):
    need(context in ('known','null'), 'known/NULL receipt only')
    source,output=paths(source,output)
    values,p,before,states=compose(source)
    paths(source,output)
    need(scan(source)==before and all(read_state(HERE/n)==row for n,row in states.items()),
         'late complete inputs before any write')
    output.mkdir(mode=0o700)
    for name,raw in sorted(values.items()):
        path=output/name
        path.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw)
            os.fchmod(stream.fileno(),0o644)
    need(tree(output)==values and all(stat.S_IMODE((output/n).stat().st_mode)==0o644 for n in values),
         'all literal production692 bytes and qualified0644 modes')
    return dict(status='SOURCE_ONLY_EXACT_GUI692_SELECTED_READBACK1200_NOT_ACCEPTANCE',
        context=context,files={n:pin(b) for n,b in values.items()},held=683,changed=9,
        source=p['result']['source'] if context=='known' else None,
        ref=p['result']['ref'] if context=='known' else None,
        actual_source=None,actual_ref=None,actual_run=None,Root_acceptance=None,
        GUI='NOT_RUN',hardware='NOT_RUN',performance='NOT_RUN',fit='NOT_ESTABLISHED')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--context',choices=('known','null'),required=True)
    args=parser.parse_args()
    print(json.dumps(emit(args.source,args.output,args.context),sort_keys=True,indent=2))


