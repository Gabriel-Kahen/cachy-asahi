# SPDX-License-Identifier: MIT
"""Portable exact public357→357 tooling1197 context; no installed authority."""
import argparse
import hashlib
import json
import os
import stat
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROFILE = {'bytes': 1486, 'sha256': 'ab6f28ec8d5a3f637729c4f5fbf7ca3c0846d705967650f60c072b5468baa156'}


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


def tree(root):
    return scan(root)[0]


def paths(parent, fresh, output):
    parent, fresh, output = map(canonical, (parent, fresh, output))
    need(output.parent.is_dir() and not os.path.lexists(output), 'fresh output required')
    need(not any('native-actual' in p.name for p in (output, *output.parents)),
         'no source-factory output in actual roots')
    for a,b in ((parent,fresh),(parent,HERE),(fresh,HERE)):
        need(not a.is_relative_to(b) and not b.is_relative_to(a), 'independent input/factory roots')
    for protected in (parent,fresh,HERE):
        need(not output.is_relative_to(protected) and not protected.is_relative_to(output),
             'disjoint input/factory/output roots')
    return parent,fresh,output


def one(raw, before, after):
    before,after = before.encode(),after.encode()
    need(raw.count(before) == 1, 'one exact source-context text seam')
    return raw.replace(before,after,1)


def render(parent, fresh):
    profile_raw,profile_state = read_state(HERE/'profile.json')
    need(pin(profile_raw) == PROFILE, 'entry-point-pinned context profile')
    p = json.loads(profile_raw)
    need((p['parent'],p['result'],p['held'],p['added']) == (357,357,351,[]) and
         len(p['changed']) == 6 and all(p[k] is None for k in
         ('actual_source','actual_ref','actual_run','Root_acceptance')), 'source-only same357 profile')
    states = {n:read_state(HERE/n) for n in p['files']}
    need({n:pin(v[0]) for n,v in states.items()} == p['files'], 'every readable operand pinned')
    values = {n:v[0] for n,v in states.items()}
    maps = {k:json.loads(values[k+'-source.json']) for k in ('before','after','fresh')}
    need(all(maps[k]['source'] == p['sources'][k] and maps[k]['actual'] is None for k in maps),
         'all three exact public source identities')
    before,before_state = scan(parent)
    incoming,incoming_state = scan(fresh)
    need(len(before) == 357 and {n:pin(b) for n,b in before.items()} == maps['before']['files'],
         'whole original public357 input')
    need(len(incoming) == 1197 and {n:pin(b) for n,b in incoming.items()} == maps['fresh']['files'],
         'whole exact public1197 source input; never installed authority')
    context = json.loads(values['context.json'])
    need(context['fresh_source_files'] == maps['fresh']['files'] and
         context['fresh_source'] == p['sources']['fresh'] and
         context['fresh_ref'] == 'codex/latest607-fresh-tooling-inputs-v1' and
         context['fresh_source_authorization'] == pin(encoded(maps['fresh']['files'])),
         'closed typed public1197 source context')
    out = dict(before)
    old_parent = json.loads(before['implementation/parent355.json'])
    profile = json.loads(before['implementation/profile.json'])
    profile.update(context)
    out['implementation/profile.json'] = encoded(profile)
    r = json.loads(values['readme.json'])
    text = one(one(before['README.md'],old_parent['README_after'],r['after']),
               old_parent['README_after2'],r['after2'])
    for a,b in r['edits']:
        text = one(text,a,b)
    out['README.md'] = text
    product = dict(old_parent)
    product.update(profile_after=context,source_publication=context['fresh_source'],
                   source_ref=context['fresh_ref'],README_after=r['after'],README_after2=r['after2'])
    product['before357'] = dict(files=maps['before']['files'],pin=pin(encoded(maps['before']['files'])),
        namespace_body=before['implementation/namespace_context.py'].decode(),
        parent_context={k:old_parent[k] for k in
            ('profile_after','source_publication','source_ref','README_after','README_after2')},
        readme_before=before['README.md'].decode(),readme_after=text.decode())
    out['implementation/parent355.json'] = encoded(product)
    out['implementation/namespace_context.py'] = values['namespace_context.py.in']
    out['implementation/source_guard.py'] = one(before['implementation/source_guard.py'],
        'whole corrected1178 fixed-target installer source','whole corrected1197 fixed-target installer source')
    manifest = json.loads(before['source-manifest.json'])
    manifest['files'] = {n:pin(b) for n,b in sorted(out.items()) if n != 'source-manifest.json'}
    out['source-manifest.json'] = encoded(manifest)
    need(len(out) == 357 and set(out) == set(before) and
         {n for n in before if out[n] != before[n]} == set(p['changed']) and
         {n:pin(b) for n,b in out.items()} == maps['after']['files'],
         'whole exact public357 output;351 held/six changed/no additions')
    # Independently reconstruct every old357 byte without executing either input.
    restored = dict(out)
    restored['README.md'] = product['before357']['readme_before'].encode()
    old_profile = json.loads(out['implementation/profile.json'])
    old_profile.update(old_parent['profile_after'])
    restored['implementation/profile.json'] = encoded(old_profile)
    restored['implementation/parent355.json'] = encoded(old_parent)
    restored['implementation/namespace_context.py'] = product['before357']['namespace_body'].encode()
    restored['implementation/source_guard.py'] = one(out['implementation/source_guard.py'],
        'whole corrected1197 fixed-target installer source','whole corrected1178 fixed-target installer source')
    old_manifest = json.loads(out['source-manifest.json'])
    old_manifest['files'] = {n:w for n,w in maps['before']['files'].items() if n != 'source-manifest.json'}
    restored['source-manifest.json'] = encoded(old_manifest)
    need(restored == before, 'whole357 before-body inverse including355/208 substrate')
    states.update({'profile.json':(profile_raw,profile_state),'prepare.py':read_state(HERE/'prepare.py')})
    need(scan(parent) == (before,before_state) and scan(fresh) == (incoming,incoming_state) and
         all(read_state(HERE/n) == row for n,row in states.items()), 'late complete input/operand drift')
    return out,((before,before_state),(incoming,incoming_state)),states


def build(parent,fresh,output,context='null'):
    need(context in ('known','null'), 'known/NULL source receipt choice')
    parent,fresh,output = paths(parent,fresh,output)
    values,before,states = render(parent,fresh)
    paths(parent,fresh,output)
    need((scan(parent),scan(fresh)) == before and
         all(read_state(HERE/n) == row for n,row in states.items()), 'late inputs before first write')
    output.mkdir(mode=0o700)
    for n,raw in sorted(values.items()):
        path = output/n
        path.parent.mkdir(parents=True,exist_ok=True)
        fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(raw)
    need(tree(output) == values, 'whole final357 source output')
    return dict(status='REPRODUCED_PUBLIC357_TOOLING1197_SOURCE_ONLY_UNBOUND',
        receipt_context=context,publication_assertion=None if context=='null' else 'EXACT_PUBLIC1197_SOURCE_ONLY',
        files={n:pin(b) for n,b in values.items()},actual_source=None,actual_ref=None,
        actual_run=None,fresh607=None,baseline607=None,Root_acceptance=None,hardware='NOT_RUN')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent',required=True)
    parser.add_argument('--fresh',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--context',choices=('known','null'),default='null')
    args = parser.parse_args()
    print(json.dumps(build(args.parent,args.fresh,args.output,args.context),sort_keys=True,indent=2))
