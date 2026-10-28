# SPDX-License-Identifier: MIT
"""Portable public1197→1203 generic16K source factory; default4K and authority held."""
import argparse
import ast
import hashlib
import json
import os
import stat
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROFILE = {
  'bytes': 5115,
  'sha256': '445bbd8c30843b6bd3d6f7a109efea96ff33ec30e927ffc4ecab9ed6f19ebc23'
}


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
    need(path == path.resolve(), 'canonical resolved path required')
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


def pure_helper(raw):
    """Compile only sealed readable DATA transforms, never supplied parent code."""
    parsed = ast.parse(raw)
    wanted = {'one','with_mode','run_body','transformed'}
    scope = dict(C=types.SimpleNamespace(need=need,pin=pin,enc=encoded),json=json)
    for node in parsed.body:
        if isinstance(node,ast.Assign) and len(node.targets)==1 and isinstance(node.targets[0],ast.Name) and node.targets[0].id in ('ALIASES','DOC','STEP'):
            scope[node.targets[0].id] = ast.literal_eval(node.value)
    nodes = [node for node in parsed.body if isinstance(node,ast.FunctionDef) and node.name in wanted]
    need({node.name for node in nodes}==wanted and len(nodes)==4 and
         all(n in scope for n in ('ALIASES','DOC','STEP')), 'four closed pure transforms')
    exec(compile(ast.Module(body=nodes,type_ignores=[]),'<sealed-pure-source-transform>','exec'),scope)
    return types.SimpleNamespace(**scope)


def family(before, inputs):
    old = pure_helper(inputs['page_source.before.py.in'])
    current = pure_helper(inputs['page_source.py.in'])
    before_rows = {n:pin(b) for n,b in before.items()}
    products = {'implementation/'+n:inputs[n+'.in'] for n in
        ('page_mode.py','kernel20_input.py','page-mode-profile.json','test_page_mode.py')}
    changed = ('README.md','implementation/run.py','implementation/source_guard.py',
        'implementation/test_source.py','implementation/workflow-template.yml',
        'source-manifest.json',*old.ALIASES)
    history = json.loads(inputs['history.json.in'])
    need(history['actual'] is None and history['acceptance']=='NOT_TRANSFERRED' and
         history['original1203']=='UNPUBLISHED_SOURCE_DATA_ONLY' and
         pin(inputs['page_source.before.py.in'])==history['original_template'],
         'original1203 source history, never publication/native authority')
    parent = dict(files=before_rows,source='b9976eea34eaed4b6e56af3be21d4d652fa971d6',
        ref='codex/latest607-fresh-tooling-inputs-v1',
        before_bodies={n:before[n].decode() for n in changed},
        products={n:pin(b) for n,b in products.items()},
        guard_template=pin(inputs['page_source.before.py.in']))
    parent_raw = encoded(parent)
    need(pin(parent_raw)==history['original_page_parent'], 'exact original1197 parent context')
    template = inputs['page_source.before.py.in']
    need(template.count(b'@PARENT_SHA@')==1, 'one old selfseal declaration')
    original = old.transformed(before,products,parent_raw,
        template.replace(b'@PARENT_SHA@',pin(parent_raw)['sha256'].encode()))
    old_rows = {n:pin(b) for n,b in original.items()}
    need(len(original)==1203 and pin(encoded(old_rows))==history['original1203_map'],
         'whole original1203 finite inverse, no historical tree payload')
    scope_changed = ('implementation/page_source.py','implementation/page-parent.json',
        'implementation/workflow-template.yml','source-manifest.json',*current.ALIASES)
    parent.update(guard_template=pin(inputs['page_source.py.in']),
        scope_parent=dict(files=old_rows,before_bodies={n:original[n].decode() for n in scope_changed},
            qualification=history['qualification'],actual=None,acceptance='NOT_TRANSFERRED'))
    parent_raw = encoded(parent)
    template = inputs['page_source.py.in']
    need(template.count(b'@PARENT_SHA@')==1, 'one current selfseal declaration')
    out = current.transformed(before,products,parent_raw,
        template.replace(b'@PARENT_SHA@',pin(parent_raw)['sha256'].encode()))
    restored = json.loads(out['implementation/page-parent.json'])
    need(restored['files']==before_rows and restored['scope_parent']['files']==old_rows and
         {n:pin(restored['before_bodies'][n].encode() if n in restored['before_bodies'] else out[n])
          for n in before}==before_rows, 'complete1197/current1203 byte inverse')
    return out


def render(parent):
    profile_raw, profile_state = read_state(HERE/'profile.json')
    need(pin(profile_raw)==PROFILE, 'entry-point-pinned1203 factory profile')
    profile = json.loads(profile_raw)
    need((profile['parent'],profile['result'],profile['held'])==(1197,1203,1189) and
         len(profile['changed'])==8 and len(profile['added'])==6 and
         all(profile[k] is None for k in ('actual_source','actual_ref','actual_run','Root_acceptance')),
         'closed1197→1203 source-only profile')
    entry = read_state(HERE/'prepare.py')
    operands = {n:read_state(HERE/n) for n in profile['files']}
    need({n:pin(row[0]) for n,row in operands.items()}==profile['files'],
         'nine readable exact source-map/transform operands')
    inputs = {n:row[0] for n,row in operands.items()}
    expected = json.loads(inputs['input-source.json'])
    before, identities = scan(parent)
    need(expected['source']=='b9976eea34eaed4b6e56af3be21d4d652fa971d6' and
         expected['ref']=='codex/latest607-fresh-tooling-inputs-v1' and expected['actual'] is None and
         len(before)==1197 and {n:pin(b) for n,b in before.items()}==expected['files'],
         'whole ordinary exact public1197 source required')
    out = family(before,inputs)
    wanted = json.loads(inputs['output-source.json'])
    need(wanted['source']=='3160eaa23a25275a9a341874b528b60b69e4f8cb' and
         wanted['ref']=='codex/latest607-fresh-generic16k-scope-v1' and wanted['actual'] is None and
         len(out)==1203 and {n:pin(b) for n,b in out.items()}==wanted['files'],
         'whole exact corrected public1203 source')
    need(set(out)-set(before)==set(profile['added']) and
         {n for n in before if out[n]!=before[n]}==set(profile['changed']) and
         sum(out[n]==before[n] for n in before)==1189, 'exact1189held/eightchanged/sixadded')
    states = dict(operands,**{'profile.json':(profile_raw,profile_state),'prepare.py':entry})
    need(scan(parent)==(before,identities) and
         all(read_state(HERE/n)==row for n,row in states.items()), 'late whole source/operand drift')
    return out,(before,identities),states


def build(parent, output, context='known'):
    need(context in ('known','null'), 'known/NULL source-only receipt context')
    parent,output = paths(parent,output)
    values,before,states = render(parent)
    paths(parent,output)
    need(scan(parent)==before and all(read_state(HERE/n)==row for n,row in states.items()),
         'late complete parent/operands before any output write')
    output.mkdir(mode=0o700)
    for name,raw in sorted(values.items()):
        p=output/name
        p.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(raw)
    need(tree(output)==values, 'complete1203 output unchanged')
    return dict(status='REPRODUCED_SOURCE_ONLY1203_OPTIONAL_GENERIC16K_DEFAULT4K_HELD',
        context=context,files={n:pin(b) for n,b in values.items()},
        source='3160eaa23a25275a9a341874b528b60b69e4f8cb' if context=='known' else None,
        ref='codex/latest607-fresh-generic16k-scope-v1' if context=='known' else None,
        actual_source=None,actual_ref=None,actual_run=None,Root_acceptance=None,
        generic16k='NOT_RUN',generic16k_fit='NOT_ESTABLISHED',hardware='NOT_RUN',performance='NOT_MEASURED')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent',required=True)
    parser.add_argument('--output',required=True)
    parser.add_argument('--context',choices=('known','null'),default='known')
    args=parser.parse_args()
    print(json.dumps(build(args.parent,args.output,args.context),sort_keys=True,indent=2))


