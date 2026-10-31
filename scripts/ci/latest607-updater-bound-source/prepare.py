# SPDX-License-Identifier: MIT
"""Portable finite public357→bound357 source DATA factory; no actor execution."""
import argparse
import hashlib
import json
import os
import stat
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROFILE = {'bytes': 18898, 'sha256': '28d209ed1be8d5a2e79524cd542be896b40b203d2429bc68e5f8476e7b781ebd'}


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



def one(raw, before, after):
    a,b=before.encode(),after.encode()
    need(raw.count(a)==1, 'one exact finite code seam')
    return raw.replace(a,b,1)


def helper():
    import importlib.util
    spec=importlib.util.spec_from_file_location('_fixed_bound_data_policy',HERE/'data_policy.py')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def paths(parent,fresh,baseline,carrier,output,receipt):
    args=tuple(map(canonical,(parent,fresh,baseline,carrier,output,receipt)))
    inputs=args[:4];output,receipt=args[4:]
    for i,a in enumerate(inputs):
        for b in inputs[i+1:]+(HERE,):
            need(not a.is_relative_to(b) and not b.is_relative_to(a), 'independent explicit ordinary inputs')
    for path in(output,receipt):
        need(path.parent.is_dir()and not os.path.lexists(path),'fresh output/receipt')
        need(not any('native-actual'in p.name for p in(path,*path.parents)),'no writes to actual roots')
        for protected in(*inputs,HERE):
            need(not path.is_relative_to(protected)and not protected.is_relative_to(path),'disjoint factory/input/output')
    need(not output.is_relative_to(receipt)and not receipt.is_relative_to(output),'disjoint output and receipt')
    return args


def render(parent,fresh,baseline,carrier):
    profile_raw,state=read_state(HERE/'profile.json');need(PROFILE is not None and pin(profile_raw)==PROFILE,'genuine final bound publication required')
    spec=json.loads(profile_raw)
    operands={n:read_state(HERE/n)for n in spec['files']}
    need({n:pin(v[0])for n,v in operands.items()}==spec['files'],'every source-relative readable operand pinned')
    need(all(spec[k]is None for k in('actual_source','actual_ref','actual_run'))and
         (spec['parent'],spec['result'],spec['held'],spec['changed'],spec['added'])==(357,357,350,7,0),
         'finite same357/350held/sevenchanged/ownactualNULL')
    maps={k:json.loads(operands[k+'-source.json'][0])for k in('before','after')}
    snapshots={k:scan(root)for k,root in(('before',parent),('fresh607',fresh),('baseline607',baseline),('carrier',carrier))}
    need({n:pin(b)for n,b in snapshots['before'][0].items()}==maps['before']['files']and
         maps['before']['source']==spec['sources']['before'],'whole original public357')
    for kind in('fresh607','baseline607','carrier'):
        need({n:pin(b)for n,b in snapshots[kind][0].items()}==spec['inputs'][kind]['files'],
             'entire exact independent public DATA input')
    before=snapshots['before'][0];out=dict(before)
    edits=json.loads(operands['edits.json'][0])
    for n,pairs in edits.items():
        for a,b in pairs:out[n]=one(out[n],a,b)
    out['implementation/authority.py']+=operands['authority.py.in'][0]
    out['test_source.py']=one(out['test_source.py'],"if __name__=='__main__':",operands['tests.py.in'][0].decode()+"\nif __name__=='__main__':")
    policy=json.loads(before['implementation/profile.json']);original=json.loads(encoded(policy))
    need(policy['authorities']=={'fresh607':None,'baseline607':None}and policy['authority_files']is None and
         policy['input_sources']['latest_decisions']is None and all(policy[k]is None for k in('actual_source','actual_ref','actual_run')),
         'whole original UNBOUND source policy')
    locks=[]
    for n,k in(('before607.lock','before'),('after607.lock','after')):
        need(pin(before['implementation/'+n])==policy[k],'whole held lock')
        pairs=[line.split()for line in before['implementation/'+n].decode('ascii').splitlines()]
        need(len(pairs)==607 and len(dict(pairs))==607,'complete fixed607 inventory')
        locks.append(dict(pairs))
    need(locks[0]['cachy-asahi-apps']=='0.1.0-6'and locks[1]==dict(locks[0],**{'cachy-asahi-apps':'0.1.0-16'}),
         'ONLY Apps6→16, other606/Runtime1 held')
    D=helper();records={}
    for kind in('fresh607','baseline607'):
        incoming=spec['inputs'][kind]
        record=dict(source=incoming['source'],ref=incoming['ref'],files=incoming['files'],
                    original=json.loads(snapshots[kind][0]['decision.json']))
        D.original_decision(kind,record['original'],policy)
        need(encoded(record['original'])==snapshots[kind][0]['decision.json'],'original full issued decision bytes')
        records[kind]=record
    need(len({r['source']for r in records.values()})==2 and
         len({r['original']['run_id']for r in records.values()})==2,'two separate genuine prerequisites')
    policy.update(authority_projection=D.PROJECTION_KIND,
                  authority_projection_policy=dict(schema_version=1,records=records))
    carried=snapshots['carrier'][0];need(len(carried)==50,'whole exact independent50 carrier')
    for kind,record in records.items():
        projection=D.projection(kind,record,policy,locks[0]);name=kind+'/projection.json';raw=encoded(projection)
        need(carried.get(name)==raw and
             {n[len(kind+'/record/'):]:b for n,b in carried.items()if n.startswith(kind+'/record/')}==snapshots[kind][0],
             'exact source-derived projection AND entire original24')
        policy['authorities'][kind]=dict(path=name,**pin(raw),source=record['original']['source_sha'],run=record['original']['run_id'])
    policy['authority_files']=spec['inputs']['carrier']['files']
    policy['input_sources']['latest_decisions']=spec['inputs']['carrier']['source']
    out['implementation/profile.json']=encoded(policy)
    parent355=json.loads(before['implementation/parent355.json'])
    parent355['binding_context']=dict(files=maps['before']['files'],source=maps['before']['source'],ref=maps['before']['ref'],
        bodies={n:before[n].decode()for n in edits})
    out['implementation/parent355.json']=encoded(parent355)
    manifest=json.loads(before['source-manifest.json'])
    manifest['files']={n:pin(b)for n,b in out.items()if n!='source-manifest.json'}
    out['source-manifest.json']=encoded(manifest)
    need(set(out)==set(before)and len(out)==357 and
         {n for n in before if before[n]!=out[n]}==set(spec['changed_names'])and
         {n:pin(b)for n,b in out.items()}==maps['after']['files']and maps['after']['source']==spec['sources']['after'],
         'whole exact genuine public bound357,350 held/seven changed')
    # Entire original357 private inverse is DATA only; no parent code executes.
    restored=dict(out)
    for n,b in parent355['binding_context']['bodies'].items():restored[n]=b.encode()
    oldpolicy=json.loads(out['implementation/profile.json'])
    for n in('authority_projection','authority_projection_policy'):oldpolicy.pop(n)
    oldpolicy['authorities']=original['authorities'];oldpolicy['authority_files']=None
    oldpolicy['input_sources']['latest_decisions']=None
    restored['implementation/profile.json']=encoded(oldpolicy)
    oldparent=dict(parent355);oldparent.pop('binding_context');restored['implementation/parent355.json']=encoded(oldparent)
    oldmanifest=json.loads(out['source-manifest.json'])
    oldmanifest['files']={n:w for n,w in maps['before']['files'].items()if n!='source-manifest.json'}
    restored['source-manifest.json']=encoded(oldmanifest)
    need(restored==before,'whole original357 inverse including355/208 source/security bodies')
    operands.update({'profile.json':(profile_raw,state),'prepare.py':read_state(HERE/'prepare.py')})
    need(read_state(HERE/'profile.json')==(profile_raw,state),'late fixed profile identity')
    return out,snapshots,operands


def build(parent,fresh,baseline,carrier,output,receipt,context='null'):
    need(context in('known','null'),'known/NULL publication receipt only; same bound source')
    parent,fresh,baseline,carrier,output,receipt=paths(parent,fresh,baseline,carrier,output,receipt)
    values,snapshots,operands=render(parent,fresh,baseline,carrier)
    need({k:scan(root)for k,root in(('before',parent),('fresh607',fresh),('baseline607',baseline),('carrier',carrier))}==snapshots and
         all(read_state(HERE/n)==v for n,v in operands.items()),'late complete namespace/FD/operand identity')
    paths(parent,fresh,baseline,carrier,output,receipt)
    output.mkdir(mode=0o700)
    for n,b in values.items():
        path=output/n;path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        with path.open('xb')as f:f.write(b)
        path.chmod(0o644)
    need(tree(output)==values,'whole emitted357 source bytes')
    result=dict(status='EXACT_PUBLIC_BOUND357_SOURCE_REQUIRES_RUNTIME_AUTHORITY_GATES',context=context,
        publication=None if context=='null'else json.loads(operands['after-source.json'][0])['source'],
        files={n:pin(b)for n,b in values.items()},actual_source=None,actual_ref=None,actual_run=None,
        actor_authority=False,new_acceptance_issued=False)
    with receipt.open('xb')as f:f.write(encoded(result))
    receipt.chmod(0o644)
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in('parent','fresh','baseline','carrier','output','receipt'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--context',choices=('known','null'),default='null')
    args=parser.parse_args()
    print(json.dumps(build(args.parent,args.fresh,args.baseline,args.carrier,args.output,args.receipt,args.context),sort_keys=True))
