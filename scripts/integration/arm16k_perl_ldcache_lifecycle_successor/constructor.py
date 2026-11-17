#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Compose Source339 with a provider-derived cache transition; no Root authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import types
import importlib.util

HERE = Path(__file__).resolve().parent
CAP = 4 * 1024**2
PREFIX = '_ldcache_transition/'
ACTUAL = ('Source_CID', 'source_ref', 'Root_authority', 'runtime', 'nonce', 'VM', 'ALPM', 'M2', 'release')


def need(ok, why):
    if not ok:
        raise ValueError(why)


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def decode(raw):
    def unique(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=unique)
    need(type(value) is dict and raw == canonical(value), 'canonical JSON object')
    return value


def ordinary(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and
         not any(p.is_symlink() for p in (path, *path.parents)), 'ordinary absolute unaliased DATA path')
    return path


def read(path):
    path = ordinary(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC), 'rb') as stream:
        first = os.fstat(stream.fileno())
        need(stat.S_ISREG(first.st_mode) and first.st_nlink == 1 and first.st_size <= CAP,
             'bounded ordinary single-link source leaf')
        raw = stream.read(CAP + 1)
        last = os.fstat(stream.fileno())
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    need(identity(first) == identity(last) == identity(path.lstat()) and len(raw) == first.st_size <= CAP,
         'source changed during read')
    mode = stat.S_IMODE(first.st_mode)
    need(mode in (0o644, 0o755), 'Git-representable ordinary source mode')
    return raw, mode


def rows(files):
    return {name: dict(**pin(body), mode=mode) for name, (body, mode) in sorted(files.items())}


def snapshot(root):
    root = ordinary(root)
    need(root.is_dir(), 'explicit source directory')
    files = {}; directories = set(); size = 0
    for current, dirs, leaves in os.walk(root, followlinks=False):
        for name in dirs:
            child = ordinary(Path(current) / name)
            directories.add(child.relative_to(root).as_posix())
        for name in leaves:
            path = Path(current) / name
            relative = path.relative_to(root).as_posix()
            need(len(files) < 512, 'finite source leaf count')
            files[relative] = read(path)
            size += len(files[relative][0])
            need(size <= CAP, 'unchanged four-MiB fixture Source cap')
    expected_dirs = {p.as_posix() for name in files for p in PurePosixPath(name).parents if str(p) != '.'}
    need(directories == expected_dirs, 'exact namespace without empty/extra directories')
    return files


def closed(files, expected):
    need('source.lock.json' in files and files['source.lock.json'][1] == 0o644,
         'ordinary Source lock')
    raw = files['source.lock.json'][0]
    need(pin(raw) == expected, 'whole externally pinned Source lock')
    lock = decode(raw)
    need(type(lock.get('actual')) is dict and all(value is None for value in lock['actual'].values()),
         'unissued Source only; no inherited actual authority')
    need(lock['files'] == rows({name: row for name, row in files.items() if name != 'source.lock.json'}),
         'whole Source membership, bytes and modes')
    return lock


def own(expected):
    files=snapshot(HERE);closed(files,expected);return files,decode(files['inputs.json'][0])


def proposal_closed(files,expected):
    need(rows(files)==expected['files']and pin(files['source.lock.json'][0])==expected['source_lock'],'complete pinned35-leaf semantic proposal')
    lock=decode(files['source.lock.json'][0]);need(lock['files']==rows({n:r for n,r in files.items()if n!='source.lock.json'}),'whole proposal closure')


def material(ref):
    need(type(ref)is dict and set(ref)=={'path','bytes','sha256'},'explicit whole public material reference')
    path=ordinary(ref['path']);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size==ref['bytes']<=4*CAP,'bounded ordinary public material')
        digest=hashlib.sha256();count=0
        while block:=os.read(fd,1024**2):digest.update(block);count+=len(block);need(count<=ref['bytes'],'finite public material')
        b=os.fstat(fd);ident=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mode,s.st_mtime_ns,s.st_ctime_ns)
        need(count==ref['bytes']and digest.hexdigest()==ref['sha256']and ident(a)==ident(b)==ident(path.lstat()),'whole stable matching namespace/package material pin')
    finally:os.close(fd)


def selection(value,inputs):
    need(type(value)is dict and set(value)=={'kind','predecessor','proposal','baseline','materials','output','actual'}and value['kind']=='EXPLICIT_UNISSUED_CACHE_SUCCESSOR_SELECTION_V1','closed pure construction selection')
    need(value['actual']==dict.fromkeys(ACTUAL)and all(value[n]is not None for n in('predecessor','proposal','baseline','materials','output')),'all explicit baseline/material/source paths required; no default authority or construction')
    need(value['materials']==inputs['materials'],'exact retained namespace/ownership/ALPM/package references, no qualification waiver')
    need(type(value['baseline'])is dict and set(value['baseline'])=={'path','bytes','sha256'}and {k:value['baseline'][k]for k in('bytes','sha256')}==inputs['baseline'],'exact independently extracted17551 baseline body pin')
    for ref in value['materials'].values():material(ref)
    material(value['baseline'])
    return value


def control(path,cap=65536):
    path=ordinary(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size<=cap,'bounded ordinary control DATA');body=os.read(fd,cap+1);b=os.fstat(fd);need(len(body)==a.st_size and (a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns)==(path.stat().st_dev,path.stat().st_ino,path.stat().st_size,path.stat().st_mtime_ns,path.stat().st_ctime_ns),'stable whole control DATA');return body
    finally:os.close(fd)


def baseline_bytes(ref):
    material(ref);body=control(ref['path'],1024**2);need(pin(body)=={k:ref[k]for k in('bytes','sha256')},'exact stable public baseline body');return body


def budget_bound(predecessor,proposal,constructor):
    """Conservative byte bound only, with zero placeholders; never a Source export.

    Frozen transform adds the helper and <2048 comparison bytes to initialized,
    <1024 root phase bytes, a TSV<=512 and construction manifest<=16384. Actual
    project() still computes and enforces its exact result BEFORE any mutation.
    """
    inputs=decode(constructor['inputs.json'][0]);closed(predecessor,inputs['predecessor']['source_lock']);proposal_closed(proposal,inputs['proposal'])
    files={n:r for n,r in predecessor.items()if n!='source.lock.json'}
    for name,extra in(('guest/initialized-state.sh',len(proposal['guest-cache-transition.sh'][0])+2048),('guest/root.sh',1024),('adapter.py',512)):
        files[name]=(b'\0'*(len(predecessor[name][0])+extra),predecessor[name][1])
    files[PREFIX+'inverse/source.lock.json']=predecessor['source.lock.json']
    for prefix,family in(('proposal/',proposal),('constructor/',constructor)):
        for name,row in family.items():files[PREFIX+prefix+name]=row
    files[PREFIX+'materials/baseline-cache.bin']=(b'\0'*17551,0o644);files['expected-cache-transition.tsv']=(b'\0'*512,0o644);files[PREFIX+'construction.DATA.json']=(b'\0'*16384,0o644)
    old=decode(predecessor['source.lock.json'][0]);lock=dict(old,files=rows(files),actual=dict.fromkeys(old['actual']));files['source.lock.json']=(canonical(lock),0o644)
    total=sum(len(b)for b,_ in files.values())
    return dict(kind='CONSERVATIVE_PRECOPY_BOUND_NOT_CONSTRUCTION_PROOF',upper_bound_files=len(files),upper_bound_bytes=total,fixture_source_cap_bytes=CAP,remaining_bound_bytes=CAP-total,fits_conservative_bound=total<=CAP,baseline_body=None,actual_source_lock=None,actual=dict.fromkeys(ACTUAL))


def project(predecessor,proposal,constructor,proposal_root,baseline,materials):
    inputs=decode(constructor['inputs.json'][0]);old_lock=closed(predecessor,inputs['predecessor']['source_lock'])
    need(len(predecessor)==339==inputs['predecessor']['files']and sum(len(b)for b,_ in predecessor.values())==3512147==inputs['predecessor']['closed_leaf_bytes'],'exact complete Source339 tuple')
    need(inputs['fixture_source_cap_bytes']==CAP and all(v is None for v in inputs['actual'].values()),'fixed4MiB cap and no inherited actual roles')
    proposal_closed(proposal,inputs['proposal']);need(pin(baseline)==inputs['baseline']and materials==inputs['materials'],'exact baseline and whole pinned provider materials')
    need(not any(n.startswith(PREFIX)for n in predecessor),'new successor namespace only')
    spec=importlib.util.spec_from_file_location('authenticated_cache_transition',proposal_root/'transform.py');T=importlib.util.module_from_spec(spec);spec.loader.exec_module(T)
    generated=T.apply(predecessor['guest/initialized-state.sh'][0],predecessor['guest/root.sh'][0],baseline)
    need(T.inverse(generated,baseline)==(predecessor['guest/initialized-state.sh'][0],predecessor['guest/root.sh'][0]),'whole exact2-leaf proposal byte inverse')
    spec=importlib.util.spec_from_file_location('authenticated_fixture_delivery',HERE/'fixture_delivery.py');D=importlib.util.module_from_spec(spec);spec.loader.exec_module(D)
    need(constructor['predecessor-adapter.py']==predecessor['adapter.py'],'retained exact third operational preimage');generated['adapter']=D.transform(predecessor['adapter.py'][0]);need(D.inverse(generated['adapter'],predecessor['adapter.py'][0])==predecessor['adapter.py'][0],'exact fixed-name fixture-delivery inverse')
    result={n:r for n,r in predecessor.items()if n!='source.lock.json'};changes={}
    for name,key in(('guest/initialized-state.sh','initialized'),('guest/root.sh','root'),('adapter.py','adapter')):
        result[name]=generated[key],predecessor[name][1];changes[name]=dict(before=rows({name:predecessor[name]})[name],after=rows({name:result[name]})[name])
    # The original operational preimages already occur inside the35-leaf proposal.
    # Reuse them; retain only the old whole lock and added membership additionally.
    result[PREFIX+'inverse/source.lock.json']=predecessor['source.lock.json']
    for prefix,source in(('proposal/',proposal),('constructor/',constructor)):
        for name,row in source.items():result[PREFIX+prefix+name]=row
    result[PREFIX+'materials/baseline-cache.bin']=baseline,0o644
    result['expected-cache-transition.tsv']=generated['manifest'],0o644
    manifest_name=PREFIX+'construction.DATA.json';added=sorted((set(result)-set(predecessor))|{manifest_name})
    preimages={'adapter.py':PREFIX+'constructor/predecessor-adapter.py','guest/initialized-state.sh':PREFIX+'proposal/predecessor-initialized-state.sh','guest/root.sh':PREFIX+'proposal/predecessor-root.sh'}
    for name,ref in preimages.items():need(result[ref]==predecessor[name],'reused exact preimage body/mode')
    manifest=dict(fixture_delivery=dict(kind='ONE_FIXED_TSV_THROUGH_EXISTING_ADAPTER_CONTENTS',name='expected-cache-transition.tsv',delta=pin(constructor['fixture_delivery.py'][0])),kind='UNISSUED_PROVIDER_DERIVED_CACHE_LIFECYCLE_SUCCESSOR_V1',predecessor=inputs['predecessor'],proposal=dict(commit=inputs['proposal']['commit'],source_lock=inputs['proposal']['source_lock']),constructor=pin(constructor['source.lock.json'][0]),baseline=inputs['baseline'],material_refs=materials,derivation=dict(baseline=generated['derivation']['baseline'],installed=generated['derivation']['installed'],restored=generated['derivation']['restored'],added_entries=generated['derivation']['added_entries']),changes=changes,inverse=dict(preimages=preimages,old_lock=PREFIX+'inverse/source.lock.json',strategy='WHOLE339_REUSE_UNCHANGED_PLUS_PINNED_TWO_PREIMAGES_OLD_LOCK_AND_ADDED_MEMBERSHIP'),added_membership=added,fixture_source_cap_bytes=CAP,source_qualification='UNISSUED_NEEDS_MATCHING_SUCCESSOR_CASE_NAMESPACE_AND_MATERIAL_BINDING_NO_F51_WAIVER',actual=dict.fromkeys(ACTUAL))
    need(len(canonical(manifest))<=16384,'bounded membership/construction manifest')
    result[manifest_name]=canonical(manifest),0o644
    lock=dict(old_lock,files=rows(result),actual=dict.fromkeys(old_lock['actual']));result['source.lock.json']=canonical(lock),0o644
    need(sum(len(body)for body,_ in result.values())<=CAP,'computed physical successor exceeds unchanged4MiB cap before any output copy')
    return result


def inverse(files,expected):
    manifest=decode(files[PREFIX+'construction.DATA.json'][0]);added=manifest['added_membership'];need(type(added)is list and added==sorted(set(added))and all(n in files for n in added),'complete exact added-membership inverse')
    old={n:r for n,r in files.items()if n not in added};old['source.lock.json']=files[manifest['inverse']['old_lock']]
    for name,ref in manifest['inverse']['preimages'].items():
        need(name in manifest['changes']and rows({name:files[ref]})[name]==manifest['changes'][name]['before'],'whole pinned changed preimages');old[name]=files[ref]
    closed(old,expected['source_lock']);need(len(old)==339 and sum(len(b)for b,_ in old.values())==3512147,'complete339 byte/mode/whole-lock inverse');return old


def verify_export(root,expected,constructor_expected):
    constructor,inputs=own(constructor_expected);files=snapshot(root);closed(files,expected)
    old=inverse(files,inputs['predecessor'])
    def subtree(prefix):return {n[len(prefix):]:r for n,r in files.items()if n.startswith(prefix)}
    proposal=subtree(PREFIX+'proposal/');need(subtree(PREFIX+'constructor/')==constructor,'whole constructor provenance')
    manifest=decode(files[PREFIX+'construction.DATA.json'][0]);base=files[PREFIX+'materials/baseline-cache.bin'][0]
    replay=project(old,proposal,constructor,ordinary(root)/PREFIX/'proposal',base,manifest['material_refs']);need(files==replay,'complete deterministic source, exact inverse and physical bytes/modes')
    compiled=0
    for name,(body,_)in files.items():
        if name.endswith('.py'):compile(body,name,'exec');compiled+=1
    count=sum(len(b)for b,_ in files.values())
    return dict(status='PASS_PHYSICAL_SOURCE_AND_WHOLE339_INVERSE_ONLY_ROOT_QUALIFICATION_HELD',files=len(files),closed_leaf_bytes=count,source_lock=expected,fixture_source_cap_bytes=CAP,remaining_source_bytes=CAP-count,compiled_python_files=compiled,changed_operational_leaves=['adapter.py','guest/initialized-state.sh','guest/root.sh'],derived_manifest=pin(files['expected-cache-transition.tsv'][0]),baseline=inputs['baseline'],source_qualification=None,actual=dict.fromkeys(ACTUAL))


def construct(value,constructor_expected):
    constructor,inputs=own(constructor_expected);selection(value,inputs)
    roots=[ordinary(value[n])for n in('predecessor','proposal')];out=ordinary(value['output']);baseline=baseline_bytes(value['baseline'])
    need(not out.exists()and out.parent.is_dir()and out.parent.stat().st_uid==os.getuid()and not out.parent.stat().st_mode&0o022,'fresh private owned output parent')
    need(all(not out.is_relative_to(r)and not r.is_relative_to(out)for r in(*roots,HERE,*[ordinary(v['path'])for v in value['materials'].values()],ordinary(value['baseline']['path']))),'source output disjoint from all frozen inputs')
    before=[snapshot(r)for r in roots];result=project(*before,constructor,roots[1],baseline,value['materials'])
    need(all(snapshot(r)==prior for r,prior in zip(roots,before))and snapshot(HERE)==constructor,'all whole source/proposal/constructor inputs unchanged')
    for ref in value['materials'].values():material(ref)
    need(baseline_bytes(value['baseline'])==baseline,'baseline body unchanged before export')
    # Full bytes (including final lock) and cap were computed before this first mutation.
    out.mkdir(mode=0o700)
    for name,(body,mode)in sorted(result.items()):
        p=out/name;p.parent.mkdir(parents=True,exist_ok=True)
        with p.open('xb')as f:f.write(body)
        p.chmod(mode)
    return verify_export(out,pin(result['source.lock.json'][0]),constructor_expected)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--constructor-lock-sha256',required=True);sub=p.add_subparsers(dest='command',required=True)
    c=sub.add_parser('construct');c.add_argument('--selection',type=Path,required=True);c.add_argument('--selection-sha256',required=True)
    v=sub.add_parser('verify');v.add_argument('--source',type=Path,required=True);v.add_argument('--source-lock-sha256',required=True);a=p.parse_args()
    try:
        body=read(HERE/'source.lock.json')[0];expected=dict(bytes=len(body),sha256=a.constructor_lock_sha256)
        if a.command=='construct':
            body=control(a.selection);need(pin(body)['sha256']==a.selection_sha256,'whole externally selected construction DATA');answer=construct(decode(body),expected)
        else:
            body=read(a.source/'source.lock.json')[0];answer=verify_export(a.source,dict(bytes=len(body),sha256=a.source_lock_sha256),expected)
        print(json.dumps(answer,sort_keys=True,indent=2))
    except(OSError,ValueError,KeyError,TypeError)as error:p.exit(2,'cache successor DATA refusal: '+str(error)+'\n')
if __name__=='__main__':main()
