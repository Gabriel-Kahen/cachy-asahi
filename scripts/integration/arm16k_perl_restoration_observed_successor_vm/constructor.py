#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Compact Source387 diagnostic projection and exact canonical-lock inverse."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import types
import base64
import difflib
import importlib.util

HERE = Path(__file__).resolve().parent
CAP = 4 * 1024**2
PREFIX = '_restoration_observed/'
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


def authenticate_family(files,expected):
    need(rows(files)==expected['files']and pin(files['source.lock.json'][0])==expected['source_lock'],'whole immutable diagnostic family including tests/docs')
    lock=decode(files['source.lock.json'][0]);need(lock['files']==rows({n:r for n,r in files.items()if n!='source.lock.json'}),'closed original family map')


def compact_patch(before,after):
    a=before.splitlines(keepends=True);b=after.splitlines(keepends=True);offsets=[0]
    for line in b:offsets.append(offsets[-1]+len(line))
    patch=[]
    for op,a0,a1,b0,b1 in difflib.SequenceMatcher(a=a,b=b,autojunk=False).get_opcodes():
        if op!='equal':patch.append(dict(start=offsets[b0],end=offsets[b1],after=pin(b''.join(b[b0:b1])),before_b64=base64.b64encode(b''.join(a[a0:a1])).decode('ascii')))
    need(restore_patch(after,patch)==before,'exact byte-delta roundtrip before projection');return patch


def restore_patch(after,patch):
    need(type(patch)is list and len(patch)<=64,'finite changed byte-range inverse');last=0
    for p in patch:
        need(type(p)is dict and set(p)=={'start','end','after','before_b64'}and type(p['start'])is type(p['end'])is int and last<=p['start']<=p['end']<=len(after),'ordered disjoint exact changed-byte ranges')
        need(pin(after[p['start']:p['end']])==p['after'],'changed-range whole after bytes');last=p['end']
    result=after
    for p in reversed(patch):result=result[:p['start']]+base64.b64decode(p['before_b64'],validate=True)+result[p['end']:]
    return result


def project(predecessor,diagnostic,constructor,diagnostic_root,qmp=None):
    inputs=decode(constructor['inputs.json'][0]);old=closed(predecessor,inputs['predecessor']['source_lock'])
    need(canonical(old)==predecessor['source.lock.json'][0],'original69318 canonical JSON byte identity proved before changes')
    need(len(predecessor)==387 and sum(len(b)for b,_ in predecessor.values())==4106688,'complete387 predecessor tuple')
    need(inputs['fixture_source_cap_bytes']==CAP and all(v is None for v in inputs['actual'].values()),'unchanged4MiB cap/unissued roles')
    authenticate_family(diagnostic,inputs['diagnostic']);need(qmp is None and inputs['qmp']is None,'QMP composition requires separately frozen ready contract; never infer one')
    need(not any(n.startswith(PREFIX)for n in predecessor),'new compact successor namespace')
    spec=importlib.util.spec_from_file_location('authenticated_restoration_diagnostic',diagnostic_root/'proposal.py');D=importlib.util.module_from_spec(spec);spec.loader.exec_module(D)
    before=predecessor['guest/root.sh'][0];after=D.transform(before);need(D.inverse(after)==before,'exact frozen501 one-leaf inverse')
    result={n:r for n,r in predecessor.items()if n!='source.lock.json'};result['guest/root.sh']=after,predecessor['guest/root.sh'][1]
    changes={'guest/root.sh':dict(before=rows({'guest/root.sh':predecessor['guest/root.sh']})['guest/root.sh'],after=rows({'guest/root.sh':result['guest/root.sh']})['guest/root.sh'],patch=compact_patch(before,after))}
    manifest_name=PREFIX+'construction.DATA.json';added=[manifest_name]
    manifest=dict(kind='UNISSUED_COMPACT_RESTORATION_DIAGNOSTIC_SUCCESSOR_V1',predecessor=inputs['predecessor'],original_lock_metadata={k:v for k,v in old.items()if k!='files'},canonical_predecessor_lock_byte_identity=True,diagnostic=dict(commit=inputs['diagnostic']['commit'],source_lock=inputs['diagnostic']['source_lock'],projection='ROOT_RUNTIME_INLINE_ONLY_ORIGINAL_FAMILY_AUTHENTICATED_EXTERNALLY'),qmp=None,constructor=pin(constructor['source.lock.json'][0]),changes=changes,added_membership=added,inverse='RESTORE_EXACT_CHANGED_BYTE_RANGES_AND_MODES_REMOVE_ADDED_MEMBERSHIP_REGENERATE_CANONICAL_387_LOCK',fixture_source_cap_bytes=CAP,source_qualification=None,actual=dict.fromkeys(ACTUAL))
    need(len(canonical(manifest))<=16384,'bounded compact inverse/provenance DATA');result[manifest_name]=canonical(manifest),0o644
    lock=dict(old,files=rows(result),actual=dict.fromkeys(old['actual']));result['source.lock.json']=canonical(lock),0o644
    need(sum(len(b)for b,_ in result.values())<=CAP,'exact full result cap computed before output mutation')
    need(inverse(result,inputs['predecessor'])==predecessor,'all387 original byte/mode/whole-lock inverse')
    return result


def inverse(files,expected):
    new=decode(files['source.lock.json'][0]);need(new['files']==rows({n:r for n,r in files.items()if n!='source.lock.json'}),'whole current Source map before inverse')
    manifest=decode(files[PREFIX+'construction.DATA.json'][0]);added=manifest['added_membership'];need(type(added)is list and added==sorted(set(added))and all(n in files for n in added),'complete exact added membership')
    original={n:r for n,r in files.items()if n not in added and n!='source.lock.json'}
    for name,change in manifest['changes'].items():
        need(rows({name:files[name]})[name]==change['after'],'whole changed after body/mode')
        if change['before']is None:need(name in added,'new operational module is declared membership');continue
        need(name not in added and name in original,'overwritten predecessor leaf is never added membership')
        body=restore_patch(files[name][0],change['patch']);row=change['before'];need(pin(body)=={k:row[k]for k in('bytes','sha256')},'whole exact preimage after compact inverse');original[name]=body,row['mode']
    need({k:v for k,v in new.items()if k!='files'}==manifest['original_lock_metadata'],'unchanged canonical old/new lock metadata')
    old=dict(manifest['original_lock_metadata'],files=rows(original));raw=canonical(old);need(pin(raw)==expected['source_lock'],'regenerated69318-byte canonical predecessor lock exactly matches original')
    original['source.lock.json']=raw,0o644;closed(original,expected['source_lock']);need(len(original)==387 and sum(len(b)for b,_ in original.values())==4106688,'complete387 inverse tuple');return original


def verify_export(root,expected,diagnostic_root,constructor_expected):
    constructor,inputs=own(constructor_expected);files=snapshot(root);closed(files,expected);diagnostic=snapshot(diagnostic_root);authenticate_family(diagnostic,inputs['diagnostic'])
    old=inverse(files,inputs['predecessor']);replay=project(old,diagnostic,constructor,ordinary(diagnostic_root));need(replay==files,'deterministic runtime-only projection and compact whole387 inverse')
    for n,(body,_)in files.items():
        if n.endswith('.py'):compile(body,n,'exec')
    manifest=decode(files[PREFIX+'construction.DATA.json'][0]);total=sum(len(b)for b,_ in files.values());patch_bytes=sum(len(base64.b64decode(p['before_b64']))for c in manifest['changes'].values()for p in c['patch'])
    return dict(status='PASS_PHYSICAL_COMPACT_SOURCE_AND_WHOLE387_INVERSE_ONLY',files=len(files),closed_leaf_bytes=total,source_lock=expected,fixture_source_cap_bytes=CAP,remaining_source_bytes=CAP-total,changed_operational_leaves=sorted(manifest['changes']),retained_preimage_snippet_bytes=patch_bytes,full_old_lock_copied=False,full_old_root_copied=False,source_qualification=None,actual=dict.fromkeys(ACTUAL))


def construct(predecessor_root,diagnostic_root,output,constructor_expected,qmp=None):
    constructor,inputs=own(constructor_expected);need(qmp is None,'QMP contract unbound')
    roots=[ordinary(p)for p in(predecessor_root,diagnostic_root)];out=ordinary(output)
    need(not out.exists()and out.parent.is_dir()and out.parent.stat().st_uid==os.getuid()and not out.parent.stat().st_mode&0o022,'fresh private owned output')
    need(all(not out.is_relative_to(p)and not p.is_relative_to(out)for p in(*roots,HERE)),'output disjoint from immutable source inputs')
    before=[snapshot(p)for p in roots];result=project(*before,constructor,roots[1])
    need(all(snapshot(p)==s for p,s in zip(roots,before))and snapshot(HERE)==constructor,'all authenticated operands stable before first output mutation')
    out.mkdir(mode=0o700)
    for name,(body,mode)in sorted(result.items()):
        p=out/name;p.parent.mkdir(parents=True,exist_ok=True)
        with p.open('xb')as f:f.write(body)
        p.chmod(mode)
    return verify_export(out,pin(result['source.lock.json'][0]),roots[1],constructor_expected)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--constructor-lock-sha256',required=True);sub=p.add_subparsers(dest='command',required=True)
    c=sub.add_parser('construct')
    for name in('predecessor','diagnostic','output'):c.add_argument('--'+name,type=Path,required=True)
    v=sub.add_parser('verify')
    for name in('source','diagnostic'):v.add_argument('--'+name,type=Path,required=True)
    v.add_argument('--source-lock-sha256',required=True);a=p.parse_args()
    try:
        raw=read(HERE/'source.lock.json')[0];expected=dict(bytes=len(raw),sha256=a.constructor_lock_sha256)
        if a.command=='construct':answer=construct(a.predecessor,a.diagnostic,a.output,expected)
        else:
            raw=read(a.source/'source.lock.json')[0];answer=verify_export(a.source,dict(bytes=len(raw),sha256=a.source_lock_sha256),a.diagnostic,expected)
        print(json.dumps(answer,sort_keys=True,indent=2))
    except(OSError,ValueError,KeyError,TypeError)as error:p.exit(2,'compact Source DATA refusal: '+str(error)+'\n')
if __name__=='__main__':main()
