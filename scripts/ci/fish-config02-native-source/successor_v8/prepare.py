#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Construct explicit exact-Source read-only bindings for both Fish unit domains."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import stat
from types import ModuleType

HERE=Path(__file__).resolve().parent
PREFIX='scripts/ci/fish-config02-native-source/successor_v2/'
def need(ok,why):
    if not ok:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encode(v):return(json.dumps(v,indent=2,sort_keys=True)+'\n').encode()
def row(raw):return dict(pin(raw),mode=0o644)


def read(path):
    path=Path(path);need(path.is_absolute()and path==path.resolve()and not path.is_symlink(),'canonical operand')
    info=path.lstat();need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and not info.st_mode&0o022 and
                         0<info.st_size<=2*1024**2,'bounded ordinary operand')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    identity=lambda s:tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
    try:
        need(identity(info)==identity(os.fstat(fd)),'same operand descriptor')
        with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(2*1024**2+1)
        need(len(raw)==info.st_size and identity(info)==identity(os.fstat(fd))==identity(path.lstat()),'whole stable operand')
        return raw
    finally:os.close(fd)


def load_bytes(raw,name,path):
    m=ModuleType(name);m.__file__=str(path);exec(compile(raw,str(path),'exec'),m.__dict__);return m


def origin():
    m=load_bytes(read(HERE/'inverse.py'),'inert_inverse',HERE/'inverse.py');return m.SOURCE60



def frozen(base):
    base=Path(base);expected=origin();raw=read(base/'source-map.json');need(pin(raw)==expected['map'],'exact Source60 map')
    manifest=json.loads(raw);rows=dict(manifest['files'],**{'source-map.json':row(raw)});found=set()
    need(len(rows)==60 and manifest['kind']=='FISH02_FIXED_FILESYSTEM_DIAGNOSTIC_SOURCE_V7'and
         all(v is None for v in manifest['actual'].values()),'exact frozen60 schema')
    for index,p in enumerate(base.rglob('*')):
        need(index<256 and not p.is_symlink()and(p.is_dir()or p.is_file()),'bounded closed Source60')
        if p.is_file():found.add(p.relative_to(base).as_posix())
    need(found==set(rows),'complete Source60 namespace')
    bodies={}
    for name,wanted in rows.items():
        need(not Path(name).is_absolute()and '..'not in Path(name).parts,'safe Source60 member')
        body=read(base/name);need(row(body)==wanted and stat.S_IMODE((base/name).stat().st_mode)==0o644,'whole Source60 member/mode');bodies[name]=body
    d=load_bytes(bodies[PREFIX+'data.py'],'verified_source60_data',base/PREFIX/'data.py')
    need(sum(map(len,bodies.values()))==expected['bytes']and d.git_tree(bodies)==expected['tree'],'complete60 bytes/tree')
    d.source(base,expected['map']['sha256'])
    return bodies,manifest,d


DECLARATION=dict(kind='FISH02_EXACT_SOURCE_READONLY_UNIT_BINDING_V8',domains=['owner','daemon'],
    source_operand='controller.root',unit_property='BindReadOnlyPaths',same_source_destination=True,
    required=True,canonical_absolute=True,whole_quota_volume_disjoint=True,missing_source_refuses=True,
    payload_guard_unchanged=True,write_paths_unchanged=True)


def projections(original):
    data=original[PREFIX+'data.py'].decode();owner=original[PREFIX+'hosted_owner.py'].decode();seams={}
    def replace(text,before,after,key):
        need(text.count(before)==1 and before!=after,'one exact Source read-only seam')
        seams.setdefault(key,[]).append(dict(before=before,after=after));return text.replace(before,after)
    key=PREFIX+'data.py'
    before='def service_args(nonce, kind, limits, command, log, uid=None, gid=None):'
    data=replace(data,before,before[:-2]+', *, source_root):',key)
    before="    volume=log.parent\n    args += ['--property=ProtectSystem=strict','--property=ReadOnlyPaths=/tmp /var/tmp /sys/fs/cgroup']"
    after="""    volume=log.parent
    need(isinstance(source_root,Path) and source_root.is_absolute() and source_root!=Path('/')
         and re.fullmatch(r'/[A-Za-z0-9_./-]+',str(source_root)) and source_root==source_root.resolve(strict=True)
         and source_root.is_dir(),'required exact canonical Source root for read-only unit binding')
    need(volume.is_absolute() and re.fullmatch(r'/[A-Za-z0-9_./-]+',str(volume))
         and volume==volume.resolve(strict=True) and volume.is_dir(),'canonical existing quota volume for source disjointness')
    need(not source_root.is_relative_to(volume) and not volume.is_relative_to(source_root),
         'Source root and whole quota volume must be disjoint')
    args += ['--property=ProtectSystem=strict','--property=ReadOnlyPaths=/tmp /var/tmp /sys/fs/cgroup',
             '--property=BindReadOnlyPaths='+str(source_root)]"""
    data=replace(data,before,after,key)
    key=PREFIX+'hosted_owner.py'
    before="argv=D.service_args(self.nonce,kind,self.policy[kind],command,self.out/'volume'/(kind+'.log'),uid,gid)"
    owner=replace(owner,before,before[:-1]+',source_root=self.root)',key)
    ast.parse(data);ast.parse(owner)
    return {PREFIX+'data.py':data.encode(),PREFIX+'hosted_owner.py':owner.encode()},seams


def projected_data(raw):
    text=raw.decode();old="value['kind']=='FISH02_FIXED_FILESYSTEM_DIAGNOSTIC_SOURCE_V7' and len(rows)==59"
    need(text.count(old)==1,'one finite outer Source frame seam')
    text=text.replace(old,"value['kind']=='FISH02_EXPLICIT_SOURCE_READONLY_SOURCE_V8' and len(rows)==61")
    call='    inverse_source48(root,inverse_source50(inverse_source53(inverse_source57(bodies))))\n'
    need(text.count(call)==1,'one predecessor inverse call')
    text=text.replace(call,'    inverse_source48(root,inverse_source50(inverse_source53(inverse_source57(inverse_source60(bodies)))))\n')
    return text.encode()+b'\n'+read(HERE/'inverse.py')


def construct(base,output):
    base,output=map(Path,(base,output))
    need(output.is_absolute()and output==output.resolve()and output.parent.is_dir()and not output.exists()and
         not output.is_relative_to(base)and not base.is_relative_to(output),'fresh disjoint successor output')
    original,manifest,d=frozen(base);code,seams=projections(original);bodies=dict(original);bodies.update(code)
    before=json.loads(original[PREFIX+'policy.json']);policy=dict(before)
    need('source_readonly_binding'not in policy,'new explicit Source binding declaration')
    policy['source_readonly_binding']=DECLARATION
    restored=dict(policy);restored.pop('source_readonly_binding');need(restored==before,'all original quotas/VA/retirement/package policy unchanged')
    bodies[PREFIX+'policy.json']=encode(policy);bodies[PREFIX+'data.py']=projected_data(code[PREFIX+'data.py'])
    bodies[PREFIX+'README.md']=read(HERE/'README.md')
    binding=PREFIX+'source-ro-binding.json';inverse=PREFIX+'source60-inverse.json';program=PREFIX+'owner-program.json'
    bodies[binding]=encode(dict(kind='FISH02_EXACT_SOURCE_READONLY_PROJECTION_BINDING_V8',declaration=DECLARATION,seams=seams,
        cross_controller_reference=dict(project='llhttp',source_files=85,case='Root-reported Native92 Source confinement failure',
            original=dict(bytes=60995,sha256='80cb6154035c5b1b5e4c7c6dc7f6411e59446c1c3b93fb9333ec93fc43fb3c54'),
            source_writable=True,source_statvfs_readonly=False,source_covermount_readonly=False,source_covermount_class='other',
            provenance='Root-reported only; no Original read/refetch; not Fish actual evidence'),
        actual_source=None,actual_run=None,Root_authority=None,actual_runtime=None,role_label=None))
    changed={n:raw.decode()for n,raw in original.items()if bodies[n]!=raw}
    changed['source-map.json']=original['source-map.json'].decode();changed[program]=original[program].decode()
    added=sorted((set(bodies)-set(original))|{inverse});excluded={'source-map.json',program,inverse}
    bodies[inverse]=encode(dict(kind='FISH_COMPLETE_SOURCE60_INVERSE_V8',origin=origin(),before_utf8=changed,
        after={n:row(raw)for n,raw in bodies.items()if n not in excluded and(n in changed or n in added)},added=added,actual=None))
    p=json.loads(original[program]);p['files']={n:row(raw)for n,raw in sorted(bodies.items())if not n.startswith('held-source32/')and n not in('source-map.json',program)}
    bodies[program]=encode(p)
    value=dict(manifest,kind='FISH02_EXPLICIT_SOURCE_READONLY_SOURCE_V8',files={n:row(raw)for n,raw in sorted(bodies.items())if n!='source-map.json'})
    bodies['source-map.json']=encode(value)
    validator=load_bytes(bodies[PREFIX+'data.py'],'staged_successor_validator',base/PREFIX/'data.py')
    restored=validator.inverse_source60(bodies);restored=validator.inverse_source57(restored);restored=validator.inverse_source53(restored);restored=validator.inverse_source50(restored);validator.inverse_source48(None,restored)
    need(len(bodies)==62 and sum(map(len,bodies.values()))<2*1024**2,'bounded computed successor62')
    output.mkdir(mode=0o700)
    for name,body in sorted(bodies.items()):
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb')as stream:stream.write(body)
        path.chmod(0o644)
    validator.source(output,pin(bodies['source-map.json'])['sha256'])
    return dict(files=62,bytes=sum(map(len,bodies.values())),source_map=pin(bodies['source-map.json']),
                policy=pin(bodies[PREFIX+'policy.json']),owner_program=pin(bodies[program]),tree=d.git_tree(bodies),
                original60_inverse=True,original57_inverse=True,original53_inverse=True,original50_inverse=True,original48_inverse=True,
                actual_source=None,Root_authority=None,actual_runtime=None,actual_run=None,role_label=None)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();print(json.dumps(construct(a.base,a.output),indent=2,sort_keys=True))
