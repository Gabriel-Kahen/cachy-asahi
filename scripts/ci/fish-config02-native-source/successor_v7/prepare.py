#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Construct a diagnostic-only fixed-path Fish filesystem Source successor."""
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
    m=load_bytes(read(HERE/'inverse.py'),'inert_inverse',HERE/'inverse.py');return m.SOURCE57



HELPER_PIN=dict(bytes=3065,sha256='d07339b6815852f459ee71b037c6eff3a52fc78de09b1b62fa30a80f3531ef45')


def frozen(base):
    base=Path(base);expected=origin();raw=read(base/'source-map.json');need(pin(raw)==expected['map'],'exact Source57 map')
    manifest=json.loads(raw);rows=dict(manifest['files'],**{'source-map.json':row(raw)});found=set()
    need(len(rows)==57 and manifest['kind']=='FISH02_PAYLOAD_RETIREMENT_SOURCE_V6'and
         all(v is None for v in manifest['actual'].values()),'exact frozen57 schema')
    for index,p in enumerate(base.rglob('*')):
        need(index<256 and not p.is_symlink()and(p.is_dir()or p.is_file()),'bounded closed Source57')
        if p.is_file():found.add(p.relative_to(base).as_posix())
    need(found==set(rows),'complete Source57 namespace')
    bodies={}
    for name,wanted in rows.items():
        need(not Path(name).is_absolute()and '..'not in Path(name).parts,'safe Source57 member')
        body=read(base/name);need(row(body)==wanted and stat.S_IMODE((base/name).stat().st_mode)==0o644,'whole Source57 member/mode');bodies[name]=body
    d=load_bytes(bodies[PREFIX+'data.py'],'verified_source57_data',base/PREFIX/'data.py')
    need(sum(map(len,bodies.values()))==expected['bytes']and d.git_tree(bodies)==expected['tree'],'complete57 bytes/tree')
    d.source(base,expected['map']['sha256'])
    return bodies,manifest,d


def helper():
    need(HELPER_PIN is not None,'whole reviewed filesystem diagnostic helper is required')
    raw=read(HERE/'filesystem_diagnostic.py');need(pin(raw)==HELPER_PIN,'whole pinned filesystem diagnostic helper')
    return raw


def projections(original):
    payload=original[PREFIX+'payload.py'].decode();seams=[]
    def replace(before,after):
        nonlocal payload
        need(payload.count(before)==1 and before!=after,'one exact filesystem diagnostic seam')
        seams.append(dict(before=before,after=after));payload=payload.replace(before,after)
    anchor="s = importlib.util.spec_from_file_location('fish02_payload_diagnostic_v6',HERE/'payload_diagnostic.py');X=importlib.util.module_from_spec(s);s.loader.exec_module(X)"
    replace(anchor,anchor+"\ns = importlib.util.spec_from_file_location('fish02_filesystem_diagnostic_v7',HERE/'filesystem_diagnostic.py');Y=importlib.util.module_from_spec(s);s.loader.exec_module(Y)")
    anchor="    D.need(not os.access('/tmp',os.W_OK) and not os.access('/var/tmp',os.W_OK) and not os.access(root,os.W_OK),'actual owner writable filesystem restricted to quota work domain')"
    replace(anchor,"    Y.emit(root,Path(config['output']).parent)\n"+anchor)
    ast.parse(payload)
    return {PREFIX+'payload.py':payload.encode()},{PREFIX+'payload.py':seams}


def projected_data(raw):
    text=raw.decode();old="value['kind']=='FISH02_PAYLOAD_RETIREMENT_SOURCE_V6' and len(rows)==56"
    need(text.count(old)==1,'one finite outer Source frame seam')
    text=text.replace(old,"value['kind']=='FISH02_FIXED_FILESYSTEM_DIAGNOSTIC_SOURCE_V7' and len(rows)==59")
    call='    inverse_source48(root,inverse_source50(inverse_source53(bodies)))\n'
    need(text.count(call)==1,'one predecessor inverse call')
    text=text.replace(call,'    inverse_source48(root,inverse_source50(inverse_source53(inverse_source57(bodies))))\n')
    return text.encode()+b'\n'+read(HERE/'inverse.py')


def construct(base,output):
    base,output=map(Path,(base,output))
    need(output.is_absolute()and output==output.resolve()and output.parent.is_dir()and not output.exists()and
         not output.is_relative_to(base)and not base.is_relative_to(output),'fresh disjoint successor output')
    original,manifest,d=frozen(base);operand=helper()
    Y=load_bytes(operand,'pinned_filesystem_diagnostic',HERE/'filesystem_diagnostic.py')
    code,seams=projections(original);bodies=dict(original);bodies.update(code)
    before=json.loads(original[PREFIX+'policy.json']);policy=dict(before)
    need('filesystem_diagnostics'not in policy,'new diagnostic-only policy declaration')
    policy['filesystem_diagnostics']=Y.DECLARATION
    restored=dict(policy);restored.pop('filesystem_diagnostics');need(restored==before,'all original confinement/resources/VA/retirement/package policy unchanged')
    bodies[PREFIX+'policy.json']=encode(policy);bodies[PREFIX+'data.py']=projected_data(original[PREFIX+'data.py'])
    bodies[PREFIX+'README.md']=read(HERE/'README.md');bodies[PREFIX+'filesystem_diagnostic.py']=operand
    binding=PREFIX+'filesystem-diagnostic-binding.json';inverse=PREFIX+'source57-inverse.json';program=PREFIX+'owner-program.json'
    bodies[binding]=encode(dict(kind='FISH02_FIXED_PATH_FILESYSTEM_DIAGNOSTIC_BINDING_V7',helper=pin(operand),seams=seams,
        cross_controller_reference=dict(project='llhttp',source_files=76,run='44048877765',job=None,
            phase='readonly-filesystem',message_bytes=64,message_sha256='fb486df27f93098ca0869bbefefdfc5eebd0260b10abfcc4fb1b8c1dfb3286bb',
            provenance='Root-reported; not a Fish failure or qualification; no original fetched'),
        source_conclusion='No deterministic Fish contract defect proven; diagnostic only',actual=None,role_label=None))
    changed={n:raw.decode()for n,raw in original.items()if bodies[n]!=raw}
    changed['source-map.json']=original['source-map.json'].decode();changed[program]=original[program].decode()
    added=sorted((set(bodies)-set(original))|{inverse});excluded={'source-map.json',program,inverse}
    bodies[inverse]=encode(dict(kind='FISH_COMPLETE_SOURCE57_INVERSE_V7',origin=origin(),before_utf8=changed,
        after={n:row(raw)for n,raw in bodies.items()if n not in excluded and(n in changed or n in added)},added=added,actual=None))
    p=json.loads(original[program]);p['files']={n:row(raw)for n,raw in sorted(bodies.items())if not n.startswith('held-source32/')and n not in('source-map.json',program)}
    bodies[program]=encode(p)
    value=dict(manifest,kind='FISH02_FIXED_FILESYSTEM_DIAGNOSTIC_SOURCE_V7',files={n:row(raw)for n,raw in sorted(bodies.items())if n!='source-map.json'})
    bodies['source-map.json']=encode(value)
    validator=load_bytes(bodies[PREFIX+'data.py'],'staged_successor_validator',base/PREFIX/'data.py')
    restored=validator.inverse_source57(bodies);restored=validator.inverse_source53(restored);restored=validator.inverse_source50(restored);validator.inverse_source48(None,restored)
    need(len(bodies)==60 and sum(map(len,bodies.values()))<2*1024**2,'bounded computed successor60')
    output.mkdir(mode=0o700)
    for name,body in sorted(bodies.items()):
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb')as stream:stream.write(body)
        path.chmod(0o644)
    validator.source(output,pin(bodies['source-map.json'])['sha256'])
    return dict(files=60,bytes=sum(map(len,bodies.values())),source_map=pin(bodies['source-map.json']),
                policy=pin(bodies[PREFIX+'policy.json']),owner_program=pin(bodies[program]),tree=d.git_tree(bodies),
                original57_inverse=True,original53_inverse=True,original50_inverse=True,original48_inverse=True,
                helper=pin(operand),actual_source=None,Root_authority=None,actual_run=None,role_label=None)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();print(json.dumps(construct(a.base,a.output),indent=2,sort_keys=True))
