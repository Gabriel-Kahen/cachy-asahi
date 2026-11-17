#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Construct a pin-gated Fish successor; NULL Root operand refuses output.

This is DATA assembly, not a limit implementation. It imports only the pinned
pure Root helper, never applies limits/launches children or issues authority.
"""
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
SEMANTICS=dict(controller_soft=512*1024**2,controller_hard=2*1024**3,
               qualified_docker_soft=2*1024**3,qualified_docker_hard=2*1024**3,
               other_qualified_soft=512*1024**2,other_qualified_hard=512*1024**2)


class MissingOperand(ValueError):pass


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
    m=load_bytes(read(HERE/'inverse.py'),'inert_inverse',HERE/'inverse.py');return m.SOURCE50


def frozen(base):
    base=Path(base);expected=origin();raw=read(base/'source-map.json');need(pin(raw)==expected['map'],'exact Source50 map')
    manifest=json.loads(raw);rows=dict(manifest['files'],**{'source-map.json':row(raw)});found=set()
    need(len(rows)==50 and manifest['kind']=='FISH02_NO_HOST_APT_SOURCE_V4'and
         all(v is None for v in manifest['actual'].values()),'exact frozen50 schema')
    for index,p in enumerate(base.rglob('*')):
        need(index<256 and not p.is_symlink()and(p.is_dir()or p.is_file()),'bounded closed Source50')
        if p.is_file():found.add(p.relative_to(base).as_posix())
    need(found==set(rows),'complete Source50 namespace')
    bodies={}
    for name,wanted in rows.items():
        need(not Path(name).is_absolute()and '..'not in Path(name).parts,'safe Source50 member')
        body=read(base/name);need(row(body)==wanted and stat.S_IMODE((base/name).stat().st_mode)==0o644,'whole Source50 member/mode');bodies[name]=body
    # Only execute the validator after its body and complete fixed Source are pinned.
    d=load_bytes(bodies[PREFIX+'data.py'],'verified_source50_data',base/PREFIX/'data.py')
    need(sum(map(len,bodies.values()))==expected['bytes']and d.git_tree(bodies)==expected['tree'],'complete50 bytes/tree')
    d.source(base,expected['map']['sha256'])
    return bodies,manifest,d


def requirement():
    value=json.loads(read(HERE/'helper.REQUIRED.json'))
    if any(value.get(k)is None for k in ('helper','api','upstream_commit')):
        raise MissingOperand('Root immutable helper body/pin/API is NULL; no Source emitted')
    need(value['helper']==dict(file='go_cli_va.py',bytes=1996,sha256='3b2feba315f3a0e4cfed2498160e75591d64c7b8f0e8f5c11b46321b04b5eff3') and
         value['upstream_commit']=='b156e3886a12f95cb3d364b84fc3a946bb7d2967' and
         value['api']==['controller_limit(policy)','child_plan(argv,observed_tools,policy)','child_limits(plan)'],
         'only exact Root immutable helper/API binding')
    return value


def operand(root,spec):
    need(type(spec)is dict and set(spec)=={'file','bytes','sha256'}and
         type(spec['file'])is str and Path(spec['file']).name==spec['file']and spec['file']not in('','.','..'),
         'single exact declared operand leaf')
    raw=read(Path(root)/spec['file']);need(pin(raw)=={k:spec[k]for k in('bytes','sha256')},'whole pinned Root operand')
    return raw


def protected_policy(before,after,declaration):
    restored=dict(after);need(restored.pop('docker_cli_address_space')==declaration,'exact Root finite Docker-only declaration')
    need(restored==before,'all previous controller soft/physical and other budgets unchanged')


OWNER_EDITS=(
("s=importlib.util.spec_from_file_location('fish02_v2_host_tools',HERE/'host_tools.py');H=importlib.util.module_from_spec(s);s.loader.exec_module(H)",
 "s=importlib.util.spec_from_file_location('fish02_v2_host_tools',HERE/'host_tools.py');H=importlib.util.module_from_spec(s);s.loader.exec_module(H)\ns=importlib.util.spec_from_file_location('fish_go_cli_va_v5',HERE/'go_cli_va.py');V=importlib.util.module_from_spec(s);s.loader.exec_module(V)"),
("        child=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,",
 "        D.need(resource.getrlimit(resource.RLIMIT_AS)==V.controller_limit(self.policy),'same finite controller soft/hard VA ceiling before launch')\n        address_space=V.child_plan(args,self.tools,self.policy)\n        child=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,preexec_fn=V.child_limits(address_space),"),
("self.commands.append(dict(argv=args,retirement=row,output=D.pin(body)))", "self.commands.append(dict(argv=args,address_space=address_space,retirement=row,output=D.pin(body)))"),
("resource.setrlimit(resource.RLIMIT_AS,(policy['controller']['AS_bytes'],policy['controller']['AS_bytes']))", "resource.setrlimit(resource.RLIMIT_AS,V.controller_limit(policy))"),
)


def projected_owner(raw):
    text=raw.decode()
    for before,after in OWNER_EDITS:
        need(text.count(before)==1 and after not in text,'one exact Root API owner seam');text=text.replace(before,after)
    restored=text
    for before,after in reversed(OWNER_EDITS):
        need(restored.count(after)==1,'one exact owner inverse seam');restored=restored.replace(after,before)
    need(restored.encode()==raw,'whole Source50 owner inverse')
    return text.encode()


def projected_data(raw):
    text=raw.decode();old="value['kind']=='FISH02_NO_HOST_APT_SOURCE_V4' and len(rows)==49"
    need(text.count(old)==1,'one finite outer Source frame seam')
    text=text.replace(old,"value['kind']=='FISH02_FINITE_DOCKER_VA_SOURCE_V5' and len(rows)==52")
    call='    inverse_source48(root,bodies)\n';need(text.count(call)==1,'one predecessor inverse call')
    text=text.replace(call,'    inverse_source48(root,inverse_source50(bodies))\n')
    return text.encode()+b'\n'+read(HERE/'inverse.py')


def construct(base,output):
    base,output=map(Path,(base,output))
    need(output.is_absolute()and output==output.resolve()and output.parent.is_dir()and not output.exists()and
         not output.is_relative_to(base)and not base.is_relative_to(output),'fresh disjoint successor output')
    original,manifest,d=frozen(base)
    required=requirement() # NULL/wrong pins refuse BEFORE helper load or output write.
    helper=operand(HERE,required['helper'])
    V=load_bytes(helper,'whole_pinned_Root_va_helper',HERE/'go_cli_va.py')
    owner=projected_owner(original[PREFIX+'hosted_owner.py'])
    before_policy=json.loads(original[PREFIX+'policy.json']);after_policy=dict(before_policy)
    need('docker_cli_address_space'not in after_policy,'no prior Docker VA allowance')
    after_policy['docker_cli_address_space']=V.DECLARATION;policy=encode(after_policy)
    protected_policy(before_policy,after_policy,V.DECLARATION)
    need(V.controller_limit(after_policy)==(SEMANTICS['controller_soft'],SEMANTICS['controller_hard']),
         'Root helper finite controller pair agrees')
    ast.parse(owner) # Only the pure pinned helper is imported; no limit is applied.
    bodies=dict(original);helper_name=PREFIX+required['helper']['file']
    need(helper_name not in original,'new distinct helper namespace')
    bodies[helper_name]=helper;bodies[PREFIX+'hosted_owner.py']=owner;bodies[PREFIX+'policy.json']=policy
    bodies[PREFIX+'data.py']=projected_data(original[PREFIX+'data.py'])
    bodies[PREFIX+'README.md']=read(HERE/'README.md')
    binding=PREFIX+'child-va-binding.json';inverse=PREFIX+'source50-inverse.json';program=PREFIX+'owner-program.json'
    bodies[binding]=encode(dict(kind='FISH_WHOLE_PINNED_DOCKER_VA_OPERAND_V5',requirements=required,actual=None))
    changed={n:raw.decode()for n,raw in original.items()if bodies[n]!=raw}
    changed['source-map.json']=original['source-map.json'].decode();changed[program]=original[program].decode()
    added=sorted((set(bodies)-set(original))|{inverse})
    excluded={'source-map.json',program,inverse}
    proof=dict(kind='FISH_COMPLETE_SOURCE50_INVERSE_V5',origin=origin(),before_utf8=changed,
               after={n:row(raw)for n,raw in bodies.items()if n not in excluded and(n in changed or n in added)},added=added,actual=None)
    bodies[inverse]=encode(proof)
    p=json.loads(original[program]);p['files']={n:row(raw)for n,raw in sorted(bodies.items())if not n.startswith('held-source32/')and n not in('source-map.json',program)}
    bodies[program]=encode(p);value=dict(manifest,kind='FISH02_FINITE_DOCKER_VA_SOURCE_V5',files={n:row(raw)for n,raw in sorted(bodies.items())if n!='source-map.json'})
    bodies['source-map.json']=encode(value)
    validator=load_bytes(bodies[PREFIX+'data.py'],'staged_successor_validator',base/PREFIX/'data.py')
    restored=validator.inverse_source50(bodies);validator.inverse_source48(None,restored)
    need(len(bodies)==53 and sum(map(len,bodies.values()))<2*1024**2,'bounded computed successor53')
    output.mkdir(mode=0o700)
    for name,body in sorted(bodies.items()):
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb')as stream:stream.write(body)
        path.chmod(0o644)
    validator.source(output,pin(bodies['source-map.json'])['sha256'])
    return dict(files=53,bytes=sum(map(len,bodies.values())),source_map=pin(bodies['source-map.json']),
                policy=pin(policy),owner_program=pin(bodies[program]),tree=d.git_tree(bodies),
                original50_inverse=True,helper=pin(helper),actual_source=None,Root_authority=None,actual_run=None)


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();print(json.dumps(construct(a.base,a.output),indent=2,sort_keys=True))
