#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pure DATA construction of a new Fish32-derived owned-domain Source."""
import argparse
import importlib.util
import json
from pathlib import Path
import stat

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('fish02_v2_data',HERE/'data.py');D=importlib.util.module_from_spec(s);s.loader.exec_module(D)
LOCAL=('data.py','hosted_owner.py','host_tools.py','payload.py','retain.py','policy.json','README.md','admission.TEMPLATE.json','runtime.TEMPLATE.json','base-read-delta.json')
WORKFLOW='.github/workflows/native-arm-fish-config02-source-v2.yml'


def construct(base,workflow,output):
    base,workflow,output=map(Path,(base,workflow,output))
    D.need(all(p.is_absolute() and p==p.resolve() for p in (base,workflow,output))
           and not output.exists() and not output.is_relative_to(base),'fresh disjoint DATA output')
    body=D.read(base/D.BASE_PREFIX/'source-map.json');D.need(D.pin(body)==dict(bytes=D.BASE_MAP_BYTES,sha256=D.BASE_MAP),'fixed Source32 map')
    prior=D.decode(body);names=set(prior['files'])|{D.BASE_PREFIX+'source-map.json'}
    found={str(p.relative_to(base)) for p in base.rglob('*') if p.relative_to(base).parts[0]!='.git' and (p.is_file() or p.is_symlink())}
    D.need(found==names and len(names)==32,'complete exact Source32 namespace')
    bodies={}
    for name in sorted(names):
        raw=D.read(base/name);mode=stat.S_IMODE((base/name).stat().st_mode)
        D.need(mode==0o644 and (name not in prior['files'] or dict(D.pin(raw),mode=mode)==prior['files'][name]),'whole held Source32 body/mode')
        bodies['held-source32/'+name]=raw
    D.need(sum(map(len,bodies.values()))==D.BASE_BYTES,'whole held Source32 bytes')
    bodies.update({D.PREFIX+n:D.read(HERE/n) for n in LOCAL});bodies[WORKFLOW]=D.read(workflow)
    bodies['LICENSE']=bodies['held-source32/LICENSE']
    program=dict(schema=1,base_source_map_sha256=D.BASE_MAP,
                 files={n:dict(D.pin(raw),mode=0o644) for n,raw in sorted(bodies.items()) if not n.startswith('held-source32/')})
    program_raw=(json.dumps(program,indent=2,sort_keys=True)+'\n').encode()
    bodies[D.PREFIX+'owner-program.json']=program_raw
    value=dict(kind='FISH02_OWNED_HOSTED_SOURCE_V2',files={n:dict(D.pin(raw),mode=0o644) for n,raw in sorted(bodies.items())},
               actual=dict(source=None,ref=None,run=None,job=None,Root_admission=None,runtime=None,image=None,owner_domain=None,daemon_domain=None))
    bodies['source-map.json']=(json.dumps(value,indent=2,sort_keys=True)+'\n').encode()
    D.need(len(bodies)<48 and sum(map(len,bodies.values()))<2*1024**2,'finite successor closure')
    output.mkdir(mode=0o700)
    for name,raw in bodies.items():
        path=output/name;path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('xb') as stream:stream.write(raw)
        path.chmod(0o644)
    sha=D.pin(bodies['source-map.json'])['sha256'];D.source(output,sha)
    return dict(files=len(bodies),bytes=sum(map(len,bodies.values())),source_map=D.pin(bodies['source-map.json']),
                owner_program=D.pin(program_raw),bootstrap_resource_domain=D.pin(bodies[D.PREFIX+'policy.json']),actual=value['actual'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('base','workflow','output'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();print(json.dumps(construct(a.base,a.workflow,a.output),indent=2,sort_keys=True))
