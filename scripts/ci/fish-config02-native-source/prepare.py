#!/usr/bin/python3 -I -B
# SPDX-License-Identifier: MIT
"""Pure DATA constructor for the minimal fixed Fish02 hosted Source."""
import argparse
import importlib.util
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('fish02_contract',HERE/'contract.py');C=importlib.util.module_from_spec(s);s.loader.exec_module(C)
LOCAL=('README.md','contract.py','entry.py','finish_pair.py','profile.json','expected349.lock','reviewed-inputs.json','admission.TEMPLATE.json','runtime.TEMPLATE.json')
CHECKER = 'runtime/scripts/checks/package_checks.py'
HELD_CHECKER = ('scripts/ci/llhttp-minimal-native-source-data/fixtures/Source95/held-source/'
                'scripts/ci/llhttp-reference-native-source/base/' + CHECKER)


def construct(root,output):
    root=C.ordinary(root);output=C.ordinary(output);C.need(not output.exists()and root not in output.parents,'new disjoint Source output')
    profile=C.load(HERE/'profile.json');C.need(all(v is None for v in profile['actual'].values()),'prospective actual selectors remain null')
    bodies={C.PREFIX+'/'+n:C.read(HERE/n)for n in LOCAL};bodies[C.WORKFLOW]=C.read(root/C.WORKFLOW)
    for name,row in profile['held_inputs'].items():
        source = HELD_CHECKER if name == CHECKER else row['source_path']
        body=C.read(root/source);C.need(C.pin(body)=={n:row[n]for n in('bytes','sha256')},'exact Main held input: '+name)
        target=C.PREFIX+'/'+name
        C.need(target not in bodies or bodies[target]==body,'duplicate Source leaf differs');bodies[target]=body
    license=C.read(root/'LICENSE');C.need(C.pin(license)==C.pin(bodies[C.PREFIX+'/recipe/LICENSE']),'same exact original MIT license');bodies['LICENSE']=license
    body=bodies[C.PREFIX+'/runtime/scripts/build/build_v2.py'];bodies[C.PREFIX+'/runtime/scripts/build/build_fish02.py']=C.projected_build(body)
    C.need(C.pin(bodies[C.PREFIX+'/finish_pair.py'])==profile['finisher'],'exact unchanged release finisher')
    C.need(sum(map(len,bodies.values()))<2*1024**2,'small finite Source byte budget')
    output.mkdir(mode=0o700)
    for name,body in bodies.items():
        path=output/name;path.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
        with path.open('xb')as stream:stream.write(body)
        path.chmod(0o644)
    value=dict(kind='FISH02_MINIMAL_HOSTED_SOURCE_MAP_V1',files={n:dict(C.pin(v),mode=0o644)for n,v in sorted(bodies.items())},actual=profile['actual'])
    raw=(json.dumps(value,indent=2,sort_keys=True)+'\n').encode();path=output/C.PREFIX/'source-map.json';path.write_bytes(raw);path.chmod(0o644)
    C.verify_source(output,C.pin(raw)['sha256']);return dict(output=str(output),files=len(bodies)+1,bytes=sum(map(len,bodies.values()))+len(raw),source_map=C.pin(raw),actual=profile['actual'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(construct(a.root,a.output),indent=2,sort_keys=True))
