#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root final source freeze; no actors, builds, keys or dispatch."""
import argparse
from pathlib import Path
import contract as C


def freeze(source):
    source=C.safe(source.absolute());C.policy();C.verify_source(source);here=source/'scripts/ci/orphans-native'
    C.need(here==C.HERE,'freeze only the adopted canonical lane')
    recipes={name:C.recipe(source,name) for name in C.NAMES}
    selected=C.read(source/'scripts/ci/maintained-desktop574-inputs.json');base={r['name']:r for r in selected['packages']}
    dependencies=[]
    for relation in recipes[C.PRODUCT]['metadata']['depends']:
        name=relation.split('>=')[0];C.need(name in base,'missing offline dependency; no waiver or fetch')
        dependencies.append(dict(relation=relation,provider=name,version=base[name]['version'],native_check='MANDATORY_PACMAN_T_AND_STANDARD_MAKEPKG'))
    names=set(C.read(here/'infrastructure-pins.json'))
    names|={p.relative_to(source).as_posix() for p in here.iterdir() if p.is_file() and p.name!='source-manifest.json'}
    names|={'packages/tools/'+C.PRODUCT+'/'+name for name in C.policy()['source_files']}
    C.need(len(names)<=128,'inherited source closure bound')
    value=dict(schema_version=1,status='FROZEN_ROOT_FINAL_SOURCE',scope='ONE_UNSELECTED_READONLY_ORPHAN_CANDIDATE',native='NOT_RUN',hardware='NOT_RUN',
        recipes=recipes,dependencies=dependencies,files={name:dict(bytes=(source/name).stat().st_size,sha256=C.digest(source/name)) for name in sorted(names)})
    manifest=here/'source-manifest.json';manifest.write_bytes(C.encoded(value))
    workflow=source/'.github/workflows/native-arm-orphans-candidate.yml';text=workflow.read_text()
    for marker,path in (('@JOB_SHA256@',here/'job.py'),('@MANIFEST_SHA256@',manifest)):
        C.need(text.count(marker)==1,'Root must explicitly refresh the two workflow freeze markers');text=text.replace(marker,C.digest(path))
    workflow.write_text(text);return dict(status='FROZEN_SOURCE_ONLY',files=len(names),manifest_sha256=C.digest(manifest),native='NOT_RUN',hardware='NOT_RUN')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);a=p.parse_args()
    print(__import__('json').dumps(freeze(a.source),sort_keys=True))
