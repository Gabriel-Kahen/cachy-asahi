#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-only final source binding; refuses unfinished candidate data and never runs actors."""
import argparse
from pathlib import Path
import contract as C


def freeze(source):
    C.policy();C.verify_source(source);here=source/'scripts/ci/apps-cache-native'
    C.need(here==C.HERE,'run from adopted canonical source after final Root product binding')
    names=set(C.read(here/'infrastructure-pins.json'))
    names|={p.relative_to(source).as_posix() for p in here.iterdir() if p.is_file() and p.name!='source-manifest.json'}
    recipes={name:C.recipe(source,name) for name in C.NAMES}
    names|={('packages/tools/'+name+'/'+relative) for name,recipe in recipes.items() for relative in recipe['input_sha256']}
    C.need(len(names)<=128,'inherited source closure cap')
    value=dict(schema_version=1,status='FROZEN_ROOT_FINAL_SOURCES',native='NOT_RUN',hardware='NOT_RUN',recipes=recipes,
        files={name:dict(bytes=(source/name).stat().st_size,sha256=C.digest(source/name)) for name in sorted(names)})
    manifest=here/'source-manifest.json';manifest.write_bytes(C.encoded(value))
    workflow=source/'.github/workflows/native-arm-apps-cache-candidates.yml';text=workflow.read_text()
    for marker,path in (('@JOB_SHA256@',here/'job.py'),('@MANIFEST_SHA256@',manifest)):
        C.need(text.count(marker)==1,'Root must explicitly refresh the two workflow freeze markers')
        text=text.replace(marker,C.digest(path))
    workflow.write_text(text);return dict(status='FROZEN_SOURCE_ONLY',files=len(names),native='NOT_RUN',hardware='NOT_RUN')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);a=p.parse_args()
    print(__import__('json').dumps(freeze(C.safe(a.source.absolute())),sort_keys=True))
