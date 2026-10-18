#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Freeze only final adopted tool recipes, using the accepted producer closure."""
import argparse
import json
from pathlib import Path
import re
import contract as C


def freeze(source):
    source=C.safe(source.absolute());here=source/'scripts/ci/tools-native'
    C.need(here.resolve()==Path(__file__).resolve().parent,'freeze must run from the adopted canonical lane')
    C.final_spec()
    recipes={name:C.recipe(source,name) for name in C.NAMES}  # Missing unfinished product is a hard gate.
    for name in C.NAMES:
        for original,mode in C.files(name).values():C.need(original in recipes[name]['input_sha256'],'payload source absent: '+original)
    selected=json.loads((source/'scripts/ci/maintained-desktop574-inputs.json').read_text())
    base={r['name']:r for r in selected['packages']};dependencies={}
    for name,recipe in recipes.items():
        dependencies[name]=[]
        for key in ('depends','makedepends','checkdepends'):
            for relation in recipe['metadata'].get(key,[]):
                provider=re.split('[<>=]',relation,1)[0]
                C.need(provider in base,'missing offline dependency; no fetch allowed: '+relation)
                dependencies[name].append(dict(relation=relation,provider=provider,version=base[provider]['version'],
                                              actual_version_check='REQUIRED_PACMAN_T_AND_MAKEPKG_NATIVE'))
    accepted=json.loads((source/'scripts/ci/welcome-native/ci/source-manifest.json').read_text())['files']
    names={n for n in accepted if n.startswith(('scripts/build/','scripts/checks/','scripts/virtual/')) or n in (
        'scripts/ci/maintained-desktop574-inputs.json','scripts/ci/maintained_desktop574.py','scripts/ci/old_four_seed.py',
        'scripts/ci/test_maintained_desktop574.py','scripts/ci/welcome-native/run.py',
        'scripts/ci/welcome-native/lifecycle.py','scripts/ci/welcome-native/ci/caller.py')}
    names.add('scripts/ci/zsh-highlighting-native/terminal.py')
    names|={str(p.relative_to(source)) for name in C.NAMES for p in (source/'packages/tools'/name).iterdir()}
    names|={str(p.relative_to(source)) for p in here.iterdir() if p.is_file() and p.name not in ('source-pins.json','source-manifest.json')}
    pins={name:C.digest(source/name) for name in sorted(names)}
    (here/'source-pins.json').write_text(json.dumps(pins,sort_keys=True,indent=2)+'\n')
    names.add('scripts/ci/tools-native/source-pins.json')
    manifest=dict(schema_version=1,scope='THREE_UNSELECTED_TOOLS_CANDIDATES',native_runtime='NOT_RUN',
        dependencies=dependencies,recipes=recipes,files={name:dict(bytes=(source/name).stat().st_size,sha256=C.digest(source/name)) for name in sorted(names)})
    (here/'source-manifest.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    workflow=source/'.github/workflows/native-arm-tools-candidates.yml';text=workflow.read_text()
    for marker,path in (('@JOB_SHA256@',here/'job.py'),('@MANIFEST_SHA256@',here/'source-manifest.json')):
        C.need(text.count(marker)==1,'initial workflow freeze marker missing; Root must explicitly refresh frozen pins')
        text=text.replace(marker,C.digest(path))
    workflow.write_text(text)
    return dict(status='FROZEN_SOURCE_ONLY',files=len(names),manifest_sha256=C.digest(here/'source-manifest.json'),
                native='NOT_RUN',hardware='NOT_RUN')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',type=Path,required=True);args=parser.parse_args()
    print(json.dumps(freeze(args.source),sort_keys=True))
