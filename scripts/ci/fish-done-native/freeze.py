#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Freeze final Fish input and inherited helper bytes, never build a package."""
import argparse
import json
from pathlib import Path
import contract as C

PREREQUISITES=('scripts/build/build.py','scripts/build/compare.py','scripts/build/container-entry.sh',
 'scripts/checks/package_checks.py','scripts/virtual/common.py','scripts/ci/maintained-desktop574-inputs.json',
 'scripts/ci/maintained_desktop574.py','scripts/ci/old_four_seed.py','scripts/ci/test_maintained_desktop574.py',
 'scripts/ci/welcome-native/run.py','scripts/ci/welcome-native/lifecycle.py','scripts/ci/welcome-native/ci/caller.py',
 'scripts/ci/tools-native/run.py','scripts/ci/tools-native/job.py')


def freeze(root):
    root=C.safe(root.absolute());here=root/'scripts/ci/fish-done-native'
    C.need(here.resolve()==Path(__file__).resolve().parent,'freeze must run from adopted Fish lane')
    recipe=C.recipe(root);selected=json.loads((root/'scripts/ci/maintained-desktop574-inputs.json').read_text())
    packages={r['name']:r for r in selected['packages']}
    C.need(len(packages)==574 and packages['fish']['version']=='4.9.3-1' and all(n in packages for n in ('python','libnotify','coreutils')),'held Fish/libnotify/coreutils/Python binding differs')
    names=set(PREREQUISITES)|{str(p.relative_to(root)) for p in (root/'packages/tools'/C.PACKAGE).iterdir()}
    names|={str(p.relative_to(root)) for p in here.iterdir() if p.is_file() and p.name not in ('source-pins.json','source-manifest.json')}
    pins={name:C.digest(root/name) for name in sorted(names)}
    (here/'source-pins.json').write_text(json.dumps(pins,sort_keys=True,indent=2)+'\n');names.add('scripts/ci/fish-done-native/source-pins.json')
    manifest=dict(schema_version=1,scope='ONE_UNSELECTED_FISH_DONE_CANDIDATE',native_runtime='NOT_RUN',recipe=recipe,
        dependency_bindings={n:packages[n] for n in ('fish','python','libnotify','coreutils')},
        files={name:dict(bytes=(root/name).stat().st_size,sha256=C.digest(root/name)) for name in sorted(names)})
    (here/'source-manifest.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    workflow=root/'.github/workflows/native-arm-fish-done-candidate.yml';text=workflow.read_text()
    for marker,path in (('@JOB_SHA256@',here/'job.py'),('@MANIFEST_SHA256@',here/'source-manifest.json')):
        C.need(text.count(marker)==1,'initial workflow marker absent; Root must refresh its frozen pins explicitly');text=text.replace(marker,C.digest(path))
    workflow.write_text(text)
    return dict(status='FROZEN_SOURCE_ONLY',files=len(names),native='NOT_RUN',hardware='NOT_RUN')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',type=Path,required=True)
    print(json.dumps(freeze(parser.parse_args().source),sort_keys=True))
