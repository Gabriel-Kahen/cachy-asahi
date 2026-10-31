#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Source-only freeze after staging the proposed setup5 overlay; no native actors."""
import argparse
import json
from pathlib import Path
import contract as C

PREREQUISITES=('LICENSE','scripts/build/build.py','scripts/build/compare.py','scripts/build/container-entry.sh',
 'scripts/checks/package_checks.py','scripts/virtual/common.py','scripts/ci/maintained-desktop574-inputs.json',
 'scripts/ci/maintained_desktop574.py','scripts/ci/old_four_seed.py','scripts/ci/test_maintained_desktop574.py',
 'scripts/ci/welcome-native/run.py','scripts/ci/welcome-native/lifecycle.py','scripts/ci/welcome-native/ci/caller.py',
 'scripts/ci/tools-native/run.py','scripts/ci/tools-native/job.py','scripts/setup/setup.py','scripts/setup/test_setup.py','scripts/setup/test_shell_modules.py')


def freeze(root):
    root=C.safe(root.absolute());here=root/'scripts/ci/setup5-native'
    C.need(here.resolve()==Path(__file__).resolve().parent,'freeze only the chosen adopted/private source root')
    recipe=C.recipe(root);base=json.loads((root/'scripts/ci/maintained-desktop574-inputs.json').read_text());packages={r['name']:r for r in base['packages']}
    C.need(len(packages)==574 and all(n in packages for n in ('python','pacman','gnupg')) and C.PACKAGE not in packages,'exact574 supplies setup dependencies without addon packages')
    names=set(PREREQUISITES)|{C.RECIPE+'/'+n for n in C.INPUTS}
    names|={str(p.relative_to(root)) for p in here.iterdir() if p.is_file() and p.name not in ('source-pins.json','source-manifest.json')}
    pins={n:C.digest(root/n) for n in sorted(names)};(here/'source-pins.json').write_text(json.dumps(pins,sort_keys=True,indent=2)+'\n');names.add('scripts/ci/setup5-native/source-pins.json')
    manifest=dict(schema_version=1,setup5_product_source='1542b27e2e11d43697ca9b1818aca553ea4a8111',scope='ONE_UNSELECTED_SETUP5_CANDIDATE',native_runtime='NOT_RUN',recipe=recipe,
        dependency_bindings={n:packages[n] for n in ('python','pacman','gnupg')},
        retained_setup4=dict(source='93bc9bfac7343ee3b443ae3332c0942ed1ba5b55',bytes=69776,sha256='1637452a84733fdf059d7dbc10c5b6dddd11c589c4f97ebb6a4655aedd12359f'),
        files={n:dict(bytes=(root/n).stat().st_size,sha256=C.digest(root/n)) for n in sorted(names)})
    (here/'source-manifest.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    workflow=root/'.github/workflows/native-arm-setup5-candidate.yml';text=workflow.read_text()
    for marker,path in (('@JOB_SHA256@',here/'job.py'),('@MANIFEST_SHA256@',here/'source-manifest.json')):
        C.need(text.count(marker)==1,'workflow marker absent; restore explicit markers before re-freezing');text=text.replace(marker,C.digest(path))
    workflow.write_text(text);return dict(status='FROZEN_SOURCE_ONLY',files=len(names),native='NOT_RUN',hardware='NOT_RUN')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);print(json.dumps(freeze(p.parse_args().source)))
