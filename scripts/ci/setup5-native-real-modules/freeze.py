#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root's source-only freeze; no native/build/fetch/system actor."""
import argparse
import json
from pathlib import Path
import contract as C


PREREQUISITES=('scripts/ci/setup5-native/source-manifest.json','scripts/ci/setup5-native/source-pins.json','scripts/ci/setup5-real-modules/source-manifest.json','scripts/ci/expanded-development-composition/installed_shells.py','scripts/ci/tools-native/run.py','scripts/ci/tools-native/job.py')


def freeze(source):
    source=C.safe(source.absolute());here=source/'scripts/ci/setup5-native-real-modules';C.need(here==Path(__file__).resolve().parent,'freeze only the chosen private/adopted tree')
    C.policy();names=set(PREREQUISITES)|{str(p.relative_to(source)) for p in here.iterdir() if p.is_file() and p.name!='source-manifest.json'}
    manifest=dict(schema_version=1,scope='SETUP5_LEGACY_8_ALPM_24_OBSERVATIONS_THEN_EXACT581_REAL_MODULES',module_source_ref=C.policy()['module_source_ref'],native='NOT_RUN_BY_WORKER',files={n:dict(bytes=(source/n).stat().st_size,sha256=C.digest(source/n)) for n in sorted(names)})
    (here/'source-manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');C.verify_source(source);return manifest


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);a=p.parse_args();print(json.dumps(dict(status='FROZEN_SOURCE_ONLY',files=len(freeze(a.source)['files']))))
