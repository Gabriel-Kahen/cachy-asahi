#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-only closed source freeze; no actor, authority creation or native credit."""
import argparse,json
from pathlib import Path
import contract as C
import repair

def freeze(source):
 C.policy();C.verify_source(source);here=source/'scripts/ci/apps6-native-reinstall'
 C.need(here==C.HERE,'freeze only the adopted candidate checkout')
 names=set(C.read(here/'infrastructure-pins.json'))|set(repair.DEPENDENCIES)
 names|={p.relative_to(source).as_posix() for p in here.iterdir() if p.is_file() and p.name!='source-manifest.json'}
 recipes={name:C.recipe(source,name) for name in C.NAMES}
 names|={'packages/tools/'+name+'/'+p for name,r in recipes.items() for p in r['input_sha256']}
 C.need(len(names)<=128,'original finite128 source manifest bound')
 value=dict(schema_version=1,status='FROZEN_ROOT_FINAL_SOURCES',native='NOT_RUN',hardware='NOT_RUN',recipes=recipes,files={n:dict(bytes=(source/n).stat().st_size,sha256=C.digest(source/n)) for n in sorted(names)})
 manifest=here/'source-manifest.json';manifest.write_bytes(C.encoded(value))
 wf=source/'.github/workflows/native-arm-apps6-reinstall.yml';text=wf.read_text()
 for marker,path in (('@JOB_SHA256@',here/'job.py'),('@MANIFEST_SHA256@',manifest)):
  C.need(text.count(marker)==1,'two explicit Root workflow freeze placeholders required');text=text.replace(marker,C.digest(path))
 wf.write_text(text);return dict(status='FROZEN_APPS6_SOURCE_ONLY',files=len(names),native='NOT_RUN')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);a=p.parse_args();print(json.dumps(freeze(a.source.absolute()),sort_keys=True))
