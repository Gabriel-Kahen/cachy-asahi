#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Root-only final byte closure; no actor, secret, build or dispatch."""
import argparse
import json
from pathlib import Path
import contract as C


def freeze(source):
    source=C.safe(source.absolute());C.policy();C.held_source(source)
    here=source/'scripts/ci/expanded604-composition'
    C.need(here==C.HERE,'freeze only the adopted canonical lane')
    workflow=source/'.github/workflows/native-arm-expanded604.yml'
    names=set(C.read(here/'held-pins.json'))
    names|={p.relative_to(source).as_posix() for p in here.iterdir() if p.is_file() and p.name!='source-manifest.json'}
    C.need(0<len(names)<=512,'explicit604 source closure bound')
    files={}
    for name in sorted(names):
        path=C.safe(source/name);info=path.lstat()
        C.need(__import__('stat').S_ISREG(info.st_mode) and info.st_nlink==1 and info.st_size<=16*1024**2,'ordinary source closure member required')
        files[name]=dict(bytes=info.st_size,sha256=C.sha(path))
    manifest=here/'source-manifest.json'
    manifest.write_bytes(C.encoded(dict(schema_version=1,status='FROZEN_ROOT_FINAL_SOURCE',files=files,
        scope='PRIVATE_SIGNED604_COMPOSITION',native='NOT_RUN',hardware='NOT_RUN')))
    text=workflow.read_text()
    for marker,path in (('@OWNER_SHA256@',here/'run.py'),('@MANIFEST_SHA256@',manifest)):
        C.need(text.count(marker)==1,'Root must explicitly refresh both workflow markers')
        text=text.replace(marker,C.sha(path))
    workflow.write_text(text)
    C.verify_source(source)
    return dict(status='FROZEN_SOURCE_ONLY',files=len(files),manifest_sha256=C.sha(manifest),native='NOT_RUN',hardware='NOT_RUN')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source',type=Path,required=True)
    print(json.dumps(freeze(parser.parse_args().source),sort_keys=True))
