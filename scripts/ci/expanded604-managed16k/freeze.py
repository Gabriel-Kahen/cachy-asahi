#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit Root-only source materialization; records current bytes, never accepts actuals."""
import argparse
from pathlib import Path
import hashlib
import json
HERE=Path(__file__).resolve().parent
PREFIX='scripts/ci/expanded604-managed16k/'

def freeze(root):
    def read(p):return json.loads((root/p).read_bytes())
    names=set()
    for name in ('managed-gui-generic16k/ci/source-manifest.json','welcome-management-native/source-manifest.json','expanded604-installer-vm/source-manifest.json'):
        path='scripts/ci/'+name;names.add(path);names.update(read(path)['files'])
    for name in ('scripts/ci/managed-gui-generic16k/dependencies.json','scripts/ci/welcome-management-native/infrastructure-pins.json'):
        names.add(name);value=read(name);names.update(value.get('files',value))
    names|={p.relative_to(root).as_posix() for p in (root/PREFIX).iterdir() if p.is_file() and p.name not in ('dependencies.json','source-manifest.json')}
    names={n for n in names if not n.startswith('.github/workflows/')}
    assert 1<=len(names)<=512
    files={}
    for n in sorted(names):
        p=root/n;assert p.is_file() and not any(x.is_symlink() for x in (p,*p.parents)) and p.stat().st_nlink==1 and 0<p.stat().st_size<=16*1024**2
        raw=p.read_bytes();files[n]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    raw=(json.dumps(dict(schema_version=1,status='SOURCE_ONLY_NOT_NATIVE_ACCEPTANCE',files=files),sort_keys=True,indent=2)+'\n').encode()
    (root/PREFIX/'dependencies.json').write_bytes(raw)
    manifest=dict(schema_version=1,status='ROOT_FROZEN_SOURCE_ONLY',files=files|{PREFIX+'dependencies.json':dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())},hardware='NOT_RUN')
    data=(json.dumps(manifest,sort_keys=True,indent=2)+'\n').encode();(root/PREFIX/'source-manifest.json').write_bytes(data)
    workflow=root/'.github/workflows/native-arm-expanded604-managed16k.yml'
    if workflow.exists():
        text=workflow.read_text()
        for marker,path in (('@OWNER_SHA256@',root/PREFIX/'ci.py'),('@MANIFEST_SHA256@',root/PREFIX/'source-manifest.json')):
            assert text.count(marker)==1; text=text.replace(marker,hashlib.sha256(path.read_bytes()).hexdigest())
        workflow.write_text(text)
    return manifest
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);print(json.dumps(dict(files=len(freeze(p.parse_args().source)['files']),native='NOT_RUN')))
