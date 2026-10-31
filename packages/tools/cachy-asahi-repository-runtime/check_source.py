#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Byte-exact three-helper source and disposable installed-payload checks."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import stat

HERE=Path(__file__).absolute().parent
PREFIX='usr/share/cachy-asahi/repository-runtime/'

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--recipe-root',type=Path,default=HERE)
    parser.add_argument('--stage',type=Path);args=parser.parse_args();root=args.recipe_root
    recipe=(root/'PKGBUILD').read_text()
    sources=shlex.split(re.search(r'^source=\((.*?)\)',recipe,re.M|re.S)[1]);pins=shlex.split(re.search(r'^sha256sums=\((.*?)\)',recipe,re.M|re.S)[1])
    assert len(sources)==len(pins)==len(set(sources))==9
    for name,pin in zip(sources,pins):
        assert Path(name).name==name and re.fullmatch('[0-9a-f]{64}',pin)
        path=root/name;assert not path.is_symlink() and path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest()==pin,name
        if name.endswith('.py'):compile(path.read_bytes(),name,'exec')
    helper_pins=json.loads((root/'helper-pins.json').read_bytes())['files']
    assert set(helper_pins)=={'scripts/client/client.py','scripts/release/release.py','scripts/release/source_delivery.py'}
    payload={}
    for name,row in helper_pins.items():
        source=Path(name).name;raw=(root/source).read_bytes()
        assert dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==row
        assert b'SPDX-License-Identifier: MIT' in raw[:200]
        payload[PREFIX+name]=source
    assert sum(p['bytes'] for p in helper_pins.values())==86445
    for name in ('README.md','source-provenance.json','helper-pins.json'):
        payload['usr/share/doc/cachy-asahi-repository-runtime/'+name]=name
    for name in ('LICENSE','NOTICE'):payload['usr/share/licenses/cachy-asahi-repository-runtime/'+name]=name
    info={}
    for line in (root/'.SRCINFO').read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):continue
        key,value=line.strip().split(' = ',1);info.setdefault(key,[]).append(value)
    assert info['source']==sources and info['sha256sums']==pins
    assert info['pkgname']==['cachy-asahi-repository-runtime'] and info['pkgver']==['0.1.0'] and info['pkgrel']==['1']
    assert info['arch']==['any'] and info['license']==['MIT'] and not list(root.glob('*.install'))
    assert 'Permission is hereby granted' in (root/'LICENSE').read_text()
    if args.stage:
        actual={p.relative_to(args.stage).as_posix() for p in args.stage.rglob('*') if p.is_file()}
        assert actual==set(payload)
        for name,source in payload.items():
            target=args.stage/name;assert not target.is_symlink() and stat.S_IMODE(target.stat().st_mode)==0o644
            assert target.read_bytes()==(root/source).read_bytes()
        helpers={p.relative_to(args.stage/PREFIX).as_posix() for p in (args.stage/PREFIX).rglob('*') if p.is_file()}
        assert helpers==set(helper_pins)
    print(json.dumps(dict(status='PASS_EXACT_THREE_HELPERS_AND_STAGE',helper_files=3,helper_bytes=86445,sources=9,
        installed_files=8,stage='PASS' if args.stage else 'NOT_RUN',native_build='NOT_RUN',installed_lifecycle='NOT_RUN'),sort_keys=True))

if __name__=='__main__':main()
