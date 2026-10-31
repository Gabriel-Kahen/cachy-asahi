#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Check local recipe/source/helper pins and an optional disposable staged payload."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shlex
import stat
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).absolute().parent
PAYLOAD={'usr/bin/cachy-asahi-apps':('cachy-asahi-apps',0o755),
 'usr/lib/cachy-asahi-apps/inventory.py':('inventory.py',0o644),
 'usr/lib/cachy-asahi-apps/apps.py':('apps.py',0o644),
 'usr/lib/cachy-asahi-apps/helper-pins.json':('helper-pins.json',0o644),
 'usr/share/doc/cachy-asahi-apps/README.md':('README.md',0o644),
 'usr/share/doc/cachy-asahi-apps/source-provenance.json':('source-provenance.json',0o644),
 'usr/share/licenses/cachy-asahi-apps/NOTICE':('NOTICE',0o644),
 'usr/share/licenses/cachy-asahi-apps/LICENSE':('LICENSE',0o644)}

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--repository-source',type=Path,required=True)
    parser.add_argument('--recipe-root',type=Path,default=HERE);parser.add_argument('--stage',type=Path);args=parser.parse_args()
    root=args.recipe_root;recipe=(root/'PKGBUILD').read_text()
    sources=shlex.split(re.search(r'^source=\((.*?)\)',recipe,re.M|re.S)[1]);pins=shlex.split(re.search(r'^sha256sums=\((.*?)\)',recipe,re.M|re.S)[1])
    assert len(sources)==len(pins)==len(set(sources))
    for name,pin in zip(sources,pins):
        assert Path(name).name==name and re.fullmatch('[0-9a-f]{64}',pin)
        path=root/name;assert not path.is_symlink() and path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest()==pin,name
        if name.endswith('.py'):compile(path.read_bytes(),name,'exec')
    assert "arch=('any')" in recipe and "license=('MIT')" in recipe and not list(root.glob('*.install'))
    assert 'cachy-asahi-repository-runtime=0.1.0-1' in recipe
    compile((root/'cachy-asahi-apps').read_bytes(),'cachy-asahi-apps','exec')
    assert 'Permission is hereby granted' in (root/'LICENSE').read_text()
    info={}
    for line in (root/'.SRCINFO').read_text().splitlines():
        if not line.strip() or line.lstrip().startswith('#'):continue
        key,value=line.strip().split(' = ',1);info.setdefault(key,[]).append(value)
    assert info['source']==sources and info['sha256sums']==pins and info['pkgname']==['cachy-asahi-apps']
    assert info['pkgver']==['0.1.0'] and info['pkgrel']==['6'] and info['arch']==['any'] and info['license']==['MIT']
    spec=importlib.util.spec_from_file_location('checked_apps',root/'apps.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    _,_,helpers=module.helpers(args.repository_source)
    if args.stage:
        stage=args.stage;actual={p.relative_to(stage).as_posix() for p in stage.rglob('*') if p.is_file()}
        assert actual==set(PAYLOAD)
        for name,(source,mode) in PAYLOAD.items():
            path=stage/name;assert not path.is_symlink() and stat.S_IMODE(path.stat().st_mode)==mode
            assert path.read_bytes()==(root/source).read_bytes()
    print(json.dumps(dict(status='PASS_SOURCE_AND_STAGING_CONTRACT',sources=len(sources),runtime_helpers=len(helpers),installed_files=len(PAYLOAD),
         stage='PASS' if args.stage else 'NOT_RUN',native_build='NOT_RUN',installed_lifecycle='NOT_RUN'),sort_keys=True))

if __name__=='__main__':main()
