#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Exact opt-in source/payload; original runtime files remain a dependency only."""
import argparse,hashlib,json,re,shlex,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PREFIX='usr/share/cachy-asahi/repository-runtime/'

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--recipe-root',type=Path,default=HERE);p.add_argument('--stage',type=Path);a=p.parse_args();root=a.recipe_root;recipe=(root/'PKGBUILD').read_text()
 names=shlex.split(re.search(r'^source=\((.*?)\)',recipe,re.M|re.S)[1]);sums=shlex.split(re.search(r'^sha256sums=\((.*?)\)',recipe,re.M|re.S)[1]);assert len(names)==len(sums)==len(set(names))==9
 for name,digest in zip(names,sums):
  f=root/name;assert Path(name).name==name and not f.is_symlink()and f.is_file()and re.fullmatch('[a-f0-9]{64}',digest)and hashlib.sha256(f.read_bytes()).hexdigest()==digest
  if name.endswith('.py'):compile(f.read_bytes(),name,'exec')
 pins=json.loads((root/'helper-pins.json').read_bytes());assert set(pins['files'])=={'scripts/client/client_v2.py'};raw=(root/'client_v2.py').read_bytes();assert pins['files']['scripts/client/client_v2.py']==dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest());assert len(raw)==28763 and hashlib.sha256(raw).hexdigest()=='915c2336a6515dcbde9801d7778c0aeae3a0251cf6463c4704d47590d94d1409'
 dependency=pins['required_runtime'];assert dependency['package']=='cachy-asahi-repository-runtime'and dependency['version']=='0.1.0-1'and set(dependency['files'])=={'scripts/client/client.py','scripts/release/release.py','scripts/release/source_delivery.py'}
 assert set(pins['files']).isdisjoint(dependency['files'])and 'Permission is hereby granted'in(root/'LICENSE').read_text()
 info={}
 for line in(root/'.SRCINFO').read_text().splitlines():
  if line.strip():k,v=line.strip().split(' = ',1);info.setdefault(k,[]).append(v)
 assert info['source']==names and info['sha256sums']==sums and info['pkgname']==['cachy-asahi-repository-client-v2']and info['pkgver']==['0.1.0']and info['pkgrel']==['1']and info['arch']==['any']and info['license']==['MIT']and info['depends']==['python>=3.11','cachy-asahi-repository-runtime=0.1.0-1']and not list(root.glob('*.install'))
 payload={PREFIX+'scripts/client/client_v2.py':'client_v2.py'}
 for n in('README.md','source-provenance.json','helper-pins.json'):payload['usr/share/doc/cachy-asahi-repository-client-v2/'+n]=n
 for n in('LICENSE','NOTICE'):payload['usr/share/licenses/cachy-asahi-repository-client-v2/'+n]=n
 if a.stage:
  actual={f.relative_to(a.stage).as_posix()for f in a.stage.rglob('*')if f.is_file()};assert actual==set(payload)
  for n,source in payload.items():
   f=a.stage/n;assert not f.is_symlink()and stat.S_IMODE(f.stat().st_mode)==0o644 and f.read_bytes()==(root/source).read_bytes()
 print(json.dumps(dict(status='PASS_OPT_IN_COMPANION_EXACT_SOURCE_AND_PAYLOAD',sources=9,helper_files=1,helper_bytes=28763,installed_files=6,stage='PASS'if a.stage else'NOT_RUN',native_build='NOT_RUN',installed_ALPM_lifecycle='NOT_RUN'),sort_keys=True))

if __name__=='__main__':main()
