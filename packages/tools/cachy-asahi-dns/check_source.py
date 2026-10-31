#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Exact source and optional owned disposable payload inspection; no nmcli calls."""
import argparse,hashlib,json,re,shlex,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--recipe-root',type=Path,default=HERE);p.add_argument('--stage',type=Path);a=p.parse_args();root=a.recipe_root;recipe=(root/'PKGBUILD').read_text()
 names=shlex.split(re.search(r'^source=\((.*?)\)',recipe,re.M|re.S)[1]);pins=shlex.split(re.search(r'^sha256sums=\((.*?)\)',recipe,re.M|re.S)[1]);assert len(names)==len(pins)==len(set(names))==7
 for name,digest in zip(names,pins):
  f=root/name;assert Path(name).name==name and not f.is_symlink()and f.is_file()and re.fullmatch('[a-f0-9]{64}',digest)and hashlib.sha256(f.read_bytes()).hexdigest()==digest
  if name.endswith('.py')or name=='cachy-asahi-dns':compile(f.read_bytes(),name,'exec')
 info={}
 for line in(root/'.SRCINFO').read_text().splitlines():
  if line.strip():key,v=line.strip().split(' = ',1);info.setdefault(key,[]).append(v)
 assert info['pkgname']==['cachy-asahi-dns']and info['pkgver']==['0.1.0']and info['pkgrel']==['1']and info['arch']==['any']and info['license']==['MIT']and info['depends']==['python>=3.11','networkmanager>=1.44']and info['source']==names and info['sha256sums']==pins and not list(root.glob('*.install'))
 provenance=json.loads((root/'source-provenance.json').read_bytes());raw=(root/'cachy-asahi-dns').read_bytes();assert provenance['installed_program']==dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
 payload={'usr/bin/cachy-asahi-dns':('cachy-asahi-dns',0o755)}
 for name in('README.md','source-provenance.json'):payload['usr/share/doc/cachy-asahi-dns/'+name]=(name,0o644)
 for name in('NOTICE','LICENSE'):payload['usr/share/licenses/cachy-asahi-dns/'+name]=(name,0o644)
 if a.stage:
  actual={f.relative_to(a.stage).as_posix()for f in a.stage.rglob('*')if f.is_file()};assert actual==set(payload)
  for name,(original,mode)in payload.items():
   f=a.stage/name;assert not f.is_symlink()and stat.S_IMODE(f.stat().st_mode)==mode and f.read_bytes()==(root/original).read_bytes()
 print(json.dumps(dict(status='PASS_DNS_SOURCE_AND_OPTIONAL_STAGE',sources=7,payload=5,stage='PASS'if a.stage else'NOT_RUN',native='NOT_RUN',ALPM='NOT_RUN',live_DNS='NOT_TESTED'),sort_keys=True))

if __name__=='__main__':main()
