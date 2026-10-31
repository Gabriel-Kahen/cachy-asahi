#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce KSM worker/bridge roles from exact code-only basis and native source."""
import argparse,hashlib,json,shutil,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;LANE='scripts/ci/current606-ksm2-copy'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def read(path):
 need(not any(p.is_symlink()for p in(path,*path.parents))and path.is_file()and path.stat().st_nlink==1 and path.stat().st_size<=16*1024**2,'ordinary bounded singlelink source');return path.read_bytes()
def files(root):return {p.relative_to(root).as_posix()for p in root.rglob('*')if p.is_file()and p.relative_to(root).parts[0]!='.git'}
def roles(basis,native,output,owner):
 need(output.is_absolute()and not output.exists()and output.parent.is_dir()and not any(p.is_symlink()for p in(output,*output.parents)),'fresh ordinary source output')
 pins=json.loads(read(HERE/'dependency-pins.json'))
 for home,key in((basis,'basis'),(native,'native')):
  need(home.is_absolute()and home.is_dir()and files(home)==set(pins[key]),'whole explicit dependency source role')
  for name,row in pins[key].items():need(pin(read(home/name))==row,'whole dependency source pin')
 output.mkdir(mode=0o700);shutil.copytree(basis/'held606',output/'held606');shutil.copytree(basis/'bridge',output/'bridge');shutil.copytree(basis/'copyworker/held-copy',output/'copyworker/held-copy')
 target=output/'copyworker'/LANE;target.mkdir(parents=True)
 for p in HERE.iterdir():
  if p.is_file()and p.name not in('source-manifest.json','role-pins.json'):shutil.copyfile(p,target/p.name)
 shutil.copytree(native/'packages/tools/cachy-asahi-ksmctl2',output/'copyworker/held-ksm/source');(output/'copyworker/held-ksm/checks').mkdir()
 shutil.copyfile(native/'scripts/ci/ksm2-upgrade-native/fixture_checks.py',output/'copyworker/held-ksm/fixture_checks.py');shutil.copyfile(basis/'copyworker/held-apps/checks/package_checks.py',output/'copyworker/held-ksm/checks/package_checks.py')
 for p in(output/'bridge').rglob('*.py'):p.write_text(p.read_text().replace('CURRENT606_APPS7','CURRENT606_KSM2'))
 api=pin(read(owner/'selection.py'));(target/'owner-api.json').write_bytes(encoded(dict(path='/runner/owner/selection.py',**api)));(output/'bridge/scripts/ci/current606-welcome5-source-bridge/owner-api.json').write_bytes(encoded(dict(path='/runner/owner/selection.py',pin=api)))
 for home,path in((output/'copyworker',LANE+'/source-manifest.json'),(output/'bridge','scripts/ci/current606-welcome5-source-bridge/source-manifest.json')):
  manifest=home/path;value=json.loads(manifest.read_bytes())if manifest.exists()else dict(status='SOURCE_ONLY_COPY_WORKER_NOT_NATIVE_ACCEPTANCE');value['files']={n:pin(read(home/n))for n in sorted(files(home)-{path})};manifest.write_bytes(encoded(value))
 held={p.relative_to(output/'copyworker').as_posix():dict(**pin(read(p)),scope='EXACT_SOURCE_ONLY_NOT_NATIVE_ACCEPTANCE')for role in('held-copy','held-ksm')for p in(output/'copyworker'/role).rglob('*')if p.is_file()};(target/'role-pins.json').write_bytes(encoded(held))
 # Refresh worker manifest after writing exact held-role provenance.
 manifest=target/'source-manifest.json';value=json.loads(manifest.read_bytes());value['files']={n:pin(read(output/'copyworker'/n))for n in sorted(files(output/'copyworker')-{LANE+'/source-manifest.json'})};manifest.write_bytes(encoded(value))
 return dict(status='SOURCE_ONLY_ROLES_NO_NATIVE_OR_PUBLIC_AUTHORITY',roles={n:len(files(output/n))for n in('held606','bridge','copyworker')})
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('basis-source','native-source','owner-source','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(roles(a.basis_source.absolute(),a.native_source.absolute(),a.output.absolute(),a.owner_source.absolute()),sort_keys=True))
