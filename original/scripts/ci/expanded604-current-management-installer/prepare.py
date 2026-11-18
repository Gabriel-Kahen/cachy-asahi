#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite current604 installer source emission; no actor or Root acceptance."""
import argparse,ast,hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='scripts/ci/expanded604-installer-vm';NEW='scripts/ci/expanded604-current-management-installer'
NATIVE='scripts/ci/expanded604-current-management'
OLD_TARGET='76c37db5eb097662f4a9ca0465680de285466b0443916a50255ea5b8f6d6c946'
TARGET='3f64a13c4af7ab8b1598583f534af3347c8df2397a0afa33fb8b0f5f06b19cf5'
OWN=('prepare.py','adapter.py','policy.json','source-pins.json','test_current.py','README.md')
MODULES=('contract.py','ci.py','gate.py','freeze.py','test_adapter.py','test_source.py')
WORKFLOW='.github/workflows/native-arm-expanded604-current-management-installer.yml'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def source(root):
 rows=json.loads((HERE/'source-pins.json').read_bytes())['files'];need(0<len(rows)<=512,'finite current604 installer source closure')
 for n,row in rows.items():
  p=root/n;need(not any(x.is_symlink() for x in (p,*p.parents)) and p.is_file() and p.stat().st_nlink==1 and p.stat().st_size<=16*1024**2 and pin(p.read_bytes())==row,'exact current604 installer support: '+n)
 return rows

def adapt(raw,name):
 text=raw.decode();before={n.name:ast.get_source_segment(text,n) for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
 # Explicit lane/target/authority identities. No runtime, numeric or deadline edits.
 changes={OLD:NEW,'expanded604-composition':'expanded604-current-management',OLD_TARGET:TARGET,
  'ROOT_BOUND_NATIVE604_ACCEPTANCE':'ROOT_BOUND_CURRENT604_NATIVE_ACCEPTANCE',
  'ROOT_ACCEPTED_NATIVE_EXPANDED604_COMPOSITION':'ROOT_ACCEPTED_NATIVE_CURRENT604_COMPOSITION'}
 if name in ('contract.py','ci.py'):
  changes['expanded604-installer-vm']='expanded604-current-management-installer'
  if name=='ci.py':changes['GENERIC4K_SIGNED604_FRESH_INSTALLER_SOFTWARE_ONLY']='GENERIC4K_CURRENT_SIGNED604_FRESH_INSTALLER_SOFTWARE_ONLY'
 if name in ('test_adapter.py','test_source.py'):
  changes.update({'PASS_EXPANDED604_INSTALLER':'PASS_CURRENT604_INSTALLER','cachy-asahi.expanded604-installer=':'cachy-asahi.current604-installer=','native-arm-expanded604-installer-vm.yml':'native-arm-expanded604-current-management-installer.yml'})
 edits={}
 for a,b in changes.items():
  count=text.count(a)
  if count:edits[a]=count;text=text.replace(a,b)
 if name=='contract.py':
  anchor="    names.add('scripts/ci/expanded604-current-management/source-manifest.json')\n"
  need(text.count(anchor)==1,'one Root freeze source-closure anchor')
  text=text.replace(anchor,anchor+"    names.update(read(HERE/'source-pins.json')['files'])\n")
 ast.parse(text);after={n.name:ast.get_source_segment(text,n) for n in ast.parse(text).body if isinstance(n,ast.FunctionDef)}
 return text.encode(),dict(literal_identities=edits,unchanged=sorted(n for n in before if before[n]==after[n]),changed=sorted(n for n in before if before[n]!=after[n]))

def emit(root,output):
 rows=source(root);need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary installer source output');output.mkdir(mode=0o700)
 for n in rows:
  p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((root/n).read_bytes())
 lane=output/NEW;lane.mkdir(parents=True,exist_ok=True)
 for n in OWN:(lane/n).write_bytes((HERE/n).read_bytes())
 receipt={}
 for n in MODULES:raw,receipt[n]=adapt((root/OLD/n).read_bytes(),n);(lane/n).write_bytes(raw)
 lock=(root/NATIVE/'expected604.lock').read_bytes();need(pin(lock)['sha256']==TARGET,'exact current604 native lock');(lane/'expected604.lock').write_bytes(lock);(lane/'input-policy.json').write_bytes((HERE/'policy.json').read_bytes())
 files={n:pin((output/n).read_bytes()) for n in rows};files.update({p.relative_to(output).as_posix():pin(p.read_bytes()) for p in lane.iterdir() if p.is_file()});manifest=dict(schema_version=1,status='FROZEN_ROOT_FINAL_SOURCE',files=files,scope='CURRENT604_INSTALLER_SOURCE_ONLY_UNBOUND_NO_RUNTIME_CREDIT',native='NOT_RUN',hardware='NOT_RUN');(lane/'source-manifest.json').write_bytes(encoded(manifest))
 text=(root/'.github/workflows/native-arm-expanded604-installer-vm.yml').read_text().replace('native-arm-expanded604-installer-vm','native-arm-expanded604-current-management-installer').replace(OLD,NEW)
 for a,b in ((pin((root/OLD/'ci.py').read_bytes())['sha256'],pin((lane/'ci.py').read_bytes())['sha256']),(pin((root/OLD/'source-manifest.json').read_bytes())['sha256'],pin((lane/'source-manifest.json').read_bytes())['sha256'])):need(text.count(a)==1,'exact original installer workflow stamp');text=text.replace(a,b)
 # Preserve both original suites; add only this lane's focused source controls.
 text=text.replace("          EXPANDED604_SOURCE: ${{ github.workspace }}/expanded604-installer", "          CURRENT604_INSTALLER_SOURCE: ${{ github.workspace }}/expanded604-installer\n          EXPANDED604_SOURCE: ${{ github.workspace }}/expanded604-installer",1)
 wf=output/WORKFLOW;wf.parent.mkdir(parents=True,exist_ok=True);wf.write_text(text)
 result=dict(status='SOURCE_ONLY_CURRENT604_FRESH_INSTALLER_UNBOUND',sources=len(rows),functions=receipt,expected604_sha256=TARGET,workflow=pin(wf.read_bytes()),native604_acceptance='UNBOUND_NOT_FABRICATED',current_input_packet=json.loads((root/NATIVE/'input-policy.json').read_bytes())['welcome']['carrier_source'],current_installer='NOT_RUN',GUI='FAIL_NOT_ACCEPTED',hardware='NOT_RUN',release='NOT_ADMITTED');(output/'installer-adaptation.json').write_bytes(encoded(result));return result

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(emit(a.source.absolute(),a.output.absolute()),sort_keys=True))
