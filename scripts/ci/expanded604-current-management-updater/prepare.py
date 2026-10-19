#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit finite current604 updater source only. No authority or actor execution."""
import argparse,ast,hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='scripts/ci/expanded604-root-upgrade';NEW='scripts/ci/expanded604-current-management-updater'
OLD_BEFORE='e52be4b82b824bfbb6f1fb5bc8a742a2a2fb5c555aafe2d82532534385ec7e80'
OLD_AFTER='76c37db5eb097662f4a9ca0465680de285466b0443916a50255ea5b8f6d6c946'
BEFORE='5553e3c67423dffa54e521a211ff471faf6b384f61ff5bb56495b05b39600566'
AFTER='3f64a13c4af7ab8b1598583f534af3347c8df2397a0afa33fb8b0f5f06b19cf5'
OWN=('prepare.py','adapter.py','policy.json','source-pins.json','test_current.py','README.md')
MODULES=('contract.py','gate.py','run.py','before_cache.py','freeze.py','driver_progress.py',
         'test_adapter.py','test_cache.py','test_gate.py','test_driver_progress.py')
WORKFLOW='.github/workflows/native-arm-expanded604-current-management-updater.yml'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def sources(root):
 rows=json.loads((HERE/'source-pins.json').read_bytes())['files'];need(0<len(rows)<=512,'finite support closure')
 for name,row in rows.items():
  p=root/name;need(not any(x.is_symlink() for x in (p,*p.parents)) and p.is_file() and p.stat().st_nlink==1 and pin(p.read_bytes())==row,'current updater support differs: '+name)
 return rows

def adapt(raw,name):
 text=raw.decode();changes={OLD:NEW,OLD_BEFORE:BEFORE,OLD_AFTER:AFTER,
  'expanded604-installer-vm':'expanded604-current-management-installer',
  'expanded604-composition':'expanded604-current-management',
  'expanded604-root-upgrade':'expanded604-current-management-updater',
  'ROOT_BOUND_ACTUAL_PREREQUISITES':'ROOT_BOUND_ACTUAL_CURRENT604_PREREQUISITES',
  'ROOT_ACCEPTED_NATIVE_EXPANDED604_COMPOSITION':'ROOT_ACCEPTED_NATIVE_CURRENT604_COMPOSITION',
  'ROOT_ACCEPTED_SIGNED_EXPANDED604_FRESH_INSTALLER':'ROOT_ACCEPTED_SIGNED_CURRENT604_FRESH_INSTALLER',
  'GENERIC4K_NATIVE604_COPIED_ROOT_SOFTWARE_ONLY':'GENERIC4K_NATIVE_CURRENT604_COPIED_ROOT_SOFTWARE_ONLY'}
 if name=='contract.py':
  changes.update({"after['cachy-asahi-welcome']=='0.1.0-2'":"after['cachy-asahi-welcome']=='0.1.0-4'", "'cachy-asahi-orphans':'0.1.0-1'":"'cachy-asahi-orphans':'0.1.0-2'"})
 if name=='test_adapter.py':changes["before['cachy-asahi-welcome'],'0.1.0-2'"]="before['cachy-asahi-welcome'],'0.1.0-4'"
 edits={}
 for a,b in changes.items():
  if a in text:edits[a]=text.count(a);text=text.replace(a,b)
 if name=='freeze.py':
  anchor="    names=set(old)|{'scripts/ci/expanded600-root-upgrade/source-manifest.json'}\n"
  need(text.count(anchor)==1,'exact updater freeze closure anchor')
  text=text.replace(anchor,anchor+"    names.update(C.read(C.HERE/'source-pins.json')['files'])\n")
 ast.parse(text);return text.encode(),edits

def emit(root,output):
 rows=sources(root);need(not output.exists() and output.parent.is_dir() and not any(x.is_symlink() for x in (output,*output.parents)),'fresh ordinary output required');output.mkdir(mode=0o700)
 for name in rows:
  p=output/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes((root/name).read_bytes())
 lane=output/NEW;lane.mkdir(parents=True,exist_ok=True)
 for name in OWN:(lane/name).write_bytes((HERE/name).read_bytes())
 receipt={}
 for name in MODULES:raw,receipt[name]=adapt((root/OLD/name).read_bytes(),name);(lane/name).write_bytes(raw)
 final=(root/'scripts/ci/expanded604-current-management/expected604.lock').read_bytes();before=final.replace(b'cachy-asahi-setup 0.1.0-5\n',b'cachy-asahi-setup 0.1.0-3\n')
 need(pin(final)['sha256']==AFTER and pin(before)['sha256']==BEFORE,'only Setup predecessor current lock change')
 for name,raw in (('before604.lock',before),('after604.lock',final),('input-policy.json',(HERE/'policy.json').read_bytes())):(lane/name).write_bytes(raw)
 # Check the current normal inputs by reversing only declared lock/purpose literals
 # to the original exact BASIS; all other bytes and the AST-removal proof stay held.
 d=lane/'driver_progress.py';text=d.read_text()
 anchor=" need(name in BASIS and pin(raw)==BASIS[name],'exact original normal604 diagnostic basis required: '+name)"
 replacement=(" current = raw\n"
  +" for before,after in "+repr(((OLD_BEFORE,BEFORE),(OLD_AFTER,AFTER),('actual604-persistent-root-setup5-test','actual-current604-persistent-root-setup5-test')))+":\n"
  +"  need(before.encode() not in raw,'historical or mixed normal basis refused')\n"
  +"  current=current.replace(after.encode(),before.encode())\n"
  +" need(raw!=current and name in BASIS and pin(current)==BASIS[name],'exact original normal604 diagnostic basis required: '+name)")
 need(text.count(anchor)==1,'exact original normal basis guard');d.write_text(text.replace(anchor,replacement));basis='ORIGINAL_EXACT_BASIS_AFTER_ONLY_INVERSE_DECLARED_LOCK_PURPOSE_IDENTITIES'
 files={name:pin((output/name).read_bytes()) for name in rows};files.update({p.relative_to(output).as_posix():pin(p.read_bytes()) for p in lane.iterdir() if p.is_file()})
 manifest=lane/'source-manifest.json';manifest.write_bytes(encoded(dict(schema_version=1,status='FROZEN_ROOT_FINAL_SOURCE',files=files,native='NOT_RUN',hardware='NOT_RUN',scope='CURRENT604_UPDATER_SOURCE_ONLY_UNBOUND')))
 text=(root/'.github/workflows/native-arm-expanded604-root-upgrade.yml').read_text().replace('native-arm-expanded604-root-upgrade','native-arm-expanded604-current-management-updater').replace(OLD,NEW)
 for old,new in ((root/OLD/'run.py',lane/'run.py'),(root/OLD/'source-manifest.json',manifest)):
  a,b=pin(old.read_bytes())['sha256'],pin(new.read_bytes())['sha256'];need(text.count(a)==1,'exact workflow digest marker');text=text.replace(a,b)
 wf=output/WORKFLOW;wf.parent.mkdir(parents=True,exist_ok=True);wf.write_text(text)
 result=dict(status='SOURCE_ONLY_CURRENT604_UPDATER_UNBOUND',sources=len(rows),adaptations=receipt,before_sha256=BEFORE,after_sha256=AFTER,protected_packages=603,progress_basis=basis,workflow=pin(wf.read_bytes()),native='NOT_RUN',GUI='FAIL_NOT_ACCEPTED',release='NOT_ADMITTED');(output/'updater-adaptation.json').write_bytes(encoded(result));return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(emit(a.source.absolute(),a.output.absolute()),sort_keys=True))
