#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit a separate public-pair installer; only finite source/input identities change."""
import argparse,ast,hashlib,json,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='scripts/ci/expanded604-apps6-installer';NEW='scripts/ci/expanded604-apps6-public-pair-installer'
COMP='scripts/ci/expanded604-apps6-public-pairs'
WF='.github/workflows/native-arm-expanded604-apps6-public-pair-installer.yml'
MODULES=('contract.py','adapter.py','ci.py','gate.py','freeze.py')
OWN=('prepare.py','policy.json','source-pins.json','test_lane.py','README.md')
TARGET='7bc6caa51301bf076aeda4d137277a128c53a16e5bfd25f02e7309c4b3a408c3'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def source(repo,composition):
 result={};pins=json.loads((HERE/'source-pins.json').read_bytes());groups=pins['groups']
 controls=pins['workflow_control_inputs']
 need(len(controls)==9 and all(groups['composition'].get(n)==row and pins['files'].get(n)==row for n,row in controls.items()),'complete original workflow control closure required')
 recipes=pins['composition_recipe_inputs']
 need(len(recipes)==80 and all(groups['composition'].get(n)==row and pins['files'].get(n)==row for n,row in recipes.items()),'complete pinned composition recipe/provenance closure required')
 need(set(groups)=={'installer','composition'},'two finite source roles required')
 for role,root in (('installer',repo),('composition',composition)):
  rows=groups[role];need(0<len(rows)<=512,'finite source closure')
  for name,row in rows.items():
   need(not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/')),'relative source path required')
   path=root/name
   need(not any(p.is_symlink() for p in (path,*path.parents)),'source aliases refused')
   info=path.lstat();need(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and 0<info.st_size<=16*1024**2,'ordinary bounded source required')
   raw=path.read_bytes();need(pin(raw)==row,'pinned source differs: '+role+':'+name)
   need(name not in result or result[name]==raw,'source roles conflict');result[name]=raw
 return result

def adapt(raw,name):
 text=raw.decode();ledger=[]
 def replace(before,after,count=None):
  nonlocal text
  actual=text.count(before);need(actual>0 and (count is None or actual==count),'public-pair installer anchor '+name+': '+before)
  text=text.replace(before,after);ledger.append(dict(before=before,after=after,count=actual))
 if 'expanded604-apps6-installer' in text:replace('expanded604-apps6-installer','expanded604-apps6-public-pair-installer')
 if name in ('contract.py','ci.py'):
  replace('expanded604-apps6/','expanded604-apps6-public-pairs/')
 if name=='contract.py':replace("'expanded604-apps6'","'expanded604-apps6-public-pairs'",1)
 if 'apps6_native_source' in text:replace('apps6_native_source','apps6_authority_source')
 if name=='gate.py':replace("composition['apps6']['native_source']","composition['apps6']['authority_source']",1)
 for before,after in (
  ('ROOT_BOUND_APPS6_CURRENT604_NATIVE_ACCEPTANCE','ROOT_BOUND_PUBLIC_PAIRS_APPS6_CURRENT604_NATIVE_ACCEPTANCE'),
  ('ROOT_ACCEPTED_NATIVE_APPS6_CURRENT604_COMPOSITION','ROOT_ACCEPTED_NATIVE_PUBLIC_PAIRS_APPS6_CURRENT604_COMPOSITION'),
  ('PASS_APPS6_CURRENT604_INSTALLER','PASS_PUBLIC_PAIRS_APPS6_CURRENT604_INSTALLER'),
  ('GENERIC4K_APPS6_SIGNED604_FRESH_INSTALLER_SOFTWARE_ONLY','GENERIC4K_PUBLIC_PAIRS_APPS6_SIGNED604_FRESH_INSTALLER_SOFTWARE_ONLY')):
  if before in text:replace(before,after)
 ast.parse(text);return text.encode(),ledger

def workflow(raw,rows,owner,manifest):
 text=raw.decode()
 for name,digest in (('ci.py',owner),('source-manifest.json',manifest)):
  before=rows[OLD+'/'+name]['sha256'];need(text.count(before)==1,'held workflow digest marker');text=text.replace(before,digest)
 text=text.replace('expanded604-apps6-installer','expanded604-apps6-public-pair-installer')
 need(text.count('apps6_native_source')==2 and text.count('--apps6-native-source')==2,'two public authority checkout/argv sites')
 text=text.replace('apps6_native_source','apps6_authority_source').replace('apps6-native','apps6-authority')
 anchor='          CURRENT604_INSTALLER_SOURCE: ${{ github.workspace }}/expanded604-installer\n'
 need(text.count(anchor)==1,'one focused controls implementation root')
 text=text.replace(anchor,anchor+'          PUBLIC_PAIR_INSTALLER_ROOT: ${{ github.workspace }}/expanded604-installer\n          PUBLIC_PAIR_COMPOSITION_ROOT: ${{ github.workspace }}/expanded604-installer\n')
 return text.encode()

def emit(repo,composition,output):
 rows=source(repo,composition)
 need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary output required')
 output.mkdir(mode=0o700)
 for name,raw in rows.items():p=output/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
 lane=output/NEW;lane.mkdir(parents=True);changes={}
 for name in OWN:(lane/name).write_bytes((HERE/name).read_bytes())
 for name in MODULES:raw,changes[name]=adapt(rows[OLD+'/'+name],name);(lane/name).write_bytes(raw)
 lock=rows[COMP+'/expected604.lock'];need(pin(lock)['sha256']==TARGET,'fixed Apps6 target required')
 (lane/'expected604.lock').write_bytes(lock);(lane/'input-policy.json').write_bytes((HERE/'policy.json').read_bytes())
 files={name:pin(raw) for name,raw in rows.items()}
 files.update({p.relative_to(output).as_posix():pin(p.read_bytes()) for p in lane.iterdir() if p.is_file()})
 manifest=lane/'source-manifest.json';manifest.write_bytes(encoded(dict(schema_version=1,status='FROZEN_ROOT_FINAL_SOURCE',files=files,scope='PUBLIC_PAIRS_APPS6_FRESH_ONLY_UNBOUND',native='NOT_RUN',hardware='NOT_RUN')))
 wf=output/WF;wf.parent.mkdir(parents=True,exist_ok=True)
 original=json.loads((HERE/'source-pins.json').read_bytes())['groups']['installer']
 wf.write_bytes(workflow(rows['.github/workflows/native-arm-expanded604-apps6-installer.yml'],original,pin((lane/'ci.py').read_bytes())['sha256'],pin(manifest.read_bytes())['sha256']))
 result=dict(status='SOURCE_ONLY_PUBLIC_PAIRS_APPS6_FRESH_INSTALLER_UNBOUND',target_sha256=TARGET,source_rows=len(files),changes=changes,native='NOT_RUN',hardware='NOT_RUN')
 (output/'fresh-adaptation.json').write_bytes(encoded(result));return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('source','composition','output'):p.add_argument('--'+name,type=Path,required=True)
 a=p.parse_args();print(json.dumps(emit(a.source.absolute(),a.composition.absolute(),a.output.absolute()),sort_keys=True))
