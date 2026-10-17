#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Finite public-pair604 upgrade/recovery emission; future actual gates remain UNBOUND."""
import argparse,ast,hashlib,importlib.util,json,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
OLD='scripts/ci/expanded604-apps6-updater';NEW='scripts/ci/expanded604-apps6-public-pair-updater'
FRESH='scripts/ci/expanded604-apps6-public-pair-installer';COMP='scripts/ci/expanded604-apps6-public-pairs'
WF='.github/workflows/native-arm-expanded604-apps6-public-pair-updater.yml'
OWN=('prepare.py','adapter.py','aux_transition.py','test_aux_transition.py','selected_package.py','baseline.py','apps6-product.json','policy.json','source-pins.json','test_lane.py','README.md','fixtures/normal-upgrade-config.json','fixtures/precommit-lane-config.json','fixtures/local_transaction.py')
MODULES=('contract.py','gate.py','run.py','before_cache.py','freeze.py')
NATIVE604='b0154bd3b60434e45d4411b558f3ffda9e415640'
def need(v,w):
 if not v:raise ValueError(w)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def source(repo,fresh):
 groups=json.loads((HERE/'source-pins.json').read_bytes())['groups'];need(set(groups)=={'updater','fresh'},'exact two source roles');result={}
 for role,root in (('updater',repo),('fresh',fresh)):
  need(0<len(groups[role])<=512,'finite source role')
  for n,row in groups[role].items():
   need(n and not n.startswith('/') and '\\' not in n and all(p not in ('','.','..') for p in n.split('/')),'relative source path');p=root/n
   need(not any(q.is_symlink() for q in (p,*p.parents)),'no source aliases');s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<s.st_size<=16*1024**2,'bounded ordinary source');raw=p.read_bytes();need(pin(raw)==row,'source role differs: '+role+':'+n);need(n not in result or result[n]==raw,'source roles conflict');result[n]=raw
 return result

def setup_recipe(source):
 # The actual unchanged setup_pair guard consumes12 recipe inputs +helper/license.
 spec=importlib.util.spec_from_file_location('_closed_public_updater_setup_recipe',source/'scripts/ci/setup5-native/contract.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);value=module.recipe(source)
 need(len(value['input_sha256'])==12 and value['metadata']['pkgrel']==['5'],'genuine closed Setup5 recipe guard');return value

def adapt(raw,name):
 text=raw.decode();ledger=[]
 def replace(a,b,count=None):
  nonlocal text
  actual=text.count(a);need(actual>0 and (count is None or actual==count),'public updater '+name+' seam: '+a);text=text.replace(a,b);ledger.append(dict(before=a,after=b,count=actual))
 if 'expanded604-apps6-updater' in text:replace('expanded604-apps6-updater','expanded604-apps6-public-pair-updater')
 if 'apps6_native_source' in text:replace('apps6_native_source','apps6_authority_source')
 if name=='contract.py':
  replace("NATIVE='ec135f26326158591e6d25d5f670083d5306b071'","NATIVE='c5481ad6bfd1539ab9a289bc9541133b979858f7'",1)
  replace("HERE.parent/'expanded604-apps6/apps_inputs.py'","HERE.parent/'expanded604-apps6-public-pairs/apps_inputs.py'",1)
  replace("HERE.parent/'expanded604-apps6/contract.py'","HERE.parent/'expanded604-apps6-public-pairs/contract.py'",1)
  replace("value['installer_inputs']['apps6_authority_source']==NATIVE","value['installer_inputs']['apps6_authority_source']==value['apps6']['authority_source']",1)
  anchor="    need(len({str(r['run_id']) for r in result.values()})==5,'five distinct actual prerequisite runs required')"
  replace(anchor,anchor+"\n    need(result['native604']['source_sha']=='"+NATIVE604+"' and result['fresh604'].get('native604_decision_sha256')==value['prerequisites']['native604']['sha256'],'exact new public-pair native604 and separately accepted fresh604 authority')",1)
 if name=='gate.py':
  replace('expanded604-apps6-installer/contract.py','expanded604-apps6-public-pair-installer/contract.py',1)
  replace("comp['apps6']['native_source']","comp['apps6']['authority_source']",1)
  replace("api.HERE.parent/'expanded604-apps6/materializer.py'","api.HERE.parent/'expanded604-apps6-public-pairs/materializer.py'",1)
 if name=='run.py':
  replace("output/'apps6',policy['apps6'])","output/'apps6',policy['apps6'],a.apps6_authority_source,a.implementation)",1)
 for a,b in (('ROOT_BOUND_ACTUAL_APPS6_CURRENT604_PREREQUISITES','ROOT_BOUND_ACTUAL_PUBLIC_PAIRS_APPS6_CURRENT604_PREREQUISITES'),('ROOT_ACCEPTED_NATIVE_APPS6_CURRENT604_COMPOSITION','ROOT_ACCEPTED_NATIVE_PUBLIC_PAIRS_APPS6_CURRENT604_COMPOSITION'),('ROOT_ACCEPTED_SIGNED_APPS6_CURRENT604_FRESH_INSTALLER','ROOT_ACCEPTED_SIGNED_PUBLIC_PAIRS_APPS6_CURRENT604_FRESH_INSTALLER'),('GENERIC4K_APPS5_TO6_CURRENT604_COPIED_ROOT_SOFTWARE_ONLY','GENERIC4K_PUBLIC_PAIRS_APPS5_TO6_CURRENT604_COPIED_ROOT_SOFTWARE_ONLY')):
  if a in text:replace(a,b)
 ast.parse(text);return text.encode(),ledger

def workflow(raw,rows,owner,manifest):
 text=raw.decode()
 for name,digest in (('run.py',owner),('source-manifest.json',manifest)):
  before=rows[OLD+'/'+name]['sha256'];need(text.count(before)==1,'exact updater workflow pin');text=text.replace(before,digest)
 need(text.count('apps6_native_source')==2 and text.count('--apps6-native-source')==2,'three public authority workflow operands')
 text=text.replace('expanded604-apps6-updater','expanded604-apps6-public-pair-updater').replace('apps6_native_source','apps6_authority_source').replace('apps6-native','apps6-authority');return text.encode()

def emit(repo,fresh,output):
 repo=Path(repo).absolute();fresh=Path(fresh).absolute();output=Path(output).absolute();rows=source(repo,fresh);setup=setup_recipe(fresh)
 need(not output.exists() and output.parent.is_dir() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh disjoint ordinary output')
 output.mkdir(mode=0o700)
 def write(n,raw):p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
 for n,raw in rows.items():write(n,raw)
 for n in OWN:write(NEW+'/'+n,(HERE/n).read_bytes())
 changes={}
 for n in MODULES:
  raw,changes[n]=adapt(rows[OLD+'/'+n],n);write(NEW+'/'+n,raw)
 for n in ('before604.lock','after604.lock'):write(NEW+'/'+n,rows[OLD+'/'+n])
 write(NEW+'/input-policy.json',(HERE/'policy.json').read_bytes())
 files={p.relative_to(output).as_posix():pin(p.read_bytes()) for p in output.rglob('*') if p.is_file()};need(len(files)<=512,'finite complete updater source')
 raw=encoded(dict(schema_version=1,status='FROZEN_ROOT_FINAL_SOURCE',files=files,scope='PUBLIC_PAIRS_APPS5_TO6_UNBOUND',native='NOT_RUN',hardware='NOT_RUN'));write(NEW+'/source-manifest.json',raw)
 write(WF,workflow(rows['.github/workflows/native-arm-expanded604-apps6-updater.yml'],json.loads((HERE/'source-pins.json').read_bytes())['groups']['updater'],files[NEW+'/run.py']['sha256'],pin(raw)['sha256']))
 result=dict(status='SOURCE_ONLY_PUBLIC_PAIRS_APPS5_TO6_CURRENT604_UNBOUND',source_rows=len(files),composition_source=NATIVE604,native604='UNBOUND',fresh604='UNBOUND',setup_recipe_guard='PASS_EXACT_ORIGINAL_RECIPE_HELPER_LICENSE',changes=changes,other603='UNCHANGED',actors='NOT_RUN');write('updater-adaptation.json',encoded(result));return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('source','fresh','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(emit(a.source,a.fresh,a.output),sort_keys=True))
