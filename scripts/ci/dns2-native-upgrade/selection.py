# SPDX-License-Identifier: MIT
"""Two exact local recipes; NULL template never authorizes actors or actual success."""
import hashlib,importlib.util,json,re,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
NAMES=('cachy-asahi-dns','cachy-asahi-dns2')
BASE='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'

def need(ok,message):
 if not ok:raise ValueError(message)

def read(path):
 def pairs(items):
  value={}
  for key,item in items:need(key not in value,'duplicate JSON key');value[key]=item
  return value
 return json.loads(path.read_bytes(),object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))

def checked(path,row):
 need(not any(p.is_symlink()for p in(path,*path.parents)),'source alias refused');info=path.lstat()
 need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and set(row)=={'bytes','sha256'}and type(row['bytes'])is int and 0<row['bytes']<=16*1024**2 and info.st_size==row['bytes']and hashlib.sha256(path.read_bytes()).hexdigest()==row['sha256'],'exact source byte join differs: '+str(path))

def policy(require_bound=True):
 value=read(HERE/'input-policy.json')
 need(not sys.flags.optimize and value['schema_version']==1 and value['base_inventory_sha256']==BASE and set(value['products'])==set(NAMES),'exact two-product574 policy required')
 need(all(value[k]is None for k in('actual_source','actual_ref','actual_run')),'policy carries no actual authority')
 if require_bound:need(value['status']=='ROOT_BOUND_FINAL_PRODUCT_SOURCES'and re.fullmatch('[0-9a-f]{40}',value.get('candidate_source')or''),'Root recipe source remains UNBOUND')
 else:need((value['status']=='UNBOUND_SOURCE_TEMPLATE'and value['candidate_source']is None)or(value['status']=='ROOT_BOUND_FINAL_PRODUCT_SOURCES'and re.fullmatch('[0-9a-f]{40}',value.get('candidate_source')or'')),'source-only selection differs')
 for name,row in value['products'].items():
  need(row['version']==('0.1.0-1'if name==NAMES[0]else'0.1.0-2')and row['package_name']=='cachy-asahi-dns'and 1<=len(row['source_files'])<=16 and 1<=len(row['payload'])<=16 and row['check_markers'],'fixed finite product version/source/payload/checks required')
 return value

def verify_source(source,require_bound=True):
 value=policy(require_bound)
 for name,row in read(HERE/'infrastructure-pins.json').items():checked(source/name,row)
 for name,product in value['products'].items():
  root=source/'packages/tools'/name
  need({p.name for p in root.iterdir()}==set(product['source_files']),'closed flat recipe source set differs')
  for relative,row in product['source_files'].items():need(Path(relative).name==relative,'flat recipe required');checked(root/relative,row)
 return dict(status='SOURCE_CALIBRATED_ONLY',products=2,actual_source=None,actual_ref=None,actual_run=None)

def recipe(source,name):
 need(name in NAMES,'finite product only');final=policy()['products'][name]
 spec=importlib.util.spec_from_file_location('dns2_upgrade_package_checks',source/'scripts/checks/package_checks.py');checks=importlib.util.module_from_spec(spec);spec.loader.exec_module(checks)
 result=checks.recipe(source/'packages/tools'/name/'PKGBUILD');meta=result['metadata']
 need(not result['errors']and meta.get('pkgname')==[final['package_name']]and meta.get('arch')==['any']and meta.get('license')==['MIT']and not any(meta.get(k)for k in('install','provides','conflicts','replaces','backup','makedepends','checkdepends')),'small script-only source required')
 need(meta['pkgver'][0]+'-'+meta['pkgrel'][0]==final['version']and result['input_sha256']=={p:r['sha256']for p,r in final['source_files'].items()},'final source/metadata differs')
 need(meta.get('depends')==['python>=3.11','networkmanager>=1.44'],'fixed dependency set differs')
 need(all(Path(p).name==p and '://'not in p for p in meta['source'])and 'check()'in(source/'packages/tools'/name/'PKGBUILD').read_text(),'native offline check() required')
 return result

def package_name(role):
 need(role in NAMES,'finite DNS recipe role only');return policy()['products'][role]['package_name']
