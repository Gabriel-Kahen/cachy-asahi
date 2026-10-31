# SPDX-License-Identifier: MIT
"""Two immutable source roles for one package; NULL recipes forbid native actors."""
import hashlib,importlib.util,json,re,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
NAMES=('cachy-asahi-sysctl','cachy-asahi-sysctl2');PACKAGE='cachy-asahi-sysctl'
BASE='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
def need(ok,message):
 if not ok:raise ValueError(message)
def read(path):
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate JSON');out[k]=v
  return out
 return json.loads(path.read_bytes(),object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def checked(path,row):
 need(not any(p.is_symlink()for p in(path,*path.parents)),'source alias refused');s=path.lstat()
 need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and set(row)=={'bytes','sha256'}and type(row['bytes'])is int and 0<row['bytes']<=16*1024**2 and s.st_size==row['bytes']and hashlib.sha256(path.read_bytes()).hexdigest()==row['sha256'],'exact source byte join differs: '+str(path))
def policy(require_bound=True):
 v=read(HERE/'input-policy.json');need(not sys.flags.optimize and v['schema_version']==1 and v['base_inventory_sha256']==BASE and set(v['products'])==set(NAMES),'exact same-name574 upgrade policy')
 need(all(v[k]is None for k in('actual_source','actual_ref','actual_run')),'source policy grants no actual authority')
 ids=v['recipe_sources'];need(set(ids)==set(NAMES),'both explicit recipe sources required')
 bound=v['status']=='ROOT_BOUND_FINAL_VERSION_SOURCES'and all(re.fullmatch('[0-9a-f]{40}',x or '')for x in ids.values())
 need(bound or (not require_bound and v['status']=='UNBOUND_SOURCE_TEMPLATE'and all(x is None for x in ids.values())),'both recipe authorities remain NULL/UNBOUND')
 for role,version,recipe in [('cachy-asahi-sysctl','0.1.0-1','packages/tools/cachy-asahi-sysctl'),('cachy-asahi-sysctl2','0.1.0-2','packages/tools/cachy-asahi-sysctl2')]:
  row=v['products'][role];need(row['version']==version and row['recipe']==recipe and len(row['source_files'])==8 and len(row['payload'])==5 and row['check_markers']==['Ran '+('19'if role==NAMES[0]else'28')+' tests','\nOK'],'exact finite role/version/source/controls')
 return v
def recipe_path(source,role):
 need(role in NAMES,'explicit version role required');return source/policy(False)['products'][role]['recipe']
def verify_source(source,require_bound=True):
 p=policy(require_bound)
 for n,row in read(HERE/'infrastructure-pins.json').items():checked(source/n,row)
 for role,product in p['products'].items():
  root=recipe_path(source,role);need({p.name for p in root.iterdir()}==set(product['source_files']),'closed flat recipe source')
  for n,row in product['source_files'].items():need(Path(n).name==n,'flat source leaf');checked(root/n,row)
 return dict(status='SOURCE_CALIBRATED_ONLY',roles=2,actual_source=None,actual_ref=None,actual_run=None)
def recipe(source,role):
 final=policy()['products'][role];spec=importlib.util.spec_from_file_location('sysctl2_package_checks',source/'scripts/checks/package_checks.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c);r=c.recipe(recipe_path(source,role)/'PKGBUILD');m=r['metadata']
 need(not r['errors']and m.get('pkgname')==[PACKAGE]and m.get('arch')==['any']and m.get('license')==['MIT']and m.get('depends')==['python>=3.11']and not any(m.get(k)for k in('install','provides','conflicts','replaces','backup','makedepends','checkdepends')),'same actual package, script-only dependency/security policy')
 need(m['pkgver'][0]+'-'+m['pkgrel'][0]==final['version']and r['input_sha256']=={n:v['sha256']for n,v in final['source_files'].items()},'exact version/source recipe identity')
 need(all(Path(n).name==n and '://'not in n for n in m['source'])and 'check()'in(recipe_path(source,role)/'PKGBUILD').read_text(),'offline native check required');return r
