# SPDX-License-Identifier: MIT
"""Two explicit compiled Welcome recipe roles; no actual authority in a policy."""
import ast,hashlib,importlib.util,json,re,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
NAMES=('cachy-asahi-welcome','cachy-asahi-welcome5');PACKAGE='cachy-asahi-welcome'
BASE='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
def need(ok,why):
 if not ok:raise ValueError(why)
def read(path):
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate JSON');out[k]=v
  return out
 return json.loads(path.read_bytes(),object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def checked(path,row):
 need(not any(p.is_symlink()for p in(path,*path.parents)),'source alias refused');s=path.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and set(row)=={'bytes','sha256'}and 0<row['bytes']<=16*1024**2 and s.st_size==row['bytes']and hashlib.sha256(path.read_bytes()).hexdigest()==row['sha256'],'exact source byte join differs: '+str(path))
def policy(require_bound=True):
 v=read(HERE/'input-policy.json');need(not sys.flags.optimize and v['schema_version']==1 and v['base_inventory_sha256']==BASE and set(v['products'])==set(NAMES),'exact Welcome4/5 policy')
 need(all(v[k]is None for k in('actual_source','actual_ref','actual_run')),'source grants no actual authority');ids=v['recipe_sources'];need(set(ids)==set(NAMES),'two recipe authorities')
 bound=v['status']=='ROOT_BOUND_FINAL_VERSION_SOURCES'and all(re.fullmatch('[0-9a-f]{40}',x or '')for x in ids.values())
 need(bound or(not require_bound and v['status']=='UNBOUND_SOURCE_TEMPLATE'and all(x is None for x in ids.values())),'both recipe authorities remain NULL/UNBOUND')
 for role,version in zip(NAMES,('0.1.0-4','0.1.0-5')):
  r=v['products'][role];need(r['package_name']==PACKAGE and r['version']==version and r['recipe']=='packages/tools/'+role and len(r['source_files'])==25 and len(r['payload'])==9,'exact compiled role/version/source')
 return v
def recipe_path(source,role):
 need(role in NAMES,'explicit version role');return source/policy(False)['products'][role]['recipe']
def verify_source(source,require_bound=True):
 p=policy(require_bound)
 for n,row in read(HERE/'infrastructure-pins.json').items():checked(source/n,row)
 for role,product in p['products'].items():
  root=recipe_path(source,role);need({p.name for p in root.iterdir()}==set(product['source_files']),'closed25-file Welcome recipe')
  for n,row in product['source_files'].items():need(Path(n).name==n,'flat source');checked(root/n,row)
 return dict(status='SOURCE_CALIBRATED_ONLY',roles=2,actual_source=None,actual_ref=None,actual_run=None)
def recipe(source,role):
 p=policy()['products'][role];root=recipe_path(source,role);values={}
 keys=('pkgname','pkgver','pkgrel','pkgdesc','arch','url','license','depends','makedepends','checkdepends','optdepends','source','sha256sums')
 import shlex
 for m in re.finditer(r'^([a-z0-9_]+)=(\([^)]*\)|[^\n]*)',(root/'PKGBUILD').read_text(),re.M):
  k,v=m.groups();need(k in keys and k not in values,'constant single-package metadata');values[k]=shlex.split(v[1:-1]if v.startswith('(')else v,comments=True)
 need(values['pkgname']==[PACKAGE]and values['pkgver'][0]+'-'+values['pkgrel'][0]==p['version']and values['arch']==['aarch64']and values['license']==['MIT']and values['depends']==['gtk3>=3.24','glib2>=2.74']and values['makedepends']==['gcc','make','pkgconf']and values['checkdepends']==['python'],'exact compiled Welcome dependencies/version')
 need(len(values['source'])==len(values['sha256sums'])==23 and len(set(values['source']))==23,'23 pinned original source inputs')
 for n,sha in zip(values['source'],values['sha256sums']):need(n in p['source_files']and p['source_files'][n]['sha256']==sha and '/'not in n,'local source pin')
 return dict(metadata=values,input_sha256={n:r['sha256']for n,r in p['source_files'].items()})
def files(role):
 need(role in NAMES,'explicit payload role');return policy()['products'][role]['payload']
def welcome(source):
 import adapter as A
 raw=A.B.read(source,'scripts/ci/welcome-native/contract.py');m=type(sys)('welcome5_original_elf');m.__file__=str(source/'scripts/ci/welcome-native/contract.py');exec(compile(raw,m.__file__,'exec'),m.__dict__);return m,raw

def payload(report,source,role):
 import adapter as A
 m,raw=welcome(source);node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name=='payload');body=ast.get_source_segment(raw,node)
 before="files=FILES if name==NAME else {\n        'usr/bin/'+DOCTOR:(DOCTOR,0o755),\n        'usr/share/doc/'+DOCTOR+'/README.md':('README.md',0o644),\n        **{'usr/share/licenses/'+DOCTOR+'/'+n:(n,0o644) for n in ('LICENSE','NOTICE')}}"
 body=A.one(body,before,'files=payload_files(name)');body=A.one(body,"({'usr/bin/'+NAME} if name==NAME else set())","{'usr/bin/'+NAME}")
 m.NAMES=NAMES;m.payload_files=files;exec(compile(body,'<whole-pinned Welcome payload role derivative>','exec'),m.__dict__);return m.payload(report,source,role)
def elf(data,checks):
 import adapter as A
 m,_=welcome(A.ROOT);return m.elf(data,checks)
def check_log(path,role):
 text=path.read_text(errors='replace');need(path.stat().st_size<=16*1024**2,'build log cap')
 for marker in policy()['products'][role]['check_markers']:need(marker in text,'native compiled controls missing: '+marker)
 skips=[x for x in text.splitlines()if '# SKIP' in x or '# skip' in x];count=13 if role==NAMES[0]else 15
 need(len(skips)==1 and re.fullmatch(r'ok '+str(count)+r' /management/root-guard # SKIP Root guard requires an actual root test process',skips[0])and not re.search(r'\bskipped=[1-9]|\bOK \(skipped=',text),'only original ordinary-builder root guard deferment; executed in root lifecycle separately')
 return dict(status='PASS_COMPILED_WELCOME_CHECKS_ROOT_GUARD_DEFERRED_TO_ROOT_LIFECYCLE',source_payload='PASS',root_guard='REQUIRED_IN_ROOT_LIFECYCLE',GUI='NOT_RUN')
