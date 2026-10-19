# SPDX-License-Identifier: MIT
"""Separate fixed604+2 source choice; NULL authorities precede all actors."""
import hashlib,importlib.util,json,re,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
OLD='scripts/ci/expanded604-apps6-public-pairs';ROLES=('cachy-asahi-dns2','cachy-asahi-sysctl2')
BASE='b0154bd3b60434e45d4411b558f3ffda9e415640';RECIPES='709e7a917cd67aaf6b1bceb314f7713dc4daec85'
def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(p):
 need(p.is_file()and not p.is_symlink()and p.stat().st_size<=4*1024**2,'bounded ordinary JSON')
 def pairs(rows):
  out={}
  for k,v in rows:need(k not in out,'duplicate JSON');out[k]=v
  return out
 return json.loads(p.read_bytes(),object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def checked(path,row):
 need(not any(p.is_symlink()for p in(path,*path.parents)),'source alias');s=path.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<=16*1024**2 and pin(path.read_bytes())==row,'whole source drift: '+path.name);return path

def authorities(a):
 need(type(a)is dict and set(a)=={'base604','dns2','sysctl2'},'all three genuine Root source decisions required')
 b,d,s=(a[n]for n in('base604','dns2','sysctl2'))
 need(b.get('status')=='ROOT_ACCEPTED_NATIVE_PUBLIC_PAIRS_APPS6_CURRENT604_COMPOSITION'and b.get('source_sha')==BASE and b.get('run_id')=='39044616267'and b.get('package_count')==604 and b.get('expected604_sha256')=='7bc6caa51301bf076aeda4d137277a128c53a16e5bfd25f02e7309c4b3a408c3'and b.get('installed_lifecycle')==b.get('cleanup')=='PASS','exact accepted base604')
 need(d.get('status')=='ROOT_ACCEPTED_NATIVE_DNS1_TO2_UPGRADE_AND_REAL_PRIVATE_DISCOVERY_RETAINED_SCOPE'and d.get('source')=='59a9aee351226e93e22574fd14bd3e0b45c8368d'and d.get('run')==39101228683 and d.get('candidate_program_sha256')=='d708cbe54a8e96a62ff7d85e4eadfb7a980401adb3a9fe8465052f754b4c8c88'and d.get('installed_controls')==dict(ordinary_homes=2,v1=21,v2=27)and d.get('retirement')=='DIRECT_WAIT0_WORKER_DAEMON_GROUP_ABSENCE_THEN_SEVEN_CONSUMERS_BEFORE_PRODUCER','exact accepted DNS2')
 need(s.get('status')=='ROOT_ACCEPTED_NATIVE_SYSCTL1_TO2_UPGRADE_RETAINED_SCOPE'and s.get('source')=='e2b0f5d6cde885936369949c6b0fcab2e4f66d12'and s.get('run')==39100389988 and s.get('installed_controls')==dict(ordinary_homes=2,v1=19,v2=28)and s.get('host_sysctl_mutation')=='NOT_RUN'and s.get('cleanup')=='RETAINED_ORDERED_SIX_CONSUMERS_THEN_PRODUCER','exact accepted Sysctl2')
 need(d.get('transitions')==s.get('transitions')==[575,575,574,575,574]and all(x.get('hardware')=='NOT_RUN'and x.get('release')=='NOT_ADMITTED'for x in(a.values())),'bounded prerequisite scope; no new606 admission');return a

def policy(bound=True):
 p=read(HERE/'input-policy.json');need(not sys.flags.optimize and p['schema_version']==1 and set(p['products'])==set(ROLES)and all(p[k]is None for k in('actual_source','actual_ref','actual_run')),'finite prospective606 policy')
 if bound:need(p['status']=='ROOT_BOUND_ACCEPTED604_DNS2_SYSCTL2'and p['base_source']==BASE and p['recipe_source']==RECIPES,'NULL606 source/authority refuses before actors');authorities(p['authorities'])
 else:need(p['status']in('UNBOUND_SOURCE_TEMPLATE','ROOT_BOUND_ACCEPTED604_DNS2_SYSCTL2'),'source-only state')
 need(p['base604_sha256']=='7bc6caa51301bf076aeda4d137277a128c53a16e5bfd25f02e7309c4b3a408c3','held604 lock')
 need(pin((HERE/'expected606.lock').read_bytes())['sha256']==p['target606_sha256'],'exact606 target lock')
 for role,count in zip(ROLES,(27,28)):
  r=p['products'][role];need(r['package_name']==role[:-1]and r['version']=='0.1.0-2'and r['controls']==count and len(r['payload'])==5,'exact two new package roles')
 return p

def metadata():
 value=read(HERE/'metadata-pins.json')
 need(set(value)=={'schema_version','role','source','files'}and value['schema_version']==1 and value['role']=='B015_ORIGINAL_INPUT_GATE_SOURCE_METADATA'and value['source']==BASE and len(value['files'])==47,'exact b015 metadata role')
 base=read(HERE/'base-pins.json');need(len(base)==151 and not(base.keys()&value['files'].keys()),'separate disjoint151+47 source roles')
 for name,row in value['files'].items():
  need(type(name)is str and not name.startswith('/')and Path(name).as_posix()==name and not any(p in('', '.', '..')for p in name.split('/'))and set(row)=={'bytes','sha256'},'finite relative metadata source pin')
 return value['files']

def verify(root=ROOT,bound=True):
 policy(bound)
 for prefix,filename in(('held604','base-pins.json'),('held-tools','build-pins.json')):
  for n,row in read(HERE/filename).items():checked(root/prefix/n,row)
 for n,row in metadata().items():checked(root/'held604'/n,row)
 need({p.relative_to(root/'held604').as_posix()for p in(root/'held604').rglob('*')if p.is_file()}==read(HERE/'base-pins.json').keys()|metadata().keys(),'complete exact151+47 held604 source closure')
 for role,p in policy(False)['products'].items():
  home=root/'held-tools'/p['recipe'];need({q.name for q in home.iterdir()}==set(p['source_files']),'exact recipe closure')
  for n,row in p['source_files'].items():checked(home/n,row)
 if(HERE/'source-manifest.json').exists():
  manifest=read(HERE/'source-manifest.json');need(manifest['schema_version']==1 and manifest['status']=='SOURCE_ONLY606_NOT_ACTUAL'and 0<len(manifest['files'])<=512,'original604 source manifest bound')
  for n,row in manifest['files'].items():checked(root/n,row)
 return dict(status='SOURCE_ONLY606_NOT_ACTUAL',base_files=151,metadata_files=47,metadata_source=BASE,actual_source=None,actual_ref=None,actual_run=None)
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
