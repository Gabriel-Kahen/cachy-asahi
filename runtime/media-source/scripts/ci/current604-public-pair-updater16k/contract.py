# SPDX-License-Identifier: MIT
"""Separate TEST-only16K update authority; no imports authorize execution."""
import hashlib,importlib.util,json,re,stat,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
# Repository-only test reference; copied /workspace helpers take explicit roots.
ROOT=HERE.parents[2] if len(HERE.parents)>2 else None
OLD='scripts/ci/expanded604-apps6-public-pair-updater'
LANE='scripts/ci/current604-public-pair-updater16k'
PASS='PASS_GENERIC16K_VM_PUBLIC_PAIRS_APPS5_TO6_CURRENT604_UPDATE'
CASES=('normal','precommit-exit86','postcommit-exit87')
CAPS=(0,1,3,4,5,6,7,18,31)
MASK=sum(1<<n for n in CAPS)
def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()
def read(p,cap=4*1024**2):
 p=Path(p);need(not any(q.is_symlink() for q in (p,*p.parents)),'ordinary path required');s=p.stat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<=s.st_size<=cap,'bounded single-link file required');d=p.read_bytes();need(len(d)==s.st_size,'file changed');return d
def decode(d):
 def pairs(rows):
  v={}
  for k,x in rows:need(k not in v,'duplicate JSON key');v[k]=x
  return v
 return json.loads(d,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def row(p):
 with Path(p).open('rb') as f:d=hashlib.file_digest(f,'sha256').hexdigest()
 return dict(bytes=Path(p).stat().st_size,sha256=d)
def save(p,v):Path(p).write_bytes(encoded(v))
def load(name,p):
 s=importlib.util.spec_from_file_location('_apps6_update16k_'+name,p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m);return m
def relative(n):need(type(n) is str and n and not n.startswith('/') and all(x not in ('','.','..') for x in n.split('/')),'safe relative path');return n
def check_source(root):
 pins=decode(read(HERE/'source-manifest.json'))['files'];need(0<len(pins)<=512,'bounded source closure')
 for n,r in pins.items():need(dict(bytes=len(read(Path(root)/relative(n),16*1024**2)),sha256=sha(read(Path(root)/n,16*1024**2)))==r,'source differs: '+n)
 return pins
def gate(root,case):
 need(case in CASES,'explicit single update case')
 p=decode(read(HERE/'input-policy.json'));need(p.get('status')=='ROOT_BOUND_PUBLIC_PAIRS_APPS6_CURRENT604_UPDATER16K' and type(p.get('binding')) is dict,'UNBOUND16K: no output, credentials or actors permitted')
 check_source(root);old=load('held_contract',Path(root)/OLD/'contract.py');held=old.policy()
 b=p['binding'];need(set(b)=={'updater_source','updater_manifest_sha256','decision_carrier_source','decisions'} and re.fullmatch('[0-9a-f]{40}',b['updater_source'] or '') and re.fullmatch('[0-9a-f]{40}',b['decision_carrier_source'] or '') and set(b['decisions'])==set(CASES),'new exact three-case updater authority')
 need(re.fullmatch('[0-9a-f]{64}',b['updater_manifest_sha256'] or '') and row(Path(root)/OLD/'source-manifest.json')['sha256']==b['updater_manifest_sha256'],'same accepted updater complete source manifest required')
 return old,held,b

def accepted(old,root,b):
 need(old.revision(root)==b['decision_carrier_source'],'exact updater Root decision carrier')
 truth={'normal':(1,True,True,True),'precommit-exit86':(0,False,False,False),'postcommit-exit87':(1,True,True,False)}
 out={}
 for case in CASES:
  d=old.read(old.checked(root,b['decisions'][case]));t=truth[case]
  need(d.get('status')=={'normal':'ROOT_ACCEPTED_PUBLIC_PAIRS_APPS6_CURRENT604_COPIED_ROOT_NORMAL','precommit-exit86':'ROOT_ACCEPTED_PUBLIC_PAIRS_APPS6_CURRENT604_COPIED_ROOT_PRECOMMIT_EXIT86','postcommit-exit87':'ROOT_ACCEPTED_PUBLIC_PAIRS_APPS6_CURRENT604_COPIED_ROOT_POSTCOMMIT_EXIT87'}[case] and d.get('case')==case and d.get('source_sha')==b['updater_source'] and d.get('source_manifest_sha256')==b['updater_manifest_sha256'] and d.get('before_sha256')==old.BEFORE and d.get('after_sha256')==old.AFTER and d.get('package_sha256')==old.PACKAGE and d.get('package_count')==604 and d.get('cleanup')=='PASS' and d.get('hardware')=='NOT_RUN' and d.get('release')=='NOT_ADMITTED','new Apps6 updater actual acceptance required')
  a=tuple(d.get(k) for k in ('committed_transactions','commit_started','packages_committed','checkpoint_changed'));need(a==t and all(type(x)is type(y) for x,y in zip(a,t)),'exact original commit/checkpoint truth')
  need(d.get('copy_cleanup')=='PASS-owned-workspace-removed' and str(d.get('run_id','')).isdecimal(),'actual copy disposal/run required')
  if case=='normal':need(d.get('checkpoint_directory_synced') is True,'durable normal checkpoint')
  elif case=='precommit-exit86':need(d.get('before_inventory_preserved') is True,'precommit baseline preserved')
  else:need(all(d.get(k) is True for k in ('after604_database_verified','postcommit_payload_verified','postcommit_preservation_verified')),'independent postcommit payload/preservation')
  out[case]=d
 need(len({str(v['run_id']) for v in out.values()})==3,'three distinct original runs');return out


def own_source(old,root,expected):
 need(re.fullmatch('[0-9a-f]{40}',expected or '') and old.revision(root)==expected,'exact new VM implementation revision')
 pins=check_source(root)
 subprocess.run(['git','-C',str(root),'diff','--exit-code','HEAD','--',*pins,LANE+'/source-manifest.json'],check=True,capture_output=True,timeout=15)
 return pins
