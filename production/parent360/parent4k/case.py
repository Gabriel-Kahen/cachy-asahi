# SPDX-License-Identifier: MIT
"""Separate native ARM4K wrapper custody; external b21 code remains an input."""
import hashlib,importlib.util,json,os,re,stat,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;HELD='b21a5864d5a4610b9181a1c270ac8821d8448a17';OLD='scripts/ci/expanded604-apps6-public-pair-updater';LANE='scripts/ci/current604-public-pair-updater16k';WF='.github/workflows/native-arm-build.yml';NAMED='.github/workflows/native-arm-updater604-recovery4k.yml';CASES=('precommit-exit86','postcommit-exit87')
def need(x,y):
 if not x:raise ValueError(y)
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def read(p,cap=16*1024**2):
 p=Path(p).absolute();need(not any(q.is_symlink()for q in(p,*p.parents)),'ordinary source ancestry');s=p.lstat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and 0<=s.st_size<=cap,'bounded source leaf');b=p.read_bytes();t=p.lstat();need(len(b)==s.st_size and all(getattr(s,k)==getattr(t,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')),'stable source leaf');return b
def obj(p):return json.loads(read(p))
def closed(root,rows):
 actual=set()
 for b,ds,fs in os.walk(root):
  if Path(b)==root:ds[:]=[n for n in ds if n!='.git'];fs=[n for n in fs if n!='.git']
  for n in ds:need(not(Path(b)/n).is_symlink(),'source directory alias')
  actual.update(str((Path(b)/n).relative_to(root))for n in fs)
 need(actual==set(rows),'whole closed source map')
 for n,w in rows.items():need(n and not Path(n).is_absolute()and '..'not in Path(n).parts and pin(read(root/n))==w,'whole source pin '+n)
 return rows
def source_context(held):
 p=obj(HERE/'profile.json');need(p['status']=='EXPLICIT_NATIVE_ARM4K_UPDATER604_RECOVERY_SOURCE_ONLY_NOT_ACCEPTED'and p['held_source']==HELD and p['cases']==list(CASES)and p['page_size']==4096 and all(p[k]is None for k in('wrapper_source','wrapper_ref','wrapper_run')),'explicit source-only native4K selection');m=obj(HERE/'source-manifest.json');closed(HERE,dict(m['files'],**{'source-manifest.json':pin(read(HERE/'source-manifest.json'))}));closed(held,p['held_files']);need(len(p['held_files'])==489 and p['held_git']['files']==p['held_files']and p['held_git']['source']==p['held_publication']['source']==HELD and p['held_git']['status']=='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN'and p['held_publication']['status']=='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE','whole immutable held489 source custody');need(read(HERE/WF)==read(HERE/NAMED),'registered and named native4K workflow identical');return p

def native():
 u=os.uname();page=os.sysconf('SC_PAGE_SIZE');uid=os.getuid();euid=os.geteuid();need(u.sysname=='Linux'and u.machine=='aarch64'and page==4096 and uid==euid>0 and not sys.flags.optimize,'ordinary native ARM4K owner only');return dict(sysname=u.sysname,architecture=u.machine,kernel_release=u.release,page_size=page,uid=uid,euid=euid)
def git(root,*args):
 row=subprocess.run(['git','-C',str(root),*args],capture_output=True,timeout=15,check=True);return row.stdout.decode().strip()
def authenticate(held,source,workflow,case,env=None):
 p=source_context(held);need(case in CASES and source==workflow and re.fullmatch('[a-f0-9]{40}',source or''),'new wrapper source/workflow/recovery selection before actors');readback=native();env=os.environ if env is None else env;need(env.get('GITHUB_REPOSITORY')=='Gabriel-Kahen/cachy-asahi'and env.get('GITHUB_SHA')==source and env.get('GITHUB_EVENT_NAME')=='workflow_dispatch'and env.get('GITHUB_RUN_ATTEMPT')=='1'and re.fullmatch('[1-9][0-9]*',env.get('GITHUB_RUN_ID',''))and env.get('GITHUB_REF','').startswith('refs/heads/codex/'),'current exact workflow/run/firstattempt context');need(env.get('GITHUB_WORKFLOW_REF')=='Gabriel-Kahen/cachy-asahi/'+WF+'@'+env['GITHUB_REF']and env.get('GITHUB_WORKFLOW')=='native-arm-updater604-recovery4k','registered current native4K workflow identity');need(git(HERE,'rev-parse','HEAD')==source and git(held,'rev-parse','HEAD')==HELD,'separate wrapper and held source revisions');need(git(HERE,'show',source+':'+WF).encode()+b'\n'==read(HERE/WF),'actual registered workflow bytes');git(HERE,'diff','--exit-code','HEAD','--','.');git(held,'diff','--exit-code','HEAD','--','.');return dict(status='CURRENT_NATIVE_ARM4K_UPDATER604_SOURCE_CUSTODY_NOT_ACCEPTANCE',source=source,ref=env['GITHUB_REF'],run=int(env['GITHUB_RUN_ID']),attempt=1,case=case,page_size=4096,architecture='aarch64',native_readback=readback,held_source=HELD,held_files=489,source_files=len(obj(HERE/'source-manifest.json')['files'])+1,hardware='NOT_RUN')
def load(name,path,aliases=None):
 before={k:sys.modules.get(k)for k in(aliases or{})}
 try:
  if aliases:sys.modules.update(aliases)
  s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
 finally:
  for k,v in before.items():
   if v is None:sys.modules.pop(k,None)
   else:sys.modules[k]=v

def apis(held):
 C=load('_native4k_held16k_contract',held/LANE/'contract.py');W=load('_native4k_held_wiring',held/LANE/'wiring.py',{'contract':C});A=load('_native4k_exact_descriptor_adapter',held/LANE/'adapter.py',{'contract':C});return C,W,A
