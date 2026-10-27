# SPDX-License-Identifier: MIT
"""Closed source/native gates for one private-root Orphans3 trial."""
import hashlib,importlib.util,json,os,re,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
LANE='scripts/ci/orphans3-native';PRODUCT='cachy-asahi-orphans';NAMES=(PRODUCT,);NAME='NO_ELF_PRODUCT'
BASE='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
LABEL='org.cachy-asahi.orphans3-native.job'
FIXTURES=tuple('caa-orphans3-'+n for n in ('leaf-a','leaf-b','explicit','required','hard-user','optional','optional-user','protected'))
WORKFLOWS=('.github/workflows/native-arm-orphans3-offline-removal.yml','.github/workflows/native-arm-build.yml')

def need(value,reason):
 if not value:raise ValueError(reason)
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def digest(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def safe(p):
 p=Path(p);need(p.is_absolute() and '..' not in p.parts and p==p.resolve() and not any(q.is_symlink() for q in (p,*p.parents)) and not any(c in str(p) for c in ',\r\n\0'),'ordinary canonical absolute path required');return p
def read(p,cap=32*1024**2):
 p=safe(Path(p).absolute());s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and 0<s.st_size<=cap,'bounded single-link JSON required')
 def pairs(rows):
  result={}
  for k,v in rows:need(k not in result,'duplicate JSON field');result[k]=v
  return result
 return json.loads(p.read_bytes(),object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite JSON required'))
def load(name,p):
 spec=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
def checked(root,name,row):
 p=Path(name);need(not p.is_absolute() and '..' not in p.parts,'ordinary relative source required');p=safe(root/p);s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size==row['bytes'] and s.st_size<=16*1024**2 and digest(p)==row['sha256'],'source pin differs: '+name)
def verify_source(root):
 root=safe(root);manifest=read(root/LANE/'source-manifest.json');need(manifest.get('schema_version')==1 and 1<=len(manifest['files'])<=128,'finite source closure')
 for n,row in manifest['files'].items():checked(root,n,row)
 allowed=set(manifest['files'])|{LANE+'/source-manifest.json',*WORKFLOWS};actual=set()
 for directory,dirs,names in os.walk(root,followlinks=False):
  if Path(directory)==root:
   if 'retained574' in dirs:
    need(not(root/'retained574').is_symlink() and (root/'retained574').is_dir(),'external retained carrier must be an ordinary directory');dirs.remove('retained574')
   dirs[:]=[d for d in dirs if d!='.git'];names=[n for n in names if n!='.git']
  for d in dirs:need(not(Path(directory)/d).is_symlink(),'source directory alias')
  actual.update((Path(directory)/n).relative_to(root).as_posix() for n in names)
 need(actual==allowed,'whole closed source set differs')
 template=(root/LANE/'workflow.yml').read_text();rendered=template.replace('@JOB_SHA256@',digest(root/LANE/'job.py')).replace('@MANIFEST_SHA256@',digest(root/LANE/'source-manifest.json'))
 need(all((root/n).read_text()==rendered for n in WORKFLOWS),'workflow source aliases differ')
 need(manifest.get('actual_source') is None and manifest.get('actual_ref') is None and manifest.get('actual_run') is None,'source construction grants no actual authority')
def recipe(source,name):
 need(name==PRODUCT,'one successor only');checks=load('orphans3_recipe_checks',source/'scripts/checks/package_checks.py');row=checks.recipe(source/'packages/tools'/name/'PKGBUILD');m=row['metadata']
 need(not row['errors'] and m.get('pkgname')==[PRODUCT] and m.get('pkgver')==['0.2.0'] and m.get('pkgrel')==['1'] and m.get('arch')==['any'] and m.get('depends')==['python>=3.11','pacman'] and m.get('license')==['MIT'],'exact successor recipe required')
 need(not any(m.get(k) for k in ('install','backup','provides','conflicts','replaces','makedepends','checkdepends')) and len(m['source'])==13,'no extra recipe behavior')
 return row
def version(source,name):need(name==PRODUCT,'one successor only');return '0.2.0-1'
def payload(report,source,name):
 need(name==PRODUCT and not report['errors'] and not report['elf'],'ordinary script-only package required');check=load('orphans3_payload',source/'packages/tools'/PRODUCT/'check_source.py');expected=check.PAYLOAD
 actual={p:r for p,r in report['members'].items() if r['type']!='5' and p not in ('.PKGINFO','.BUILDINFO','.MTREE')};need(set(actual)==set(expected),'exact ten-file successor payload')
 parents={str(p) for n in expected for p in Path(n).parents if str(p)!='.'}
 for n,r in report['members'].items():
  if r['type']=='5':need(n in parents,'unexpected empty directory')
 for n,(original,mode) in expected.items():
  r=actual[n];need(r['type']=='0' and r['mode']==mode and r['uid']==r['gid']==0 and r['sha256']==digest(source/'packages/tools'/name/original),'payload/source identity differs')
 return actual
def check_log(path,name):
 need(name==PRODUCT and path.stat().st_size<=16*1024**2,'bounded candidate build log');text=path.read_text(errors='replace')
 counts=re.findall(r'^Ran (\d+) tests in [0-9.]+s$',text,re.M);need('Starting check()' in text and counts==['20','25','8'] and len(re.findall('^OK$',text,re.M))==3 and not re.search(r'\bskipped=|\bOK \(|\bFAILED\b|^ERROR',text,re.M),'all original45 plus8 retirement controls must run without skips')
 return dict(status='PASS_53_NATIVE_PACKAGE_CHECKS_NO_SKIPS',count=53)
def pair_gate(v):
 need(v['status']=='contents-reproduced' and not v['errors'] and len(v['packages'])==1 and all(all(r[k] is True for k in ('installed_contents_equal','pkginfo_equal','bytes_equal','buildinfo_equal')) for r in v['packages'].values()),'distinct clean pair must match contents/PKGINFO/BUILDINFO/archive bytes')
def validate_lifecycle(v):
 need(v.get('status')=='PASS_ORPHANS3_REAL_NATIVE_OFFLINE_REMOVAL' and v.get('real_backend') is True and v.get('hardware')=='NOT_RUN' and v.get('version')=='0.2.0-1' and v.get('architecture')=='aarch64' and type(v.get('page_size')) is int and v['page_size']>0,'complete real native removal result required')
 before={n:'1-1' for n in FIXTURES};after={n:r for n,r in before.items() if n!='caa-orphans3-leaf-a'}
 need(v.get('before_count')==8 and v.get('after_count')==7 and v.get('before')==before and v.get('after')==after and v.get('base574_preserved') is True and v.get('final_lock')=='ABSENT','exact8to7 and original574 preservation required')
 cases=('different-selection','duplicate-selection','same-bytes-assessment','foreign-lock','positive','stale-after-removal','helper-alias','unsafe-payload');events=v.get('events')
 need(type(events) is list and [e.get('case') for e in events]==list(cases),'complete eight real removal observations required')
 for e in events:
  r=e['result']
  if e['case']=='positive':
   need(r.get('status')=='APPLIED' and r.get('commit_started') is True and r.get('packages_committed') is True and r.get('prepared_add')=={} and r.get('prepared_remove')=={'caa-orphans3-leaf-a':'1-1'} and r.get('transaction_released') is True and r.get('handle_released') is True and r.get('lock_state')=='ABSENT' and r.get('cleanup_errors')==[] and r.get('worker',{}).get('reaped') is True and r['worker'].get('exitcode')==0 and e.get('durable_result'),'exact actual commit/cleanup required')
  else:need(r.get('commit_started') is False and r.get('packages_committed') is False and r.get('status')=='REFUSED','refusal must establish no commit')
 cleanup=v.get('cleanup',{});need(cleanup.get('outer_candidate')=='REMOVED' and cleanup.get('foreign_lock')=='RELEASED_BY_OWN_HANDLE' and cleanup.get('TEST_agents')=='STOPPED' and cleanup.get('outer_container')=='PARENT_MUST_VERIFY_ABSENCE_AFTER_ACTOR_EXIT','complete inner cleanup required')
 need(type(v.get('commands')) is list and v['commands'] and all(r.get('exitcode')==r.get('expected_exit') and type(r.get('stdout')) is str and type(r.get('stderr')) is str for r in v['commands']),'complete actual command exits/stdout/stderr required')
 return v
