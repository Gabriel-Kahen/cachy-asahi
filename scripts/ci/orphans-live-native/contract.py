# SPDX-License-Identifier: MIT
"""Closed source/native gates for one private-root Orphans3 trial."""
import hashlib,importlib.util,json,os,re,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
LANE='scripts/ci/orphans-live-native';RECIPE='packages/tools/cachy-asahi-orphans03';PRODUCT='cachy-asahi-orphans';NAMES=(PRODUCT,);NAME='NO_ELF_PRODUCT'
BASE='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
LABEL='org.cachy-asahi.orphans03-native.job';CONSUMER_TOKEN_PREFIX='orphans03-consumer:'
FIXTURES=tuple('caa-orphans3-'+n for n in ('leaf-a','leaf-b','explicit','required','hard-user','optional','optional-user','protected'))
WORKFLOWS=('.github/workflows/native-arm-orphans-live.yml','.github/workflows/native-arm-build.yml')

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
 p=Path(name);need(not p.is_absolute() and '..' not in p.parts,'ordinary relative source required');p=safe(root/p);s=p.lstat();need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size==row['bytes'] and s.st_size<=16*1024**2 and digest(p)==row['sha256'] and ('mode' not in row or (0o100000|stat.S_IMODE(s.st_mode))==row['mode']),'source pin or mode differs: '+name)
def verify_source(root):
 root=safe(root);manifest=read(root/LANE/'source-manifest.json');need(manifest.get('schema_version')==1 and 1<=len(manifest['files'])<=128,'finite source closure')
 for n,row in manifest['files'].items():checked(root,n,row)
 allowed=set(manifest['files'])|{LANE+'/source-manifest.json',*WORKFLOWS};actual=set()
 for directory,dirs,names in os.walk(root,followlinks=False):
  if Path(directory)==root:
   if 'retained574-data' in dirs:
    need(not(root/'retained574-data').is_symlink() and (root/'retained574-data').is_dir(),'external retained carrier must be an ordinary directory');dirs.remove('retained574-data')
   dirs[:]=[d for d in dirs if d!='.git'];names=[n for n in names if n!='.git']
  for d in dirs:need(not(Path(directory)/d).is_symlink(),'source directory alias')
  actual.update((Path(directory)/n).relative_to(root).as_posix() for n in names)
 need(actual==allowed,'whole closed source set differs')
 template=(root/LANE/'workflow.yml').read_text();rendered=template.replace('@JOB_SHA256@',digest(root/LANE/'job.py')).replace('@MANIFEST_SHA256@',digest(root/LANE/'source-manifest.json'))
 need(all((root/n).read_text()==rendered for n in WORKFLOWS),'workflow source aliases differ')
 need(manifest.get('actual_source') is None and manifest.get('actual_ref') is None and manifest.get('actual_run') is None,'source construction grants no actual authority')
def recipe(source,name):
 need(name==PRODUCT,'one successor only');checks=load('orphans3_recipe_checks',source/'scripts/checks/package_checks.py');row=checks.recipe(source/RECIPE/'PKGBUILD');m=row['metadata']
 need(not row['errors'] and m.get('pkgname')==[PRODUCT] and m.get('pkgver')==['0.3.0'] and m.get('pkgrel')==['1'] and m.get('arch')==['any'] and m.get('depends')==['python>=3.11','pacman'] and m.get('license')==['MIT'],'exact successor recipe required')
 need(not any(m.get(k) for k in ('install','backup','provides','conflicts','replaces','makedepends','checkdepends')) and len(m['source'])==18,'no extra recipe behavior')
 profile=read(source/LANE/'product-profile.json');need(profile['recipe_path']==RECIPE and profile['package_name']==PRODUCT and profile['version']=='0.3.0-1' and profile['test_counts']==[20,25,8,24,25,7] and profile['tests']==109 and profile['payload_files']==12 and set(profile['files'])==set(row['input_sha256']) and len(profile['files'])==20,'exact isolated20-file0.3 recipe selection required')
 for n,r in profile['files'].items():checked(source,RECIPE+'/'+n,r);need(row['input_sha256'][n]==r['sha256'],'recipe source-delivery pin differs')
 delivery=load('orphans03_delivery_profile',source/'scripts/release/recipe_source_delivery.py');bodies,info=delivery.source_set(PRODUCT,lambda n:(source/RECIPE/n).read_bytes());need(len(bodies)==20 and info['pkgver']==['0.3.0'] and delivery.source_profile(PRODUCT,bodies)['version']=='0.3.0-1' and len(delivery.payload(PRODUCT,'0.3.0-1'))==12 and delivery.profile(PRODUCT)['version']=='0.1.0-2','additive0.3 delivery profile must preserve default0.1')
 checker=load('orphans03_profile_payload',source/RECIPE/'check_source.py');need(delivery.payload(PRODUCT,'0.3.0-1')==checker.PAYLOAD,'0.3 source-delivery payload must match all12 actual runtime mappings')
 need((source/LANE/'candidate.SRCINFO').read_bytes()==(source/RECIPE/'.SRCINFO').read_bytes(),'selected0.3 native metadata differs')
 return row
def version(source,name):need(name==PRODUCT,'one successor only');return '0.3.0-1'
def payload(report,source,name):
 need(name==PRODUCT and not report['errors'] and not report['elf'],'ordinary script-only package required');check=load('orphans3_payload',source/RECIPE/'check_source.py');expected=check.PAYLOAD
 actual={p:r for p,r in report['members'].items() if r['type']!='5' and p not in ('.PKGINFO','.BUILDINFO','.MTREE')};need(set(actual)==set(expected),'exact twelve-file successor payload')
 parents={str(p) for n in expected for p in Path(n).parents if str(p)!='.'}
 for n,r in report['members'].items():
  if r['type']=='5':need(n in parents,'unexpected empty directory')
 for n,(original,mode) in expected.items():
  r=actual[n];need(r['type']=='0' and r['mode']==mode and r['uid']==r['gid']==0 and r['sha256']==digest(source/RECIPE/original),'payload/source identity differs')
 return actual
def check_log(path,name):
 need(name==PRODUCT and path.stat().st_size<=16*1024**2,'bounded candidate build log');text=path.read_text(errors='replace')
 counts=re.findall(r'^Ran (\d+) tests in [0-9.]+s$',text,re.M);need('Starting check()' in text and counts==['20','25','8','24','25','7'] and len(re.findall('^OK$',text,re.M))==6 and not re.search(r'\bskipped=|\bOK \(|\bFAILED\b|^ERROR',text,re.M),'all exact109 selected recipe controls must run without skips')
 return dict(status='PASS_109_NATIVE_PACKAGE_CHECKS_NO_SKIPS',count=109)
def pair_gate(v):
 need(v['status']=='contents-reproduced' and not v['errors'] and len(v['packages'])==1 and all(all(r[k] is True for k in ('installed_contents_equal','pkginfo_equal','bytes_equal','buildinfo_equal')) for r in v['packages'].values()),'distinct clean pair must match contents/PKGINFO/BUILDINFO/archive bytes')
def validate_lifecycle(v):
 actor=load('orphans03_lifecycle_contract',HERE/'lifecycle.py');return actor.validate_lifecycle(v)
