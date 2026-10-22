# SPDX-License-Identifier: MIT
"""Exact accepted Apps11 pair DATA, full source/Git join and fresh owned TEST signature."""
import hashlib,importlib.util,json,os,re,shutil,subprocess,time,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
PAIR={'bytes': 26716, 'sha256': '80fe5fd4117c5b994e724ba29bb60473da86d829af757c8c62bea1164758901a'}

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def module(path,name):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def policy():
 p=json.loads((HERE/'carrier-profile.json').read_bytes())
 need(all(p.get(k)is not None for k in('source','ref','publication','git_authorization','files','archives','native_source','native_run','acceptance','archive')),'Apps11 carrier/pair authority NULL/unpublished')
 need(re.fullmatch('[a-f0-9]{40}',p['source'])and p['native_source']=='d4e86c4e7799b4138fc1a1a8720b223e78b99fe6'and p['native_run']==39769794548 and p['recipe_source']=='31bc46cdd58840e5c4337d2270a307d23a171373','exact Apps11 native/recipe constraints')
 need(len(p['files'])==94,'exact complete Apps11 carrier94 closure')
 need(p['publication']==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source=p['source'],ref=p['ref'],files=len(p['files']),git_joins=len(p['files']),actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and p['git_authorization']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=p['source'],ref=p['ref'],files=p['files']),'whole genuine closed carrier publication/Git')
 d=p['acceptance'];need(d['source']==p['native_source']and d['run']==p['native_run']and d['ref']=='codex/apps11-pair-native-v1'and d['recipe_source']==p['recipe_source']and d['status']=='ROOT_ACCEPTED_APPS11_NATIVE_BUILD_PAIRS_AND_FINITE_INSTALLED_LIFECYCLE'and d['accepted_pair']['package']=='cachy-asahi-apps'and d['accepted_pair']['version']=='0.1.0-11'and d['accepted_pair']['byte_identical']is True and d['accepted_pair']['archive']==p['archive'],'issued exact Root Apps11 pair decision')
 need(type(p['archive'])is dict and set(p['archive'])=={'bytes','sha256'}and type(p['archive']['bytes'])is int and 0<p['archive']['bytes']<=8*1024**2 and re.fullmatch('[a-f0-9]{64}',p['archive']['sha256'])and PAIR==p['archive'],'whole pair authority/source operand equal')
 return p

def inspect(carrier,*,git_dir=None,deadline=None):
 p=policy();deadline=time.monotonic()+120 if deadline is None else deadline
 L=module(HERE/'carrier_source.py','_apps11_whole_git_proof')
 proof=L.prove(Path(carrier).absolute(),Path(git_dir or Path(carrier)/'.git').absolute(),p,deadline)
 index=json.loads(L.read(Path(carrier)/'index.json',deadline,1024**2));decision=json.loads(L.read(Path(carrier)/index['acceptance'],deadline,1024**2))
 need(index['status']=='EXACT_ACCEPTED_APPS11_PAIR_INPUT_DATA_ONLY'and index['archives']==p['archives'],'whole accepted pair index')
 common=module(HERE/'contract_common.py','_apps11_exact_shared_carrier_index');common.index_check(index,p['files'],p['recipe_files'],decision)
 need(decision==p['acceptance']and decision['accepted_pair']['archive']==PAIR and decision['accepted_pair']['byte_identical']is True,'exact Root accepted pair decision')
 reports=[];checks=module(ROOT/'scripts/checks/package_checks.py','_apps11_package_checks')
 for row in p['archives']:
  path=Path(carrier)/row['path'];need(pin(L.read(path,deadline))==PAIR,'exact accepted archive input');report=checks.package(path)
  need(not report['errors']and report['metadata']['.PKGINFO']['pkgname']==['cachy-asahi-apps']and report['metadata']['.PKGINFO']['pkgver']==['0.1.0-11']and report['metadata']['.PKGINFO']['arch']==['any'],'full actual Apps11 package identity')
  need(report['metadata']['.BUILDINFO']['pkgbuild_sha256sum']==[p['files']['recipe-source/packages/tools/cachy-asahi-apps11/PKGBUILD']['sha256']],'BUILDINFO exact recipe source')
  reports.append(report)
 need(reports[0]==reports[1],'both accepted complete package reports equal')
 return dict(proof=proof,report=reports[0],archive=Path(carrier)/p['archives'][0]['path'])

