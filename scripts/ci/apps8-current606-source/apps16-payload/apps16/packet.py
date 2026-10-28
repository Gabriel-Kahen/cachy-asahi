# SPDX-License-Identifier: MIT
"""Exact accepted Apps16 pair DATA, full source/Git join and fresh owned TEST signature."""
import hashlib,importlib.util,json,os,re,shutil,subprocess,time,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
PAIR={'bytes': 29664, 'sha256': '319cc1db4738945ad3b146490ea0fabd80f8c8d89d8c41a11750dd0ba5d5b8af'}

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def module(path,name):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def policy():
 p=json.loads((HERE/'carrier-profile.json').read_bytes())
 need(all(p.get(k)is not None for k in('source','ref','publication','git_authorization','files','archives','native_source','native_run','acceptance','archive')),'Apps16 carrier/pair authority NULL/unpublished')
 need(re.fullmatch('[a-f0-9]{40}',p['source'])and p['native_source']=='135b8fb21941d0ea27da7d34b1fc7b9eb0939ee8'and p['native_run']==40170377974 and p['recipe_source']=='a32501a76b79b65d175c8eefc2b4f741ec0388e5','exact Apps16 native/recipe constraints')
 need(len(p['files'])==94,'exact complete Apps16 carrier94 closure')
 need(p['publication']==dict(status='COMMITTED_EXACT_CLOSED_TRIAL_SOURCE',source=p['source'],ref=p['ref'],files=len(p['files']),git_joins=len(p['files']),actual='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')and p['git_authorization']==dict(status='PASS_INDEPENDENT_FULL_GIT_BLOB_JOIN',source=p['source'],ref=p['ref'],files=p['files']),'whole genuine closed carrier publication/Git')
 d=p['acceptance'];need(d['source']==p['native_source']and d['run']==p['native_run']and d['ref']=='codex/apps16-pair-native-v1'and d['recipe_source']==p['recipe_source']and d['status']=='ROOT_ACCEPTED_APPS16_NATIVE_BUILD_PAIRS_AND_FINITE_INSTALLED_LIFECYCLE'and d['accepted_pair']['package']=='cachy-asahi-apps'and d['accepted_pair']['version']=='0.1.0-16'and d['accepted_pair']['byte_identical']is True and d['accepted_pair']['archive']==p['archive'],'issued exact Root Apps16 pair decision')
 need(type(p['archive'])is dict and set(p['archive'])=={'bytes','sha256'}and type(p['archive']['bytes'])is int and 0<p['archive']['bytes']<=8*1024**2 and re.fullmatch('[a-f0-9]{64}',p['archive']['sha256'])and PAIR==p['archive'],'whole pair authority/source operand equal')
 return p

def inspect(carrier,*,git_dir=None,deadline=None):
 p=policy();deadline=time.monotonic()+120 if deadline is None else deadline
 L=module(ROOT/'retained-inputs/legacy_prefill.py','_apps16_whole_git_proof')
 proof=L.prove(Path(carrier).absolute(),Path(git_dir or Path(carrier)/'.git').absolute(),p,deadline)
 index=json.loads(L.read(Path(carrier)/'index.json',deadline,1024**2));decision=json.loads(L.read(Path(carrier)/index['acceptance'],deadline,1024**2))
 need(index['status']=='EXACT_ACCEPTED_APPS16_PAIR_INPUT_DATA_ONLY'and index['archives']==p['archives'],'whole accepted pair index')
 common=module(HERE/'contract_common.py','_apps16_exact_shared_carrier_index');common.index_check(index,p['files'],p['recipe_files'],decision)
 need(decision==p['acceptance']and decision['accepted_pair']['archive']==PAIR and decision['accepted_pair']['byte_identical']is True,'exact Root accepted pair decision')
 reports=[];checks=module(ROOT/'copyworker/held-apps/checks/package_checks.py','_apps16_package_checks')
 for row in p['archives']:
  path=Path(carrier)/row['path'];need(pin(L.read(path,deadline))==PAIR,'exact accepted archive input');report=checks.package(path)
  need(not report['errors']and report['metadata']['.PKGINFO']['pkgname']==['cachy-asahi-apps']and report['metadata']['.PKGINFO']['pkgver']==['0.1.0-16']and report['metadata']['.PKGINFO']['arch']==['any'],'full actual Apps16 package identity')
  need(report['metadata']['.BUILDINFO']['pkgbuild_sha256sum']==[p['files']['recipe-source/packages/tools/cachy-asahi-apps16/PKGBUILD']['sha256']],'BUILDINFO exact recipe source')
  reports.append(report)
 need(reports[0]==reports[1],'both accepted complete package reports equal')
 return dict(proof=proof,report=reports[0],archive=Path(carrier)/p['archives'][0]['path'])

class LoggedSigner:
 """Bound the whole held signer subprocess closure; retain public DATA, no secrets."""
 def __init__(self,deadline):self.deadline=deadline;self.rows=[]
 def execute(self,argv,*,text=False,timeout=30,**kwargs):
  remaining=self.deadline-time.monotonic();need(remaining>0,'owned signer120s budget')
  result=subprocess.run(argv,capture_output=True,timeout=min(timeout,remaining),check=False)
  self.rows.append(dict(operation='KEY_GENERATE'if '--quick-generate-key'in argv else'PUBLIC_LIST'if '--list-keys'in argv else'PUBLIC_EXPORT'if '--export'in argv else'ARCHIVE_SIGN',exit=result.returncode,stdout=pin(result.stdout),stderr=pin(result.stderr)))
  need(result.returncode==0 and len(result.stdout)+len(result.stderr)<=65536,'bounded owned TEST signer operation')
  return result.stdout.decode()if text else result.stdout
 def run(self,argv,**kw):self.execute(argv,**kw)
 def check_output(self,argv,**kw):return self.execute(argv,**kw)

def extend(*,carrier,output,deadline):
 """Original Apps6/7/Runtime plan is already made from the same producer."""
 fact=inspect(carrier,deadline=min(deadline,time.monotonic()+120));raw=(output/'lifecycle-plan.json').read_bytes();value=json.loads(raw)
 need(set(value)=={'original6','new7','runtime','original606_manifest','verification_keys'},'exact original signed606 plan before Apps16 extension')
 archive=output/'archives/cachy-asahi-apps-0.1.0-16-any.pkg.tar.xz';need(not archive.exists(),'fresh candidate14 operand');shutil.copyfile(fact['archive'],archive)
 signer_root=output.parent/'apps16-private-signer';need(not signer_root.exists(),'fresh owner signing root');signer_root.mkdir(mode=0o700)
 signer=module(HERE/'test_signer.py','_whole_original_apps16_test_signer');logged=LoggedSigner(min(deadline,time.monotonic()+120));signer.subprocess=logged
 public=output/'keys/TEST-public.asc';need(not public.exists(),'fresh TEST public export');cleanup=False
 try:primary=signer.sign(public.parent,signer_root,[archive])
 finally:
  home=signer_root/'test-signing'
  if home.exists():
   remaining=logged.deadline-time.monotonic();need(remaining>0,'owned signer retirement120s budget')
   result=subprocess.run(['/usr/bin/gpgconf','--homedir',str(home),'--kill','all'],capture_output=True,timeout=min(20,remaining))
   need(result.returncode==0 and len(result.stdout)+len(result.stderr)<=65536,'owned signer retirement required before secret removal')
   shutil.rmtree(home);cleanup=True
  signer_root.rmdir()
 need(cleanup and re.fullmatch('[A-F0-9]{40}',primary),'retired owned TEST signer')
 checks=module(ROOT/'copyworker/held-apps/checks/package_checks.py','_apps16_package_checks_extend');report=checks.package(archive)
 payload={n:r for n,r in report['members'].items()if r['type']!='5'and n not in('.PKGINFO','.BUILDINFO','.MTREE')}
 need(len(payload)==8 and set(payload)==set(value['new7']['payload']),'same eight selected payload paths')
 mtree=report['members']['.MTREE'];product=dict(path='/runner/inputs/archives/'+archive.name,**PAIR,version='0.1.0-16',signer=primary,payload=payload,pkginfo=report['metadata']['.PKGINFO'],mtree=dict(bytes=mtree['size'],sha256=mtree['sha256']),signature=dict(path='/runner/inputs/archives/'+archive.name+'.sig',**pin(Path(str(archive)+'.sig').read_bytes())))
 value['new16']=product;value['verification_keys'].append(dict(path='/runner/inputs/keys/TEST-public.asc',signer=primary,**pin(public.read_bytes())))
 (output/'lifecycle-plan.json').write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
 receipt=dict(status='SOURCE_BOUND_ACCEPTED_APPS16_INPUT_FRESH_TEST_SIGNATURE_ONLY',carrier=fact['proof'],accepted_pair=PAIR,signer=primary,signing=dict(limit=120,operations=logged.rows,private_home='RETIRED_REMOVED'),actual=None,current606_acceptance='NOT_GRANTED')
 (output/'apps16-custody.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n');return receipt
