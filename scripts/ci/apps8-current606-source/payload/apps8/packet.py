# SPDX-License-Identifier: MIT
"""Exact accepted Apps8 pair DATA, full source/Git join and fresh owned TEST signature."""
import hashlib,importlib.util,json,os,re,shutil,subprocess,time,types
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
PAIR=dict(bytes=23528,sha256='d4d83458765d732ae78664143c9042dcc1159b7d3e19f4b7976f8499c2619f4a')

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def module(path,name):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def policy():
 p=json.loads((HERE/'carrier-profile.json').read_bytes())
 need(p['source']is not None and re.fullmatch('[0-9a-f]{40}',p['source'])and p['publication']is not None,'Apps8 carrier NULL/unpublished')
 need(p['source']=='979b2d6ec7417e607a911d8c25bef2f1f7f72dcb'and p['ref']=='codex/apps8-accepted-inputs-v1'and p['publication']['source']==p['source']and p['publication']['files']==p['publication']['git_joins']==93,'genuine exact public carrier binding')
 need(len(p['files'])==93 and p['native_source']=='f1984a2481c541add7eb99b311a3ae3228307aa6'and p['native_run']==39727987029 and p['recipe_source']=='98a0a6ab18355604683bee42c84c393940a690a1','exact93 accepted native/recipe roles')
 return p

def inspect(carrier,*,git_dir=None,deadline=None):
 p=policy();deadline=time.monotonic()+120 if deadline is None else deadline
 L=module(ROOT/'retained-inputs/legacy_prefill.py','_apps8_whole_git_proof')
 proof=L.prove(Path(carrier).absolute(),Path(git_dir or Path(carrier)/'.git').absolute(),p,deadline)
 index=json.loads(L.read(Path(carrier)/'index.json',deadline,1024**2));decision=json.loads(L.read(Path(carrier)/index['acceptance'],deadline,1024**2))
 need(index['status']=='EXACT_ACCEPTED_APPS8_PAIR_INPUT_DATA_ONLY'and index['archives']==p['archives'],'whole accepted pair index')
 need(decision==p['acceptance']and decision['accepted_pair']['archive']==PAIR and decision['accepted_pair']['byte_identical']is True,'exact Root accepted pair decision')
 reports=[];checks=module(ROOT/'copyworker/held-apps/checks/package_checks.py','_apps8_package_checks')
 for row in p['archives']:
  path=Path(carrier)/row['path'];need(pin(L.read(path,deadline))==PAIR,'exact accepted archive input');report=checks.package(path)
  need(not report['errors']and report['metadata']['.PKGINFO']['pkgname']==['cachy-asahi-apps']and report['metadata']['.PKGINFO']['pkgver']==['0.1.0-8'],'full actual Apps8 package identity')
  need(report['metadata']['.BUILDINFO']['pkgbuild_sha256sum']==[p['files']['recipe-source/packages/tools/cachy-asahi-apps8/PKGBUILD']['sha256']],'BUILDINFO exact recipe source')
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
 need(set(value)=={'original6','new7','runtime','original606_manifest','verification_keys'},'exact original signed606 plan before Apps8 extension')
 archive=output/'archives/cachy-asahi-apps-0.1.0-8-any.pkg.tar.xz';need(not archive.exists(),'fresh candidate8 operand');shutil.copyfile(fact['archive'],archive)
 signer_root=output.parent/'apps8-private-signer';need(not signer_root.exists(),'fresh owner signing root');signer_root.mkdir(mode=0o700)
 signer=module(HERE/'test_signer.py','_whole_original_apps8_test_signer');logged=LoggedSigner(min(deadline,time.monotonic()+120));signer.subprocess=logged
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
 checks=module(ROOT/'copyworker/held-apps/checks/package_checks.py','_apps8_package_checks_extend');report=checks.package(archive)
 payload={n:r for n,r in report['members'].items()if r['type']!='5'and n not in('.PKGINFO','.BUILDINFO','.MTREE')}
 need(len(payload)==8 and set(payload)==set(value['new7']['payload']),'same eight selected payload paths')
 mtree=report['members']['.MTREE'];product=dict(path='/runner/inputs/archives/'+archive.name,**PAIR,version='0.1.0-8',signer=primary,payload=payload,pkginfo=report['metadata']['.PKGINFO'],mtree=dict(bytes=mtree['size'],sha256=mtree['sha256']),signature=dict(path='/runner/inputs/archives/'+archive.name+'.sig',**pin(Path(str(archive)+'.sig').read_bytes())))
 value['new8']=product;value['verification_keys'].append(dict(path='/runner/inputs/keys/TEST-public.asc',signer=primary,**pin(public.read_bytes())))
 (output/'lifecycle-plan.json').write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
 receipt=dict(status='SOURCE_BOUND_ACCEPTED_APPS8_INPUT_FRESH_TEST_SIGNATURE_ONLY',carrier=fact['proof'],accepted_pair=PAIR,signer=primary,signing=dict(limit=120,operations=logged.rows,private_home='RETIRED_REMOVED'),actual=None,current606_acceptance='NOT_GRANTED')
 (output/'apps8-custody.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n');return receipt
