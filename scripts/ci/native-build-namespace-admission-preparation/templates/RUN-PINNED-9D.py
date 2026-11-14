"""Root-owned external pre-POST restriction; execute unchanged9d bytes -B/no-I."""
import argparse,hashlib,importlib.util,json,subprocess,sys,time
from datetime import datetime,timezone
from pathlib import Path
sys.dont_write_bytecode=True
T=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('_platform_root_operator',T/'ROOT-NATIVE-ONCE.py');O=importlib.util.module_from_spec(spec);spec.loader.exec_module(O)
p=argparse.ArgumentParser();p.add_argument('--fd',type=int,required=True);p.add_argument('--owner',type=int,required=True);p.add_argument('--owner-start',type=int,required=True);p.add_argument('--source',required=True);p.add_argument('--authority',required=True);p.add_argument('--authority-sha256',required=True);a=p.parse_args()
C,U,S,L=O.bootstrap();C.OWNER_START=a.owner_start;O.U=U;O.C=C;O.S=S;O.L=L
O.need(a.source==O.SOURCE,'only exact actual published namespace diagnostic Source')
O.admission(a.authority,a.authority_sha256)
helper=O.COMMON/'dispatch_native_once_20261026.py';raw=U.read(helper);O.need(hashlib.sha256(raw).hexdigest()=='9d014a2c5405f2ba5a478143545629cd5499eda2218a7306ca20cd4f24d5f94f','exact unchanged9d')
original=subprocess.run;sent=False
expected=['gh','api','--method','POST','repos/Gabriel-Kahen/cachy-asahi/actions/workflows/381664314/dispatches','--input','-']
def guarded(argv,*args,**kwargs):
 global sent
 if '--method'in argv and 'POST'in argv:
  O.need(argv==expected and not sent,'only one exact original9d POST')
  live=U.obj(U.read(O.OUT/'live-gate-qualified.json'));age=(datetime.now(timezone.utc)-datetime.fromisoformat(live['checked_at_utc'])).total_seconds()
  O.need(0<=age<=120 and live['source']==a.source and live['group']==O.GROUP and live['operation']==O.OP and live['complete_paginated']is True and live['same_group']==live['same_operation']==live['unknown_native']==0,'fresh<=120s exact scheduling guard immediately before POST')
  O.need(live['authority_sha256']==a.authority_sha256,'same Root-issued operation/resource authority')
  O.admission(a.authority,a.authority_sha256)
  O.need(json.loads(kwargs['input'])==dict(ref=O.REF,inputs=dict(source_sha=a.source,source_map_sha256=O.MAP,operation=O.OP)),'exact unchanged three inputs')
  intent=U.obj(U.read(O.ACTUAL/'dispatch-intent.json'));O.need(intent['prior_run_ids']==[] and intent['source']==a.source and intent['once']is True and intent['retry']is False,'original9d found no prior actual/uncertain selection')
  source=U.obj(U.read(O.OUT/'source-qualification.json'));O.need(source['status']=='EXACT_NAMESPACE_PREFLIGHT_PUBLISHED_SOURCE200_AND_MERGED_FACTORY'and source['source']==a.source,'same exact qualified Source/factory/Reader before POST')
  def direct_git(*parts):
   result=original(['/usr/bin/git','--no-replace-objects',*parts],cwd=O.ROOT,capture_output=True,timeout=30);result.check_returncode();return result.stdout.decode().strip()
  O.need(direct_git('rev-parse','HEAD')==source['main']and direct_git('rev-parse','refs/remotes/origin/main')==source['main']and direct_git('ls-remote','--heads','origin','refs/heads/main').split()==[source['main'],'refs/heads/main']and not direct_git('status','--porcelain','--untracked-files=no'),'same actual clean Main immediately at POST')
  O.need((datetime.now(timezone.utc)-datetime.fromisoformat(live['checked_at_utc'])).total_seconds()<=120,'gate remains fresh after final Main CAS')
  held=C.held(U,L,a.fd,a.owner);sent=True
  U.save(O.OUT/'at-actual-POST-guard.json',dict(status='PASS_FRESH_EXACT_ACTUAL_POST_GUARD',age_seconds=age,checked_at_utc=live['checked_at_utc'],source=a.source,ref=O.REF,group=O.GROUP,operation=O.OP,helper_sha256=hashlib.sha256(raw).hexdigest(),lease=held,once=True,retry=False))
 return original(argv,*args,**kwargs)
subprocess.run=guarded
try:
 sys.path.insert(0,str(helper.parent));sys.argv=[str(helper),str(O.OUT/'publication-for-original9d'),str(O.ACTUAL),'--inputs',str(O.OUT/'dispatch-inputs-only.json')]
 exec(compile(raw,str(helper),'exec'),dict(__name__='__main__',__file__=str(helper)))
 O.need(sent,'original helper never proved its once POST boundary')
finally:subprocess.run=original
