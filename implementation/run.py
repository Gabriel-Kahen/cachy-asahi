#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Complete original producer/VM owner, with three finite fresh607 integration seams."""
import argparse,importlib.util,json,os,sys,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as C,accepted,adapter,materialize,source_guard,runtime_context,tooling_inputs
from loaders import load,revision
LANE='scripts/ci/expanded604-apps6-public-pair-installer'
EDITS=(
 ('            with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(lambda row:auditor.fetch(row,cache,True),downloads))','            Y.seed_tooling(auditor,downloads,cache,owner)\n            with ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(lambda row:auditor.fetch(row,cache,True),downloads))'),
 ("auditor=C.load('_fresh604_tooling',args.legacy_source/'scripts/virtual/audit_tooling.py')","auditor=Y.tooling()"),
 ("PURPOSE='expanded604-apps6-public-pair-installer'","PURPOSE='latest607-fresh-installer'"),
 ("implementation_source=args.implementation_revision","implementation_source=Y.source,installer_library_source=args.implementation_revision"),
 ("prerequisites=accepted","prerequisites=dict(accepted,latest_six=Y.decision)"),
 ("        materializer.prepare(ready,producer_output,", "        Y.bind(materializer,producer_output).prepare(ready,producer_output,"),
 ("        adapter.materialize(args.legacy_source,candidate)","        Y.candidate(candidate)"),
 ("        signal.setitimer(signal.ITIMER_REAL,0);safe=vm_retired(vm_output)","        signal.setitimer(signal.ITIMER_REAL,0);safe=vm_retired(vm_output) and Y.verifier_absent(producer_output)"),
 ("'GENERIC4K_PUBLIC_PAIRS_APPS6_SIGNED604_FRESH_INSTALLER_SOFTWARE_ONLY'","'GENERIC4K_LATEST607_FRESH_INSTALLER_SOFTWARE_ONLY'"),
 ("expected604_sha256=C.TARGET_SHA","expected607_sha256=Y.target"),
)
def derive(raw):
 text=raw.decode()
 for before,after in EDITS:C.need(text.count(before)==1,'one complete old owner integration seam');text=text.replace(before,after,1)
 old=text
 for before,after in reversed(EDITS):C.need(old.count(after)==1,'unique owner inverse');old=old.replace(after,before,1)
 C.need(old.encode()==raw,'whole original604 producer/cleanup/VM main inverse');compile(text,'<latest607-original-owner>','exec');return text

class Integration:
 def __init__(self,record,public,legacy,contract,source=None,decision=None,tooling_root=None):self.tooling_root=tooling_root;self.record,self.public,self.legacy,self.contract=record,public,legacy,contract;self.source,self.decision=source,decision;self.target=C.profile()['target']['sha256']
 def candidate(self,path):return adapter.emit(path)
 def tooling(self):return runtime_context.tooling(self.contract,self.legacy)
 def seed_tooling(self,auditor,downloads,cache,owner):
  C.need(self.tooling_root is not None,'explicit exact tooling carrier required');return tooling_inputs.seed(self.tooling_root,self.legacy,downloads,cache,owner)
 def verifier_absent(self,producer):return not os.path.lexists(producer/'private/latest607-verifier')
 def bind(self,original,producer):
  prepare=original.prepare;api=self
  def fresh(ready,producer_root,*args):
   C.need(producer_root==producer,'same original live producer ownership');C.need(len(args)>=7,'exact original604 materializer operands');target=args[4];base=producer/'private/latest607-base604';changed=list(args);changed[4]=base;prepare(ready,producer_root,*changed)
   helper=api.contract.scoped_load('_latest607_original_sign_copy',C.ROOT/'installer604/scripts/ci/expanded600-installer-vm/materializer.py',{'contract':api.contract});verifier=load('_latest607_original_verifier',api.legacy/'scripts/ci/full-composition-installer-vm/producer.py');checks=load('_latest607_exact_package_checks',api.legacy/'scripts/checks/package_checks.py');payload=load('_latest607_original_project_payload',api.legacy/'scripts/ci/full-development-composition/run.py')
   lease=runtime_context.BaseCache(producer,base)
   try:materialize.prepare(base,api.public,producer,target,helper=helper,verifier_api=verifier,checks=checks,payload_api=payload)
   finally:lease.retire()
   return target
  return types.SimpleNamespace(prepare=fresh)

def main(argv=None):
 fact=source_guard.verify();argv=list(sys.argv[1:]if argv is None else argv)
 if argv==['--source-preflight']:print(json.dumps(fact,sort_keys=True));return 0
 # Remaining arguments are parsed, gated and owned by the unchanged old CLI.
 p=argparse.ArgumentParser(add_help=False)
 for n in('six-record','six-public','installer604-source','tooling-inputs'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--fresh-source-revision',required=True);new,rest=p.parse_known_args(argv);record,public,oldroot,tooling_root=map(C.safe,(new.six_record,new.six_public,new.installer604_source,new.tooling_inputs));decision,_=accepted.public(record,public);revision(record,C.profile()['accepted_record_source']);revision(C.ROOT,new.fresh_source_revision);revision(oldroot,'bd0cf1891083d011b70edab10501c317d3720b78')
 rows=json.loads(C.read(C.ROOT/'source-manifest.json'))['parents']['installer604']
 C.need({q.relative_to(oldroot).as_posix()for q in oldroot.rglob('*')if q.is_file()and'.git'not in q.parts}==set(rows),'exact entire qualified274 installer publication')
 for n,w in rows.items():C.checked(oldroot/n,w)
 C.need(rest.count('--implementation')==1 and Path(rest[rest.index('--implementation')+1]).resolve()==oldroot,'original CLI must gate the exact original installer implementation')
 parser=argparse.ArgumentParser(add_help=False);parser.add_argument('--legacy-source',type=Path,required=True);oldargs,_=parser.parse_known_args(rest);legacy=C.safe(oldargs.legacy_source)
 revision(tooling_root,tooling_inputs.SOURCE);tooling_inputs.preflight(tooling_root,legacy)
 contract=load('_latest607_complete_old_contract',oldroot/LANE/'contract.py');oldadapter=contract.scoped_load('_latest607_complete_old_adapter',oldroot/LANE/'adapter.py',{'contract':contract});raw=C.checked(oldroot/LANE/'ci.py',rows[LANE+'/ci.py']);text=derive(raw);module=types.ModuleType('_latest607_complete_original_owner');module.__file__=str(oldroot/LANE/'ci.py');module.Y=Integration(record,public,legacy,contract,new.fresh_source_revision,decision,tooling_root);missing=object();prior={k:sys.modules.get(k,missing)for k in('contract','adapter')}
 try:
  sys.modules.update(contract=contract,adapter=oldadapter);exec(compile(text,module.__file__,'exec'),module.__dict__);return module.main(rest)
 finally:
  for k,v in prior.items():
   if v is missing:sys.modules.pop(k,None)
   else:sys.modules[k]=v
if __name__=='__main__':raise SystemExit(main())
