#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""One normal repair actor; unchanged original full574 ownership and teardown."""
import argparse,ast,sys,os
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
H=C.load('original_full574_owner',C.HERE.parent/'apps-full574-native/job.py');H.C=C

def function(text,name):
 rows=[n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name==name];C.need(len(rows)==1,'one original function required');return ast.get_source_segment(text,rows[0])+'\n'
def replace(text,old,new):
 C.need(text.count(old)==1,'exact finite original owner seam required');return text.replace(old,new)
def derived(text):
 run=function(text,'run');retain=function(text,'retain');actor=function(text,'actor')
 actor=replace(actor," row=reserve(report,output,role);"," C.case(report['case'])\n row=reserve(report,output,role);")
 actor=replace(actor," argv+=['--entrypoint=/usr/bin/python3'"," if role=='lifecycle':argv+=['--env=CACHY_APPS574_REPAIR_CASE='+report['case']]\n argv+=['--entrypoint=/usr/bin/python3'")
 run=replace(run,"report=dict(status='FAIL',token=","report=dict(status='FAIL',case=args.case,token=")
 start=run.index("   actor(args.source,args.output,report,command,api,'interruption'");end=run.index("   api.retire(report['actors']",start);run=run[:start]+run[end:]
 run=replace(run,'lifecycle=life,interruption=interruption','lifecycle=life')
 retain=replace(retain,";interruption=C.decode(C.read(args.output/'interruption-public/interruption.json'))",'')
 start=retain.index("  C.need(interruption['status']");end=retain.index("  snap=C.decode",start);retain=retain[:start]+"  C.need(owner['lifecycle']==life,'original lifecycle owner join required')\n  C.load('retained_inspection_joins',C.HERE/'checks.py').retained(C,life,args.output/'lifecycle-public',result['files'])\n"+retain[end:]
 retain=replace(retain,"  C.need(not result['errors'],'closed evidence incomplete')","  C.need([r['role'] for r in owner['actors']]==['export','extract','signer','lifecycle','source-verify','scrub','source-cleanup'] and all(r.get('exit')==0 for r in owner['actors'] if r['role']!='export'),'exact seven normal roles and natural exits required')\n  C.need(not result['errors'],'closed evidence incomplete')")
 C.need(not any(isinstance(n,ast.Name) and n.id=='interruption' for n in ast.walk(ast.parse(run+retain))),'no inactive interruption operand')
 retain=replace(retain,"result=dict(status='FAIL_OR_INCOMPLETE',files={}","result=dict(status='FAIL_OR_INCOMPLETE',case=args.case,files={}")
 retain=replace(retain," copy(args.proof,'source-proof.json',65536);", " copy(args.proof.parent/'apps574-repair-handoff-diagnostic.json','outer-handoff-diagnostic.json',32768,False)\n copy(args.proof,'source-proof.json',65536);")
 retain=replace(retain,"  C.need(owner['lifecycle']==life,", "  C.need(proof_value['case']==owner['case']==ordered['case']==life['case']==args.case,'exact retained selected case')\n  C.need(owner['lifecycle']==life,")
 return dict(run=run,retain=retain,actor=actor)

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=('proof','check','run','cleanup','retain'))
 for name in ('source','packet','proof','base','output','receipt','public'):parser.add_argument('--'+name,type=Path)
 parser.add_argument('--case',choices=('repair-bytes','repair-missing'),required=True)
 args=parser.parse_args();C.case(args.case);C.need(os.environ.get('REPAIR_CASE')==args.case,'explicit workflow case matches argv');C.source(args.source) # UNBOUND refuses before secrets/actors or derivation.
 for body in derived(C.read(Path(H.__file__)).decode()).values():exec(compile(body,H.__file__+':normal-repair','exec'),H.__dict__)
 if args.mode in ('run','cleanup','retain'):C.need(C.decode(C.read(args.proof))['case']==args.case,'original proof selected case differs')
 value=getattr(H,args.mode)(args)
 if args.mode=='proof':
  value.update(case=args.case,outer_handoff=str(args.proof.parent/'apps574-repair-job.json'));C.save(args.proof,value)
 elif args.mode=='cleanup':value.update(case=args.case);C.save(args.receipt,value)
 elif args.mode=='check':value.update(case=args.case)
 print(C.encoded(dict(status=value['status'])).decode(),end='')
 return int(value['status'] not in ('SOURCE_PROOF_PASS','EXACT_NATIVE_INPUTS_CHECKED_NOT_EXECUTED','PASS_ACTUAL_TRANSACTIONS_PENDING_ORDERED_CLEANUP','PASS_ORDERED_CONSUMERS_COPIES_KEYS_SOURCE_THEN_PRODUCER',C.STATUS))
if __name__=='__main__':raise SystemExit(main())
