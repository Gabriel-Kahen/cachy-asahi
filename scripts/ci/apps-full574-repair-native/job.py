#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""One normal repair actor; unchanged original full574 ownership and teardown."""
import argparse,ast,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
H=C.load('original_full574_owner',C.HERE.parent/'apps-full574-native/job.py');H.C=C

def function(text,name):
 rows=[n for n in ast.parse(text).body if isinstance(n,ast.FunctionDef) and n.name==name];C.need(len(rows)==1,'one original function required');return ast.get_source_segment(text,rows[0])+'\n'
def replace(text,old,new):
 C.need(text.count(old)==1,'exact finite original owner seam required');return text.replace(old,new)
def derived(text):
 run=function(text,'run');retain=function(text,'retain');check=replace(function(text,'check'),'str(args.packet.parent)','str(args.packet)')
 start=run.index("   actor(args.source,args.output,report,command,api,'interruption'");end=run.index("   api.retire(report['actors']",start);run=run[:start]+run[end:]
 run=replace(run,'lifecycle=life,interruption=interruption','lifecycle=life')
 retain=replace(retain,";interruption=C.decode(C.read(args.output/'interruption-public/interruption.json'))",'')
 start=retain.index("  C.need(interruption['status']");end=retain.index("  snap=C.decode",start);retain=retain[:start]+"  C.need(owner['lifecycle']==life,'original lifecycle owner join required')\n"+retain[end:]
 retain=replace(retain,"  C.need(not result['errors'],'closed evidence incomplete')","  C.need([r['role'] for r in owner['actors']]==['export','extract','signer','lifecycle','source-verify','scrub','source-cleanup'] and all(r.get('exit')==0 for r in owner['actors'] if r['role']!='export'),'exact seven normal roles and natural exits required')\n  C.need(not result['errors'],'closed evidence incomplete')")
 C.need(not any(isinstance(n,ast.Name) and n.id=='interruption' for n in ast.walk(ast.parse(run+retain))),'no inactive interruption operand')
 return dict(check=check,run=run,retain=retain)

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=('proof','check','run','cleanup','retain'))
 for name in ('source','packet','proof','base','output','receipt','public'):parser.add_argument('--'+name,type=Path)
 args=parser.parse_args();C.source(args.source) # UNBOUND refuses before secrets/actors or derivation.
 for body in derived(C.read(Path(H.__file__)).decode()).values():exec(compile(body,H.__file__+':normal-repair','exec'),H.__dict__)
 value=getattr(H,args.mode)(args);print(C.encoded(dict(status=value['status'])).decode(),end='')
 return int(value['status'] not in ('SOURCE_PROOF_PASS','EXACT_NATIVE_INPUTS_CHECKED_NOT_EXECUTED','PASS_ACTUAL_TRANSACTIONS_PENDING_ORDERED_CLEANUP','PASS_ORDERED_CONSUMERS_COPIES_KEYS_SOURCE_THEN_PRODUCER',C.STATUS))
if __name__=='__main__':raise SystemExit(main())
