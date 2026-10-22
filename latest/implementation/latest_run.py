#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fresh genuine606 producer, one isolated latest-six consumer; no default actor."""
import json,sys,types
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
import latest_guard as G
import latest_owner as B
import latest_inputs as I

def main(argv=None):
 argv=list(sys.argv[1:]if argv is None else argv);fact=G.verify()
 if argv==['--source-preflight']:print(json.dumps(fact,sort_keys=True));return 0
 if argv==['--require-selection']:G.authorize();return 0
 G.authorize();flag='--apps8-packet';G.P.need(argv.count(flag)==1 and argv.index(flag)+1<len(argv),'one separate qualified Apps8 carrier before actors');at=argv.index(flag);apps8_packet=Path(argv[at+1]).absolute();argv=argv[:at]+argv[at+2:];packets={}
 for role in('apps','doctor','ksm','welcome','boot'):
  flag='--'+role+'-packet';G.P.need(argv.count(flag)==1 and argv.index(flag)+1<len(argv),'allfive finite publishedcarrier operands');at=argv.index(flag);packets[role]=Path(argv[at+1]).absolute();argv=argv[:at]+argv[at+2:]
 extra_packets={}
 for role in('apps10','welcome8','setup6','onboarding','apps10qualification'):
  flag='--'+role+'-packet';G.P.need(argv.count(flag)==1 and argv.index(flag)+1<len(argv),'one exact new source-owned input '+role);at=argv.index(flag);extra_packets[role]=Path(argv[at+1]).absolute();argv=argv[:at]+argv[at+2:]
 G.public_checkouts(packets,apps8_packet=apps8_packet,extra_packets=extra_packets)
 if argv==['--native-inputs']:return 0
 prior=G.original();O,S,P,old,bridge,C=prior.original_context();text=B.bridge_source((G.BASE/'held606/scripts/ci/current606-native/bridge606.py').read_text());adapted=types.ModuleType('_latest_native606_typed_bridge');adapted.__file__=str(G.BASE/'held606/scripts/ci/current606-native/bridge606.py')
 with I.aliases({'contract':P,'adapter':old,'build_pairs':bridge.build_pairs}):exec(compile(text,adapted.__file__,'exec'),vars(adapted))
 Y=B.Integration(G.ROOT,G.BASE,prior,adapted,packets,G.authorize,apps8_packet=apps8_packet,extra_packets=extra_packets);module=types.ModuleType('_latest_native607_owner');module.__file__=str(G.BASE/'held606/held604'/P.OLD/'run.py');module.X=Y;module.Y=Y
 with I.aliases({'contract':C}):exec(compile(B.owner(old.owner(G.BASE/'held606')),module.__file__,'exec'),vars(module));return module.main(argv)
if __name__=='__main__':raise SystemExit(main())
