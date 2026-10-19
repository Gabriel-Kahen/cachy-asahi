#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Native606 plus accepted Boot component; never use the blocked copied-root CLI."""
import json
from pathlib import Path
import sys
import types
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import guard as G
import owner_adapter as B


def main(argv=None):
    argv=list(sys.argv[1:] if argv is None else argv)
    fact=G.verify()
    if argv==['--source-preflight']:
        print(json.dumps(fact,sort_keys=True));return 0
    if argv==['--require-selection']:
        G.authorize();return 0
    if len(argv)==3 and argv[:2]==['--native-inputs','--boot-packet']:
        G.public_checkout(Path(argv[2]));return 0
    G.authorize()
    G.A.need(argv.count('--boot-packet')==1,'one exact accepted Boot native input checkout')
    at=argv.index('--boot-packet');G.A.need(at+1<len(argv),'Boot native packet operand')
    packet=Path(argv[at+1]).absolute();argv=argv[:at]+argv[at+2:]
    G.public_checkout(packet)
    O,S,P,old,bridge,C=G.original_context()
    Y=B.Integration(G.ROOT,bridge,HERE,packet/'payload',G.authorize)
    module=types.ModuleType('_native606_boot607_owner')
    module.__file__=str(G.ROOT/'held606/held604'/P.OLD/'run.py')
    module.X=Y;module.Y=Y
    with G.aliases({'contract':C}):
        exec(compile(B.owner(old.owner(G.ROOT/'held606')),module.__file__,'exec'),module.__dict__)
        return module.main(argv)

if __name__=='__main__':raise SystemExit(main())
