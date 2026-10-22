#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit normal-Docker full606 Apps7+Setup6 lane; source checks never launch actors."""
import argparse,json,sys,types
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import guard as G
import integration as I

def main(argv=None):
 argv=list(sys.argv[1:]if argv is None else argv)
 if argv==['--help']:
  p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-preflight',action='store_true');p.add_argument('--require-selection',action='store_true');p.add_argument('--setup-packet',type=Path);p.add_argument('--apps-packet',type=Path);p.print_help();return 0
 G.verify();anchor=G.anchor();context=anchor.source_context(G.ROOT);P,A,X,C=context
 if argv==['--source-preflight']:P.verify(bound=False);I.owner_program(A.owner(P.ROOT));I.native_program((P.HERE/'tools606.py').read_bytes());print(json.dumps(G.verify(),sort_keys=True));return 0
 policy=anchor.O.authorize(anchor.O.read(anchor.O.HERE/'input-policy.json'))
 if argv==['--require-selection']:return 0
 if len(argv)==5 and argv[:2]==['--native-inputs','--apps-packet']and argv[3]=='--setup-packet':anchor.builds.public_checkout(Path(argv[2]).absolute(),policy);anchor.builds.doctor_checkout(Path(argv[4]).absolute(),policy);return 0
 for flag in('--apps-packet','--setup-packet'):G.need(argv.count(flag)==1 and argv.index(flag)+1<len(argv),'one explicit immutable input '+flag)
 packet=Path(argv[argv.index('--apps-packet')+1]).absolute();setup=Path(argv[argv.index('--setup-packet')+1]).absolute()
 for flag in('--apps-packet','--setup-packet'):
  at=argv.index(flag);del argv[at:at+2]
 P.verify();Y=I.Integration(G,anchor,context,packet,setup);program=anchor.PDIAG.route_owner(I.owner_program(A.owner(P.ROOT)));m=types.ModuleType('_owned_normal606_setup6_owner');m.__file__=str(P.ROOT/'held604'/P.OLD/'run.py');m.X=Y;m.Y=Y;m.PDIAG=anchor.PDIAG
 with anchor.builds.aliases({'contract':C}):exec(compile(program,m.__file__,'exec'),vars(m));return m.main(argv)
if __name__=='__main__':raise SystemExit(main())
