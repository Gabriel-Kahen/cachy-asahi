#!/usr/bin/python3 -I
"""Run unchanged staged selected.py with only the authenticated held payload facade."""
import argparse,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
H=C.load('held_selected_payloads',C.HERE/'held_payloads.py')
def main():
 p=argparse.ArgumentParser(add_help=False);p.add_argument('--staged-source',type=Path,required=True);a,rest=p.parse_known_args()
 C.source(Path('/source'));stage=C.load('held_stage_check',C.HERE/'stage_source.py');stage.validate(C,a.staged_source)
 selected=C.load('held_staged_selected',a.staged_source/'scripts/orphans/selected.py');H.configure(selected.T,C,a.staged_source)
 H.supervisor(selected.T,a.staged_source/'scripts/orphans/selected.py',[C.HERE/'selected_fixture.py','--staged-source',a.staged_source])
 return selected.main(rest)
if __name__=='__main__':raise SystemExit(main())
