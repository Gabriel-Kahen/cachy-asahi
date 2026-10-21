"""Before secrets/actors, bind the complete source and Root source-only decision."""
import argparse,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as C
import effective_profile as E
p=argparse.ArgumentParser();p.add_argument('--source',required=True);p.add_argument('--run',type=int,required=True);p.add_argument('--attempt',type=int,required=True);p.add_argument('--cell',required=True);a=p.parse_args()
C.preflight();C.policy();E.authorize();C.identity(a.source,a.run,a.attempt,a.cell)
head=subprocess.check_output(['/usr/bin/git','-C',str(C.ROOT),'rev-parse','HEAD'],text=True,timeout=10).strip()
C.need(head==a.source,'checkout HEAD differs from explicit source');print('PASS: whole source+Root source-only selection, no native/build acceptance')
