"""Preserve an existing positive export; otherwise emit failure-only retained DATA."""
import argparse,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import common as C;import owner as O
p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--source',required=True);p.add_argument('--run',type=int,required=True);p.add_argument('--attempt',type=int,required=True);p.add_argument('--cell',required=True);a=p.parse_args()
C.preflight();C.policy();identity=C.identity(a.source,a.run,a.attempt,a.cell)
if not a.output.exists():C.private(a.output,True)
out=C.private(a.output)
if(out/'export/index.json').exists():
 v=C.load(out/'export/index.json');expected=dict(v['files']);expected['index.json']=C.pin(C.read(out/'export/index.json'))
 C.need(C.files(out/'export')==expected and v['identity']==identity,'existing whole export differs; never rebaseline')
 print('PASS: existing source-owned export held unchanged')
else:
 C.need(not(out/'export').exists(),'partial export retained UNKNOWN; never overwrite')
 state=C.load(out/'owner.json')if(out/'owner.json').exists()else{}
 O.export(out,identity,state.get('nonce'),'FAIL',dict(kind='PRE_OWNER_OR_INTERRUPTED_FAILURE',message='No complete original owner export; no positive/commit/cleanup authority'))
 print('FAILURE DATA exported; no positive native authority')
