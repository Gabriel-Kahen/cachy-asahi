#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline original991 DATA staging from exact22 record, not acquisition or acceptance."""
import argparse,io,json,sys,zipfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import latest_common as C,accepted_inputs,source_guard
import latest_transport as T

def write_values(values,want,output,protected=()):
 output,=C.fresh(output,protected=protected);C.need(len(values)==len(want)==991 and {n:C.pin(b)for n,b in values.items()}==want,'whole original991 DATA map')
 for n in values:T.safe(n)
 output.mkdir(mode=0o700)
 for n,b in values.items():p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b);p.chmod(0o600)
 C.need({p.relative_to(output).as_posix():C.pin(C.read(p,max(16*1024**2,want[p.relative_to(output).as_posix()]['bytes'])))for p in output.rglob('*')if p.is_file()}==want,'complete staged991 byte map')

def stage(record,output):
 source_guard.verify();record=C.safe(record);_,post=accepted_inputs.record(record);raw=C.checked(record/'originals/artifact.zip',C.profile()['record_files']['originals/artifact.zip'])
 with zipfile.ZipFile(io.BytesIO(raw))as z:
  infos=z.infolist();C.need(len(infos)==2 and{p.filename for p in infos}=={'transport.json','retention-step.txt'}and all(p.file_size<=(1024**2 if p.filename=='transport.json'else T.STEP_CAP)for p in infos),'exact original two indexed transport members/caps');step=z.read('retention-step.txt')
 packets,_=T.decode_step(step);_,values=T.reconstruct(packets);write_values(values,post['public'],output,protected=(C.ROOT,record));return dict(status='MATERIALIZED_HISTORICAL991_DATA_ONLY',files=991,new_GUI_acceptance=False,acquisition=False,current_actual=None)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--record',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(stage(a.record,a.output),sort_keys=True))
