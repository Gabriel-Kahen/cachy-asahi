#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Future immutable input DATA materialization, never qualification or acquisition."""
import argparse,io,json,sys,zipfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as C,accepted,source_guard
from loaders import load,revision

def write_values(values,want,output,protected=()):
 output,=C.fresh(output,protected=protected);C.need(len(values)==len(want)==991 and {n:C.pin(b)for n,b in values.items()}==want,'whole exact991 accepted public DATA byte map')
 for n in values:C.need(type(n)is str and not n.startswith('/')and'\\'not in n and all(p not in('','.','..')for p in n.split('/')),'canonical closed DATA leaf')
 output.mkdir(mode=0o700)
 for n,b in values.items():p=output/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b);p.chmod(0o600)
 C.need({p.relative_to(output).as_posix():C.pin(C.read(p,max(16*1024**2,want[p.relative_to(output).as_posix()]['bytes'])))for p in output.rglob('*')if p.is_file()}==want,'whole materialized DATA bytes')

def stage(record,output):
 source_guard.verify();record=C.safe(record);_,post=accepted.record(record);revision(record,C.profile()['accepted_record_source']);T=load('_fresh607_held_bounded_input_transport',C.ROOT/'parent853/latest/implementation/latest_transport.py');raw=C.checked(record/'originals/artifact.zip',C.profile()['record_files']['originals/artifact.zip'])
 with zipfile.ZipFile(io.BytesIO(raw))as z:
  infos=z.infolist();C.need(len(infos)==2 and{p.filename for p in infos}=={'transport.json','retention-step.txt'}and all(p.file_size<=(1024**2 if p.filename=='transport.json'else T.STEP_CAP)for p in infos),'exact pinned original artifact members and original bounds');step=z.read('retention-step.txt')
 packets,_=T.decode_step(step);_,values=T.reconstruct(packets);write_values(values,post['public'],output,protected=(C.ROOT,record));return dict(status='MATERIALIZED_HISTORICAL_INPUT991_DATA_ONLY_NOT_QUALIFICATION',files=991,source=C.profile()['native_source'],run=C.profile()['native_run'],new_native_acceptance=False,acquisition=False)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--record',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(stage(a.record,a.output),sort_keys=True))
