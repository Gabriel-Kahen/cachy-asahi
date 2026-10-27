"""Frozen packet byte closure only; no IPC/actors/authority activation."""
from pathlib import Path
import protocol as P
D=Path(__file__).resolve().parent;v=P.decode((D/'freeze.json').read_bytes());rows=v['files']
P.need({p.relative_to(D).as_posix()for p in D.rglob('*')if p.is_file()and p.name!='freeze.json'}==set(rows),'exact frozen closure')
for name,row in rows.items():P.need(P.pin((D/name).read_bytes())==row,'frozen byte drift: '+name)
P.need(P.decode((D/'input-pins.json').read_bytes())['accepted_authorities']is None,'all authority unbound')
print('PASS_FROZEN_BROKER_SOURCE_ONLY_NO_PID1_OR_VERITY_ACTIVATION')
