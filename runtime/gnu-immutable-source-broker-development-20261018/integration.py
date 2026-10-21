"""Exact opt-in bootstrap derivative; original prototype is never edited."""
from pathlib import Path
import ast,context as C,protocol as P

def derive(raw):
 _,expected=C.trusted('gnu-verity-bootstrap-development-20261018/bootstrap.py');P.need(raw==expected,'whole bootstrap bytes required')
 changes=(
  (b'def prepare_pid1(value):\n',b'def prepare_pid1(value,broker_value,limits):\n'),
  (b"  Path('/dev/mapper/control').unlink();Path('/dev/mapper').rmdir()\n  return device,prepared\n",b"  broker_context=SOURCE_BROKER.Context(broker_value,Path('/held'),Path('/work'),limits)\n  Path('/dev/mapper/control').unlink();Path('/dev/mapper').rmdir()\n  return device,prepared,broker_context\n"),
  (b"masks=R.restricted(R.status());need(all(masks[k]==WORKER_MASK for k in('CapEff','CapPrm','CapBnd')),'exact9-cap worker without SYS_ADMIN');return masks",b"SOURCE_CLIENT.restricted();return dict(mask=WORKER_MASK,purpose='GNU_PID1_VERITY_SOURCE_BROKER_V1')"))
 out=raw
 for old,new in changes:P.need(out.count(old)==1,'one exact bootstrap seam');out=out.replace(old,new)
 # Explicit new purpose must refuse before the original bootstrap actor entry.
 old=b" value=selection(value);dm.pid1();need(os.uname().release==value['kernel']['release'],'actual fresh selected kernel release')"
 new=b" SOURCE_BROKER.selection(broker_value);value=selection(value);dm.pid1();need(os.uname().release==value['kernel']['release'],'actual fresh selected kernel release')"
 P.need(out.count(old)==1,'one original bootstrap gate');out=out.replace(old,new);changes=(*changes,(old,new))
 restored=out
 for old,new in reversed(changes):restored=restored.replace(new,old)
 P.need(restored==raw,'complete original bootstrap inverse');compile(out,'<source-bound-broker-bootstrap>','exec');return out

def worker_entry(server_endpoint,worker_endpoint,derived_bootstrap,nonce,work):
 # Call ONLY after PID1 forks this reserved child. No host process can enter.
 import os,broker,scope
 P.need(os.getpid()!=1 and os.getppid()==1,'actual reserved direct child only')
 server_endpoint.close();broker.close_except({0,1,2,worker_endpoint.fileno()})
 derived_bootstrap.install_worker_fences();derived_bootstrap.drop_worker()
 # Do not call old Prepared.activate()/activate_in_child(): that route enforces
 # the legacy8 mask and assumes worker-owned DM query/proc mount authority.
 return scope.Scope(worker_endpoint,nonce)

if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);a=p.parse_args();P.need(not a.output.exists(),'fresh derivative output')
 _,raw=C.trusted('gnu-verity-bootstrap-development-20261018/bootstrap.py');a.output.write_bytes(derive(raw));print('SOURCE_ONLY_DERIVED_BOOTSTRAP_NO_ACTORS_NO_QUALIFICATION')
