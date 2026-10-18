"""Original offline preparer with one explicit new-purpose staging call."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import inputs,disk_adapter,stage,runtime_policy
P,_,_,_=inputs.broker()
def load(value):
 original=inputs.original('_immutable_native_original_prepare','scripts/ci/glibc-gnu-provider-installed16k/prepare.py');raw=Path(original.__file__).read_bytes();space=dict(vars(original),runtime_stage=stage,runtime_policy=value)
 text=disk_adapter.preparer(raw)
 exec(compile(text,original.__file__,'exec'),space);space['INIT']=disk_adapter.init(raw)[0];return space
if __name__=='__main__':
 value=P.decode(runtime_policy.read(Path('/runtime-selection/policy.json'),1024**2));runtime_policy.gate(value,preparing=True);load(value)['prepare']()
