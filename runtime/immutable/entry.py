"""Explicit PID1/worker CLI. Defaults refuse before any process/device action."""
import ctypes,json,os,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import runtime_policy as contract,inputs
P,C,_,_=inputs.broker()
if __name__=='__main__':
 value=P.decode(contract.read(Path('/immutable/policy.json'),1024**2));contract.gate(value)
 if sys.argv[1:2]==['worker']:
  import worker,bootstrap_loader
  # Child uses only held filter/drop functions; no leases/native data needed.
  bootstrap=bootstrap_loader.load(None,None);worker.run(int(sys.argv[2]),sys.argv[3],bootstrap)
 else:
  C.pid1();import owner
  try:print(P.encode(owner.run(value)).decode(),end='',flush=True)
  except BaseException as e:print(P.encode(dict(purpose='GNU_IMMUTABLE_RUNTIME_V1',status='FAIL',error_type=type(e).__name__,error=str(e)[:512],cleanup='NOT_ACCEPTED_UNKNOWN_STATE_RETAIN_BACKING_FILES')).decode(),end='',flush=True)
  finally:
   sys.stdout.flush();sys.stderr.flush();os.sync();ctypes.CDLL(None,use_errno=True).reboot(0x4321fedc)
