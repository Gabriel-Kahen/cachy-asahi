# SPDX-License-Identifier: MIT
"""Existing606 producer plus accepted public pair operands; no new fake builders."""
import contextlib,importlib.util,subprocess,sys
from pathlib import Path
import contract as O

@contextlib.contextmanager
def aliases(values):
 old={k:sys.modules.get(k)for k in values};sys.modules.update(values)
 try:yield
 finally:
  for k,v in old.items():
   if v is None:sys.modules.pop(k,None)
   else:sys.modules[k]=v

def public_checkout(packet,policy):
 O.need(packet.is_absolute()and packet.is_dir()and not any(p.is_symlink()for p in(packet,*packet.parents)),'ordinary exact public native pair checkout')
 for command,expected in [(['rev-parse','HEAD'],policy['native_pair_source'].encode()+b'\n'),(['status','--porcelain','--untracked-files=all'],b'')]:
  row=subprocess.run(['git','-C',str(packet),*command],capture_output=True,timeout=10);O.need(row.returncode==0 and row.stdout==expected and len(row.stderr)<=4096,'exact clean real public native pair checkout required')
 # DATA validation happens before the original producer or secrets are used.
 return inspect(packet)

def apis():
 root=O.ROOT/'copyworker';lane=root/'scripts/ci/current606-ksm2-copy'
 C=O.module('_ksm606_worker_contract',lane/'contract.py')
 with aliases({'contract':C}):P=O.module('_ksm606_plan',lane/'plan.py');I=O.module('_ksm606_inputs',lane/'inputs.py')
 return C,P,I

def inspect(packet):
 C,P,I=apis()
 with aliases({'contract':C,'plan':P}):return I.inspect(packet/'payload')

def ksm(*,root,packet,ready604,output):
 C,P,I=apis()
 with aliases({'contract':C,'plan':P}):I.make(packet=packet/'payload',ready604=ready604,output=output)
 return output
