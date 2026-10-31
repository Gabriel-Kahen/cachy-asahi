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
 root=O.ROOT/'copyworker';lane=root/'scripts/ci/current606-doctor2-copy'
 C=O.module('_doctor106_worker_contract',lane/'contract.py')
 with aliases({'contract':C}):P=O.module('_doctor106_plan',lane/'plan.py');I=O.module('_doctor106_inputs',lane/'inputs.py')
 return C,P,I

def inspect(packet):
 C,P,I=apis()
 with aliases({'contract':C,'plan':P}):return I.legacy().inspect(packet/'payload')

def doctor(*,root,packet,doctor_packet,ready604,output,producer,original_api):
 C,P,I=apis()
 with aliases({'contract':C,'plan':P}):I.make(packet=packet/'payload',doctor_packet=doctor_packet,ready604=ready604,output=output,source=root/'held606',producer=producer,original_api=original_api)
 return output


def doctor_checkout(packet,policy):
 O.need(packet.is_absolute()and packet.is_dir()and not any(p.is_symlink()for p in(packet,*packet.parents)),'ordinary exact Doctor native DATA checkout')
 for command,expected in [(['rev-parse','HEAD'],policy['doctor_packet_source'].encode()+b'\n'),(['status','--porcelain','--untracked-files=all'],b'')]:
  row=subprocess.run(['git','-C',str(packet),*command],capture_output=True,timeout=10);O.need(row.returncode==0 and row.stdout==expected and len(row.stderr)<=4096,'exact clean real Doctor native DATA checkout')
 C,P,I=apis()
 with aliases({'contract':C}):return I.inspect(packet)
