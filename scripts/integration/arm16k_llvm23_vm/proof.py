# SPDX-License-Identifier: MIT
"""Passive durable guest-output review; never grants VM or Root acceptance."""
import hashlib,importlib.util,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent

def load(name):
 s=importlib.util.spec_from_file_location('llvm_vm_passive_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def outputs(directory,fields,baseline_sha256,host_epoch,host_now,byte_cap,nonce):
 """Called only after Root's natural VM retirement and readonly disk extraction."""
 K=load('contracts');P=load('protocol');P.validate(fields,baseline_sha256,host_epoch,host_now)
 root=K.ordinary(directory);K.need(root.is_dir()and type(byte_cap)is int and byte_cap>0,'bounded durable output directory')
 K.need({p.name for p in root.iterdir()}=={'smoke','unwind','outputs.sha256','summary.env'},'closed durable results membership')
 total=0;observed={}
 for p in root.iterdir():
  info=p.lstat();K.need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and not stat.S_IMODE(info.st_mode)&0o022,'ordinary Root-controlled extracted output')
  total+=info.st_size;K.need(total<=byte_cap,'actual durable output cap');observed[p.name]=K.pin(p,byte_cap)
 expected={'smoke':fields['C_SHA256'],'unwind':fields['CXX_SHA256']}
 for n,h in expected.items():K.need(observed[n]['sha256']==h,'durable binary differs from Root restoration receipt')
 manifest=''.join(expected[n]+'  '+n+'\n'for n in('smoke','unwind')).encode()
 K.need((root/'outputs.sha256').read_bytes()==manifest,'exact two-output hash inventory')
 raw=(root/'summary.env').read_bytes();summary=P.frame(raw,nonce,'RESTORED');K.need(summary==fields,'durable and serial nonce-bound Root restoration receipts differ')
 path=HERE/'frozen/llvm_elf.py';origin=K.load(HERE/'helper-origin.json');K.need(K.pin(path)=={k:origin['files']['llvm_elf.py'][k]for k in('bytes','sha256')},'exact reviewed passive ELF helper')
 spec=importlib.util.spec_from_file_location('llvm_vm_frozen_elf',path);E=importlib.util.module_from_spec(spec);spec.loader.exec_module(E)
 elfs={}
 for name in expected:
  file=root/name
  with file.open('rb')as stream:row=E.elf(stream,observed[name]['bytes'],name)
  K.need(row is not None and row['kind']in(2,3),'actual linked AArch64 ELF with16K LOAD geometry');elfs[name]=row
 return dict(status='PASS_DURABLE_LLVM23_OUTPUT_DATA_ONLY',files=observed,ELF16K=elfs,VM_acceptance=None,Root_acceptance=None,native_acceptance=False)
