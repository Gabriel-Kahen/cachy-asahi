#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fixed bounded receipts only. No private maps, package inputs or images."""
import argparse,os,re,stat,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import hosted as O
FIXED={'archive8-custody.json','archive20-custody.json','archive32-custody.json','owner-lease.json','source-proof.json','component-custody.json','commands.json','owner-result.json','cleanup-commands.json','failure-cleanup.json','runtime/qemu.json','runtime/uart.log','runtime/qemu.stderr','runtime/guest-result.json','runtime/producer-retirement.json','runtime/preparation-retirement.json','prepare/commands.json','prepare/preparation-result.json'}
def permitted(name):return name in FIXED or re.fullmatch(r'(command|cleanup)-[0-9]{2}\.(stdout|stderr)',name)is not None or re.fullmatch(r'prepare/command-[0-9]{2}\.(stdout|stderr)',name)is not None

def run(work,output):
 O.need(not output.exists()and not output.is_symlink()and output.parent.is_dir(),'fresh bounded public output');rows={};values={};total=0
 if work.exists():
  st=work.lstat();O.need(stat.S_ISDIR(st.st_mode)and st.st_uid==os.getuid()and stat.S_IMODE(st.st_mode)==0o700,'owned private output root')
  for directory in (work,work/'runtime',work/'prepare'):
   if not directory.exists():continue
   O.need(not directory.is_symlink(),'ordinary receipt directory')
   for p in directory.iterdir():
    name=p.relative_to(work).as_posix()
    if not permitted(name):continue
    raw=O.read(p,16*1024**2);total+=len(raw);O.need(total<=192*1024**2 and len(rows)<128,'original192MiB finite receipt cap');rows[name]=O.pin(raw);values[name]=raw
 output.mkdir(mode=0o700)
 for name,raw in values.items():p=output/name;p.parent.mkdir(mode=0o700,exist_ok=True);p.write_bytes(raw);p.chmod(0o600)
 result=dict(status='RETAINED_DATA_ONLY_NOT_ACCEPTANCE',files=rows,total_bytes=total,private_maps='NOT_EXPORTED',packages='NOT_EXPORTED',kernel_Image='NOT_EXPORTED');(output/'retention.json').write_bytes(O.encoded(result));return result
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--work',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(O.encoded(run(a.work,a.output)).decode())
