#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Create one private execution selection only after genuine component gates."""
import argparse,json,os,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
import kernel_input as K,media_adapter as M

def configure(binding,inputs,output):
 s=C.decode(C.read(binding));C.native_gate(s,inputs);C.actual_environment(s);profile,_,_,_=K.imported(s,inputs);C.source_check();C.support()
 C.need(os.getuid()==os.geteuid()>0 and output.is_absolute()and not output.exists()and not output.is_symlink()and output.parent.is_dir(),'ordinary caller and fresh selection file')
 C.need(s.get('media')is None and s.get('producer_report')is not None,'new prepared-media lease required after existing original574 producer')
 C.checked(inputs,s['producer_report'],2*1024**2)
 selection=dict(s,nonce=os.urandom(16).hex(),uid=os.getuid(),gid=os.getgid(),kernel=profile,bindings=list(M.BINDINGS),source_files=C.decode(C.read(C.HERE/'source-files.json',1024**2))['files'],runner_files=C.decode(C.read(C.HERE/'runner-files.json'))['files'])
 fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
 try:
  with os.fdopen(fd,'wb')as stream:stream.write(C.encoded(selection));stream.flush();os.fsync(stream.fileno())
 except BaseException:raise # Unknown partial file is retained, never silently reused.
 return dict(status='BOUND_EXECUTION_SELECTION_NOT_BOOT_OR_ACCEPTANCE',selection=C.row(output),nonce=selection['nonce'],actual_source=selection['VM_source'],actual_run=selection['VM_run'])
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in('binding','inputs','output'):p.add_argument('--'+n,type=Path,required=True)
 a=p.parse_args();print(json.dumps(configure(a.binding,a.inputs,a.output),sort_keys=True))
