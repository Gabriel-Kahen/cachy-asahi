#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Read exact externally whole-pinned public cache DATA only; no image or actor."""
import argparse,hashlib,importlib.util,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
s=importlib.util.spec_from_file_location('pure_aux_defined_fields',HERE/'auxcache.py');A=importlib.util.module_from_spec(s);s.loader.exec_module(A)
def read_public(path,sha):
 path=Path(path);A.need(path.is_absolute()and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary selected public DATA path')
 fd=os.open(path,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);A.need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<a.st_size<=A.CAP,'bounded ordinary public cache body');body=os.read(fd,A.CAP+1);b=os.fstat(fd);identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns);A.need(identity(a)==identity(b)==identity(path.lstat())and len(body)==a.st_size and hashlib.sha256(body).hexdigest()==sha,'stable whole selected public cache SHA');return body
 finally:os.close(fd)
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--before',type=Path,required=True);p.add_argument('--before-sha256',required=True);p.add_argument('--after',type=Path);p.add_argument('--after-sha256');a=p.parse_args()
 try:
  first=read_public(a.before,a.before_sha256)
  if a.after is None:A.need(a.after_sha256 is None,'no partial after reference');answer=A.normalize(first)[0]
  else:A.need(a.after_sha256 is not None,'whole after pin required');answer=A.compare(first,read_public(a.after,a.after_sha256))
  print(json.dumps(answer,sort_keys=True,indent=2));return 0
 except(OSError,ValueError,TypeError)as error:p.exit(2,'public aux DATA refusal: '+str(error)+'\n')
if __name__=='__main__':raise SystemExit(main())
