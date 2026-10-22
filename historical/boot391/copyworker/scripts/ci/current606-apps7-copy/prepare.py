#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Re-emit this exact finite worker role; no actor or selection binding."""
import argparse,json,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
def verify():
 m=C.decode(C.ordinary(HERE/'source-manifest.json',4*1024**2));C.need(m['status']=='SOURCE_ONLY_COPY_WORKER_NOT_NATIVE_ACCEPTANCE','finite source-only role')
 C.need(0<len(m['files'])<=64,'finite source role count')
 for name,pin in m['files'].items():
  C.need(type(name)is str and not name.startswith('/')and Path(name).as_posix()==name and not{'.','..'}&set(Path(name).parts),'contained source file')
  C.need(C.pin(C.ordinary(ROOT/name,16*1024**2))==pin,'whole source role pin')
 roles=C.decode(C.ordinary(HERE/'role-pins.json',1024**2))
 for name,row in roles.items():C.need(m['files'][name]=={k:row[k]for k in('bytes','sha256')},'exact held role provenance')
 return m

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path);a=p.parse_args();m=verify()
 if a.output:
  C.need(a.output.is_absolute()and not a.output.exists()and not any(p.is_symlink()for p in(a.output.parent,*a.output.parent.parents)),'fresh explicit source output');a.output.mkdir(mode=0o700)
  for name in list(m['files'])+[HERE.relative_to(ROOT).as_posix()+'/source-manifest.json']:
   q=a.output/name;q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/name,q)
 print(json.dumps(dict(status='SOURCE_ONLY_COPY_WORKER_NOT_NATIVE_ACCEPTANCE',files=len(m['files'])+1,actual_source=None,actual_ref=None,actual_run=None)))
if __name__=='__main__':main()
