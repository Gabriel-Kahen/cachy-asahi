#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit exact GNU745 fresh-parent source from a complete fixed parent; no actors."""
import argparse,hashlib,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE_SHA='13d00bd6b78c95ced162f657ea0806a5a1f8bf7735ce773baf8dbf479ffda8c8'

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def identity(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def ordinary(path):need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary no-alias path')
def read(path):
 before=path.lstat();need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=16*1024**2,'bounded ordinary single-link file')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  need(identity(os.fstat(fd))==identity(before),'opened input identity')
  with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(before.st_size+1)
  need(len(raw)==before.st_size and identity(os.fstat(fd))==identity(path.lstat())==identity(before),'whole stable input')
  return raw
 finally:os.close(fd)
def tree(root,checkout=False):
 ordinary(root);need(root.is_dir(),'ordinary source root');result={}
 for directory,dirs,names in os.walk(root,followlinks=False):
  directory=Path(directory)
  if directory==root and checkout:
   dirs[:]=[n for n in dirs if n!='.git'];names=[n for n in names if n!='.git']
  for name in dirs:need(stat.S_ISDIR((directory/name).lstat().st_mode),'ordinary source directory')
  for name in names:
   path=directory/name;result[path.relative_to(root).as_posix()]=read(path)
 return result
def pins(rows):return {n:pin(raw)for n,raw in rows.items()}
def profile():
 raw=read(HERE/'profile.json');need(pin(raw)['sha256']==PROFILE_SHA,'whole fixed GNU parent profile');value=json.loads(raw)
 need(len(value['before'])==len(value['after'])==745 and value['before'].keys()==value['after'].keys(),'whole fixed745 membership')
 changed={n:dict(before=value['before'][n],after=value['after'][n])for n in value['before']if value['before'][n]!=value['after'][n]}
 need(changed==value['changed']and len(changed)==8 and value['held']==737,'eight changed737 held')
 return value

def emit(parent,output):
 parent,output=Path(parent).absolute(),Path(output).absolute();ordinary(parent);ordinary(output)
 need(not output.exists()and output.parent.is_dir(),'fresh output with existing ordinary parent')
 for root in(parent,HERE):need(not output.is_relative_to(root)and not root.is_relative_to(output),'disjoint source/output')
 value=profile();before=tree(parent,checkout=True);need(pins(before)==value['before'],'whole pinned GNU parent745')
 payload=tree(HERE/'payload');need(pins(payload)=={n:row['after']for n,row in value['changed'].items()},'whole eight readable payload replacements')
 proposed=before|payload;need(pins(proposed)==value['after'],'whole proposed745 before output')
 output.mkdir(mode=0o700)
 for name,raw in sorted(proposed.items()):
  path=output/name;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 need(pins(tree(output))==value['after'],'whole emitted745')
 return dict(status='SOURCE_ONLY',files=745,changed=8,held=737,parent_source=value['parent_source'],expected_source=value['expected_source'],native_fit='UNKNOWN',acceptance=False)
if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--parent',type=Path,required=True,help='complete immutable4a9b3833 source checkout');parser.add_argument('--output',type=Path,required=True,help='fresh disjoint ordinary output');parser.add_argument('--immutable-map',action='store_true',help='explicit406d parent to46db private immutable-map745 profile');args=parser.parse_args()
 if args.immutable_map:
  import importlib.util
  spec=importlib.util.spec_from_file_location('_gnu_immutable_map_factory',HERE/'immutable_map.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);result=module.emit(args.parent,args.output)
 else:result=emit(args.parent,args.output)
 print(json.dumps(result,sort_keys=True))
