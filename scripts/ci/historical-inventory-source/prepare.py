#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit closed source view for unchanged historical inventory-bound factories."""
import argparse,hashlib,json,os,stat
from pathlib import Path,PurePosixPath
HERE=Path(__file__).resolve().parent
PROFILE_SHA='edbf28ee65bdc68c903255be16bac7147c6d08e2c1856ad6b282c81df297179e'
BASELINE='inventory-19a8bdb45916e5dffef7a4c1496ebbc489792795ea2906a3d705a67e3906b880'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def identity(s):return(s.st_mode,s.st_dev,s.st_ino,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def ordinary(path,directory=False):
 path=Path(path).absolute();need('..'not in path.parts and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary unaliased source/view path');s=path.lstat();need(stat.S_ISDIR(s.st_mode)if directory else stat.S_ISREG(s.st_mode)and s.st_nlink==1,'ordinary directory or single-link source required');return path,s
def read(path):
 path,s=ordinary(path);need(0<s.st_size<=8*1024**2,'bounded nonempty source');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 try:
  need(identity(os.fstat(fd))==identity(s),'source changed before read');parts=[];total=0
  while raw:=os.read(fd,1024**2):parts.append(raw);total+=len(raw);need(total<=s.st_size,'source grew')
  need(total==s.st_size and identity(os.fstat(fd))==identity(s)==identity(path.lstat()),'whole stable source read');return b''.join(parts)
 finally:os.close(fd)
def relative(name):
 p=PurePosixPath(name);need(type(name)is str and name==p.as_posix()and not p.is_absolute()and all(v not in('','.','..')for v in p.parts),'exact relative source leaf');return p

def profile():
 raw=read(HERE/'profile.json');need(pin(raw)['sha256']==PROFILE_SHA,'whole fixed historical profile');p=json.loads(raw);need(p['schema']==1 and p['baseline']==BASELINE and len(p['factories'])==14,'finite explicit historical factories');return p

def selected(p,factories):
 need(type(factories)is list and factories and len(factories)==len(set(factories)),'explicit distinct factory selectors')
 if factories==['all']:factories=sorted(p['factories'])
 need(all(n in p['factories']for n in factories),'unknown historical factory selection');files={}
 for name in factories:
  for n,row in p['factories'][name]['files'].items():
   relative(n);need(n not in files or files[n]==row,'conflicting historical source roles');files[n]=row
 need(0<len(files)<=1024 and files[p['inventory_path']]=={k:p['snapshot'][k]for k in('bytes','sha256')},'finite single exact historical inventory');return factories,dict(sorted(files.items()))

def prepare(source,output,factories,baseline=BASELINE):
 p=profile();need(baseline==p['baseline'],'explicit immutable historical baseline required');source,_=ordinary(source,True);output=Path(output).absolute();need('..'not in output.parts and not os.path.lexists(output)and output.parent.is_dir()and not any(q.is_symlink()for q in(output,*output.parents)),'fresh owned ordinary source view');need(output.parent.stat().st_uid==os.getuid()and not(output.parent.stat().st_mode&0o022),'private caller-owned output parent')
 factories,files=selected(p,factories);need(not source.is_relative_to(output)and not output.is_relative_to(HERE)and all(not(source/n).is_relative_to(output)and not output.is_relative_to(source/n)for n in files),'view must be disjoint from every immutable input leaf');snapshot=read(HERE/relative(p['snapshot']['path']));need(pin(snapshot)=={k:p['snapshot'][k]for k in('bytes','sha256')},'exact immutable inventory snapshot');current=read(source/p['inventory_path']);contents={};modes={}
 for name,want in files.items():
  path=source/relative(name)
  if name==p['inventory_path']:raw=snapshot;mode=0o644
  else:raw=read(path);mode=path.stat().st_mode&0o777;need(not mode&0o022,'noninventory source is not group/world writable')
  need(pin(raw)==want,'historical noninventory source drift: '+name);contents[name]=raw;modes[name]=mode
 # Every byte is verified before the first output node. No code/actors/Git/network run.
 output.mkdir(mode=0o700)
 for name,raw in contents.items():
  path=output/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,modes[name])
  with os.fdopen(fd,'wb')as stream:stream.write(raw)
 actual={q.relative_to(output).as_posix():pin(read(q))for q in output.rglob('*')if q.is_file()};need(actual==files,'whole closed emitted historical source view');return dict(status='SOURCE_ONLY_EXPLICIT_HISTORICAL_INVENTORY_VIEW',baseline=baseline,factories=factories,files=len(files),historical_inventory=pin(snapshot),current_inventory=pin(current),current_inventory_used_for_historical_emission=False,native='NOT_RUN',acceptance=False)

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',required=True,type=Path);p.add_argument('--output',required=True,type=Path);p.add_argument('--factory',required=True,action='append',help='fixed factory name; all selects the exact union of fourteen views');p.add_argument('--baseline',default=BASELINE);a=p.parse_args();print(json.dumps(prepare(a.source,a.output,a.factory,a.baseline),sort_keys=True))
if __name__=='__main__':main()
