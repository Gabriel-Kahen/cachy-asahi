#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit only the exact frozen Doctor2 current606 source; no actors or package changes."""
import argparse,base64,hashlib,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 1426795, 'sha256': '39459c6aab766b1a31207628dbac9c24e1a11af197fab6c554063df6f118f5ac'}
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def relative(name):
 need(type(name)is str and name and not name.startswith('/')and Path(name).as_posix()==name and '\\'not in name and all(n not in('','.','..')for n in name.split('/')),'contained source path');return name

def ordinary(path,cap=16*1024**2):
 path=Path(path).absolute();need('..'not in path.parts,'ordinary source path');parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  for part in path.parts[1:-1]:
   fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent);os.close(parent);parent=fd
  fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
  try:
   a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded ordinary single-link source');raw=bytearray()
   while len(raw)<=a.st_size:
    part=os.read(fd,min(65536,a.st_size-len(raw)+1))
    if not part:break
    raw.extend(part)
   b=os.fstat(fd);key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
   need(key(a)==key(b)==key(os.stat(path.name,dir_fd=parent,follow_symlinks=False))and len(raw)==a.st_size,'source changed during read');return bytes(raw)
  finally:os.close(fd)
 finally:os.close(parent)

def files(root):
 need(root.is_absolute()and root.is_dir()and not any(p.is_symlink()for p in(root,*root.parents)),'ordinary explicit predecessor root');out={}
 for parent,dirs,names in os.walk(root):
  if Path(parent)==root:dirs[:]=[n for n in dirs if n!='.git'];names=[n for n in names if n!='.git']
  for n in dirs:need(not(Path(parent)/n).is_symlink(),'source directory alias')
  for n in names:
   p=Path(parent)/n;out[p.relative_to(root).as_posix()]=ordinary(p)
 return out

def profile():
 raw=ordinary(HERE/'source.json');need(pin(raw)==PROFILE,'whole frozen Doctor source authority');return json.loads(raw)

def prepare(predecessor,output,*,selected=False):
 p=profile();before=files(predecessor);need({n:pin(v)for n,v in before.items()}==p['predecessor']['files']and len(before)==348,'complete genuine Apps350348 predecessor required before output')
 need(type(selected)is bool,'explicit selected source view');view=p['views']['selected'if selected else'default'];need(len(view['files'])==353 and len(view['paths'])==348 and len(view['added'])==5,'finite Doctor353 source closure');result={}
 for old,new in view['paths'].items():
  relative(old);relative(new);need(old in before and new not in result,'one complete predecessor path correspondence');wanted=view['files'][new]
  raw=before[old]if pin(before[old])==wanted else base64.b64decode(p['blobs'][wanted['sha256']],validate=True);need(pin(raw)==wanted,'whole proposed source body');result[new]=raw
 for name in view['added']:
  relative(name);need(name not in result,'distinct exact new source leaf');wanted=view['files'][name];raw=base64.b64decode(p['blobs'][wanted['sha256']],validate=True);need(pin(raw)==wanted,'whole exact added source');result[name]=raw
 need(set(result)==set(view['files'])and {n:pin(b)for n,b in result.items()}==view['files'],'complete353 before output')
 output=Path(output).absolute();need(not output.exists()and output.parent.is_dir()and not any(p.is_symlink()for p in(output,*output.parents))and not output.is_relative_to(predecessor)and not predecessor.is_relative_to(output),'fresh disjoint ordinary source output')
 output.mkdir(mode=0o700)
 for name,raw in result.items():
  target=output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
 need({n:pin(v)for n,v in files(output).items()}==view['files'],'whole emitted source equality');return dict(status='SOURCE_ONLY_DOCTOR2_CURRENT606_NOT_NATIVE',files=353,view='selected'if selected else'default',source_authority=p['source_authority'],actual_source=None,actual_ref=None,actual_run=None,acceptance='NOT_GRANTED')

def prepare_real27(predecessor,output):
 p=profile();v=p['real27'];before=files(predecessor)
 need(len(before)==361 and {n:pin(b)for n,b in before.items()}==v['predecessor']['files'],'complete genuine nullfd361 predecessor required before output')
 need(len(v['files'])==361 and set(v['files'])==set(before)and len(v['changed'])==4,'finite real27 source closure');result={}
 for name,wanted in v['files'].items():
  relative(name);raw=before[name]if pin(before[name])==wanted else base64.b64decode(p['blobs'][wanted['sha256']],validate=True);need(pin(raw)==wanted,'exact real27 source body');result[name]=raw
 need({n for n in before if result[n]!=before[n]}==set(v['changed']),'only four real27 source leaves')
 output=Path(output).absolute();need(not output.exists()and output.parent.is_dir()and not any(x.is_symlink()for x in(output,*output.parents))and not output.is_relative_to(predecessor)and not predecessor.is_relative_to(output),'fresh disjoint ordinary source output')
 output.mkdir(mode=0o700)
 for name,raw in result.items():
  target=output/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
 need({n:pin(b)for n,b in files(output).items()}==v['files'],'whole emitted real27 source equality')
 return dict(status='SOURCE_ONLY_DOCTOR2_REAL27_NOT_NATIVE',files=361,source_authority=v['source'],actual_source=None,actual_ref=None,actual_run=None,acceptance='NOT_GRANTED')

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--predecessor-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True);g=p.add_mutually_exclusive_group();g.add_argument('--selected',action='store_true');g.add_argument('--real27',action='store_true',help='emit exact94a45 source from complete60b574361 predecessor');a=p.parse_args();result=prepare_real27(a.predecessor_root.absolute(),a.output.absolute())if a.real27 else prepare(a.predecessor_root.absolute(),a.output.absolute(),selected=a.selected);print(encoded(result).decode(),end='')
if __name__=='__main__':main()
