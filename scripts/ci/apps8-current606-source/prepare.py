#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit exact380 from complete348 and accepted carrier93; source-only, no actors."""
import argparse,hashlib,json,os,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 20243, 'sha256': '926cd8a673e8fd934893c0efa30dcbd8eb8616233c8d4355b06d8ea09395ade1'}

def need(ok,why):
 if not ok:raise ValueError(why)

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def ordinary(path):
 path=Path(path).absolute();need('..'not in path.parts and not any(p.is_symlink()for p in(path,*path.parents)),'no source/output aliases or traversal');return path

def read(path):
 path=ordinary(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=16*1024**2,'bounded singlelink source/support input');raw=bytearray()
  while block:=os.read(fd,1024**2):raw.extend(block);need(len(raw)<=a.st_size,'source grew during read')
  identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns);need(len(raw)==a.st_size and identity(a)==identity(os.fstat(fd))==identity(path.lstat()),'whole stable atime-independent source identity');return bytes(raw)
 finally:os.close(fd)

def source(root,wanted):
 root=ordinary(root);need(root.is_dir(),'whole source/support directory required');expected_dirs={''}
 for n in wanted:
  p=Path(n);need(n and not p.is_absolute()and p.as_posix()==n and not set(p.parts)&{'.','..'}and'\\'not in n,'fixed canonical relative source path');expected_dirs.update(q.as_posix()if str(q)!='.'else''for q in p.parents)
 bodies={};directories={''}
 for p in sorted(root.rglob('*')):
  name=p.relative_to(root).as_posix()
  if p.relative_to(root).parts[0]=='.git':continue
  need(not p.is_symlink(),'source/support symlink refused')
  if p.is_dir():directories.add(name)
  else:need(name in wanted,'extra source/support file');bodies[name]=read(p)
 need(directories==expected_dirs and{n:pin(v)for n,v in bodies.items()}==wanted,'complete exact source/support closure including directories');return bodies

def inputs():
 need(not sys.flags.optimize,'optimized source checks refused');raw=read(HERE/'profile.json');need(pin(raw)==PROFILE,'whole pinned Apps8/current606 factory profile');p=json.loads(raw);need(p['kind']=='SOURCE_ONLY_EXACT_APPS8_CURRENT606_380_FACTORY'and p['actual']is None and p['parent']['source']=='3660e6cb87b4cb5591b1d295c62c8b02cca4b7e6'and p['carrier']['source']=='979b2d6ec7417e607a911d8c25bef2f1f7f72dcb'and p['carrier']['ref']=='codex/apps8-accepted-inputs-v1'and p['result']['source']=='c2b61b7089e41baed6b284bf0f3a55819f661c05','only exact published348/carrier93/result380 source case')
 maps=[]
 for name,row in(('parent348.json',p['parent']),('carrier93.json',p['carrier']),('expected380.json',p['result'])):
  raw=read(HERE/name);need(pin(raw)==row['map'],'whole hardpinned input/output map');maps.append(json.loads(raw))
 before,carrier,after=maps;need((len(before),len(carrier),len(after))==(348,93,380)and set(before)<=set(after)and set(after)-set(before)==set(p['added'])and {n for n in before if before[n]!=after[n]}==set(p['changed'])and(len(p['changed']),len(p['added']),p['held'])==(16,32,332),'finite16changed32added332held source closure')
 for n,row in p['changed'].items():need(row==dict(before=before[n],proposed=after[n]),'exact original and proposed source operands')
 need(p['payload']=={n:after[n]for n in set(p['changed'])|set(p['added'])},'exact48 source replacement/addition bodies')
 for name,w in p['legal'].items():need(name in('LICENSE','NOTICE.md')and pin(read(HERE/name))==w,'whole original source-factory license/notice')
 need(set(p['legal'])=={'LICENSE','NOTICE.md'},'complete factory legal closure');return p,before,carrier,after,source(HERE/'payload',p['payload'])

def emit(parent,carrier,output):
 p,before,input_map,after,payload=inputs();parent,carrier,output=map(ordinary,(parent,carrier,output));need(not os.path.lexists(output)and output.parent.is_dir()and all(not output.is_relative_to(root)and not root.is_relative_to(output)for root in(parent,carrier)),'fresh disjoint source-only output');bodies=source(parent,before);source(carrier,input_map)
 bodies.update(payload);need({n:pin(raw)for n,raw in bodies.items()}==after,'whole exact380 before any output');output.mkdir(mode=0o700)
 for n,raw in sorted(bodies.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 need({n:pin(raw)for n,raw in source(output,after).items()}==after,'complete final380 output');return dict(status='SOURCE_ONLY_EXACT_APPS8_CURRENT606_380_NOT_NATIVE_ACCEPTANCE',files=380,source=p['result']['source'],parent=p['parent']['source'],carrier=p['carrier']['source'],held=332,changed=16,added=32,actual=None,native='NOT_RUN',GUI='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')

CORRECTION_PROFILE={'bytes': 2854, 'sha256': '271e9c170590dd46247099f0cf4b4395ecd1ae20ed57697b2a1ce265560c3efb'}
def correction_inputs():
 raw=read(HERE/'correction-profile.json');need(pin(raw)==CORRECTION_PROFILE,'whole pinned carrier-env-correction profile');p=json.loads(raw);need(p['kind']=='SOURCE_ONLY_EXACT_CARRIER_ENV_CORRECTION'and p['actual']is None and p['before_source']=='c2b61b7089e41baed6b284bf0f3a55819f661c05'and p['after_source']=='5c3c2d0ce5b4f6c2672c9367b722170687c7de69','exact published correction source case')
 raw=read(HERE/'correction-maps.json');need(pin(raw)==p['maps'],'whole correction before/after map pins');maps=json.loads(raw);before,after=maps['before'],maps['after'];need(set(before)==set(after)and len(after)==p['files']==380 and {n for n in before if before[n]!=after[n]}==set(p['changed'])and len(p['changed'])==5 and p['held']==375,'finite exact correction operands')
 for n,row in p['changed'].items():need(row==dict(before=before[n],proposed=after[n]),'complete correction before/proposed operands')
 need(p['payload']=={n:after[n]for n in p['changed']},'exact readable correction payload set')
 payload=source(HERE/'correction-payload',p['payload'])
 return p,before,after,payload

def emit_carrier_env(parent,carrier,output):
 p,before,input_map,old,payload=inputs();variant,previous,after,replacements=correction_inputs();need(old==previous,'whole original380 correction input');parent,carrier,output=map(ordinary,(parent,carrier,output));need(not os.path.lexists(output)and output.parent.is_dir()and all(not output.is_relative_to(root)and not root.is_relative_to(output)for root in(parent,carrier)),'fresh disjoint source-only correction output');bodies=source(parent,before);source(carrier,input_map)
 bodies.update(payload);need({n:pin(raw)for n,raw in bodies.items()}==old,'whole original380 emission in memory');bodies.update(replacements);need({n:pin(raw)for n,raw in bodies.items()}==after,'whole corrected380 before any output');output.mkdir(mode=0o700)
 for n,raw in sorted(bodies.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 source(output,after);return dict(status='SOURCE_ONLY_EXACT380_CARRIER_ENV_CORRECTION_NOT_NATIVE',files=380,source=variant['after_source'],previous_source=variant['before_source'],held=variant['held'],changed=len(replacements),actual=None,native='NOT_RUN',hardware='NOT_RUN')

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--parent',type=Path,required=True);parser.add_argument('--carrier',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);parser.add_argument('--carrier-env-correction',action='store_true',help='explicit corrected5c3c carrier environment; defaultc2 unchanged');a=parser.parse_args();print(json.dumps((emit_carrier_env if a.carrier_env_correction else emit)(a.parent,a.carrier,a.output),sort_keys=True))
if __name__=='__main__':main()
