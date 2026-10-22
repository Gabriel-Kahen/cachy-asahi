#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce exact published Core7 two-boot source33; no actors or acceptance."""
import argparse,hashlib,json,os,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 9359, 'sha256': '47ba8af77569cc2fb381f7c8b3cc76020d3686c3912038ae60902c0a7391b6b5'}

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def ordinary(path):
 path=Path(path).absolute();need('..'not in path.parts and not any(p.is_symlink()for p in(path,*path.parents)),'no source/output aliases or traversal');return path
def read(path,cap=16*1024**2):
 path=ordinary(path);fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded singlelink source/support input');raw=bytearray()
  while block:=os.read(fd,1024**2):raw.extend(block);need(len(raw)<=a.st_size,'source grew during read')
  identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns);need(len(raw)==a.st_size and identity(a)==identity(os.fstat(fd))==identity(path.lstat()),'whole stable atime-independent source identity');return bytes(raw)
 finally:os.close(fd)
def source(root,wanted,cap=16*1024**2):
 root=ordinary(root);need(root.is_dir(),'whole source/support directory required');expected_dirs={''}
 for n in wanted:
  p=Path(n);need(n and not p.is_absolute()and p.as_posix()==n and not set(p.parts)&{'.','..'}and'\\'not in n,'fixed canonical relative source path');expected_dirs.update(q.as_posix()if str(q)!='.'else''for q in p.parents)
 bodies={};directories={''}
 for p in sorted(root.rglob('*')):
  name=p.relative_to(root).as_posix()
  if p.relative_to(root).parts[0]=='.git':continue
  need(not p.is_symlink(),'source/support symlink refused')
  if p.is_dir():directories.add(name)
  else:need(name in wanted,'extra source/support file');bodies[name]=read(p,cap)
 need(directories==expected_dirs and{n:pin(v)for n,v in bodies.items()}==wanted,'complete exact source/support closure including directories');return bodies

def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def inputs():
 need(not sys.flags.optimize,'optimized source checks refused');raw=read(HERE/'profile.json');need(pin(raw)==PROFILE,'whole pinned two-boot factory profile');p=json.loads(raw)
 need(p['kind']=='SOURCE_ONLY_EXACT_CORE7_REAL_SYSTEMD_TWO_BOOT_FACTORY'and p['actual']is None and p['result']['source']=='d0a63680da2bc5e94c32aec27a40dcadf8b024f9'and p['result']['ref']=='codex/core7-systemd-two-boot-v1','only exact source-only33 profile')
 expected=p['result']['files'];need(len(expected)==33 and len(p['templates'])==30 and p['derived']==dict(manifest='source-manifest.json',workflows=['.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml']),'finite30-readable/three-derived source closure')
 bodies=source(HERE/'templates',p['templates']);manifest=encoded(dict(schema=1,purpose='CORE7_REAL_HOOKS_AND_ACTUAL_PID1_SOURCE_ONLY',actual=None,files=p['templates']));bodies['source-manifest.json']=manifest
 workflow=bodies['workflow.yml.in'].replace(b'@ENTRY_SHA@',pin(bodies['entry.py'])['sha256'].encode()).replace(b'@MANIFEST_SHA@',pin(manifest)['sha256'].encode())
 need(b'@ENTRY_SHA@'not in workflow and b'@MANIFEST_SHA@'not in workflow,'closed generated workflow stamps')
 for name in p['derived']['workflows']:bodies[name]=workflow
 need({n:pin(raw)for n,raw in bodies.items()}==expected,'all33 exact source bytes before writing');return p,bodies

def emit(output):
 p,bodies=inputs();output=ordinary(output);need(not os.path.lexists(output)and output.parent.is_dir()and not output.is_relative_to(HERE)and not HERE.is_relative_to(output),'fresh ordinary disjoint source-only output');output.mkdir(mode=0o700)
 for n,raw in sorted(bodies.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 need({n:pin(raw)for n,raw in source(output,p['result']['files']).items()}==p['result']['files'],'all33 emitted bytes after writing');return result(p)

def result(p):return dict(status='SOURCE_ONLY_EXACT33_CORE7_TWO_BOOT_NOT_NATIVE_ACCEPTANCE',files=33,source=p['result']['source'],actual=None,native='NOT_RUN',Asahi='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')
def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path);parser.add_argument('--source-only',action='store_true',help='check all33 composed bytes without writing or actors');a=parser.parse_args();need(a.output is not None or a.source_only,'explicit fresh output or source-only required');print(json.dumps(emit(a.output)if a.output is not None else result(inputs()[0]),sort_keys=True))
if __name__=='__main__':main()
