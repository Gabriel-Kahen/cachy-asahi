#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce exact published Core7 two-boot source34; no actors or acceptance."""
import argparse,hashlib,json,os,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROFILE={'bytes': 9626, 'sha256': '3358391cb476548a4ecc44cb205ff5595f44a44d6f96155ae5fd1d6ef18c5cc2'}

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
 need(p['kind']=='SOURCE_ONLY_EXACT_CORE7_REAL_SYSTEMD_TWO_BOOT_FACTORY'and p['actual']is None and p['result']['source']=='a74c54093bf8d09883e32b0d64b77f46223920e1'and p['result']['ref']=='codex/core7-host-qemu-v1','only exact source-only34 profile')
 expected=p['result']['files'];need(len(expected)==34 and len(p['templates'])==31 and p['derived']==dict(manifest='source-manifest.json',workflows=['.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml']),'finite31-readable/three-derived source closure')
 bodies=source(HERE/'templates',p['templates']);manifest=encoded(dict(schema=1,purpose='CORE7_REAL_HOOKS_AND_ACTUAL_PID1_SOURCE_ONLY',actual=None,files=p['templates']));bodies['source-manifest.json']=manifest
 workflow=bodies['workflow.yml.in'].replace(b'@ENTRY_SHA@',pin(bodies['entry.py'])['sha256'].encode()).replace(b'@MANIFEST_SHA@',pin(manifest)['sha256'].encode())
 need(b'@ENTRY_SHA@'not in workflow and b'@MANIFEST_SHA@'not in workflow,'closed generated workflow stamps')
 for name in p['derived']['workflows']:bodies[name]=workflow
 need({n:pin(raw)for n,raw in bodies.items()}==expected,'all34 exact source bytes before writing');return p,bodies

def emit(output):
 p,bodies=inputs();output=ordinary(output);need(not os.path.lexists(output)and output.parent.is_dir()and not output.is_relative_to(HERE)and not HERE.is_relative_to(output),'fresh ordinary disjoint source-only output');output.mkdir(mode=0o700)
 for n,raw in sorted(bodies.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 need({n:pin(raw)for n,raw in source(output,p['result']['files']).items()}==p['result']['files'],'all34 emitted bytes after writing');return result(p)

def result(p):return dict(status='SOURCE_ONLY_EXACT34_CORE7_TWO_BOOT_NOT_NATIVE_ACCEPTANCE',files=34,source=p['result']['source'],actual=None,native='NOT_RUN',Asahi='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')
VIRTIO20_PROFILE = {'bytes': 20331, 'sha256': '1e284deca83abf31b6fca663705f371b9642006e09c2f45840118b0c22e444db'}

def virtio20_inputs():
 original,bodies=inputs();raw=read(HERE/'virtio20-profile.json');need(pin(raw)==VIRTIO20_PROFILE,'whole pinned virtio20 correction profile');p=json.loads(raw)
 need(p['kind']=='SOURCE_ONLY_EXACT_CORE7_VIRTIO20_CORRECTION'and p['actual']is None and p['parent']['files']==original['result']['files']and p['parent']['source']==original['result']['source']and p['result']['source']=='bc9c55f9c245df31061aed7e49e636eeae0a018c'and p['result']['ref']=='codex/core7-virtio20-v1','exact unchanged34 parent and new34 source-only identity')
 need(set(p['payload'])=={'case.py','boot.py','host.py','guest_guard.py','controller.py','guest.py','validate.py','test_case.py','test_protocol.py'}and len(p['held'])==22,'nine readable correction leaves and22 held source leaves')
 bodies.update(source(HERE/'virtio20',p['payload']))
 manifest=encoded(dict(schema=1,purpose='CORE7_REAL_HOOKS_AND_ACTUAL_PID1_SOURCE_ONLY',actual=None,files={n:pin(raw)for n,raw in bodies.items()if n!='source-manifest.json'and not n.startswith('.github/')}));bodies['source-manifest.json']=manifest
 workflow=bodies['workflow.yml.in'].replace(b'@ENTRY_SHA@',pin(bodies['entry.py'])['sha256'].encode()).replace(b'@MANIFEST_SHA@',pin(manifest)['sha256'].encode())
 for n in original['derived']['workflows']:bodies[n]=workflow
 need({n:pin(raw)for n,raw in bodies.items()}==p['result']['files']and len(bodies)==34 and all(p['parent']['files'][n]==p['result']['files'][n]==row for n,row in p['held'].items()),'all34 corrected source bytes before writing')
 return p,bodies

def emit_virtio20(output):
 p,bodies=virtio20_inputs();output=ordinary(output);need(not os.path.lexists(output)and output.parent.is_dir()and not output.is_relative_to(HERE)and not HERE.is_relative_to(output),'fresh ordinary disjoint source-only output');output.mkdir(mode=0o700)
 for n,raw in sorted(bodies.items()):
  path=output/n;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 need({n:pin(raw)for n,raw in source(output,p['result']['files']).items()}==p['result']['files'],'all34 emitted virtio20 bytes after writing');return result(p)

def main():
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path);parser.add_argument('--source-only',action='store_true',help='check all34 composed bytes without writing or actors');parser.add_argument('--virtio20',action='store_true',help='opt in to exact published20-byte serial/bootstrap correction');a=parser.parse_args();need(a.output is not None or a.source_only,'explicit fresh output or source-only required');selected_emit=emit_virtio20 if a.virtio20 else emit;selected_inputs=virtio20_inputs if a.virtio20 else inputs;print(json.dumps(selected_emit(a.output)if a.output is not None else result(selected_inputs()[0]),sort_keys=True))
if __name__=='__main__':main()
