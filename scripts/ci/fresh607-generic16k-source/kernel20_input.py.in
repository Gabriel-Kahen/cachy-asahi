#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact existing kernel20 BUILD_ONLY input; no priorboot/runtime authority."""
import argparse,importlib.util,json,os,shutil,sys,tempfile,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common as C,page_mode as M

def rows(root):
 root=C.safe(root);v={}
 for q in root.rglob('*'):
  n=q.relative_to(root).as_posix()
  if n.split('/')[0]=='.git':continue
  C.need(not q.is_symlink()and(q.is_file()or q.is_dir()),'ordinary exact kernel source')
  if q.is_file():v[n]=C.pin(C.read(q))
 return v

def acquire(source,output):
 source=C.safe(source);output,=C.fresh(output,protected=(source,C.ROOT));p=M.configuration();C.need(rows(source)==p['gnu_source_files']and p['gnu_source']=='de1aab259df6bda8ad36f959392e3fc4eb35b622','whole exact749 kernel-input SOURCE only');started=time.monotonic();saved,paths=dict(sys.modules),list(sys.path)
 with tempfile.TemporaryDirectory(prefix='fresh607-kernel20-')as td:
  root=Path(td)/'source';root.mkdir(mode=0o700)
  for n,w in p['gnu_source_files'].items():q=root/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(C.checked(source/n,w))
  C.need(rows(root)==p['gnu_source_files']and rows(source)==p['gnu_source_files'],'kernel source snapshot preflight');lane=root/'scripts/ci/gnu-immutable-source-native'
  try:
   for n in {q.stem for q in lane.glob('*.py')}|{'custody','replay','collect'}:sys.modules.pop(n,None)
   sys.path.insert(0,str(lane));s=importlib.util.spec_from_file_location('_fresh607_kernel20_input',lane/'kernel_input.py');k=importlib.util.module_from_spec(s);s.loader.exec_module(k);known,decision=k.known();C.need(known==p['kernel']and decision['boot']==decision['VM']==decision['hardware']=='NOT_RUN','BUILD_ONLY no priorboot credit');download=Path(td)/'input';k.acquire(download);C.need(time.monotonic()-started<300,'whole source-owned kernel input300');M.export(download/'Image',download/'config',output)
  finally:
   sys.path[:]=paths
   for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
   sys.modules.update(saved)
  C.need(rows(root)==p['gnu_source_files']and rows(source)==p['gnu_source_files'],'kernel source preserved after input checking')
 return dict(status='EXACT_EXISTING_KERNEL20_INPUT_ONLY',artifact=p['kernel']['artifact'],page_size=16384,boot='NOT_RUN',fresh607='NOT_RUN',hardware='NOT_RUN')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(acquire(a.source,a.output),sort_keys=True))
