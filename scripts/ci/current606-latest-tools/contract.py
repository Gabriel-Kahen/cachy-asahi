# SPDX-License-Identifier: MIT
"""Finite source-only joint composition; historical sources stay whole."""
import hashlib,importlib.util,json,os,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
LANE='scripts/ci/current606-latest-tools'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def read(p,cap=4*1024**2):
 need(not any(q.is_symlink()for q in(p,*p.parents))and p.is_file()and p.stat().st_nlink==1 and p.stat().st_size<=cap,'ordinary bounded source DATA')
 def pairs(rows):
  d={}
  for k,v in rows:need(k not in d,'duplicate JSON');d[k]=v
  return d
 return json.loads(p.read_bytes(),object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite JSON'))
def files(root):
 result={}
 for directory,dirs,names in os.walk(root):
  if Path(directory)==root:dirs[:]=[n for n in dirs if n!='.git'];names=[n for n in names if n!='.git']
  for n in dirs:need(not(Path(directory)/n).is_symlink(),'source directory alias')
  for n in names:
   p=Path(directory)/n;need(not p.is_symlink()and p.stat().st_nlink==1,'ordinary closed source leaf');result[p.relative_to(root).as_posix()]=pin(p.read_bytes())
 return result
def verify(root=ROOT):
 rows=read(HERE/'source-manifest.json')['files'];actual=files(root)
 excluded={LANE+'/source-manifest.json','.github/workflows/native-arm-current606-latest-tools-owned-copy.yml','.github/workflows/native-arm-build.yml'}
 need({k:v for k,v in actual.items()if k not in excluded}==rows and set(actual)==set(rows)|excluded,'complete exact joint source closure')
 roles=read(HERE/'historical-pins.json')
 for name,count in [('apps',336),('welcome',428)]:need(len(roles[name])==count and files(root/'historical'/name)==roles[name],'whole historical source role')
 return dict(status='SOURCE_ONLY_JOINT_LATEST_TOOLS_NOT_NATIVE',files=len(actual),historical_apps=336,historical_welcome=428,original_builder_count=8,capture_actors=9,final_actors=12,actual_source=None,actual_ref=None,actual_run=None)
def load(name,path,aliases=None):
 previous={k:sys.modules.get(k)for k in(aliases or{})};sys.modules.update(aliases or{})
 try:
  spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
 finally:
  for k,v in previous.items():
   if v is None:sys.modules.pop(k,None)
   else:sys.modules[k]=v
