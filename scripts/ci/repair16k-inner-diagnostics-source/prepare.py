#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Exact finite203 diagnostic emission from genuine compiled-parent source204."""
import argparse,hashlib,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
CARRIER='33b9bcee3b42dd21f4317d3b400744839cdd38be'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def ordinary(p):
 need(p.is_absolute()and not any(q.is_symlink()for q in(p,*p.parents)),'ordinary absolute source required');a=p.stat();need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=16*1024**2,'bounded single-link source');raw=p.read_bytes();b=p.stat();key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns);need(key(a)==key(b)and len(raw)==a.st_size,'stable complete source');return raw
def relative(n):
 need(type(n)is str and n and not n.startswith('/')and '\\'not in n and all(p not in('','.','..')for p in n.split('/')),'safe source path');return Path(n)
def files(root):
 need(root.is_absolute()and root.is_dir()and not any(p.is_symlink()for p in(root,*root.parents)),'ordinary source root');out={}
 for base,dirs,names in os.walk(root):
  if Path(base)==root:dirs[:]=[n for n in dirs if n!='.git'];names=[n for n in names if n!='.git']
  need(not any((Path(base)/n).is_symlink()for n in dirs),'source directory alias')
  for name in names:
   p=Path(base)/name;out[p.relative_to(root).as_posix()]=pin(ordinary(p))
 return out

def prepare(base,output,selected=False):
 lock=json.loads(ordinary(HERE/'source.json'));need(lock['carrier_source']==CARRIER and len(lock['base_files'])==203,'genuine finite203 base source');need(files(base)==lock['base_files'],'whole exact published204 source required');view=lock['selected']if selected else lock['default'];need(set(view['files'])==set(lock['base_files']),'same full203 source role set')
 planned={n:ordinary(base/relative(n))for n in lock['base_files']}
 for name,text in view['delta'].items():need(name in planned and type(text)is str,'finite explicit source delta');planned[name]=text.encode()
 need({n:pin(raw)for n,raw in planned.items()}==view['files'],'whole expected diagnostic source emission');need(output.is_absolute()and output.parent.is_dir()and not output.exists()and base not in output.parents and not any(p.is_symlink()for p in(output,*output.parents)),'fresh separate output')
 policy=json.loads(planned['scripts/ci/apps7-full574-repair16k/source-pins.json']);need(policy['actual_source']is policy['actual_ref']is None and all(v is None for v in policy['actual_runs'].values()),'actual defaults NULL')
 output.mkdir(mode=0o700)
 for name,raw in planned.items():
  p=output/relative(name);p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(0o644)
 need(files(output)==view['files'],'post-write complete203 source check')
 return dict(status='EMITTED_EXACT_DIAGNOSTIC_SOURCE_ONLY',carrier=CARRIER,files=203,selected=selected,source=None,ref=None,run_ids={'repair-bytes':None,'repair-missing':None},hardware='NOT_RUN',release='NOT_ADMITTED')
if __name__=='__main__':
 q=argparse.ArgumentParser(description=__doc__);q.add_argument('--base-root',type=Path,required=True);q.add_argument('--output',type=Path,required=True);q.add_argument('--selected',action='store_true');a=q.parse_args();print(json.dumps(prepare(a.base_root.absolute(),a.output.absolute(),a.selected),sort_keys=True))
