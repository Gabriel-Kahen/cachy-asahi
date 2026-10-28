#!/usr/bin/env python3
"""Explicit private EMULATED16K lifecycle; production stays unchanged."""
import hashlib,importlib.util,json,os,stat,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
PURPOSE='normal-emulated16k-lifecycle-v1'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def read(p):
 p=Path(p);need(not any(q.is_symlink()for q in(p,*p.parents)),'ordinary source');s=p.stat();need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_size<=16*1024**2,'bounded source');b=p.read_bytes();t=p.stat();key=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns);need(len(b)==s.st_size and key(s)==key(t),'stable whole source');return b
def rows(root):
 result={}
 for p in root.rglob('*'):
  if root==ROOT and p.relative_to(root).parts[0]=='.git':continue
  need(not p.is_symlink()and(p.is_file()or p.is_dir()),'ordinary source closure')
  if p.is_file():result[p.relative_to(root).as_posix()]=pin(read(p))
 return result
def verify():
 need(not sys.flags.optimize,'assertion-enabled lifecycle context');v=json.loads(read(ROOT/'profile.json'));m=json.loads(read(ROOT/'source-manifest.json'))
 need(rows(ROOT)==dict(m['files'],**{'source-manifest.json':pin(read(ROOT/'source-manifest.json'))}),'whole lifecycle source')
 need(v['purpose']==PURPOSE and v['normal_updater_acceptance']is False and v['hardware']=='NOT_RUN'and all(v[k]is None for k in('source','ref','run','Root_acceptance')),'NULL lifecycle defaults')
 need(len(v['production_files'])==709 and rows(ROOT/'production')==v['production_files']and rows(ROOT/'lifecycle')==v['lifecycle_files'],'complete production/private source');return v
def private():
 sys.path.insert(0,str(ROOT/'lifecycle'));p=ROOT/'lifecycle/entry.py';s=importlib.util.spec_from_file_location('_normal_emulated16k_entry',p);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m);return m
def main(argv=None):
 args=list(sys.argv[1:]if argv is None else argv);verify()
 if args==['--source-preflight']:print(json.dumps(dict(status='SOURCE_ONLY_NORMAL_LIFECYCLE_NOT_EXECUTED',actual=None)));return 0
 need(args.count('--lifecycle-mode')==1,'explicit private lifecycle context');i=args.index('--lifecycle-mode');need(i+1<len(args)and args[i+1]==PURPOSE,'fixed lifecycle context');del args[i:i+2];return private().main(args)
if __name__=='__main__':raise SystemExit(main())
