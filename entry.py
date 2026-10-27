#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Separate source-closed capacity probe; no normal updater acceptance."""
import hashlib,importlib.util,json,os,stat,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
PURPOSE='generic16k-fullcopy-capacity'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def read(path):
 need(not any(p.is_symlink()for p in(path,*path.parents)),'ordinary source parents');fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  first=os.fstat(fd);need(stat.S_ISREG(first.st_mode)and first.st_nlink==1 and 0<=first.st_size<=16*1024**2,'bounded single-link source');raw=bytearray()
  while chunk:=os.read(fd,1024**2):raw.extend(chunk);need(len(raw)<=first.st_size,'source grew')
  identity=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_nlink,v.st_uid,v.st_gid,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
  need(len(raw)==first.st_size and identity(first)==identity(os.fstat(fd))==identity(path.lstat()),'stable source descriptor/path');return bytes(raw)
 finally:os.close(fd)
def close(root,expected):
 actual={}
 for p in root.rglob('*'):
  if p.relative_to(root).parts[0]=='.git':continue
  need(not p.is_symlink() and(p.is_file()or p.is_dir()),'ordinary whole capacity source')
  if p.is_file():actual[p.relative_to(root).as_posix()]=pin(read(p))
 need(len(actual)<=4096 and actual==expected,'exact whole capacity source closure')
def verify():
 manifest=json.loads(read(ROOT/'source-manifest.json'));expected=manifest['files'];close(ROOT,dict(expected,**{'source-manifest.json':pin(read(ROOT/'source-manifest.json'))}))
 profile=json.loads(read(ROOT/'profile.json'));need(profile['purpose']==PURPOSE and profile['normal_updater_acceptance']is False and all(profile[k]is None for k in('actual_source','actual_ref','actual_run','Root_acceptance')) and profile['actuals']=={'capacity':None} and profile['implementation']=='fixed-statx-input-candidate' and profile['package_count']==607 and profile['page_size']==16384,'unexecuted diagnostic-only capacity profile')
 need(profile.get('actuals')=={'capacity':None},'all default capacity actual selectors NULL')
 binding=json.loads(read(ROOT/'binding.json'));need(all(binding[k]is None for k in('source','ref','run','attempt','case')),'unbound default capacity context')
 close(ROOT/'production',profile['production_files'])
 need(len(profile['production_files'])==709,'complete independent production709 dependency')
 return profile
def main(argv=None):
 args=list(sys.argv[1:]if argv is None else argv);verify()
 if args==['--source-preflight']:print(json.dumps(dict(status='SOURCE_ONLY_CAPACITY_NOT_EXECUTED',actual=None)));return 0
 need(args.count('--probe-mode')==1,'explicit capacity probe mode required');i=args.index('--probe-mode');need(i+1<len(args)and args[i+1]==PURPOSE,'exact diagnostic probe mode');del args[i:i+2]
 path=ROOT/'capacity/entry.py';sys.path.insert(0,str(path.parent));spec=importlib.util.spec_from_file_location('_capacity_private_entry',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module.main(args)
if __name__=='__main__':raise SystemExit(main())
