#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Require full retained1153 DATA; use original574 producer with no fetch fallback."""
import argparse,importlib.util,json,os,platform,shutil,stat,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C

def identity(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def fetch_existing(original,item):
 C.need(os.path.lexists(item['target']),'missing retained input; downloads forbidden')
 def deny(*a,**kw):raise ValueError('network acquisition forbidden')
 return original(item,opener=deny)

def inventory(source,context,*,hashes=True):
 M=C.load('orphans3_original574_plan',source/'scripts/ci/maintained_desktop574.py');inputs=C.read(source/'scripts/ci/maintained-desktop574-inputs.json');items=M.plan(inputs,context);problems=[]
 for item in items:
  p=item['target'];reason=None
  try:
   C.safe(p);s=p.lstat()
   if not stat.S_ISREG(s.st_mode) or s.st_nlink!=1 or s.st_size!=item['size']:reason='TYPE_LINK_OR_SIZE'
   elif hashes and C.digest(p)!=item['sha256']:reason='SHA256'
  except (OSError,ValueError):reason='MISSING_OR_UNSAFE'
  if reason:problems.append(dict(path=str(p.relative_to(context)),bytes=item['size'],sha256=item['sha256'],reason=reason))
 return M,items,problems

def execute(source,retained,output,token,packages=None,bootstrap=None):
 source=C.safe(source.absolute());output=C.safe(output.absolute());C.verify_source(source)
 retained=C.safe(retained.absolute()) if retained is not None else None
 C.need(platform.system()=='Linux' and platform.machine()=='aarch64' and os.getuid()==os.geteuid()>0,'ordinary native ARM caller required')
 roles=[source,retained] if retained is not None else [source,C.safe(packages.absolute()),C.safe(bootstrap.absolute())]
 C.need(not output.exists() and output.parent.is_dir() and all(not output.is_relative_to(p) and not p.is_relative_to(output) for p in roles),'fresh disjoint producer output')
 M=C.load('orphans3_original574_build',source/'scripts/ci/maintained_desktop574.py');M.owner_names(token)
 if retained is not None:
  _,items,problems=inventory(source,retained);C.need(not problems,'retained1153 context incomplete: '+json.dumps(problems[:8],sort_keys=True))
 output.mkdir(mode=0o700);(output/'home').mkdir(mode=0o700);until=time.monotonic()+2300
 if retained is None:
  D=C.load('orphans3_retained_join',source/C.LANE/'retained.py');D.stage(source,packages,bootstrap,output/'context')
 else:
  (output/'context/deps').mkdir(parents=True,mode=0o700);(output/'context/keys').mkdir(mode=0o700)
  for item in items:
   C.need(time.monotonic()<until,'original producer budget exhausted');p=item['target'];target=output/'context'/p.relative_to(retained);before=p.stat();shutil.copyfile(p,target);target.chmod(0o600)
   C.need(identity(p.stat())==identity(before) and target.stat().st_size==item['size'] and C.digest(target)==item['sha256'],'retained input changed during copy')
 original=M.fetch
 def no_download(item):return fetch_existing(original,item)
 M.fetch=no_download
 previous=sys.argv;sys.argv=[str(source/'scripts/ci/maintained_desktop574.py'),'build','--inputs',str(source/'scripts/ci/maintained-desktop574-inputs.json'),'--output',str(output),'--job-token',token]
 try:return M.main()
 finally:sys.argv=previous
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--source',type=Path,required=True)
 for n in ('retained-context','packages','bootstrap'):p.add_argument('--'+n,type=Path)
 p.add_argument('--output',type=Path);p.add_argument('--job-token');p.add_argument('--audit-only',action='store_true');a=p.parse_args()
 C.need(a.retained_context is not None and a.packages is None and a.bootstrap is None or a.retained_context is None and a.packages is not None and a.bootstrap is not None,'one explicit complete context or packages/bootstrap pair required')
 if a.audit_only and a.retained_context is not None:
  _,items,problems=inventory(a.source.absolute(),a.retained_context.absolute());print(json.dumps(dict(status='PASS_EXACT_RETAINED1153' if not problems else 'MISSING_RETAINED_INPUTS',files=len(items),problems=problems,actual_source=None,actual_ref=None,actual_run=None),sort_keys=True,indent=2));raise SystemExit(bool(problems))
 C.need(not a.audit_only,'use retained.py to audit package/bootstrap roles')
 C.need(a.output is not None and a.job_token is not None,'output/token required');raise SystemExit(execute(a.source,a.retained_context,a.output,a.job_token,a.packages,a.bootstrap))
