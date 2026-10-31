#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""One source-bound native job; original updater/VM entry runs as owned child."""
import argparse,os,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
import wiring as W

def parent(root,source,case,argv):
 C.need(source and case in C.CASES,'explicit implementation/case');W.authorize(root,source,source,case)
 # All original input/native/fresh/decision and actual kernel checks are repeated
 # by the original unchanged entry; no prior verification grants installation.
 runtime=W.load(root,'scripts/ci/glibc-owned-runtime/runner.py')
 p=argparse.ArgumentParser(add_help=False);p.add_argument('--output',type=Path,required=True);a,_=p.parse_known_args(argv)
 C.need(a.output.parent==Path('/tmp') and not a.output.exists(),'fresh direct/tmp original owner path')
 home=a.output.with_name(a.output.name+'-job-home');C.need(not home.exists(),'fresh job HOME');home.mkdir(mode=0o700)
 C.save(home/'child.json',dict(status='LAUNCH_ATTEMPTED_TERMINAL_UNKNOWN',source=source,case=case))
 row=out=err=error=None
 try:
  row,out,err,error=runtime.run_command(['/usr/bin/python3','-I','-B',str(root/C.LANE/'run.py'),*argv],home,dict(PATH='/usr/local/bin:/usr/bin:/bin',HOME=str(home),LANG='C.UTF-8',TZ='UTC',PYTHONDONTWRITEBYTECODE='1'),15600,4*1024**2)
  C.save(home/'child.json',dict(status='WAIT_RETURNED',source=source,case=case,child=row,error=None if error is None else dict(type=type(error).__name__,message=str(error)[:2048])))
  C.need(a.output.is_dir() and not a.output.is_symlink(),'original owner did not create its output')
  own=C.decode(C.read(a.output/'owner.json'));C.need(own['purpose']=='expanded604-apps6-updater' and own['case']==case and own['output']==str(a.output),'original child-owned output identity')
  (a.output/'wiring-child.stdout').write_bytes(out);(a.output/'wiring-child.stderr').write_bytes(err)
  C.save(a.output/'wiring-owner.json',dict(status='PASS' if error is None and row['exit_code']==0 and row['group_absence_verified'] is True else 'FAIL',case=case,source=source,child=row,source_manifest=C.row(root/C.LANE/'wiring-source-manifest.json'),workflow=C.row(root/W.WF),error=None if error is None else dict(type=type(error).__name__,message=str(error)[:2048]),scope='GENERIC16K_VM_NOT_NATIVE_HOST_OR_HARDWARE'))
  # Preserve the original seven-file transport's tail slot without rewriting
  # any original caller/result. This is a bounded tail of original guest output.
  parts=[]
  for name in ('updater16k-caller.stdout','updater16k-caller.stderr'):
   p=a.output/'public'/name
   if p.exists():
    C.read(p,2*1024**2)
    with p.open('rb') as stream:stream.seek(max(0,p.stat().st_size-65536));parts.append(stream.read(65536))
  if parts:
   with (a.output/'public/transaction-tail.log').open('xb') as stream:stream.write(b''.join(parts)[-65536:])
  if error is not None:raise error
  C.need(row['exit_code']==0 and row['group_absence_verified'] is True,'original update owner exit/group absence');return 0
 finally:
  # Only the empty job HOME is ours. Backing roots/actors remain with the original
  # owner; no recursive cleanup here can hide an uncertain original outcome.
  if not any(home.iterdir()):home.rmdir()

def main(argv=None):
 args=list(sys.argv[1:] if argv is None else argv)
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('preflight','decisions','inputs','run'));p.add_argument('--implementation',type=Path,required=True);p.add_argument('--case',choices=C.CASES,required=True);p.add_argument('--source');p.add_argument('--workflow-sha');p.add_argument('--implementation-revision');p.add_argument('--updater-decisions',type=Path)
 a,_=p.parse_known_args(args)
 source=a.source if a.mode!='run' else a.implementation_revision;workflow=a.workflow_sha if a.mode!='run' else source
 old,held,binding=W.authorize(a.implementation,source,workflow,a.case)
 if a.mode=='run':return parent(a.implementation,source,a.case,args[1:])
 forward=args[1:]
 if '--updater-decisions' in forward:
  i=forward.index('--updater-decisions');forward=forward[:i]+forward[i+2:]
 if a.mode=='preflight':forward+=['--preflight']
 else:
  C.need(a.updater_decisions is not None,'new original updater decisions required');C.accepted(old,a.updater_decisions,binding)
  if a.mode=='decisions':forward+=['--decisions-only']
 result=W.old_gate(a.implementation,old).main(forward)
 if a.mode=='preflight':W.output('updater_decisions',binding['decision_carrier_source'])
 return result
if __name__=='__main__':raise SystemExit(main())
