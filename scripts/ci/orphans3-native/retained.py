#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Join existing exact574 archives and341 bootstrap DATA; no Git/network/actors."""
import argparse,json,os,shutil,stat,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
import producer as P

def audit(source,packages,bootstrap):
 source,packages,bootstrap=map(C.safe,(source,packages,bootstrap));M=C.load('orphans3_retained_plan',source/'scripts/ci/maintained_desktop574.py');lock=C.read(source/'scripts/ci/maintained-desktop574-inputs.json');items=M.plan(lock,Path('/context'));problems=[];rows=[]
 package_names={x['filename'] for x in items if x['target'].parent.name=='deps'}
 C.need({p.name for p in packages.iterdir()}==package_names,'exact original1148 package/signature DATA set required')
 for item in items:
  relative=item['target'].relative_to('/context');origin=packages/item['filename'] if relative.parts[0]=='deps' else bootstrap/item['filename'];reason=None
  try:
   C.safe(origin);s=origin.lstat();C.need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_size==item['size'] and C.digest(origin)==item['sha256'],'exact stable original DATA required')
  except (ValueError,OSError):reason='MISSING_UNSAFE_OR_MISMATCHED'
  row=dict(path=str(relative),origin=str(origin),bytes=item['size'],sha256=item['sha256']);rows.append(row)
  if reason:problems.append(dict(row,reason=reason))
 return dict(status='PASS_EXACT_RETAINED1153_DATA' if not problems else 'RETAINED_INPUTS_REFUSED',files=rows,problems=problems,actual_source=None,actual_ref=None,actual_run=None,native='NOT_RUN')

def stage(source,packages,bootstrap,output):
 source,packages,bootstrap,output=map(C.safe,(source,packages,bootstrap,output));C.verify_source(source)
 C.need(not output.exists() and output.parent.is_dir() and output.parent.stat().st_uid==os.getuid() and not output.parent.stat().st_mode&0o022 and all(not output.is_relative_to(p) and not p.is_relative_to(output) for p in (source,packages,bootstrap)),'fresh disjoint caller-owned retained context')
 value=audit(source,packages,bootstrap);C.need(not value['problems'],'all1153 retained inputs required before context creation');until=time.monotonic()+180
 C.need(shutil.disk_usage(output.parent).free>=sum(r['bytes'] for r in value['files'])+8*1024**2,'retained DATA staging capacity insufficient')
 output.mkdir(mode=0o700);(output/'deps').mkdir(mode=0o700);(output/'keys').mkdir(mode=0o700)
 for row in value['files']:
  C.need(time.monotonic()<until,'retained DATA staging deadline');p=Path(row['origin']);before=P.identity(p.stat());target=output/row['path'];shutil.copyfile(p,target);target.chmod(0o600)
  C.need(P.identity(p.stat())==before and target.stat().st_size==row['bytes'] and C.digest(target)==row['sha256'],'retained DATA changed during copy')
 _,items,problems=P.inventory(source,output);C.need(not problems and len(items)==1153,'complete emitted retained context required');return dict(status='PASS_STAGED1153_DATA_ONLY',files=1153,actual_source=None,actual_ref=None,actual_run=None,native='NOT_RUN',context=str(output))
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for n in ('source','packages','bootstrap'):p.add_argument('--'+n,type=Path,required=True)
 p.add_argument('--output',type=Path);a=p.parse_args()
 C.verify_source(a.source.absolute());v=stage(a.source.absolute(),a.packages.absolute(),a.bootstrap.absolute(),a.output.absolute()) if a.output is not None else audit(a.source.absolute(),a.packages.absolute(),a.bootstrap.absolute());print(json.dumps(v,sort_keys=True,indent=2));raise SystemExit(bool(v.get('problems')))
