# SPDX-License-Identifier: MIT
"""Emit this finite lifecycle source from the exact745 public runtime, without actors."""
import argparse,hashlib,json,os,shutil,stat,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
HERE=Path(__file__).resolve().parent;LANE='scripts/ci/core-native-lifecycle';WF=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core-lifecycle.yml')

def files(root):
 rows={}
 for p in sorted(root.rglob('*')):
  if p.relative_to(root).parts[0]=='.git':continue
  C.need(not p.is_symlink()and(p.is_file()or p.is_dir()),'ordinary whole source namespace')
  if p.is_file():rows[p.relative_to(root).as_posix()]=C.pin(C.read(p,32*1024**2))
 return rows

def emit(runtime,output):
 runtime=Path(runtime).absolute();output=Path(output).absolute();before=files(runtime);C.need(before==C.profile()['runtime']['files']and len(before)==745,'whole genuine public745 input bytes');C.need(not output.exists()and output.parent.is_dir()and not any(p.is_symlink()for p in output.parents)and not output.is_relative_to(runtime)and not runtime.is_relative_to(output),'fresh disjoint output before copying')
 shutil.copytree(runtime,output,ignore=shutil.ignore_patterns('.git','__pycache__'));lane=output/LANE;C.need(not lane.exists(),'new purpose-owned lane');lane.mkdir(parents=True)
 for p in HERE.rglob('*'):
  rel=p.relative_to(HERE)
  if'__pycache__'in rel.parts or rel.as_posix()=='source-manifest.json':continue
  C.need(not p.is_symlink()and(p.is_file()or p.is_dir()),'ordinary maintained factory leaves')
  if p.is_dir():(lane/rel).mkdir(exist_ok=True)
  else:shutil.copy2(p,lane/rel)
 rows={n:r for n,r in files(output).items()if n not in WF};manifest=dict(schema=1,purpose='CORE7_NATIVE_DISPOSABLE_LIFECYCLE',files=rows,actual_source=None,actual_ref=None,actual_run=None,hardware='NOT_RUN');(lane/'source-manifest.json').write_bytes(C.encoded(manifest));workflow=(lane/'workflow.yml.in').read_text().replace('@ENTRY_SHA@',rows[LANE+'/entry.py']['sha256']).replace('@MANIFEST_SHA@',C.pin(C.encoded(manifest))['sha256'])
 for n in WF:(output/n).write_text(workflow)
 current=files(output);held={n:r for n,r in before.items()if n not in WF};C.need(all(current[n]==r for n,r in held.items()),'all744 original source bodies held; only registered alias changes');return dict(status='CLOSED_CORE7_LIFECYCLE_SOURCE_ONLY',files=current,old_runtime745=before,held=len(held),changed_original=['.github/workflows/native-arm-build.yml'],actual=None,native='NOT_RUN',old_target261='UNCHANGED_UNACCEPTED')
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--runtime',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(C.encoded(emit(a.runtime,a.output)).decode(),end='')
