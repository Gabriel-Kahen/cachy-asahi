#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Flat offline caa3 recipe inputs; no configure/compiler/native execution."""
import argparse,json,shutil,sys,tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import materialize as M
import authority as G
HERE=Path(__file__).resolve().parent
# makepkg reserves .asc for detached signatures; retain original auth names too.
KEY_COPIES={'archive-key-12.asc':'archive-key-12.key','archive-key-13.asc':'archive-key-13.key'}
def recipe_inputs(files):
 for original,copy in KEY_COPIES.items():
  if original in files or copy in files:
   M.need(original in files and copy in files and files[original]==files[copy],'exact public key data copy required: '+copy)
 return {n:row for n,row in files.items() if n not in KEY_COPIES}
STAGE_SHA='43b1b441dcc384379ab80c4864bbf7ffd898d56e4ba629c0faa966c25a979e6c'
def render(files):
 files=recipe_inputs(files);names=list(files);M.need(all(Path(n).name==n and n not in ('.','..') and all(c.isalnum() or c in '_.-' for c in n) for n in names),'flat safe recipe source names required')
 rows="source=("+' '.join("'"+n+"'" for n in names)+")\nsha256sums=("+' '.join("'"+files[n]['sha256']+"'" for n in names)+")"
 text=(HERE/'PKGBUILD.in').read_text();M.need(text.count('@SOURCE_ARRAYS@')==1,'exact recipe input anchor required');return text.replace('@SOURCE_ARRAYS@',rows).encode()
def materialize(inputs,patch_tar,output,policy=HERE/'authority.json',auth_helper=None,inspector_helper=None,stage=None):
 M.need(not sys.flags.optimize,'ordinary unoptimized Python required');authority=G.check(policy,inputs,auth_helper)
 inputs=Path(inputs).absolute();output=Path(output).absolute();M.need(not output.exists() and not any(p.is_symlink() for p in (output,*output.parents)),'fresh ordinary bundle output required')
 a=M.helper('maintained_bundle_auth',M.helper_path('auth.py',auth_helper),M.AUTH_SHA)
 inspector=M.helper_path('original_inspector.py',inspector_helper);stage=Path(stage) if stage else HERE.parents[2]/'packages/core/cachy-asahi-glibc-debian-provider/stage.py'
 M.need(a.pin(a.read(stage))['sha256']==STAGE_SHA,'unchanged exact provider stage required')
 with tempfile.TemporaryDirectory(prefix='maintained-source-preparation-',dir=output.parent) as tmp:
  prep=Path(tmp)/'prepared';result=M.materialize(inputs,patch_tar,prep,auth_helper,inspector_helper);M.need(result['failed_patch'] is None and result['completed']==85 and result['after_tree']==G.EXPECTED['prepared_tree'],'complete authenticated source preparation required')
  output.mkdir(mode=0o700)
  try:
   names=list(a.PUBLIC_PINS)+[json.loads(Path(policy).read_bytes())['decision']['path']]
   for name in names:shutil.copyfile(inputs/name,output/name)
   copies={'glibc_2.43-7.debian.tar.xz':patch_tar,'auth.py':M.helper_path('auth.py',auth_helper),'original_inspector.py':inspector,'stage.py':stage,'authority.json':policy}
   for name in ('materialize.py','authority.py','source-lock.json','0002-held-builder-test-expectations.patch','source-provenance.json','NOTICE','LICENSE'):copies[name]=HERE/name
   M.need(not set(names)&set(copies),'noncolliding bounded bundle inputs required')
   for name,path in copies.items():a.read(path);shutil.copyfile(path,output/name)
   for original,copy in KEY_COPIES.items():shutil.copyfile(output/original,output/copy)
   files={p.name:a.pin(a.read(p)) for p in sorted(output.iterdir())};M.need(len(files)<=32,'finite bundle input count');(output/'PKGBUILD').write_bytes(render(files))
   evidence=dict(source_preparation=result,source_authority=authority,chain=json.loads((prep/'source-chain.json').read_bytes()),patch_authentication=json.loads((prep/'patch-authentication.json').read_bytes()),proof_files={n:a.pin(a.read(prep/n,8*1024**2)) for n in ('before-tree.json','after-tree.json','series-plan.json','patch-commands.json','metadata-manifest.json')})
   (output/'source-authentication.json').write_bytes(M.encoded(evidence));closed={p.name:a.pin(a.read(p,8*1024**2 if p.name=='source-authentication.json' else 96*1024**2)) for p in sorted(output.iterdir())};value=dict(schema_version=1,status='SOURCE_BUNDLE_READY_UNSELECTED_MAINTAINED_DEBIAN_PROVIDER',package_version='2.43.caa3-1',files=closed,prepared_tree=result['after_tree'],native='NOT_RUN',security='NO_CREDIT',release='NOT_ADMITTED');(output/'bundle.json').write_bytes(M.encoded(value));return value
  except BaseException:shutil.rmtree(output);raise
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for name in ('inputs','patch-tar','output'):p.add_argument('--'+name,type=Path,required=True)
 p.add_argument('--authority',type=Path,default=HERE/'authority.json')
 for name in ('auth-helper','inspector-helper','stage'):p.add_argument('--'+name,type=Path)
 args=p.parse_args()
 try:print(json.dumps(materialize(args.inputs,args.patch_tar,args.output,args.authority,args.auth_helper,args.inspector_helper,args.stage),sort_keys=True))
 except (ValueError,OSError,KeyError) as error:print(json.dumps(dict(status='REFUSED_BEFORE_MAINTAINED_BUILD_BUNDLE',reason=str(error)[:300],native='NOT_RUN')));raise SystemExit(1)
