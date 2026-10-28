#!/usr/bin/python3
# SPDX-License-Identifier: MIT
"""Emit a fresh source-only trial or an explicit Root-bound clone; never run actors."""
import argparse,hashlib,importlib.util,json,re,shutil,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import adapter as A
HERE=Path(__file__).resolve().parent
LANE='scripts/ci/apps16-client-native';WF='.github/workflows/native-arm-build.yml'
RECIPES={'runtime':('cachy-asahi-repository-runtime','0.1.0-1'),'apps':('cachy-asahi-apps16','0.1.0-16'),'client':('cachy-asahi-repository-client-v2','0.1.0-1')}

def row(path):return dict(bytes=path.stat().st_size,sha256=hashlib.sha256(path.read_bytes()).hexdigest())
def save(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def emit(source,output,candidate_source=None):
 source=source.absolute();output=output.absolute()
 if output.exists()or not output.parent.is_dir()or output.is_relative_to(source)or any(p.is_symlink()for p in(output,*output.parents)):raise ValueError('fresh disjoint ordinary source destination required')
 if candidate_source is not None and not re.fullmatch('[a-f0-9]{40}',candidate_source):raise ValueError('exact Root source selection required')
 infra=json.loads(A.read(source,'scripts/ci/apps-cache-native/infrastructure-pins.json'))
 originals=json.loads((HERE/'original-pins.json').read_bytes());infra.update(originals)
 for name,pin in infra.items():
  if row(source/name)!=pin:raise ValueError('original infrastructure differs: '+name)
 checks=load('unchanged_native_package_checks',source/'scripts/checks/package_checks.py');products={};names=set(infra)
 for role,(directory,version)in RECIPES.items():
  root=source/'packages/tools'/directory;recipe=checks.recipe(root/'PKGBUILD');meta=recipe['metadata'];name=meta['pkgname'][0]
  if recipe['errors']or meta['pkgver'][0]+'-'+meta['pkgrel'][0]!=version:raise ValueError('explicit candidate recipe/version differs')
  if candidate_source:
   for path in root.iterdir():
    if path.is_file()and subprocess.check_output(['git','-C',str(source),'show',candidate_source+':'+path.relative_to(source).as_posix()])!=path.read_bytes():raise ValueError('Root selected published recipe differs')
  pins={n:row(root/n)for n in recipe['input_sha256']};names|={str((root/n).relative_to(source))for n in pins}
  checker=load('new_payload_'+role,root/'check_source.py')
  if role=='apps':payload={n:[src,mode]for n,(src,mode)in checker.PAYLOAD.items()};markers=['PASS_SOURCE_AND_STAGING_CONTRACT','Ran 54 tests','Ran 32 tests','Ran 8 tests','OK']
  elif role=='runtime':
   original=json.loads(A.read(source,'scripts/ci/apps-cache-native/input-policy.json'));payload=original['products']['runtime']['payload'];markers=['PASS_EXACT_THREE_HELPERS_AND_STAGE']
  else:
   prefix='usr/share/cachy-asahi/repository-runtime/';payload={prefix+'scripts/client/client_v2.py':['client_v2.py',420]}
   for n in('README.md','source-provenance.json','helper-pins.json'):payload['usr/share/doc/'+name+'/'+n]=[n,420]
   for n in('NOTICE','LICENSE'):payload['usr/share/licenses/'+name+'/'+n]=[n,420]
   markers=['PASS_OPT_IN_COMPANION_EXACT_SOURCE_AND_PAYLOAD','Ran 5 tests','OK']
  products[role]=dict(name=name,version=version,recipe_directory='packages/tools/'+directory,source_sha=candidate_source,recipe_sha256=row(root/'PKGBUILD')['sha256'],source_files=pins,payload=payload,check_markers=markers)
 output.mkdir(mode=0o700)
 names|={p.relative_to(source).as_posix()for p in (source/'scripts/ci/setup6-retained-helpers').iterdir()if p.is_file()}
 for name in sorted(names):
  target=output/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/name,target)
 lane=output/LANE;lane.mkdir(parents=True)
 for path in HERE.iterdir():
  if path.is_file()and path.name not in('source-manifest.json','input-policy.json','infrastructure-pins.json'):shutil.copyfile(path,lane/path.name)
 save(lane/'infrastructure-pins.json',infra)
 old=json.loads(A.read(source,'scripts/ci/apps-cache-native/input-policy.json'))
 policy=dict(schema_version=1,status='ROOT_BOUND_FINAL_PRODUCT_SOURCES'if candidate_source else'UNBOUND_APPS16_CLIENT_NATIVE',purpose='APPS16_AND_OPT_IN_CLIENT_V2_NATIVE',candidate_source=candidate_source,base_inventory_sha256=old['base_inventory_sha256'],helper_pins=old['helper_pins'],dependency=None,dependency_source=None,products=products)
 save(lane/'input-policy.json',policy)
 rows={p.relative_to(output).as_posix():row(p)for p in output.rglob('*')if p.is_file()};assert len(rows)<=128
 save(lane/'source-manifest.json',dict(schema_version=1,status='FROZEN_ROOT_FINAL_SOURCES'if candidate_source else'SOURCE_READY_UNBOUND_APPS16_CLIENT_NATIVE',files=rows,native='NOT_RUN',hardware='NOT_RUN',workflow_path=WF,workflow_ref='refs/heads/codex/apps16-pair-native-v1',repository='Gabriel-Kahen/cachy-asahi'))
 text=(HERE/'workflow.yml').read_text().replace('@JOB_SHA256@',row(lane/'job.py')['sha256']).replace('@MANIFEST_SHA256@',row(lane/'source-manifest.json')['sha256']);target=output/WF;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(text);(output/'.github/workflows/native-arm-apps16-client.yml').write_text(text)
 # Do not retain a second workflow inside the runtime source leaf set.
 return dict(status=policy['status'],source_rows=len(rows),workflow=row(target),native='NOT_RUN')

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--candidate-source');a=p.parse_args();print(json.dumps(emit(a.source,a.output,a.candidate_source),sort_keys=True))
