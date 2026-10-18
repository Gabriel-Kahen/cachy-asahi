#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Close exactly two recipes and the pinned original owner; no Git mutations or actors."""
import argparse,hashlib,json,re,shutil,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
LANE='scripts/ci/dns-sysctl-native'
NAMES=('cachy-asahi-dns','cachy-asahi-sysctl')

def need(ok,message):
 if not ok:raise ValueError(message)

def row(path):
 raw=path.read_bytes();return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())

def write(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')

def prepare(source,output,recipes,package_source=None):
 need(not output.exists()and output.is_absolute()and source.is_absolute()and not any(p.is_symlink()for p in(output,*output.parents,source,*source.parents)),'fresh ordinary source/output required')
 need(package_source is None or re.fullmatch('[0-9a-f]{40}',package_source),'exact package source SHA required')
 pins=json.loads((HERE/'original-pins.json').read_bytes())
 for name,expected in pins.items():
  path=source/name;need(path.is_file()and not any(p.is_symlink()for p in(path,*path.parents))and row(path)==expected,'original complete owner drift: '+name)
 products={}
 for name,recipe in zip(NAMES,recipes):
  files={p.name:row(p)for p in sorted(recipe.iterdir())if p.is_file()}
  need(set(files)=={p.name for p in recipe.iterdir()}and len(files)==(9 if name==NAMES[0]else 8)and all(not p.is_symlink()for p in recipe.iterdir()),'closed flat product source required')
  if package_source:
   for relative,expected in files.items():
    raw=subprocess.check_output(['git','-C',str(source),'show',package_source+':packages/tools/'+name+'/'+relative],timeout=20)
    need(dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())==expected,'published package source Git join differs')
  payload={'usr/bin/'+name:[name,0o755]}
  for filename in('README.md','source-provenance.json'):payload['usr/share/doc/'+name+'/'+filename]=[filename,0o644]
  for filename in('NOTICE','LICENSE'):payload['usr/share/licenses/'+name+'/'+filename]=[filename,0o644]
  products[name]=dict(version='0.1.0-1',source_files=files,payload=payload,check_markers=['Ran '+('21'if name==NAMES[0]else'19')+' tests','\nOK'])
 output.mkdir(mode=0o700)
 for name in pins:
  target=output/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source/name,target)
 for name,recipe in zip(NAMES,recipes):shutil.copytree(recipe,output/'packages/tools'/name)
 target=output/LANE;target.mkdir(parents=True)
 for path in sorted(HERE.iterdir()):
  if path.is_file()and path.name not in('input-policy.json','source-manifest.json','infrastructure-pins.json'):shutil.copyfile(path,target/path.name)
 policy=dict(schema_version=1,status='ROOT_BOUND_FINAL_PRODUCT_SOURCES'if package_source else'UNBOUND_SOURCE_TEMPLATE',candidate_source=package_source,actual_source=None,actual_ref=None,actual_run=None,base_inventory_sha256='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac',products=products)
 write(target/'input-policy.json',policy);write(target/'infrastructure-pins.json',pins)
 workflow=output/'.github/workflows/native-arm-dns-sysctl-candidates.yml';workflow.parent.mkdir(parents=True)
 # Template is a separately owned source file, never edits the historical workflow.
 workflow.write_bytes((HERE/'workflow.yml.in').read_bytes())
 files={p.relative_to(output).as_posix():row(p)for p in sorted(output.rglob('*'))if p.is_file()and p!=workflow}
 manifest=dict(schema_version=1,scope='TWO_DNS_SYSCTL_NATIVE_CANDIDATES_ONLY',native_runtime='NOT_RUN',files=files)
 need(len(files)<=128,'original bounded manifest count exceeded');write(target/'source-manifest.json',manifest)
 text=workflow.read_text()
 for marker,path in(('@JOB_SHA256@',target/'job.py'),('@MANIFEST_SHA256@',target/'source-manifest.json')):
  need(text.count(marker)==1,'workflow freeze marker differs');text=text.replace(marker,row(path)['sha256'])
 workflow.write_text(text)
 alias=workflow.with_name('native-arm-build.yml');shutil.copyfile(workflow,alias)
 authorization={'files':{p.relative_to(output).as_posix():row(p)for p in sorted(output.rglob('*'))if p.is_file()}}
 write(output.parent/(output.name+'-authorization.json'),authorization)
 return dict(status='SOURCE_ONLY_CLOSED_NO_ACTUAL_AUTHORITY',source_files=len(authorization['files']),manifest_files=len(files),products=2,package_source=package_source,actual_source=None,actual_ref=None,actual_run=None)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--dns-recipe',type=Path);p.add_argument('--sysctl-recipe',type=Path);p.add_argument('--package-source');a=p.parse_args()
 print(json.dumps(prepare(a.source.absolute(),a.output.absolute(),[a.dns_recipe or a.source/'packages/tools'/NAMES[0],a.sysctl_recipe or a.source/'packages/tools'/NAMES[1]],a.package_source),sort_keys=True))
