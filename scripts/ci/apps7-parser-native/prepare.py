#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Closed code-only emission; explicit Root selection is separate from NULL template."""
import argparse,hashlib,json,shutil
from pathlib import Path
HERE=Path(__file__).resolve().parent;LANE='scripts/ci/apps7-parser-native'
def need(ok,why):
 if not ok:raise ValueError(why)
def row(path):
 raw=path.read_bytes();return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def save(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def emit(workspace,output,selection=None):
 need(not output.exists()and not any(p.is_symlink()for p in(output,*output.parents)),'fresh ordinary source output')
 policy=json.loads((HERE/'default-input-policy.json').read_bytes());need(policy['status']=='UNBOUND_SOURCE_TEMPLATE'and all(r['authority_source']is None for r in policy['sources'].values()),'held NULL template')
 if selection is not None:
  need(set(selection)=={'status','baseline','candidate'}and selection['status']=='ROOT_SELECTED_PUBLIC_PARSER_CODE','explicit finite Root source selection')
  for role in('baseline','candidate'):need(selection[role]==policy['sources'][role]['expected_public_source'],'exact public code authority');policy['sources'][role]['authority_source']=selection[role]
  policy['status']='ROOT_BOUND_PUBLIC_PARSER_SOURCES'
 need(all(policy[k]is None for k in('actual_source','actual_ref','actual_run')),'no actual identities')
 pins=json.loads((HERE/'infrastructure-pins.json').read_bytes());target=output/LANE
 for name,pin in pins.items():
  source=workspace/name;need(not any(p.is_symlink()for p in(source,*source.parents))and row(source)==pin,'whole original infrastructure pin');dest=output/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,dest)
 target.mkdir(parents=True)
 for source in HERE.iterdir():
  if source.is_file()and source.name not in('input-policy.json','source-manifest.json'):shutil.copyfile(source,target/source.name)
 save(target/'input-policy.json',policy)
 files={p.relative_to(output).as_posix():row(p)for p in sorted(output.rglob('*'))if p.is_file()};need(len(files)<=128,'source manifest bound');save(target/'source-manifest.json',dict(schema_version=1,scope='READONLY_NATIVE_ARM_ACTUAL574_PARSER_MICROBENCHMARK',native='NOT_RUN',files=files))
 text=(target/'workflow.yml.in').read_text()
 for marker,path in(('@JOB_SHA256@',target/'job.py'),('@MANIFEST_SHA256@',target/'source-manifest.json')):need(text.count(marker)==1,'one exact workflow stamp');text=text.replace(marker,row(path)['sha256'])
 workflow=output/'.github/workflows/native-arm-apps7-parser.yml';workflow.parent.mkdir(parents=True);workflow.write_text(text);shutil.copyfile(workflow,workflow.with_name('native-arm-build.yml'))
 return dict(schema_version=1,status='SOURCE_ONLY_NOT_RUN',files={p.relative_to(output).as_posix():row(p)for p in sorted(output.rglob('*'))if p.is_file()},actual_source=None,actual_ref=None,actual_run=None)
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--workspace',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--selection',type=Path);p.add_argument('--authorization',type=Path,required=True);a=p.parse_args();save(a.authorization,emit(a.workspace.absolute(),a.output.absolute(),None if a.selection is None else json.loads(a.selection.read_bytes())))
