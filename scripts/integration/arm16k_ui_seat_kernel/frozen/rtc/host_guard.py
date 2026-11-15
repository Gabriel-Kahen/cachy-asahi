#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Finite pre/post guard for Root's explicit readonly host-/usr cross domain."""
import argparse,datetime,importlib.util,json
from pathlib import Path
HERE=Path(__file__).resolve().parent


def load(name):
 spec=importlib.util.spec_from_file_location('rtc_host_'+name,HERE/(name+'.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def capture():
 C=load('contract');C.data();candidate=json.loads((HERE/'data/new-llvm22-cross-candidate.json').read_text());bc=json.loads((HERE/'data/bc-input.json').read_text())
 for row in candidate['tools'].values():C.checked(Path(row['path']),row)
 for path,row in candidate['runtime_files'].items():C.checked(Path(path),row)
 C.checked(Path(candidate['ld_cache']['path']),candidate['ld_cache'])
 for name,row in candidate['packages'].items():
  directory=Path('/var/lib/pacman/local')/row['local_directory']
  for filename,ref in row['metadata_files'].items():C.checked(directory/filename,ref)
 C.checked(Path(bc['binary']['path']),bc['binary'])
 return {'schema_version':1,'status':'HOST_USR_BOUND_INPUTS_VERIFIED','observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source_inventory':C.pin(HERE/'data/new-llvm22-cross-candidate.json'),'packages':candidate['packages'],'tool_files_verified':len(candidate['tools'])+1,'runtime_files_verified':len(candidate['runtime_files']),'ld_cache':candidate['ld_cache'],'bc_binary':{k:bc['binary'][k] for k in ('bytes','sha256')},'kernel_source_execution':'NOT RUN','resource_authority':None}


def candidate_profile(snapshot,pin):
 C=load('contract');T=load('toolchain');source=json.loads((HERE/'data/new-llvm22-cross-candidate.json').read_text());bc=json.loads((HERE/'data/bc-input.json').read_text());tools={**source['tools'],'bc':{'path':'/tools/bin/bc',**{k:bc['binary'][k] for k in ('bytes','sha256')}}}
 profile={'schema_version':1,'operation':C.lock()['operation'],'status':'HOST_USR_INPUTS_VERIFIED_REVIEW_PENDING','mode':'HOST_CROSS_ARM64','runtime_domain':'HOST_USR_READONLY_BIND_V1','host_architecture':'x86_64','target_architecture':'arm64','same_toolchain':False,'image_id':source['image_id'],'tools':tools,'runtime_files':source['runtime_files'],'packages':source['packages'],'host_inventory':snapshot['source_inventory'],'host_provenance':pin,'ld_cache':source['ld_cache'],'runtime_closure_reviewed':None,'compiler_facts':None,'configured_result_sha256':None,'resource_authority':None}
 profile['environment_sha256']=T.environment(profile);return profile


def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--profile-template',type=Path);a=p.parse_args();C=load('contract');snapshot=capture()
 with a.output.open('x') as f:json.dump(snapshot,f,indent=2,sort_keys=True);f.write('\n')
 if a.profile_template:
  with a.profile_template.open('x') as f:json.dump(candidate_profile(snapshot,C.pin(a.output)),f,indent=2,sort_keys=True);f.write('\n')
 print(json.dumps({'status':snapshot['status'],'snapshot':C.pin(a.output),'resource_authority':None,'kernel_source_execution':'NOT RUN'}))


if __name__=='__main__':main()
