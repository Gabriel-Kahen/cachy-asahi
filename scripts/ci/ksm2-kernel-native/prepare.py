#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit the exact frozen build-only18 source; never build, boot or bind actuals."""
import argparse,hashlib,json,os,stat
from pathlib import Path
HERE=Path(__file__).resolve().parent
LANE='scripts/ci/ksm2-kernel-native'
WORKFLOW='.github/workflows/native-arm-ksm2-kernel.yml'
ALIAS='.github/workflows/native-arm-build.yml'
OWN=('fixtures/baseline.config','fixtures/configuration-proof.json','fixtures/ksm.config','input-policy.json','ksm_profile.py','lane.py','runtime.py','source-manifest.json','test_lane.py')
HELD=('scripts/ci/managed-gui-generic16k/build_kernel.py','scripts/ci/managed-gui-generic16k/kernel.fragment','scripts/ci/managed-gui-generic16k/kernel_contract.py','scripts/ci/managed-gui-generic16k/run.py','scripts/ci/tools-generic16k/acquire_kernel.py','scripts/virtual/generic16k/fetch_inputs.py','scripts/virtual/generic16k/inputs.json')
EXPECTED={LANE+'/'+n for n in OWN}|set(HELD)|{WORKFLOW,ALIAS}
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def decode(raw):
 def pairs(rows):
  value={}
  for key,item in rows:need(key not in value,'duplicate JSON key');value[key]=item
  return value
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def read(path):
 need(path.is_absolute()and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary absolute source without aliases')
 a=path.lstat();need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size<=1024**2,'bounded singlelink source file')
 raw=path.read_bytes();b=path.lstat();keys=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 need(keys(a)==keys(b)and len(raw)==a.st_size,'source identity changed');return raw
def prepare(source,output):
 source=Path(source);output=Path(output)
 need(source.is_absolute()and source.is_dir()and not any(p.is_symlink()for p in(source,*source.parents)),'ordinary absolute source root')
 need(output.is_absolute()and not output.exists()and not output.is_symlink()and output.parent.is_dir()and not any(p.is_symlink()for p in output.parents)and not output.is_relative_to(source),'fresh output outside source')
 authorization=output.with_name(output.name+'-authorization.json')
 need(not authorization.exists()and not authorization.is_symlink(),'fresh outside-closure authorization')
 spec=decode(read(HERE/'source-pins.json'))
 need(set(spec)=={'schema_version','purpose','reference_source','files'}and type(spec['schema_version'])is int and spec['schema_version']==1 and spec['purpose']=='EXACT_KSM2_KERNEL_BUILD_ONLY_SOURCE_FACTORY'and spec['reference_source']=='7b382cd8087407cebb33327180c8a76e7be5a79c'and set(spec['files'])==EXPECTED,'exact frozen18 source declaration')
 need(spec['files'][WORKFLOW]==spec['files'][ALIAS],'registered alias must equal dedicated workflow')
 data={}
 for name in sorted(EXPECTED-{ALIAS}):
  raw=read(source/name);need(pin(raw)==spec['files'][name],'source pin differs: '+name);data[name]=raw
 data[ALIAS]=data[WORKFLOW]
 policy=decode(data[LANE+'/input-policy.json'])
 need(all(policy[k]is None for k in('actual_source','actual_ref','actual_run','native_package_decision')),'default actual authority must remain NULL')
 # All source inputs are validated and captured before any output is created.
 output.mkdir(mode=0o700)
 for name,raw in data.items():
  path=output/name;path.parent.mkdir(parents=True,exist_ok=True)
  with path.open('xb')as stream:stream.write(raw)
 actual={p.relative_to(output).as_posix():pin(read(p))for p in output.rglob('*')if p.is_file()}
 need(actual==spec['files'],'emitted closed18 differs')
 receipt=dict(status='EXACT_SOURCE_ONLY_NOT_BUILD_OR_BOOT',source=None,ref=None,run_id=None,native_package_decision=None,reference_source=spec['reference_source'],files=actual,build='NOT_RUN',boot='NOT_RUN',hardware='NOT_RUN',release='NOT_ADMITTED')
 with authorization.open('xb')as stream:stream.write(encoded(receipt))
 return dict(status=receipt['status'],source_files=len(actual),source=None,ref=None,run_id=None,authorization=str(authorization))
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();print(json.dumps(prepare(a.source,a.output),sort_keys=True))
