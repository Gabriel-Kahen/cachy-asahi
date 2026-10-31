#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit one finite hosted source from the whole frozen608 source role."""
import argparse,json,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import hosted as O

def assemble(runtime,output,binding=None):
 role=O.decode(O.read(O.HERE/'runtime-role.json',2*1024**2));actual={p.relative_to(runtime).as_posix():O.pin(O.read(p))for p in runtime.rglob('*')if p.is_file()};O.need(role['purpose']=='WHOLE_FROZEN608_KSM_VM_SOURCE_ONLY_NOT_ACTUAL_AUTHORITY'and len(actual)==608 and actual==role['files'],'exact whole608 source role, not historical native/VM acceptance')
 policy=O.defaults();O.need(all(policy[k]is None for k in('native_carrier','kernel_carrier','native_decision','native_inputs','kernel_authority','kernel_transport','kernel_build','kernel_run','actual_source','actual_ref','actual_run')),'emitter template remains NULL')
 if binding is not None:policy=O.selected(O.decode(O.read(binding)))
 O.need(output.is_absolute()and not output.exists()and not output.is_symlink()and output.parent.is_dir(),'fresh emitted source only');output.mkdir(mode=0o700);shutil.copytree(runtime,output/'runtime')
 lane=output/O.LANE;lane.mkdir(parents=True)
 for p in O.HERE.iterdir():
  if p.is_file()and p.name!='source-manifest.json':O.read(p);shutil.copyfile(p,lane/p.name)
 (lane/'input-policy.json').write_bytes(O.encoded(policy));rows={p.relative_to(output).as_posix():O.pin(O.read(p))for p in output.rglob('*')if p.is_file()};(lane/'source-manifest.json').write_bytes(O.encoded(dict(schema_version=1,purpose='KSM2_GENERIC16K_HOSTED_TEST_ONLY',files=rows)))
 wf=output/'.github/workflows';wf.mkdir(parents=True);raw=O.workflow(output)
 for name in('native-arm-ksm2-generic16k.yml','native-arm-build.yml'):(wf/name).write_bytes(raw)
 files=O.files(output);return dict(status='EMITTED_SOURCE_NOT_ACTUAL_AUTHORITY',files=len(files),whole_runtime_files=len(actual),actual_source=None,actual_run=None,bounds=O.BOUNDS)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--runtime',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--binding',type=Path);a=p.parse_args();print(json.dumps(assemble(a.runtime,a.output,a.binding),sort_keys=True))
