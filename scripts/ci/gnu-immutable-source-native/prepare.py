"""Emit one closed new-purpose deployment; no credentials, Git, API or actors."""
import argparse,json,shutil,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import deploy as D,runtime_adapter
WORKFLOW='.github/workflows/native-arm-gnu-immutable-source.yml'
def emit(runtime,output,boot_decision=None,boot_result=None):
 runtime=runtime.absolute();output=output.absolute();basis=D.obj(D.read(D.HERE/'runtime-basis.json',2*1024**2));D.need(len(basis)==667 and not output.exists()and output.parent.is_dir()and not any(p.is_symlink()for p in output.parents),'fresh closed deployment output')
 for n,row in basis.items():D.need(D.pin(D.read(runtime/n,16*1024**2))==row,'exact frozen runtime667 input')
 output.mkdir(mode=0o700);target=output/D.LANE;shutil.copytree(D.HERE,target,ignore=shutil.ignore_patterns('__pycache__'));shutil.copytree(runtime,output/'runtime');proof=runtime_adapter.apply(output/'runtime');(target/'runtime-derivation.json').write_bytes(D.encoded(proof))
 D.need((boot_decision is None)==(boot_result is None),'supply both exact Root boot DATA operands or neither')
 if boot_decision is not None:
  import boot_binding,kernel_input
  raw=D.read(boot_decision);result=D.read(boot_result);k,_=kernel_input.known();projection=D.encoded(boot_binding.projection(raw,result,k))
  (target/'Root-boot-decision.json').write_bytes(raw);(target/'Root-boot-strict.json').write_bytes(result);(target/'boot-projection.json').write_bytes(projection)
  policy=D.obj(D.read(target/'input-policy.json'));policy.update(boot_decision=D.pin(raw),boot_projection=D.pin(projection));(target/'input-policy.json').write_bytes(D.encoded(policy))
 # The archived source template is never overwritten by a selected private binding.
 rows={p.relative_to(output).as_posix():D.pin(p.read_bytes())for p in output.rglob('*')if p.is_file()};m=dict(schema_version=1,purpose='GNU_IMMUTABLE_RUNTIME_NATIVE_V1',files=rows,actual_source=None,actual_ref=None,actual_run=None);(target/'source-manifest.json').write_bytes(D.encoded(m));workflow=D.read(target/'workflow.yml.in').decode().replace('@ENTRY_SHA@',rows[D.LANE+'/entry.py']['sha256']).replace('@MANIFEST_SHA@',D.pin(D.read(target/'source-manifest.json',2*1024**2))['sha256']).encode();(output/'.github/workflows').mkdir(parents=True)
 for n in(WORKFLOW,'.github/workflows/native-arm-build.yml'):(output/n).write_bytes(workflow)
 return dict(status='CLOSED_DEPLOYMENT_SOURCE_ONLY_NO_ACTORS',files=len(rows)+3,runtime=proof,actual_source=None,actual_ref=None,actual_run=None)
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--runtime',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--boot-decision',type=Path);p.add_argument('--boot-result',type=Path);a=p.parse_args();print(D.encoded(emit(a.runtime,a.output,a.boot_decision,a.boot_result)).decode(),end='')
