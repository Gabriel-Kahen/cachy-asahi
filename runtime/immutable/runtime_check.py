"""Process-blocked source composition; never an immutable/native acceptance."""
import ast,json,shutil,subprocess,sys,tempfile
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parent))
import inputs,factory,runtime_policy,supervisor,disk_adapter,bootstrap_loader,native_controller,native_prepare,stage,worker
P,C,_,_=inputs.broker()
def check():
 with patch.object(subprocess,'Popen',side_effect=AssertionError('SOURCE_ONLY_NO_ACTORS')):
  pins=inputs.check();proofs={}
  for n in factory.OWN:
   if n.endswith('.py'):compile((inputs.D/n).read_bytes(),n,'exec')
  for name in('policy.json','qualification-pins.json'):
   value=P.decode((inputs.D/name).read_bytes());P.need(all(v is None for k,v in value.items()if k not in('purpose','bounds')),'all future prerequisite/source/run operands NULL')
  try:runtime_policy.gate(P.decode((inputs.D/'policy.json').read_bytes()))
  except ValueError as e:P.need('NULL'in str(e),'default refusal before actors')
  else:raise AssertionError('unbound source activated')
  original=inputs.original('_source_original_owner','scripts/ci/glibc-debian-maintained-installed16k/run.py');derived,proofs['native_owner']=native_controller.derive(Path(original.__file__).read_bytes());compile(derived,'<native-owner>','exec')
  prepared=native_prepare.load(None);P.need('/immutable/entry.py'in prepared['INIT']and 'runtime_stage.execute'in __import__('inspect').getsource(disk_adapter.preparer),'counted original offline stage wiring')
  bootstrap=bootstrap_loader.load(None,None);P.need(bootstrap.WORKER_MASK==P.WORKER_MASK==0x800400fb,'new exact9mask, no old8-purpose claim')
  image=stage.original_images();P.need(callable(image.prepare),'complete offline formatter source composition')
  module=inputs.original('_source_runner','scripts/ci/glibc-owned-runtime/runner.py');_,proofs['supervisor']=supervisor.derive(Path(module.__file__).read_bytes())
  # Construct the actual inherited16K lifecycle, then derive the exact new
  # preflight guard; no lifecycle body or inert success result is executed.
  adapter=inputs.original('_source_adapter','scripts/ci/glibc-debian-maintained-installed16k/adapter.py');api,mods=C.source_api();root=Path(mods['full_root'].__file__).parents[2];
  with tempfile.TemporaryDirectory(dir=inputs.D)as td:
   complete=Path(td)/'complete';shutil.copytree(root,complete);supplement=pins['runtime_supplement'];target=complete/'scripts/ci/glibc-debian-maintained-installed16k/test_progress.py'
   if not target.exists():target.write_bytes((inputs.D.parent/supplement['input']).read_bytes())
   P.need(P.pin(target.read_bytes())==supplement['pin'],'exact manifest test supplement');text,oldproof=adapter.derive(complete)
  compile(worker.lifecycle(text.encode()),'<new-purpose-lifecycle>','exec');proofs['runtime_VM']=dict(whole_historical_role=226,new_complete_view=227,supplement=pins['runtime_supplement'])
  proofs['lifecycle']=dict(original=P.pin(text.encode()),proposed=P.pin(worker.lifecycle(text.encode()).encode()),changed='ONE_NEW_PURPOSE_PROC_PREFLIGHT_RECEIPT_GUARD_ALL_OTHER_BODIES_HELD')
 return dict(status='PASS_PROCESS_BLOCKED_COMPOSED_SOURCE_ONLY',inputs=len(pins['files']),own=len(factory.OWN),proofs=proofs,actual_source=None,actual_ref=None,actual_run=None,kernel_build='NULL',kernel_boot='NULL',mapping='UNRUN',lifecycle='UNRUN',fit='NOT_ESTABLISHED')
if __name__=='__main__':print(json.dumps(check(),sort_keys=True,indent=2))
