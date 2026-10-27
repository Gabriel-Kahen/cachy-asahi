# SPDX-License-Identifier: MIT
"""Fixed historical TEST-signature SOURCE reproduction; never live authority."""
import ast,copy,hashlib,json,subprocess,sys,types
from pathlib import Path
from unittest.mock import Mock

SCOPE='HISTORICAL_SIGNATURE_SOURCE_ONLY_NOT_ACTOR_AUTHORITY'
EPOCH=1792457344
EXPIRES=1793062144
SIGNER='E0000BEFC3B3EB622B6F4B6B55995A5352ECB50D'
CARRIER='7cf7fb81d0b70b1b7421dc85788fabd45ec5adfc'
INDEX={'bytes':69418,'sha256':'e705cc670d11cd188c971a36953dd76941a6f4c706eb9b64ddd131dd55a4898e'}
RENEWAL_SHA='7950cc367e36252f0141be0c82d0de5d5affe346939df29d4b5f2b76e3f586b7'
CANDIDATES_SHA='ebaa95bd680350142c3a9c6806ef7eee1d095b35d0d2a847067d6853a27a3627'
HELD_PREPARE_SHA='560c119d10a1fc508ba5d16e1ee76e4513b1396d9c8f1998a5747a66f1eb32e5'
DERIVE_SHA='17b59a53b188ecef78b09f0224366ecb978f3c4673c7d26a8579db4d393318eb'
ROLE=Path('scripts/ci/welcome5-native-gui')
MARKER='historical-source-only.json'

def need(ok,message):
 if not ok:raise ValueError(message)

def canonical(value):
 raw=str(value);path=Path(value)
 need(path.is_absolute()and raw==str(path)and path==path.resolve()and not any(p.is_symlink()for p in(path,*path.parents)),'canonical historical SOURCE operand required')
 return path

def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()

def function_copy(fn,space):
 result=types.FunctionType(fn.__code__,space,fn.__name__,fn.__defaults__,fn.__closure__)
 result.__kwdefaults__=fn.__kwdefaults__;return result

def module_copy(module):
 result=types.ModuleType('_historical_SOURCE_ONLY_'+module.__name__);space=vars(result);space.update(vars(module))
 for name,value in tuple(space.items()):
  if isinstance(value,types.FunctionType)and value.__globals__ is vars(module):space[name]=function_copy(value,space)
 return result

def source_function(module,name,transform):
 raw=canonical(module.__file__).read_text();nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef)and n.name==name]
 need(len(nodes)==1 and not nodes[0].decorator_list,'one exact finite historical SOURCE function')
 node=copy.deepcopy(nodes[0]);transform(node);tree=ast.fix_missing_locations(ast.Module(body=[node],type_ignores=[]));space=dict(vars(module))
 exec(compile(tree,str(module.__file__)+'::<SOURCE_ONLY '+name+'>','exec'),space)
 return space[name]

def reference(renewal,root):
 path=canonical(renewal.__file__);root=canonical(root)
 need(tuple(path.parts[-4:])==(*ROLE.parts,'renewal.py')and hashlib.sha256(path.read_bytes()).hexdigest()==RENEWAL_SHA,'exact original renewal SOURCE function required')
 need(renewal.INDEX==INDEX and renewal.SIGNER==SIGNER and renewal.CARRIER==CARRIER,'fixed original public renewal identity required')
 need(renewal.pin(root/'index.json')==renewal.INDEX,'exact recorded renewal index required')
 index=renewal.read(root/'index.json');proof=renewal.read(root/'provenance.json')
 need((index['created'],index['expires'],index['signer'])==(EPOCH,EXPIRES,SIGNER)and(proof['created'],proof['expires'],proof['signer'])==(EPOCH,EXPIRES,SIGNER),'fixed genuine recorded signature reference required')
 need(set(proof['verification'])==set(renewal.KINDS),'all four genuine recorded verification receipts required')
 for row in proof['verification'].values():
  lines=[line.split()for line in row['status'].splitlines()if line.startswith('[GNUPG:] VALIDSIG ')]
  need(row['gpg_exit']==0 and len(lines)==1 and len(lines[0])in(11,12)and lines[0][2]==SIGNER and lines[0][4]==str(EPOCH),'exact genuine recorded VALIDSIG epoch required')
 return index

def historical_overlay(renewal,root):
 """Validate exact archived provenance at its recorded epoch, without a clock."""
 index=reference(renewal,root)
 def historical_clock(node):
  target=ast.parse("value['created']<=time.time()<value['expires']",mode='eval').body
  matches=[n for n in ast.walk(node)if isinstance(n,ast.Compare)and ast.dump(n,include_attributes=False)==ast.dump(target,include_attributes=False)]
  clocks=[n for n in ast.walk(node)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and isinstance(n.func.value,ast.Name)and n.func.value.id=='time'and n.func.attr=='time']
  need(len(matches)==len(clocks)==1,'one exact original current-validity comparator')
  matches[0].comparators[0]=ast.Constant(EPOCH)
 fn=source_function(renewal,'overlay',historical_clock);value=fn(canonical(root))
 need(value==index,'whole recorded overlay DATA unchanged by historical validity comparison')
 return dict(value,source_scope=SCOPE,reference_epoch=EPOCH,actor_ready=False)

def historical_renewal(renewal,bound_assets):
 result=module_copy(renewal);space=vars(result)
 space['overlay']=lambda root:historical_overlay(renewal,root)
 def source_receipt(node):
  found=[n for n in ast.walk(node)if isinstance(n,ast.Constant)and n.value=='CURRENT_TEST_SIGNATURES_ONLY_NATIVE_CREDIT_UNCHANGED']
  need(len(found)==1,'one exact renewal receipt DATA status');found[0].value=SCOPE
 copied=source_function(renewal,'apply',source_receipt);copied=function_copy(copied,space)
 def apply(source,assets,output,lock):
  need(canonical(assets)==bound_assets,'fixed historical SOURCE assets only')
  value=copied(source,assets,output,lock);receipt=renewal.read(Path(output)/'test-signature-renewal.json')
  need(receipt['status']==SCOPE and(receipt['created'],receipt['expires'])==(EPOCH,EXPIRES),'historical SOURCE receipt only')
  receipt.update(source_scope=SCOPE,reference_epoch=EPOCH,actor_ready=False,actual=None)
  (Path(output)/'test-signature-renewal.json').write_bytes(encoded(receipt));return value
 space['apply']=apply;return result

def actor_free_caller():
 # The inherited source case already prohibits every subprocess.run/Popen call.
 # Assert that provenance rather than installing a process-global clock/patch.
 for operation in(subprocess.run,subprocess.Popen):
  need(isinstance(operation,Mock)and type(operation.side_effect)is AssertionError and operation._mock_wraps is None,'historical SOURCE prepare requires inherited NO_ACTORS controls')

def historical_factory(base_factory,root,assets):
 """Return only source preparation and unbound sealing, preserving service1800."""
 root=canonical(root);assets=canonical(assets);factory_path=canonical(base_factory.__file__)
 kinds={root.parents[1]/'implementation/factory/factory.py':('1a39c8356380b7fdeed853f623faa59c901ee4ebee3ceeacad79355fa7dcc5db','UNBOUND_LATEST607_GUI_CODE_ONLY_RUNTIME_REFUSES',607,605),root.parent/'factory/factory.py':('2e6f7af631bad24113a90eded38c7a6847f18a86a78c82d9a82fd24ce4e23fd7','UNBOUND_CURRENT606_GUI_CODE_ONLY_RUNTIME_REFUSES',606,604)}
 need(factory_path in kinds and canonical(base_factory.HERE)==factory_path.parent,'exact fixed606/607 factory/root SOURCE relationship')
 factory_sha,unbound,packages,absent=kinds[factory_path];need(hashlib.sha256(factory_path.read_bytes()).hexdigest()==factory_sha,'exact original606/607 factory SOURCE bytes')
 home=root/ROLE;held_path=home/'prepare.py';candidates_path=home/'candidates.py';renewal_path=home/'renewal.py';derive_path=home/'derive.py'
 need(hashlib.sha256(held_path.read_bytes()).hexdigest()==HELD_PREPARE_SHA and hashlib.sha256(candidates_path.read_bytes()).hexdigest()==CANDIDATES_SHA and hashlib.sha256(derive_path.read_bytes()).hexdigest()==DERIVE_SHA,'exact held prepare/candidates/derive SOURCE bytes')
 base_load=base_factory.load;space=dict(vars(base_factory))
 def load(name,path):
  path=canonical(path)
  if path!=held_path:return base_load(name,path)
  held=module_copy(base_load('_historical_fresh_held_prepare',held_path))
  # Load fresh by exact path, never inherit a stale sys.modules['candidates'].
  candidates=module_copy(base_load('_historical_fresh_candidates',candidates_path));candidate_space=vars(candidates);original_load=candidates.load
  renewal=base_load('_historical_fresh_renewal',renewal_path);source_renewal=historical_renewal(renewal,assets)
  def candidate_load(module_name,module_path):
   if canonical(module_path)==renewal_path:return source_renewal
   return original_load(module_name,module_path)
  candidate_space['load']=candidate_load;vars(held)['A']=candidates;vars(held)['D']=base_load('_historical_fresh_derive',derive_path);return held
 space['load']=load;space['prepare_code']=function_copy(base_factory.prepare_code,space)
 selected=function_copy(base_factory.service1800,space)();prepared={}
 marker=dict(status=SCOPE,source_scope=SCOPE,reference_epoch=EPOCH,created=EPOCH,expires=EXPIRES,carrier=CARRIER,index_pin=INDEX,actor_ready=False,actual=None)
 def prepare_code(source,supplied_assets,out,profile,mode):
  actor_free_caller();need(canonical(source)==root and canonical(supplied_assets)==assets,'fixed historical SOURCE/root asset operands')
  out=canonical(out);need(not out.exists()and out.parent.is_dir()and all(not out.is_relative_to(p)and not p.is_relative_to(out)for p in(root,assets)),'fresh disjoint historical SOURCE output')
  saved=dict(sys.modules);paths=sys.path[:]
  try:result=selected.prepare_code(source,supplied_assets,out,profile,mode)
  finally:
   sys.path[:]=paths
   for name in set(sys.modules)-set(saved):sys.modules.pop(name,None)
   sys.modules.update(saved)
  (out/MARKER).write_bytes(encoded(marker));prepared[out]=(profile,mode);return result
 def seal(out,profile,mode,basis,changes,ready):
  out=canonical(out);need(ready is False,'historical SOURCE can never seal actor-ready output')
  need(prepared.get(out)==(profile,mode)and(out/MARKER).read_bytes()==encoded(marker),'only this SOURCE facade prepared output may be sealed')
  result=selected.seal(out,profile,mode,basis,changes,False)
  need(result['status']==unbound and(result['packages'],result['optional_absent'])==(packages,absent)and result['actual_run']is None,'unchanged typed606/607 unbound runtime refusal required')
  result.update(source_scope=SCOPE,reference_epoch=EPOCH,actor_ready=False)
  (out/'current606-proof.json').write_bytes(encoded(result));return result
 def emit(*args,**kwargs):raise ValueError('historical SOURCE facade refuses every actor emission')
 facade=types.ModuleType('_historical_SOURCE_ONLY_factory');facade_space=dict(vars(selected));facade_space.update(prepare_code=prepare_code,seal=seal,source_scope=SCOPE,actor_ready=False)
 facade_space['emit']=function_copy(emit,facade_space);vars(facade).update(facade_space)
 return facade

def historical_selected_factory(base_factory,root,assets):
 """Apply the exact selected3460 observer to a source-only607 facade."""
 root=canonical(root);home=root.parents[1]/'implementation'
 need(canonical(base_factory.__file__)==home/'factory/factory.py','selected3460 SOURCE requires the fixed607 factory')
 path=canonical(home/'observer_apply.py')
 need(hashlib.sha256(path.read_bytes()).hexdigest()=='5a42b1e7cd081528b3a8871e1500645f44d53c7100180c1b72dc7212a9ed1018','exact original selected607 observer SOURCE')
 observer=base_factory.load('_historical_selected607_observer',path)
 return observer.factory(historical_factory(base_factory,root,assets))

def source_runner_contract(runner_context,runner):
 """Run exact607 code/policy predicates against explicitly unbound SOURCE data."""
 rpath=canonical(runner_context.__file__);home=rpath.parent;runner=canonical(runner)
 need(rpath.name=='runner_context.py'and home.name=='implementation'and canonical(runner_context.HERE)==home and hashlib.sha256(rpath.read_bytes()).hexdigest()=='d693706a608adce7904ac16e611d59cd861e71457520404fada6cea518acb901','exact original selected607 runner-context SOURCE')
 context_path=canonical(home/'factory/context606.py')
 need(hashlib.sha256(context_path.read_bytes()).hexdigest()=='94b9265e1680e38fbc93c63b6f83cec1d67bed2759cb791d0b55a254b2d13301','exact original selected607 context SOURCE')
 original_load=runner_context.load;context=original_load('_historical_contract_exact_context',context_path)
 need(canonical(context.__file__)==context_path and canonical(context.HERE)==context_path.parent,'exact context SOURCE path binding')
 private_context=module_copy(context)
 marker=dict(status=SCOPE,source_scope=SCOPE,reference_epoch=EPOCH,created=EPOCH,expires=EXPIRES,carrier=CARRIER,index_pin=INDEX,actor_ready=False,actual=None)
 def authorize_source(path):
  path=canonical(path);need(path==runner,'fixed historical SOURCE runner only')
  paths=list(path.rglob('*'));need(not any(p.is_symlink()for p in paths)and all(p.is_dir()or p.is_file()for p in paths),'historical SOURCE runner aliases/special nodes refused')
  proof=context.obj(path/'current606-proof.json')
  need(proof['status']=='UNBOUND_LATEST607_GUI_CODE_ONLY_RUNTIME_REFUSES'and(proof['packages'],proof['optional_absent'])==(607,605)and proof['actual_run']is None,'historical SOURCE proof must stay unbound607')
  need(proof.get('source_scope')==SCOPE and proof.get('reference_epoch')==EPOCH and proof.get('actor_ready')is False and context.read(path/MARKER)==encoded(marker),'explicit historical SOURCE marker and proof required')
  actual={p.relative_to(path).as_posix():context.pin(context.read(p))for p in paths if p.is_file()and p!=path/'current606-proof.json'}
  need(actual==proof['files'],'whole historical SOURCE file closure drift')
  directories={p.relative_to(path).as_posix()for p in paths if p.is_dir()};wanted=set()
  for name in actual:
   member=Path(name);need(not member.is_absolute()and member.as_posix()==name and not{'.','..'}&set(member.parts),'ordinary contained SOURCE member')
   wanted.update(p.as_posix()for p in member.parents if p!=Path('.'))
  need(directories==wanted,'whole historical SOURCE directory closure drift')
  # Only a private in-memory schema projection removes these three SOURCE
  # annotations. Neither status nor the on-disk proof is promoted to readiness.
  result=dict(proof)
  for name in('source_scope','reference_epoch','actor_ready'):result.pop(name)
  return result
 vars(private_context)['authorize_runner']=authorize_source
 def source_load(name,path):
  if canonical(path)==context_path:return private_context
  return original_load(name,path)
 space=dict(vars(runner_context));space['load']=source_load
 result=function_copy(runner_context.authorize_runner,space)(runner)
 need(result['status']=='UNBOUND_LATEST607_GUI_CODE_ONLY_RUNTIME_REFUSES','SOURCE contract cannot grant readiness')
 return dict(result,source_scope=SCOPE,reference_epoch=EPOCH,actor_ready=False)


LEGACY_TEST_SHA='eaed7917e62319ba721461cfbf02a116c901f31e8f4068c937e44a257f2a8d2f'

def historical_legacy_prepare(root,assets):
 """Private held-lane test adapter; default candidates.stage remains live."""
 import importlib.util
 root=canonical(root);assets=canonical(assets);home=root/ROLE
 expected={'prepare.py':HELD_PREPARE_SHA,'candidates.py':CANDIDATES_SHA,'derive.py':DERIVE_SHA,'renewal.py':RENEWAL_SHA}
 for name,sha in expected.items():need(hashlib.sha256(canonical(home/name).read_bytes()).hexdigest()==sha,'exact historical legacy SOURCE module '+name)
 def load(name,path):
  spec=importlib.util.spec_from_file_location(name,canonical(path));module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module
 held=module_copy(load('_historical_legacy_held_prepare',home/'prepare.py'))
 candidates=module_copy(load('_historical_legacy_fresh_candidates',home/'candidates.py'));original_load=candidates.load
 renewal=load('_historical_legacy_fresh_renewal',home/'renewal.py');source_renewal=historical_renewal(renewal,assets)
 def candidate_load(name,path):
  if canonical(path)==home/'renewal.py':return source_renewal
  return original_load(name,path)
 vars(candidates)['load']=candidate_load;vars(held)['A']=candidates;vars(held)['D']=load('_historical_legacy_fresh_derive',home/'derive.py')
 marker=dict(status=SCOPE,source_scope=SCOPE,reference_epoch=EPOCH,created=EPOCH,expires=EXPIRES,carrier=CARRIER,index_pin=INDEX,actor_ready=False,actual=None)
 def prepare(source,supplied_assets,out,selected):
  actor_free_caller();need(canonical(source)==root and canonical(supplied_assets)==assets,'fixed historical legacy SOURCE operands')
  out=canonical(out);need(not out.exists()and out.parent.is_dir()and all(not out.is_relative_to(p)and not p.is_relative_to(out)for p in(root,assets)),'fresh disjoint historical legacy SOURCE output')
  saved=dict(sys.modules);paths=sys.path[:]
  try:value=held.prepare(source,supplied_assets,out,selected)
  finally:
   sys.path[:]=paths
   for name in set(sys.modules)-set(saved):sys.modules.pop(name,None)
   sys.modules.update(saved)
  (out/MARKER).write_bytes(encoded(marker));proof=json.loads((out/'runner-proof.json').read_bytes())
  need(proof['status']=='DERIVED_SOURCE_ONLY_GUI_NOT_RUN'and proof['actuals']=={'minimal':None,'overlay':None},'unchanged unbound held SOURCE proof required')
  raw=(out/MARKER).read_bytes();proof['files'][MARKER]=dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
  proof.update(status=SCOPE,source_scope=SCOPE,reference_epoch=EPOCH,actor_ready=False)
  (out/'runner-proof.json').write_bytes(encoded(proof));return value
 facade=types.ModuleType('_historical_legacy_SOURCE_ONLY_prepare');vars(facade).update(prepare=prepare,source_scope=SCOPE,actor_ready=False,__file__=str(home/'prepare.py'))
 return facade

def legacy_source_tests(source,assets):
 """Fixed standalone worker for the exact inherited held source test file."""
 import os,runpy
 source=canonical(source);assets=canonical(assets)
 need(canonical(__file__)==source/'implementation/historical_source.py','worker must belong to its explicit693 SOURCE tree')
 root=source/'parent574/original';home=root/ROLE;target=canonical(home/'test_lane.py')
 need(hashlib.sha256(target.read_bytes()).hexdigest()==LEGACY_TEST_SHA,'only the exact pinned inherited source test path is allowed')
 manifest=json.loads((source/'source-manifest.json').read_bytes());helper=canonical(__file__).read_bytes()
 need(len(manifest['files'])==692 and manifest['files']['implementation/historical_source.py']==dict(bytes=len(helper),sha256=hashlib.sha256(helper).hexdigest()),'explicit whole693 SOURCE helper binding required')
 # This irreversible hook belongs only to this one-purpose CLI worker. Library
 # historical_overlay/factory calls install no process-global hooks or patches.
 denied={'subprocess.Popen','os.system','os.fork','os.forkpty','os.posix_spawn','os.exec','pty.spawn'}
 def no_actors(event,args):
  if event in denied or event.startswith('socket.'):
   raise RuntimeError('historical SOURCE worker prohibits process/network actors: '+event)
 sys.addaudithook(no_actors)
 os.environ['WELCOME5_GUI_SOURCE']=str(root);os.environ['WELCOME5_GUI_ASSETS']=str(assets);os.environ.pop('WELCOME5_GUI_DEVELOPMENT',None)
 sys.path.insert(0,str(home))
 need('prepare'not in sys.modules and 'candidates'not in sys.modules,'fresh standalone inherited SOURCE worker required')
 sys.modules['prepare']=historical_legacy_prepare(root,assets)
 sys.argv=[str(target)]
 runpy.run_path(str(target),run_name='__main__')

def main():
 import argparse
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('operation',choices=('legacy-source-tests',))
 parser.add_argument('--source',required=True);parser.add_argument('--assets',required=True)
 args=parser.parse_args();legacy_source_tests(args.source,args.assets)

if __name__=='__main__':main()
