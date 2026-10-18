"""Counted deployment of frozen new-purpose mechanism onto actual current lane."""
import ast,hashlib,json
from pathlib import Path
import deploy as D
RULES=(('glibc-gnu-provider-installed16k','glibc-debian-maintained-installed16k'),('/installed16k','/debian-maintained-installed16k'),('init-installed16k','init-debian-maintained-installed16k'),('caa_gnu_installed16k=1','caa_debian_maintained_installed16k=1'),('CAA_INSTALLED16K_PREPARE','CAA_DEBIAN_MAINTAINED_INSTALLED16K_PREPARE'))
FILES=('native_controller.py','native_prepare.py','disk_adapter.py','stage.py','worker.py','owner.py','runtime_check.py','test_controls.py','bootstrap_loader.py')
def derive(raw,name):
 text=raw.decode();edits=[]
 for before,after in RULES:
  count=text.count(before)
  if count:text=text.replace(before,after);edits.append(dict(old=before,new=after,count=count))
 if name=='disk_adapter.py':
  before="init=/init-debian-maintained-installed16k caa_debian_maintained_installed16k=1'";after="init=/init-debian-maintained-installed16k caa_debian_maintained_installed16k=1 arm64.nomops'";D.need(text.count(before)==1,'one exact CURRENT nomops cmdline');text=text.replace(before,after);edits.append(dict(old=before,new=after,count=1))
 if name=='bootstrap_loader.py':
  before=" data=integration.derive(data)"
  after=before+"\n old=b\"need(value['producer_retirement']=={'status':'ROOT_VERIFIED_SOURCE_PRODUCERS_RETIRED','source':SOURCE},'source writer retirement authority required')\";new=b\"writer_retired(value['producer_retirement'])\";P.need(data.count(old)==1,'one exact new-purpose writer guard');data=data.replace(old,new)"
  D.need(text.count(before)==1,'one private bootstrap derivation');text=text.replace(before,after);edits.append(dict(old=before,new=after,count=1))
  before="vars(module).update(SOURCE_BROKER=proxy,SOURCE_CLIENT=client,dm=dm,R=R)"
  after="vars(module).update(SOURCE_BROKER=proxy,SOURCE_CLIENT=client,dm=dm,R=R,writer_retired=writer_retired)"
  D.need(text.count(before)==1,'one writer witness global');text=text.replace(before,after);edits.append(dict(old=before,new=after,count=1))
  before="def load(leases,native):"
  after="""def writer_retired(value):
 import re
 policy=P.decode((inputs.D/'policy.json').read_bytes())
 P.need(type(value)is dict and set(value)=={'status','source','token','owner_report','inner_report','prior_Root_decision'}and value['status']=='SOURCE_ENFORCED_CURRENT_NATIVE_WRITERS_RETIRED'and value['source']==policy['actual_source']and re.fullmatch('[a-f0-9]{40}',value['source']or'')and re.fullmatch('[a-f0-9]{32}',value['token'])and value['prior_Root_decision']=='INPUT_AUTHORITY_ONLY_NOT_CURRENT_NATIVE_ACCEPTANCE','fresh source-owned writer retirement witness, never Root acceptance')
 for n in('owner_report','inner_report'):
  r=value[n];P.need(type(r)is dict and set(r)=={'bytes','sha256'}and type(r['bytes'])is int and 0<r['bytes']<=4*1024**2 and re.fullmatch('[a-f0-9]{64}',r['sha256']),'whole retired native report identity')
 return value

"""+before
  D.need(text.count(before)==1,'one finite writer predicate');text=text.replace(before,after);edits.append(dict(old=before,new=after,count=1))
 if name=='stage.py':
  # Held fence reads its historical sandbox pathname. Preserve BOTH exact
  # namespaces rather than modifying filter source or pretending old CAA2 runs.
  before=" policy=boot/'immutable/policy.json';policy.write_bytes(P.encode(value))"
  after=" compat=boot/'installed16k';P.need(not compat.exists(),'fresh fixed source-only fence namespace');compat.mkdir(mode=0o755);sandbox=Path('/debian-maintained-installed16k/sandbox.py');held=P.decode((inputs.D.parent/'gnu-verity-bootstrap-development-20261018/runtime-pins.json').read_bytes())['/installed16k/sandbox.py'];P.need(P.pin(sandbox.read_bytes())==held,'identical whole old/current sandbox filter source');(compat/'sandbox.py').write_bytes(sandbox.read_bytes())\n"+before
  D.need(text.count(before)==1,'one declared readonly sandbox compatibility leaf');text=text.replace(before,after);edits.append(dict(old=before,new=after,count=1))
 restored=text
 for e in reversed(edits):D.need(restored.count(e['new'])==e['count'],'inverse counted new-purpose namespace seam');restored=restored.replace(e['new'],e['old'])
 D.need(restored.encode()==raw,'whole frozen667 function/code inverse');compile(text,name,'exec');return text.encode(),edits
INPUT_APPEND='''
def current_module(name,path):
 # Source-owned import isolation only: every executable byte remains pinned.
 import types
 def plain(n,p):
  s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);sys.modules[n]=m;s.loader.exec_module(m);return m
 contract=plain('_immutable_current_contract',path.parent/'contract.py')
 if path.name=='contract.py':return contract
 raw=path.read_bytes();space=dict(__name__=name,__file__=str(path),C=contract);anchor=b'import contract as C\\n';need(raw.count(anchor)==1,'one exact CURRENT contract import');raw=raw.replace(anchor,b'')
 if b'import adapter\\n'in raw:
  a=current_module('_immutable_current_adapter',path.parent/'adapter.py');raw=raw.replace(b'import adapter\\n',b'');space['adapter']=a
 for module,alias in(('snapshot_progress','S'),('observer_progress','O')):
  anchor=('import '+module+' as '+alias+'\\n').encode()
  if anchor in raw:raw=raw.replace(anchor,b'');space[alias]=plain('_immutable_current_'+module,path.parent/(module+'.py'))
 m=types.ModuleType(name);vars(m).update(space);sys.modules[name]=m;exec(compile(raw,str(path),'exec'),vars(m));return m
'''
def input_derivative(raw):
 text=raw.decode();anchor=" spec=importlib.util.spec_from_file_location(name,path);";D.need(text.count(anchor)==1,'one original owned helper import entry');replacement=" if '/glibc-debian-maintained-installed16k/'in relative:return current_module(name,path)\n"+anchor;text=text.replace(anchor,replacement)+INPUT_APPEND;D.need(text.removesuffix(INPUT_APPEND).replace(replacement,anchor).encode()==raw,'whole input loader inverse');compile(text,'inputs.py','exec');return text.encode()
def apply(runtime):
 basis=D.obj(D.read(D.HERE/'runtime-basis.json',2*1024**2));before={n:D.pin(D.read(runtime/n,16*1024**2))for n in basis};D.need(before==basis,'whole frozen runtime667 before derivative');changes={}
 for name in FILES:
  p=runtime/'immutable'/name;old=p.read_bytes();new,edits=derive(old,name)
  if new!=old:p.write_bytes(new);changes['immutable/'+name]=dict(before=D.pin(old),after=D.pin(new),inverse=edits)
 p=runtime/'immutable/inputs.py';old=p.read_bytes();new=input_derivative(old);p.write_bytes(new);changes['immutable/inputs.py']=dict(before=D.pin(old),after=D.pin(new),inverse='ONE_CONTRACT_IMPORT_ENTRY_PLUS_SOURCE_OWNED_CURRENT_MODULE_IMPORT_ISOLATOR')
 # All413 original operands, including historical native157/VM226, stay held.
 manifest=D.obj((runtime/'runtime-source.json').read_bytes())
 for n,row in changes.items():manifest['files'][n]=row['after']
 (runtime/'runtime-source.json').write_bytes(D.encoded(manifest));changes['runtime-source.json']=dict(before=basis['runtime-source.json'],after=D.pin((runtime/'runtime-source.json').read_bytes()),inverse='EXACT_DERIVED_OWN_ROWS_ONLY')
 after={n:D.pin((runtime/n).read_bytes())for n in basis};D.need({n for n in basis if before[n]!=after[n]}==set(changes),'only declared source derivatives')
 return dict(basis_files=667,changed=changes,held=len(basis)-len(changes),current_pair='a8e9f3e1d8ffe049fdc834f62e74c14ff622b98898c2f849e1580ab8aa0fdbd9',legacy_pair='NOT_SELECTED',scope='CURRENT_CAA3_FULL_LIFECYCLE_WITH_NEW_PID1_SOURCE_PURPOSE_NOT_NATIVE_ACCEPTANCE')
