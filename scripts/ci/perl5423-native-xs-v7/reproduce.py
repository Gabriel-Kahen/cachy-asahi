# SPDX-License-Identifier: MIT
"""Replay trusted runner validation on retained DATA; never import artifact code."""
import ast,hashlib,importlib.util,json,os,stat,tarfile
from pathlib import Path
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;REPO=HERE.parents[2]
CONSUMER=REPO/'scripts/port/perl5423-xs-consumer'
TAR_PIN=dict(bytes=35328,sha256='fe5c145db338c7e61832008f42c1c29ac86f3cdcb330ee699df6de97592d90b8')
RUNTIME_PIN=dict(bytes=12381,sha256='bddd4d6ac49929d96f102a0a424a4efe9a8a673645f7c070fd50918265d69320')
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def need(ok,why):
 if not ok:raise ValueError(why)
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def bounded(path,cap):
 path=Path(path);need(path.is_absolute()and path==path.resolve(),'ordinary absolute retained DATA')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 with os.fdopen(fd,'rb')as f:
  before=os.fstat(f.fileno());need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=cap,'bounded regular retained DATA')
  raw=f.read(cap+1);after=os.fstat(f.fileno())
 key=lambda v:(v.st_dev,v.st_ino,v.st_mode,v.st_nlink,v.st_size,v.st_mtime_ns,v.st_ctime_ns)
 need(len(raw)==before.st_size and key(before)==key(after)==key(path.lstat()),'stable retained DATA bytes');return raw
def actual(root):
 root=Path(root);manifest=json.loads(bounded(root/'ZIP-materialization.json',2*1024**2));expected=next(r for r in manifest['entries']if r['path']=='xs/output.tar');path=root/'Decoded-ZIP/xs/output.tar';raw=bounded(path,65536);need(pin(raw)==TAR_PIN=={k:expected[k]for k in('bytes','sha256')},'whole genuine faithful TAR pin')
 wanted={'output/runtime-observation.json','output/actor-result.json'};found={};regular=0
 with tarfile.open(path,'r:')as t:
  for m in t:
   if m.isdir():need(m.name.rstrip('/')=='output'and m.size==0,'single ordinary output directory');continue
   regular+=1
   need(m.isfile()and m.name.startswith('output/')and '..'not in Path(m.name).parts and m.size<=16384,'bounded seven regular outputs only')
   if m.name in wanted:found[m.name]=t.extractfile(m).read()
 need(regular==7 and set(found)==wanted and pin(found['output/runtime-observation.json'])==RUNTIME_PIN,'whitelisted actual runtime observation')
 runtime=json.loads(found['output/runtime-observation.json']);result=json.loads(found['output/actor-result.json']);need(result['failure']=='ValueError: canonical shell-safe absolute path'and result['nested_invocation']=='NOT_INVOKED','actual failed guard before nested invocation')
 plan=bounded(root/'Decoded-ZIP/bundle/xs-plan.json',32768);admission=bounded(root/'Decoded-ZIP/bundle/xs-admission.json',32768);need(pin(plan)['sha256']==runtime['sandbox']['plan_sha256'],'actual plan/sandbox join')
 return runtime,plan,admission
class BoundaryReached(Exception):pass
def replay(root,string_argument=False):
 runtime,plan,admission=actual(root);sandbox=runtime['sandbox'];sandbox_raw=(json.dumps(sandbox,sort_keys=True,indent=2)+'\n').encode()
 runner=module('trusted_v7_runner_reproduction',CONSUMER/'runner/run.py');preflight=module('trusted_v7_preflight_reproduction',CONSUMER/'preflight.py')
 need(pin((CONSUMER/'runner/run.py').read_bytes())['sha256']==sandbox['runner_sha256'],'trusted maintained runner matches actual admitted runner')
 paths=[];real=preflight.path
 def trace(value):
  import inspect
  caller=inspect.currentframe().f_back;paths.append(dict(type=type(value).__name__,value=str(value),function=caller.f_code.co_name,line=caller.f_lineno));return real(value)
 data={'/inputs/xs-plan.json':plan,'/tmp/xs-sandbox.json':sandbox_raw,'/inputs/xs-admission.json':admission,str(CONSUMER/'runner/run.py'):(CONSUMER/'runner/run.py').read_bytes()}
 def read(value,*args):return data[str(value)]
 def boundary(*args):raise BoundaryReached('strict external operand validation complete; real sandbox gate fenced')
 # Derive the caller operand from the pinned trusted maintained v6 actor AST.
 native=(CONSUMER/'native_adapter/hosted_source_v6/payload/consumer/native_adapter/native.py').read_bytes()
 need(pin(native)==dict(bytes=48295,sha256='c492eb1b7175407d20a78305d8d1d499c67960d3b295aeea5ae206b9222d04cd'),'exact maintained actor matches failed Source321')
 actor=next(n for n in ast.parse(native).body if isinstance(n,ast.FunctionDef)and n.name=='actor')
 assignments=[n for n in ast.walk(actor)if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='sandbox_path'for t in n.targets)]
 calls=[n for n in ast.walk(actor)if isinstance(n,ast.Call)and isinstance(n.func,ast.Attribute)and isinstance(n.func.value,ast.Name)and n.func.value.id=='runner'and n.func.attr=='execute']
 need(len(assignments)==len(calls)==1,'single exact actor sandbox assignment/call')
 value=assignments[0].value;call=calls[0]
 need(isinstance(value,ast.Call)and isinstance(value.func,ast.Name)and value.func.id=='Path'and len(value.args)==1 and isinstance(value.args[0],ast.Constant)and value.args[0].value=='/tmp/xs-sandbox.json'and isinstance(call.args[2],ast.Name)and call.args[2].id=='sandbox_path','exact old Path object reaches runner argument3')
 argument=str(Path(value.args[0].value))if string_argument else Path(value.args[0].value)
 with patch.object(runner,'load_module',side_effect=lambda n,*a:preflight if n=='xs_frozen_preflight'else object()),patch.object(preflight,'read',side_effect=read),patch.object(preflight,'pinned',return_value=b'PINNED_READER_DATA_ONLY'),patch.object(preflight,'path',new=trace),patch.object(runner,'sandbox_check',side_effect=boundary):
  try:runner.execute('/inputs/xs-plan.json',sandbox['plan_sha256'],argument,pin(sandbox_raw)['sha256'])
  except BoundaryReached:
   need(string_argument,'old Path argument unexpectedly progressed');return dict(status='STRING_ARGUMENT_REACHES_FENCED_SANDBOX_GATE',paths=paths,actor_executed=False)
  except ValueError as e:
   need(not string_argument and str(e)=='canonical shell-safe absolute path'and paths[-1]['value']=='/tmp/xs-sandbox.json'and paths[-1]['type']=='PosixPath','exact observed error/call operand reproduced');return dict(status='EXACT_PATH_OBJECT_FAILURE_REPRODUCED',failure=str(e),call=paths[-1],paths=paths,actor_executed=False)
 raise AssertionError('reproduction did not reach expected boundary')
