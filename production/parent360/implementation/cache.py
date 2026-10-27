# SPDX-License-Identifier: MIT
"""All original cache/archive/signer guards with exact baseline607 operands."""
import ast,types
from pathlib import Path
import common as C

def function(raw,name,scope,counts,strings=()):
 text=raw.decode();tree=ast.parse(raw);node=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name==name);old=ast.get_source_segment(text,node);new=old
 for before,after,count in strings:C.need(new.count(before)==count,'counted cache function seam '+name);new=new.replace(before,after)
 selected=ast.parse(new).body[0];lines=new.encode().splitlines(keepends=True);offset=[0]
 for line in lines:offset.append(offset[-1]+len(line))
 edits=[];actual={}
 for n in ast.walk(selected):
  if isinstance(n,ast.Constant)and type(n.value)is int and n.value in counts:
   before,after,count=n.value,*counts[n.value];actual[before]=actual.get(before,0)+1;start=offset[n.lineno-1]+n.col_offset;end=offset[n.end_lineno-1]+n.end_col_offset;edits.append((start,end,repr(after).encode(),new.encode()[start:end]))
 C.need(actual=={k:v[1]for k,v in counts.items()},'typed complete cache operand counts '+name);body=new.encode()
 for a,b,after,before in sorted(edits,reverse=True):body=body[:a]+after+body[b:]
 restored=body
 for a,b,after,before in sorted(edits):C.need(restored[a:a+len(after)]==after,'cache whole inverse operand');restored=restored[:a]+before+restored[a+len(after):]
 restored=restored.decode()
 for before,after,count in reversed(strings):C.need(restored.count(after)==count,'cache complete string inverse');restored=restored.replace(after,before)
 C.need(restored==old,'entire original cache function inverse '+name);namespace=dict(scope);exec(compile(body,'<latest607-held-'+name+'>','exec'),namespace);return namespace[name],dict(before=C.pin(old.encode()),after=C.pin(body),whole_inverse=True)

def api(original):
 # Execute the entire original target_manifest body after finite typed/lock/status
 # operands; every archive/signature/role/key/builder/aggregate predicate remains.
 raw=C.read(original.__file__);scope=dict(original.target_manifest.__globals__,TARGET_SHA=C.profile()['before']['sha256'],locks=lambda:(C.locks()[0],C.locks()[0]));selected,proof=function(raw,'target_manifest',scope,{604:(607,3)},[("READY_SIGNED_EXPANDED604","READY_SIGNED_EXPANDED607",1)])
 out=types.SimpleNamespace(**vars(original));out.target_manifest=selected;out._latest607_target_manifest_inverse=proof;return out

def module(original_contract,original_raw):
 namespace=dict(vars(original_contract));namespace.update(BEFORE=C.profile()['before']['sha256'],AFTER=C.profile()['after']['sha256'],locks=C.locks);contract=types.ModuleType('contract');contract.__dict__.update(namespace);out=types.ModuleType('_latest607_complete_before_cache');out.__file__='source-owned-baseline607-cache.py';namespace=dict(C=contract,Path=Path,shutil=__import__('shutil'),STATUS='READY_SIGNED_EXPANDED607');proof={}
 verify,proof['verify']=function(original_raw,'verify',namespace,{604:(607,2),21:(24,2)})
 namespace['verify']=verify;bind,proof['bind']=function(original_raw,'bind',namespace,{},[("'0.1.0-5'","'0.1.0-6'",1)])
 flat,proof['flat_inputs']=function(original_raw,'flat_inputs',namespace,{21:(24,1),31:(34,1)})
 out.verify,out.bind,out.flat_inputs=verify,bind,flat;out.inverse=proof;return out

class ProducerFacade:
 """The real producer keeps executing globals and original exporter mutation."""
 def __init__(self,producer,diagnostic):object.__setattr__(self,'_producer',producer);object.__setattr__(self,'_diagnostic',diagnostic)
 def __getattr__(self,name):
  if name=='prepare':return lambda args:self._diagnostic.prepare(self._producer,args)
  return getattr(self._producer,name)
 def __setattr__(self,name,value):setattr(self._producer,name,value)

def dependency_policy():
 p=C.profile()['dependency_cache'];C.need(set(p['operands'])=={'compiler6.py','compiler6-profile.json','producer_diagnostic.py'}and p['incoming_ref']=='codex/current606-incoming31-v1'and all(type(p[k])is int for k in('new_phase_seconds','prior_files','new_files','total_dependency_files','original_acquisition_seconds'))and all(p[k]is None for k in('current_actual_source','current_actual_ref','current_actual_run')),'fixed typed cache policy and current actualNULL');C.need(p['incoming_source']=='405761af52cdfa92b97bbf5b0519f32230d9a254'and p['new_phase_seconds']==240 and p['prior_files']==1159 and p['new_files']==8 and p['total_dependency_files']==10 and p['original_acquisition_seconds']==180 and p['authority']is False,'closed additional240 cache phase, no original180 reset/authority')
 for n,w in p['operands'].items():C.checked(C.HERE/n,w)
 return p

def prepare_with_plan(integration,original,producer,args):
 # New explicit240 phase fits only within the HELD original outer allowances.
 import time
 p=dependency_policy();C.need(integration.dependency_incoming is not None,'explicit immutable dependency input required')
 original_common,_=integration.source_modules();revision=C.load('_latest607_dependency_revision',integration.fresh/'implementation/loaders.py',{'common':original_common});revision.revision(integration.dependency_incoming,p['incoming_source'])
 helper=C.load('_latest607_exact_retained_dependency_copy',C.HERE/'compiler6.py');deadline=time.monotonic()+p['new_phase_seconds']
 helper.prepare_dependency_cache(integration.dependency_incoming,args.preparation_source,args.desktop/'scripts/ci/maintained-desktop574-inputs.json',args.cache,deadline)
 diagnostic=C.load('_latest607_exact_fixed_producer_diagnostic',C.HERE/'producer_diagnostic.py')
 return original.prepare_with_plan(ProducerFacade(producer,diagnostic),args)
