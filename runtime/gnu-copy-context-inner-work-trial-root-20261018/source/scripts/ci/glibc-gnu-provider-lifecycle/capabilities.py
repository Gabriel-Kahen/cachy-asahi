# SPDX-License-Identifier: MIT
"""Finite original574 capability preservation for GNU provider copies only."""
from contextlib import contextmanager
import hashlib,importlib.util,json,sys
from pathlib import Path
_spec=importlib.util.spec_from_file_location("_gnu574_copy_scope",Path(__file__).with_name("copy_scope.py"))
scope=importlib.util.module_from_spec(_spec);sys.modules[_spec.name]=scope;_spec.loader.exec_module(scope)

encoded=lambda value:(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
digest=lambda value:hashlib.sha256(encoded(value)).hexdigest()

def need(ok,why):
 if not ok:raise ValueError(why)

def binding(index):
 mapping=index['source_capabilities']
 need(type(mapping) is dict and len(encoded(mapping))<=1024**2 and digest(mapping)==index['source_capabilities_sha256'],'original574 capability map/hash binding')
 return mapping

def observe(api,root,nodes,index,limits):
 actual=api['caps'].observe(root,nodes,limits)
 need(actual==binding(index),'original574 capability map changed')
 return actual

def disjoint(index,old,new):
 """No selected glibc/provider file may own a preserved capability inode."""
 selected={name for package in (old,new) for name,row in package['nodes'].items() if row['type']!='directory'}
 need(not selected&binding(index).keys(),'capability-bearing selected provider file refused')

def failure(error):
 """Bounded exception facts only: no locals, payloads, environments or actors."""
 result=[];seen=set();frames_left=8
 while error is not None and id(error) not in seen and len(result)<4:
  seen.add(id(error));frames=[];trace=error.__traceback__;count=0
  while trace is not None and count<64:
   if frames_left:
    frames.append(dict(file=trace.tb_frame.f_code.co_filename[-256:],function=trace.tb_frame.f_code.co_name[:128],line=trace.tb_lineno))
    if len(frames)>frames_left:frames.pop(0)
   trace=trace.tb_next;count+=1
  frames_left-=len(frames)
  result.append(dict(type=type(error).__name__[:128],message=str(error)[:512],frames=frames,frames_clipped=trace is not None or count>len(frames),
                     notes=[str(n)[:256] for n in getattr(error,'__notes__',())[:4]]))
  error=error.__cause__ if error.__cause__ is not None else (None if error.__suppress_context__ else error.__context__)
 return result

@contextmanager
def copied_root(api,source,workspace,index,evidence=None,**kwargs):
 # Unchanged copier owns disposal; diagnostics never grant copy acceptance.
 if evidence is None:evidence={}
 need(type(evidence) is dict and not evidence,'fresh copy diagnostic object')
 evidence.update(schema_version=1,stage='COPY_ENTER')
 try:
  with scope.copied_root(source,workspace,**kwargs) as (root,lifetime):
   evidence.update(stage='COPY_RETURNED',lifetime=lifetime)
   limits=kwargs['limits'];evidence['stage']='COPIED_TREE_OBSERVATION'
   nodes=api['roots'].observe(root,limits=limits,hardlinks='generic-development-internal')['nodes']
   evidence['stage']='CAPABILITY_RESTORE'
   actual=api['caps'].restore(root,nodes,binding(index),limits)
   need(actual==binding(index),'complete restored capability map differs')
   lifetime.update(security_capabilities='EXACT_SOURCE_MAP_RESTORED_AND_VERIFIED',source_capabilities_sha256=index['source_capabilities_sha256'])
   evidence['stage']='CALLER_YIELDED'
   yield root,lifetime
  evidence['stage']='COPY_LIFETIME_RETIRED'
 except BaseException as error:
  evidence['failure']=failure(error)
  raise

def records(index,cases,stages):
 mapping=binding(index)
 need(type(cases) is dict and set(cases)=={'pristine','modified'},'complete capability cases')
 for case,row in cases.items():
  scope.receipt(row['copy_lifetime']['copy']['gnu_bind_scope'],case)
  checks=row['capability_checks'];wanted={case+'-'+stage for stage in stages}
  need(set(checks)==wanted and all(value==dict(status='EXACT_SOURCE_MAP_PRESERVED',sha256=index['source_capabilities_sha256'],paths=len(mapping)) for value in checks.values()),'complete source/copy/stage capability preservation')
  need(row['copy_lifetime']['security_capabilities']=='EXACT_SOURCE_MAP_RESTORED_AND_VERIFIED' and row['copy_lifetime']['source_capabilities_sha256']==index['source_capabilities_sha256'],'complete copied capability preservation')
 return dict(status='EXACT_SOURCE_MAP_PRESERVED',source_capabilities_sha256=index['source_capabilities_sha256'],paths=len(mapping),cases=2,stages=len(stages),copy_scope_sha256={case:digest(row['copy_lifetime']['copy']['gnu_bind_scope']) for case,row in cases.items()})
