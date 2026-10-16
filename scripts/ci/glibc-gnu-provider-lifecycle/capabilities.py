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

@contextmanager
def copied_root(api,source,workspace,index,**kwargs):
 # Unchanged copier owns all lifetime/error disposal. Restoration is inside its
 # context before the first caller yield, so refusal cannot accept a bare copy.
 with scope.copied_root(source,workspace,**kwargs) as (root,lifetime):
  limits=kwargs['limits'];nodes=api['roots'].observe(root,limits=limits,hardlinks='generic-development-internal')['nodes']
  actual=api['caps'].restore(root,nodes,binding(index),limits)
  need(actual==binding(index),'complete restored capability map differs')
  lifetime.update(security_capabilities='EXACT_SOURCE_MAP_RESTORED_AND_VERIFIED',source_capabilities_sha256=index['source_capabilities_sha256'])
  yield root,lifetime

def records(index,cases,stages):
 mapping=binding(index)
 need(type(cases) is dict and set(cases)=={'pristine','modified'},'complete capability cases')
 for case,row in cases.items():
  scope.receipt(row['copy_lifetime']['copy']['gnu_bind_scope'],case)
  checks=row['capability_checks'];wanted={case+'-'+stage for stage in stages}
  need(set(checks)==wanted and all(value==dict(status='EXACT_SOURCE_MAP_PRESERVED',sha256=index['source_capabilities_sha256'],paths=len(mapping)) for value in checks.values()),'complete source/copy/stage capability preservation')
  need(row['copy_lifetime']['security_capabilities']=='EXACT_SOURCE_MAP_RESTORED_AND_VERIFIED' and row['copy_lifetime']['source_capabilities_sha256']==index['source_capabilities_sha256'],'complete copied capability preservation')
 return dict(status='EXACT_SOURCE_MAP_PRESERVED',source_capabilities_sha256=index['source_capabilities_sha256'],paths=len(mapping),cases=2,stages=len(stages),copy_scope_sha256={case:digest(row['copy_lifetime']['copy']['gnu_bind_scope']) for case,row in cases.items()})
