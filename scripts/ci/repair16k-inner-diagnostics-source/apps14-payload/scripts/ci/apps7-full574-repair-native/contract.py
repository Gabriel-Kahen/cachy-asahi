# SPDX-License-Identifier: MIT
"""Finite native574 Apps owner binding; no actor is allowed while UNBOUND."""
import hashlib,importlib.util,json,os,re,stat,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
LANE='scripts/ci/apps7-full574-repair-native'
MANAGEMENT='scripts/ci/management-tools-generic16k'
BASE='cfd4c76f8602164c1091aed121332d201d0bf9299d3a51aedfb67f79c834e0ac'
LABEL='org.cachy-asahi.apps-full574-native'
STATUS='PASS_APPS14_GENERIC16K_SIGNED_REPAIR_CASE_AND_ORDERED_TEARDOWN'
ENV=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',TZ='UTC')
VERSIONS={'cachy-asahi-repository-runtime':'0.1.0-1','cachy-asahi-apps':'0.1.0-14','cachy-asahi-cache':'0.2.0-1','cachy-asahi-orphans':'0.1.0-2'}

def need(ok,why):
 if not ok:raise ValueError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def safe(path):
 path=Path(path).absolute();need('..' not in path.parts and not any(p.is_symlink() for p in (path,*path.parents)),'ordinary canonical path required');return path
def read(path,cap=2*1024**2):
 path=safe(path);a=path.stat();need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_size<=cap,'bounded ordinary single-link file required')
 raw=path.read_bytes();b=path.stat();need((a.st_dev,a.st_ino,a.st_mode,a.st_uid,a.st_gid,a.st_nlink,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_mode,b.st_uid,b.st_gid,b.st_nlink,b.st_size,b.st_mtime_ns,b.st_ctime_ns) and len(raw)==a.st_size,'file drift');return raw
def decode(raw):
 def pairs(rows):
  result={}
  for k,v in rows:need(k not in result,'duplicate JSON key');result[k]=v
  return result
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite JSON required'))
def save(path,value):
 temporary=path.with_suffix('.pending');temporary.write_bytes(encoded(value));temporary.replace(path)
def ref(root,path):
 raw=read(path,16*1024**2);return dict(path=path.relative_to(root).as_posix(),bytes=len(raw),sha256=sha(raw))
def checked(root,row):
 need(type(row) is dict and set(row)=={'path','bytes','sha256'} and type(row['bytes']) is int and 0<row['bytes']<=16*1024**2 and re.fullmatch('[0-9a-f]{64}',row['sha256'] or ''),'exact bounded reference required')
 name=row['path'];need(type(name) is str and name and not name.startswith('/') and '\\' not in name and all(p not in ('','.','..') for p in name.split('/')),'safe relative reference')

 if name.startswith('APPS14_CARRIER/'):
  return load('apps14_selected_read',HERE.parents[2]/'apps14-repair/selection.py').checked(HERE.parents[2],row)
 raw=read(root/name,16*1024**2);need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'source/input hash differs: '+name);return raw
def load(name,path):
 spec=importlib.util.spec_from_file_location('apps574_'+name,path);module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;spec.loader.exec_module(module);return module

def policy():
 need(not sys.flags.optimize,'ordinary unoptimized Python required')
 _selected=load('apps14_selected_authority',HERE.parents[2]/'apps14-repair/selection.py');_selected.authority(HERE.parents[2])
 value=decode(read(HERE/'input-policy.json'))
 need(value.get('schema_version')==1 and value.get('cases')==list(CASES) and value.get('aggregate')=='BOTH_INDEPENDENT_ROOT_CASE_DECISIONS_REQUIRED' and value.get('status')=='SOURCE_SELECTED_APPS14_PAIR_PLUS_HELD_RUNTIME_CACHE_ORPHANS' and value.get('versions')==VERSIONS and
      re.fullmatch('[0-9a-f]{40}',value.get('packet_source') or '') and type(value.get('packet_index')) is dict and type(value.get('adapter')) is dict and value['adapter'].get('path')==LANE+'/closure.py','UNBOUND native574 Apps packet/closure; no secrets or actors permitted')
 return value

def source(root):
 binding=policy();value=decode(read(HERE/'source-manifest.json'))
 need(value['schema_version']==1 and value.get('status')=='FROZEN_APPS14_REPAIR_EXECUTION_SOURCE' and 1<=len(value['files'])<=256,'Root frozen finite source closure required')
 need({'scripts/apps/file_capabilities.py','scripts/apps/test_file_capabilities.py',LANE+'/export_extract.py'}<=value['files'].keys(),'capability-aware Apps source closure required')
 for name,pin in value['files'].items():checked(root,dict(path=name,**pin))
 checked(root,binding['adapter']);return binding

def inputs(root,packet_root):
 source(root)
 return load('apps14_selected_inputs',Path(root)/'apps14-repair/selection.py').inputs(root,packet_root)

def adapter(root):
 binding=source(root);module=load('closure_adapter',root/binding['adapter']['path'])
 return module

def result(value):
 return load('actual_repair_result',HERE/'checks.py').result(sys.modules[__name__],value)

CASES=('repair-bytes','repair-missing')
def case(value):
 need(type(value) is str and value in CASES,'one explicit repair case required');return value
