#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Finite measurement Source/DRAFT constructor; no actor or acquisition calls."""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
import stat
from pathlib import Path
import tempfile

HERE=Path(__file__).resolve().parent
FAMILY='scripts/ci/measurement-tools-native-source'
RECIPE='packages/tools/cachy-asahi-measurement-tools'
BASE_COMMIT='e8e8e5819fba20f1848c8e245966b79c25f08598'
INPUTS_SHA256='a850daaf4514185c7fcad755cd0700f05ae783d3ec8f0a8a6bac8ac43c1d4512'
ACTUAL=dict.fromkeys(('source','ref','run','job','artifact','nonce','runtime','acceptance'))
REPLACED={'native/measurement_tools_v1.py','native/measurement_reader_v1.py'}
ADDED={'native/measurement_installed_probe_v2.py'}

def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def need(ok,message):
 if not ok:raise ValueError(message)

def ordinary(path,maximum):
 path=Path(path)
 need(path.is_absolute() and not any(p.is_symlink()for p in(path,*path.parents)),'nonaliased maintained input')
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  info=os.fstat(fd);need(stat.S_ISREG(info.st_mode)and info.st_nlink==1 and 0<=info.st_size<=maximum,'bounded ordinary single-link input')
  chunks=[];size=0
  while block:=os.read(fd,min(65536,maximum+1-size)):
   chunks.append(block);size+=len(block);need(size<=maximum,'maintained input size bound')
  after=os.fstat(fd);fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
  need(size==info.st_size and all(getattr(info,k)==getattr(after,k)==getattr(path.lstat(),k)for k in fields),'maintained input changed')
  return b''.join(chunks),stat.S_IMODE(info.st_mode)
 finally:os.close(fd)

def load_factory(checkout):
 checkout=Path(checkout);raw=ordinary(HERE/'inputs.json',1024**2)[0];need(pin(raw)['sha256']==INPUTS_SHA256,'fixed whole maintained input manifest');inputs=json.loads(raw)
 need(inputs['maintained_checkout_commit']==BASE_COMMIT and set(inputs)=={'maintained_checkout_commit','files'},'fixed maintained input schema')
 factory_raw=None
 for name,row in inputs['files'].items():
  raw,mode=ordinary(checkout/name,row['bytes'])
  need(dict(pin(raw),mode=mode)==row,'exact maintained input: '+name)
  if name==FAMILY+'/prepare.py':factory_raw=raw
 name=checkout/FAMILY/'prepare.py';spec=importlib.util.spec_from_file_location('fixed_measurement_v1_data_factory',name);factory=importlib.util.module_from_spec(spec);need(factory_raw is not None,'pinned finite factory required');exec(compile(factory_raw,str(name),'exec'),factory.__dict__)
 return factory

def draft():
 value=json.loads(ordinary(HERE/'Root-admission.DRAFT.json',65536)[0])
 need(value==dict(schema=2,kind='UNISSUED_MEASUREMENT_NATIVE_SOURCE_V2_DRAFT',issuer=None,Root_trust=None,signing=None,resources=None,actual=ACTUAL,approved=None,accepted=None),'Root trust/signing/resources/actual/acceptance must remain NULL')
 return value

def closure(factory,checkout,source):
 contract=json.loads(source['native/measurement-contract-v1.json'][0]);recipe=Path(checkout)/RECIPE
 expected=contract['recipe']['source_files'];actual=factory.tree(recipe)
 need(factory.rows(actual)==expected,'current exact18 recipe bytes/modes differ from held candidate')
 need(set(actual)==set(expected)and len(actual)==18,'exact18 current recipe namespace')
 provenance=json.loads(actual['source-provenance.json'][0]);modules={}
 need(provenance['base_commit']=='852d1b7324e4ad840fa94ea7c9fc994b1aa07280','original five-module MIT source identity')
 for row in provenance['sources']:
  raw,mode=actual[row['file']]
  need(pin(raw)=={k:row[k]for k in('bytes','sha256')} and factory.oid(b'blob',raw).hex()==row['git_blob'] and row['license']=='MIT' and row['transformation']=='none; byte-identical','original MIT body/blob/provenance join')
  modules[row['file']]=row
 need(set(modules)=={'benchmark.py','benchmark_platform_metrics.py','platform_metrics.py','process_group_memory.py','owned_process.py','LICENSE'},'exact five modules and license closure')
 bundle=factory.tree(Path(checkout)/FAMILY/'payload')
 need(bundle['native/measurement-sources-v1.tar']==source['native/measurement-sources-v1.tar'],'unchanged exact25-member original source delivery')
 return dict(schema=2,package='cachy-asahi-measurement-tools',version='0.1.0-1',license='MIT',recipe_files=expected,original_modules_and_license=modules,original_source_commit=provenance['base_commit'],runtime_dependencies=['python>=3.12'],check_dependencies=['bubblewrap'],native_dependencies=contract['dependencies'],complete_native_inventory=contract['expected349'],buildinfo_installed=contract['buildinfo_installed'],payload_files=contract['recipe']['payload_files'],bundle=contract['bundle'],namespace_support='UNKNOWN',native='NOT RUN',ALPM='NOT RUN',M2='NOT RUN',performance='NOT MEASURED',release='NOT ADMITTED')

def finite_probe_delta(old,overlay):
 """Preserve every existing target and API outside the installed probe seams."""
 for name,changed,added in (('native/measurement_tools_v1.py',{'business'},set()),('native/measurement_reader_v1.py',{'measurement_business'},{'measurement_probe_v2'})):
  before=ast.parse(old[name][0]);after=ast.parse(overlay[name][0]);kinds=(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)
  functions=lambda tree:{node.name:node for node in tree.body if isinstance(node,kinds)}
  frame=lambda tree:[ast.dump(node,include_attributes=False)for node in tree.body if not isinstance(node,kinds)]
  a,b=functions(before),functions(after)
  need(set(b)==set(a)|added and frame(before)==frame(after),'preserve complete existing runtime module/API frame')
  need(all(ast.dump(node,include_attributes=False)==ast.dump(b[key],include_attributes=False)for key,node in a.items()if key not in changed),'preserve every existing build/lifecycle/Reader target outside installed probe')
  need(all(ast.dump(a[key].args,include_attributes=False)==ast.dump(b[key].args,include_attributes=False)for key in changed),'preserve installed business call APIs')

def render(checkout,basis):
 factory=load_factory(checkout);draft();profile,before,old=factory.render(Path(basis))
 licenses=closure(factory,checkout,old);overlay=factory.tree(HERE/'payload')
 need(set(overlay)==REPLACED|ADDED and all(m==0o644 for b,m in overlay.values()),'only fixed probe and tools/Reader seams')
 finite_probe_delta(old,overlay)
 source=dict(old);source.update(overlay)
 manifest=json.loads(old['native/source-map.json'][0]);need(all(v is None for v in manifest['actual'].values()),'old operation selectors remain NULL')
 manifest['files']=factory.rows({n:r for n,r in source.items()if n!='native/source-map.json'})
 source['native/source-map.json']=(encoded(manifest),0o644)
 for name,(raw,mode)in source.items():
  if name.endswith('.py'):compile(raw,name,'exec')
 inverse=dict(source)
 for name in ADDED:del inverse[name]
 for name in REPLACED|{'native/source-map.json'}:inverse[name]=old[name]
 need(factory.rows(inverse)==factory.rows(old) and factory.git_tree(inverse)==profile['source_tree'],'complete exact199 predecessor inverse')
 identity=dict(files=len(source),bytes=sum(len(b)for b,m in source.values()),tree=factory.git_tree(source),source_map=pin(source['native/source-map.json'][0]))
 expected=json.loads(ordinary(HERE/'profile.json',65536)[0])
 need(expected==dict(schema=2,scope='MEASUREMENT_TOOLS_NATIVE_SOURCE_DRAFT_V2',source=identity,closure=pin(encoded(licenses)),actual=ACTUAL,Root_trust=None,signing=None,resources=None,acceptance=None,parent_source=dict(files=199,tree=profile['source_tree'],map_sha256=profile['source_map_sha256']),namespace_support='UNKNOWN',native='NOT RUN',ALPM='NOT RUN',M2='NOT RUN',performance='NOT MEASURED',release='NOT ADMITTED'),'whole profiled Source/DRAFT identity')
 need(ordinary(HERE/'closure.DATA.json',1024**2)[0]==encoded(licenses),'checked exact source/license/dependency closure')
 need(len(source)==200 and set(source)==set(old)|ADDED,'finite exact200 Source namespace')
 return factory,old,source,identity,licenses

def construct(checkout,basis,output,profile_sha256):
 checkout,basis,output=map(Path,(checkout,basis,output))
 factory=load_factory(checkout)
 for p in(checkout,basis,output):factory.absolute(p)
 need(pin(factory.read(HERE/'profile.json')[0])['sha256']==profile_sha256,'external whole profile pin required')
 need(not any(output.is_relative_to(p)or p.is_relative_to(output)for p in(checkout,basis,HERE)),'fresh disjoint output required')
 info=output.parent.stat();need(info.st_uid==os.geteuid() and info.st_mode&0o777==0o700 and not os.path.lexists(output),'fresh output in owned0700 parent')
 factory,old,source,identity,licenses=render(checkout,basis)
 changed=REPLACED|ADDED|{'native/source-map.json'}
 inverse=dict(schema=2,parent_files=199,parent_tree=factory.git_tree(old),parent_map_sha256=pin(old['native/source-map.json'][0])['sha256'],changes={n:dict(before=factory.rows(old).get(n),after=factory.rows(source)[n])for n in sorted(changed)},Root_acceptance=None)
 bodies={'source/'+n:r for n,r in source.items()}
 bodies.update({'before-v1/'+n:old[n]for n in changed if n in old})
 bodies.update({n:(encoded(v),0o644)for n,v in {'stage.DRAFT.json':dict(schema=2,status='SOURCE_DRAFT_ONLY_NO_ACTORS',actual=ACTUAL,Root_trust=None,signing=None,resources=None,acceptance=None,source=identity,namespace_support='UNKNOWN',native='NOT RUN',ALPM='NOT RUN',M2='NOT RUN',performance='NOT MEASURED',release='NOT ADMITTED'),'closure.json':licenses,'inverse-v1.DATA.json':inverse,'Root-admission.DRAFT.json':draft()}.items()})
 with tempfile.TemporaryDirectory(prefix='.measurement-v2-',dir=output.parent)as temporary:
  staged=Path(temporary)/'packet';staged.mkdir(mode=0o700)
  for name,(raw,mode)in sorted(bodies.items()):
   target=staged/name;target.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
   with target.open('xb')as stream:stream.write(raw)
   target.chmod(mode)
  need(factory.rows(factory.tree(staged/'source'))==factory.rows(source),'complete published Source check')
  # Reuse the maintained factory's no-replace atomic publication primitive.
  rename=factory.ctypes.CDLL(None,use_errno=True).renameat2
  rename.argtypes=[factory.ctypes.c_int,factory.ctypes.c_char_p,factory.ctypes.c_int,factory.ctypes.c_char_p,factory.ctypes.c_uint];rename.restype=factory.ctypes.c_int
  if rename(-100,os.fsencode(staged),-100,os.fsencode(output),1):
   code=factory.ctypes.get_errno();raise OSError(code,os.strerror(code))
 return dict(status='SOURCE_DRAFT_ONLY_NO_ACTORS',source=identity,actual=ACTUAL,Root_acceptance=None)

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__)
 for key in('checkout','basis','output'):p.add_argument('--'+key,type=Path,required=True)
 p.add_argument('--profile-sha256',required=True);a=p.parse_args()
 print(json.dumps(construct(a.checkout,a.basis,a.output,a.profile_sha256),sort_keys=True))
