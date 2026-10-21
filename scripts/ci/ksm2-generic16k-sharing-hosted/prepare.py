#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Emit exact sharing628 from scalar605 and maintained, pinned sharing deltas."""
import argparse, hashlib, json, os, stat, sys, types
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
SCALAR=HERE.parent/'ksm2-generic16k-vm-hosted'
LANE='scripts/ci/ksm2-generic16k-vm-hosted'
PROFILE_SHA='b6d8d3d205845cef7885276043e74125dcd1d397824d0d3a2e258185d28f3c72'

def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def decode(raw):
 def pairs(rows):
  result={}
  for key,value in rows:need(key not in result,'duplicate metadata key');result[key]=value
  return result
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite metadata required'))
def relative(name):
 need(type(name)is str and name and not name.startswith('/')and '\\'not in name and '\0'not in name and all(p not in('','.','..')for p in name.split('/')),'contained source role required');return name

def stable_identity(info):
 return(info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)

def read(path,cap=16*1024**2):
 path=Path(path);need(path.is_absolute()and not any(p.is_symlink()for p in(path,*path.parents)),'ordinary absolute source required')
 before=path.lstat();need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=cap,'bounded ordinary source required')
 raw=path.read_bytes();need(stable_identity(path.lstat())==stable_identity(before) and len(raw)==before.st_size,'source drift');return raw

def files(root):
 root=Path(root);need(root.is_absolute()and root.is_dir()and not any(p.is_symlink()for p in(root,*root.parents)),'ordinary runtime directory required');result={}
 for path in sorted(root.rglob('*')):
  need(not path.is_symlink()and(path.is_file()or path.is_dir()),'closed ordinary runtime required')
  if path.is_file():result[relative(path.relative_to(root).as_posix())]=read(path)
 return result

def profile():
 raw=read(HERE/'profile.json',2*1024**2);need(pin(raw)['sha256']==PROFILE_SHA,'whole maintained sharing profile differs');value=decode(raw)
 need(value['schema_version']==1 and value['purpose']=='MAINTAINED_KSM16K_SHARING_FACTORY_SOURCE_ONLY'and all(value[k]is None for k in('actual_source','actual_ref','actual_run')),'source-only NULL factory profile required')
 role=read(SCALAR/'runtime-role.json',2*1024**2);need(pin(role)==value['scalar_role'],'original scalar605 role differs');role=decode(role)
 need(role['purpose']=='WHOLE_FROZEN605_KSM_VM_SOURCE_ONLY_NOT_ACTUAL_AUTHORITY'and role['files']==value['base_runtime']and len(role['files'])==605,'held scalar605 source role required')
 need(len(value['runtime_files'])==608 and len(value['runtime_overrides'])==22 and set(value['base_runtime'])<=set(value['runtime_files']),'exact sharing608 runtime role required')
 return value

def render(runtime,binding=None):
 p=profile();source=files(Path(runtime));need({n:pin(raw)for n,raw in source.items()}==p['base_runtime'],'exact whole scalar605 input runtime required')
 for name,row in p['runtime_overrides'].items():
  relative(name);need(row['before']==p['base_runtime'].get(name),'whole runtime before pin differs')
  if name in source:need(pin(source[name])==row['before'],'runtime predecessor differs')
  raw=read(HERE/relative(row['path']));need(pin(raw)==row['proposed']==p['runtime_files'][name],'maintained sharing delta differs');source[name]=raw
 need({n:pin(raw)for n,raw in source.items()}==p['runtime_files'],'whole sharing608 runtime differs')
 result={'runtime/'+n:raw for n,raw in source.items()}
 for name,row in p['outer_templates'].items():
  relative(name);origin=row['origin'];relative(origin)
  path=SCALAR/name if origin=='scalar/'+name else HERE/origin
  raw=read(path);need(pin(raw)==row['pin'],'held hosted template differs: '+name);result[LANE+'/'+name]=raw
 # This exact pinned hosted module supplies the unchanged Root-selection gate.
 module=types.ModuleType('_maintained_sharing_hosted');module.__file__=str(HERE/'templates/hosted.py')
 exec(compile(result[LANE+'/hosted.py'],module.__file__,'exec'),module.__dict__)
 policy=module.defaults();need(policy==p['policies']['default'],'whole NULL policy differs');view='default'
 if binding is not None:
  policy=module.selected(decode(read(Path(binding),65536)));need(policy==p['policies']['selected'],'explicit reviewed Root selection differs');view='selected'
 need(all(policy[k]is None for k in('actual_source','actual_ref','actual_run')),'actual source/ref/run remain NULL')
 result[LANE+'/input-policy.json']=encoded(policy)
 manifest=encoded(dict(schema_version=1,purpose='KSM2_GENERIC16K_HOSTED_TEST_ONLY',files={n:pin(raw)for n,raw in result.items()}));result[LANE+'/source-manifest.json']=manifest
 text=result[LANE+'/workflow.yml.in'].decode()
 for key,raw in (('@ENTRY_SHA@',result[LANE+'/entry.py']),('@MANIFEST_SHA@',manifest),('@HOSTED_SHA@',result[LANE+'/hosted.py'])):
  need(text.count(key)==1,'one exact workflow stamp required');text=text.replace(key,pin(raw)['sha256'])
 for name in('native-arm-build.yml','native-arm-ksm2-generic16k.yml'):result['.github/workflows/'+name]=text.encode()
 need(len(result)==628 and {n:pin(raw)for n,raw in result.items()}==p['expected_sources'][view],'complete exact628 source bytes differ')
 return result,view,module.BOUNDS

def assemble(runtime,output,binding=None):
 result,view,bounds=render(runtime,binding);output=Path(output)
 need(output.is_absolute()and output.parent.is_dir()and not output.exists()and not any(p.is_symlink()for p in(output,*output.parents)),'fresh ordinary output required')
 output.mkdir(mode=0o700)
 for name,raw in result.items():
  path=output/relative(name);path.parent.mkdir(parents=True,exist_ok=True)
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
  with os.fdopen(fd,'wb')as stream:stream.write(raw)
 need({n:pin(raw)for n,raw in files(output).items()}=={n:pin(raw)for n,raw in result.items()},'emitted whole628 readback differs')
 return dict(status='EMITTED_EXACT_SHARING628_SOURCE_ONLY',view=view,files=628,base_runtime_files=605,whole_runtime_files=608,actual_source=None,actual_ref=None,actual_run=None,acceptance='NOT_GRANTED',hardware='NOT_RUN',performance='NOT_MEASURED',bounds=bounds)

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--runtime',type=Path,required=True,help='Exact whole frozen scalar605 runtime; sharing deltas are maintained here');parser.add_argument('--output',type=Path,required=True);parser.add_argument('--binding',type=Path,help='Explicit existing Root component selection, never an actual run identity');parser.add_argument('--controlled-interruption',action='store_true',help='Emit the fixed controlled-SIGTERM sharing637 source; actual execution remains untested');args=parser.parse_args()
 if args.controlled_interruption:
  path=HERE.parent/'ksm2-generic16k-interrupted-sharing-hosted/prepare.py';module=types.ModuleType('_ksm_controlled_interruption_factory');module.__file__=str(path)
  exec(compile(read(path),str(path),'exec'),module.__dict__);result=module.assemble(args.runtime,args.output,args.binding)
 else:result=assemble(args.runtime,args.output,args.binding)
 print(json.dumps(result,sort_keys=True))
