#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Add one explicit interrupted-sharing case to the pinned sharing628 factory."""
import argparse,hashlib,json,stat,sys,types
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
BASE=HERE.parent/'ksm2-generic16k-sharing-hosted'
PROFILE_SHA='2c5acc34baad54b6fadb8552e9c622a02b509e1b54ef0bc5468fac00119cd97d'

def need(ok,why):
 if not ok:raise ValueError(why)

def local_read(path):
 path=Path(path);need(path.is_absolute()and not any(q.is_symlink()for q in(path,*path.parents)),'ordinary fixed source')
 a=path.lstat();need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and 0<=a.st_size<=16*1024**2,'bounded singlelink fixed source');raw=path.read_bytes()
 identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 need(identity(a)==identity(path.lstat())and len(raw)==a.st_size,'fixed source drift excluding atime only');return raw

def base():
 raw=local_read(HERE/'profile.json');need(hashlib.sha256(raw).hexdigest()==PROFILE_SHA,'whole fixed profile before code import');p=json.loads(raw)
 actual={}
 for path in BASE.rglob('*'):
  need(not path.is_symlink()and(path.is_dir()or path.is_file()),'ordinary closed predecessor')
  if path.is_file():
   name=path.relative_to(BASE).as_posix();raw=local_read(path);actual[name]=(raw,dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest()))
 need({n:v[1]for n,v in actual.items()}==p['base_factory'],'whole predecessor factory before code import')
 m=types.ModuleType('_held_sharing_factory');m.__file__=str(BASE/'prepare.py');exec(compile(actual['prepare.py'][0],m.__file__,'exec'),m.__dict__);return m

def profile(F):
 raw=F.read(HERE/'profile.json',4*1024**2);F.need(F.pin(raw)['sha256']==PROFILE_SHA,'whole interrupted-sharing profile');p=F.decode(raw)
 F.need(p['purpose']=='MAINTAINED_CONTROLLED_SIGTERM_KSM16K_SOURCE_ONLY'and all(p[k]is None for k in('actual_source','actual_ref','actual_run')),'NULL actual source/ref/run required')
 for name,row in p['base_factory'].items():F.need(F.pin(F.read(BASE/F.relative(name)))==row,'whole held sharing factory before import/render')
 F.need(p['base_profile']==F.profile(),'all original sharing/scalar behavior and selectors held');return p

def derive(F,p,source):
 source=dict(source);lane=F.LANE
 for name,row in p['payload'].items():
  F.need(row['before']==F.pin(source[name])if name in source else row['before']is None,'exact source delta before pin')
  raw=F.read(HERE/F.relative(row['path']));F.need(F.pin(raw)==row['proposed'],'whole fixed interrupted payload');source[name]=raw
 # Only full maps/self-reproduction metadata change beyond the explicit payloads.
 runner=F.decode(source['runtime/runner-files.json']);runner['files']['guest.py']=F.pin(source['runtime/guest.py']);source['runtime/runner-files.json']=F.encoded(runner)
 runtime={n.removeprefix('runtime/'):raw for n,raw in source.items()if n.startswith('runtime/')and n!='runtime/source-files.json'}
 source['runtime/source-files.json']=F.encoded(dict(files={n:F.pin(raw)for n,raw in runtime.items()}));runtime['source-files.json']=source['runtime/source-files.json']
 F.need(len(runtime)==610,'exact610 whole runtime')
 source[lane+'/runtime-role.json']=F.encoded(dict(purpose='WHOLE_FROZEN610_KSM_VM_SOURCE_ONLY_NOT_ACTUAL_AUTHORITY',files={n:F.pin(raw)for n,raw in runtime.items()}))
 del source[lane+'/source-manifest.json']
 for name in('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-ksm2-generic16k.yml'):del source[name]
 manifest=F.encoded(dict(schema_version=1,purpose='KSM2_GENERIC16K_HOSTED_TEST_ONLY',files={n:F.pin(raw)for n,raw in source.items()}));source[lane+'/source-manifest.json']=manifest
 text=source[lane+'/workflow.yml.in'].decode()
 for key,raw in(('@ENTRY_SHA@',source[lane+'/entry.py']),('@MANIFEST_SHA@',manifest),('@HOSTED_SHA@',source[lane+'/hosted.py'])):
  F.need(text.count(key)==1,'one original workflow stamp');text=text.replace(key,F.pin(raw)['sha256'])
 for name in('native-arm-build.yml','native-arm-ksm2-generic16k.yml'):source['.github/workflows/'+name]=text.encode()
 return source

def render(runtime,binding=None):
 F=base();p=profile(F);source,view,bounds=F.render(runtime,binding);F.need({n:F.pin(raw)for n,raw in source.items()}==p['base_profile']['expected_sources'][view],'whole predecessor sharing628 source')
 result=derive(F,p,source);F.need(len(result)==637 and {n:F.pin(raw)for n,raw in result.items()}==p['expected_sources'][view],'whole interrupted637 source');F.need(bounds==p['bounds'],'all original budgets held');return F,result,view,bounds

def assemble(runtime,output,binding=None):
 F,result,view,bounds=render(runtime,binding);output=Path(output);F.need(output.is_absolute()and output.parent.is_dir()and not output.exists()and not any(p.is_symlink()for p in(output,*output.parents)),'fresh ordinary output required');output.mkdir(mode=0o700)
 import os
 for name,raw in result.items():
  path=output/F.relative(name);path.parent.mkdir(parents=True,exist_ok=True);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
  with os.fdopen(fd,'wb')as stream:stream.write(raw)
 F.need(F.files(output)==result,'whole emitted637 source readback')
 return dict(status='EMITTED_INTERRUPTED637_SOURCE_ONLY',view=view,files=637,runtime_files=610,actual_source=None,actual_ref=None,actual_run=None,interruption='NOT_RUN',native='NOT_RUN',hardware='NOT_RUN',performance='NOT_MEASURED',acceptance='NOT_GRANTED',bounds=bounds)

if __name__=='__main__':
 a=argparse.ArgumentParser(description=__doc__);a.add_argument('--runtime',required=True,type=Path);a.add_argument('--output',required=True,type=Path);a.add_argument('--binding',type=Path);a.add_argument('--sharing-factory',type=Path,help='Optional explicit exact maintained predecessor directory');v=a.parse_args();BASE=v.sharing_factory.absolute()if v.sharing_factory else BASE;print(json.dumps(assemble(v.runtime,v.output,v.binding),sort_keys=True))
