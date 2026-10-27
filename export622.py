# SPDX-License-Identifier: MIT
"""Preserve current public DATA and invoke the entire original opaque transport."""
import argparse,hashlib,importlib.util,json,os,stat,sys,types
from pathlib import Path

# Admit only this canonical closed Source directory before sibling imports.
import sys

def _admit_closed_sibling_source():
 root=Path(__file__).absolute().parent
 def require(value):
  if not value:raise ValueError('closed current Source sibling admission refused')
 def identity(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 require(root==root.resolve()and not any(p.is_symlink()for p in(root,*root.parents)));before=root.stat();require(stat.S_ISDIR(before.st_mode)and before.st_uid==os.getuid()and not before.st_mode&0o022)
 def raw(name):
  path=root/name;require(path.is_relative_to(root)and not any(p.is_symlink()for p in(path,*path.parents)));fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   first=os.fstat(fd);require(stat.S_ISREG(first.st_mode)and first.st_nlink==1 and first.st_uid==os.getuid()and stat.S_IMODE(first.st_mode)==0o644 and 0<=first.st_size<=4*1024**2);data=bytearray()
   while len(data)<=first.st_size:
    part=os.read(fd,min(1024**2,first.st_size+1-len(data)))
    if not part:break
    data.extend(part)
   require(len(data)==first.st_size and identity(first)==identity(os.fstat(fd))==identity(path.lstat()));return bytes(data)
  finally:os.close(fd)
 manifest=json.loads(raw('source-manifest.json'));files=manifest['files'];aliases=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-core7-real-systemd.yml');expected=set(files)|{'source-manifest.json',*aliases};require(type(files)is dict and len(files)==63 and len(expected)==66 and manifest['actual']is None);found=set();directories={''}
 for path in root.rglob('*'):
  name=path.relative_to(root).as_posix()
  if name.split('/')[0]=='.git':continue
  require(not path.is_symlink()and(path.is_dir()or path.is_file()))
  if path.is_dir():directories.add(name)
  else:found.add(name)
 require(found==expected);wanted={''}
 for name in expected:
  require(type(name)is str and name==Path(name).as_posix()and not Path(name).is_absolute()and all(p not in('', '.', '..')for p in name.split('/')))
  wanted.update(''if str(p)=='.'else p.as_posix()for p in Path(name).parents)
 require(directories==wanted)
 for name,want in files.items():
  data=raw(name);require(want==dict(bytes=len(data),sha256=hashlib.sha256(data).hexdigest()))
 require(all(raw(name)==raw('workflow.yml.in')for name in aliases));require(identity(before)==identity(root.stat()))
 for name in('case','ownership622'):
  module=sys.modules.get(name)
  if module is not None:require(Path(getattr(module,'__file__','/invalid')).absolute()==root/(name+'.py'))
 sys.path.insert(0,str(root));return root

_ADMITTED_SOURCE=None

def need(v,s):
 if not v:raise ValueError(s)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def copy(output,public,*,retained_transport=False):
 source=output/'core622-public';need(output.parent==Path('/tmp')and output.is_absolute()and public.is_absolute()and not public.exists()and not any(x.is_symlink()for x in(output,public,*output.parents,*public.parents)),'fresh explicit current output/public paths');rows={};total=0
 if source.exists():
  for f in source.rglob('*'):
   st=f.lstat();need(st.st_uid==os.getuid()and not f.is_symlink()and(stat.S_ISDIR(st.st_mode)or stat.S_ISREG(st.st_mode)and st.st_nlink==1),'only current caller-owned ordinary public evidence')
   if f.is_file():
    n=f.relative_to(source).as_posix();need(st.st_size<=128*1024**2 and len(rows)<4096,'original individual public caps');raw=f.read_bytes();need(len(raw)==st.st_size,'whole current public bytes');rows[n]=pin(raw);total+=len(raw);need(total<=768*1024**2,'original768MiB aggregate');target=public/n;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
  need((public/'export.json').is_file(),'source-owned full Core retainer required');record=json.loads((public/'export.json').read_bytes());need(set(rows)==set(record['files'])|{'export.json'}and all(rows[n]==v for n,v in record['files'].items()),'unchanged complete current Core public closure');
  if retained_transport:_retain_transport_or_early_data(public)
  return
 public.mkdir(mode=0o700)
 # An original producer failure can precede every Core consumer. Preserve only
 # the fixed outer current result; no invented Core owner or cleanup receipt.
 result=output/'result.json'
 if result.is_file():
  st=result.lstat();need(stat.S_ISREG(st.st_mode)and st.st_nlink==1 and st.st_uid==os.getuid()and st.st_size<=4*1024**2,'ordinary bounded current outer result');raw=result.read_bytes();need(len(raw)==st.st_size,'whole current result');(public/'fresh607-caller-result.json').write_bytes(raw);rows['fresh607-caller-result.json']=pin(raw)
 raw=(json.dumps(dict(status='CORE622_PRE_PROVISION_FAILURE_DATA_ONLY',scope='COPIED_ROOT_PROVISIONING_NOT_NORMAL_HOOK_INSTALLATION_THEN_NORMAL_CORE_VM',Core_runtime='NOT_ESTABLISHED',acceptance=False,hardware='NOT_RUN'),sort_keys=True,indent=2)+'\n').encode();(public/'current622-context.json').write_bytes(raw);rows['current622-context.json']=pin(raw);(public/'export.json').write_text(json.dumps(dict(schema=1,status='FAIL_OR_INCOMPLETE',files=rows,bytes=sum(r['bytes']for r in rows.values()),errors=[dict(file='Core622',error='PRE_PROVISION_FAILURE_DATA_ONLY')],hardware='NOT_RUN'),sort_keys=True,indent=2)+'\n')

 if retained_transport:_retain_transport_or_early_data(public)


def _retain_early_transport_data(public,reason):
 """Stdlib-only failure DATA; no sibling imports, actor or cleanup authority."""
 public=Path(public);temporary=Path(os.environ['RUNNER_TEMP']);work=temporary/'core622-retained-transport';root=Path(__file__).absolute().parent
 def require(value):
  if not value:raise ValueError('bounded early transport DATA custody refused')
 def raw(path,cap):
  path=Path(path);require(path.is_absolute()and not any(p.is_symlink()for p in(path,*path.parents)));fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
  try:
   before=os.fstat(fd);identity=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns);require(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and before.st_uid==os.getuid()and 0<=before.st_size<=cap);data=bytearray()
   while len(data)<=before.st_size:
    part=os.read(fd,min(1024**2,before.st_size+1-len(data)))
    if not part:break
    data.extend(part)
   require(len(data)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(path.lstat()));return bytes(data)
  finally:os.close(fd)
 require(temporary.is_absolute()and temporary==temporary.resolve()and temporary.is_dir()and temporary.stat().st_uid==os.getuid()and not temporary.stat().st_mode&0o022 and not public.is_relative_to(root)and not root.is_relative_to(public));record=json.loads(raw(public/'export.json',4*1024**2));record['status']='FAIL_OR_INCOMPLETE';record['errors'].append(dict(file='retained-input-transport',error='EARLY_DEPENDENCY_OR_RETENTION_'+reason));target=public/'retained-input-transport';require(not target.is_symlink());target.mkdir(mode=0o700,exist_ok=True);require(target.stat().st_uid==os.getuid()and stat.S_IMODE(target.stat().st_mode)==0o700);names={'owner.json','preparation.json','phase.stdout','phase.stderr','phase.exit-code','input-transport-actors/actors.json'}|{'input-transport-actors/%04d.log'%n for n in range(5)};total=0;copied=[];errors=[]
 if work.exists():
  require(work==work.resolve()and work.stat().st_uid==os.getuid()and stat.S_IMODE(work.stat().st_mode)==0o700)
  for p in work.rglob('*'):
   n=p.relative_to(work).as_posix();require(not p.is_symlink()and(p.is_dir()or p.is_file()))
   if p.is_file():require(n in names)
 for n in sorted(names):
  p=work/n
  if not p.exists():continue
  try:
   cap=16*1024**2 if n.endswith('.log')else 4*1024**2 if n.endswith('.json')else 1024**2;data=raw(p,cap);require(total+len(data)<=16*1024**2 and record['bytes']+len(data)<=768*1024**2);q=target/n;q.parent.mkdir(parents=True,exist_ok=True)
   if q.exists():require(raw(q,cap)==data)
   else:q.write_bytes(data)
   key='retained-input-transport/'+n
   if key in record['files']:require(record['files'][key]==pin(data))
   else:record['files'][key]=pin(data);record['bytes']+=len(data)
   total+=len(data);copied.append(n)
  except BaseException as error:errors.append(dict(file=n,error_type=type(error).__name__))
 for source,n in((temporary/'core622-job-clock.json','job-clock.json'),(temporary/'core622-native-phase.json','native-phase.json')):
  if source.exists():
   try:
    data=raw(source,16384);require(record['bytes']+len(data)<=768*1024**2);q=target/n
    if q.exists():require(raw(q,16384)==data)
    else:q.write_bytes(data)
    key='retained-input-transport/'+n
    if key in record['files']:require(record['files'][key]==pin(data))
    else:record['files'][key]=pin(data);record['bytes']+=len(data)
    copied.append(n)
   except BaseException as error:errors.append(dict(file=n,error_type=type(error).__name__))
 record['early_retention']=dict(schema=1,status='BOUNDED_EARLY_TRANSPORT_DATA_ONLY',reason_type=reason,dependency_source='ADMISSION_OR_RETENTION_FAILED_NOT_CLASSIFIED',files=copied,errors=errors,first_transport_exception='UNKNOWN_UNLESS_RAW_PHASE_STDERR_IDENTIFIES_IT',native='NOT_RUN',native_scope='THIS_STDLIB_RETENTION_FALLBACK_ONLY',prior_job_native='NOT_INFERRED',native_cleanup='NOT_ESTABLISHED',acceptance=False);(public/'export.json').write_text(json.dumps(record,sort_keys=True,indent=2,allow_nan=False)+'\n');return record

def _retain_transport_or_early_data(public):
 try:
  _admit_closed_sibling_source();__import__('ownership622').retain_complete574_transport(public)
 except BaseException as error:return _retain_early_transport_data(public,type(error).__name__)

def transport(core,public,target):
 path=core/'scripts/ci/core-native-lifecycle/owner.py';sys.path.insert(0,str(path.parent));spec=importlib.util.spec_from_file_location('_core622_whole_original_transport',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module.transport(types.SimpleNamespace(public=public,output=target))

def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--public',type=Path,required=True);p.add_argument('--transport-only',action='store_true');p.add_argument('--core-source',type=Path);p.add_argument('--transport',type=Path);a=p.parse_args()
 if a.transport_only:need(a.core_source is not None and a.transport is not None,'explicit original transport source/output');return transport(a.core_source,a.public,a.transport)
 return copy(a.output,a.public,retained_transport=True)
if __name__=='__main__':raise SystemExit(main())
