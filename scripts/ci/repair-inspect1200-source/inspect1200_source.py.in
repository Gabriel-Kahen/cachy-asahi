# SPDX-License-Identifier: MIT
"""Explicit VM inspect validation AND complete unmodified239 source ancestry."""
import base64,contextlib,hashlib,io,json,runpy,stat,sys,tempfile,zlib
from pathlib import Path
PROFILE_SHA='ffcac836cbfc6ebc9fc43921c816a0b01d1b5b4a28eb37d66f4b30892f566110'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def read(path,cap=8*1024**2):
 need(not any(p.is_symlink()for p in(path,*path.parents))and path.is_file()and path.stat().st_nlink==1 and path.stat().st_size<=cap,'ordinary bounded single-link source');raw=path.read_bytes();need(len(raw)<=cap,'bounded source bytes');return raw
# SPDX-License-Identifier: MIT
"""Finite complete239 successor; every ordinary byte reconstructed by inverse."""
import base64,json
A='scripts/ci/apps7-full574-repair16k/adapter.py';VM='scripts/ci/apps7-full574-repair16k/vm.py';JOB='scripts/ci/apps7-full574-repair16k/job.py';SELECT='apps16-repair/selection.py';SUCCESSOR='apps16-repair/successor.json';HELPER='apps16-repair/inspect_validation.py';GUARD='apps16-repair/inspect1200_source.py';PROFILE='apps16-repair/inspect1200-profile.json'
MANIFESTS=('scripts/ci/apps7-full574-repair-native/source-manifest.json','scripts/ci/apps7-full574-repair16k/source-manifest.json','scripts/ci/apps7-full574-repair16k-ci/source-manifest.json')
WORKFLOWS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-apps7-full574-repair16k.yml')
OLDHOOK=" load(root/'apps16-repair/separated_source.py','_apps16_separated_input_source').prove(root)\n"
NEWHOOK=" load(root/'apps16-repair/inspect1200_source.py','_apps16_inspect1200_source').prove(root)\n"
WRAPPERS='''
# Explicit opt-in source profile. Every default method retains exact239 output.
def _inspect_profile_helper():
 import types
 m=types.ModuleType('_source_owned_inspect_profile');exec(compile(_INSPECT_VALIDATION_SOURCE,'<source-owned-inspect-profile>','exec'),vars(m));return m

def rendered_backend(source,*,inspect_profile=False):
 raw,ledger=_rendered_backend_original(source)
 if not inspect_profile:return raw,ledger
 m=_inspect_profile_helper();out=m.backend(raw,_INSPECT_VALIDATION_SOURCE);ledger=dict(ledger,owned_inspect_validation=dict(profile=m.PROFILE,backend_seconds=1200,caller_seconds=1210,parent_backend=pin(raw),derived_backend=pin(out),default_backend_seconds=600,default_caller_seconds=610,scope='EXACT_OWNED_COPY_INSPECT_ARGV_ONLY',old600_fit='NOT_ESTABLISHED',M2_performance='NOT_RUN'))
 return out,ledger

def lifecycle(raw,*,inspect_profile=False):
 out=_lifecycle_original(raw)
 return _inspect_profile_helper().lifecycle(out,_INSPECT_VALIDATION_SOURCE)if inspect_profile else out
'''
def one(raw,before,after):
 need(raw.count(before)==1,'one finite exact source seam: '+str(before)[:80]);out=raw.replace(before,after,1);need(out.replace(after,before,1)==raw,'whole finite source inverse');return out

def transformed(old,helper,guard,profile):
 need(len(old)==239,'entire exact239 parent');out=dict(old)
 a=one(old[A],b'def rendered_backend(source):',b'def _rendered_backend_original(source):');a=one(a,b'def lifecycle(raw):',b'def _lifecycle_original(raw):');a=one(a,b'def execution(source,output,manifest):',b'def execution(source,output,manifest,*,inspect_profile=False):');a=one(a,b'rendered,derivation=rendered_backend(source)',b'rendered,derivation=rendered_backend(source,inspect_profile=inspect_profile)');a=one(a,b"unchanged_functions='ALL_NATIVE_RENDERED_BACKEND_FUNCTIONS_EXCEPT_ENVIRONMENT_AND_EXPLICIT_READONLY_INVENTORY_BINDING'",b"unchanged_functions=('ALL_PARENT_RUNTIME_BODIES_HELD_EXCEPT_TYPED_INSPECT_PARSER_AND_SELECTED_BUDGET_WRAPPER'if inspect_profile else'ALL_NATIVE_RENDERED_BACKEND_FUNCTIONS_EXCEPT_ENVIRONMENT_AND_EXPLICIT_READONLY_INVENTORY_BINDING')")
 out[A]=a+b'\n_INSPECT_VALIDATION_SOURCE='+repr(helper.decode()).encode()+b'\n'+WRAPPERS.encode()
 out[VM]=one(old[VM],b'adaptation=adapter.execution(root,execution,manifest)',b'adaptation=adapter.execution(root,execution,manifest,inspect_profile=True)');out[VM]=one(out[VM],b'derived=adapter.lifecycle(raw)',b'derived=adapter.lifecycle(raw,inspect_profile=True)');out[VM]=one(out[VM],b"case_body='UNCHANGED'",b"case_body='UNCHANGED',owned_inspect_validation=dict(profile='REPAIR_GENERIC16K_OWNED_INSPECT_VALIDATION_1200_V1',backend_seconds=1200,caller_seconds=1210,added_function='_tcg_owned_inspect_call',default_route_retained=True)")
 # The selected export changes one exact routing seam after whole native retain
 # derivation. Its original body and all other packet references stay accessible.
 out[JOB]=one(old[JOB],b' J=native_job(args.source,native);original=J.derived\n',b" J=native_job(args.source,native);original=J.derived\n J.H._inspect_validation=C.load('selected_inspect_validation',args.source/'apps16-repair/inspect_validation.py')\n")
 out[JOB]=one(out[JOB],b"parts['actor']=actor_body(parts['actor']);return parts",b"parts['actor']=actor_body(parts['actor']);parts['retain']=J.H._inspect_validation.retention(parts['retain'],selected=True);return parts")
 out[SELECT]=one(old[SELECT],OLDHOOK.encode(),NEWHOOK.encode());out[HELPER]=helper;out[GUARD]=guard;out[PROFILE]=profile
 s=json.loads(old[SUCCESSOR])
 for n in(VM,JOB):
  need(n not in s['before_bodies']and pin(old[n])==s['before'][n],'previously held original235 operand');s['before_bodies'][n]=base64.b64encode(old[n]).decode()
 s['after']={n:pin(v)for n,v in sorted(out.items())if n not in s['excluded_seals']};out[SUCCESSOR]=enc(s)
 for name in MANIFESTS:
  m=json.loads(old[name]);m['files']={n:pin(out[n])for n in sorted(set(m['files'])|{HELPER,GUARD,PROFILE})};out[name]=enc(m)
 before=pin(old[MANIFESTS[-1]])['sha256'].encode();after=pin(out[MANIFESTS[-1]])['sha256'].encode()
 for name in WORKFLOWS:out[name]=one(old[name],before,after)
 need(set(out)-set(old)=={HELPER,GUARD,PROFILE}and len(out)==242,'honest complete242 source namespace')
 return out
def profile(root):
 raw=read(root/PROFILE);need(pin(raw)['sha256']==PROFILE_SHA,'whole fixed inspect1200 profile');p=json.loads(raw);need(all(p[n]is None for n in('source','ref','run','actual')),'no invented current authority')
 need(pin(read(root/GUARD).replace(PROFILE_SHA.encode(),b'PROFILE_SHA_PLACEHOLDER'))==p['guard_template'],'entire current guard self-template')
 need(len(p['before'])==239 and p['before']==p['parent_authorization']['files']==p['parent_git']['files'],'complete239 authorization/Git namespace')
 pub=p['parent_publication'];need(pub['source']=='cd89f189f373dd5cc86450a7f07d0a1369238993'and pub['files']==pub['git_joins']==239,'exact genuine239 public source')
 need(p['budget']==dict(profile='REPAIR_GENERIC16K_OWNED_INSPECT_VALIDATION_1200_V1',backend=1200,caller=1210,default_backend=600,default_caller=610,output_limit=1048576,old600_fit='NOT_ESTABLISHED',new1200_fit='NOT_ESTABLISHED',M2_performance='NOT_RUN'),'explicit finite VM validation profile only')
 post=json.loads(base64.b64decode(p['cause']['post_base64'],validate=True));need(pin(enc(post))==p['cause']['post']and post['status']=='PASS_SOURCE239_GIT_READER994_ONCE8_PUBLIC481_FAILURE_CUSTODY_ONLY'and post['source']==pub['source']and post['run']==40190029771 and post['cleanup_authority']is False,'qualified original failure custody, no cleanup authority')
 frame=json.loads(base64.b64decode(p['cause']['frame_base64'],validate=True));need(frame['role']=='OWNED_COPY_INSPECT'and frame['source']==pub['source']and frame['run']==40190029771 and frame['source_argv_sha256']=='2944386c2012b81e55be33068d1a894dc8b11538945d49a4c759c2ec273b1e6e'and frame['supervisor']['time_limit']==610 and frame['supervisor']['exit_code']==1 and frame['supervisor']['group_absence_verified']is True,'actual returned failure, never inferred backend or capability failure')
 for side in('stdout','stderr'):
  body=base64.b64decode(p['cause'][side+'_base64'],validate=True);need(pin(body)==dict(bytes=frame['supervisor'][side+'_bytes'],sha256=frame['supervisor'][side+'_sha256']),'entire authentic returned '+side)
 need(b'root observation deadline'in base64.b64decode(p['cause']['stderr_base64'],validate=True),'actual shared root observation deadline')
 return p

def bodies(root,p):
 old={}
 for name,w in p['before'].items():
  if name in p['before_bodies_zlib']:
   decoder=zlib.decompressobj();raw=decoder.decompress(base64.b64decode(p['before_bodies_zlib'][name],validate=True),8*1024**2+1);need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,'bounded complete before-body codec')
  else:raw=read(root/name)
  need(len(raw)<=8*1024**2 and pin(raw)==w,'entire exact239 body '+name);old[name]=raw
 return old

def old_entry(old,p):
 saved,path,argv=dict(sys.modules),sys.path[:],sys.argv[:];stems={Path(n).stem for n in old if n.endswith('.py')}
 try:
  for n in list(sys.modules):
   if n.split('.')[0]in stems:sys.modules.pop(n,None)
  with tempfile.TemporaryDirectory(prefix='inspect1200-whole239-')as tmp:
   root=Path(tmp)/'source';root.mkdir(mode=0o700)
   for n,b in old.items():q=root/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(b);q.chmod(p['before_modes'][n])
   sys.path.insert(0,str(root/'apps16-repair'));sys.argv=[str(root/'apps16-repair/entry.py'),'--source-only','--require-selection'];out=io.StringIO()
   with contextlib.redirect_stdout(out):runpy.run_path(sys.argv[0],run_name='__main__')
   v=json.loads(out.getvalue());need(v['status']=='SOURCE_ONLY_APPS16_REPAIR_REQUIRES_NEW_PAIR_AND_BOTH_NEW_CASES'and v['source_files']==239 and v['parent']==235 and v['original210']==210 and v['authority']is v['actual']is None,'complete original239 entry and every older gate required');return v
 finally:
  sys.path[:]=path;sys.argv[:]=argv
  for n in set(sys.modules)-set(saved):sys.modules.pop(n,None)
  sys.modules.update(saved)

def prove(root):
 root=Path(root);p=profile(root);old=bodies(root,p);actual={};dirs=set()
 for file in root.rglob('*'):
  relative=file.relative_to(root)
  if relative.parts[0]=='.git':continue
  need('.git'not in relative.parts,'nested Git administration is foreign source');s=file.lstat();need(stat.S_ISDIR(s.st_mode)or stat.S_ISREG(s.st_mode)and s.st_nlink==1,'closed ordinary single-link source')
  if stat.S_ISREG(s.st_mode):actual[relative.as_posix()]=read(file)
  else:dirs.add(relative.as_posix())
 need(set(actual)==set(old)|{HELPER,GUARD,PROFILE}and dirs=={q.as_posix()for n in actual for q in Path(n).parents if q.as_posix()!='.'},'closed exact242 namespace')
 need(actual==transformed(old,actual[HELPER],actual[GUARD],actual[PROFILE]),'entire current source with finite whole239 inverse')
 parent=old_entry(old,p)
 return dict(status='SOURCE_ONLY_OWNED_INSPECT1200_AND_EXACT_FOUR_ALIAS_EXPORTS',source_files=242,parent_source239=parent,profile=p['budget'],current_source=None,current_ref=None,current_run=None,actual=None,hardware='NOT_RUN',release='NOT_ADMITTED')
