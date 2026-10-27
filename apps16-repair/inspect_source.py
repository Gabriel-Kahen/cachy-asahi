# SPDX-License-Identifier: MIT
"""Fixed inspect failure DATA: exact old235 entry AND complete new source."""
import ast,base64,contextlib,hashlib,io,json,runpy,stat,sys,tempfile,zlib
from pathlib import Path
PROFILE_SHA='4d190cdb03ec51991787572d81005d898b8afb94fb1777cbbf8553ffb047e578'
PROFILE='apps16-repair/inspect-profile.json'
GUARD='apps16-repair/inspect_source.py'
ADAPTER='scripts/ci/apps7-full574-repair16k/adapter.py'
SELECTION='apps16-repair/selection.py'
SUCCESSOR='apps16-repair/successor.json'
MANIFESTS=('scripts/ci/apps7-full574-repair-native/source-manifest.json','scripts/ci/apps7-full574-repair16k/source-manifest.json','scripts/ci/apps7-full574-repair16k-ci/source-manifest.json')
WORKFLOWS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-apps7-full574-repair16k.yml')
HOOK=" load(root/'apps16-repair/inspect_source.py','_apps16_fixed_inspect_source').prove(root)\n"

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def read(path,limit=8*1024**2):
 need(path.is_file()and not path.is_symlink()and path.stat().st_nlink==1,'ordinary single-link source file required');raw=path.read_bytes();need(len(raw)<=limit,'source input bound');return raw

def profile(root):
 raw=read(root/PROFILE,4*1024**2);need(pin(raw)['sha256']==PROFILE_SHA,'whole fixed inspect profile');p=json.loads(raw)
 need(p['actual']==p['source']==p['ref']==p['run']==None,'no current actual/publication authority')
 template=read(root/GUARD).replace(PROFILE_SHA.encode(),b'PROFILE_SHA_PLACEHOLDER')
 need(pin(template)==p['guard_template'],'whole source guard self-template')
 need(len(p['before'])==235 and p['before']==p['parent_authorization']==p['parent_git']['files'],'whole235 authorization/Git join')
 pub=p['parent_publication'];need(pub['source']=='ac1df3c2b1859f97534d1db5064d51472b18567c'and pub['ref']=='codex/apps16-repair16k-v1'and pub['files']==pub['git_joins']==235,'genuine source235 publication')
 return p

# This literal is replaced from the equally pinned author transform before emission.
NAME='BACKEND_NOTE'
CALL="""  try:
   if len(captured)==1:
    inspect_note=types.ModuleType('_vm_fixed_inspect_note')
    exec(compile(_VM_INSPECT_NOTE_SOURCE,'<source-owned-fixed-inspect-note>','exec'),vars(inspect_note))
    if inspect_note.role(argv,seconds,expected) and captured[0][0]['argv']==argv:
     note=inspect_note.note(*captured[0],expected=expected)
     if note is not None:error.add_note(note)
  except BaseException:pass # Optional DATA cannot replace the original failure.
"""
def assignment(raw):
 text=raw.decode();tree=ast.parse(text);nodes=[n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id==NAME for t in n.targets)]
 if len(nodes)!=1:raise ValueError('one whole BACKEND_NOTE source constant')
 return text,nodes[0],ast.literal_eval(nodes[0].value)
def derivative(raw,helper):
 text,node,old=assignment(raw);anchor='  raise\n finally:self.api=original\nH.Calls.call=_vm_backend_call\n'
 if old.count(anchor)!=1:raise ValueError('one exact unchanged exception/restore boundary')
 prefix='_VM_INSPECT_NOTE_SOURCE='+repr(helper.decode())+'\n'
 note=prefix+old.replace(anchor,CALL+anchor,1)
 if note.removeprefix(prefix).replace(CALL,'',1)!=old:raise ValueError('whole original backend note inverse')
 lines=text.splitlines(keepends=True);start=sum(map(len,lines[:node.lineno-1]));end=sum(map(len,lines[:node.end_lineno]));new=text[:start]+'BACKEND_NOTE = '+repr(note)+'\n'+text[end:]
 before=ast.parse(text);after=ast.parse(new)
 for a,b in zip(before.body,after.body):
  if isinstance(a,ast.Assign)and any(isinstance(t,ast.Name)and t.id==NAME for t in a.targets):continue
  if ast.dump(a,include_attributes=False)!=ast.dump(b,include_attributes=False):raise ValueError('all other adapter AST bodies held')
 compile(new,'adapter.py','exec');return new.encode()


def transformed(old,p,guard,profile_raw):
 """Rebuild every permitted change; no exempt derived hash or runtime waiver."""
 out=dict(old);out[ADAPTER]=derivative(old[ADAPTER],p['helper_source'].encode())
 anchor=' return p,bodies\n';need(old[SELECTION].count(anchor.encode())==1,'one source-only mandatory gate boundary')
 out[SELECTION]=old[SELECTION].replace(anchor.encode(),(HOOK+anchor).encode(),1)
 need(out[SELECTION].replace(HOOK.encode(),b'',1)==old[SELECTION],'whole selection inverse')
 out[GUARD]=guard;out[PROFILE]=profile_raw
 s=json.loads(old[SUCCESSOR]);s['after']={n:pin(v)for n,v in sorted(out.items())if n not in s['excluded_seals']};out[SUCCESSOR]=encoded(s)
 for name in MANIFESTS:
  m=json.loads(old[name]);names=set(m['files'])|{GUARD,PROFILE};m['files']={n:pin(out[n])for n in sorted(names)};out[name]=encoded(m)
 oldsha=pin(old[MANIFESTS[-1]])['sha256'].encode();newsha=pin(out[MANIFESTS[-1]])['sha256'].encode()
 for name in WORKFLOWS:
  need(old[name].count(oldsha)==1,'one exact CI source-manifest workflow seal');out[name]=old[name].replace(oldsha,newsha,1)
 need(set(out)-set(old)=={GUARD,PROFILE}and len(out)==237,'whole237 source namespace')
 return out

def bodies(root,p):
 old={}
 for name,row in p['before'].items():
  if name in p['before_bodies_zlib']:
   data=zlib.decompressobj();raw=data.decompress(base64.b64decode(p['before_bodies_zlib'][name],validate=True),8*1024**2+1)
   need(data.eof and not data.unused_data and not data.unconsumed_tail,'bounded complete inverse codec')
  else:raw=read(root/name)
  need(pin(raw)==row,'whole original235 body: '+name);old[name]=raw
 return old

def old_entry(old,p):
 """Run the actual held source-only entry, restoring the entire import context."""
 saved,path,argv=dict(sys.modules),sys.path[:],sys.argv[:]
 stems={Path(n).stem for n in old if n.endswith('.py')}
 try:
  for name in list(sys.modules):
   if name.split('.')[0]in stems:sys.modules.pop(name,None)
  with tempfile.TemporaryDirectory(prefix='fixed-inspect-held235-')as tmp:
   root=Path(tmp)/'source';root.mkdir(mode=0o700)
   for name,raw in old.items():
    file=root/name;file.parent.mkdir(parents=True,exist_ok=True);file.write_bytes(raw);file.chmod(p['before_modes'][name])
   sys.path.insert(0,str(root/'apps16-repair'));sys.argv=[str(root/'apps16-repair/entry.py'),'--source-only','--require-selection'];capture=io.StringIO()
   with contextlib.redirect_stdout(capture):runpy.run_path(sys.argv[0],run_name='__main__')
   result=json.loads(capture.getvalue());need(result['status']=='SOURCE_ONLY_APPS16_REPAIR_REQUIRES_NEW_PAIR_AND_BOTH_NEW_CASES'and result['parent']==235 and result['original210']==210 and result['source_files']==235 and result['authority']is None and result['actual']is None,'entire old235 source entry required')
   return result
 finally:
  sys.path[:]=path;sys.argv[:]=argv
  for name in set(sys.modules)-set(saved):sys.modules.pop(name,None)
  sys.modules.update(saved)

def prove(root):
 root=Path(root);p=profile(root);old=bodies(root,p)
 actual={}
 for file in root.rglob('*'):
  relative=file.relative_to(root)
  if relative.parts[0]=='.git':continue # Top-level checkout administration only.
  need('.git'not in relative.parts,'nested Git administration is foreign source')
  need(not file.is_symlink(),'closed source refuses symlinks')
  if file.is_file():
   name=file.relative_to(root).as_posix();need(name in p['before']or name in(GUARD,PROFILE),'closed237 source file set');actual[name]=read(file)
 need(set(actual)==set(p['before'])|{GUARD,PROFILE},'closed237 source file set')
 expected=transformed(old,p,actual[GUARD],actual[PROFILE]);need(actual==expected,'complete fixed-inspect source emission')
 parent=old_entry(old,p)
 return dict(status='SOURCE_ONLY_FIXED_INSPECT_RETURNED_FAILURE_DATA',source_files=237,parent_source235=parent,current_source=None,current_ref=None,current_run=None,actual=None,hardware='NOT_RUN',release='NOT_ADMITTED')
