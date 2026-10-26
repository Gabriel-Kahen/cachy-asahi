# SPDX-License-Identifier: MIT
"""Private canonical relative fast path AND complete unmodified242 ancestry."""
import base64,contextlib,hashlib,io,json,runpy,stat,sys,tempfile,zlib
from pathlib import Path
PROFILE_SHA='89a0d49e0063e00eee4b036ec484e66f9aa0b4151c7f059a4c8fe4a0d986e206'
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def enc(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def read(path,cap=8*1024**2):
 need(not any(p.is_symlink()for p in(path,*path.parents))and path.is_file()and path.stat().st_nlink==1 and path.stat().st_size<=cap,'ordinary bounded single-link source');raw=path.read_bytes();need(len(raw)<=cap,'bounded source bytes');return raw
"""One private FRESH_QUERY installer dependency; complete242 inverse."""
import ast,json
A='scripts/ci/apps7-full574-repair16k/adapter.py';SELECT='apps16-repair/selection.py';SUCCESSOR='apps16-repair/successor.json';HELPER='apps16-repair/relative_query.py';GUARD='apps16-repair/relative_source.py';PROFILE='apps16-repair/relative-profile.json'
MANIFESTS=('scripts/ci/apps7-full574-repair-native/source-manifest.json','scripts/ci/apps7-full574-repair16k/source-manifest.json','scripts/ci/apps7-full574-repair16k-ci/source-manifest.json')
WORKFLOWS=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-apps7-full574-repair16k.yml')
OLDHOOK=" load(root/'apps16-repair/inspect1200_source.py','_apps16_inspect1200_source').prove(root)\n";NEWHOOK=" load(root/'apps16-repair/relative_source.py','_apps16_private_relative_source').prove(root)\n"
def one(raw,a,b):
 need(raw.count(a)==1,'one exact private relative seam');out=raw.replace(a,b,1);need(out.replace(b,a,1)==raw,'entire private relative inverse');return out

def fresh(before,helper):
 old=" facade=types.SimpleNamespace(**vars(roots));facade._mount_id=helper._mount600(roots._mount_id)\n facade.observe=clone(roots.observe,dict(roots.observe.__globals__,_mount_id=facade._mount_id))"
 new=" installer=_relative_query.bind_installer(root,roots.installer,read)\n facade=types.SimpleNamespace(**dict(vars(roots),installer=installer));facade._mount_id=helper._mount600(roots._mount_id)\n facade.observe=clone(roots.observe,dict(roots.observe.__globals__,_mount_id=facade._mount_id,installer=installer))"
 out=one(before,old,new);anchor='def query_api(root,roots,read):\n';setup="_relative_query=types.ModuleType('_private_repair_relative')\nexec(compile("+repr(helper.decode())+",'<private-repair-relative>','exec'),vars(_relative_query))\n"
 out=one(out,anchor,setup+anchor);need(out.replace(setup,'',1).replace(new,old,1)==before,'whole fresh query before body');return out

def transformed(old,helper,guard,profile):
 need(len(old)==242,'entire242 source required');out=dict(old);raw=old[A];node=next(n for n in ast.parse(raw).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='FRESH_QUERY'for t in n.targets));before=ast.literal_eval(node.value);literal=ast.get_source_segment(raw.decode(),node.value);out[A]=one(raw,literal.encode(),repr(fresh(before,helper)).encode());out[SELECT]=one(old[SELECT],OLDHOOK.encode(),NEWHOOK.encode());out.update({HELPER:helper,GUARD:guard,PROFILE:profile})
 note=json.loads(profile)['selected_failure_note'];raw=out['apps16-repair/inspect_validation.py']
 for a,b in note['edits']['edits']:raw=one(raw,a.encode(),b.encode())
 out['apps16-repair/inspect_validation.py']=raw+note['edits']['append'].encode()
 stderr=json.loads(profile)['stderr_capture'];raw=out['apps16-repair/inspect_validation.py']
 for a,b in stderr['helper_edits']:raw=one(raw,a.encode(),b.encode())
 out['apps16-repair/inspect_validation.py']=raw+stderr['helper_append'].encode()
 binding=json.loads(profile)['operative_binding'];out[A]=one(out[A],binding['literal_before'].encode(),repr(out['apps16-repair/inspect_validation.py'].decode()).encode())
 s=json.loads(old[SUCCESSOR]);s['after']={n:pin(b)for n,b in sorted(out.items())if n not in s['excluded_seals']};out[SUCCESSOR]=enc(s)
 for name in MANIFESTS:
  m=json.loads(old[name]);m['files']={n:pin(out[n])for n in sorted(set(m['files'])|{HELPER,GUARD,PROFILE})};out[name]=enc(m)
 for name in WORKFLOWS:out[name]=one(old[name],pin(old[MANIFESTS[-1]])['sha256'].encode(),pin(out[MANIFESTS[-1]])['sha256'].encode())
 need(len(out)==245 and set(out)-set(old)=={HELPER,GUARD,PROFILE},'closed245 private relative source');return out
def profile(root):
 raw=read(root/PROFILE);need(pin(raw)['sha256']==PROFILE_SHA,'whole fixed private relative profile');p=json.loads(raw)
 need(all(p[n]is None for n in('source','ref','run','actual')),'current authority remains NULL')
 need(pin(read(root/GUARD).replace(PROFILE_SHA.encode(),b'PROFILE_SHA_PLACEHOLDER'))==p['guard_template'],'complete relative guard self-template')
 need(len(p['before'])==242 and p['before']==p['authorization']['files']==p['git']['files']and p['publication']['source']=='a9b8df2297e8aa7db96c48e27002f4a37fbde123','whole exact published242 parent')
 need(pin(read(root/HELPER))==p['helper'],'whole private relative helper')
 need(p['scope']=='PRIVATE_FRESH_QUERY_CANONICAL_STR_ONLY_ORIGINAL_FALLBACK_NO_LIVE_CACHE'and p['native_hotspot']==p['deadline_fit']=='NOT_ESTABLISHED'and p['M2']=='NOT_RUN','no native performance or capacity grant')
 note=p['selected_failure_note'];need(note['source']=='9aacd99b10d2e52a49d5ef34b89d9ea8254af6b0'and note['before']==note['git']['files']==note['authorization']and note['publication']['source']==note['source']and len(note['before'])==245,'whole genuine published245 before source')
 need(note['scope']=='FAILURE_ONLY_TYPED_OPERANDS_COMPLETE_BUFFERS_NO_ACTUAL_ROW_OR_ACCEPTANCE'and all(note[k]is None for k in('current_source','current_ref','current_run','actual')),'current diagnostic source-only authority NULL')
 binding=p['operative_binding'];need(binding['source']=='1bc1b2bce249cca55beabbd6ee74208c1e1cb4ef'and binding['before']==binding['git']['files']==binding['authorization']and binding['publication']['source']==binding['source']and len(binding['before'])==245,'whole genuine selected-note245 parent')
 need(binding['scope']=='EXACT_OPERATIVE_INLINE_HELPER_EQUALS_EXTERNAL_NO_ALGORITHM_OR_CLOCK_CHANGE'and all(binding[k]is None for k in('current_source','current_ref','current_run','actual')),'operative binding remains source-only')
 stderr=p['stderr_capture'];need(stderr['source']=='3c19d667ed2e0873112a84e97b62b54626381435'and len(stderr['before'])==245 and stderr['before']==stderr['git']['files']and stderr['scope']=='SELECTED_ONLY_COMPLETE_ELIGIBLE8192_OR_TYPED_TAIL_CANONICAL_NOTE_1900_NO_AUTHORITY'and stderr['codec']=='ZLIB_DICT_BASE64_CANONICAL_ASCII_JSON_V1'and all(stderr[k]is None for k in('current_source','current_ref','current_run','actual')),'whole current245 stderr-source context and NULL actual')
 return p

def bodies(root,p):
 old={}
 for name,w in p['before'].items():
  if name in p['before_bodies_zlib']:
   decoder=zlib.decompressobj();raw=decoder.decompress(base64.b64decode(p['before_bodies_zlib'][name],validate=True),8*1024**2+1);need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,'bounded complete before-body codec')
  else:raw=read(root/name)
  need(len(raw)<=8*1024**2 and pin(raw)==w,'entire exact242 body '+name);old[name]=raw
 return old

def old_entry(old,p):
 saved,path,argv=dict(sys.modules),sys.path[:],sys.argv[:];stems={Path(n).stem for n in old if n.endswith('.py')}
 try:
  for n in list(sys.modules):
   if n.split('.')[0]in stems:sys.modules.pop(n,None)
  with tempfile.TemporaryDirectory(prefix='relative-whole242-')as tmp:
   root=Path(tmp)/'source';root.mkdir(mode=0o700)
   for n,b in old.items():q=root/n;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes(b);q.chmod(p['before_modes'][n])
   sys.path.insert(0,str(root/'apps16-repair'));sys.argv=[str(root/'apps16-repair/entry.py'),'--source-only','--require-selection'];out=io.StringIO()
   with contextlib.redirect_stdout(out):runpy.run_path(sys.argv[0],run_name='__main__')
   v=json.loads(out.getvalue());need(v['status']=='SOURCE_ONLY_APPS16_REPAIR_REQUIRES_NEW_PAIR_AND_BOTH_NEW_CASES'and v['source_files']==242 and v['parent']==235 and v['original210']==210 and v['authority']is v['actual']is None,'complete original242 entry and every older gate required');return v
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
 need(set(actual)==set(old)|{HELPER,GUARD,PROFILE}and dirs=={q.as_posix()for n in actual for q in Path(n).parents if q.as_posix()!='.'},'closed exact245 namespace')
 need(actual==transformed(old,actual[HELPER],actual[GUARD],actual[PROFILE]),'entire current source with finite whole242 inverse')
 dictionary=next(n.value for n in ast.parse(actual['apps16-repair/inspect_validation.py']).body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='NOTE_DICTIONARY'for t in n.targets));need(pin(ast.literal_eval(dictionary))==p['stderr_capture']['dictionary'],'independent whole fixed NOTE dictionary DATA pin')
 actual,p=stderr_before(actual,p)
 binding=p['operative_binding'];immediate={};literal=repr(actual['apps16-repair/inspect_validation.py'].decode()).encode()
 for n,w in binding['before'].items():
  if n==A:b=one(actual[n],literal,binding['literal_before'].encode())
  elif n==PROFILE:
   before_profile=dict(p);before_profile.pop('operative_binding');before_profile['guard_template']=binding['before_guard_template'];b=enc(before_profile)
  elif n==GUARD:
   text=actual[n].decode();current_sha=pin(actual[PROFILE])['sha256'];need(text.count(current_sha)==1,'one current guard seal');text=text.replace(current_sha,binding['before'][PROFILE]['sha256'],1)
   for before,after in reversed(binding['guard_edits']):need(text.count(after)==1,'one immediate guard before inverse');text=text.replace(after,before,1)
   b=text.encode()
  elif n==SUCCESSOR:
   v=json.loads(actual[n]);v['after']={k:binding['before'][k]for k in v['after']};b=enc(v)
  elif n in MANIFESTS:
   v=json.loads(actual[n]);v['files']={k:binding['before'][k]for k in v['files']};b=enc(v)
  elif n in WORKFLOWS:b=one(actual[n],pin(actual[MANIFESTS[-1]])['sha256'].encode(),binding['before'][MANIFESTS[-1]]['sha256'].encode())
  else:b=actual[n]
  need(pin(b)==w,'entire immediate selected-note245 before body '+n);immediate[n]=b
 need(immediate['apps16-repair/inspect_validation.py']==actual['apps16-repair/inspect_validation.py'],'external note algorithm byte-held')
 note=p['selected_failure_note'];parent245={}
 for n,w in note['before'].items():
  if n==SUCCESSOR:
   s=json.loads(actual[n]);need(note['derived_successor_before']=='EXACT_AFTER_MAP_RESTORED_FROM_WHOLE_BEFORE245','finite original successor seal inverse');s['after']={k:note['before'][k]for k in s['after']};b=enc(s)
  elif n==A:b=immediate[n]
  elif n in note['before_bodies_zlib']:
   d=zlib.decompressobj();b=d.decompress(base64.b64decode(note['before_bodies_zlib'][n],validate=True),8*1024**2+1);need(d.eof and not d.unused_data and not d.unconsumed_tail,'bounded complete245 before codec')
  else:b=actual[n]
  need(pin(b)==w,'entire published245 before body '+n);parent245[n]=b
 oldp=json.loads(parent245[PROFILE]);oldg=parent245[GUARD];oldsha=pin(parent245[PROFILE])['sha256'];need(pin(oldg.replace(oldsha.encode(),b'PROFILE_SHA_PLACEHOLDER'))==oldp['guard_template']and oldp['before']==p['before'],'entire old245 guard selfseal and242 ancestor held')
 parent=old_entry(old,p)
 return dict(status='SOURCE_ONLY_PRIVATE_CANONICAL_RELATIVE_EQUIVALENT',source_files=245,parent_source242=parent,profile=p['scope'],current_source=None,current_ref=None,current_run=None,actual=None,hardware='NOT_RUN',release='NOT_ADMITTED',selected_failure_note='SOURCE_PROJECTED_NOT_EXPORTED_COMMAND_ROW_NO_AUTHORITY')


def stderr_before(actual,p):
 s=p['stderr_capture'];prior=dict(p);prior.pop('stderr_capture');prior['guard_template']=s['before_guard_template'];before={}
 for n,w in s['before'].items():
  if n=='apps16-repair/inspect_validation.py':
   b=actual[n];tail=s['helper_append'].encode();need(b.endswith(tail)and tail,'one complete selected stderr codec footer');b=b[:-len(tail)]
   for a,new in reversed(s['helper_edits']):b=one(b,new.encode(),a.encode())
  elif n==A:b=one(actual[n],repr(actual['apps16-repair/inspect_validation.py'].decode()).encode(),s['literal_before'].encode())
  elif n==PROFILE:b=enc(prior)
  elif n==GUARD:
   b=one(actual[n],pin(actual[PROFILE])['sha256'].encode(),s['before'][PROFILE]['sha256'].encode());tail=s['guard_append'].encode();need(b.endswith(tail)and tail,'whole stderr guard footer inverse');b=b[:-len(tail)]
   for a,new in reversed(s['guard_edits']):b=one(b,new.encode(),a.encode())
  elif n==SUCCESSOR:
   v=json.loads(actual[n]);v['after']={k:s['before'][k]for k in v['after']};b=enc(v)
  elif n in MANIFESTS:
   v=json.loads(actual[n]);v['files']={k:s['before'][k]for k in v['files']};b=enc(v)
  elif n in WORKFLOWS:b=one(actual[n],pin(actual[MANIFESTS[-1]])['sha256'].encode(),s['before'][MANIFESTS[-1]]['sha256'].encode())
  else:b=actual[n]
  need(pin(b)==w,'whole operative3c19 current245 source inverse '+n);before[n]=b
 need(len(before)==245 and pin(before[GUARD].replace(s['before'][PROFILE]['sha256'].encode(),b'PROFILE_SHA_PLACEHOLDER'))==prior['guard_template'],'entire prior245 guard/self-template')
 return before,prior
