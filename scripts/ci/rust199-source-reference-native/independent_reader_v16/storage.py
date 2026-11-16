# SPDX-License-Identifier: MIT
"""Independent bounded DATA reads; no producer/Source import or execution."""
import hashlib,json,os,re,stat,time
from pathlib import Path,PurePosixPath
MIB=1024**2;GIB=1024**3;END=None
class Hold(ValueError):pass
def need(ok,code):
 if not ok:raise Hold(code)
 if END is not None and time.monotonic()>END:raise Hold('READER_WALL_BOUND')
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def canonical(v):return(json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def decode(raw):
 def pairs(rows):
  value={}
  for key,item in rows:need(key not in value,'DUPLICATE_JSON_KEY');value[key]=item
  return value
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'NONFINITE_JSON'))
def digest(v):return type(v)is str and re.fullmatch('[0-9a-f]{64}',v)is not None
def numeric(v):return type(v)is str and re.fullmatch('[1-9][0-9]{0,19}',v)is not None
def relative(name):
 need(type(name)is str and len(name)<=512 and '\\'not in name,'UNSAFE_RELATIVE_PATH');p=PurePosixPath(name)
 need(not p.is_absolute()and str(p)==name and all(re.fullmatch('[A-Za-z0-9._+-]+',x)and x not in('.','..')for x in p.parts),'UNSAFE_RELATIVE_PATH');return name
def identity(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns'))
def opened(path,cap):
 p=Path(path);need(p.is_absolute()and p==p.resolve()and not any(q.is_symlink()for q in(p,*p.parents)),'NONCANONICAL_OR_ALIAS_INPUT')
 fd=os.open(p,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW|os.O_CLOEXEC);before=os.fstat(fd)
 try:need(stat.S_ISREG(before.st_mode)and before.st_nlink==1 and 0<=before.st_size<=cap,'INPUT_KIND_LINK_OR_SIZE')
 except BaseException:os.close(fd);raise
 return p,fd,before
def hashed(path,cap):
 p,fd,before=opened(path,cap);h=hashlib.sha256();size=0
 try:
  while block:=os.read(fd,MIB):size+=len(block);need(size<=cap,'INPUT_BYTE_BOUND');h.update(block)
  need(size==before.st_size and identity(before)==identity(os.fstat(fd))==identity(p.lstat()),'INPUT_CHANGED')
  return dict(bytes=size,sha256=h.hexdigest())
 finally:os.close(fd)
def read(path,cap=8*MIB):
 p,fd,before=opened(path,cap)
 try:
  raw=b''
  while block:=os.read(fd,min(MIB,cap+1-len(raw))):raw+=block;need(len(raw)<=cap,'INPUT_BYTE_BOUND')
  need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(p.lstat()),'INPUT_CHANGED');return raw
 finally:os.close(fd)
def git_tree(files):
 def oid(kind,raw):return hashlib.sha1(kind+b' '+str(len(raw)).encode()+b'\0'+raw).digest()
 def walk(prefix):
  names={n[len(prefix):].split('/')[0]for n in files if n.startswith(prefix)};out=[]
  for n in names:
   full=prefix+n
   if full in files:raw,mode=files[full];bits=b'100755'if mode==0o755 else b'100644';value=oid(b'blob',raw);key=n.encode()
   else:bits=b'40000';value=walk(full+'/');key=(n+'/').encode()
   out.append((key,bits+b' '+n.encode()+b'\0'+value))
  return oid(b'tree',b''.join(v for k,v in sorted(out)))
 return walk('').hex()
def namespace(root,maximum=2048):
 root=Path(root);need(root.is_absolute()and root==root.resolve()and not any(p.is_symlink()for p in(root,*root.parents)),'ROOT_ALIAS');files=set();dirs=set();count=0
 for p in root.rglob('*'):
  count+=1;need(count<=maximum*4,'NAMESPACE_NODE_BOUND');name=p.relative_to(root).as_posix();relative(name);info=p.lstat();need(not p.is_symlink(),'NAMESPACE_ALIAS')
  if stat.S_ISDIR(info.st_mode):dirs.add(name)
  else:need(stat.S_ISREG(info.st_mode)and info.st_nlink==1,'NAMESPACE_SPECIAL_OR_HARDLINK');files.add(name);need(len(files)<=maximum,'NAMESPACE_FILE_BOUND')
 need(dirs=={str(p)for n in files for p in Path(n).parents if str(p)!='.'},'EMPTY_OR_UNLISTED_DIRECTORY');return files
SOURCE=dict(files=364,bytes=43652864,tree='305db479cf93b6abfd441311fb66db047230530e',map_sha256='bd1d5d61836ee3284142884d22cf0f80ccb5d6c285dd8ca4b218708db2551406',profile_sha256='b28534a107661ccb790efc9d213eaf975c471d02c14dbd45fc801d3ba2b75e68')
SOURCE_MAP_BYTES=70343
def source(root,profile_raw,selected):
 need(all(v is not None for v in SOURCE.values()),'SOURCE16_CONTRACT_UNPINNED')
 need(selected==SOURCE and pin(profile_raw)['sha256']==SOURCE['profile_sha256'],'EXTERNAL_SOURCE_PROFILE_PIN');profile=decode(profile_raw)
 need(type(profile['schema'])is int and profile['schema']==16 and profile['scope']=='RUST199_POST_RETIREMENT_REPORT_GUARD_SUCCESSOR_V16'and profile['Root_review']is profile['accepted']is None and profile['unadmitted']is True and all(profile[k]==SOURCE[k]for k in('files','bytes','tree','map_sha256'))and all(v is None for v in profile['actual'].values()),'SOURCE_PROFILE_SCOPE')
 root=Path(root);names=namespace(root,364);raw=read(root/'source-map.json',MIB);need(pin(raw)==dict(bytes=SOURCE_MAP_BYTES,sha256=SOURCE['map_sha256']),'SOURCE_MAP_PIN');m=decode(raw)
 need(m['schema']==1 and m['operation']=='rust199-source-reference-native-v1'and all(v is None for v in m['actual'].values())and names==set(m['files'])|{'source-map.json'},'SOURCE_DECLARATIONS_NAMESPACE')
 files={}
 for name in sorted(names):
  body=read(root/name,64*MIB);mode=stat.S_IMODE((root/name).stat().st_mode);need(mode==0o644,'SOURCE_MODE')
  if name!='source-map.json':need(dict(pin(body),mode=mode)==m['files'][name],'SOURCE_WHOLE_BODY')
  files[name]=(body,mode)
 need(len(files)==364 and sum(len(v[0])for v in files.values())==SOURCE['bytes']and git_tree(files)==SOURCE['tree'],'SOURCE_WHOLE_TREE')
 need(decode(files['contract.json'][0])['holds']['source_payload_license_completeness']=='HELD; all existing license108 and related holds preserved','HISTORICAL_LICENSE_HOLDS')
 source_inverse(files)
 workspace_cleanup_source(files['hosted/owned_dir.py'][0])
 qualification_callback_source(files['hosted/qualification.py'][0],files['previous-v15/hosted/qualification.py'][0])
 return files

PARENT=dict(files=340,bytes=42985162,tree='596fe9277740365fa3e29ee11f2b75ae7ce8bbc8',map_sha256='3974a68677faadf1136f21539b595f3f0da85fa26bd72eb8d0fa8c6e922894f1')
def source_parent_inverse(files):
 marker='mount-default-cid-custody-v12.json';archive='previous-v11/';changed={'hosted/producer.py','hosted/qualification.py'}
 m=decode(files[marker][0]);actual=dict.fromkeys(('source','ref','run','job','approval','artifact','image'))
 need(m['schema']==12 and m['scope']=='RUST199_MOUNT_DEFAULT_CID_CUSTODY_SUCCESSOR_V12' and m['parent']==PARENT and m['actual']==actual and m['Root_grants']is None and m['dispatch']is None and m['unadmitted']is True and m['holds_preserved']is True,'SOURCE344_UNISSUED_INVERSE_SCOPE')
 need(all(m[k]is True for k in('empty_driverconfig_only','acknowledged_cid_before_validation','cleanup_requires_owned_identity')) and all(m[k]is False for k in('resources_changed','recipe_changed','workflows_changed','metadata_headers_changed','carrier_transport_changed','metadata_normalization_changed','request_bounds_changed')),'SOURCE344_FINITE_CHANGE_SCOPE')
 extra={marker}|{archive+n for n in changed|{'source-map.json'}};old_raw,mode=files[archive+'source-map.json'];old=decode(old_raw)
 need(pin(old_raw)==dict(bytes=66248,sha256=PARENT['map_sha256']) and mode==0o644 and set(files)==set(old['files'])|{'source-map.json'}|extra and set(m['changes'])==changed and m['archives']==sorted(archive+n for n in changed|{'source-map.json'}),'SOURCE344_EXACT_ARCHIVED340_NAMESPACE')
 restored={n:r for n,r in files.items()if n not in extra}
 for n in changed:
  body,mode=files[n];before,bmode=files[archive+n]
  need(dict(pin(body),mode=mode)==m['changes'][n]['after'] and dict(pin(before),mode=bmode)==m['changes'][n]['before'],'SOURCE344_REPLACEMENT_INVERSE_JOIN');restored[n]=(before,bmode)
 restored['source-map.json']=(old_raw,0o644)
 need(old['actual']==actual and old['files']=={n:dict(pin(b),mode=m)for n,(b,m)in restored.items()if n!='source-map.json'} and len(restored)==PARENT['files'] and sum(len(b)for b,m in restored.values())==PARENT['bytes'] and git_tree(restored)==PARENT['tree'],'SOURCE344_FULL_SOURCE340_INVERSE')
 return PARENT

PARENT344=dict(files=344,bytes=43106281,tree='3f470539f51c0bdbc9fdcb52e0657834310c9e63',map_sha256='8a2f52bb029181c3b547a09f07e4839ce0a58dd40d01c20b2cfd396af1401ec4')
def source351_inverse(files):
 marker='kernel-mount-preentry-v13.json';archive='previous-v12/'
 replaced={'actor/entry.py','actor/qualify.py','hosted/producer.py','hosted/qualification.py'};added={'actor/mount_proof.py'}
 m=decode(files[marker][0]);actual=dict.fromkeys(('source','ref','run','job','approval','artifact','image'))
 keys={'Root_grants','actual','api_subpath_is_not_kernel_proof','archives','carrier_transport_changed','changes','dispatch','holds_preserved','kernel_preentry_required','metadata_headers_changed','metadata_normalization_changed','parent','recipe_changed','request_bounds_changed','resources_changed','schema','scope','source_enforced_order','unadmitted','workflows_changed'}
 need(set(m)==keys and type(m['schema'])is int and m['schema']==13 and m['scope']=='RUST199_KERNEL_MOUNT_PREENTRY_SUCCESSOR_V13'and m['parent']==PARENT344 and m['actual']==actual and m['Root_grants']is m['dispatch']is None and m['unadmitted']is m['holds_preserved']is True,'SOURCE351_UNISSUED_INVERSE_SCOPE')
 need(all(m[k]is True for k in('api_subpath_is_not_kernel_proof','kernel_preentry_required','source_enforced_order'))and all(m[k]is False for k in('carrier_transport_changed','metadata_headers_changed','metadata_normalization_changed','recipe_changed','request_bounds_changed','resources_changed','workflows_changed')),'SOURCE351_FINITE_CHANGE_SCOPE')
 extra={marker}|added|{archive+n for n in replaced|{'source-map.json'}};old_raw,old_mode=files[archive+'source-map.json'];old=decode(old_raw)
 need(pin(old_raw)==dict(bytes=66940,sha256=PARENT344['map_sha256'])and old_mode==0o644 and set(files)==set(old['files'])|{'source-map.json'}|extra and set(m['changes'])==replaced|added and m['archives']==sorted(archive+n for n in replaced|{'source-map.json'}),'SOURCE351_EXACT_ARCHIVED344_NAMESPACE')
 current=decode(files['source-map.json'][0]);need(current['actual']==actual and current['files']=={n:dict(pin(b),mode=mode)for n,(b,mode)in files.items()if n!='source-map.json'},'SOURCE351_COMPLETE_CURRENT_MAP')
 restored={n:row for n,row in files.items()if n not in extra}
 for name in replaced|added:
  body,mode=files[name];need(m['changes'][name]['after']==dict(pin(body),mode=mode),'SOURCE351_EXACT_REPLACEMENT_AFTER')
  if name in added:need(m['changes'][name]['before']is None,'SOURCE351_ADDED_HELPER_NO_PARENT_SUBSTITUTE')
  else:
   before,before_mode=files[archive+name];need(m['changes'][name]['before']==dict(pin(before),mode=before_mode)==old['files'][name],'SOURCE351_EXACT_REPLACEMENT_BEFORE');restored[name]=(before,before_mode)
 restored['source-map.json']=(old_raw,old_mode)
 need(old['actual']==actual and old['files']=={n:dict(pin(b),mode=mode)for n,(b,mode)in restored.items()if n!='source-map.json'}and len(restored)==PARENT344['files']and sum(len(b)for b,mode in restored.values())==PARENT344['bytes']and git_tree(restored)==PARENT344['tree'],'SOURCE351_FULL_SOURCE344_INVERSE')
 source_parent_inverse(restored)
 return PARENT344

PARENT351=dict(files=351,bytes=43277113,tree='12fbd0fa35ab1c8e5a7c3cb9ab1d6d387ac57cc6',map_sha256='026e63a2bac7b65b26e5f74c0862f68cb73d2cf984b419f8e96b60f5d5f2dffe')
def source355_inverse(files):
 marker='owned-private-bind-v14.json';archive='previous-v13/';changed={'hosted/producer.py','hosted/qualification.py'}
 m=decode(files[marker][0]);actual=dict.fromkeys(('source','ref','run','job','approval','artifact','image'))
 keys={'Root_grants','actual','api_owned_private_bind_setup','archives','carrier_transport_changed','changes','dispatch','holds_preserved','kernel_preentry_required','metadata_headers_changed','metadata_normalization_changed','parent','recipe_changed','request_bounds_changed','resources_changed','schema','scope','source_enforced_order','unadmitted','workflows_changed'}
 need(set(m)==keys and type(m['schema'])is int and m['schema']==14 and m['scope']=='RUST199_API_OWNED_PRIVATE_BIND_SUCCESSOR_V14'and m['parent']==PARENT351 and m['actual']==actual and m['Root_grants']is m['dispatch']is None and m['unadmitted']is m['holds_preserved']is True,'SOURCE355_UNISSUED_INVERSE_SCOPE')
 need(all(m[k]is True for k in('api_owned_private_bind_setup','kernel_preentry_required','source_enforced_order'))and all(m[k]is False for k in('carrier_transport_changed','metadata_headers_changed','metadata_normalization_changed','recipe_changed','request_bounds_changed','resources_changed','workflows_changed')),'SOURCE355_FINITE_CHANGE_SCOPE')
 extra={marker}|{archive+n for n in changed|{'source-map.json'}};old_raw,old_mode=files[archive+'source-map.json'];old=decode(old_raw)
 need(pin(old_raw)==dict(bytes=68126,sha256=PARENT351['map_sha256'])and old_mode==0o644 and set(files)==set(old['files'])|{'source-map.json'}|extra and set(m['changes'])==changed and m['archives']==sorted(archive+n for n in changed|{'source-map.json'}),'SOURCE355_EXACT_ARCHIVED351_NAMESPACE')
 current=decode(files['source-map.json'][0]);need(current['actual']==actual and current['files']=={n:dict(pin(b),mode=mode)for n,(b,mode)in files.items()if n!='source-map.json'},'SOURCE355_COMPLETE_CURRENT_MAP')
 restored={n:row for n,row in files.items()if n not in extra}
 for name in changed:
  body,mode=files[name];before,before_mode=files[archive+name]
  need(m['changes'][name]['after']==dict(pin(body),mode=mode),'SOURCE355_EXACT_REPLACEMENT_AFTER')
  need(m['changes'][name]['before']==dict(pin(before),mode=before_mode)==old['files'][name],'SOURCE355_EXACT_REPLACEMENT_BEFORE');restored[name]=(before,before_mode)
 restored['source-map.json']=(old_raw,old_mode)
 need(old['actual']==actual and old['files']=={n:dict(pin(b),mode=mode)for n,(b,mode)in restored.items()if n!='source-map.json'}and len(restored)==PARENT351['files']and sum(len(b)for b,mode in restored.values())==PARENT351['bytes']and git_tree(restored)==PARENT351['tree'],'SOURCE355_FULL_SOURCE351_INVERSE')
 source351_inverse(restored)
 return PARENT351

PARENT355=dict(files=355,bytes=43408000,tree='3fbb71b78e06cdb9aa219c596a41fda3ccc29280',map_sha256='4a85015fbcb513f8af71ae0d313abc4927faa50682dbf0b6ebfee8f339352bfa')
def source361_inverse(files):
 marker='owned-job-directory-v15.json';archive='previous-v14/';replaced={'hosted/producer.py','hosted/qualification.py','hosted/volume.py'};added={'hosted/owned_dir.py'}
 m=decode(files[marker][0]);actual=dict.fromkeys(('source','ref','run','job','approval','artifact','image'))
 keys={'Root_grants','actual','external_owned_job_directory_setup','archives','carrier_transport_changed','changes','dispatch','holds_preserved','kernel_preentry_required','metadata_headers_changed','metadata_normalization_changed','parent','recipe_changed','request_bounds_changed','resources_changed','schema','scope','source_enforced_order','unadmitted','workflows_changed'}
 need(set(m)==keys and type(m['schema'])is int and m['schema']==15 and m['scope']=='RUST199_EXTERNAL_OWNED_JOB_DIRECTORY_SUCCESSOR_V15'and m['parent']==PARENT355 and m['actual']==actual and m['Root_grants']is m['dispatch']is None and m['unadmitted']is m['holds_preserved']is True,'SOURCE361_UNISSUED_INVERSE_SCOPE')
 need(all(m[k]is True for k in('external_owned_job_directory_setup','kernel_preentry_required','source_enforced_order'))and all(m[k]is False for k in('carrier_transport_changed','metadata_headers_changed','metadata_normalization_changed','recipe_changed','request_bounds_changed','resources_changed','workflows_changed')),'SOURCE361_FINITE_CHANGE_SCOPE')
 extra={marker}|added|{archive+n for n in replaced|{'source-map.json'}};old_raw,old_mode=files[archive+'source-map.json'];old=decode(old_raw)
 need(pin(old_raw)==dict(bytes=68811,sha256=PARENT355['map_sha256'])and old_mode==0o644 and set(files)==set(old['files'])|{'source-map.json'}|extra and set(m['changes'])==replaced|added and m['archives']==sorted(archive+n for n in replaced|{'source-map.json'}),'SOURCE361_EXACT_ARCHIVED355_NAMESPACE')
 current=decode(files['source-map.json'][0]);need(current['actual']==actual and current['files']=={n:dict(pin(b),mode=mode)for n,(b,mode)in files.items()if n!='source-map.json'},'SOURCE361_COMPLETE_CURRENT_MAP')
 restored={n:row for n,row in files.items()if n not in extra}
 for name in replaced|added:
  body,mode=files[name];need(m['changes'][name]['after']==dict(pin(body),mode=mode),'SOURCE361_EXACT_REPLACEMENT_AFTER')
  if name in added:need(m['changes'][name]['before']is None,'SOURCE361_ADDED_HELPER_NO_PARENT_SUBSTITUTE')
  else:
   before,before_mode=files[archive+name];need(m['changes'][name]['before']==dict(pin(before),mode=before_mode)==old['files'][name],'SOURCE361_EXACT_REPLACEMENT_BEFORE');restored[name]=(before,before_mode)
 restored['source-map.json']=(old_raw,old_mode)
 need(old['actual']==actual and old['files']=={n:dict(pin(b),mode=mode)for n,(b,mode)in restored.items()if n!='source-map.json'}and len(restored)==PARENT355['files']and sum(len(b)for b,mode in restored.values())==PARENT355['bytes']and git_tree(restored)==PARENT355['tree'],'SOURCE361_FULL_SOURCE355_INVERSE')
 source355_inverse(restored)
 return PARENT355

def workspace_cleanup_source(raw):
 """Audit fresh directory scan and two-pass retirement AST as inert Source DATA."""
 import ast
 need(type(raw)is bytes and 0<len(raw)<=64*1024,'CLEANUP_SOURCE_BODY_BOUND')
 try:tree=ast.parse(raw)
 except(SyntaxError,ValueError):raise Hold('CLEANUP_SOURCE_AST')
 def dump(node):return ast.dump(node,include_attributes=False)
 def parsed(text):return ast.parse(text).body[0]
 def call(node,name):return isinstance(node,ast.Call)and dump(node.func)==dump(ast.parse(name,mode='eval').body)
 def normalized(node):
  # Diagnostic text does not affect guard semantics.
  node=ast.parse(ast.unparse(node)).body[0]
  for part in ast.walk(node):
   if call(part,'need')and len(part.args)==2 and isinstance(part.args[1],ast.Constant)and type(part.args[1].value)is str:part.args[1]=ast.Constant('diagnostic')
  return dump(node)
 functions={n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
 need({'scan','empty'}<=set(functions),'CLEANUP_FRESH_SCAN_FUNCTIONS_REQUIRED')
 expected_scan=parsed("""@contextmanager
def scan(fd):
 before=os.fstat(fd)
 fresh=os.open('.',FLAGS,dir_fd=fd)
 try:
  need(stat.S_ISDIR(before.st_mode) and node(before)==node(os.fstat(fresh)) and mount_id(fd)==mount_id(fresh),'diagnostic')
  with os.scandir(fresh) as rows:
   yield rows
 finally:os.close(fresh)
""")
 need(normalized(functions['scan'])==normalized(expected_scan),'CLEANUP_FRESH_OPEN_IDENTITY_MOUNT_AND_FINALLY_CLOSE')
 expected_empty=parsed('def empty(fd):\n with scan(fd) as rows:\n  return next(rows,None) is None\n')
 need(dump(functions['empty'])==dump(expected_empty),'CLEANUP_EMPTINESS_USES_FRESH_SCAN')
 flags=[n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='FLAGS'for t in n.targets)]
 need(len(flags)==1 and dump(flags[0])==dump(parsed('FLAGS=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC')),'CLEANUP_FRESH_SCAN_DIRECTORY_NOFOLLOW_FLAGS')
 need(len([n for n in ast.walk(tree)if call(n,'os.scandir')])==1 and not any(call(n,f'os.{name}')for n in ast.walk(tree)for name in('listdir','dup','dup2','lseek')),'CLEANUP_NO_SHARED_CURSOR_OR_REWIND_SCAN')
 leases=[n for n in tree.body if isinstance(n,ast.ClassDef)and n.name=='Lease'];need(len(leases)==1,'CLEANUP_ONE_OWNED_LEASE')
 methods={n.name:n for n in leases[0].body if isinstance(n,ast.FunctionDef)}
 need({'__init__','retire'}<=set(methods),'CLEANUP_ALLOCATION_AND_RETIREMENT_REQUIRED')
 empties=[n for n in ast.walk(leases[0])if call(n,'empty')]
 need(len(empties)==3 and all(dump(n)==dump(ast.parse('empty(self.fd)',mode='eval').body)for n in empties),'CLEANUP_CREATION_ROLLBACK_TERMINAL_FRESH_EMPTINESS')
 body=methods['retire'].body
 need(len(body)==11 and isinstance(body[2],ast.FunctionDef)and body[2].name=='walk','CLEANUP_FINITE_TWO_PASS_RETIREMENT_BODY')
 expected=['self.check()','count=[0]',None,'walk(self.fd,0,False)','count[0]=0','walk(self.fd,0,True)','self.check()',None,'os.rmdir(self.path.name,dir_fd=self.rootfd)']
 need(all(text is None or dump(body[i])==dump(parsed(text))for i,text in enumerate(expected)),'CLEANUP_COMPLETE_PREFLIGHT_BEFORE_DELETION')
 need(isinstance(body[7],ast.Expr)and call(body[7].value,'need')and len(body[7].value.args)==2 and dump(body[7].value.args[0])==dump(ast.parse('empty(self.fd)',mode='eval').body),'CLEANUP_FRESH_TERMINAL_CHECK_BEFORE_ROOT_RMDIR')
 walk=body[2];scans=[n for n in ast.walk(walk)if isinstance(n,ast.With)]
 need(len(scans)==1 and len(scans[0].items)==1 and dump(scans[0].items[0])==dump(parsed('with scan(fd) as rows:\n pass').items[0]),'CLEANUP_EVERY_WALK_PASS_USES_FRESH_SCAN')
 mutations=[]
 def visit(node,guarded=False):
  if call(node,'os.unlink')or call(node,'os.rmdir'):mutations.append(guarded)
  if isinstance(node,ast.If)and dump(node.test)==dump(ast.Name(id='remove',ctx=ast.Load())):
   for child in node.body:visit(child,True)
   for child in node.orelse:visit(child,guarded)
  else:
   for child in ast.iter_child_nodes(node):visit(child,guarded)
 visit(walk)
 need(mutations==[True,True],'CLEANUP_PREFLIGHT_HAS_NO_UNGUARDED_MUTATION')
 return dict(scope='SOURCE_AST_FRESH_FD_SCAN_AND_TWO_PASS_RETIREMENT_ONLY',fresh_open=True,preflight_before_deletion=True,terminal_fresh_empty=True,Source_executed=False)

def qualification_callback_source(current,previous):
 """Check the minimal post-retirement callback change as inert Source AST."""
 import ast,copy
 need(all(type(raw)is bytes and 0<len(raw)<=64*1024 for raw in(current,previous)),'CALLBACK_SOURCE_BODY_BOUND')
 try:after,before=map(ast.parse,(current,previous))
 except(SyntaxError,ValueError):raise Hold('CALLBACK_SOURCE_AST')
 def dump(node):return ast.dump(node,include_attributes=False)
 def runs(tree):return [n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='run']
 need(len(runs(after))==len(runs(before))==1,'CALLBACK_ONE_QUALIFICATION_RUN')
 run=runs(after)[0];old=runs(before)[0]
 callbacks=[(i,n)for i,n in enumerate(run.body)if isinstance(n,ast.FunctionDef)and n.name=='report_tick']
 need(len(callbacks)==1,'CALLBACK_ONE_POST_RETIREMENT_GUARD');index,callback=callbacks[0]
 expected=ast.parse("""def report_tick():
 need(time.monotonic()<command.deadline,'qualification report global deadline')
 need(not command.cancelled[0],'qualification report cancellation')
 if command.on_tick is not None:command.on_tick()
""").body[0]
 need(dump(callback)==dump(expected),'CALLBACK_POST_RETIREMENT_GLOBAL_DEADLINE_CANCEL_OUTER_GUARD')
 need(index==len(run.body)-6 and index>=3 and isinstance(run.body[index-3],ast.Try)and run.body[index-3].finalbody and isinstance(run.body[index-2],ast.If),'CALLBACK_AFTER_CLEANUP_FAILURE_AND_STATUS_CHECKS')
 expected_status=ast.parse("need(report['status']=='PASS_NATIVE_SOURCE_QUALIFICATION_ONLY','qualification retirement failed')").body[0]
 expected_failure=ast.parse('if failure is not None:raise failure').body[0]
 need(dump(run.body[index-1])==dump(expected_status)and dump(run.body[index-2])==dump(expected_failure),'CALLBACK_ONLY_AFTER_SUCCESSFUL_RETIREMENT')
 hashes=[n for n in ast.walk(run.body[index+4])if isinstance(n,ast.Call)and isinstance(n.func,ast.Name)and n.func.id=='sha']
 need(len(hashes)==1 and dump(hashes[0])==dump(ast.parse('sha(path,report_tick)',mode='eval').body),'CALLBACK_FINAL_CONTROLLER_HASH_USES_REPORT_GUARD')
 uses=[n for n in ast.walk(run)if isinstance(n,ast.Name)and n.id=='report_tick']
 need(len(uses)==1,'CALLBACK_REPORT_GUARD_ONLY_FOR_FINAL_CONTROLLER_HASH')
 restored=copy.deepcopy(after);restored_run=runs(restored)[0];restored_run.body.pop(index)
 class Restore(ast.NodeTransformer):
  def visit_Call(self,node):
   if isinstance(node.func,ast.Name)and node.func.id=='sha'and len(node.args)==2 and isinstance(node.args[1],ast.Name)and node.args[1].id=='report_tick':node.args[1]=ast.Name(id='tick',ctx=ast.Load())
   return self.generic_visit(node)
 restored=Restore().visit(restored)
 need(dump(restored)==dump(before),'CALLBACK_ALL_ACTIVE_GUARDS_CLEANUP_AND_OTHER_SOURCE_AST_UNCHANGED')
 return dict(scope='SOURCE_AST_ACTIVE_WORKSPACE_AND_POST_RETIREMENT_REPORT_CALLBACK_PHASES_ONLY',active_workspace_guards_preserved=True,post_retirement_deadline=True,post_retirement_cancellation=True,restored_outer_guard=True,retired_workspace_recheck=False,Source_executed=False)

PARENT361=dict(files=361,bytes=43557462,tree='a5973bcc4cca083492e365c62e282d6f4f8075b8',map_sha256='ef172f129f2970abd5685a24621d9aab5e7854e522041896ecf3570aff4c95fb')
def source_inverse(files):
 marker='post-retirement-report-v16.json';archive='previous-v15/';changed={'hosted/qualification.py'}
 m=decode(files[marker][0]);actual=dict.fromkeys(('source','ref','run','job','approval','artifact','image'))
 keys={'Root_grants','actual','post_retirement_report_guard','archives','carrier_transport_changed','changes','dispatch','holds_preserved','kernel_preentry_required','metadata_headers_changed','metadata_normalization_changed','parent','recipe_changed','request_bounds_changed','resources_changed','schema','scope','source_enforced_order','unadmitted','workflows_changed'}
 need(set(m)==keys and type(m['schema'])is int and m['schema']==16 and m['scope']=='RUST199_POST_RETIREMENT_REPORT_GUARD_SUCCESSOR_V16'and m['parent']==PARENT361 and m['actual']==actual and m['Root_grants']is m['dispatch']is None and m['unadmitted']is m['holds_preserved']is True,'SOURCE364_UNISSUED_INVERSE_SCOPE')
 need(all(m[k]is True for k in('post_retirement_report_guard','kernel_preentry_required','source_enforced_order'))and all(m[k]is False for k in('carrier_transport_changed','metadata_headers_changed','metadata_normalization_changed','recipe_changed','request_bounds_changed','resources_changed','workflows_changed')),'SOURCE364_FINITE_CHANGE_SCOPE')
 extra={marker}|{archive+n for n in changed|{'source-map.json'}};old_raw,old_mode=files[archive+'source-map.json'];old=decode(old_raw)
 need(pin(old_raw)==dict(bytes=69826,sha256=PARENT361['map_sha256'])and old_mode==0o644 and set(files)==set(old['files'])|{'source-map.json'}|extra and set(m['changes'])==changed and m['archives']==sorted(archive+n for n in changed|{'source-map.json'}),'SOURCE364_EXACT_ARCHIVED361_NAMESPACE')
 current=decode(files['source-map.json'][0]);need(current['actual']==actual and current['files']=={n:dict(pin(b),mode=mode)for n,(b,mode)in files.items()if n!='source-map.json'},'SOURCE364_COMPLETE_CURRENT_MAP')
 restored={n:row for n,row in files.items()if n not in extra}
 for name in changed:
  body,mode=files[name];before,before_mode=files[archive+name]
  need(m['changes'][name]['after']==dict(pin(body),mode=mode),'SOURCE364_EXACT_REPLACEMENT_AFTER')
  need(m['changes'][name]['before']==dict(pin(before),mode=before_mode)==old['files'][name],'SOURCE364_EXACT_REPLACEMENT_BEFORE');restored[name]=(before,before_mode)
 restored['source-map.json']=(old_raw,old_mode)
 need(old['actual']==actual and old['files']=={n:dict(pin(b),mode=mode)for n,(b,mode)in restored.items()if n!='source-map.json'}and len(restored)==PARENT361['files']and sum(len(b)for b,mode in restored.values())==PARENT361['bytes']and git_tree(restored)==PARENT361['tree'],'SOURCE364_FULL_SOURCE361_INVERSE')
 source361_inverse(restored)
 return PARENT361
