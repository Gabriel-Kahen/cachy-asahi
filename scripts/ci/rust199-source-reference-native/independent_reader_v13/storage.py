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
SOURCE=dict(files=351,bytes=43277113,tree='12fbd0fa35ab1c8e5a7c3cb9ab1d6d387ac57cc6',map_sha256='026e63a2bac7b65b26e5f74c0862f68cb73d2cf984b419f8e96b60f5d5f2dffe',profile_sha256='aca60bb938304cc306bb8ef6c1e790d7b84f49cea4178beda75dad4c00938d2f')
def source(root,profile_raw,selected):
 need(all(v is not None for v in SOURCE.values()),'SOURCE13_CONTRACT_UNPINNED')
 need(selected==SOURCE and pin(profile_raw)['sha256']==SOURCE['profile_sha256'],'EXTERNAL_SOURCE_PROFILE_PIN');profile=decode(profile_raw)
 need(profile['schema']==13 and profile['scope']=='RUST199_KERNEL_MOUNT_PREENTRY_SUCCESSOR_V13'and profile['Root_review']is profile['accepted']is None and profile['unadmitted']is True and all(profile[k]==SOURCE[k]for k in('files','bytes','tree','map_sha256'))and all(v is None for v in profile['actual'].values()),'SOURCE_PROFILE_SCOPE')
 root=Path(root);names=namespace(root,351);raw=read(root/'source-map.json',MIB);need(pin(raw)==dict(bytes=68126,sha256=SOURCE['map_sha256']),'SOURCE_MAP_PIN');m=decode(raw)
 need(m['schema']==1 and m['operation']=='rust199-source-reference-native-v1'and all(v is None for v in m['actual'].values())and names==set(m['files'])|{'source-map.json'},'SOURCE_DECLARATIONS_NAMESPACE')
 files={}
 for name in sorted(names):
  body=read(root/name,64*MIB);mode=stat.S_IMODE((root/name).stat().st_mode);need(mode==0o644,'SOURCE_MODE')
  if name!='source-map.json':need(dict(pin(body),mode=mode)==m['files'][name],'SOURCE_WHOLE_BODY')
  files[name]=(body,mode)
 need(len(files)==351 and sum(len(v[0])for v in files.values())==SOURCE['bytes']and git_tree(files)==SOURCE['tree'],'SOURCE_WHOLE_TREE')
 need(decode(files['contract.json'][0])['holds']['source_payload_license_completeness']=='HELD; all existing license108 and related holds preserved','HISTORICAL_LICENSE_HOLDS')
 source_inverse(files)
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
def source_inverse(files):
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
