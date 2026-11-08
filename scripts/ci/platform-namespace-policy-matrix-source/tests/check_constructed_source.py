#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent stdlib DATA join of the exact Source201 and physical199 inverse."""
import hashlib,json,os,stat,sys
from pathlib import Path
F=Path(__file__).resolve().parents[1]
PARENT='05df8c71ea2bcb525bb1cfbc59983452062a1e97';PTREE='7e66e27a352cee19a3d022d8c167c43b9ab72804';TREE='6225879650afde24a93fd33905819e779384c550';MAP='cc2d1aaee89bf8c8ff921b8d764572f94c29bcf76a625e501038d6413efb1cab';NULL=dict(source=None,ref=None,run=None)
def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def oid(kind,b):return hashlib.sha1(kind+b' '+str(len(b)).encode()+b'\0'+b).hexdigest()
def document(b):
 def pairs(items):
  value={}
  for k,v in items:need(k not in value,'duplicate DATA key');value[k]=v
  return value
 return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite DATA'))
def encoded(o):return(json.dumps(o,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def read(p):
 need(p.is_absolute()and p.resolve(strict=True)==p,'absolute nonaliased DATA')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size<=32*1024**2,'ordinary32MiB DATA leaf')
  with os.fdopen(fd,'rb',closefd=False)as f:b=f.read(32*1024**2+1)
  z=os.fstat(fd);n=p.lstat();keys=('st_dev','st_ino','st_mode','st_nlink','st_uid','st_gid','st_size','st_mtime_ns','st_ctime_ns')
  need(len(b)==a.st_size and all(getattr(a,k)==getattr(z,k)==getattr(n,k)for k in keys),'stable full DATA leaf')
  return b,stat.S_IMODE(a.st_mode),(a.st_dev,a.st_ino)
 finally:os.close(fd)
def tree(rows):
 root={}
 for n,r in rows.items():
  at=root
  for p in n.split('/')[:-1]:at=at.setdefault(p,{})
  at[n.split('/')[-1]]=(r['mode'],r['blob'])
 def visit(at):
  b=b''
  for n in sorted(at,key=lambda n:(n+'/'if isinstance(at[n],dict)else n).encode()):
   v=at[n];m,o=('40000',visit(v))if isinstance(v,dict)else('100755'if v[0]==493 else'100644',v[1]);b+=m.encode()+b' '+n.encode()+b'\0'+bytes.fromhex(o)
  return oid(b'tree',b)
 return visit(root)
def main():
 need(len(sys.argv)==2,'one constructed Source201 operand');root=Path(sys.argv[1]);need(root.is_absolute()and root.resolve(strict=True)==root and stat.S_IMODE(root.stat().st_mode)==0o700,'owned0700 constructed root')
 profile_raw=read(F/'parent-profile.json')[0];need(pin(profile_raw)['sha256']=='87c87e685a77609f09c1ba19a8e27c0fa2ede60b70ee3fff27707d5653020f35','exact parent profile');profile=document(profile_raw);parent=profile['files'];need(profile['parent']==PARENT and profile['parent_tree']==PTREE and len(parent)==199 and profile['actual']==NULL,'exact parent199')
 catalog_raw=read(F/'tests/fixtures/catalog.json')[0];need(pin(catalog_raw)['sha256']=='4e78bdb18ffab3565e6e8cca157dc604f313a78743c5ec61ecc17a1abf6bf6bf','exact finite fixture catalog');catalog=document(catalog_raw)
 full_raw=read(F/'tests/fixtures/source-full-map.json')[0];need(pin(full_raw)=={k:catalog['files']['source-full-map.json'][k]for k in('bytes','sha256')},'independent full201 authority');full=document(full_raw);need(len(full)==201,'exact201')
 changed={n for n in set(parent)|set(full)if (None if n not in parent else{k:parent[n][k]for k in('bytes','sha256','mode','blob')})!=(None if n not in full else{k:full[n][k]for k in('bytes','sha256','mode','blob')})};old=changed&set(parent);need(len(changed)==7 and len(old)==5,'exactseven/five delta')
 metadata={'stage.json','source-authorization.json','source-modes.json','git-blobs.json','parent-commit.raw','parent-full-map.json','delta05df.json','selected-overlay.json'};wanted={'source/'+n for n in full}|{'before05df/'+n for n in old}|metadata
 files={};identities=set();total=0;wanted_dirs={p.as_posix()for n in wanted for p in Path(n).parents if str(p)!='.'};seen_dirs=set()
 for current,dirs,names in os.walk(root,followlinks=False):
  for n in dirs:
   p=Path(current)/n;s=p.lstat();need(stat.S_ISDIR(s.st_mode)and s.st_uid==os.geteuid()and stat.S_IMODE(s.st_mode)==0o700,'ordinary owned0700 directory');seen_dirs.add(p.relative_to(root).as_posix())
  for n in names:
   p=Path(current)/n;name=p.relative_to(root).as_posix();need(name in wanted and name not in files,'closed214 physical namespace');b,m,identity=read(p);need(identity not in identities,'independent DATA inodes');identities.add(identity);total+=len(b);need(total<=96*1024**2,'whole output DATA bound');files[name]=(b,m)
 need(set(files)==wanted and seen_dirs==wanted_dirs and len(files)==214,'complete214 output')
 actual={}
 for n in full:
  b,m=files['source/'+n];need(m in(420,493),'ordinary mode');actual[n]=dict(**pin(b),mode=m,blob=oid(b'blob',b));need(actual[n]=={k:full[n][k]for k in('bytes','sha256','mode','blob')},'all201 bodies/modes/blobs')
 need(tree(actual)==TREE,'complete201 tree');map_raw=files['source/native/source-map.json'][0];mapped=document(map_raw);need(pin(map_raw)['sha256']==MAP and mapped['actual']==NULL and len(mapped['files'])==200 and mapped['files']=={n:{k:r[k]for k in('bytes','sha256','mode')}for n,r in actual.items()if n!='native/source-map.json'},'exactmap200/actualNULL')
 for name,expected in [('source-authorization.json',{n:pin(files['source/'+n][0])for n in full}),('source-modes.json',{n:files['source/'+n][1]for n in full}),('git-blobs.json',{n:dict(blob=actual[n]['blob'])for n in full}),('parent-full-map.json',parent)]:need(files[name]==(encoded(expected),420),'whole derived metadata '+name)
 inverse={}
 for n in parent:
  b,m=files[('before05df/'if n in old else'source/')+n];inverse[n]=dict(**pin(b),mode=m,blob=oid(b'blob',b))
 need(inverse==parent and tree(inverse)==PTREE and len(set(parent)-changed)==194,'complete199 inverse194held')
 raw=files['parent-commit.raw'][0];need(raw==read(F/'parent-commit.raw')[0]and pin(raw)==profile['parent_raw']and oid(b'commit',raw)==PARENT,'actual05df rawparent');head=raw.split(b'\n\n',1)[0].splitlines();need([r[5:].decode()for r in head if r.startswith(b'tree ')]==[PTREE]and[r[7:].decode()for r in head if r.startswith(b'parent ')]==[profile['parent_sole_parent']],'raw tree/soleparent')
 selected=read(F/'overlay-manifest.json')[0];need(pin(selected)['sha256']=='844228043b016d9411812cec0ce4d7fe70240b761c4d5569978cae4aec103cda'and files['selected-overlay.json']==(selected,420),'exact selected overlay')
 delta=dict(parent=PARENT,full_parent_inverse=True,changes={n:dict(before={k:parent[n][k]for k in('bytes','sha256','mode')}if n in parent else None,after={k:full[n][k]for k in('bytes','sha256','mode')}if n in full else None)for n in sorted(changed)});need(files['delta05df.json']==(encoded(delta),420),'exactseven delta')
 stage=dict(status='SOURCE_ONLY_EXACT_PLATFORM_NAMESPACE_POLICY201',operation='platform-namespace-policy-matrix-v1',parent=PARENT,parent_tree=PTREE,prospective_tree=TREE,source_map_sha256=MAP,source_files=201,source_map_rows=200,concurrency_group='native-arm-platform-tools',actual=NULL,constructed=True,built=False,installed=False,native='NOT_RUN',namespace_probe='NOT_RUN',physical_M2='NOT_RUN',release='NOT_ADMITTED',acceptance=False);need(files['stage.json']==(encoded(stage),420),'Source-only noacceptance stage')
 print(json.dumps(dict(status='PASS_CONSTRUCTED201_FULL199_INVERSE_DATA_ONLY',files=201,output_files=214,tree=TREE,map_sha256=MAP,parent=PARENT,inverse_files=199,unlisted_held=194,actual=NULL,native='NOT_RUN',acceptance=False),sort_keys=True))
if __name__=='__main__':main()
