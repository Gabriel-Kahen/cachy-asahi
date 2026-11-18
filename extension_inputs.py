# SPDX-License-Identifier: MIT
"""Only the original13 updater354 extension rows across four fixed owned input sources."""
import os,stat,time
from pathlib import Path
import admission as A
ROOT=Path(__file__).resolve().parent
FIELDS=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def identity(p):
 s=p.lstat();A.need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and s.st_uid==os.getuid(),'ordinary owned singlelink extension cache leaf');return[getattr(s,n)for n in FIELDS]
def prepare(rows,sources,cache,deadline):
 A.need(rows==A.obj(ROOT/'bootstrap-code/scripts/port/updater-extension/builder-extension.lock.json')['packages']and len(rows)==13,'all original13 extension rows only');A.need(set(sources)=={'retained574','compiler6','official3','legacy2'},'four exact original input namespaces');A.need(time.monotonic()<deadline,'original owner deadline before extension materialization');cache=Path(cache);st=cache.lstat();A.need(stat.S_ISDIR(st.st_mode)and st.st_uid==os.getuid()and st.st_mode&0o7777==0o700 and not any(p.is_symlink()for p in(cache,*cache.parents)),'private existing owned extension cache');before={p.name:identity(p)for p in cache.iterdir()};directory=[st.st_dev,st.st_ino,st.st_mode,st.st_uid,st.st_gid];targets={};counts={n:0 for n in sources}
 for row in rows:
  for suffix,size,sha in[('',row['size'],row['sha256']),('.sig',row['signature_size'],row['signature_sha256'])]:
   name=row['filename']+suffix;A.need(Path(name).name==name and name not in targets and name not in before,'distinct original extension names; no overwrite');wanted=dict(bytes=size,sha256=sha);member='packages/'+name;present=[n for n,(root,profile)in sources.items()if member in profile['files']];A.need(len(present)==1,'one exact source namespace for every original extension leaf');kind=present[0];root,profile=sources[kind];A.need(profile['files'][member]==wanted,'original extension pin in selected whole-source profile');targets[name]=(kind,Path(root)/member,wanted,profile['source']);counts[kind]+=1
 A.need(len(targets)==26 and counts==dict(retained574=10,compiler6=6,official3=6,legacy2=4),'complete original26 partition, no fallback namespace')
 expected=A.obj(ROOT/'extension-input-profile.json');A.need(expected['actual']is None and expected['original_inputs']==A.pin(A.read(ROOT/'bootstrap-code/scripts/port/updater-extension/builder-extension.lock.json'))and{k:dict(pin=w,namespace=kind,source=sha)for k,(kind,path,w,sha)in targets.items()}==expected['files'],'whole original lock and exact26 source-bound routes')
 files={}
 for name,(kind,source,wanted,source_sha)in targets.items():
  A.need(time.monotonic()<deadline,'original owner extension copy budget');raw=A.read(source,256*1024**2);A.need(A.pin(raw)==wanted,'whole exact original extension body')
  with(cache/name).open('xb')as f:f.write(raw)
  A.need(A.pin(A.read(cache/name,256*1024**2))==wanted,'whole actual extension materialization');files[name]=dict(pin=wanted,namespace=kind,source=source_sha)
 after={p.name:identity(p)for p in cache.iterdir()};now=cache.lstat();A.need(set(after)==set(before)|set(files)and{n:after[n]for n in before}==before and[now.st_dev,now.st_ino,now.st_mode,now.st_uid,now.st_gid]==directory,'entire previous cache identities and directory preserved; no foreign addition');A.need(time.monotonic()<deadline,'original owner after extension materialization')
 return dict(status='EXACT_ORIGINAL13_EXTENSION26_INPUTS_MATERIALIZED_NOT_AUTHENTICATED',packages=13,files=files,namespace_counts=counts,before_identity=before,after_previous_identity={n:after[n]for n in before},directory_identity=directory,actual_authority=False)
