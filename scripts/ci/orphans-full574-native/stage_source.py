# SPDX-License-Identifier: MIT
"""Exact frozen rules checkout owned by the native root actor, never product policy."""
import os,stat
from pathlib import Path

SOURCE=Path('/source');WORK=Path('/work')
MAX_FILES=256;MAX_FILE=4*1024**2;MAX_TOTAL=8*1024**2

def owned(C,path,directory=False):
 C.safe(path);s=path.lstat()
 C.need(s.st_uid==s.st_gid==0 and stat.S_IMODE(s.st_mode)==(0o700 if directory else 0o644) and
        (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode) and s.st_nlink==1),'root-owned private stage identity required')
 return s

def declared(C,source):
 C.source(source) # Original authority/source guard precedes every stage operation.
 name=C.LANE+'/source-manifest.json';raw=C.read(source/name,256*1024);value=C.decode(raw)
 rows=dict(value['files']);C.need(name not in rows and 0<len(rows)<=MAX_FILES,'finite nonrecursive frozen stage closure required')
 rows[name]=dict(bytes=len(raw),sha256=C.sha(raw))
 C.need(len(rows)<=MAX_FILES+1 and all(0<r['bytes']<=MAX_FILE for r in rows.values()) and sum(r['bytes'] for r in rows.values())<=MAX_TOTAL,'bounded frozen stage bytes required')
 return rows

def check(C,source,root,work):
 rows=declared(C,source);C.need(root.parent==work and root.name in ('source-normal','source-interruption') and root!=source and not source.is_relative_to(root) and not root.is_relative_to(source),'distinct fixed stage sibling required')
 owned(C,work,True);owned(C,root,True);files={};directories={root}
 for name,row in sorted(rows.items()):
  original=C.checked(source,dict(path=name,**row));path=root/name
  for parent in path.parents:
   if parent==work:break
   owned(C,parent,True);directories.add(parent)
  info=owned(C,path);copied=C.checked(root,dict(path=name,**row));C.need(original==copied,'original/staged source bytes differ')
  files[name]=dict(**row,uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode),links=info.st_nlink,original_uid=(source/name).stat().st_uid)
 actual=set(root.rglob('*'));C.need(actual=={root/n for n in files}|(directories-{root}),'closed stage contains undeclared nodes')
 # Read the original closure again after the complete staged observation.
 C.need(declared(C,source)==rows,'original source declaration changed during stage')
 return dict(status='EXACT_ROOT_OWNED_FROZEN_RULES_SOURCE',original=str(source),staged=str(root),manifest_sha256=rows[C.LANE+'/source-manifest.json']['sha256'],files=files,file_count=len(files),bytes=sum(r['bytes'] for r in rows.values()),original_staged_hashset_sha256=C.sha(C.encoded(rows)),scope='ACTOR_SOURCE_ONLY_OUTSIDE_MUTATION_ROOT_NO_PRODUCT_POLICY_CHANGE')

def copy(C,source,work,role):
 C.need(role in ('normal','interruption'),'closed stage actor role required');rows=declared(C,source);owned(C,work,True)
 root=work/('source-'+role);C.need(not root.exists() and not root.is_symlink(),'fresh stage required');root.mkdir(mode=0o700)
 for name,row in sorted(rows.items()):
  raw=C.checked(source,dict(path=name,**row));path=root/name
  parent=root
  for part in path.relative_to(root).parts[:-1]:
   parent=parent/part;parent.mkdir(mode=0o700,exist_ok=True)
  fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o644)
  try:
   os.fchmod(fd,0o644)
   with os.fdopen(fd,'wb',closefd=False) as stream:stream.write(raw);stream.flush();os.fsync(fd)
  finally:os.close(fd)
 receipt=check(C,source,root,work);return root,receipt

def stage(C,role):
 C.need(os.getuid()==os.geteuid()==0,'native root source stage only')
 return copy(C,SOURCE,WORK,role)

def validate(C,root):
 C.need(os.getuid()==os.geteuid()==0 and root in (WORK/'source-normal',WORK/'source-interruption'),'explicit fixed native staged root required')
 return check(C,SOURCE,root,WORK)
