# SPDX-License-Identifier: MIT
"""Durable bounded public GPG/ALPM output, before caller verification assertions."""
import hashlib,json,os,re,stat
from pathlib import Path
CAP=128*1024
TOTAL=4*1024**2
MAX_COMMANDS=20
INDEX_CAP=512*1024


def need(ok,why):
 if not ok:raise ValueError(why)


def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


class Diagnostics:
 def __init__(self,root):
  root=Path(root)
  need(root.is_absolute() and '..' not in root.parts and not root.exists() and not any(p.is_symlink() for p in (root,*root.parents)),'fresh ordinary diagnostics directory required')
  parent=root.parent.stat();need(stat.S_ISDIR(parent.st_mode) and not parent.st_mode&0o022 and (parent.st_uid==os.geteuid() or os.geteuid()==0),'private output parent required')
  self.owner=(parent.st_uid,parent.st_gid);root.mkdir(mode=0o700)
  if (root.stat().st_uid,root.stat().st_gid)!=self.owner:os.chown(root,*self.owner)
  root.chmod(0o700)
  self.root=root;self.files={};self.bytes=0;self.commands=[]
  self.sync_directory(root.parent);self.sync_directory();self.checkpoint('INITIALIZED')

 def sync_directory(self,path=None):
  fd=os.open(self.root if path is None else path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  try:os.fsync(fd)
  finally:os.close(fd)

 def write(self,name,raw):
  need(re.fullmatch(r'[A-Za-z0-9._-]{1,100}',name) and name not in ('index.json','index.partial') and name not in self.files and type(raw) is bytes and len(raw)<=CAP and self.bytes+len(raw)<=TOTAL,'bounded unique public diagnostic file required')
  path=self.root/name;fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  with os.fdopen(fd,'wb') as stream:
   info=os.fstat(stream.fileno())
   if (info.st_uid,info.st_gid)!=self.owner:os.fchown(stream.fileno(),*self.owner)
   os.fchmod(stream.fileno(),0o600)
   stream.write(raw);stream.flush();os.fsync(stream.fileno())
  self.files[name]=pin(raw);self.bytes+=len(raw);self.sync_directory();return name

 def capture(self,argv,label,code,stdout,stderr,started_epoch,finished_epoch,error=None):
  need(len(self.commands)<MAX_COMMANDS and type(stdout) is bytes and type(stderr) is bytes,'finite verification diagnostics required')
  need(type(argv) is list and 1<=len(argv)<=64 and all(type(v) is str and len(v)<=2048 for v in argv) and sum(len(v) for v in argv)<=8192,'bounded public argv required')
  need(type(label) is str and re.fullmatch(r'[A-Za-z0-9._-]{1,100}',label) and (code is None or type(code) is int) and type(started_epoch) is int and type(finished_epoch) is int and 0<=started_epoch<=finished_epoch and (error is None or type(error) is str and len(error)<=512),'typed command diagnostics required')
  number=len(self.commands);refs={}
  for role,body in (('stdout',stdout),('stderr',stderr)):
   retained=body[:min(CAP,max(0,TOTAL-self.bytes))];name=self.write('%03d.%s'%(number,role),retained)
   refs[role]=dict(file=name,**self.files[name],observed_bytes=len(body),complete=len(retained)==len(body))
  row=dict(operation=label,argv=list(argv),exit=code,started_epoch=started_epoch,finished_epoch=finished_epoch,stdout=refs['stdout'],stderr=refs['stderr'],complete=all(r['complete'] for r in refs.values()),error=error)
  self.commands.append(row);self.checkpoint('IN_PROGRESS');return row

 def checkpoint(self,status,gate=None):
  need(type(status) is str and re.fullmatch(r'[A-Z][A-Z0-9_-]{0,100}',status) and (gate is None or type(gate) is dict),'typed diagnostic checkpoint required')
  value=dict(schema_version=1,status=status,scope='PUBLIC_TEST_SIGNATURE_AND_ALPM_GATE_ONLY',files=self.files,total_bytes=self.bytes,cap=TOTAL,stream_cap=CAP,commands=self.commands)
  if gate is not None:value['gate']={k:v for k,v in gate.items() if k!='diagnostics'}
  raw=(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n').encode();need(len(raw)<=INDEX_CAP,'bounded diagnostic index required')
  temporary=self.root/'index.partial';fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
  with os.fdopen(fd,'wb') as stream:
   info=os.fstat(stream.fileno())
   if (info.st_uid,info.st_gid)!=self.owner:os.fchown(stream.fileno(),*self.owner)
   os.fchmod(stream.fileno(),0o600)
   stream.write(raw);stream.flush();os.fsync(stream.fileno())
  target=self.root/'index.json';need(not target.is_symlink(),'ordinary index replacement required');temporary.replace(target);self.sync_directory();return pin(raw)
