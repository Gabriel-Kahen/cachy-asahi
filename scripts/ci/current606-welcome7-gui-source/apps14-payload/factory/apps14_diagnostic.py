# SPDX-License-Identifier: MIT
"""Opt-in Apps14 stage DATA, bounded timeout observation and exact owned retirement."""
import hashlib,json,math,os,stat,subprocess,time
from pathlib import Path
PHASES=('START','SCAN_FIRST','SCAN_SECOND','COMPARE_READS','ENCODE_INPUTS','ENCODE_ROWS','ENCODE_RESULT_BOUND','ENCODE_PUBLICATION','REOPEN_OUTPUT_PARENT','OPEN_OUTPUT','WRITE_OUTPUT','FSYNC_OUTPUT','VERIFY_OUTPUT','FSYNC_PARENT','DONE')
ERRORS={'ValueError','OSError','FileNotFoundError','FileExistsError','PermissionError','Refusal','Error','KeyboardInterrupt','SystemExit','OTHER'}
def need(v,why):
 if not v:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def identity(s):return(s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def directory(p):
 need(p.is_absolute()and not any(q.is_symlink()for q in(p,*p.parents)),'ordinary diagnostic output ancestry');fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);s=os.fstat(fd)
 try:need(stat.S_ISDIR(s.st_mode)and s.st_uid==os.geteuid()and not stat.S_IMODE(s.st_mode)&0o022,'private caller-owned diagnostic parent');return fd
 except BaseException:os.close(fd);raise
def validate(value):
 wanted={'schema','status','phase','sequence','elapsed_seconds','authority'}
 need(type(value)is dict and set(value)==wanted|({'error_type'}if value.get('status')=='FAILED'else set()),'finite stage fields only')
 need(type(value['status'])is str and type(value['phase'])is str,'finite textual stage enums')
 need(type(value['schema'])is int and value['schema']==1 and value['status']in('RUNNING','DONE','FAILED')and value['phase']in PHASES and type(value['sequence'])is int and value['sequence']==PHASES.index(value['phase'])and value['authority']=='DIAGNOSTIC_ONLY_NOT_ACCEPTANCE','exact source diagnostic phase')
 need(type(value['elapsed_seconds'])in(int,float)and math.isfinite(value['elapsed_seconds'])and 0<=value['elapsed_seconds']<=40,'bounded stage monotonic elapsed DATA')
 if value['status']=='DONE':need(value['phase']=='DONE','complete terminal diagnostic phase')
 if value['status']=='RUNNING':need(value['phase']!='DONE','inflight diagnostic phase')
 if value['status']=='FAILED':need(type(value['error_type'])is str and value['error_type']in ERRORS,'finite stage error class only')
 return value
def retire(parent,home,name):
 """Read fixed metadata only; unlink ONLY the stable validated owned new stage."""
 try:s=os.stat(name,dir_fd=parent,follow_symlinks=False)
 except FileNotFoundError:return dict(status='ABSENT',document=None,retired=True,acceptance_authority=False)
 fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
 try:
  a=os.fstat(fd);need(identity(a)==identity(s)and stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_uid==os.geteuid()and stat.S_IMODE(a.st_mode)==0o600 and 0<a.st_size<=1024,'owned bounded singlelink diagnostic stage')
  raw=os.read(fd,1025);need(len(raw)==a.st_size and identity(a)==identity(os.fstat(fd))==identity(os.stat(name,dir_fd=parent,follow_symlinks=False)),'diagnostic stage changed during read')
  def pairs(rows):
   v={}
   for k,x in rows:need(k not in v,'duplicate diagnostic field');v[k]=x
   return v
  value=validate(json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite stage')))
  need(raw==(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+'\n').encode(),'exact source stage JSON codec bytes')
  reopened=directory(home)
  try:need((os.fstat(reopened).st_dev,os.fstat(reopened).st_ino)==(os.fstat(parent).st_dev,os.fstat(parent).st_ino),'diagnostic parent rebound')
  finally:os.close(reopened)
  need(identity(a)==identity(os.stat(name,dir_fd=parent,follow_symlinks=False))and os.pread(fd,1025,0)==raw,'owned stage identity/fullhash before retirement');os.unlink(name,dir_fd=parent)
  try:os.stat(name,dir_fd=parent,follow_symlinks=False)
  except FileNotFoundError:pass
  else:raise ValueError('diagnostic stage retirement not absent')
  return dict(status='OWNED_STAGE_READ_AND_RETIRED_DATA_ONLY',document=value,file=pin(raw),retired=True,acceptance_authority=False)
 finally:os.close(fd)
def observe_and_retire(parent,target):
 try:return retire(parent,target.parent,target.name+'.stage.json')
 except (OSError,ValueError,UnicodeError)as error:return dict(status='UNREADABLE_OR_FOREIGN_STAGE_PRESERVED',document=None,retired=False,error_type=type(error).__name__,acceptance_authority=False)
def run(argv,env,target):
 target=Path(target);need(argv==['/usr/bin/cachy-asahi-apps','inventory','--dbpath','/var/lib/pacman','--output',str(target),'--diagnostic-stage'],'exact actual optional Apps14 inventory argv')
 parent=directory(target.parent);started=time.monotonic()
 try:
  for name in(target.name,target.name+'.stage.json'):
   try:os.stat(name,dir_fd=parent,follow_symlinks=False)
   except FileNotFoundError:pass
   else:raise ValueError('fresh inventory and diagnostic stage required')
  try:process=subprocess.run(argv,env=env,capture_output=True,timeout=35)
  except subprocess.TimeoutExpired as error:
   # subprocess.run has killed/reaped its direct owned child before raising.
   error.apps14_stage=observe_and_retire(parent,target);error.apps14_seconds=time.monotonic()-started;raise
  stage=observe_and_retire(parent,target)
  if process.returncode==0:need(stage['status']=='OWNED_STAGE_READ_AND_RETIRED_DATA_ONLY'and stage['document']['status']=='DONE'and stage['retired']is True,'successful actual Apps14 requires complete retired diagnostic stage')
  return process,stage,time.monotonic()-started
 finally:os.close(parent)
def success(value):
 need(type(value)is dict and set(value)=={'status','document','file','retired','acceptance_authority'}and value['file']==pin((json.dumps(value['document'],sort_keys=True,indent=2,ensure_ascii=True)+'\n').encode())and value['status']=='OWNED_STAGE_READ_AND_RETIRED_DATA_ONLY'and value['retired']is True and value['acceptance_authority']is False,'actual stage retired without acceptance authority');validate(value['document']);need(value['document']['status']=='DONE','Apps14 successful DONE stage');return value
