# SPDX-License-Identifier: MIT
"""Host-origin nonce custody for failure diagnostics; no VM acceptance authority."""
import json,os,re,stat
from pathlib import Path
CAP=4096
STATUS='HOST_ORIGIN_PRE_VM_NONCE_DIAGNOSTIC_ONLY'

def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def identity(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def context(case,source,environ):
 need(case in ('repair-bytes','repair-missing'),'exact receipt case')
 need(re.fullmatch('[0-9a-f]{40}',source or '') and source==environ.get('SOURCE_SHA')==environ.get('GITHUB_SHA')==environ.get('GITHUB_WORKFLOW_SHA'),'exact host source/workflow identity')
 run=environ.get('GITHUB_RUN_ID');attempt=environ.get('GITHUB_RUN_ATTEMPT');repository=environ.get('GITHUB_REPOSITORY');job=environ.get('GITHUB_JOB');workflow_ref=environ.get('GITHUB_WORKFLOW_REF')
 need(re.fullmatch('[1-9][0-9]{0,19}',run or '') and re.fullmatch('[1-9][0-9]{0,4}',attempt or ''),'canonical host run/attempt')
 need(re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',repository or '') and re.fullmatch('[A-Za-z_][A-Za-z0-9_-]{0,99}',job or ''),'finite host repository/job')
 need(type(workflow_ref)is str and len(workflow_ref)<=512 and workflow_ref.startswith(repository+'/.github/workflows/') and workflow_ref.count('@')==1 and not any(c in workflow_ref for c in '\r\n\x00'),'finite host workflow ref')
 need(workflow_ref.split('@',1)[0]in {repository+'/.github/workflows/native-arm-apps7-full574-repair16k.yml',repository+'/.github/workflows/native-arm-build.yml'} and workflow_ref.split('@',1)[1].startswith('refs/heads/') and len(workflow_ref.split('@',1)[1])>11,'exact repair workflow branch')
 return dict(source_sha=source,workflow_sha=source,repository=repository,run_id=run,run_attempt=attempt,job=job,workflow_ref=workflow_ref,case=case)
def parent(path):
 path=Path(path);need(path.is_absolute() and all(p not in ('','.','..')for p in path.parts[1:]),'absolute ordinary receipt path');fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
 try:
  for part in path.parts[1:-1]:
   child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);os.close(fd);fd=child
  s=os.fstat(fd);need(s.st_uid==os.getuid() and not stat.S_IMODE(s.st_mode)&0o022,'private host receipt parent');return fd,path.name
 except BaseException:os.close(fd);raise
def named_parent(path,fd):
 other,_=parent(path)
 try:need(identity(os.fstat(other))[:5]==identity(os.fstat(fd))[:5],'host receipt parent remains source named')
 finally:os.close(other)
def create(path,nonce,case,source,environ=None):
 value=dict(schema_version=1,status=STATUS,origin='HOST_COORDINATOR_OS_URANDOM_BEFORE_DISK_AND_VM',context=context(case,source,os.environ if environ is None else environ),nonce=nonce,positive_authority=False)
 need(type(nonce)is str and re.fullmatch('[0-9a-f]{32}',nonce),'exact host nonce');raw=encoded(value);need(len(raw)<=CAP,'bounded host receipt');pfd,name=parent(path)
 try:
  fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=pfd)
  try:
   with os.fdopen(fd,'wb',closefd=False)as stream:stream.write(raw);stream.flush();os.fsync(fd)
  finally:os.close(fd)
  os.fsync(pfd);named_parent(path,pfd)
 finally:os.close(pfd)
 return value
def read(path,case,source,environ=None):
 pfd,name=parent(path)
 try:
  fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=pfd)
  try:
   before=os.fstat(fd);need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==os.getuid() and stat.S_IMODE(before.st_mode)==0o600 and 0<before.st_size<=CAP,'ordinary private bounded host receipt');raw=os.read(fd,CAP+1);need(len(raw)==before.st_size and identity(before)==identity(os.fstat(fd))==identity(os.stat(name,dir_fd=pfd,follow_symlinks=False)),'host receipt identity/bytes unchanged')
  finally:os.close(fd)
  named_parent(path,pfd)
 finally:os.close(pfd)
 def pairs(items):
  out={}
  for k,v in items:need(k not in out,'duplicate host receipt key');out[k]=v
  return out
 value=json.loads(raw,object_pairs_hook=pairs);need(type(value)is dict and set(value)=={'schema_version','status','origin','context','nonce','positive_authority'} and type(value['schema_version'])is int and value['schema_version']==1 and value['status']==STATUS and value['origin']=='HOST_COORDINATOR_OS_URANDOM_BEFORE_DISK_AND_VM' and value['positive_authority']is False and value['context']==context(case,source,os.environ if environ is None else environ) and type(value['nonce'])is str and re.fullmatch('[0-9a-f]{32}',value['nonce']) and raw==encoded(value),'exact host-origin receipt and run/source/case join');return raw,value
