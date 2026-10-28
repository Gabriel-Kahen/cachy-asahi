# SPDX-License-Identifier: MIT
"""Bounded public handoff observation; never retirement or cleanup authority."""
import base64,hashlib,json,math,os,re,stat
from pathlib import Path
CAP=16384
STATUS='ORIGINAL_OUTER_HANDOFF_DIAGNOSTIC_NOT_CLEANUP_AUTHORITY'
STATES={'RUNNING_NOT_CLEANUP_AUTHORITY','DIRECT_JOB_REAPED_GROUP_ABSENT_INNER_CLEANUP_STILL_REQUIRED','FAIL_OUTER_RETIREMENT_UNKNOWN'}
INNER='NOT_OBSERVED_OR_RETIRED_BY_OUTER_SUPERVISOR'
ERRORS={'outer job group absence unproved','unreaped owned job identity changed','fresh exact owned job session','handoff named identity changed','exact private0600 handoff mode','bounded outer handoff receipt','complete handoff write'}
TYPES={'ValueError','ProcessLookupError','PermissionError','FileNotFoundError','TimeoutExpired','KeyboardInterrupt','OSError'}

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def decode(raw):
 def pairs(rows):
  value={}
  for key,item in rows:need(key not in value,'duplicate JSON key');value[key]=item
  return value
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'finite JSON only'))
def stamp(info):return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,info.st_nlink,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
def parent(path):
 path=Path(path);need(path.is_absolute() and '..' not in path.parts and path.name not in ('','.','..'),'absolute ordinary diagnostic path')
 fd=os.open('/',os.O_DIRECTORY|os.O_RDONLY|os.O_CLOEXEC)
 try:
  for part in path.parts[1:-1]:
   nextfd=os.open(part,os.O_DIRECTORY|os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd);os.close(fd);fd=nextfd
  return fd,path.name
 except BaseException:os.close(fd);raise

def read(path,cap,private=False):
 directory,name=parent(path)
 try:
  before=os.stat(name,dir_fd=directory,follow_symlinks=False)
  need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_uid==os.getuid() and before.st_size<=cap and (not private or stat.S_IMODE(before.st_mode)==0o600),'ordinary owned bounded input')
  fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=directory)
  try:
   need(stamp(os.fstat(fd))==stamp(before),'input identity before read');raw=os.read(fd,cap+1)
   need(len(raw)==before.st_size and stamp(os.fstat(fd))==stamp(before) and stamp(os.stat(name,dir_fd=directory,follow_symlinks=False))==stamp(before),'input changed during bounded read')
   return raw
  finally:os.close(fd)
 finally:os.close(directory)

def identity(value):
 need(type(value) is dict and set(value) in ({'source_sha','trial','proof_sha256','consumer_token','producer_token'},{'case','source_sha','trial','proof_sha256','consumer_token','producer_token'}),'finite original identity fields')
 for name,pattern in [('source_sha','[0-9a-f]{40}'),('proof_sha256','[0-9a-f]{64}'),('consumer_token','[0-9a-f]{32}'),('producer_token','[0-9a-f]{16}'),('trial','[a-z0-9-]{1,64}')]:need(type(value[name]) is str and re.fullmatch(pattern,value[name]) is not None,'typed original identity')
 if 'case' in value:need(value['case'] in ('repair-bytes','repair-missing'),'finite original case')
 return value

def sources(root,manifest,paths):
 """Caller still runs its original source/lease gate before this passive join."""
 root=Path(root);need(root.is_absolute() and len(set(paths))==len(paths) and 1<=len(paths)<=4,'finite source records')
 raw=read(manifest,1024*1024);rows=decode(raw)['files'];records={}
 for name in paths:
  need(type(name) is str and not name.startswith('/') and all(p not in ('','.','..') for p in name.split('/')),'ordinary relative source')
  observed=pin(read(root/name,1024*1024));need(rows.get(name)==observed,'exact source manifest row');records[name]=observed
 return dict(manifest=pin(raw),files=records)

def public(value,expected):
 need(type(value) is dict and value.get('identity')==expected,'matching original identity')
 result={'identity':expected};complete=True
 def field(name,predicate):
  nonlocal complete
  if name in value and predicate(value[name]):result[name]=value[name]
  else:complete=False
 field('schema_version',lambda x:type(x) is int and x==1)
 field('status',lambda x:type(x) is str and x in STATES)
 field('group_absent',lambda x:type(x) is bool);field('direct_reaped',lambda x:type(x) is bool)
 field('inner_actors',lambda x:x==INNER)
 def job(x):return x is None or (type(x) is dict and set(x)=={'pid','pgid','sid','start'} and all(type(n) is int and n>0 for n in x.values()) and x['pid']>1 and x['pid']==x['pgid']==x['sid'])
 field('job',job)
 allowed=set(result)|{'exit_code','signals','cancellation_signal','cancellation_seconds','seconds','error_type','error','retirement_error'}
 for key in value:
  if key not in allowed:complete=False
 predicates={'exit_code':lambda x:type(x) is int and -128<=x<=255,'signals':lambda x:type(x) is list and len(x)<=8 and all(type(n) is int and n in (2,15,9) for n in x),'cancellation_signal':lambda x:x is None or type(x) is int and x in (2,15),'cancellation_seconds':lambda x:x is None or type(x) in (int,float) and math.isfinite(x) and 0<=x<=86400,'seconds':lambda x:type(x) in (int,float) and math.isfinite(x) and 0<=x<=86400,'error_type':lambda x:type(x) is str and x in TYPES,'retirement_error':lambda x:type(x) is str and x in TYPES,'error':lambda x:type(x) is str and x in ERRORS}
 for key,predicate in predicates.items():
  if key in value:
   if predicate(value[key]):result[key]=value[key]
   else:complete=False
 # No implied positive outcome from a RUNNING receipt or absent optional fields.
 return result,complete

def diagnostic(receipt,expected,source_records):
 expected=identity(expected);need(type(source_records) is dict and set(source_records)=={'manifest','files'},'explicit source joins required')
 for row in [source_records['manifest'],*source_records['files'].values()]:need(type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int and row['bytes']>=0 and re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None,'typed source pins')
 report=dict(schema_version=1,status=STATUS,cleanup_authority=False,identity=expected,sources=source_records,handoff_state='MISSING',public=None,raw_base64=None)
 try:raw=read(receipt,CAP,private=True)
 except FileNotFoundError:return report
 except (OSError,ValueError):report['handoff_state']='UNSAFE_OR_UNSTABLE_NOT_READ';return report
 report.update(raw_bytes=len(raw),raw_sha256=pin(raw)['sha256'])
 try:value=decode(raw)
 except (ValueError,UnicodeError,RecursionError):report['handoff_state']='MALFORMED_HASH_ONLY';return report
 try:projection,complete=public(value,expected)
 except (ValueError,TypeError):report['handoff_state']='IDENTITY_OR_SCHEMA_MISMATCH_HASH_ONLY';return report
 report.update(public=projection,handoff_state='COMPLETE_TYPED' if complete else 'PARTIAL_TYPED_HASH_ONLY')
 if complete:report['raw_base64']=base64.b64encode(raw).decode()
 return report

def save_diagnostic(path,value):
 verify(value);raw=encoded(value);need(len(raw)<=32768,'bounded handoff diagnostic export');directory,name=parent(path)
 try:
  need(os.fstat(directory).st_uid==os.getuid(),'owned diagnostic parent')
  fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
  try:
   need(os.write(fd,raw)==len(raw),'complete diagnostic write');os.fsync(fd)
  finally:os.close(fd)
 finally:os.close(directory)
 need(read(path,32768,private=True)==raw,'private diagnostic readback')
 return value

def verify(value):
 need(type(value) is dict and set(value)<= {'schema_version','status','cleanup_authority','identity','sources','handoff_state','public','raw_base64','raw_bytes','raw_sha256'} and set(value)>={'schema_version','status','cleanup_authority','identity','sources','handoff_state','public','raw_base64'},'exact diagnostic schema')
 need(type(value['schema_version']) is int and value['schema_version']==1 and value['status']==STATUS and value['cleanup_authority'] is False,'diagnostic never cleanup authority');expected=identity(value['identity']);records=value['sources']
 need(type(records) is dict and set(records)=={'manifest','files'} and type(records['files']) is dict and 1<=len(records['files'])<=4,'finite diagnostic source records')
 for name,row in [('manifest',records['manifest']),*records['files'].items()]:
  need(type(name) is str and len(name)<=256 and type(row) is dict and set(row)=={'bytes','sha256'} and type(row['bytes']) is int and 0<=row['bytes']<=1024*1024 and type(row['sha256']) is str and re.fullmatch('[0-9a-f]{64}',row['sha256']) is not None,'typed bounded diagnostic source pin')
 state=value['handoff_state'];need(state in ('MISSING','UNSAFE_OR_UNSTABLE_NOT_READ','MALFORMED_HASH_ONLY','IDENTITY_OR_SCHEMA_MISMATCH_HASH_ONLY','PARTIAL_TYPED_HASH_ONLY','COMPLETE_TYPED'),'finite handoff state')
 if state in ('MISSING','UNSAFE_OR_UNSTABLE_NOT_READ'):need('raw_bytes' not in value and 'raw_sha256' not in value and value['raw_base64'] is None and value['public'] is None,'unread source has no invented bytes')
 else:need(type(value.get('raw_bytes')) is int and 0<=value['raw_bytes']<=CAP and type(value.get('raw_sha256')) is str and re.fullmatch('[0-9a-f]{64}',value['raw_sha256']) is not None,'actual raw hash required')
 if state=='COMPLETE_TYPED':
  need(type(value['raw_base64']) is str,'exact validated raw encoding');raw=base64.b64decode(value['raw_base64'],validate=True);need(pin(raw)==dict(bytes=value['raw_bytes'],sha256=value['raw_sha256']),'exact original handoff raw join');projection,complete=public(decode(raw),expected);need(complete and projection==value['public'],'complete public projection joins raw')
 else:
  need(value['raw_base64'] is None,'unvalidated raw is never public')
  if state=='PARTIAL_TYPED_HASH_ONLY':
   projection,_=public(value['public'],expected);need(projection==value['public'],'typed partial public projection')
  else:need(value['public'] is None,'no invented partial projection')
 return value
