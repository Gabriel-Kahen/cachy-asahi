#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bounded diagnostic-only GNU owner log frame; never supplies acceptance."""
import argparse,base64,hashlib,json,os,re,stat,zipfile
from pathlib import Path,PurePosixPath
PREFIX='GNU_FAILURE_LOG_V1 '
MAX_JSON=16384
MAX_FRAME=24576
LANES=('lifecycle','interruption')

def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def decode(raw):
 def pairs(rows):
  value={}
  for k,v in rows:need(k not in value,'duplicate JSON key');value[k]=v
  return value
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def raw(path,cap):
 path=Path(path);need(not any(p.is_symlink() for p in (path,*path.parents)),'no symbolic report path');a=path.stat();need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and 0<=a.st_size<=cap,'bounded ordinary single-link report')
 value=path.read_bytes();b=path.stat();need((a.st_dev,a.st_ino,a.st_size,a.st_mtime_ns,a.st_ctime_ns)==(b.st_dev,b.st_ino,b.st_size,b.st_mtime_ns,b.st_ctime_ns) and len(value)==a.st_size,'report changed');return value
def fields(value,names,limit=128):
 if type(value) is not dict:return {}
 return {k:(v[:limit] if type(v) is str else v) for k in names if k in value and (type(v:=value[k]) in (str,int,bool) or v is None)}
def failure(value):
 result=[];left=4
 if type(value) is not list:return result
 for row in value[:2]:
  if type(row) is not dict:continue
  v=fields(row,('type','message','frames_clipped'),384);frames=row.get('frames',[])
  if type(frames) is list:
   v['frames']=[fields(f,('file','function','line'),192) for f in frames[-left:] if type(f) is dict] if left else [];left-=len(v['frames'])
  notes=row.get('notes',[])
  if type(notes) is list:v['notes']=[n[:128] for n in notes[:1] if type(n) is str]
  result.append(v)
 return result

def root_initialization(value):
 if type(value) is not dict:return None
 names=('status','path','before','after','parent_before','parent_after','source_before','source_after','source_mutation','payload_nodes_mutation')
 if set(value)!=set(names):return dict(observation='UNRECOGNIZED_RECEIPT_NO_CREDIT')
 result=fields(value,('status','path','source_mutation','payload_nodes_mutation'),192)
 for name in names[2:8]:
  row=value[name]
  if type(row) is not dict or set(row)!={'device','inode','mode','uid','gid'} or not all(type(v) is int and 0<=v<2**64 for v in row.values()):return dict(observation='MALFORMED_RECEIPT_NO_CREDIT')
  result[name]=row
 return result

def command(value,directory,prefix):
 rows=value.get('commands',[])
 if type(rows) is not list or len(rows)>256:return dict(observation='MISSING_OR_UNBOUNDED_COMMAND_ROWS')
 # Keep only the first failure, otherwise the last observed completed command.
 failed=[(i,r) for i,r in enumerate(rows) if type(r) is dict and (r.get('exit_code')!=0 or r.get('group_absence_verified') is not True)]
 if not rows:return dict(count=0)
 i,row=failed[0] if failed else (len(rows)-1,rows[-1]);result=dict(count=len(rows),index=i,observation='FIRST_NONZERO_OR_UNRETIRED' if failed else 'LAST_OBSERVED',**fields(row,('exit_code','group_absence_verified','stdout_bytes','stdout_sha256','stderr_bytes','stderr_sha256','time_limit','output_limit')))
 if type(row) is dict and row.get('stderr_bytes',0):
  try:
   data=raw(directory/(prefix%i+'.stderr'),1024**2);need(pin(data)==dict(bytes=row['stderr_bytes'],sha256=row['stderr_sha256']),'stderr row/hash differs');result['stderr_preview']=data[:512].decode(errors='replace');result['stderr_preview_clipped']=len(data)>512
  except Exception as error:result['stderr_observation']=type(error).__name__
 return result

def report(path,cap,kind):
 try:
  data=raw(path,cap);value=decode(data);need(type(value) is dict,'object report required')
  result=dict(observation='READ',file=pin(data),summary=fields(value,('status','error_type','error','cleanup_error_type','cleanup_error','outer_cleanup_error','consumer_cleanup','actor_cleanup','root_cleanup','producer_cleanup')))
  if kind in ('owner','inner','child'):
   result['command']=command(value,path.parent if kind=='owner' else (path.parent/'public' if kind=='inner' else path.parent),'owner-command-%03d' if kind=='inner' else 'command-%03d')
  if kind=='child':
   result['cases']={};cases=value.get('cases',{})
   for case in ('pristine','modified'):
    row=cases.get(case) if type(cases) is dict else None
    if type(row) is not dict:result['cases'][case]=dict(observation='NOT_RECORDED');continue
    v=dict(observation='RECORDED',summary=fields(row,('status','clone_cleanup_check','source_before','source_after')),root_initialization=root_initialization(row.get('root_initialization')),primary_failure=failure(row.get('primary_failure')),cleanup_failure=failure(row.get('cleanup_failure')))
    lifetime=row.get('copy_lifetime',{});v['copy_lifetime']=fields(lifetime,('cleanup','security_capabilities','source_capabilities_sha256'))
    copyrow=lifetime.get('copy',{}) if type(lifetime) is dict else {};v['copy_initialization']=fields(copyrow,('copy_byte_identical_before_initialization',))
    evidence=row.get('copy_evidence',{});v['copy_stage']=fields(evidence,('stage',));v['copy_failure']=failure(evidence.get('failure')) if type(evidence) is dict and not v['primary_failure'] else []
    v['normal_runtime']={}
    for stage in ('before_runtime','recovered_runtime','provider_runtime','reinstalled_runtime','held_runtime'):
     runtime=row.get(stage);v['normal_runtime'][stage]=fields(runtime.get('result'),('status','cases','page_size','glibc_version')) if type(runtime) is dict else dict(observation='NOT_RECORDED')
    interrupted=row.get('interruption',{});v['interruption']=fields(interrupted,('status','observed_stop','partial_state'));result['cases'][case]=v
  if kind=='cleanup':
   result['consumer']=fields(value,('consumer',));result['producer']=fields(value.get('producer'),('status',));result['apparmor']=fields(value.get('apparmor'),('status','name'))
  if kind=='export':
   result['errors']=[fields(r,('file','error'),256) for r in value.get('errors',[])[:4] if type(r) is dict] if type(value.get('errors')) is list else []
  return result,value
 except Exception as error:return dict(observation='MISSING_OR_UNREADABLE',error_type=type(error).__name__,error=str(error)[:192]),None

def collect(owner,proof,cleanup,public,lane,env,retain_exit):
 need(lane in LANES and type(retain_exit) is int and 0<=retain_exit<=255,'finite lane/exit status');source=env.get('SOURCE_SHA','');run=env.get('GITHUB_RUN_ID','');attempt=env.get('GITHUB_RUN_ATTEMPT','')
 need(re.fullmatch('[0-9a-f]{40}',source) and source==env.get('WORKFLOW_SHA')==env.get('GITHUB_SHA') and re.fullmatch('[1-9][0-9]{0,19}',run) and re.fullmatch('[1-9][0-9]{0,3}',attempt),'exact frozen CI run identity')
 p=decode(raw(proof,65536));need(p['source_sha']==source and str(p['run_id'])==run and str(p['attempt'])==attempt and re.fullmatch('[0-9a-f]{32}',p['consumer_token']),'source proof/run/token binding')
 result=dict(schema_version=1,status='DIAGNOSTIC_ONLY_NO_ACCEPTANCE',lane=lane,source_sha=source,run_id=run,attempt=attempt,consumer_token=p['consumer_token'],retain_exit_code=retain_exit,proof=pin(raw(proof,65536)),native_acceptance=False,hardware='NOT_RUN',reports={})
 paths=(('owner',owner/'owner.json',2*1024**2),('inner',owner/'inner/owner.json',2*1024**2),('child',owner/'inner/public/result.json',8*1024**2),('cleanup',cleanup,2*1024**2),('export',public/'export.json',2*1024**2))
 observed={}
 for name,path,cap in paths:result['reports'][name],observed[name]=report(path,cap,name)
 outer,inner=observed['owner'],observed['inner']
 result['owner_identity']='UNKNOWN'
 if type(outer) is dict and type(inner) is dict:
  result['owner_identity']='MATCH' if outer.get('token')==inner.get('token')==p['consumer_token'] and outer.get('source_sha')==source and outer.get('image')==inner.get('image_id') else 'MISMATCH_NO_CREDIT'
 result['bounded_projection']=True;result['projection_clipped_for_frame']=False
 if len(encoded(result))>MAX_JSON:
  result['projection_clipped_for_frame']=True
  for r in result['reports'].values():
   if 'command' in r and 'stderr_preview' in r['command']:r['command']['stderr_preview']=r['command']['stderr_preview'][:128];r['command']['stderr_preview_clipped']=True
   for v in r.get('cases',{}).values():
    for key in ('primary_failure','cleanup_failure','copy_failure'):
     for error in v.get(key,[]):
      if 'message' in error:error['message']=error['message'][:96]
      error['frames']=error.get('frames',[])[:1];error['frames_clipped']=True;error['notes']=[]
 need(len(encoded(result))<=MAX_JSON,'bounded projection exceeded fixed frame limit');return result

def frame(value):
 data=encoded(value);need(len(data)<=MAX_JSON,'bounded diagnostic JSON');text=PREFIX+base64.b64encode(data).decode();need(len(text)<=MAX_FRAME,'bounded single-line frame');return text

def extract(logs,source,run,attempt,lane):
 need(re.fullmatch('[0-9a-f]{40}',source) and re.fullmatch('[1-9][0-9]{0,19}',str(run)) and re.fullmatch('[1-9][0-9]{0,3}',str(attempt)) and lane in LANES,'expected original identity');raw(logs,32*1024**2);found={}
 with zipfile.ZipFile(logs) as archive:
  entries=archive.infolist();need(len(entries)<1500 and sum(r.file_size for r in entries)<=32*1024**2 and len({r.filename for r in entries})==len(entries),'bounded original log ZIP')
  for row in entries:
   p=PurePosixPath(row.filename);need(not p.is_absolute() and '..' not in p.parts and '\\' not in row.filename and stat.S_IFMT(row.external_attr>>16) in (0,stat.S_IFREG,stat.S_IFDIR),'safe log ZIP member')
   for line in archive.read(row).splitlines():
    match=re.fullmatch(rb'[0-9T:.Z+\-]{20,40} '+PREFIX.encode()+rb'([A-Za-z0-9+/=]+)',line)
    if not match:continue
    need(len(line)<=MAX_FRAME+41,'bounded frame line');data=base64.b64decode(match[1],validate=True);need(len(data)<=MAX_JSON,'bounded frame payload');value=decode(data)
    need((value['schema_version'],value['status'],value['source_sha'],str(value['run_id']),str(value['attempt']),value['lane'],value['native_acceptance'])==(1,'DIAGNOSTIC_ONLY_NO_ACCEPTANCE',source,str(run),str(attempt),lane,False),'log frame source/run/scope differs');found[hashlib.sha256(data).hexdigest()]=value;need(len(found)<=1,'conflicting original log frames')
 need(len(found)==1,'no original diagnostic frame; cause remains UNOBSERVABLE');return next(iter(found.values()))

if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('emit','extract'));p.add_argument('--lane',choices=LANES,required=True)
 for name in ('owner','proof','cleanup','public','logs','output'):p.add_argument('--'+name,type=Path)
 for name in ('source','run','attempt'):p.add_argument('--'+name)
 p.add_argument('--retain-exit',type=int);a=p.parse_args()
 if a.action=='emit':
  try:value=collect(a.owner,a.proof,a.cleanup,a.public,a.lane,os.environ,a.retain_exit);code=0
  except Exception as error:
   # Preserve a small diagnostic even if a malformed/oversized report refuses projection.
   value=dict(schema_version=1,status='DIAGNOSTIC_ONLY_NO_ACCEPTANCE',lane=a.lane,source_sha=os.environ.get('SOURCE_SHA','')[:40],run_id=os.environ.get('GITHUB_RUN_ID','')[:20],attempt=os.environ.get('GITHUB_RUN_ATTEMPT','')[:4],native_acceptance=False,source_proof='UNESTABLISHED',diagnostic_error=dict(type=type(error).__name__,message=str(error)[:192]));code=1
  print(frame(value),flush=True);raise SystemExit(code)
 else:
  need(not a.output.exists() and a.output.parent.is_dir(),'fresh diagnostic output');v=extract(a.logs,a.source,a.run,a.attempt,a.lane);a.output.write_bytes(encoded(v)+b'\n');print(json.dumps(dict(status=v['status'],native_acceptance=False,output=str(a.output))))
