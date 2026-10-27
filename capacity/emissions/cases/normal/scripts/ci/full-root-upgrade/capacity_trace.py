# SPDX-License-Identifier: MIT
"""Mandatory bounded scalar probe telemetry; no filesystem observations cached."""
import hashlib,json,os,re,resource,stat,time
from pathlib import Path
BUDGETS = {'actor_retirement_reserve': 900, 'caller': 7800, 'capability_map': 900, 'composition_step': 18600, 'control_lease_cleanup': 300, 'copy': 3600, 'copy_workspace_cleanup': 900, 'disk_command': 600, 'driver': 4800, 'elf_audit': 300, 'export_actor': 1200, 'guest_worker': 10200, 'host_owner': 17400, 'infrastructure_copy': 900, 'job': 21600, 'job_build_reserve': 2400, 'job_owner': 18000, 'pid1_worker': 10320, 'post_composition_reserve': 600, 'prepare_actor': 2400, 'prepare_observations': 1800, 'qemu': 10800, 'quiescence': 120, 'scrub_actor': 1200, 'source_stage': 1500, 'source_verify': 900, 'vm_transport': 15840}
PROFILE_SHA256 = '7f91ec63081af3aee3fe092646ec801816803fd54062c0b14649483a2988b0a9'
PURPOSE='generic16k-fullcopy-capacity'
MAX_EVENTS=96;MAX_FRAME=16384;MAX_BYTES=512*1024

def need(ok,why):
 if not ok:raise ValueError(why)
def encoded(v):return(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
class Trace:
 def __init__(self,path,identity):
  path=Path(path);need(path.is_absolute()and path.parent==path.parent.resolve()and not any(p.is_symlink()for p in(path.parent,*path.parent.parents)),'canonical telemetry parent')
  info=path.parent.stat();need(stat.S_ISDIR(info.st_mode)and info.st_uid==os.geteuid()and not stat.S_IMODE(info.st_mode)&0o077,'private telemetry parent')
  self.fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600);self.path=path
  self.identity=identity;self.events=[];self.bytes=0;self.origin=time.monotonic_ns();self.cpu=time.process_time_ns();self.source_totals=None;self.closed=False
 def event(self,phase,event,stats=None,totals=None,details=None):
  need(not self.closed and type(phase)is str and re.fullmatch('[A-Z][A-Z_]{0,63}',phase)and event in('BEGIN','POINT','END','FAIL'),'closed capacity phase/event')
  need(len(self.events)<MAX_EVENTS,'capacity telemetry event ceiling')
  usage=resource.getrusage(resource.RUSAGE_SELF)
  row=dict(sequence=len(self.events)+1,phase=phase,event=event,elapsed_ns=time.monotonic_ns()-self.origin,cpu_ns=time.process_time_ns()-self.cpu,user_us=int(usage.ru_utime*1000000),system_us=int(usage.ru_stime*1000000),maxrss_kib=usage.ru_maxrss)
  if stats is not None:
   need(type(stats)is list and len(stats)==7 and all(type(v)is int and 0<=v<2**63 for v in stats),'typed current scalar copy counters');row['counters']=dict(zip(('completed_groups','completed_members','completed_bytes','parent_calls','alias_calls','statx_success','mount_fallback'),stats))
  if totals is not None:row['totals']=totals
  if details is not None:row['details']=details
  raw=encoded(row);need(len(raw)<=MAX_FRAME and self.bytes+len(raw)<=MAX_BYTES,'capacity telemetry byte ceiling')
  view=memoryview(raw)
  while view:
   count=os.write(self.fd,view);need(count>0,'capacity telemetry write progress');view=view[count:]
  self.bytes+=len(raw);self.events.append(row);return row
 def totals(self,observation):
  need(observation.get('complete')is True,'complete eligible source total')
  nodes=observation['nodes'];groups=observation['hardlink_groups'];seen=set();members=logical=copy_bytes=0
  for name,node in nodes.items():
   if node['type']!='file':continue
   need(type(node['bytes'])is int and node['bytes']>=0,'source file byte total')
   members+=1;logical+=node['bytes'];group=node.get('hardlink_group');key=('group',group)if group is not None else('file',name)
   if group is not None:
    declared=groups[group]['members'];need(name in declared and all(n in nodes and nodes[n]['type']=='file'and nodes[n]['bytes']==node['bytes']for n in declared),'source hardlink denominator')
   if key not in seen:seen.add(key);copy_bytes+=node['bytes']
  totals=dict(groups=len(seen),members=members,copy_bytes=copy_bytes,logical_bytes=logical,nodes=len(nodes),directories=sum(n['type']=='directory'for n in nodes.values()),symlinks=sum(n['type']=='symlink'for n in nodes.values()))
  need(all(type(v)is int and 0<=v<2**63 for v in totals.values()),'bounded exact source totals')
  if self.source_totals is None:self.source_totals=totals;self.event('SOURCE_TOTALS','POINT',totals=totals)
  else:need(totals==self.source_totals,'fresh source/destination denominator changed')
  return totals
 def summary(self):
  return dict(schema_version=1,purpose=PURPOSE,status='DIAGNOSTIC_DATA_NOT_ACCEPTANCE',identity=self.identity,profile_sha256=PROFILE_SHA256,source_totals=self.source_totals,totals_available=self.source_totals is not None,events=list(self.events),event_count=len(self.events),bytes=self.bytes,closed=self.closed,acceptance=False,updater_acceptance=False,hardware='NOT_RUN')
 def close(self):
  if not self.closed:
   try:os.fsync(self.fd)
   finally:os.close(self.fd);self.closed=True

def from_args(args):
 selection=Path('/workspace/selection.json');need(selection.is_absolute()and selection==selection.resolve()and not any(p.is_symlink()for p in(selection,*selection.parents)),'source-bound capacity selection path')
 raw=selection.read_bytes();need(len(raw)<=2*1024**2,'bounded capacity selection');s=json.loads(raw)
 capacity=s['capacity'];need(capacity['purpose']==PURPOSE and capacity['profile_sha256']==PROFILE_SHA256 and capacity['implementation']=='fixed-statx-input-candidate','explicit capacity purpose/profile/implementation')
 current=s['current607'];need(set(current)=={'source','run','attempt','ref','page_profile'}and re.fullmatch('[0-9a-f]{40}',current['source'])and re.fullmatch('[1-9][0-9]*',current['run'])and current['attempt']=='1'and current['ref'].startswith('refs/heads/codex/')and current['page_profile']=='generic16k','exact source/run/ref generic16K context')
 need(re.fullmatch('[0-9a-f]{32}',s['nonce'])and s['kernel']['release']=='7.1.13-generic16k-managed-gui'and os.sysconf('SC_PAGE_SIZE')==16384 and os.uname().release==s['kernel']['release'],'actual capacity guest kernel/page identity')
 identity=dict(current607=current,nonce=s['nonce'],purpose=PURPOSE,implementation='fixed-statx-input-candidate',kernel=s['kernel']['release'],page_size=16384)
 return Trace(Path(args.data)/'capacity-events.jsonl',identity)
