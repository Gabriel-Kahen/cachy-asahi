# SPDX-License-Identifier: MIT
"""Explicit current-onboarding host prerequisite; no action on import.

Root must separately select this proposal and enter its dedicated finite scope.
The pinned Fish plan owns the nine normal signed APT commands, not target ALPM.
"""
import ast
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import resource
import signal
import stat
import subprocess
import time
from types import FunctionType, SimpleNamespace

API = 'CURRENT_ONBOARDING_HOST_PREREQUISITES_V3'
DONORS = {
 'host_prerequisite_plan': (13845, '4bef653f0e999876e8dd1e74e7d61b808182f7528f4f50ce6444e14f6ff33d64'),
 'host_prerequisite_tools': (5273, '5f980d2df87cebdf264167e7be7220485a6fcc555667782d31316da0d08aef72'),
 'host_prerequisite_runner_basis': (31464, '7f4d2a68f13a2439a4363cfb154553dc9e721a88dc985080dd290d44583ad634')}
OWNED_SHA = '83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'
SCOPE = {'memory.max': '536870912', 'memory.swap.max': '0', 'cpu.max': '100000 100000', 'pids.max': '64'}
PROPOSAL = dict(kind=API, scope_seconds=495, work_seconds=450, observation_seconds=15,
 cleanup_seconds=30, controller_AS_bytes=512*1024**2, controller_CPU_seconds=500,
 core_bytes=0, scope_limits=SCOPE, output_bytes=16*1024**2, output_nodes=64,
 minimum_free_bytes=784*1024**2, minimum_free_nodes=4288,
 prerequisite_plan_sha256=DONORS['host_prerequisite_plan'][1], Root_acceptance=None)
FINAL = dict(Root_acceptance=None, Root_final_acceptance=None, independent_component_acceptance=False,
 hardware_acceptance=False, release_acceptance=False)


def need(ok, why):
 if not ok: raise ValueError(why)
def pin(raw): return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
def encoded(value): return (json.dumps(value, sort_keys=True, allow_nan=False)+'\n').encode()
def decode(raw):
 def pairs(rows):
  result={}
  for key,value in rows: need(key not in result, 'duplicate JSON key'); result[key]=value
  return result
 return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: need(False,'nonfinite JSON'))
def read(path, cap=128*1024):
 path=Path(path); need(path.is_absolute() and path==path.resolve() and not any(p.is_symlink() for p in (path,*path.parents)), 'ordinary canonical input')
 fd=os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  a=os.fstat(fd); need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and not a.st_mode&0o022 and 0<a.st_size<=cap, 'bounded ordinary input')
  raw=os.read(fd,cap+1)
  key=lambda s:(s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
  need(len(raw)==a.st_size and key(a)==key(os.fstat(fd))==key(path.lstat()), 'stable whole input'); return raw
 finally: os.close(fd)
def body(root, row):
 need(type(row)is dict and set(row)=={'member','bytes','sha256'}, 'exact Source descriptor')
 member=Path(row['member']); need(not member.is_absolute() and member.as_posix()==row['member'] and all(x not in ('','.','..') for x in member.parts), 'closed Source member')
 need(type(row['bytes'])is int and row['bytes']>0 and type(row['sha256'])is str and re.fullmatch('[0-9a-f]{64}',row['sha256']), 'typed descriptor pin')
 raw=read(root/member); need(pin(raw)=={k:row[k] for k in ('bytes','sha256')}, 'whole Source program pin'); return raw

def module(raw, name, filename):
 result=SimpleNamespace(__file__=str(filename), __name__=name)
 exec(compile(raw,str(filename),'exec'),result.__dict__); return result

def selected(root, d, role):
 row=d['programs'][role]; return module(body(root,row), 'current_prerequisite_'+role, root/row['member'])

def write(path, value):
 raw=encoded(value); need(len(raw)<=1024**2,'bounded public receipt')
 path=Path(path); temporary=path.with_suffix('.partial')
 if path.exists():
  s=path.lstat(); need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600,'same owned receipt')
 fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 try:
  with os.fdopen(fd,'wb') as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
  os.replace(temporary,path)
 finally:
  if temporary.exists(): temporary.unlink()


def current_context(env, machine, release, uid, expected, record=None):
 """Truthful onboarding identity; never project an onboarding job into Fish."""
 need(type(release)is bytes and len(release)<=16384,'bounded os-release')
 values={}
 for line in release.decode('utf-8').splitlines():
  if line.split('=',1)[0] not in ('ID','VERSION_ID'): continue
  match=re.fullmatch(r'(ID|VERSION_ID)=(?:"([A-Za-z0-9._-]{1,32})"|([A-Za-z0-9._-]{1,32}))',line)
  need(match is not None and match[1] not in values,'unambiguous os-release'); values[match[1]]=match[2] or match[3]
 public={key:env.get(key) if env.get(key)==value else None for key,value in expected.items()}
 checks=dict(root=type(uid)is int and uid==0, machine=machine in ('aarch64','arm64'),
  ubuntu24=values==dict(ID='ubuntu',VERSION_ID='24.04'), public_identity=public==expected)
 facts=dict(kind='CURRENT_ONBOARDING_PUBLIC_HOST_CONTEXT_V3', machine=machine if machine in ('aarch64','arm64') else None,
  os_release=values, environment=public, checks=checks, reason_codes=[k for k,v in checks.items() if not v], **FINAL)
 if record: record(facts)
 need(all(checks.values()),'Ubuntu24 ARM64 actual current CI identity required'); return facts


def scope_observation(E, domain, raw, nonce):
 expected='/system.slice/cachy-current-prerequisites-'+nonce+'.scope'
 need(domain['cgroup']==expected and domain['limits']==SCOPE and domain['pid']==os.getpid() and domain['starttime']>0,'same actual finite prerequisite kernel domain')
 rows=raw.decode('ascii').splitlines(); need(len(rows)==3 and all('=' in row for row in rows),'complete scope properties')
 props=dict(row.split('=',1) for row in rows)
 need(set(props)=={'RuntimeMaxUSec','ActiveEnterTimestampMonotonic','ControlGroup'} and props['ControlGroup']==expected,'exact current prerequisite scope')
 entered=props['ActiveEnterTimestampMonotonic']; need(entered.isdecimal() and int(entered)>0,'actual scope activation clock')
 runtime=E.runtime_microseconds(props['RuntimeMaxUSec']); need(runtime==495*1000000,'explicit exact495s prerequisite scope')
 end=int(entered)/1000000+495; need(end-time.monotonic()>=480,'remaining work and cleanup reservation')
 return dict(domain=domain,properties=props),end


class Tools:
 def __init__(self,E,H): self.E,self.H=E,H
 def probe_all(self): return self.E.probe_tools()
 def inspect(self,path): return self.H.inspect(path)
 def checked(self,row):
  return self.H.checked(row) if Path(row['candidate']).name in ('apt-get','apt-cache','dpkg','dpkg-query') else self.E.checked_tool(row)


class Owner:
 def __init__(self,Q,H,O,out,end,runner):
  self.Q,self.H,self.O,self.out,self.end,self.runner=Q,H,O,out,end,runner
  self.tools={}; self.commands=[]; self.policy={'host_prerequisites':Q.DECLARATION}
 def tool(self,name): return self.H.checked(self.tools[name])
 def record_prerequisite(self,report): write(self.out/'prerequisite.json',report)
 def run_prerequisite(self,*args):
  need(len(self.commands)<10,'at most one scope observation and nine prerequisite commands')
  self.O.prepare() # Fresh exclusive held custody before each Popen.
  return self.runner(self,*args)


def runner_from(raw,Q,H):
 tree=ast.parse(raw); classes=[n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Controller']
 need(len(classes)==1,'literal audited controller')
 nodes=[n for n in classes[0].body if isinstance(n,ast.FunctionDef) and n.name=='run_prerequisite']
 need(len(nodes)==1,'literal audited prerequisite runner')
 namespace=dict(D=SimpleNamespace(need=need,pin=pin),Q=Q,H=H,write=write,
  resource=resource,math=math,subprocess=subprocess,os=os,time=time)
 exec(compile(ast.Module(body=nodes,type_ignores=[]),'<whole-pinned Fish prerequisite runner>','exec'),namespace)
 return namespace['run_prerequisite']


def finish(owner,deadline):
 """Remove only finite new cache/logs; retain one public, bounded receipt."""
 owner.Q.cleanup(owner.out,deadline,owner.Q.DECLARATION)
 leaves=list(owner.out.iterdir()); need(len(leaves)<=64,'finite prerequisite output nodes')
 total=0
 for leaf in leaves:
  s=leaf.lstat(); need(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and not leaf.is_symlink(),'ordinary owned output')
  total+=s.st_size; need(total<=16*1024**2 and time.monotonic()<deadline,'finite prerequisite output cleanup')
  if leaf.name!='prerequisite.json':
   need(re.fullmatch(r'command-[0-9]{3}\.(bin|json)',leaf.name),'only literal owned command output'); leaf.unlink()
 return True


def prepare_host_prerequisites(*, source_root, delegation_raw, delegation_sha256, context, environment, output):
 """Execute only after Root review and caller-owned dedicated scope entry.

 No default grants, Source exports, network acquisition or privilege escalation.
 Returns a provisional CI-only receipt; installed host package is not removed.
 """
 need(type(delegation_raw)is bytes and len(delegation_raw)<=1024**2 and pin(delegation_raw)['sha256']==delegation_sha256,'external Root delegation pin')
 root=Path(source_root); preview=decode(delegation_raw)
 C=selected(root,preview,'context'); d=C.validate_delegation(delegation_raw,delegation_sha256)
 C.source(d,root); C.validate_context(d,context)
 need(d['expires_epoch']-time.time()>=495,'fresh delegation covers complete prerequisite domain')
 need(context['source_root']==str(root) and context['binding']==dict(context['binding'],source=d['binding']['source'],ref=d['binding']['ref']),'actual selected Source context')
 need(d['capability'].get('allow_host_prerequisites')is True,'explicit conditional host-prerequisite authorization')
 need(pin(read(Path(__file__).resolve()))=={k:d['programs']['host_prerequisites'][k] for k in ('bytes','sha256')},'executing reviewed helper')
 policy=decode(body(root,d['policy'])); need(policy['host_prerequisites_current_v3']==PROPOSAL,'separate exact reviewed prerequisite proposal')
 donor={role:body(root,d['programs'][role]) for role in DONORS}
 for role,(size,digest) in DONORS.items(): need(pin(donor[role])==dict(bytes=size,sha256=digest),'exact audited Fish013c donor '+role)
 Q=module(donor['host_prerequisite_plan'],'current_apt_plan',root/d['programs']['host_prerequisite_plan']['member'])
 H=module(donor['host_prerequisite_tools'],'current_apt_tools',root/d['programs']['host_prerequisite_tools']['member'])
 E=selected(root,d,'image_executor')
 need(E.API=='CURRENT_ONBOARDING_IMAGE_EXECUTOR_V3' and len(E.NAMES)==16 and len(set(E.NAMES))==16,'complete current sixteen-tool observer API')
 need(pin(body(root,d['programs']['owned_process']))['sha256']==OWNED_SHA,'held custody unchanged')
 O=selected(root,d,'owned_process')
 need(os.getuid()==os.geteuid()==0,'root-only scoped prerequisite')
 for name,cap in [(resource.RLIMIT_AS,512*1024**2),(resource.RLIMIT_CPU,500),(resource.RLIMIT_CORE,0)]:
  soft,hard=resource.getrlimit(name); need(0<=soft<=hard<=cap,'actual finite prerequisite controller rlimit')
 need(re.fullmatch('[0-9a-f]{64}',d['nonce']),'exact reviewed nonce')
 domain=E.kernel_domain(os.getpid()); expected='/system.slice/cachy-current-prerequisites-'+d['nonce']+'.scope'
 need(domain['cgroup']==expected and domain['limits']==SCOPE,'kernel prerequisite domain before any command')
 out=Path(output); need(out.is_absolute() and out==out.resolve() and out.name=='cachy-current-prerequisites-'+d['nonce'] and not out.exists(),'fresh exact owned output')
 out.parent.mkdir(exist_ok=True); parent=out.parent.stat(); need(parent.st_uid==0 and not parent.st_mode&0o022,'root-owned output parent')
 v=os.statvfs(out.parent); need(v.f_bavail*v.f_frsize>=PROPOSAL['minimum_free_bytes'] and v.f_favail>=PROPOSAL['minimum_free_nodes'],'finite real prerequisite capacity')
 out.mkdir(mode=0o700)
 T=Tools(E,H); owner=Owner(Q,T,O,out,time.monotonic()+465,runner_from(donor['host_prerequisite_runner_basis'],Q,T))
 cleanup_end=time.monotonic()+495
 def cancel(signum,frame): raise KeyboardInterrupt('prerequisite cancellation')
 old={sig:signal.signal(sig,cancel) for sig in (signal.SIGINT,signal.SIGTERM)}
 try:
  facts=T.probe_all(); need(set(facts['missing_or_invalid'])<={'bsdtar'},'only libarchive-tools may be missing')
  owner.tools={n:r['selected'] for n,r in facts['tools'].items() if r['selected'] is not None}
  cache=out/Q.CACHE; cache.mkdir(mode=0o755)
  _,raw=owner.run_prerequisite([owner.tool('systemctl'),'show',expected.rsplit('/',1)[1],'--no-pager','--property=RuntimeMaxUSec,ActiveEnterTimestampMonotonic,ControlGroup'],15,True,owner.end,cache,Q.DECLARATION)
  observation,cleanup_end=scope_observation(E,domain,raw,d['nonce']); finish(owner,min(cleanup_end,time.monotonic()+30))
  owner.end=min(time.monotonic()+450,cleanup_end-30)
  b=context['binding']; hosted=context['hosted']
  expected_env=dict(GITHUB_ACTIONS='true',RUNNER_OS='Linux',RUNNER_ARCH='ARM64',GITHUB_REPOSITORY=hosted['GITHUB_REPOSITORY'],
   GITHUB_EVENT_NAME='workflow_dispatch',GITHUB_RUN_ATTEMPT='1',GITHUB_RUN_ID=str(b['run']),GITHUB_SHA=b['source'],GITHUB_REF=b['ref'],GITHUB_JOB=hosted['GITHUB_JOB'])
  guard=lambda env,machine,release,uid,record=None:current_context(env,machine,release,uid,expected_env,record)
  plan=FunctionType(Q.prepare.__code__,dict(Q.__dict__,context=guard),Q.prepare.__name__,Q.prepare.__defaults__)
  report=plan(owner,environment,platform.machine())
  report.update(api=API,binding=b,delegation_pin=pin(delegation_raw),scope_observation=observation,tool_count=len(report['tools_after']['tools']),**FINAL)
  owner.record_prerequisite(report); return report
 finally:
  try: finish(owner,cleanup_end)
  finally:
   for sig,handler in old.items(): signal.signal(sig,handler)
