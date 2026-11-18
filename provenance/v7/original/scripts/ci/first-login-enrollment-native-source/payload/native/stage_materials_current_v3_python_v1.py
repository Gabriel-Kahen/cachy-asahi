# SPDX-License-Identifier: MIT
"""Versioned c640 successor: audited canonical tool selection, unchanged staging contract.

No package installation, signature authentication, native build or authority.
"""
import argparse
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import resource
import shutil
import signal
import ssl
import stat
import subprocess
import sys
import time
from types import ModuleType
from urllib.parse import urljoin, urlsplit

API='CURRENT_COMPLETE517_MATERIAL_STAGING_V3'
IMPLEMENTATION='ROOT_QUALIFIED_CANONICAL_PYTHON_V1'
FAMILY='scripts/ci/first-login-enrollment-native-source'
OWNED_SHA='83444522f4dfede67f6965ea75de8411b9e34510c04d40571fe439c223294e8f'
PROVIDER_SHA='9e35c3ae6c3e1e9596f54806279d05cc77ae6a2cb5fb284d469df549e1d3abc6'
SCOPE={'memory.max':'536870912','memory.swap.max':'0','cpu.max':'100000 100000','pids.max':'64'}
PROPOSAL=dict(kind=API,whole_budget_seconds=7560,staging_seconds=3600,cleanup_seconds=30,
 controller_AS_bytes=2147483648,controller_CPU_seconds=3600,context_age_seconds=7560,initial_metadata_queries=1,scope_limits=SCOPE,
 storage_bytes=8*1024**3,storage_nodes=20000,storage_minimum_free_bytes=6*1024**3,command_rows=27,python_spawn_ceiling=2400,child_output_bytes=131072,
 file_bytes=2*1024**3+128*1024**2,download_requests=63,download_redirects=42,download_seconds=90,
 transport_policy=dict(fetch_seconds=400,transport_seconds=480,outer_seconds=500,
 reason='Explicit one-fetch allocation for full retained DATA; no measured latency guarantee'),Root_acceptance=None)
FINAL=dict(Root_final_acceptance=None,independent_component_acceptance=False,hardware_acceptance=False,release_acceptance=False)
FAILURE_KIND='CURRENT_MATERIAL_STAGE_FAILURE_V1'
FAILURE_BYTES=1024
FAILURE_PHASES=('ENTRY','AUTHORIZE','SOURCE','NATIVE_CONTEXT','INPUTS','HELPERS','TOOLS','STORAGE','SCOPE','TRANSPORT_PUBLIC14','TRANSPORT_NATIVE248','PRIVATE_SEED','PUBLIC14_PREPARE','NATIVE248_PREPARE','DOWNLOAD','COMPLETE517','FINALIZE','CHILD')
FAILURE_REASONS=('PHASE_FAILED','COMMAND_FAILED')
# Exact Source139 parent helpers. Preserve paths: their original relative imports
# and canonical/owned-process resolution must not resolve outside reviewed code.
HELPERS={
 'private_seed':('bootstrap/scripts/ci/old_four_seed.py','a14e0318549d24a9bc91ceeb03ec2c1fa2d12f2b3a4f9b0a4cccfb64be34b2b7'),
 'retained_prepare':('bootstrap/scripts/ci/setup6-retained-helpers/prepare.py','6c688c315cb962c641b8c0b1d9d88f94778d57ae19bcef251e88e49cb4be6316'),
 'retained_prefill':('bootstrap/scripts/ci/setup6-retained-helpers/legacy_prefill.py','05a91a91efd69b3b2e06561f5bbf08bdbb105998d42dbf133e75fd1fe25945ac'),
 'material_transport':('native/retained_transport.py','46708771ccb93bbfe22c4f449f3a54052bc9494c4fb572e10b0853b5aa47bdef'),
 'retained_transport_core':('scripts/maintenance/retained_git_transport.py','9b90c423fd67c261d8be1dddd8450df5b927b6dbaba9972c4daff8c0da2836b7'),
 'owned_process':('scripts/virtual/owned_process.py',OWNED_SHA),
 'base_inputs':(FAMILY+'/payload/native/base_inputs_current_v3.py',PROVIDER_SHA)}
MATERIALS={
 'retained_carrier_profile':('bootstrap/scripts/ci/setup6-retained-helpers/carrier-profile.json','4089fd798849cafda23d03c0dd95ac896a83fd63ad21e331ae420c147535586c'),
 'retained_prefill_profile':('bootstrap/scripts/ci/setup6-retained-helpers/legacy-prefill-profile.json','9cc82d4e0947415ecad9d40094a4c0a2709d01be54513e78af8c739fd76fb696')}
PUBLIC_SOURCE='04a4a74e16e1e1bc939ea74791bf1f1bf7b46bbd'
NATIVE_SOURCE='ddc6ca5f3478f9c607f8fae52661c451ae0bf3ad'
PUBLIC_SEED='a7857658af224984065e575f6ffed8308ea85027d46eace8bda146d9033e93b3'
PUBLIC_INDEX='a388c8c8ba8e06cb92fd2be598b86e433c4e403b6e71a0f15b1eaec381bb7300'
PUBLIC14_FILES={'README.md': {'bytes': 8216, 'sha256': 'fd4be1f1c311423f81349fd4fbb194fb255ce413d3116ff8d7abe30c7c292cd5'}, 'index.json': {'bytes': 2740, 'sha256': 'a388c8c8ba8e06cb92fd2be598b86e433c4e403b6e71a0f15b1eaec381bb7300'}, 'inputs/curl-8.22.0-1-aarch64.pkg.tar.xz': {'bytes': 1281188, 'sha256': '5461bb97fca88b237d17db833622789eedca390634a6d2fb2e3b71287e52acb2'}, 'inputs/curl-8.22.0-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'sha256': '2523ff1b88dfc1ed910ad90d44c04387a86c397bf8043b518cad1c33dd9524e8'}, 'inputs/libarchive-3.8.9-1-aarch64.pkg.tar.xz': {'bytes': 513496, 'sha256': '030848f1d81d2558f3efacbf7d435f53f8809266c22d4744354ed90f8f46fe4d'}, 'inputs/libarchive-3.8.9-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'sha256': 'f8153448fa459fe3fd7eb65f0741b14352af77f9d32634b49f85bba5fc68f247'}, 'inputs/openssh-10.6p1-1-aarch64.pkg.tar.xz': {'bytes': 1228712, 'sha256': '28522c0cb098994889b8186315f7629bf1d75931487f16a237dd3e93bbdbaa10'}, 'inputs/openssh-10.6p1-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'sha256': '2b6ebf8553f7b10ba22f768adc7dbcbd00ce983364a0000f85ed13d11cb44ac1'}, 'inputs/pacman-7.1.0.r9.g54d9411-2-aarch64.pkg.tar.xz': {'bytes': 904012, 'sha256': '0e7a5a731727b50e5453f9946afed63456ca6d7015ec0044426489dc78134e3d'}, 'inputs/pacman-7.1.0.r9.g54d9411-2-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'sha256': '86824e704f0f19a7e065b63a8e553c9cadf3b4c49dbeb3f367435d2f557ac26f'}, 'inputs/uwsm-0.27.0-1-any.pkg.tar.xz': {'bytes': 87248, 'sha256': 'd7efdda151008fa354ade5276b8ff92f9682c63f9a749304ae91ccd36cf19549'}, 'inputs/uwsm-0.27.0-1-any.pkg.tar.xz.sig': {'bytes': 566, 'sha256': '651f3022fc7b4e78e698685d2ae89c85f45935e55e1f453b78bf84148f5ac767'}, 'inputs/xorg-server-common-21.1.25-1-aarch64.pkg.tar.xz': {'bytes': 27344, 'sha256': '6cc9149138662041aa13c6ec027c074c67ee411848e38c349232acd9d97fca98'}, 'inputs/xorg-server-common-21.1.25-1-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'sha256': 'cb12e8a377cd9a8f4718faa270f7b5ca0834e7b72b70c073338f57bfea31b4d3'}, 'inputs/zlib-1:1.3.2-3-aarch64.pkg.tar.xz': {'bytes': 77320, 'sha256': '7e31b465e09e8e61375578b8e26ed883906e126e0c0ef1c75b7ccccfa95a58c4'}, 'inputs/zlib-1:1.3.2-3-aarch64.pkg.tar.xz.sig': {'bytes': 566, 'sha256': 'ec8d454359ded82cd5dfe368de1cb16303e88ca2b180fba9bcb44ba75a6a7e9d'}, 'seed.py': {'bytes': 3834, 'sha256': 'a7857658af224984065e575f6ffed8308ea85027d46eace8bda146d9033e93b3'}, 'test_seed.py': {'bytes': 5439, 'sha256': '723820e2b1bcea3f038f14def03b1adaf84ca8fe0def57556ac3b752455bc005'}}


def need(ok,why):
 if not ok:raise ValueError('HOLD_MATERIALS: '+why)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def diagnostic_phase(diagnostic,phase):
 if diagnostic is not None:
  need(type(phase)is str and phase in FAILURE_PHASES,'fixed failure phase')
  diagnostic.update(phase=phase,reason='PHASE_FAILED',command_ordinal=None)
def diagnostic_command(diagnostic,ordinal):
 if diagnostic is not None:
  diagnostic.update(reason='COMMAND_FAILED',command_ordinal=ordinal if type(ordinal)is int and 0<=ordinal<27 else None)
def failure_packet(diagnostic):
 need(type(diagnostic)is dict and set(diagnostic)=={'phase','reason','command_ordinal'},'closed failure diagnostic')
 ordinal=diagnostic['command_ordinal']
 need(type(diagnostic['phase'])is str and diagnostic['phase']in FAILURE_PHASES and type(diagnostic['reason'])is str and diagnostic['reason']in FAILURE_REASONS
      and(ordinal is None or type(ordinal)is int and 0<=ordinal<27),'finite failure diagnostic values')
 raw=encoded(dict(schema=1,kind=FAILURE_KIND,**diagnostic));need(len(raw)<=FAILURE_BYTES,'failure packet bound');return raw
def emit_failure(diagnostic,error=None):
 # Best effort only: failure to report must never mask the original exception.
 try:
  raw=failure_packet(diagnostic);stream=getattr(sys.stderr,'buffer',None)
  written=stream.write(raw)if stream is not None else sys.stderr.write(raw.decode('ascii'))
  if written!=len(raw):return False
  (stream if stream is not None else sys.stderr).flush()
  if error is not None:error._current_material_failure_emitted=True
  return True
 except BaseException:return False
def decoded(raw):
 def pairs(rows):
  result={}
  for k,v in rows:need(k not in result,'duplicate JSON key');result[k]=v
  return result
 return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite DATA'))
def identity(s):return tuple(getattr(s,k)for k in('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))
def read(path,cap=2*1024**2):
 p=Path(path);need(p.is_absolute()and p==p.resolve()and not any(q.is_symlink()for q in(p,*p.parents)),'canonical nonaliased DATA')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
 try:
  s=os.fstat(fd);need(stat.S_ISREG(s.st_mode)and s.st_nlink==1 and not s.st_mode&0o022 and 0<=s.st_size<=cap,'ordinary bounded DATA')
  with os.fdopen(os.dup(fd),'rb')as stream:raw=stream.read(cap+1)
  need(len(raw)==s.st_size and identity(s)==identity(os.fstat(fd))==identity(p.lstat()),'stable whole DATA');return raw
 finally:os.close(fd)
def descriptor(root,row):
 need(type(row)is dict and set(row)=={'member','bytes','sha256'},'Source descriptor')
 p=Path(row['member']);need(not p.is_absolute()and p.as_posix()==row['member']and all(n not in('','.','..')for n in p.parts),'Source-relative descriptor')
 raw=read(root/p);need(type(row['bytes'])is int and row['bytes']>0 and pin(raw)=={k:row[k]for k in('bytes','sha256')},'whole nonempty Source descriptor');return raw
def module(path,raw):
 m=ModuleType('current_staging_'+path.stem);m.__file__=str(path);exec(compile(raw,str(path),'exec'),m.__dict__);return m
def selected(root,d,role):
 need(role in d.get('programs',{}),'missing Source helper '+role)
 row=d['programs'][role];return module(root/row['member'],descriptor(root,row))
def write(path,value):
 raw=encoded(value);need(len(raw)<=2*1024**2,'bounded public receipt')
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb')as f:f.write(raw)
def secret_names():
 names=['CACHY_OLD_FOUR_'+tag+'_%02d'%i for tag,count in(('JBIGKIT',2),('JBIGKIT_SIG',1),('LIBTIFF',15),('LIBTIFF_SIG',1))for i in range(1,count+1)]
 return names+['CACHY_RETAINED_BUBBLEWRAP_V1_PACKAGE_01','CACHY_RETAINED_BUBBLEWRAP_V1_PACKAGE_02','CACHY_RETAINED_BUBBLEWRAP_V1_SIGNATURE_01']
class OneShotSecrets:
 """Own exactly22 explicit values; never look up an environment/credential."""
 def __init__(self,values):
  need(type(values)is dict and set(values)==set(secret_names())and all(type(v)is str and 0<len(v)<=32768 for v in values.values()),'explicit exact22 values required')
  self.values=values
 def close(self):
  if self.values is not None:self.values.clear();self.values=None
 def __call__(self,names):
  need(tuple(names)==tuple(secret_names())and self.values is not None,'single exact22 consumption only')
  values=self.values;self.values=None;return values


def public_url(value):
 u=urlsplit(value);need(u.scheme=='https'and u.hostname and u.port in(None,443)and not(u.username or u.password or u.query or u.fragment)and len(value)<=2048,'fixed public HTTPS URL');return value


def public14_profile():
 return dict(schema=1,actual=None,source=PUBLIC_SOURCE,ref=PUBLIC_SOURCE,files=PUBLIC14_FILES)


def validate_grant(raw,sha,d,context,policy):
 need(type(raw)is bytes and len(raw)<=65536 and pin(raw)['sha256']==sha,'external Root staging grant whole pin')
 g=decoded(raw);need(raw==encoded(g)and set(g)=={'schema','kind','issuer','approved','source','ref','source_lock','nonce','policy','issued_epoch','expires_epoch','redirect_urls','secret_provider','scope','storage_parent'},'exact Root conditional staging schema')
 need(type(g['schema'])is int and g['schema']==3 and g['kind']=='ROOT_CURRENT_COMPLETE517_STAGING_V3'and g['issuer']=='Root'and g['approved']is True,'actual Root staging authorization required')
 b=context['binding'];need(all(g[k]==b[k]for k in('source','ref','source_lock'))and g['nonce']==d['nonce']and g['policy']=={k:d['policy'][k]for k in('bytes','sha256')},'same actual Source/context/policy')
 need(d['capability'].get('allow_material_staging')is True and policy['material_staging_current_v3']==PROPOSAL,'separate exact Root staging policy')
 need(d['context_limits']['max_context_age_seconds']==7560 and d['context_limits']['max_delegation_seconds']==7560,'explicit reviewed whole-pipeline context lifetime; no old TTL waiver')
 need(type(g['storage_parent'])is str and Path(g['storage_parent']).is_absolute()and Path(g['storage_parent']).name=='cachy-current-material-domain-'+d['nonce'],'explicit Root storage selector')
 need(g['scope']=='COMPLETE517_PUBLIC_DATA_ONLY'and g['secret_provider']=='CALLER_ONE_SHOT_EXACT22'and type(g['redirect_urls'])is dict,'no authority or generic credential provider')
 need(all(type(d[k])is int and type(g[k])is int for k in('issued_epoch','expires_epoch'))and d['issued_epoch']<=g['issued_epoch']<=time.time()<g['expires_epoch']<=d['expires_epoch']
      and 0<d['expires_epoch']-d['issued_epoch']<=7560,'whole pipeline lifetime at most7560; Root expiry not extended')
 return g


def census(root,deadline):
 need(time.monotonic()<deadline,'finite staging deadline');pending=[root];nodes=0;size=0
 while pending:
  p=pending.pop();s=p.lstat();nodes+=1;size+=s.st_blocks*512
  need(nodes<=PROPOSAL['storage_nodes']and size<=PROPOSAL['storage_bytes']and time.monotonic()<deadline,'finite staging allocation/nodes/time')
  need(not p.is_symlink()and(stat.S_ISDIR(s.st_mode)or stat.S_ISREG(s.st_mode)),'ordinary owned staging namespace')
  if p.is_dir():
   for child in p.iterdir():
    need(nodes+len(pending)<PROPOSAL['storage_nodes'],'finite pending nodes');pending.append(child)
 return dict(nodes=nodes,allocated_bytes=size)


def kernel_scope(nonce,expiry):
 proc=Path('/proc/self');raw=(proc/'cgroup').read_text();expected='/system.slice/cachy-current-materials-'+nonce+'.scope'
 need(raw=='0::'+expected+'\n','actual exact selected staging cgroup')
 root=Path('/sys/fs/cgroup'+expected);limits={k:read_kernel(root/k)for k in SCOPE};need(limits==SCOPE,'actual staging kernel512MiB/CPU1/PIDs64/swap0')
 need(resource.getrlimit(resource.RLIMIT_AS)==(2147483648,2147483648)and resource.getrlimit(resource.RLIMIT_CORE)==(0,0),'actual finite controller limits')
 cpu=resource.getrlimit(resource.RLIMIT_CPU);need(0<cpu[0]<=cpu[1]<=3600,'finite controller CPU')
 fields=read_kernel(proc/'stat').rpartition(')')[2].split();starttime=int(fields[19]);need(starttime>0,'actual controller start identity')
 return dict(cgroup=expected,pid=os.getpid(),starttime=starttime,limits=limits,Root_acceptance=None)
def read_kernel(path):
 with path.open('rb')as f:raw=f.read(4097)
 need(len(raw)<=4096,'bounded actual kernel fact');return raw.decode().strip()
def storage_domain(parent,selected,nonce,source):
 need(parent==Path(selected)and parent.is_absolute()and parent==parent.resolve()and parent.name=='cachy-current-material-domain-'+nonce,'exact Root selected storage parent')
 s=parent.lstat();need(stat.S_ISDIR(s.st_mode)and s.st_uid==os.getuid()and stat.S_IMODE(s.st_mode)==0o700 and parent.is_mount()and s.st_dev!=source.stat().st_dev,'owned private separate mounted DATA domain')
 v=os.statvfs(parent);need(0<v.f_blocks*v.f_frsize<=PROPOSAL['storage_bytes']and 0<v.f_files<=PROPOSAL['storage_nodes'],'actual finite filesystem byte/inode ceilings')
 need(v.f_bavail*v.f_frsize>=PROPOSAL['storage_minimum_free_bytes']and v.f_favail>=18000,'actual complete staging free space/nodes')
 return dict(path=str(parent),device=s.st_dev,total_bytes=v.f_blocks*v.f_frsize,total_nodes=v.f_files,free_bytes=v.f_bavail*v.f_frsize,free_nodes=v.f_favail,Root_acceptance=None)


def natural(row):
 need(row['reaped']is True and row['ownership']=='REAPED'and row['group_census']=='EMPTY_TWICE'and row['output_complete']is True and row['signals']==[]and row['timeout']is False and row['error']is None and row['exit']==0,'natural complete command only; no retry/forced acceptance')


def qualified_tools(E):
 # The held inspector validates the fixed candidate, every root-owned alias/
 # ancestor, canonical target and whole body. Its checked return is canonical.
 # A valid python3 -> python3.N alias is not a pathname-equality failure.
 result={}
 for name in('python3','systemctl'):
  row=E.inspect_tool('/usr/bin/'+name)
  need(E.checked_tool(row)==row['path'],'held qualified canonical tool rejoin')
  result[name]=row
 return result


class Runner:
 def __init__(self,O,out,end,E,tools,_diagnostic=None):self.O,self.out,self.end,self.E,self.tools=O,out,end,E,tools;self.rows=[];self._diagnostic=_diagnostic
 def run(self,argv,seconds,*,env=None):
  diagnostic_command(self._diagnostic,len(self.rows))
  need(len(self.rows)<PROPOSAL['command_rows']and type(argv)is list and argv and all(type(a)is str and '\0'not in a for a in argv),'finite direct argv')
  matches=[row for row in self.tools.values()if row['path']==argv[0]]
  need(len(matches)==1 and self.E.checked_tool(matches[0])==argv[0],'immediately rejoined qualified canonical staging executable')
  need(time.monotonic()+seconds<self.end,'entire held original command budget fits shared deadline')
  index=len(self.rows);stdout=self.out/('command-%02d.stdout'%index);stderr=self.out/('command-%02d.stderr'%index)
  child=None;row=None;failure=None;finish=time.monotonic()+seconds
  environment=dict(PATH='/usr/bin:/usr/sbin:/bin',HOME=str(self.out/'empty-home'),LC_ALL='C',PYTHONDONTWRITEBYTECODE='1')
  if env is not None:environment.update(env)
  def limits():
   resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_AS,(PROPOSAL['controller_AS_bytes'],)*2)
   resource.setrlimit(resource.RLIMIT_FSIZE,(PROPOSAL['file_bytes'],)*2)
  with stdout.open('xb')as so,stderr.open('xb')as se:
   try:
    self.O.prepare();child=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=so,stderr=se,cwd=self.out,env=environment,start_new_session=True,preexec_fn=limits)
    while os.waitid(os.P_PID,child.pid,os.WEXITED|os.WNOWAIT|os.WNOHANG)is None:
     census(self.out,finish-2);need(os.fstat(so.fileno()).st_size+os.fstat(se.fileno()).st_size<=131072,'finite child diagnostics');time.sleep(.05)
   except BaseException as error:failure=error
   finally:
    environment.clear()
    if env is not None:env.clear()
    if child is not None:
     left=finish-time.monotonic()
     if left<=0 and failure is None:failure=TimeoutError('original command budget exhausted; retirement only')
     row=self.O.supervise(child,cap=max(.1,left),retirement=min(.4,max(.05,left/2)),grace=.01,streams=(),max_output=0)
  try:
   need(stdout.stat().st_size+stderr.stat().st_size<=131072,'complete bounded diagnostics')
   raw=stdout.read_bytes();record=dict(argv=argv,natural=False,Root_acceptance=None)
   # Never retain raw private-seed stdout/stderr or environment values.
   if failure is not None:raise failure
   natural(row);record['natural']=True;self.rows.append(record);census(self.out,self.end)
   if self._diagnostic is not None:diagnostic_phase(self._diagnostic,self._diagnostic['phase'])
   return raw
  finally:stdout.unlink();stderr.unlink()


def verify_helpers(root,d,plan):
 factory=decoded(read(root/FAMILY/'profile.json'))
 for role,(member,sha)in HELPERS.items():
  need(role in d['programs'],'missing exact Source helper '+role)
  row=d['programs'][role];need(row['member']==member and pin(descriptor(root,row))['sha256']==sha,'missing/different exact helper '+role)
  if role not in('base_inputs','owned_process'):need(factory['parent_files'][member]['sha256']==sha,'helper joins Source139 frozen parent profile')
 for role,(member,sha)in MATERIALS.items():
  need(role in d['materials'],'missing retained Source metadata '+role)
  row=d['materials'][role];need(row['member']==member and pin(descriptor(root,row))['sha256']==sha and factory['parent_files'][member]['sha256']==sha,'exact retained metadata '+role)
 need('public14_profile'in d['materials'],'missing explicit whole public14 profile')
 public=decoded(descriptor(root,d['materials']['public14_profile']))
 need(descriptor(root,d['materials']['public14_profile'])==encoded(public14_profile()),'exact whole public14 source profile; no invented carrier')
 native=decoded(descriptor(root,d['materials']['retained_carrier_profile']))
 need(native['source']==NATIVE_SOURCE and len(native['files'])==1154,'whole original native248/desktop574 carrier')
 return public,native


def validate_local_references(*,provider,source_root,source_map,base_lock,bootstrap_profile,materials):
 """Real offline validation, no acquisition/copy/grant or hosted-delivery claim."""
 need(pin(read(Path(provider.__file__)))['sha256']==PROVIDER_SHA,'exact maintained public DATA provider')
 result=provider.build_selected_references(materials=materials,source_root=source_root,source_map=source_map,base_lock=base_lock,bootstrap_profile=bootstrap_profile)
 return dict(status='COMPLETE517_LOCAL_REFS_DATA_ONLY',references=result,assembler_fields=provider.assembler_fields(result),archive_copies=0,hosted_delivery=False,**FINAL)


def _stage_materials(*,source_root,delegation_raw,delegation_sha256,context,grant_raw,grant_sha256,output,secret_provider,base_lock,bootstrap_profile,_diagnostic=None):
 """Actual runtime entry; caller owns explicit physical scope and final absence.

 Caller supplies Root-authenticated hash inputs and one-shot22-value provider;
 no live environment, token, private home or credential-store lookup occurs here.
 """
 diagnostic_phase(_diagnostic,'ENTRY')
 need(pin(delegation_raw)['sha256']==delegation_sha256 and pin(grant_raw)['sha256']==grant_sha256,'external whole inputs before selected code')
 diagnostic_phase(_diagnostic,'AUTHORIZE')
 root=Path(source_root);preview=decoded(delegation_raw);C=selected(root,preview,'context');d=C.validate_delegation(delegation_raw,delegation_sha256)
 diagnostic_phase(_diagnostic,'SOURCE');C.source(d,root);C.validate_context(d,context)
 need(context['source_root']==str(root),'actual selected GITHUB_WORKSPACE Source root')
 diagnostic_phase(_diagnostic,'AUTHORIZE')
 policy=decoded(descriptor(root,d['policy']));g=validate_grant(grant_raw,grant_sha256,d,context,policy)
 diagnostic_phase(_diagnostic,'SOURCE')
 need(pin(read(Path(__file__).resolve()))=={k:d['programs']['materials_stager'][k]for k in('bytes','sha256')},'actual reviewed stager program')
 diagnostic_phase(_diagnostic,'SCOPE')
 expiry=min(d['expires_epoch'],g['expires_epoch'],d['issued_epoch']+7560);shared_end=time.monotonic()+expiry-time.time();need(shared_end-time.monotonic()>120,'remaining shared budget')
 diagnostic_phase(_diagnostic,'NATIVE_CONTEXT')
 need(os.getuid()==os.geteuid()>0 and os.uname().sysname=='Linux'and os.uname().machine=='aarch64','ordinary native ARM64 hosted staging controller')
 need(type(secret_provider)is OneShotSecrets,'Root caller must supply one-shot exact22 provider before acquisition')
 diagnostic_phase(_diagnostic,'SCOPE')
 domain=kernel_scope(d['nonce'],expiry);B=selected(root,d,'base_inputs')
 source_map=dict(path=str(root/'source-map.json'),**d['binding']['source_lock'])
 diagnostic_phase(_diagnostic,'INPUTS')
 plan=B.metadata(source_root=root,source_map=source_map,base_lock=base_lock,bootstrap_profile=bootstrap_profile)
 diagnostic_phase(_diagnostic,'HELPERS');public,native=verify_helpers(root,d,plan)
 diagnostic_phase(_diagnostic,'TOOLS')
 E=selected(root,d,'image_executor');L=selected(root,d,'hosted_launcher');L.fixed_tool('/usr/bin/git')
 tools=qualified_tools(E)
 diagnostic_phase(_diagnostic,'STORAGE')
 out=Path(output);need(out.is_absolute()and out==out.resolve()and out.name=='cachy-current-materials-'+d['nonce']and not out.exists()and not out.is_relative_to(root)and not root.is_relative_to(out),'fresh exact disjoint domain')
 parent=out.parent;storage=storage_domain(parent,g['storage_parent'],d['nonce'],root)
 out.mkdir(mode=0o700);(out/'empty-home').mkdir(mode=0o700);cache=out/'cache';cache.mkdir(mode=0o700)
 diagnostic_phase(_diagnostic,'TOOLS')
 O=selected(root,d,'owned_process');end=min(shared_end,time.monotonic()+3600)-30;R=Runner(O,out,end,E,tools,_diagnostic)
 diagnostic_phase(_diagnostic,'SCOPE')
 raw=R.run([E.checked_tool(tools['systemctl']),'show','cachy-current-materials-'+d['nonce']+'.scope','--no-pager','--property=RuntimeMaxUSec,ActiveEnterTimestampMonotonic,ControlGroup'],15)
 props=dict(line.split('=',1)for line in raw.decode().splitlines());need(set(props)=={'ControlGroup','RuntimeMaxUSec','ActiveEnterTimestampMonotonic'}and props['ControlGroup']==domain['cgroup']and props['ActiveEnterTimestampMonotonic'].isdigit()and int(props['ActiveEnterTimestampMonotonic'])>0,'actual finite staging scope properties')
 runtime=E.runtime_microseconds(props['RuntimeMaxUSec'])
 physical_end=(runtime+int(props['ActiveEnterTimestampMonotonic']))/1000000
 need(0<runtime<=3600*1000000 and time.monotonic()+30<physical_end<=shared_end,'physical scope cannot extend Root/shared deadline');R.end=min(end,physical_end-30)
 diagnostic_phase(_diagnostic,'INPUTS')
 acquisition=B.acquisition_plan(plan,cache_root=cache,public14_root=out/'public14',retained_root=out/'native248',retained_git=out/'native248/.git',helper_root=root/'bootstrap/scripts/ci/setup6-retained-helpers',deadline=R.end)
 need(acquisition['existing_secret_names']==secret_names(),'unchanged22 secret interface')
 redirects=g['redirect_urls'];downloads=acquisition['remaining_base5_and_supplement8'];need(set(redirects)=={x['filename']for x in downloads},'explicit exact21 redirect selections')
 for row in downloads:
  aliases=redirects[row['filename']];need(type(aliases)is list and len(aliases)<=2 and len(set(aliases))==len(aliases),'finite exact redirect URLs')
  for url in [row['argv'][-1],*aliases]:public_url(url)
 authority=dict(delegation_json=delegation_raw.decode(),delegation_sha256=delegation_sha256,grant_json=grant_raw.decode(),grant_sha256=grant_sha256,context=context)
 request=dict(authority=authority,source_root=str(root),programs=d['programs'],cache=str(cache),deadline=R.end,base_lock=base_lock,transport_policy=PROPOSAL['transport_policy'],public_profile=public,native_profile=native)
 write(out/'child-request.json',request);child_sha=pin(read(out/'child-request.json'))['sha256']
 child=[E.checked_tool(tools['python3']),'-I','-B',str(Path(__file__).resolve())]
 try:
  for which in ('public14','native248'):
   diagnostic_phase(_diagnostic,'TRANSPORT_PUBLIC14'if which=='public14'else'TRANSPORT_NATIVE248')
   R.run([*child,'transport','--request',str(out/'child-request.json'),'--request-sha256',child_sha,'--which',which],500)
  diagnostic_phase(_diagnostic,'PRIVATE_SEED')
  need(callable(secret_provider),'explicit one-shot secret provider required');values=secret_provider(tuple(secret_names()))
  try:
   need(type(values)is dict and set(values)==set(secret_names())and all(type(v)is str and 0<len(v)<=32768 for v in values.values()),'exact bounded22 values, never log contents')
   R.run([*child,'private-seed','--request',str(out/'child-request.json'),'--request-sha256',child_sha],65,env=dict(values,CACHY_OLD_FOUR_SCHEMA='1',CACHY_OLD_FOUR_SOURCE_EPOCH='1791748800'))
  finally:
   if type(values)is dict:values.clear()
  diagnostic_phase(_diagnostic,'PUBLIC14_PREPARE')
  need(pin(read(out/'public14/seed.py'))['sha256']==PUBLIC_SEED and pin(read(out/'public14/index.json'))['sha256']==PUBLIC_INDEX,'immediate public14 helper/index rejoin before execution')
  R.run([E.checked_tool(tools['python3']),*acquisition['public14']['argv'][1:]],30)
  diagnostic_phase(_diagnostic,'NATIVE248_PREPARE')
  R.run([*child,'prepare','--request',str(out/'child-request.json'),'--request-sha256',child_sha],480)
  diagnostic_phase(_diagnostic,'DOWNLOAD')
  for row in downloads:
   request_row=dict(authority=authority,source_root=str(root),programs=d['programs'],base_lock=base_lock,bootstrap_profile=bootstrap_profile,cache=str(cache),filename=row['filename'],url=row['argv'][-1],redirect_urls=redirects[row['filename']],expected=row['whole_pin'],output=str(cache/row['filename']))
   file=out/('download-'+row['filename']+'.json');write(file,request_row)
   R.run([*child,'download','--request',str(file),'--request-sha256',pin(read(file))['sha256']],90);file.unlink()
  diagnostic_phase(_diagnostic,'COMPLETE517')
  result=B.build_references(cache_root=cache,source_root=root,source_map=source_map,base_lock=base_lock,bootstrap_profile=bootstrap_profile)
  fields=B.assembler_fields(result);need(time.monotonic()<R.end,'whole staging and verification within shared deadline')
  diagnostic_phase(_diagnostic,'FINALIZE')
  for name in ('public14','native248','public14-evidence','native248-evidence'):shutil.rmtree(out/name)
  census(out,min(shared_end,physical_end));write(out/'complete517.json',result);write(out/'assembler-fields.json',fields)
  receipt=dict(status='COMPLETE517_HOSTED_CACHE_DATA_ONLY',binding=context['binding'],domain=domain,storage_domain=storage,grant_pin=pin(grant_raw),policy_pin=g['policy'],
   whole_deadline_monotonic=shared_end,Root_expires_epoch=expiry,physical_scope_end_monotonic=physical_end,commands=R.rows,
   verified_files=517,verified_bytes=result['verified_bytes'],cache=str(cache),materialization='UNCHANGED_ORIGINAL_SEEDS_AND_FIXED_PINNED_DOWNLOADS',cache_created_files=517,provider_validation_archive_copies=0,caller_must_prove_scope_retirement_and_absence=True,**FINAL)
  write(out/'staging-receipt.json',receipt);return dict(receipt=receipt,references=result,assembler_fields=fields)
 except BaseException:
  # Preserve original transports' partial-DATA inverse. No foreign/uncertain
  # cleanup or accepted partial cache: caller owns bounded CLOSEONLY disposal.
  write(out/'HOLD.json',dict(status='HOLD_PARTIAL_OWNED_DATA_CLOSEONLY',scope=domain['cgroup'],Root_acceptance=None));raise


def stage_materials(*,source_root,delegation_raw,delegation_sha256,context,grant_raw,grant_sha256,output,secret_provider,base_lock,bootstrap_profile):
 diagnostic=dict(phase='ENTRY',reason='PHASE_FAILED',command_ordinal=None)
 try:
  return _stage_materials(source_root=source_root,delegation_raw=delegation_raw,delegation_sha256=delegation_sha256,context=context,
   grant_raw=grant_raw,grant_sha256=grant_sha256,output=output,secret_provider=secret_provider,base_lock=base_lock,bootstrap_profile=bootstrap_profile,_diagnostic=diagnostic)
 except BaseException as error:
  emit_failure(diagnostic,error);raise
 finally:
  if type(secret_provider)is OneShotSecrets:secret_provider.close()


def child_request(path,sha):
 raw=read(path);need(pin(raw)['sha256']==sha,'external parent-selected whole child request');return decoded(raw)
def child_authority(r):
 root=Path(r['source_root']);a=r['authority'];raw=a['delegation_json'].encode()
 need(pin(raw)['sha256']==a['delegation_sha256'],'child external delegation pin')
 C=selected(root,decoded(raw),'context');d=C.validate_delegation(raw,a['delegation_sha256']);C.source(d,root);C.validate_context(d,a['context'])
 need(a['context']['source_root']==str(root),'child actual Source workspace')
 need(r['programs']==d['programs'],'child helper map equals whole reviewed Source')
 g=validate_grant(a['grant_json'].encode(),a['grant_sha256'],d,a['context'],decoded(descriptor(root,d['policy'])))
 need(pin(read(Path(__file__).resolve()))=={k:d['programs']['materials_stager'][k]for k in('bytes','sha256')},'reviewed child code')
 kernel_scope(d['nonce'],g['expires_epoch']);return root,d,g
def child_main(mode,path,sha,which=None):
 r=child_request(path,sha);root,d,g=child_authority(r)
 budget={'transport':32 if which=='public14'else 1170,'prepare':1160,'private-seed':0,'download':0}[mode];calls=[0]
 def commands(event,args):
  if event=='subprocess.Popen':calls[0]+=1;need(calls[0]<=budget,'literal held descendant command ceiling')
 sys.addaudithook(commands)
 if mode=='download':
  B=selected(root,d,'base_inputs');plan=B.metadata(source_root=root,source_map=dict(path=str(root/'source-map.json'),**d['binding']['source_lock']),base_lock=r['base_lock'],bootstrap_profile=r['bootstrap_profile'])
  row=plan['files'][r['filename']]
  need(r['url']==row['url']and r['expected']=={k:row[k]for k in('bytes','sha256')}and r['redirect_urls']==g['redirect_urls'][r['filename']]and r['output']==str(Path(r['cache'])/r['filename']),'child fetch joins frozen input and exact Root redirect selection')
  return download(r)
 if mode=='transport':
  T=selected(root,r,'material_transport');profile=r['public_profile']if which=='public14'else r['native_profile'];raw=encoded(profile)
  result=T.deliver(root,Path(path).parent/which,Path(path).parent/(which+'-evidence'),raw,pin(raw)['sha256'],policy=r['transport_policy'])
  need(result['status']=='PASS_EXACT_RETAINED_GIT_DATA_ONLY','exact original transport success');return
 if mode=='prepare':
  L=selected(root,r,'retained_prefill');sys.modules['legacy_prefill']=L;P=selected(root,r,'retained_prepare')
  receipt=P.prepare(Path(path).parent/'native248',Path(r['cache']),'native248',Path(r['base_lock']['path']),r['deadline'],Path(path).parent/'native248/.git')
  need(receipt['status']=='EXACT_RETAINED_INPUT_PREPARATION_DATA_ONLY'and receipt['actual']is None,'actual unchanged native248 preparation');return
 if mode=='private-seed':
  P=selected(root,r,'private_seed');P.seed_current_build_cache(Path(r['cache']),'beca39e04e125a0fa72dedab2dd772e048655d80c36c216a031df0a0c3852e8f')
  need(not any(k.startswith(('CACHY_OLD_FOUR_','CACHY_RETAINED_BUBBLEWRAP_V1_'))for k in os.environ),'private child erased all transport values');return
 raise ValueError('literal child mode')


def download(r):
 urls=[public_url(r['url']),*[public_url(u)for u in r['redirect_urls']]];current=urls[0];target=Path(r['output']);need(not target.exists(),'fresh download destination')
 expected=r['expected'];end=time.monotonic()+90;used=set()
 for request_number in range(3):
  need(current in urls and current not in used and time.monotonic()<end,'closed finite nonretry HTTPS request');used.add(current);u=urlsplit(current)
  connection=http.client.HTTPSConnection(u.hostname,443,timeout=min(15,max(.1,end-time.monotonic())),context=ssl.create_default_context())
  try:
   connection.request('GET',u.path or '/',headers={'Accept-Encoding':'identity','User-Agent':'cachy-asahi-complete517-data-v3'})
   response=connection.getresponse()
   if response.status in(301,302,303,307,308):
    current=urljoin(current,response.getheader('Location')or'');need(current in urls and current not in used,'only exact Root-listed redirect URL');continue
   need(response.status==200 and response.getheader('Content-Encoding')in(None,'identity'),'one complete unencoded public body')
   length=response.getheader('Content-Length');need(length is None or length.isdigit()and int(length)==expected['bytes'],'exact declared body length')
   h=hashlib.sha256();count=0
   with target.open('xb')as out:
    while block:=response.read(min(1024**2,expected['bytes']-count+1)):
     count+=len(block);need(count<=expected['bytes']and time.monotonic()<end,'bounded whole download');h.update(block);out.write(block)
   need(dict(bytes=count,sha256=h.hexdigest())==expected,'whole body pin');return
  finally:connection.close()
 raise ValueError('finite redirect budget exhausted')


if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('mode',choices=('transport','prepare','private-seed','download'));p.add_argument('--request',type=Path,required=True);p.add_argument('--request-sha256',required=True);p.add_argument('--which',choices=('public14','native248'));a=p.parse_args()
 try:child_main(a.mode,a.request,a.request_sha256,a.which)
 except BaseException:
  emit_failure(dict(phase='CHILD',reason='PHASE_FAILED',command_ordinal=None));raise SystemExit(2)from None
