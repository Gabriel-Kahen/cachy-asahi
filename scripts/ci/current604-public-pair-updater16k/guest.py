#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Actual16K PID1; original nine-cap child and bounded natural-QEMU protocol."""
import ast,ctypes,errno,json,os,resource,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
import contract as C
import disk,cap_scope

def facts():
 v=dict(x.split(':',1) for x in Path('/proc/self/status').read_text().splitlines() if ':' in x)
 values=[int(v[k].strip(),16) for k in ('CapEff','CapPrm','CapBnd')];C.need(len(set(values))==1,'identical capability sets')
 return dict(mask=values[0],nnp=int(v['NoNewPrivs'].strip()),inh=int(v['CapInh'].strip(),16),amb=int(v['CapAmb'].strip(),16))

def isolate():
 os.setgroups([]);os.setgid(0);os.setuid(0)
 before=facts();C.need(not any(p.is_block_device() for p in Path('/dev').iterdir()) and {p.name for p in Path('/dev').iterdir()}=={'null','zero','random','urandom'},'no raw disk nodes')
 for n in Path('/proc/self/fd').iterdir():
  try:C.need(not n.is_block_device(),'no raw block descriptors')
  except FileNotFoundError:pass
 C.need(not Path('/volume').exists(),'writable raw data alias remains')
 helper=C.load('isolation','/source/scripts/install/local_transaction.py');C.need(ctypes.CDLL(None).prctl(38,1,0,0,0)==0,'NNP before authority reduction');helper.capability_mask=lambda fixture_identity_map=None:C.MASK;helper.reduce_capabilities()
 # Reuse only the source-pinned pure mount/namespace BPF rows. Private GPG
 # AF_UNIX remains usable; no host runtime/socket is staged.
 tree=ast.parse(C.read('/source/scripts/ci/glibc-gnu-provider-installed16k/sandbox.py'));fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='filter_rows')
 namespace=dict(errno=errno,ENOSYS_CALLS=(428,429,430,431,432,433,442),EPERM_CALLS=(33,41,97,117,268,271,280));exec(compile(ast.Module(body=[fn],type_ignores=[]),'held-mount-fence','exec'),namespace);rows=namespace['filter_rows']()
 class Filter(ctypes.Structure):_fields_=[('code',ctypes.c_ushort),('jt',ctypes.c_ubyte),('jf',ctypes.c_ubyte),('k',ctypes.c_uint)]
 class Program(ctypes.Structure):_fields_=[('length',ctypes.c_ushort),('filters',ctypes.POINTER(Filter))]
 filters=(Filter*len(rows))(*(Filter(*r) for r in rows));program=Program(len(rows),filters);C.need(ctypes.CDLL(None).prctl(22,2,ctypes.byref(program),0,0)==0,'source-owned mount/namespace fence')
 after=facts();C.need(after==dict(mask=C.MASK,nnp=1,inh=0,amb=0),'actual original nine-cap NNP worker')
 seccomp=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line);C.need(seccomp['Seccomp'].strip()=='2' and os.getgroups()==[],'observed fence and cleared supplementary groups')
 return dict(before=before,after=after,seccomp=2,uid=os.getuid(),gid=os.getgid(),groups=os.getgroups(),mount_filter_sha256=C.sha(repr(rows).encode()),docker_seccomp='NOT_CLAIMED',private_gpg_ipc='ALLOWED_IN_PRIVATE_GUEST_ONLY',scope='EXACT_ORIGINAL_CALLER_NINE_CAPABILITIES_NO_SYS_ADMIN')

def emit(s,v):
 raw=C.encoded(v);C.need(len(raw)<=2*1024**2,'bounded guest record');print('APPS6_UPDATE16K '+s['nonce']+' '+json.dumps(v,sort_keys=True,separators=(',',':')),flush=True)

def capmap(scope,roots,seconds):
 limits=disk.limits(roots,seconds);policy=scope.mount_policy(Path('/'),Path('/measurement/inspection'),scope.mounts(scope._mount_table()));nodes,_=scope.source_manifest(Path('/'),limits,roots,policy)
 caps=cap_scope.derive(C.read('/source/scripts/apps/file_capabilities.py'),set(policy['observed_mounts'])|scope.RUNTIME)
 return nodes,caps.observe(Path('/'),cap_scope.nodes(nodes),limits)

def boot_readback_diagnostic(s,before,expected,mapping):
 """Existing finite maps only; no values, content, new walk or authority."""
 try:
  common=set(before)&set(expected);changed={n for n in common if before[n]!=expected[n]};missing=set(expected)-set(before);extra=set(before)-set(expected);different=changed|missing|extra;first=min(different)if different else None;fields=[]
  if first in changed:
   fields=sorted(k for k in set(before[first])|set(expected[first])if before[first].get(k)!=expected[first].get(k))
  value=dict(schema_version=1,status='BOOT_READBACK_MISMATCH_DATA_NOT_ACCEPTANCE',nonce=s['nonce'],node_equal=before==expected,cap_hash_equal=C.sha(C.encoded(mapping))==s['capabilities_sha256'],expected_nodes=len(expected),actual_nodes=len(before),missing_nodes=len(missing),extra_nodes=len(extra),changed_nodes=len(changed),first_key=None if first is None else first[:256],first_key_truncated=first is not None and len(first)>256,differing_fields=[k[:64]for k in fields[:32]],field_names_truncated=len(fields)>32,cleanup_authority=False,acceptance_authority=False)
  text=json.dumps(value,sort_keys=True,separators=(',',':'));C.need(len(text.encode())<=3072,'bounded fixed boot readback diagnostic');print('APPS6_BOOT_READBACK_DIAGNOSTIC '+text,flush=True)
 except Exception:pass # Diagnostic loss cannot replace the original predicate.

def caller_failure(s,record,stdout,stderr,error):
 # Failure DATA only. Existing guard below still decides failure and cleanup.
 import base64,math
 try:nonce=s.get('nonce')
 except Exception:return
 if type(nonce)is not str or len(nonce)!=32 or any(c not in '0123456789abcdef'for c in nonce):return
 try:
  keys={'argv','exit_code','seconds','time_limit','output_limit','group_absence_verified','stdout_bytes','stdout_sha256','stderr_bytes','stderr_sha256'}
  C.need(type(record)is dict and set(record)==keys,'exact original worker command fields')
  C.need(record['argv']==['/usr/bin/python3','-I','-B','/runner.py']and type(record['argv'])is list and 1<=len(record['argv'])<=16 and all(type(v)is str and 0<len(v)<=4096 and '\0'not in v for v in record['argv'])and sum(len(v)for v in record['argv'])<=8192,'bounded original worker argv')
  C.need(type(record['exit_code'])is int and type(record['group_absence_verified'])is bool and type(record['seconds'])in(int,float)and math.isfinite(record['seconds'])and 0<=record['seconds']<2**63 and type(record['time_limit'])is int and record['time_limit']==3900 and type(record['output_limit'])is int and record['output_limit']==2*1024**2,'original worker command budgets/result')
  C.need(error is not None or record['exit_code']!=0 or record['group_absence_verified']is not True,'worker diagnostic only for failed original predicate')
  def stream(raw,side,cap):
   C.need(type(raw)is bytes and type(record[side+'_bytes'])is int and len(raw)==record[side+'_bytes']and C.sha(raw)==record[side+'_sha256'],'original captured worker stream pin')
   tail=raw[-cap:]
   return dict(bytes=len(raw),sha256=C.sha(raw),tail_bytes=len(tail),tail_base64=base64.b64encode(tail).decode(),omitted_bytes=len(raw)-len(tail),truncated=len(tail)<len(raw))
  C.need(type(stdout)is type(stderr)is bytes and len(stdout)+len(stderr)<=2*1024**2,'original combined worker capture cap')
  value=dict(schema_version=1,status='FAILED_ORIGINAL_GUEST_CALLER_DATA_NOT_ACCEPTANCE',nonce=nonce,record=record,error_type=None if error is None else type(error).__name__[:64],stdout=stream(stdout,'stdout',4096),stderr=stream(stderr,'stderr',8192),capture_scope='ORIGINAL_RUN_COMMAND_CAPTURE_MAY_BE_PARTIAL_ON_ERROR',cleanup_acceptance='NOT_GRANTED')
  text=json.dumps(value,sort_keys=True,separators=(',',':'));C.need(len(text.encode())<=24*1024,'bounded original worker failure JSON')
 except Exception as failure:text=json.dumps(dict(schema_version=1,status='DIAGNOSTIC_UNAVAILABLE_NOT_ACCEPTANCE',nonce=nonce,error_type=type(failure).__name__[:64]),sort_keys=True,separators=(',',':'))
 try:print('APPS6_UPDATE16K_CALLER_FAILURE '+nonce+' '+text,flush=True)
 except Exception:pass

def forward_caller_failure(s,record,stdout):
 # Source-captured frame DATA only; never an additional regular guest record.
 try:
  nonce=s['nonce'];C.need(type(nonce)is str and len(nonce)==32 and all(x in '0123456789abcdef'for x in nonce),'caller frame nonce')
  C.need(type(stdout)is bytes and len(stdout)<=2*1024**2 and record['argv']==['/usr/bin/python3','-I','-B','/workspace/guest.py','worker']and record['stdout_bytes']==len(stdout)and record['stdout_sha256']==C.sha(stdout),'original captured worker stdout join')
  prefix=('APPS6_UPDATE16K_CALLER_FAILURE '+nonce+' ').encode();lines=[x for x in stdout.splitlines()if x.startswith(prefix)]
  C.need(len(lines)==1 and len(lines[0])<=25*1024,'one bounded original caller frame')
  line=lines[0];value=C.decode(line[len(prefix):]);C.need(value['nonce']==nonce and value['status']in('FAILED_ORIGINAL_GUEST_CALLER_DATA_NOT_ACCEPTANCE','DIAGNOSTIC_UNAVAILABLE_NOT_ACCEPTANCE')and 'worker_capture'not in value,'failure-only original caller data')
  value['worker_capture']=dict(bytes=len(stdout),sha256=C.sha(stdout),frame_offset=stdout.index(line),frame_bytes=len(line),frame_sha256=C.sha(line),scope='SOURCE_CAPTURED_WORKER_STDOUT_FRAME_NOT_FULL_STREAM_EXPORT')
  text=json.dumps(value,sort_keys=True,separators=(',',':'));C.need(len(text.encode())<=32*1024,'bounded forwarded caller data');print(prefix.decode()+text,flush=True)
 except Exception:pass # Missing/invalid diagnostic never changes the original guard.

def worker(s):
 C.need(os.getpid()!=1 and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and os.sysconf('SC_PAGE_SIZE')==16384 and os.uname().release==s['kernel']['release'],'actual generic16K worker')
 isolation=isolate();
 input_map=C.decode(C.read('/workspace/input-map.json',16*1024**2))
 for n,pin in input_map.items():
  p=Path(n);info=p.lstat();C.need(not p.is_symlink() and (info.st_mode&0o7777,info.st_uid,info.st_gid)==(pin['mode'],pin['uid'],pin['gid']),'copied input metadata')
  if pin['type']=='file':C.need(p.is_file() and info.st_nlink==1 and C.row(p)=={k:pin[k] for k in ('bytes','sha256')},'copied input source/content')
  else:C.need(p.is_dir(),'copied input directory')
 scope,roots,_,_=disk.apis();before,mapping=capmap(scope,roots,600)
 expected=C.decode(C.read('/workspace/baseline-nodes.json',64*1024**2))
 if before!=expected or C.sha(C.encoded(mapping))!=s['capabilities_sha256']:boot_readback_diagnostic(s,before,expected,mapping)
 C.need(before==expected and C.sha(C.encoded(mapping))==s['capabilities_sha256'],'complete original boot574 metadata/hash/hardlink/capability map readback')
 env=dict(PATH='/usr/bin:/bin',LC_ALL='C',LANG='C',HOME='/tmp',TMPDIR='/tmp',PYTHONDONTWRITEBYTECODE='1',**s['env'])
 os.environ.clear();os.environ.update(env)
 runner=C.load('supervisor','/source/scripts/ci/glibc-owned-runtime/runner.py')
 record,stdout,stderr,error=runner.run_command(['/usr/bin/python3','-I','-B','/runner.py'],Path('/tmp'),env,3900,2*1024**2)
 Path('/out/updater16k-caller.stdout').write_bytes(stdout);Path('/out/updater16k-caller.stderr').write_bytes(stderr)
 if error is not None or record['exit_code']!=0 or record['group_absence_verified']is not True:caller_failure(s,record,stdout,stderr,error)
 C.need(error is None and record['exit_code']==0 and record['group_absence_verified'] is True,'original caller exit/group absence')
 # The caller writes only after all original helper/groups/source/copy checks.
 raw=C.read('/out/result.json',2*1024**2);caller=C.decode(raw);C.need(caller['status']=='PASS','original caller failed')
 policy=scope.mount_policy(Path('/'),Path('/measurement/inspection'),scope.mounts(scope._mount_table()));reader=C.load('elf_reader','/source/scripts/virtual/generic16k/fixture.py');elf=cap_scope.audit(C.read('/source/scripts/ci/managed-gui-generic16k/elf_audit.py'),set(policy['observed_mounts'])|scope.RUNTIME,Path('/'),reader)
 before_elf=C.decode(C.read('/workspace/boot-elf16k.json',16*1024**2))
 C.need(before_elf['status']==elf['status']=='PASS_STAGED_NATIVE_AARCH64_ELF16K_ALIGNMENT','complete original574 and actual604 native ELF16K audit')
 after,last=capmap(scope,roots,600);C.need(last==mapping,'baseline file capabilities changed or candidate added capabilities')
 C.save('/out/updater16k-worker.json',dict(status='PRIVATE_COMPLETE_WORKER',case=s['case'],caller=caller,child=record,isolation=isolation,source_capabilities_before=C.sha(C.encoded(mapping)),source_capabilities_after=C.sha(C.encoded(last)),elf16k=dict(before=dict(sha256=C.sha(C.encoded(before_elf)),ELFs=len(before_elf['ELF'])),after=dict(sha256=C.sha(C.encoded(elf)),ELFs=len(elf['ELF'])),status=elf['status'],raw_maps='PRIVATE_NOT_EXPORTED'),original_stdout=dict(bytes=len(stdout),sha256=C.sha(stdout)),original_stderr=dict(bytes=len(stderr),sha256=C.sha(stderr))))

def worker_failure(s,record,stdout,stderr,error):
 # Failure DATA only. Existing guard below still decides failure and cleanup.
 import base64,math
 try:nonce=s.get('nonce')
 except Exception:return
 if type(nonce)is not str or len(nonce)!=32 or any(c not in '0123456789abcdef'for c in nonce):return
 try:
  keys={'argv','exit_code','seconds','time_limit','output_limit','group_absence_verified','stdout_bytes','stdout_sha256','stderr_bytes','stderr_sha256'}
  C.need(type(record)is dict and set(record)==keys,'exact original worker command fields')
  C.need(type(record['argv'])is list and 1<=len(record['argv'])<=16 and all(type(v)is str and 0<len(v)<=4096 and '\0'not in v for v in record['argv'])and sum(len(v)for v in record['argv'])<=8192,'bounded original worker argv')
  C.need(type(record['exit_code'])is int and type(record['group_absence_verified'])is bool and type(record['seconds'])in(int,float)and math.isfinite(record['seconds'])and 0<=record['seconds']<2**63 and type(record['time_limit'])is int and record['time_limit']==3900 and type(record['output_limit'])is int and record['output_limit']==2*1024**2,'original worker command budgets/result')
  C.need(error is not None or record['exit_code']!=0 or record['group_absence_verified']is not True,'worker diagnostic only for failed original predicate')
  def stream(raw,side,cap):
   C.need(type(raw)is bytes and type(record[side+'_bytes'])is int and len(raw)==record[side+'_bytes']and C.sha(raw)==record[side+'_sha256'],'original captured worker stream pin')
   tail=raw[-cap:]
   return dict(bytes=len(raw),sha256=C.sha(raw),tail_bytes=len(tail),tail_base64=base64.b64encode(tail).decode(),omitted_bytes=len(raw)-len(tail),truncated=len(tail)<len(raw))
  C.need(type(stdout)is type(stderr)is bytes and len(stdout)+len(stderr)<=2*1024**2,'original combined worker capture cap')
  value=dict(schema_version=1,status='FAILED_ORIGINAL_GUEST_WORKER_DATA_NOT_ACCEPTANCE',nonce=nonce,record=record,error_type=None if error is None else type(error).__name__[:64],stdout=stream(stdout,'stdout',4096),stderr=stream(stderr,'stderr',8192),capture_scope='ORIGINAL_RUN_COMMAND_CAPTURE_MAY_BE_PARTIAL_ON_ERROR',cleanup_acceptance='NOT_GRANTED')
  text=json.dumps(value,sort_keys=True,separators=(',',':'));C.need(len(text.encode())<=32*1024,'bounded original worker failure JSON')
 except Exception as failure:text=json.dumps(dict(schema_version=1,status='DIAGNOSTIC_UNAVAILABLE_NOT_ACCEPTANCE',nonce=nonce,error_type=type(failure).__name__[:64]),sort_keys=True,separators=(',',':'))
 try:print('APPS6_UPDATE16K_WORKER_FAILURE '+nonce+' '+text,flush=True)
 except Exception:pass

def initialize_launcher_clock():
 # Exact existing desktop handoff bounds; PID1 only, before worker capability drop.
 C.need(os.getpid()==1 and os.getuid()==os.geteuid()==0,'privileged owned PID1 clock initialization only')
 raw=Path('/proc/cmdline').read_text();C.need(len(raw)<=65536,'bounded guest clock command line required');prefix='cachy_asahi_updater_epoch='
 rows=[word[len(prefix):]for word in raw.split()if word.startswith(prefix)]
 C.need(len(rows)==1 and rows[0].isascii()and rows[0].isdecimal()and len(rows[0])==10 and str(int(rows[0]))==rows[0],'one canonical launcher UTC epoch required')
 epoch=int(rows[0]);C.need(1700000000<=epoch<2**32,'bounded launcher UTC epoch required');before=time.time_ns();time.clock_settime(time.CLOCK_REALTIME,epoch);after=time.time_ns();C.need(epoch*10**9<=after<(epoch+2)*10**9,'guest realtime clock handoff failed')
 return dict(source='OWNED_QEMU_LAUNCHER_NOT_EXTERNAL_TIME_AUTHORITY',before_ns=before,requested_epoch_s=epoch,after_ns=after)

def main():
 s=C.decode(C.read('/workspace/selection.json'));C.need('caa_apps6_update16k=1' in Path('/proc/cmdline').read_text().split(),'owned16K boot marker')
 for n,pin in s['runner_files'].items():C.need(C.row(Path('/workspace')/n)==pin,'source-pinned guest module')
 if sys.argv[1:]==['worker']:return worker(s)
 C.need(os.getpid()==1 and os.getuid()==os.geteuid()==0 and os.sysconf('SC_PAGE_SIZE')==16384 and os.uname().release==s['kernel']['release'],'actual root16K PID1')
 clock=initialize_launcher_clock()
 before=list(resource.getrlimit(resource.RLIMIT_NOFILE));resource.setrlimit(resource.RLIMIT_NOFILE,(8192,8192));after=list(resource.getrlimit(resource.RLIMIT_NOFILE));C.need(after==[8192,8192],'exact native8192 descriptor budget')
 libc=ctypes.CDLL(None,use_errno=True);C.need(libc.prctl(4,0,0,0,0)==0,'protect privileged PID1')
 emit(s,dict(event='boot',page_size=16384,kernel=os.uname().release,architecture=os.uname().machine,kernel_profile_sha256=C.sha(C.encoded(s['kernel'])),nofile=dict(before=before,after=after),clock=clock))
 runner=C.load('supervisor','/source/scripts/ci/glibc-owned-runtime/runner.py');record,out,err,error=runner.run_command(['/usr/bin/python3','-I','-B','/workspace/guest.py','worker'],Path('/tmp'),dict(PATH='/usr/bin:/bin',LC_ALL='C',HOME='/tmp',TMPDIR='/tmp'),3900,2*1024**2)
 if error is not None or record['exit_code']!=0 or record['group_absence_verified']is not True:
  forward_caller_failure(s,record,out)
  worker_failure(s,record,out,err,error)
 C.need(error is None and record['exit_code']==0 and record['group_absence_verified'] is True,'whole updater worker exit/group absence')
 v=C.decode(C.read('/out/updater16k-worker.json',2*1024**2));v.update(event='result',status=C.PASS,files={n:C.row('/out/'+n) for n in ('result.json','updater16k-worker.json','updater16k-caller.stdout','updater16k-caller.stderr')},page_size=16384,hardware='NOT_RUN',release='NOT_ADMITTED')
 emit(s,v)
 for dest in reversed((*s['bindings'],'/measurement','/workspace','/source')):
  p=subprocess.run(['/usr/bin/umount',dest],capture_output=True,timeout=15);C.need(p.returncode==0 and not os.path.ismount(dest),'actual owned mount retirement')
 emit(s,dict(event='exit',status=C.PASS,cleanup='PASS_OWNED_MOUNTS_RETIRED'))
if __name__=='__main__':
 try:main()
 except BaseException as e:
  print('APPS6_UPDATE16K_ERROR '+type(e).__name__+' '+str(e)[:2048],flush=True)
  if os.getpid()!=1:raise SystemExit(1)
 finally:
  if os.getpid()==1:
   sys.stdout.flush();sys.stderr.flush();os.sync();ctypes.CDLL(None).reboot(0x4321fedc)
