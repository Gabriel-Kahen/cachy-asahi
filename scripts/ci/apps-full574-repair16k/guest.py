#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Actual16K bootstrap and five-cap repair case; no Docker marker fabrication."""
import ast,base64,ctypes,errno,json,os,resource,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C

def emit(s,value):
 raw=C.encoded(value);C.need(len(raw)<=2*1024**2,'bounded nonce guest frame');print('APPS574_REPAIR16K '+s['nonce']+' '+json.dumps(value,sort_keys=True,separators=(',',':')),flush=True)
def worker_failure(s,record,out,err,error):
 """One failure-only bounded original-buffer diagnostic, never authority."""
 if error is None and record['exit_code']==0 and record['group_absence_verified'] is True:return False
 C.need(type(s['nonce'])is str and len(s['nonce'])==32 and all(c in '0123456789abcdef' for c in s['nonce']) and s['case'] in C.CASES,'failure diagnostic nonce/case')
 keys={'argv','exit_code','seconds','time_limit','output_limit','group_absence_verified','stdout_bytes','stdout_sha256','stderr_bytes','stderr_sha256'}
 C.need(type(record)is dict and set(record)==keys and record['argv']==['/usr/bin/python3','-I','-B','/workspace/guest.py','worker'] and type(record['exit_code'])is int and type(record['group_absence_verified'])is bool and 0<record['time_limit']<=3000 and record['output_limit']==2*1024**2,'original fixed worker supervisor record')
 C.need(type(out)is bytes and type(err)is bytes and len(out)+len(err)<=2*1024**2,'unchanged original combined worker output cap')
 streams={}
 for name,raw in (('stdout',out),('stderr',err)):
  C.need(record[name+'_bytes']==len(raw) and record[name+'_sha256']==C.sha(raw),'failure original worker buffer join')
  prefix=raw[:16384];streams[name]=dict(bytes=len(raw),sha256=C.sha(raw),prefix_bytes=len(prefix),prefix_sha256=C.sha(prefix),prefix_base64=base64.b64encode(prefix).decode(),truncated=len(prefix)!=len(raw))
 failure=None
 if error is not None:
  raw=str(error).encode('utf-8','backslashreplace');failure=dict(type=type(error).__name__[:128],utf8_bytes=len(raw),sha256=C.sha(raw))
 value=dict(schema_version=1,event='worker_failure',status='DIAGNOSTIC_ONLY_NOT_ACCEPTANCE_OR_CLEANUP_AUTHORITY',case=s['case'],supervisor=record,streams=streams,error=failure,retirement='ORIGINAL_GROUP_ABSENCE_RECORDED' if record['group_absence_verified'] is True else 'UNKNOWN_GROUP_ABSENCE_NO_CLEANUP_AUTHORITY',acceptance_authority=False,cleanup_authority=False,guest_disk_readback='NOT_ESTABLISHED')
 raw=C.encoded(value);C.need(len(raw)<=65536,'bounded failure-only diagnostic frame')
 print('APPS574_REPAIR16K_FAILURE '+s['nonce']+' '+json.dumps(value,sort_keys=True,separators=(',',':')),flush=True);return True

def lifecycle_failure(s,record,out,err,error):
 """Original inner-child receipt and bounded stderr only; no map/readback authority."""
 if error is None and record['exit_code']==0 and record['group_absence_verified'] is True:return False
 C.need(type(s['nonce'])is str and len(s['nonce'])==32 and all(c in '0123456789abcdef' for c in s['nonce']) and s['case'] in C.CASES,'inner diagnostic nonce/case')
 keys={'argv','exit_code','seconds','time_limit','output_limit','group_absence_verified','stdout_bytes','stdout_sha256','stderr_bytes','stderr_sha256'}
 C.need(type(record)is dict and set(record)==keys and record['argv']==['/usr/bin/python3','-I','-B','/workspace/execution-lifecycle.py'] and type(record['exit_code'])is int and type(record['group_absence_verified'])is bool and record['time_limit']==3000 and record['output_limit']==2*1024**2,'original fixed lifecycle supervisor record')
 C.need(type(out)is bytes and type(err)is bytes and len(out)+len(err)<=2*1024**2,'unchanged original combined lifecycle output cap')
 for name,raw in (('stdout',out),('stderr',err)):
  C.need(record[name+'_bytes']==len(raw) and record[name+'_sha256']==C.sha(raw),'inner original lifecycle buffer join')
 tail=err[-2048:];failure=None
 if error is not None:
  raw=str(error).encode('utf-8','backslashreplace');failure=dict(type=type(error).__name__[:128],utf8_bytes=len(raw),sha256=C.sha(raw))
 value=dict(schema_version=1,event='lifecycle_failure',status='DIAGNOSTIC_ONLY_NOT_ACCEPTANCE_OR_CLEANUP_AUTHORITY',case=s['case'],supervisor=record,stderr_tail=dict(bytes=len(tail),sha256=C.sha(tail),base64=base64.b64encode(tail).decode(),truncated=len(err)!=len(tail)),stdout='HASH_AND_LENGTH_ONLY_NO_PRIVATE_MAP_EXPORT',error=failure,retirement='ORIGINAL_GROUP_ABSENCE_RECORDED' if record['group_absence_verified'] is True else 'UNKNOWN_GROUP_ABSENCE_NO_CLEANUP_AUTHORITY',acceptance_authority=False,cleanup_authority=False,guest_disk_readback='NOT_ESTABLISHED')
 raw=C.encoded(value);C.need(len(raw)<=12288,'bounded inner lifecycle diagnostic frame')
 print('APPS574_REPAIR16K_INNER_FAILURE '+s['nonce']+' '+json.dumps(value,sort_keys=True,separators=(',',':')),flush=True);return True

def borrowed_isolation():
 path=Path('/source/scripts/ci/current604-apps6-updater16k/guest.py');space=dict(C=C,Path=Path,os=os,ctypes=ctypes,errno=errno,ast=ast)
 C.function(path,'facts',space);raw=C.read(path).decode();node=next(n for n in ast.parse(raw).body if isinstance(n,ast.FunctionDef) and n.name=='isolate');text=ast.get_source_segment(raw,node);old="'EXACT_ORIGINAL_CALLER_NINE_CAPABILITIES_NO_SYS_ADMIN'";C.need(text.count(old)==1,'one source scope description');text=text.replace(old,"'EXACT_ORIGINAL_REPAIR_FIVE_CAPABILITIES_NO_SYS_ADMIN'");exec(compile(text,str(path)+':five-cap-profile','exec'),space);return space['isolate']()
def startup(s):
 C.need(os.getpid()==1 and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and os.sysconf('SC_PAGE_SIZE')==16384 and os.uname().release==s['kernel']['release'],'actual owned16K PID1')
 tokens=Path('/proc/cmdline').read_text().split();C.need('caa_apps574_repair16k=1' in tokens,'explicit boot marker');seeds=[v.split('=',1)[1] for v in tokens if v.startswith('caa_clock_ns=')];C.need(len(seeds)==1 and seeds[0].isdecimal(),'original fresh runner clock seed');seed=int(seeds[0]);C.need(seed>0,'nonzero startup UTC seed');before=dict(realtime_ns=time.time_ns(),monotonic_ns=time.monotonic_ns());time.clock_settime_ns(time.CLOCK_REALTIME,seed);after=dict(realtime_ns=time.time_ns(),monotonic_ns=time.monotonic_ns());elapsed=after['monotonic_ns']-before['monotonic_ns'];C.need(0<=elapsed<=5*10**9 and seed<=after['realtime_ns']<=seed+elapsed+10**9,'real startup UTC readback, no crypto clock waiver')
 old=list(resource.getrlimit(resource.RLIMIT_NOFILE));resource.setrlimit(resource.RLIMIT_NOFILE,(8192,8192));C.need(resource.getrlimit(resource.RLIMIT_NOFILE)==(8192,8192),'actual8192 descriptor ceiling');C.need(ctypes.CDLL(None).prctl(4,0,0,0,0)==0,'protect PID1')
 return dict(seed_realtime_ns=seed,before=before,after=after,authority='ORIGINAL_RUNNER_STARTUP_UTC_NOT_CONTINUOUS_SYNC',nofile=dict(before=old,after=[8192,8192]))
def lease(s):
 path=Path('/inputs/full574-lease.json');before=C.read(path,65536);value=C.decode(before);identity=[Path('/seed').stat().st_dev,Path('/seed').stat().st_ino];C.need(value['source']=='/seed' and value['token']==s['env']['OWNER_TOKEN'] and os.statvfs('/seed').f_flag&os.ST_RDONLY and not os.statvfs('/work').f_flag&os.ST_RDONLY and Path('/seed').stat().st_dev==Path('/work').stat().st_dev,'genuine readonly source/writable disjoint same-device roles')
 changed=dict(value,source_identity=identity);raw=C.encoded(changed);info=path.stat();temporary=path.with_name('full574-lease.pending');C.need(not temporary.exists(),'fresh guest lease output');temporary.write_bytes(raw);temporary.chmod(info.st_mode&0o7777);os.chown(temporary,info.st_uid,info.st_gid);temporary.replace(path)
 receipt=dict(status='FRESH_ACTUAL_GUEST_SOURCE_LEASE',before=value,after=changed,before_sha256=C.sha(before),after_sha256=C.sha(raw),changed_fields=['source_identity'],source_identity=identity,original_host_identity_not_reused=True);C.save('/out/guest-lease.json',receipt)
 p=subprocess.run(['/usr/bin/mount','-o','remount,bind,ro','/inputs'],capture_output=True,timeout=15);C.need(p.returncode==0 and os.statvfs('/inputs').f_flag&os.ST_RDONLY,'inputs immutable before worker');return receipt

def source_budget(s,T):
 from types import SimpleNamespace
 fresh=C.decode(C.read('/out/guest-lease.json'));scope=SimpleNamespace(full574_policy=Path('/inputs/full574-policy.json'),full574_policy_sha256=s['input_map']['full574-policy.json']['sha256'],full574_lease=Path('/inputs/full574-lease.json'),full574_lease_sha256=fresh['after_sha256'])
 return T.limits(scope)

def source_state(s):
 native=C.load('native_contract','/source/'+C.NATIVE+'/contract.py');native.source(Path('/source'));A=native.adapter(Path('/source'));T=C.load('native_metrics','/source/scripts/apps/transaction.py')
 limits=source_budget(s,T);before=A.measure(Path('/seed'),limits);caps=A.capability_map(Path('/seed'),before,limits)
 C.need(A.digest(before['nodes'])==s['source_tree_sha256'] and A.digest(caps)==s['source_capabilities_sha256'],'complete real source node/hash/capability roundtrip');return native,A,T,before,caps

def worker(s):
 C.need(os.getpid()!=1 and os.sysconf('SC_PAGE_SIZE')==16384 and os.uname().release==s['kernel']['release'],'actual16K worker');isolation=borrowed_isolation();native,A,T,before,caps=source_state(s)
 expected=dict(s['input_map']);actual=C.tree('/inputs');fresh=C.decode(C.read('/out/guest-lease.json'));expected['full574-lease.json']=dict(expected['full574-lease.json'],**C.row('/inputs/full574-lease.json'));C.need(actual==expected and C.row('/inputs/full574-lease.json')['sha256']==fresh['after_sha256'],'exact staged authenticated inputs except explicit fresh lease identity')
 execution=C.decode(C.read('/execution/execution-manifest.json'));C.need(C.row('/execution/execution-manifest.json')['sha256']==s['execution_manifest_sha256'] and execution['original_source_preserved'] is True,'closed execution adapter receipt')
 for name,pin in execution['execution_files'].items():C.need(C.row(Path('/execution')/C.relative(name))==pin,'exact derived execution source bytes')
 env=dict(native.ENV,HOME='/tmp',TMPDIR='/tmp',PYTHONDONTWRITEBYTECODE='1',**s['env']);os.environ.clear();os.environ.update(env);runtime=C.load('runtime','/source/scripts/ci/glibc-owned-runtime/runner.py')
 record,out,err,error=runtime.run_command(['/usr/bin/python3','-I','-B','/workspace/execution-lifecycle.py'],Path('/tmp'),env,3000,2*1024**2)
 Path('/out/repair16k-child.stdout').write_bytes(out);Path('/out/repair16k-child.stderr').write_bytes(err);C.save('/out/repair16k-child.json',record)
 lifecycle_failure(s,record,out,err,error)
 C.need(error is None and record['exit_code']==0 and record['group_absence_verified'] is True,'original case direct child/group retirement');life=native.result(C.decode(C.read('/out/lifecycle.json',4*1024**2)));C.need(life['case']==s['case'] and not Path('/work/main').exists(),'exact single case and original actual copied-root disposal')
 limits=source_budget(s,T);after=A.measure(Path('/seed'),limits);A.capability_map(Path('/seed'),after,limits,caps);C.need(after['nodes']==before['nodes'],'full actual guest source preserved')
 reader=C.load('elf_reader','/source/scripts/virtual/generic16k/fixture.py');audit=C.load('elf_audit','/source/scripts/ci/managed-gui-generic16k/elf_audit.py');elf=audit.audit(Path('/seed'),reader);C.need(elf['status']=='PASS_STAGED_NATIVE_AARCH64_ELF16K_ALIGNMENT','full original574 ELF audit');C.save('/out/repair16k-worker.json',dict(status='PRIVATE_COMPLETE_CASE',case=s['case'],isolation=isolation,child=record,source_tree_sha256=A.digest(after['nodes']),source_capabilities_sha256=A.digest(caps),ELF=dict(status=elf['status'],sha256=C.sha(C.encoded(elf)),count=len(elf['ELF'])),native_host='NOT_CLAIMED',hardware='NOT_RUN'))

def main():
 s=C.decode(C.read('/workspace/selection.json'));C.need(s['case'] in C.CASES,'one case')
 for n,pin in s['runner_files'].items():C.need(C.row(Path('/workspace')/C.relative(n))==pin,'source-pinned VM execution helper')
 if sys.argv[1:]==['worker']:return worker(s)
 clock=startup(s);fresh=lease(s);emit(s,dict(event='boot',page_size=16384,architecture=os.uname().machine,kernel=os.uname().release,kernel_profile_sha256=C.sha(C.encoded(s['kernel'])),clock=clock,lease=fresh))
 runtime=C.load('pid1_runtime','/source/scripts/ci/glibc-owned-runtime/runner.py');record,out,err,error=runtime.run_command(['/usr/bin/python3','-I','-B','/workspace/guest.py','worker'],Path('/tmp'),dict(PATH='/usr/bin:/bin',HOME='/tmp',TMPDIR='/tmp'),3000,2*1024**2);C.save('/out/repair16k-pid1-child.json',record)
 worker_failure(s,record,out,err,error)
 C.need(error is None and record['exit_code']==0 and record['group_absence_verified'] is True,'whole actual case worker retirement');v=C.decode(C.read('/out/repair16k-worker.json'));files={}
 for p in Path('/out').iterdir():
  C.need(p.is_file() and not p.is_symlink() and p.stat().st_nlink==1 and p.stat().st_size<=16*1024**2 and len(files)<160,'closed original direct guest output');files[p.name]=C.row(p)
 C.need(sum(v['bytes'] for v in files.values())<=192*1024**2,'bounded case readback');emit(s,dict(event='result',status=C.PASS,case=s['case'],worker=v,files=files,page_size=16384,lease_sha256=fresh['after_sha256']))
 for dest in ('/inputs','/source','/execution','/seed','/work','/out','/workspace'):
  p=subprocess.run(['/usr/bin/umount',dest],capture_output=True,timeout=15);C.need(p.returncode==0 and not os.path.ismount(dest),'owned mount retirement: '+dest)
 emit(s,dict(event='exit',status=C.PASS,cleanup='PASS_OWNED_MOUNTS_RETIRED'))
if __name__=='__main__':
 try:main()
 except BaseException as error:
  print('APPS574_REPAIR16K_ERROR '+type(error).__name__+' '+str(error)[:2048],flush=True)
  if os.getpid()!=1:raise SystemExit(1)
 finally:
  if os.getpid()==1:sys.stdout.flush();sys.stderr.flush();os.sync();ctypes.CDLL(None).reboot(0x4321fedc)
