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

def worker(s):
 C.need(os.getpid()!=1 and os.getuid()==os.geteuid()==0 and os.uname().machine=='aarch64' and os.sysconf('SC_PAGE_SIZE')==16384 and os.uname().release==s['kernel']['release'],'actual generic16K worker')
 isolation=isolate();
 input_map=C.decode(C.read('/workspace/input-map.json',16*1024**2))
 for n,pin in input_map.items():
  p=Path(n);info=p.lstat();C.need(not p.is_symlink() and (info.st_mode&0o7777,info.st_uid,info.st_gid)==(pin['mode'],pin['uid'],pin['gid']),'copied input metadata')
  if pin['type']=='file':C.need(p.is_file() and info.st_nlink==1 and C.row(p)=={k:pin[k] for k in ('bytes','sha256')},'copied input source/content')
  else:C.need(p.is_dir(),'copied input directory')
 scope,roots,_,_=disk.apis();before,mapping=capmap(scope,roots,600)
 expected=C.decode(C.read('/workspace/baseline-nodes.json',64*1024**2));C.need(before==expected and C.sha(C.encoded(mapping))==s['capabilities_sha256'],'complete original boot574 metadata/hash/hardlink/capability map readback')
 env=dict(PATH='/usr/bin:/bin',LC_ALL='C',LANG='C',HOME='/tmp',TMPDIR='/tmp',PYTHONDONTWRITEBYTECODE='1',**s['env'])
 os.environ.clear();os.environ.update(env)
 runner=C.load('supervisor','/source/scripts/ci/glibc-owned-runtime/runner.py')
 record,stdout,stderr,error=runner.run_command(['/usr/bin/python3','-I','-B','/runner.py'],Path('/tmp'),env,3900,2*1024**2)
 Path('/out/updater16k-caller.stdout').write_bytes(stdout);Path('/out/updater16k-caller.stderr').write_bytes(stderr)
 C.need(error is None and record['exit_code']==0 and record['group_absence_verified'] is True,'original caller exit/group absence')
 # The caller writes only after all original helper/groups/source/copy checks.
 raw=C.read('/out/result.json',2*1024**2);caller=C.decode(raw);C.need(caller['status']=='PASS','original caller failed')
 policy=scope.mount_policy(Path('/'),Path('/measurement/inspection'),scope.mounts(scope._mount_table()));reader=C.load('elf_reader','/source/scripts/virtual/generic16k/fixture.py');elf=cap_scope.audit(C.read('/source/scripts/ci/managed-gui-generic16k/elf_audit.py'),set(policy['observed_mounts'])|scope.RUNTIME,Path('/'),reader)
 before_elf=C.decode(C.read('/workspace/boot-elf16k.json',16*1024**2))
 C.need(before_elf['status']==elf['status']=='PASS_STAGED_NATIVE_AARCH64_ELF16K_ALIGNMENT','complete original574 and actual604 native ELF16K audit')
 after,last=capmap(scope,roots,600);C.need(last==mapping,'baseline file capabilities changed or candidate added capabilities')
 C.save('/out/updater16k-worker.json',dict(status='PRIVATE_COMPLETE_WORKER',case=s['case'],caller=caller,child=record,isolation=isolation,source_capabilities_before=C.sha(C.encoded(mapping)),source_capabilities_after=C.sha(C.encoded(last)),elf16k=dict(before=dict(sha256=C.sha(C.encoded(before_elf)),ELFs=len(before_elf['ELF'])),after=dict(sha256=C.sha(C.encoded(elf)),ELFs=len(elf['ELF'])),status=elf['status'],raw_maps='PRIVATE_NOT_EXPORTED'),original_stdout=dict(bytes=len(stdout),sha256=C.sha(stdout)),original_stderr=dict(bytes=len(stderr),sha256=C.sha(stderr))))

def main():
 s=C.decode(C.read('/workspace/selection.json'));C.need('caa_apps6_update16k=1' in Path('/proc/cmdline').read_text().split(),'owned16K boot marker')
 for n,pin in s['runner_files'].items():C.need(C.row(Path('/workspace')/n)==pin,'source-pinned guest module')
 if sys.argv[1:]==['worker']:return worker(s)
 C.need(os.getpid()==1 and os.getuid()==os.geteuid()==0 and os.sysconf('SC_PAGE_SIZE')==16384 and os.uname().release==s['kernel']['release'],'actual root16K PID1')
 before=list(resource.getrlimit(resource.RLIMIT_NOFILE));resource.setrlimit(resource.RLIMIT_NOFILE,(8192,8192));after=list(resource.getrlimit(resource.RLIMIT_NOFILE));C.need(after==[8192,8192],'exact native8192 descriptor budget')
 libc=ctypes.CDLL(None,use_errno=True);C.need(libc.prctl(4,0,0,0,0)==0,'protect privileged PID1')
 emit(s,dict(event='boot',page_size=16384,kernel=os.uname().release,architecture=os.uname().machine,kernel_profile_sha256=C.sha(C.encoded(s['kernel'])),nofile=dict(before=before,after=after)))
 runner=C.load('supervisor','/source/scripts/ci/glibc-owned-runtime/runner.py');record,out,err,error=runner.run_command(['/usr/bin/python3','-I','-B','/workspace/guest.py','worker'],Path('/tmp'),dict(PATH='/usr/bin:/bin',LC_ALL='C',HOME='/tmp',TMPDIR='/tmp'),3900,2*1024**2)
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
