#!/usr/bin/python3 -I
# SPDX-License-Identifier: MIT
"""Actual installed KSM2 sysfs lifecycle. Entry refuses outside owned16K PID1."""
import ctypes,fcntl,json,os,resource,stat,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent));import contract as C
COMMAND='/usr/bin/cachy-asahi-ksm-experiment';STORE=Path('/var/lib/cachy-asahi-ksm-experiments');RUN=Path('/sys/kernel/mm/ksm/run')


def supervision_runtime(runtime,worker=False):
 """Exact borrowed supervisor; reap owned adopted children before real absence."""
 import types
 raw=C.read(Path(runtime.__file__),128*1024)
 C.need(C.sha(raw)=='4d9aa954d95032ab9ea9085ced784efc81a5db42e2f1f3401e679ee861c16090','whole original command supervisor')
 before="""            for sig in (signal.SIGTERM,signal.SIGKILL):
                try:os.killpg(proc.pid,sig)
                except ProcessLookupError:pass
            code=proc.wait(timeout=5)
            try:os.killpg(proc.pid,0)
            except ProcessLookupError:group_absent=True
"""
 after="""            # One existing five-second finalization window, including leader wait.
            finish=time.monotonic()+5
            for sig in (signal.SIGTERM,signal.SIGKILL):
                try:os.killpg(proc.pid,sig)
                except ProcessLookupError:pass
            code=proc.wait(timeout=max(0,finish-time.monotonic()))
            # The guest worker is a child subreaper. Adopted descendants in this
            # exact PGID must be genuinely reaped; zombies are never ignored.
            reaped=0
            while True:
                try:
                    while True:
                        child,_status=os.waitpid(-proc.pid,os.WNOHANG)
                        if child==0:break
                        reaped+=1;need(reaped<=512,'owned-command-child-bound')
                except ChildProcessError:pass
                try:os.killpg(proc.pid,0)
                except ProcessLookupError:group_absent=True;break
                remaining=finish-time.monotonic()
                if remaining<=0:break
                time.sleep(min(.01,remaining))
"""
 C.need(raw.count(before.encode())==1,'one exact owned-group finalization seam')
 derived=raw.replace(before.encode(),after.encode())
 C.need(derived.replace(after.encode(),before.encode())==raw,'whole supervisor finalization inverse')
 if worker:
  # Only the already guarded dedicated guest worker changes its own adoption.
  libc=ctypes.CDLL(None,use_errno=True);value=ctypes.c_int(-1)
  C.need(libc.prctl(36,1,0,0,0)==0 and libc.prctl(37,ctypes.byref(value),0,0,0)==0 and value.value==1,'worker child subreaper verified')
 module=types.ModuleType('_ksm_owned_group_supervisor');module.__file__=runtime.__file__
 exec(compile(derived,runtime.__file__+':owned-group-retirement','exec'),module.__dict__)
 return module

def post_removal_data(s,expected,actual):
 """Existing failed maps only; bounded path/field/hash DATA, never acceptance."""
 try:
  if expected==actual:return
  import re
  C.need(type(s.get('nonce'))is str and re.fullmatch('[a-f0-9]{32}',s['nonce'])and type(expected)is type(actual)is dict and len(expected)<=200000 and len(actual)<=200000,'bounded original map failure context')
  def whole(value):
   raw=C.encoded(value);C.need(len(raw)<=64*1024**2,'original node-map byte cap');return dict(nodes=len(value),**C.pin(raw))
  before_map=whole(expected);after_map=whole(actual);counts=dict(added=0,removed=0,changed=0);first=None
  for name in expected.keys()|actual.keys():
   C.need(type(name)is str,'typed existing node path')
   if name not in expected:kind='added'
   elif name not in actual:kind='removed'
   elif expected[name]!=actual[name]:kind='changed'
   else:continue
   counts[kind]+=1
   if first is None or name<first:first=name
  C.need(first is not None,'actual map mismatch required')
  a=expected.get(first);b=actual.get(first);C.need((a is None or type(a)is dict)and(b is None or type(b)is dict),'typed existing node records')
  fields=sorted(k for k in set(a or{})|set(b or{})if a is None or b is None or a.get(k)!=b.get(k))
  C.need(set(fields)<={'type','mode','uid','gid','bytes','sha256','target','hardlink_group'},'source-owned node fields only')
  path=first.encode('utf8');preview=first[:80]
  value=dict(schema_version=1,status='POST_REMOVAL_NODE_MAP_FAILURE_DATA_ONLY',nonce=s['nonce'],expected=before_map,actual=after_map,counts=counts,first=dict(path=preview,path_utf8_bytes=len(path),path_sha256=C.sha(path),path_truncated=preview!=first,kind=('added'if a is None else'removed'if b is None else'changed'),fields=fields,before=None if a is None else C.pin(C.encoded(a)),after=None if b is None else C.pin(C.encoded(b))),acceptance_authority=False,cleanup_authority=False)
  prefix='KSM2_POST_REMOVAL_DATA '+s['nonce']+' '
  raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)
  if len((prefix+raw+'\n').encode())>2048:
   value['first']['path']=first[:16];value['first']['path_truncated']=value['first']['path']!=first;raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)
  C.need(len((prefix+raw+'\n').encode())<=2048,'post-removal DATA2KiB including frame')
  print(prefix+raw,flush=True)
 except BaseException:return

LDCONFIG_SHIM_SOURCE=b'/* SPDX-License-Identifier: MIT */\n#define _GNU_SOURCE\n#include <dlfcn.h>\n#include <errno.h>\n#include <string.h>\n#include <unistd.h>\n\n/* Exact built-in path from pinned native libalpm; never report helper success. */\nint execv(const char *path, char *const argv[])\n{\n    if (strcmp(path, "/usr/bin/ldconfig") == 0) {\n        static const char marker[] = "CAA_KSM2_BUILTIN_LDCONFIG_EXEC_DENIED_EPERM\\n";\n        ssize_t sent = write(STDERR_FILENO, marker, sizeof(marker) - 1);\n        (void)sent;\n        errno = EPERM;\n        return -1;\n    }\n    int (*next_execv)(const char *, char *const[]) = dlsym(RTLD_NEXT, "execv");\n    if (!next_execv) {\n        errno = ENOSYS;\n        return -1;\n    }\n    return next_execv(path, argv);\n}\n'
NATIVE_ALPM_SHA='94c013b9026772ffe4f227f508a2cdf0c61323dc1f7b7836fe629b49bfbc3902'

def ldconfig_policy(s,expected,command):
 """Native compile in owned tmp, within the existing shared command deadline."""
 native='/usr/lib/libalpm.so.16.0.1';raw=C.read(native,4*1024**2)
 C.need(C.sha(raw)==NATIVE_ALPM_SHA==expected['usr/lib/libalpm.so.16.0.1']['sha256'],'same original signed native libalpm bytes')
 C.need(raw[:6]==b'\x7fELF\x02\x01'and raw[18:20]==b'\xb7\x00'and raw.count(b'/usr/bin/ldconfig\x00')==1,'native ALPM exact built-in LDCONFIG path')
 directory=Path('/tmp')/('ksm2-ldconfig-policy-'+s['nonce']);C.need(not os.path.lexists(directory),'fresh private helper-policy directory');directory.mkdir(mode=0o700)
 source=directory/'policy.c';library=directory/'policy.so';source.write_bytes(LDCONFIG_SHIM_SOURCE);source.chmod(0o600)
 argv=['/usr/bin/cc','-std=c11','-O2','-fPIC','-shared','-Wall','-Wextra','-Werror','-Wl,-z,relro,-z,now','-Wl,--no-undefined','-Wl,-z,max-page-size=16384,-z,common-page-size=16384','-o',str(library),str(source),'-ldl']
 command(argv,seconds=35);library.chmod(0o500);compiled=C.read(library,1024**2)
 C.need(all((p.lstat().st_uid,p.lstat().st_gid,stat.S_IMODE(p.lstat().st_mode))==(0,0,mode)for p,mode in((source,0o600),(library,0o500))),'private root-owned source and policy modes')
 C.need(compiled[:6]==b'\x7fELF\x02\x01'and compiled[16:20]==b'\x03\x00\xb7\x00','fresh native aarch64 shared policy object')
 receipt=dict(status='EXPLICIT_BUILTIN_LDCONFIG_EXEC_DENIAL_NOT_HELPER_SUCCESS',helper='/usr/bin/ldconfig',deny_errno='EPERM',other_execv='RTLD_NEXT_UNCHANGED',native_libalpm=C.pin(raw),source=C.pin(LDCONFIG_SHIM_SOURCE),compiled=C.pin(compiled),compiler_argv=argv,library=str(library),environment_scope='ONLY_EXACT_SIGNED_INSTALL_AND_REMOVE_PACMAN_COMMANDS',commands=[],helper_exit='NOT_OBSERVED',production_policy='NOT_INSTALLED',denial_marker=C.pin(b'CAA_KSM2_BUILTIN_LDCONFIG_EXEC_DENIED_EPERM\n'))
 return directory,receipt

def ldconfig_environment(argv,pacman,archive,policy,directory):
 """Only the two exact selected transaction argv receive this private preload."""
 C.need(argv in(pacman+['-U',str(archive)],pacman+['-R',C.PACKAGE]),'exact signed selected install/remove argv only')
 library=directory/'policy.so';source=directory/'policy.c'
 C.need(C.row(source)==policy['source']and C.row(library)==policy['compiled']and str(library)==policy['library'],'whole compiled policy and C source held before each transaction')
 C.need(len(policy['commands'])<2,'only two selected package transactions')
 env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',HOME='/root',LD_PRELOAD=str(library));policy['commands'].append(dict(argv=list(argv),environment=C.pin(C.encoded(env))))
 return env

def retire_ldconfig_policy(directory,policy):
 C.need(set(p.name for p in directory.iterdir())=={'policy.c','policy.so'}and len(policy['commands'])==2,'exact own policy files and both transaction command records')
 C.need(all(row.get('helper_denial_capture',{}).get('status')=='HELPER_EXEC_DENIED_EPERM_NOT_HELPER_SUCCESS'for row in policy['commands']),'both actual captured helper denials required')
 for name,key in(('policy.c','source'),('policy.so','compiled')):
  p=directory/name;C.need(C.row(p)==policy[key],'same private policy bytes before retirement');p.unlink()
 directory.rmdir();C.need(not os.path.lexists(directory),'own helper policy files retired')

def ldconfig_denial_capture(policy,out,err):
 marker=b'CAA_KSM2_BUILTIN_LDCONFIG_EXEC_DENIED_EPERM\n'
 C.need((out+err).count(marker)==1,'one complete original built-in helper exec-denial marker')
 C.need(policy['commands']and'helper_denial_capture'not in policy['commands'][-1],'one actual helper denial per transaction')
 policy['commands'][-1]['helper_denial_capture']=dict(marker=C.pin(marker),stdout=C.pin(out),stderr=C.pin(err),status='HELPER_EXEC_DENIED_EPERM_NOT_HELPER_SUCCESS')

def scalar():
 fd=os.open(RUN,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  b=ctypes.create_string_buffer(512);C.need(ctypes.CDLL(None).fstatfs(fd,b)==0 and ctypes.c_long.from_buffer(b).value==0x62656572,'actual sysfs only');raw=os.read(fd,65);C.need(raw in(b'0\n',b'1\n'),'real KSM0/1 only; unmerge2 refused');return int(raw)
 finally:os.close(fd)

def foreign_edit(s,before,after):
 """One explicit guest-only competing writer; never used for ordinary apply."""
 C.guest_guard(s,worker=True);C.need(type(before)is type(after)is int and before in(0,1)and after==1-before and scalar()==before,'finite guest conflict write')
 fd=os.open(RUN,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);C.need(a.st_uid==0 and stat.S_ISREG(a.st_mode),'actual root-owned scalar');raw=(str(after)+'\n').encode();C.need(os.write(fd,raw)==len(raw),'one complete conflict write');C.need(scalar()==after,'conflict scalar readback')
 finally:os.close(fd)

def state(name):
 root=STORE/name;C.need(root.is_dir()and not root.is_symlink(),'own saved experiment directory');rows={}
 for leaf in('plan.json','journal.json'):
  raw=C.read(root/leaf,16384);info=(root/leaf).lstat();C.need(info.st_uid==info.st_gid==0 and stat.S_IMODE(info.st_mode)==0o600,'private saved experiment');rows[leaf]=dict(pin=C.pin(raw),value=C.decode(raw),identity=[info.st_dev,info.st_ino])
 return rows

def cleanup_store(names,held):
 C.need(set(p.name for p in STORE.iterdir())==set(names)|{'.lock'},'only own newly created store entries')
 root=os.open(STORE,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);lock=None
 try:
  st=os.fstat(root);C.need(st.st_uid==st.st_gid==0 and stat.S_IMODE(st.st_mode)==0o700,'own private store')
  lock=os.open('.lock',os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=root);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  for name in names:
   current=state(name);C.need(current==held[name]and current['journal.json']['value']['phase']=='UNDONE','only exact terminal restored records may retire')
   child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=root)
   try:
    C.need(set(os.listdir(child))=={'plan.json','journal.json'},'exact own saved files')
    for leaf in('plan.json','journal.json'):
     a=os.stat(leaf,dir_fd=child,follow_symlinks=False);C.need([a.st_dev,a.st_ino]==current[leaf]['identity']and a.st_nlink==1,'held ordinary state record');os.unlink(leaf,dir_fd=child)
   finally:os.close(child)
   os.rmdir(name,dir_fd=root)
  C.need(os.listdir(root)==['.lock'],'terminal store empty except owned lock');os.unlink('.lock',dir_fd=root)
 finally:
  if lock is not None:os.close(lock)
  os.close(root)
 STORE.rmdir();C.need(not STORE.exists(),'own test state removed after restoration')

def scalar_case(s,call):
 C.need(not os.path.lexists(STORE),'store absent before explicit live experiment');baseline=scalar();desired=1-baseline;events=[];held={}
 def invoke(action,name,extra=(),expected=0):
  value=call([COMMAND,action,name,*extra],expected=expected,seconds=15);C.need(type(value)is dict,'bounded helper JSON');events.append(dict(action=action,name=name,exit=expected,result=value,actual=scalar()));return value
 for index in range(2):
  name='vm-'+s['nonce'][:16]+('-restore'if index==0 else'-conflict');option='--resume-scanning'if desired else'--pause';preview=invoke('preview',name,[option]);C.need(preview['baseline']==baseline and preview['desired']==desired and preview['kernel_write']is False and scalar()==baseline,'preview must not write')
  plan=state(name);digest=preview['plan_sha256'];C.need(plan['plan.json']['pin']['sha256']==digest,'immutable actual plan pin')
  applied=invoke('apply',name,['--plan-sha256',digest,'--confirm','CHANGE_GLOBAL_KSM_SCANNING']);C.need(applied['phase']=='APPLIED'and applied['current']==scalar()==desired and applied['kernel_write']is True,'actual installed helper sysfs apply')
  inspected=invoke('inspect',name);C.need(inspected['phase']=='APPLIED'and inspected['current']==desired and inspected['intent_uncertain']is False,'separate current scalar inspection')
  if index==1:
   foreign_edit(s,desired,baseline);before=state(name);invoke('undo',name,['--plan-sha256',digest,'--confirm','RESTORE_KSM_SCANNING_BASELINE'],expected=1);C.need(scalar()==baseline and state(name)==before,'foreign edit refusal must preserve scalar and records')
   foreign_edit(s,baseline,desired)
  undone=invoke('undo',name,['--plan-sha256',digest,'--confirm','RESTORE_KSM_SCANNING_BASELINE']);C.need(undone['phase']=='UNDONE'and undone['current']==scalar()==baseline,'actual explicit scalar restoration')
  inspected=invoke('inspect',name);C.need(inspected['phase']=='UNDONE'and inspected['current']==baseline and inspected['intent_uncertain']is False,'separate restoration readback')
  final=state(name);C.need(final['plan.json']==plan['plan.json'],'full immutable actual plan remains exact');held[name]=final
 cleanup_store(list(held),held);C.need(scalar()==baseline,'original scalar restored after own state disposal')
 return dict(status='PASS_REAL_SYSFS_SCALAR_RESTORE_AND_FOREIGN_EDIT_REFUSAL',baseline=baseline,desired=desired,events=events,state_retirement='EXACT_OWN_UNDONE_RECORDS_ONLY',interruption='NOT_RUN_NO_SHIPPED_DETERMINISTIC_HOOK',unmerge='NOT_RUN_NEVER2',memory_registration='NOT_RUN',sharing_or_memory_rollback='NOT_CLAIMED')

def run(s):
 C.guest_guard(s,worker=True);C.need(all(os.statvfs(p).f_flag&os.ST_RDONLY for p in('/inputs','/workspace','/source','/upgrade-code','/upgrade-config.json','/persistent_scope.py','/upgrade-signing')),'all original code/input/trust mounts readonly');C.support('/source');C.source_check('/source');C.native_gate(s,'/inputs',root='/source');C.actual_identity(s);C.need(s.get('media')is None,'no circular staged media authority')
 M=C.load('_ksm_media','/source/media_adapter.py');isolation=M.isolate('/source');nodes,mapping,caps,cap_module,roots,disk=M.source_nodes('/source');expected=C.decode(C.read('/workspace/baseline-nodes.json',64*1024**2));held_mapping=C.decode(C.read('/workspace/capabilities.json',64*1024**2))
 C.need(nodes==expected and C.sha(C.encoded(held_mapping))==s['capabilities_sha256']and mapping==held_mapping,'complete original boot574 node/hash/hardlink/capability map readback; no slash-root restore waiver')
 I=C.load('_ksm_vm_installed','/source/borrowed/installed.py');L=C.load('_ksm_vm_preserve','/source/borrowed/lifecycle.py');driver=C.load('_ksm_vm_database','/source/borrowed/root_upgrade.py');runtime=C.load('_ksm_vm_supervision','/source/borrowed/runtime.py');runtime=supervision_runtime(runtime,worker=True)
 rows=[];deadline=time.monotonic()+C.SHARED_SECONDS;ldconfig_receipt=None;ldconfig_directory=None
 def command(argv,expected=0,seconds=35,transaction=False):
  remaining=min(seconds,deadline-time.monotonic());C.need(remaining>0,'whole VM lifecycle deadline')
  environment=ldconfig_environment(argv,pacman,archive,ldconfig_receipt,ldconfig_directory)if transaction else dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',HOME='/root')
  r,out,err,error=runtime.run_command(argv,Path('/tmp'),environment,remaining,128*1024);rows.append(r)
  command_failure_data(s,r,out,err,error,expected,seconds,len(rows))
  C.need(error is None and r['exit_code']==expected and r['group_absence_verified']is True,'natural direct installed command/group retirement');
  if transaction:ldconfig_denial_capture(ldconfig_receipt,out,err)
  if expected==1:C.need(out==b''and err==b'KSM experiment refused: KSM changed; conflict preserved\n','exact installed foreign-edit refusal')
  return out.decode() if expected==0 else C.encoded(dict(status='REFUSED',exit=expected,stderr_sha256=r['stderr_sha256'])).decode()
 L.command=lambda argv,expected=0,timeout=35:command(argv,expected,timeout)
 base=C.decode(C.read('/source/borrowed/base574.json'));C.need(len(base)==574 and L.inventory()==base and C.PACKAGE not in base,'exact original574 and KSM absent')
 log=Path('/var/log/pacman.log');log_before=C.read(log,16*1024**2);C.need(expected.get('var/log/pacman.log',{}).get('sha256')==C.sha(log_before)and log.lstat().st_nlink==1,'existing ordinary original ALPM log')
 before=I.base_state(L,driver);base_pin=I.preserve_base(L,before);trust=dict(pacman=L.entry(Path('/etc/pacman.conf')),trust=L.snapshot(Path('/etc/pacman.d')));users=L.snapshot(Path('/home'))
 ldconfig_directory,ldconfig_receipt=ldconfig_policy(s,expected,command)
 def preserve():
  C.need(I.preserve_base(L,before)==base_pin and trust==dict(pacman=L.entry(Path('/etc/pacman.conf')),trust=L.snapshot(Path('/etc/pacman.d')))and users==L.snapshot(Path('/home')),'all original574 rawDB/payload/user/system trust preserved')
 _,index=C.native_gate(s,'/inputs',root='/source');public='/inputs/'+index['files']['public_key']['path'];pacman=I.pacman(L,index['signer'],public=public);staged=Path('/tmp')/('ksm2-install-'+s['nonce']);C.need(not os.path.lexists(staged),'fresh private signed package staging');staged.mkdir(mode=0o700);archive=staged/Path(index['files']['a']['path']).name;signature=Path(str(archive)+'.sig');archive.write_bytes(C.checked('/inputs',index['files']['a']));signature.write_bytes(C.checked('/inputs',index['files']['signature']));archive.chmod(0o600);signature.chmod(0o600);staged_pins={p.name:C.row(p)for p in(archive,signature)};C.need(C.row(archive)=={k:index['files']['a'][k]for k in('bytes','sha256')}and C.row(signature)=={k:index['files']['signature'][k]for k in('bytes','sha256')},'exact original signed archive copied to own tmp staging only')
 command(pacman+['-U',str(archive)],seconds=90,transaction=True);C.need(L.inventory()==base|{C.PACKAGE:C.VERSION},'actual ordinary signed575 installation');I.payloads(L,{C.PACKAGE:dict(payload=index['product']['builds'][0]['payload'])});preserve()
 C.need(C.sha(C.read(COMMAND))==index['product']['builds'][0]['payload']['usr/bin/cachy-asahi-ksm-experiment']['sha256'],'exact installed helper bytes')
 def call(argv,expected=0,seconds=15):return C.decode(command(argv,expected,seconds).encode())
 result=scalar_case(s,call);preserve();sharing_module=C.load('_ksm_owned_sharing','/source/sharing.py');sharing_result=sharing_module.validate(C.decode(command(['/usr/bin/python3','-I','-B','/source/sharing.py','--owned-parent',str(os.getpid())],seconds=90).encode()),s['nonce']);preserve();command(pacman+['-R',C.PACKAGE],seconds=90,transaction=True);C.need(L.inventory()==base and not os.path.lexists(STORE),'original574 restored and own experiment store retired');preserve();last_nodes,last_mapping,*_=M.source_nodes('/source');C.need(last_mapping==held_mapping,'all persistent file capabilities preserved after removal');log_after=C.read(log,16*1024**2);C.need(log_after.startswith(log_before),'original ALPM log prefix preserved');permitted=dict(expected);permitted['var/log/pacman.log']=dict(expected['var/log/pacman.log'],bytes=len(log_after),sha256=C.sha(log_after));
 try:
  C.need(last_nodes==permitted,'complete post-removal node/hash/hardlink map; only existing ALPM log append permitted')
 except BaseException:
  post_removal_data(s,permitted,last_nodes)
  raise
 command(['/usr/bin/gpgconf','--homedir','/tmp/apps-cache-trust','--kill','all'])
 C.need(set(p.name for p in staged.iterdir())==set(staged_pins),'only own signed staging files');
 for p in staged.iterdir():C.need(C.row(p)==staged_pins[p.name],'held staged signed bytes');p.unlink()
 staged.rmdir();C.need(not staged.exists(),'owned signed staging retired')
 retire_ldconfig_policy(ldconfig_directory,ldconfig_receipt)
 return dict(ldconfig_policy=ldconfig_receipt,actual_source=s['VM_source'],actual_ref=s['VM_ref'],actual_run=s['VM_run'],isolation=isolation,source_capabilities_before=C.sha(C.encoded(mapping)),source_capabilities_after=C.sha(C.encoded(last_mapping)),boot574_nodes_sha256=C.sha(C.encoded(expected)),status='PASS_INSTALLED_KSM2_GENERIC16K_GUEST_ONLY',nonce=s['nonce'],page_size=16384,kernel=s['kernel'],scalar=result,base574_preservation_sha256=base_pin,package_counts=[574,575,574],complete_post_removal_map='EXACT_ORIGINAL_NODES_EXCEPT_PINNED_EXISTING_ALPM_LOG_APPEND',ALPM_log=dict(before=C.pin(log_before),after=C.pin(log_after),scope='PRIVATE_CONTENT_NOT_EXPORTED_APPEND_ONLY'),user_and_system_trust='EXACT_PRIVATE_NATIVE_GUARDS',commands=rows,hardware='NOT_RUN',performance='NOT_MEASURED',memory_sharing='PASS_OWNED_VM_ANONYMOUS_SHARING_UNMERGE',sharing=sharing_result,release='NOT_ADMITTED')

def emit(s,value):
 raw=C.encoded(value);C.need(len(raw)<=256*1024,'bounded result frame');print('KSM2_VM '+s['nonce']+' '+json.dumps(value,sort_keys=True,separators=(',',':')),flush=True)

def quiescent(s):
 C.guest_guard(s)
 for _ in range(256):
  try:pid,_status=os.waitpid(-1,os.WNOHANG)
  except ChildProcessError:break
  if pid==0:break
 else:raise ValueError('bounded adopted child retirement')
 count=0
 for entry in Path('/proc').iterdir():
  if not entry.name.isdecimal()or entry.name=='1':continue
  count+=1;C.need(count<=512,'bounded guest process closure')
  try:raw=(entry/'status').read_text()
  except FileNotFoundError:continue
  C.need(len(raw.encode())<=16384,'bounded process status');fields=dict(line.split(':',1)for line in raw.splitlines()if ':'in line);C.need(fields.get('Kthread','').strip()=='1','unknown non-kernel guest process remains')
 return dict(status='ONLY_PID1_AND_OBSERVED_KERNEL_THREADS',kernel_threads=count)

def command_failure_data(s,row,out,err,error,expected,seconds,ordinal):
 """Only original nearest-inner command capture; no acceptance or cleanup credit."""
 try:
  if error is None and row.get('exit_code')==expected and row.get('group_absence_verified')is True:return
  import base64,math,re
  C.need(type(s.get('nonce'))is str and re.fullmatch('[a-f0-9]{32}',s['nonce'])and type(row)is dict and type(expected)is int and expected in(0,1)and type(ordinal)is int and 1<=ordinal<=256,'finite inner command context')
  argv=row['argv'];C.need(type(argv)is list and 1<=len(argv)<=64 and all(type(x)is str and x and '\x00'not in x and len(x.encode())<=4096 for x in argv)and len(json.dumps(argv).encode())<=4096,'bounded original command argv')
  C.need(type(seconds)in(int,float)and math.isfinite(seconds)and 0<seconds<=90 and type(row['time_limit'])in(int,float)and math.isfinite(row['time_limit'])and 0<row['time_limit']<=seconds and row['output_limit']==128*1024 and type(row['exit_code'])is int and -64<=row['exit_code']<=255 and type(row['group_absence_verified'])is bool,'unchanged original inner budgets/outcome')
  C.need(type(row['seconds'])in(int,float)and math.isfinite(row['seconds'])and 0<=row['seconds']<=seconds+6 and type(out)is type(err)is bytes and len(out)+len(err)<=128*1024,'bounded original captured inner streams')
  streams={}
  for name,data,cap in(('stdout',out,1024),('stderr',err,4096)):
   C.need(type(row[name+'_bytes'])is int and row[name+'_bytes']==len(data)and row[name+'_sha256']==C.sha(data),'complete captured inner stream/record join')
   tail=data[-cap:];streams[name]=dict(bytes=len(data),sha256=C.sha(data),tail_bytes=len(tail),tail_sha256=C.sha(tail),tail_base64=base64.b64encode(tail).decode(),omitted_bytes=len(data)-len(tail),truncated=len(data)>len(tail),scope='COMPLETE_CAPTURE_NOT_ATTEMPTED_OUTPUT')
  kind=None if error is None else type(error).__name__;C.need(kind is None or re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}',kind),'typed supervisor error')
  v=dict(schema_version=1,status='FAILED_NEAREST_INNER_COMMAND_DATA_ONLY',nonce=s['nonce'],ordinal=ordinal,expected_exit=expected,caller_seconds=seconds,record=row,supervisor_error_type=kind,supervisor_error_code=('NONE'if error is None else str(error)if type(error)is ValueError and str(error)in('command-time-limit','command-output-limit')else'OTHER_TYPE_ONLY'),streams=streams,acceptance_authority=False,cleanup_authority=False)
  raw=json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False);C.need(len(raw.encode())<=16384,'inner diagnostic16KiB')
  print('KSM2_INNER_COMMAND_DATA '+s['nonce']+' '+raw,flush=True)
 except BaseException:return

def relay_inner_command(s,row,out,err,error):
 """Relay complete original worker capture for DATA replay; success path silent."""
 try:
  if error is None and row.get('exit_code')==0 and row.get('group_absence_verified')is True:return
  import base64,re
  C.need(type(s.get('nonce'))is str and re.fullmatch('[a-f0-9]{32}',s['nonce'])and row['argv']==['/usr/bin/python3','-I','-B','/workspace/guest.py','worker']and row['time_limit']==C.SHARED_SECONDS and row['output_limit']==512*1024,'same original worker custody')
  C.need(type(out)is type(err)is bytes and 0<len(out)<=24576 and len(out)+len(err)<=512*1024 and row['stdout_bytes']==len(out)and row['stdout_sha256']==C.sha(out)and row['stderr_bytes']==len(err)and row['stderr_sha256']==C.sha(err),'whole original worker capture record/hash')
  prefix=('KSM2_INNER_COMMAND_DATA '+s['nonce']+' ').encode();lines=[x for x in out.splitlines(keepends=True)if x.startswith(prefix)];C.need(len(lines)==1 and lines[0].endswith(b'\n')and len(lines[0])<=16465,'one complete bounded inner DATA record')
  v=dict(schema_version=1,status='COMPLETE_ORIGINAL_WORKER_STDOUT_FOR_INNER_FAILURE_DATA',nonce=s['nonce'],worker_record=row,stdout_base64=base64.b64encode(out).decode(),stderr_capture=dict(bytes=len(err),sha256=C.sha(err)),inner_line=C.pin(lines[0]),acceptance_authority=False,cleanup_authority=False)
  raw=json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False);C.need(len(raw.encode())<=36864,'relay36KiB cap within original16MiB UART')
  print('KSM2_INNER_COMMAND_RELAY '+s['nonce']+' '+raw,flush=True)
 except BaseException:return

def worker_failure_data(s,row,out,err,error):
 """Failure-only original worker captures; never alters the held outcome/guard."""
 try:
  if error is None and type(row)is dict and row.get('exit_code')==0 and row.get('group_absence_verified')is True:return
  import base64,math,re
  C.need(type(s.get('nonce'))is str and re.fullmatch('[0-9a-f]{32}',s['nonce'])and type(row)is dict,'bounded source failure nonce/record')
  C.need(row['argv']==['/usr/bin/python3','-I','-B','/workspace/guest.py','worker']and type(row['exit_code'])is int and -64<=row['exit_code']<=255 and type(row['group_absence_verified'])is bool and row['time_limit']==C.SHARED_SECONDS and row['output_limit']==512*1024,'exact original worker command/limits')
  C.need(type(out)is type(err)is bytes and len(out)+len(err)<=512*1024,'original bounded worker captures only')
  streams={}
  for name,raw,cap in(('stdout',out,4096),('stderr',err,8192)):
   C.need(type(row[name+'_bytes'])is int and row[name+'_bytes']==len(raw)and row[name+'_sha256']==C.sha(raw),'original worker stream record/capture join')
   tail=raw[-cap:];streams[name]=dict(bytes=len(raw),sha256=C.sha(raw),tail_bytes=len(tail),tail_sha256=C.sha(tail),tail_base64=base64.b64encode(tail).decode('ascii'),omitted_bytes=len(raw)-len(tail),truncated=len(raw)>len(tail),full_hash_scope='COMPLETE_CAPTURE_NOT_ATTEMPTED_OUTPUT')
  seconds=row['seconds'];C.need(type(seconds)in(int,float)and math.isfinite(seconds)and 0<=seconds<=C.SHARED_SECONDS+6,'bounded original worker elapsed')
  error_type=None if error is None else type(error).__name__;C.need(error_type is None or re.fullmatch('[A-Za-z_][A-Za-z0-9_]{0,127}',error_type),'bounded supervisor error TYPE only')
  # Only a complete original stdout line can identify a typed worker exception.
  # No message, missing prefix, private result/map or root cause is synthesized.
  lines=out.splitlines(keepends=True);types=[]
  for line in lines:
   if line.endswith(b'\n')and line.startswith(b'KSM2_VM_ERROR ')and len(line)<=4096:
    line=line.rstrip(b'\r\n')
    word=line[len(b'KSM2_VM_ERROR '):].split(b' ',1)[0]
    if re.fullmatch(b'[A-Za-z_][A-Za-z0-9_]{0,127}',word):types.append(word.decode('ascii'))
  inner=dict(status='EXACT_SOURCE_STDOUT_EXCEPTION_TYPE_ONLY'if len(types)==1 else'UNKNOWN',error_type=types[0]if len(types)==1 else None,root_cause='UNKNOWN_NO_STATE_INFERENCE')
  value=dict(schema_version=1,status='FAILED_ORIGINAL_WORKER_CAPTURE_DATA_ONLY',nonce=s['nonce'],record=row,supervisor_error_type=error_type,streams=streams,inner_result=inner,positive_authority=False,cleanup_authority=False)
  raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False);C.need(len(raw.encode())<=32768,'failure DATA32KiB maximum')
  print('KSM2_WORKER_FAILURE_DATA '+s['nonce']+' '+raw,flush=True)
 except BaseException:
  # Optional diagnosis must never replace original worker failure or cleanup.
  return

def main():
 s=C.decode(C.read('/workspace/selection.json'))
 if sys.argv[1:]==['worker']:
  result=run(s);C.save('/out/guest-result.json',result);return
 C.guest_guard(s);resource.setrlimit(resource.RLIMIT_NOFILE,(8192,8192));C.need(ctypes.CDLL(None).prctl(4,0,0,0,0)==0,'protect private PID1')
 clocks=[v.split('=',1)[1]for v in Path('/proc/cmdline').read_text().split()if v.startswith('caa_clock_ns=')];C.need(len(clocks)==1 and clocks[0].isdigit()and 1767225600000000000<=int(clocks[0])<4102444800000000000,'one finite source-owned boot clock seed');clock=int(clocks[0]);time.clock_settime_ns(time.CLOCK_REALTIME,clock)
 emit(s,dict(event='boot',architecture=os.uname().machine,page_size=16384,kernel=os.uname().release,kernel_profile_sha256=C.sha(C.encoded(s['kernel'])),clock_seed_ns=clock,nofile=8192))
 R=C.load('_ksm_pid1_supervision','/source/borrowed/runtime.py');R=supervision_runtime(R);row,out,err,error=R.run_command(['/usr/bin/python3','-I','-B','/workspace/guest.py','worker'],Path('/tmp'),dict(PATH='/usr/bin:/bin',LC_ALL='C',HOME='/tmp',TMPDIR='/tmp'),C.SHARED_SECONDS,512*1024)
 Path('/out/worker.stdout').write_bytes(out);Path('/out/worker.stderr').write_bytes(err);C.save('/out/worker.json',row)
 relay_inner_command(s,row,out,err,error)
 worker_failure_data(s,row,out,err,error)
 if error is not None or row['exit_code']!=0 or row['group_absence_verified']is not True:
  print('KSM2_VM_ERROR '+s['nonce']+' '+json.dumps(dict(status='FAILED_ORIGINAL_WORKER_NOT_ACCEPTANCE',record=row,stderr_tail=err[-4096:].decode('utf8','backslashreplace')),sort_keys=True),flush=True)
 C.need(error is None and row['exit_code']==0 and row['group_absence_verified']is True,'whole KSM guest worker exit/group retirement')
 result=C.decode(C.read('/out/guest-result.json',256*1024));result.update(event='result',worker=row,process_retirement=quiescent(s));emit(s,result)
 for dest in reversed((*s['bindings'],'/measurement','/workspace','/source')):
  p=subprocess.run(['/usr/bin/umount',dest],capture_output=True,timeout=15);C.need(p.returncode==0 and not os.path.ismount(dest),'actual owned guest mount retirement')
 emit(s,dict(event='exit',status='PASS',cleanup='PASS_OWNED_MOUNTS_RETIRED'))

if __name__=='__main__':
 try:main()
 except BaseException as error:
  print('KSM2_VM_ERROR '+type(error).__name__+' '+str(error)[:2048],flush=True)
  if os.getpid()!=1:raise SystemExit(1)
 finally:
  if os.getpid()==1:
   sys.stdout.flush();sys.stderr.flush();os.sync();ctypes.CDLL(None).reboot(0x4321fedc)
